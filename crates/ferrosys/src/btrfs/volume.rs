//! Opening a btrfs and reaching its trees: the superblock and its copies, the chunk map built
//! through the bootstrap, and every tree block fetched and verified through that one map.
//!
//! This is the layer the filesystem view stands on. It knows about addresses, blocks, and
//! trees, and nothing about files: what an item *means* is decided by whoever asked for it.
//!
//! # What opening does, in order
//!
//! 1. Read every superblock location the source reaches, and judge each one — is it there, is
//!    it a superblock, does its checksum cover it, and does it agree about where it lives.
//! 2. Choose the copy at the highest generation, which is the filesystem's own rule for which
//!    of them is live.
//! 3. Refuse what cannot be read at all: a filesystem spanning several devices, a checksum
//!    algorithm this crate does not compute, a feature bit it does not implement, a geometry
//!    the format does not define.
//! 4. Judge the copies that were *not* chosen against the device's own length, so a missing or
//!    stale one is reported rather than passed over.
//! 5. Load the bootstrap array, translate the chunk root through it, and read the chunk tree —
//!    which completes the map every read above this point goes through.
//!
//! This module does I/O.

use std::io::{Read, Seek};

use crate::io::{io_error, offset_of, read_exact_at, read_exact_into};
use crate::{Limits, OpenOptions, ReadPolicy};

use super::ChunkMap;
use super::btree::Tree;
use super::ondisk::{
    self, ChecksumType, Chunk, Header, IncompatFlags, ItemType, MAX_BLOCK_SIZE, MAX_LEVEL,
    MIN_BLOCK_SIZE, MIRRORS, ParseError, RootItem, SUPER_INFO_SIZE, SuperBlock, holds_mirror,
    objectid,
};

/// Every `incompat` bit this crate understands well enough to read a filesystem carrying it.
///
/// A bit outside this set is a hard refusal by name, which is what the word means: the format
/// is telling a reader in advance that it will not understand what follows. The list is short
/// on purpose and grows with the code that earns each entry.
///
/// `MIXED_BACKREF`, `BIG_METADATA`, `EXTENDED_IREF`, `SKINNY_METADATA` and `NO_HOLES` are the
/// five the pinned baseline sets with no options at all. `DEFAULT_SUBVOL` and `METADATA_UUID`
/// change which subvolume is mounted and which id a tree block carries, both of which this
/// layer already reads.
///
/// **Two of the entries depend on what this build carries**, and that is the one place this
/// list is not fixed. A filesystem that sets a compression bit says some extent of it is
/// stored that way, so whether it can be read at all is whether this build has the decoder —
/// which makes each bit exactly as supported as its Cargo feature. The remaining algorithm
/// sets no bit, because every reader of this format has always understood it, so a filesystem
/// using it opens either way and it is the *file* that cannot be read without the decoder.
pub const SUPPORTED_INCOMPAT: IncompatFlags = IncompatFlags::from_bits(
    IncompatFlags::MIXED_BACKREF.bits()
        | IncompatFlags::DEFAULT_SUBVOL.bits()
        | IncompatFlags::BIG_METADATA.bits()
        | IncompatFlags::EXTENDED_IREF.bits()
        | IncompatFlags::SKINNY_METADATA.bits()
        | IncompatFlags::NO_HOLES.bits()
        | IncompatFlags::METADATA_UUID.bits()
        | if cfg!(feature = "lzo") {
            IncompatFlags::COMPRESS_LZO.bits()
        } else {
            0
        }
        | if cfg!(feature = "zstd") {
            IncompatFlags::COMPRESS_ZSTD.bits()
        } else {
            0
        },
);

/// What was found at one of the three superblock locations.
///
/// Every copy is judged whether or not it is the one used, because a filesystem whose copies
/// disagree is a filesystem something went wrong on — and the account of *how* they disagree
/// is what a caller needs to tell a torn write from an image carved out at the wrong offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Mirror {
    /// The device is not long enough to hold this copy, so the format wrote none. Not a
    /// fault: the rule is every copy the device has room for, and a small filesystem has room
    /// for one or two.
    OutsideDevice,
    /// The device's own recorded length reaches this copy and the source does not, so the
    /// image in hand is shorter than the filesystem it holds.
    Truncated,
    /// The bytes are readable and are not a superblock.
    Absent,
    /// A superblock whose checksum does not cover it.
    Damaged,
    /// A superblock that records a different location as its own, which is what an image
    /// carved out of a disk at the wrong offset looks like — the checksum still verifies,
    /// because the address it disagrees about is inside what the checksum covers.
    Misplaced {
        /// The location the copy believes it lives at.
        bytenr: u64,
    },
    /// A superblock, at the transaction it records.
    Present {
        /// The transaction that wrote it. The highest across the copies is the live one.
        generation: u64,
    },
}

impl Mirror {
    /// The transaction this copy was written by, or [`None`] where there is no copy to ask.
    #[must_use]
    pub const fn generation(self) -> Option<u64> {
        match self {
            Mirror::Present { generation } => Some(generation),
            _ => None,
        }
    }
}

/// Where one tree begins, and which tree it is.
///
/// The superblock supplies two of these directly and the root tree supplies the rest, so this
/// is the one currency in which a tree is named however it was found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeRoot {
    /// Which tree — one of [`objectid`]'s named values, or a subvolume's own id.
    pub objectid: u64,
    /// The logical address of the tree's top block.
    pub bytenr: u64,
    /// The height of that block, zero where the whole tree is one leaf.
    pub level: u8,
    /// The transaction that wrote it.
    pub generation: u64,
}

/// A btrfs image opened over a seekable source: its superblock, its address space, and its
/// trees.
///
/// This is the layer below a filesystem view. It hands back tree blocks, verified, at logical
/// addresses — which is what every part of a btrfs is addressed by, files included.
///
/// ```no_run
/// use ferrosys::btrfs::{Volume, ondisk::objectid};
///
/// let mut volume = Volume::open(std::fs::File::open("root.img")?)?;
/// // Every tree the filesystem has, found through the root tree.
/// for root in volume.tree_roots()? {
///     let items = volume.tree(root).count_items()?;
///     println!("{:>16}: {items} items", objectid::name(root.objectid).unwrap_or("subvolume"));
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Volume<R> {
    src: R,
    base: u64,
    policy: ReadPolicy,
    limits: Limits,
    /// Boxed, because it is not a header — it is 4096 bytes, two kibibytes of which are the
    /// bootstrap chunk array. Held by value it would make every reader of this family an
    /// order of magnitude larger than every other family's, and the enum that holds one of
    /// each is as large as its largest variant.
    superblock: Box<SuperBlock>,
    mirrors: [Mirror; MIRRORS.len()],
    chunks: ChunkMap,
}

impl<R: Read + Seek> Volume<R> {
    /// Open the filesystem at the start of `src`, strictly, with the default limits.
    ///
    /// # Errors
    ///
    /// See [`open_with`](Self::open_with).
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, OpenOptions::new())
    }

    /// Open the filesystem `options.base` bytes into `src`.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotBtrfs`] where no location carries a superblock at all, and one of the
    /// refusals in [`ReadError`] where a filesystem is there and cannot be read: a checksum
    /// that does not cover its superblock, a feature bit nothing here implements, a
    /// multi-device filesystem this image is one device of, a geometry the format does not
    /// define, or a chunk tree that does not describe an address space.
    ///
    /// Under [`ReadPolicy::Strict`] a copy of the superblock that the device has room for and
    /// that is missing, damaged, misplaced, or behind the chosen one is also a refusal.
    /// Under [`ReadPolicy::Lenient`] every one of those is recorded in
    /// [`mirrors`](Self::mirrors) and the filesystem opens.
    pub fn open_with(mut src: R, options: OpenOptions) -> Result<Self, ReadError> {
        let base = options.base;
        let mut found = [Mirror::Absent; MIRRORS.len()];
        let mut candidates: [Option<SuperBlock>; MIRRORS.len()] = [None, None, None];

        for (index, &at) in MIRRORS.iter().enumerate() {
            // Through the shared addressing rather than by hand: `base` is a caller's and
            // `at` is the format's, and a sum that wrapped would read a superblock out of a
            // small offset the wrap landed on rather than failing.
            let Some(offset) = offset_of(base, at, 1) else {
                found[index] = Mirror::Truncated;
                continue;
            };
            let bytes = match read_exact_at(&mut src, offset, SUPER_INFO_SIZE) {
                Ok(bytes) => bytes,
                // A source that does not reach this far says nothing yet: whether the copy
                // *should* be there is a question about the device's length, and the device's
                // length is a field of a superblock not yet chosen.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    found[index] = Mirror::Truncated;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Ok(superblock) = SuperBlock::read_from(&bytes) else {
                found[index] = Mirror::Absent;
                continue;
            };
            if !checksum_holds(&bytes, superblock.csum_type) {
                found[index] = Mirror::Damaged;
                continue;
            }
            if superblock.bytenr != at {
                found[index] = Mirror::Misplaced {
                    bytenr: superblock.bytenr,
                };
                continue;
            }
            found[index] = Mirror::Present {
                generation: superblock.generation,
            };
            candidates[index] = Some(superblock);
        }

        // The filesystem's own rule for which copy is live: the newest. Ties go to the
        // earliest location, which is the one every tool reads first.
        let chosen = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, sb)| sb.as_ref().map(|sb| (index, sb)))
            .max_by_key(|(index, sb)| (sb.generation, std::cmp::Reverse(*index)))
            .map(|(index, _)| index);
        let Some(chosen) = chosen else {
            // Nothing usable. Which of the two things went wrong is worth telling apart: a
            // source with no btrfs in it is a different answer from a btrfs whose superblock
            // has been damaged, and a caller pointed at the wrong file wants the first.
            return Err(
                match found.iter().find(|m| {
                    !matches!(
                        m,
                        Mirror::Absent | Mirror::OutsideDevice | Mirror::Truncated
                    )
                }) {
                    Some(Mirror::Damaged) => ReadError::BadChecksum {
                        object: "superblock",
                        at: MIRRORS[0],
                    },
                    Some(&Mirror::Misplaced { bytenr }) => ReadError::MisplacedSuperblock {
                        expected: MIRRORS[0],
                        bytenr,
                    },
                    _ => ReadError::NotBtrfs,
                },
            );
        };
        let superblock = candidates[chosen]
            .take()
            .expect("the chosen copy was parsed");

        check_readable(&superblock)?;

        // Now that the device's length is known, each location that is not a superblock can be
        // told apart: one the device has no room for was never written, and one it has room
        // for is missing.
        let device_bytes = superblock.dev_item.total_bytes;
        for (index, &at) in MIRRORS.iter().enumerate() {
            if !holds_mirror(device_bytes, at) {
                found[index] = Mirror::OutsideDevice;
            }
        }
        if options.policy == ReadPolicy::Strict {
            for (index, &state) in found.iter().enumerate() {
                let fault = match state {
                    Mirror::OutsideDevice => continue,
                    Mirror::Present { generation } if generation == superblock.generation => {
                        continue;
                    }
                    Mirror::Present { .. } => "a copy of the superblock is behind the live one",
                    Mirror::Truncated => "the source is shorter than the device it describes",
                    Mirror::Absent => "a copy of the superblock is missing",
                    Mirror::Damaged => "a copy of the superblock fails its checksum",
                    Mirror::Misplaced { .. } => {
                        "a copy of the superblock records another place as its own"
                    }
                };
                return Err(ReadError::MirrorDisagreement {
                    mirror: index,
                    at: MIRRORS[index],
                    fault,
                });
            }
        }

        let bootstrap = superblock
            .sys_chunk_bytes()
            .ok_or(ReadError::BadBootstrap {
                at: 0,
                fault: "the recorded length of the bootstrap array is longer than the array",
            })?;
        let chunks = ChunkMap::from_bootstrap(bootstrap, superblock.dev_item.devid, device_bytes)?;

        let mut volume = Self {
            src,
            base,
            policy: options.policy,
            limits: options.limits,
            superblock: Box::new(superblock),
            mirrors: found,
            chunks,
        };
        volume.load_chunk_tree()?;
        Ok(volume)
    }

    /// The superblock the filesystem was opened through: the newest copy of it that verified.
    #[must_use]
    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }

    /// What was found at each of the three superblock locations, in the order [`MIRRORS`]
    /// gives them.
    ///
    /// A strict open has already refused anything but [`Mirror::OutsideDevice`] and a
    /// [`Mirror::Present`] at the live generation, so this is what a lenient open is for.
    #[must_use]
    pub fn mirrors(&self) -> &[Mirror; MIRRORS.len()] {
        &self.mirrors
    }

    /// The map from logical addresses to places on the device, complete once the chunk tree
    /// has been read.
    #[must_use]
    pub fn chunk_map(&self) -> &ChunkMap {
        &self.chunks
    }

    /// How strictly this volume is being read.
    #[must_use]
    pub fn policy(&self) -> ReadPolicy {
        self.policy
    }

    /// The caps this volume was opened under.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// How long one tree block is, which is the filesystem's node size.
    #[must_use]
    pub fn node_size(&self) -> u32 {
        self.superblock.nodesize
    }

    /// The root tree, whose items name every other tree.
    #[must_use]
    pub fn root_tree(&self) -> TreeRoot {
        TreeRoot {
            objectid: objectid::ROOT_TREE,
            bytenr: self.superblock.root,
            level: self.superblock.root_level,
            generation: self.superblock.generation,
        }
    }

    /// The chunk tree, which the bootstrap array exists to make reachable.
    #[must_use]
    pub fn chunk_tree(&self) -> TreeRoot {
        TreeRoot {
            objectid: objectid::CHUNK_TREE,
            bytenr: self.superblock.chunk_root,
            level: self.superblock.chunk_root_level,
            generation: self.superblock.chunk_root_generation,
        }
    }

    /// Every tree the filesystem has.
    ///
    /// Two of them come from the superblock and are first: **the root tree**, which holds no
    /// record of itself, and **the chunk tree**, which cannot be in the root tree since
    /// reading the root tree needs the chunk tree already. Every other tree — the extent,
    /// device, checksum, uuid, free-space and block-group trees, the top-level filesystem
    /// tree, and one per subvolume — follows in key order.
    ///
    /// # Errors
    ///
    /// Whatever reading the root tree does, and [`ReadError::BadRootItem`] where an item that
    /// should name a tree does not describe one.
    pub fn tree_roots(&mut self) -> Result<Vec<TreeRoot>, ReadError> {
        let mut roots = vec![self.root_tree(), self.chunk_tree()];
        let mut failure = None;
        let root_tree = self.root_tree();
        self.tree(root_tree).for_each_item(|key, data| {
            if key.kind != ItemType::ROOT_ITEM {
                return true;
            }
            match RootItem::read_from(data) {
                Ok(item) => {
                    roots.push(TreeRoot {
                        objectid: key.objectid,
                        bytenr: item.bytenr,
                        level: item.level,
                        generation: item.generation,
                    });
                    true
                }
                Err(e) => {
                    failure = Some(ReadError::BadRootItem {
                        objectid: key.objectid,
                        source: e,
                    });
                    false
                }
            }
        })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(roots),
        }
    }

    /// A handle on one tree, for searching or iterating it.
    pub fn tree(&mut self, root: TreeRoot) -> Tree<'_, R> {
        Tree::new(self, root)
    }

    /// One tree block, fetched through the chunk map and checked before it is handed back.
    ///
    /// Four things are checked, and each catches a different way of arriving at the wrong
    /// bytes: the checksum covers what was read, the block says it lives where it was fetched
    /// from, it belongs to this filesystem, and its height is one the format defines. What
    /// `nritems` may be depends on what the block is being read *as*, so that bound is applied
    /// where the array is walked rather than here.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnmappedLogical`] where the chunk map does not cover the address,
    /// [`ReadError::BadChecksum`] where the block's checksum does not cover it, and
    /// [`ReadError::BadTreeBlock`] for each of the other three.
    pub fn read_block(&mut self, logical: u64) -> Result<TreeBlock, ReadError> {
        let len = u64::from(self.superblock.nodesize);
        let physical = self.chunks.translate(logical, len)?;
        let offset =
            offset_of(self.base, physical, 1).ok_or(ReadError::UnmappedLogical { logical, len })?;
        let bytes = read_exact_at(&mut self.src, offset, len as usize)?;

        if !checksum_holds(&bytes, self.superblock.csum_type) {
            return Err(ReadError::BadChecksum {
                object: "tree block",
                at: logical,
            });
        }
        let header = Header::read_from(&bytes)?;
        if header.bytenr != logical {
            return Err(ReadError::BadTreeBlock {
                logical,
                fault: "the block records another logical address as its own",
            });
        }
        if header.fsid != self.superblock.metadata_id() {
            return Err(ReadError::BadTreeBlock {
                logical,
                fault: "the block belongs to another filesystem",
            });
        }
        if header.level > MAX_LEVEL {
            return Err(ReadError::BadTreeBlock {
                logical,
                fault: "the block is at a height the format does not define",
            });
        }
        Ok(TreeBlock { header, bytes })
    }

    /// Fill `buf` from a logical address, through the chunk map.
    ///
    /// This is the raw form of what [`read_block`](Self::read_block) does, and it exists
    /// because **a file's bytes carry nothing that identifies them**: no header saying where
    /// they live, no checksum inside the run. A data extent is verified by holding it against
    /// the checksum tree, which is a separate structure and a separate read, so this hands
    /// back the bytes at an address and says nothing about whether they are the right ones.
    ///
    /// The whole run must be inside one chunk, which is what the map guarantees for any extent
    /// a filesystem allocated: an extent never straddles a chunk boundary.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnmappedLogical`] where the chunk map does not cover the whole run, and
    /// [`ReadError::Io`] where the source does not reach that far.
    pub fn read_at(&mut self, logical: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let len = buf.len() as u64;
        let physical = self.chunks.translate(logical, len)?;
        let offset =
            offset_of(self.base, physical, 1).ok_or(ReadError::UnmappedLogical { logical, len })?;
        // Straight into the caller's buffer: this is the per-sector step of a data verify,
        // where an allocating read would cost a fresh buffer per sector of the volume.
        read_exact_into(&mut self.src, offset, buf)?;
        Ok(())
    }

    /// Read the chunk tree through the bootstrap map, adding every chunk it names.
    ///
    /// This is the second half of the bootstrap: after it, the map covers the whole address
    /// space rather than only the part that holds the chunk tree.
    fn load_chunk_tree(&mut self) -> Result<(), ReadError> {
        let devid = self.superblock.dev_item.devid;
        let device_bytes = self.superblock.dev_item.total_bytes;
        // Gathered before insertion rather than inserted during the walk, because the walk
        // borrows the volume the map lives in — and because a chunk tree that turns out to
        // overlap itself should leave the bootstrap map intact rather than half-extended.
        let mut found = Vec::new();
        let mut failure = None;
        let chunk_tree = self.chunk_tree();
        self.tree(chunk_tree).for_each_item(|key, data| {
            if key.kind != ItemType::CHUNK_ITEM {
                return true;
            }
            match Chunk::read_from(data) {
                Ok(chunk) if data.len() >= chunk.encoded_len() => {
                    found.push((*key, chunk, data[..chunk.encoded_len()].to_vec()));
                    true
                }
                Ok(chunk) => {
                    failure = Some(ReadError::BadChunk {
                        logical: key.offset,
                        fault: "a chunk item declares more stripes than the item holds",
                    });
                    let _ = chunk;
                    false
                }
                Err(e) => {
                    failure = Some(e.into());
                    false
                }
            }
        })?;
        if let Some(e) = failure {
            return Err(e);
        }
        for (key, chunk, record) in found {
            // The bootstrap array carries a copy of the system chunks the chunk tree also
            // records, so meeting one again is the ordinary case rather than a conflict. An
            // entry that repeats a mapping already held is skipped; one that *contradicts* it
            // is the overlap `insert` refuses.
            if let Some(existing) = self.chunks.chunk_at(key.offset)
                && existing.logical == key.offset
                && existing.length == chunk.length
            {
                continue;
            }
            self.chunks
                .insert(&key, &chunk, &record, devid, device_bytes)?;
        }
        Ok(())
    }
}

/// One tree block, checked and held whole.
///
/// A block is read entire because that is what its checksum covers: verifying it means having
/// every byte, so there is nothing to be gained by fetching an item at a time.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeBlock {
    header: Header,
    bytes: Vec<u8>,
}

impl TreeBlock {
    /// What the block says about itself.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The block's bytes, the header included.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many items or child pointers the block claims, held to what it has room for.
    ///
    /// This is the one bound that cannot be applied when a block is fetched, because what a
    /// count *may* be depends on which of the two things the block holds — 25 bytes per item,
    /// 33 per child pointer — and that follows from the level.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadTreeBlock`] where the count is larger than the block could hold.
    pub fn count(&self) -> Result<usize, ReadError> {
        let each = if self.header.is_leaf() {
            ondisk::Item::SIZE
        } else {
            ondisk::KeyPtr::SIZE
        };
        let claimed = self.header.nritems as usize;
        let room = (self.bytes.len() - Header::SIZE) / each;
        if claimed > room {
            return Err(ReadError::BadTreeBlock {
                logical: self.header.bytenr,
                fault: "the block claims more entries than it has room for",
            });
        }
        Ok(claimed)
    }

    /// The child pointer at `index` of an internal node.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadTreeBlock`] where the block is a leaf or `index` is past its count.
    pub fn key_ptr(&self, index: usize) -> Result<ondisk::KeyPtr, ReadError> {
        if self.header.is_leaf() {
            return Err(ReadError::BadTreeBlock {
                logical: self.header.bytenr,
                fault: "a leaf holds items rather than child pointers",
            });
        }
        if index >= self.count()? {
            return Err(ReadError::BadTreeBlock {
                logical: self.header.bytenr,
                fault: "a child pointer past the block's own count",
            });
        }
        let at = Header::SIZE + index * ondisk::KeyPtr::SIZE;
        Ok(ondisk::KeyPtr::read_from(&self.bytes[at..])?)
    }

    /// The item at `index` of a leaf.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadTreeBlock`] where the block is a node or `index` is past its count.
    pub fn item(&self, index: usize) -> Result<ondisk::Item, ReadError> {
        if !self.header.is_leaf() {
            return Err(ReadError::BadTreeBlock {
                logical: self.header.bytenr,
                fault: "an internal node holds child pointers rather than items",
            });
        }
        if index >= self.count()? {
            return Err(ReadError::BadTreeBlock {
                logical: self.header.bytenr,
                fault: "an item past the block's own count",
            });
        }
        let at = Header::SIZE + index * ondisk::Item::SIZE;
        Ok(ondisk::Item::read_from(&self.bytes[at..])?)
    }

    /// Whether the leaf's items are packed the way the format packs them.
    ///
    /// A leaf's free space is one run in the middle: the item array grows forward from the
    /// header and the data grows backward from the end of the block, with no gap between one
    /// item's data and the next's. So the first item's data ends exactly at the end of the
    /// block and every later item's ends exactly where the one before it begins.
    ///
    /// **Bounding each item separately does not imply this**, and the difference is a defect
    /// class rather than a nicety: data moved within a leaf, with the offsets moved to match,
    /// leaves every item inside the block and every item pointing at bytes that are not its
    /// own. Nothing about a bound notices, and what a reader then hands back is one record's
    /// bytes under another record's key.
    ///
    /// A block that is not a leaf is packed vacuously, and answers so.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadItem`] naming the first item whose data does not abut its neighbour's,
    /// and whatever [`item`](Self::item) refuses.
    pub fn check_leaf_packing(&self) -> Result<(), ReadError> {
        if !self.header.is_leaf() {
            return Ok(());
        }
        let count = self.count()?;
        // Item offsets are measured from the end of the header, so the region they address is
        // the block less its header.
        let mut abuts = (self.bytes.len() - Header::SIZE) as u64;
        for index in 0..count {
            let item = self.item(index)?;
            let start = u64::from(item.offset);
            if start + u64::from(item.size) != abuts {
                return Err(ReadError::BadItem {
                    logical: self.header.bytenr,
                    index,
                    fault: "the item's data does not end where the item before it begins",
                });
            }
            abuts = start;
        }
        Ok(())
    }

    /// The bytes of the item at `index`, bounded by the leaf that holds them.
    ///
    /// An item's data grows backward from the end of the block while the item array grows
    /// forward from the header, so two things must hold and both are checked: the data begins
    /// past the array, and it ends within the block. An item that failed either would
    /// otherwise be read out of the array describing it or out of whatever follows the block.
    ///
    /// **The arithmetic is done in 64 bits whatever the target's pointer width is.** Both
    /// fields are 32 bits, so their sum is bounded by 2³³ and cannot wrap a `u64` — where in
    /// `usize` it wraps on a 32-bit target and cannot on a 64-bit one, which would make this
    /// function's behaviour on a crafted leaf a property of the machine reading it and leave
    /// the difference invisible wherever development happens.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadItem`] where the item's data is not inside the space a leaf leaves for
    /// it, and whatever [`item`](Self::item) refuses.
    pub fn item_data(&self, index: usize) -> Result<&[u8], ReadError> {
        let count = self.count()?;
        let item = self.item(index)?;
        let array_end = (Header::SIZE + count * ondisk::Item::SIZE) as u64;
        let start = Header::SIZE as u64 + u64::from(item.offset);
        let end = start + u64::from(item.size);
        if start < array_end {
            return Err(ReadError::BadItem {
                logical: self.header.bytenr,
                index,
                fault: "the item's data begins inside the array describing it",
            });
        }
        if end > self.bytes.len() as u64 {
            return Err(ReadError::BadItem {
                logical: self.header.bytenr,
                index,
                fault: "the item's data runs past the end of the block",
            });
        }
        // Both casts are inside the block's own length, which the check above established.
        Ok(&self.bytes[start as usize..end as usize])
    }
}

/// Whether an object's stored checksum covers the bytes it was read as.
///
/// The bytes are the ones that came off the device, never a value re-serialized through this
/// crate's own types: a structure whose coverage of a format is partial cannot reproduce a
/// foreign tool's bytes, and a verifier built on one would report every filesystem it did not
/// write as damaged.
///
/// An algorithm this crate does not compute answers `false` — but a filesystem using one never
/// reaches here, because [`check_readable`] refuses it by name at open with a message saying
/// which algorithm it was.
fn checksum_holds(object: &[u8], csum_type: ChecksumType) -> bool {
    if csum_type != ChecksumType::CRC32C {
        return false;
    }
    let Some(digest_len) = csum_type.digest_len() else {
        return false;
    };
    ondisk::stored_crc32c(object) == ondisk::checksum(object)
        && ondisk::padding_is_clear(object, digest_len)
}

/// Whether the filesystem this superblock describes is one this crate can read at all.
///
/// Each refusal names what it would take to read it rather than reporting an unexpected value,
/// because every one of these is a filesystem that is *fine* and simply beyond this reader.
fn check_readable(sb: &SuperBlock) -> Result<(), ReadError> {
    if sb.csum_type != ChecksumType::CRC32C {
        return Err(ReadError::UnsupportedChecksum {
            csum_type: sb.csum_type.value(),
        });
    }
    let unsupported = sb.incompat_flags.without(SUPPORTED_INCOMPAT);
    if !unsupported.is_empty() {
        let mut names = String::new();
        unsupported.describe(&mut names);
        return Err(ReadError::UnsupportedFeatures {
            bits: unsupported.bits(),
            names,
        });
    }
    if sb.num_devices != 1 {
        return Err(ReadError::MultiDevice {
            num_devices: sb.num_devices,
        });
    }
    for (field, value) in [("sector size", sb.sectorsize), ("node size", sb.nodesize)] {
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&value) || !value.is_power_of_two() {
            return Err(ReadError::BadGeometry {
                field,
                value: u64::from(value),
            });
        }
    }
    if sb.nodesize < sb.sectorsize {
        return Err(ReadError::BadGeometry {
            field: "node size, which is never smaller than the sector size",
            value: u64::from(sb.nodesize),
        });
    }
    // Against the id every tree block carries, not the one a person sees. The device record
    // lives in the chunk tree and belongs to the metadata; on a filesystem whose two ids are
    // one — which is every filesystem until somebody changes the visible one — the two readings
    // agree, and on one whose ids differ only this reading accepts it.
    if sb.dev_item.fsid != sb.metadata_id() {
        return Err(ReadError::BadSuperblock {
            fault: "the device it describes belongs to another filesystem",
        });
    }
    if sb.dev_item.total_bytes == 0 {
        return Err(ReadError::BadSuperblock {
            fault: "the device it describes has no length",
        });
    }
    if sb.root == 0 || sb.chunk_root == 0 {
        return Err(ReadError::BadSuperblock {
            fault: "a tree this filesystem cannot be read without has no root",
        });
    }
    Ok(())
}

/// What reading a btrfs can fail on.
///
/// The variants divide into three kinds, and the difference is what a caller should do about
/// each. **These bytes are not ours** is [`NotBtrfs`](Self::NotBtrfs) alone. **This filesystem
/// is beyond this reader** is [`UnsupportedFeatures`](Self::UnsupportedFeatures),
/// [`UnsupportedChecksum`](Self::UnsupportedChecksum),
/// [`UnsupportedProfile`](Self::UnsupportedProfile) and [`MultiDevice`](Self::MultiDevice) —
/// each names a filesystem that is entirely well-formed and says what it would take. Every
/// other variant is **this filesystem does not describe itself consistently**, and each names
/// the structure and the address that made it so.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The source could not be read.
    #[error("i/o error ({kind:?}): {message}")]
    #[non_exhaustive]
    Io {
        /// How the failure classified itself.
        kind: std::io::ErrorKind,
        /// What it said.
        message: String,
    },
    /// No superblock location carries a btrfs signature.
    #[error("no btrfs superblock at any of the three locations the format defines")]
    NotBtrfs,
    /// An on-disk structure could not be recovered from the bytes holding it.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// A checksum did not cover the object it was read with.
    #[error("{object} at {at}: the checksum does not cover it")]
    #[non_exhaustive]
    BadChecksum {
        /// What was being read.
        object: &'static str,
        /// Where it was: a device offset for a superblock, a logical address for a block.
        at: u64,
    },
    /// The only superblock found records another location as its own.
    #[error("a superblock at {expected} records {bytenr} as its own location")]
    #[non_exhaustive]
    MisplacedSuperblock {
        /// Where it was read from.
        expected: u64,
        /// Where it says it lives.
        bytenr: u64,
    },
    /// Under a strict read, a copy of the superblock the device has room for is not a copy of
    /// the live one.
    #[error("superblock copy {mirror} at {at}: {fault}")]
    #[non_exhaustive]
    MirrorDisagreement {
        /// Which of the three locations, counting from zero.
        mirror: usize,
        /// Its byte offset within the device.
        at: u64,
        /// What is wrong with it.
        fault: &'static str,
    },
    /// The filesystem's checksums are computed by an algorithm this crate does not implement.
    #[error("checksum algorithm {csum_type} is not one this crate computes")]
    #[non_exhaustive]
    UnsupportedChecksum {
        /// The on-disk value.
        csum_type: u16,
    },
    /// The filesystem carries a feature whose on-disk form this crate does not implement.
    #[error("unsupported incompatible features: {names} ({bits:#x})")]
    #[non_exhaustive]
    UnsupportedFeatures {
        /// The bits that are not supported.
        bits: u64,
        /// Their names, or their positions where the format has not defined them.
        names: String,
    },
    /// The filesystem spans devices, so this image is a part of it rather than the whole.
    #[error("a filesystem of {num_devices} devices cannot be read from one image")]
    #[non_exhaustive]
    MultiDevice {
        /// How many devices it spans.
        num_devices: u64,
    },
    /// A chunk is replicated in a way that needs more than the device in hand, or in a way the
    /// format does not define.
    #[error(
        "the chunk at {logical} has a profile this crate cannot read from one device ({flags:#x})"
    )]
    #[non_exhaustive]
    UnsupportedProfile {
        /// The chunk's logical start.
        logical: u64,
        /// Its type-and-profile word.
        flags: u64,
    },
    /// A geometry field holds a value the format does not define.
    #[error("{field} is {value}, which the format does not define")]
    #[non_exhaustive]
    BadGeometry {
        /// Which field.
        field: &'static str,
        /// What it held.
        value: u64,
    },
    /// The superblock does not describe a filesystem consistently.
    #[error("superblock: {fault}")]
    #[non_exhaustive]
    BadSuperblock {
        /// What is wrong with it.
        fault: &'static str,
    },
    /// The bootstrap array does not frame the chunks it holds.
    #[error("the superblock's bootstrap chunk array, at byte {at}: {fault}")]
    #[non_exhaustive]
    BadBootstrap {
        /// How far into the array the framing failed.
        at: usize,
        /// What was wrong.
        fault: &'static str,
    },
    /// A chunk item does not describe a mapping.
    #[error("the chunk at {logical}: {fault}")]
    #[non_exhaustive]
    BadChunk {
        /// The chunk's logical start.
        logical: u64,
        /// What was wrong.
        fault: &'static str,
    },
    /// Two chunks claim the same logical address, so it has two mappings.
    #[error("two chunks map the logical address {logical}")]
    #[non_exhaustive]
    ChunkOverlap {
        /// Where they meet.
        logical: u64,
    },
    /// No chunk maps a logical address, or a run leaves the chunk that maps its start.
    #[error("no chunk maps {len} bytes at the logical address {logical}")]
    #[non_exhaustive]
    UnmappedLogical {
        /// The address.
        logical: u64,
        /// How many bytes were wanted there.
        len: u64,
    },
    /// A tree block does not describe itself consistently.
    #[error("the tree block at {logical}: {fault}")]
    #[non_exhaustive]
    BadTreeBlock {
        /// The block's logical address.
        logical: u64,
        /// What was wrong.
        fault: &'static str,
    },
    /// An item's data is not inside the space its leaf leaves for it.
    #[error("item {index} of the leaf at {logical}: {fault}")]
    #[non_exhaustive]
    BadItem {
        /// The leaf's logical address.
        logical: u64,
        /// Which item.
        index: usize,
        /// What was wrong.
        fault: &'static str,
    },
    /// A root item does not say where its tree is.
    #[error("the root item for tree {objectid}: {source}")]
    #[non_exhaustive]
    BadRootItem {
        /// Which tree it should have named.
        objectid: u64,
        /// What went wrong recovering it.
        source: ParseError,
    },
    /// A descent reached a block it had already been to, so the tree is not a tree.
    #[error("the tree block at {logical} is reachable from itself")]
    #[non_exhaustive]
    TreeCycle {
        /// The block met twice.
        logical: u64,
    },
    /// A child is not one level below its parent, so the descent would not terminate.
    #[error("the tree block at {logical} is at level {level} below a parent at level {parent}")]
    #[non_exhaustive]
    BadTreeLevel {
        /// The child's logical address.
        logical: u64,
        /// The level it records.
        level: u8,
        /// The level of the block that pointed at it.
        parent: u8,
    },
    /// A read would have gathered more entries than the caller's limits allow.
    #[error("a walk of tree {objectid} reached the limit of {limit} entries")]
    #[non_exhaustive]
    TooManyEntries {
        /// Which tree.
        objectid: u64,
        /// The cap that stopped it.
        limit: usize,
    },
    /// The filesystem has no tree of that id, though something named one.
    #[error("the filesystem has no tree {objectid}")]
    #[non_exhaustive]
    MissingTree {
        /// The id that was named.
        objectid: u64,
    },
    /// A subvolume's tree holds no record of an inode something named.
    #[error("subvolume {tree} holds no inode {inode}")]
    #[non_exhaustive]
    MissingInode {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
    },
    /// A path traverses through, or a name was looked up inside, something that is not a
    /// directory.
    ///
    /// The path is the one the caller stated, which is the one it can act on — this format
    /// numbers its inodes per subvolume, so the inode the traversal stopped at names nothing to
    /// a caller. Empty where no path was involved: a directory read asked of a node that is not
    /// one.
    #[error("not a directory: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotADirectory {
        /// The path as given.
        path: Vec<u8>,
    },
    /// A link target was asked of something that is not a symbolic link.
    #[error("inode {inode} of subvolume {tree} is not a symbolic link")]
    #[non_exhaustive]
    NotASymlink {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
    },
    /// No such path.
    #[error("no such path: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotFound {
        /// The path that was asked for.
        path: Vec<u8>,
    },
    /// A name in a path, or one an image stores, is one no directory can hold.
    #[error("{} is not a name a directory can hold", crate::escape::printable(.name))]
    #[non_exhaustive]
    HostileName {
        /// The offending name.
        name: Vec<u8>,
    },
    /// A directory entry names something that is neither an inode nor a subvolume.
    #[error("an entry of inode {inode} in subvolume {tree}: {fault} (item type {kind})")]
    #[non_exhaustive]
    BadDirEntry {
        /// The subvolume the directory is in.
        tree: u64,
        /// The directory's inode.
        inode: u64,
        /// What is wrong with it.
        fault: &'static str,
        /// The item type the entry's location named.
        kind: u8,
    },
    /// An extended attribute record does not frame as a name and a value.
    #[error("the extended attributes of inode {inode} in subvolume {tree} do not frame")]
    #[non_exhaustive]
    BadXattr {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
    },
    /// An extent record does not describe a run of the file it belongs to.
    #[error("the extent at offset {at} of inode {inode} in subvolume {tree}: {fault}")]
    #[non_exhaustive]
    BadExtent {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
        /// The file offset the record is keyed by.
        at: u64,
        /// What is wrong with it.
        fault: &'static str,
    },
    /// A file's bytes are compressed by an algorithm this build does not decode.
    #[error(
        "inode {inode} of subvolume {tree} is compressed with {}, which this build does not decode",
        crate::btrfs::ondisk::Compression::from_u8(*.compression)
            .name()
            .unwrap_or("an algorithm the format has not defined")
    )]
    #[non_exhaustive]
    UnsupportedCompression {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
        /// The on-disk algorithm byte.
        compression: u8,
    },
    /// A file's bytes are compressed with an algorithm this build decodes, and the stream is
    /// not a well-formed one.
    ///
    /// Apart from [`UnsupportedCompression`](Self::UnsupportedCompression), because the two
    /// say opposite things about the filesystem: that one is a filesystem that is entirely
    /// sound and beyond this build, and this one is a filesystem whose bytes do not hold what
    /// they say they hold.
    #[error(
        "the extent at offset {at} of inode {inode} in subvolume {tree} does not decode: {fault}"
    )]
    #[non_exhaustive]
    BadCompressedExtent {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
        /// The file offset the record is keyed by.
        at: u64,
        /// What was wrong with it, in the decoder's own words.
        fault: String,
    },
    /// A file's bytes carry an encoding beyond compression, which no release of the format
    /// defines a value for and nothing here can undo.
    #[error(
        "inode {inode} of subvolume {tree} is encoded ({encryption}, {other}), which this crate \
         does not decode"
    )]
    #[non_exhaustive]
    UnsupportedEncoding {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
        /// The encryption byte.
        encryption: u8,
        /// The other-encoding word.
        other: u16,
    },
    /// A whole-file read was asked for a file longer than the caller's cap.
    #[error(
        "inode {inode} of subvolume {tree} is {size} bytes, more than the {cap}-byte cap this \
         read is held to"
    )]
    #[non_exhaustive]
    FileTooLarge {
        /// Which subvolume.
        tree: u64,
        /// Which inode.
        inode: u64,
        /// The file's declared length.
        size: u64,
        /// The cap that applied.
        cap: u64,
    },
    /// A walk of the filesystem's names would have yielded more than the caller's cap.
    ///
    /// Separate from [`TooManyEntries`](Self::TooManyEntries), which is a cap on one B-tree
    /// walk. A filesystem holds one tree per subvolume and a walk of its *names* crosses all of
    /// them, so the two are different quantities and a caller acting on either wants to know
    /// which it hit.
    #[error("a walk of this filesystem reached the limit of {limit} names")]
    #[non_exhaustive]
    WalkTooLarge {
        /// The cap that stopped it.
        limit: usize,
    },
    /// A data extent's bytes do not match the checksum the filesystem recorded for them.
    ///
    /// The one fault in this crate that no structural check could have found: every tree is
    /// well-formed, every metadata block verifies, and the bytes of a file are not the bytes
    /// that were written.
    #[error("the data at {logical} does not match the checksum recorded for it")]
    #[non_exhaustive]
    DataChecksum {
        /// The logical address of the sector that failed.
        logical: u64,
    },
    /// A file whose inode says its data is checksummed has a run with no checksum recorded.
    #[error("no checksum is recorded for the data at {logical}")]
    #[non_exhaustive]
    MissingDataChecksum {
        /// The logical address with no checksum.
        logical: u64,
    },
    /// A name a walk built would be longer than any path this crate will produce.
    #[error("a path longer than this crate builds: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    PathTooLong {
        /// The path that was being built.
        path: Vec<u8>,
    },
    /// Resolving a path followed more symbolic links than
    /// [`MAX_SYMLINK_HOPS`](crate::MAX_SYMLINK_HOPS) allows.
    ///
    /// A cycle reaches it, and so does a chain that is merely long — which is the case that
    /// matters on an image this crate did not write, where the chain can be as long as somebody
    /// cared to make it.
    #[error("too many symbolic links resolving {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    SymlinkLoop {
        /// The path that was being resolved.
        path: Vec<u8>,
    },
}

io_error!(ReadError);

/// The tree engine reaches into a volume's source and its map, and nothing outside this module
/// does.
impl<R: Read + Seek> Volume<R> {
    /// The key a search may not go past, and the tree it belongs to — used by the engine to
    /// name a limit it hit.
    pub(super) fn walk_limit(&self) -> usize {
        self.limits.max_walk_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::ondisk::{CSUM_FIELD_LEN, CompatFlags, CompatRoFlags, DevItem, SuperFlags};

    fn a_superblock() -> SuperBlock {
        let mut sb = SuperBlock {
            csum: [0; CSUM_FIELD_LEN],
            fsid: [0x11; 16],
            bytenr: MIRRORS[0],
            flags: SuperFlags::NONE,
            magic: ondisk::MAGIC,
            generation: 8,
            root: 30_605_312,
            chunk_root: 22_036_480,
            log_root: 0,
            total_bytes: 1 << 30,
            bytes_used: 163_840,
            root_dir_objectid: 6,
            num_devices: 1,
            sectorsize: 4096,
            nodesize: 16_384,
            stripesize: 4096,
            sys_chunk_array_size: 0,
            chunk_root_generation: 8,
            compat_flags: CompatFlags::NONE,
            compat_ro_flags: CompatRoFlags::NONE,
            incompat_flags: IncompatFlags::MIXED_BACKREF,
            csum_type: ChecksumType::CRC32C,
            root_level: 0,
            chunk_root_level: 0,
            log_root_level: 0,
            dev_item: DevItem {
                devid: 1,
                total_bytes: 1 << 30,
                bytes_used: 0,
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                ty: 0,
                generation: 0,
                start_offset: 0,
                dev_group: 0,
                seek_speed: 0,
                bandwidth: 0,
                uuid: [0xec; 16],
                fsid: [0x11; 16],
            },
            label: [0; ondisk::LABEL_SIZE],
            cache_generation: 0,
            uuid_tree_generation: 0,
            metadata_uuid: [0; 16],
            nr_global_roots: 0,
            remap_root: 0,
            remap_root_generation: 0,
            remap_root_level: 0,
            sys_chunk_array: [0; ondisk::SYS_CHUNK_ARRAY_SIZE],
        };
        sb.sys_chunk_array_size = 0;
        sb
    }

    #[test]
    fn a_feature_bit_this_crate_does_not_implement_is_refused_by_name() {
        // The whole point of the incompatible word: the format is saying in advance that a
        // reader without the bit will misread what follows. Refusing it by name is what turns
        // the version drift this family expects into a message rather than a wrong read.
        let sb = SuperBlock {
            incompat_flags: IncompatFlags::MIXED_BACKREF | IncompatFlags::RAID_STRIPE_TREE,
            ..a_superblock()
        };
        let err = check_readable(&sb).expect_err("a stripe tree is not readable here");
        let ReadError::UnsupportedFeatures { bits, names } = err else {
            panic!("expected an unsupported-feature refusal, got {err:?}");
        };
        assert_eq!(bits, IncompatFlags::RAID_STRIPE_TREE.bits());
        // Named as `format -O` would take it, so a caller reading this refusal has the word
        // they would type to ask for such a filesystem.
        assert_eq!(names, "raid-stripe-tree");
        // And a bit the format grows after this release names its position rather than
        // vanishing, which is what makes the refusal readable.
        let future = SuperBlock {
            incompat_flags: IncompatFlags::from_bits(1 << 40),
            ..a_superblock()
        };
        let err = check_readable(&future).expect_err("a bit from the future");
        assert!(format!("{err}").contains("bit 40"), "{err}");
    }

    #[test]
    fn the_five_defaults_and_the_two_this_layer_reads_are_supported() {
        // The word the pinned baseline writes with no options at all, which must open.
        let sb = SuperBlock {
            incompat_flags: IncompatFlags::from_bits(0x361),
            ..a_superblock()
        };
        check_readable(&sb).expect("the baseline's default feature set");
        assert_eq!(SUPPORTED_INCOMPAT.bits() & 0x361, 0x361);
    }

    #[test]
    fn a_filesystem_that_spans_devices_is_refused_rather_than_read_as_a_part_of_itself() {
        let sb = SuperBlock {
            num_devices: 2,
            ..a_superblock()
        };
        assert!(matches!(
            check_readable(&sb),
            Err(ReadError::MultiDevice { num_devices: 2 })
        ));
    }

    #[test]
    fn a_geometry_the_format_does_not_define_is_refused_at_open() {
        for (sectorsize, nodesize) in [
            (2048, 16_384),  // below the floor
            (4096, 131_072), // above the ceiling
            (4096, 24_576),  // not a power of two
            (16_384, 4096),  // a node smaller than a sector
        ] {
            let sb = SuperBlock {
                sectorsize,
                nodesize,
                ..a_superblock()
            };
            assert!(
                matches!(check_readable(&sb), Err(ReadError::BadGeometry { .. })),
                "sector {sectorsize}, node {nodesize}"
            );
        }
        // And the range the pinned baseline accepts, at both ends.
        for size in [4096u32, 8192, 16_384, 32_768, 65_536] {
            let sb = SuperBlock {
                sectorsize: size,
                nodesize: size,
                ..a_superblock()
            };
            check_readable(&sb)
                .unwrap_or_else(|e| panic!("{size} is a size the format defines: {e}"));
        }
    }

    #[test]
    fn a_checksum_algorithm_this_crate_does_not_compute_is_named_rather_than_misverified() {
        // Comparing bytes against a digest this crate did not produce would report every
        // block of a healthy filesystem as damaged, which says nothing true about it.
        for value in [1u16, 2, 3, 9] {
            let sb = SuperBlock {
                csum_type: ChecksumType::from_value(value),
                ..a_superblock()
            };
            assert!(matches!(
                check_readable(&sb),
                Err(ReadError::UnsupportedChecksum { .. })
            ));
        }
    }

    #[test]
    fn a_superblock_describing_another_filesystems_device_is_refused() {
        let mut sb = a_superblock();
        sb.dev_item.fsid = [0x22; 16];
        assert!(matches!(
            check_readable(&sb),
            Err(ReadError::BadSuperblock { .. })
        ));
        // And one whose trees have no roots at all, which would otherwise fail one call later
        // with an unmapped address and no account of why.
        for sb in [
            SuperBlock {
                root: 0,
                ..a_superblock()
            },
            SuperBlock {
                chunk_root: 0,
                ..a_superblock()
            },
        ] {
            assert!(matches!(
                check_readable(&sb),
                Err(ReadError::BadSuperblock { .. })
            ));
        }
    }

    // ── Opening a forged filesystem: the copies of the superblock, and the policy over them ──

    use crate::btrfs::forge::{CHUNK_LOGICAL, DEVICE_BYTES, Forge, ROOT_TREE_AT};

    /// Two mebibytes past the second location, so a forged device holds two copies and not
    /// three. Sparse, so it costs the pages it writes rather than its length.
    const TWO_MIRRORS: u64 = (64 << 20) + (2 << 20);

    /// A byte past the third location plus a whole superblock, which is where the count
    /// becomes three — the boundary that has two readings a superblock apart.
    const THREE_MIRRORS: u64 = (256 << 30) + SUPER_INFO_SIZE as u64;

    #[test]
    fn a_device_carries_every_copy_of_the_superblock_it_has_room_for_and_no_other() {
        // The mirror-count rule read back from the reader's side. The third location is a quarter of a
        // terabyte in, and the device the gate builds is sparse — so the boundary that costs
        // the tier with host tools a file the host may refuse to create costs nothing here.
        for (bytes, expected) in [(DEVICE_BYTES, 1), (TWO_MIRRORS, 2), (THREE_MIRRORS, 3)] {
            let volume = Volume::open(Forge::of_size(bytes).source())
                .unwrap_or_else(|e| panic!("a {bytes}-byte device: {e}"));
            let present = volume
                .mirrors()
                .iter()
                .filter(|m| matches!(m, Mirror::Present { .. }))
                .count();
            assert_eq!(present, expected, "a device of {bytes} bytes");
            assert!(
                volume.mirrors()[expected..]
                    .iter()
                    .all(|m| *m == Mirror::OutsideDevice),
                "every location past the last copy is outside the device"
            );
        }
    }

    #[test]
    fn a_copy_is_written_only_where_the_device_holds_all_of_it() {
        // "Large enough" has two readings and they differ by one copy: a device of exactly
        // the third location has no room for the superblock that would start there.
        let exact = Volume::open(Forge::of_size(256 << 30).source()).expect("a formatted device");
        assert_eq!(exact.mirrors()[2], Mirror::OutsideDevice);
        let one_more =
            Volume::open(Forge::of_size(THREE_MIRRORS).source()).expect("a formatted device");
        assert!(matches!(one_more.mirrors()[2], Mirror::Present { .. }));
    }

    #[test]
    fn the_newest_copy_of_the_superblock_is_the_one_the_filesystem_is_read_through() {
        // The filesystem's own rule. A copy left behind by a torn write must not be the one a
        // reader believes, whichever location it sits at.
        let mut forge = Forge::of_size(TWO_MIRRORS);
        forge.amend_superblock(1, |sb| {
            sb.generation = 99;
            sb.root = CHUNK_LOGICAL;
        });
        let volume = Volume::open_with(
            forge.source(),
            OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a filesystem whose copies disagree still opens leniently");
        assert_eq!(volume.superblock().generation, 99);
        assert_eq!(volume.superblock().root, CHUNK_LOGICAL);
        assert_eq!(
            volume.mirrors()[0].generation(),
            Some(super::super::forge::GENERATION)
        );
        assert_eq!(volume.mirrors()[1].generation(), Some(99));
    }

    #[test]
    fn a_copy_that_disagrees_with_the_live_one_is_refused_strictly_and_recorded_leniently() {
        // Each way a copy can be wrong, and each is a refusal under a strict read: what a
        // strict read returns is a filesystem whose every field it recognized, and a copy of
        // the superblock is a field of it.
        /// What a row does to a copy of the superblock, and what a lenient read must then
        /// say about it.
        type Damage = (&'static str, Box<dyn Fn(&mut Forge)>, Mirror);

        let damage: [Damage; 3] = [
            (
                "a checksum that no longer covers it",
                Box::new(|f: &mut Forge| {
                    f.break_superblock(1);
                }),
                Mirror::Damaged,
            ),
            (
                "a copy left behind by an earlier transaction",
                Box::new(|f: &mut Forge| {
                    f.amend_superblock(1, |sb| sb.generation = 1);
                }),
                Mirror::Present { generation: 1 },
            ),
            (
                "a copy written somewhere other than where it says it is",
                Box::new(|f: &mut Forge| {
                    f.copy_superblock(0, 1);
                }),
                Mirror::Misplaced { bytenr: MIRRORS[0] },
            ),
        ];
        for (what, apply, expected) in damage {
            let mut forge = Forge::of_size(TWO_MIRRORS);
            apply(&mut forge);
            let strict = Volume::open(forge.source()).err();
            assert!(
                matches!(
                    strict,
                    Some(ReadError::MirrorDisagreement { mirror: 1, .. })
                ),
                "{what}: {strict:?}"
            );
            let lenient = Volume::open_with(
                forge.source(),
                OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap_or_else(|e| panic!("{what} opens leniently: {e}"));
            assert_eq!(lenient.mirrors()[1], expected, "{what}");
            assert_eq!(
                lenient.superblock().generation,
                super::super::forge::GENERATION
            );
        }
    }

    #[test]
    fn a_damaged_first_copy_is_read_through_the_second_rather_than_refused_outright() {
        // The reason there is more than one copy. Under a lenient read the filesystem opens
        // through the surviving copy and says which one was damaged.
        let mut forge = Forge::of_size(TWO_MIRRORS);
        forge.break_superblock(0);
        let volume = Volume::open_with(
            forge.source(),
            OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("the second copy is intact");
        assert_eq!(volume.mirrors()[0], Mirror::Damaged);
        assert!(matches!(volume.mirrors()[1], Mirror::Present { .. }));

        // And with every copy damaged there is nothing to read through, which is a checksum
        // refusal rather than "these bytes are not a btrfs" — the two say different things
        // about a source and a caller pointed at the wrong file wants the second.
        let mut forge = Forge::of_size(TWO_MIRRORS);
        forge.break_superblock(0).break_superblock(1);
        assert!(matches!(
            Volume::open_with(
                forge.source(),
                OpenOptions::new().policy(ReadPolicy::Lenient)
            )
            .err(),
            Some(ReadError::BadChecksum {
                object: "superblock",
                ..
            })
        ));
    }

    #[test]
    fn a_source_with_no_btrfs_in_it_says_so_rather_than_naming_a_structure() {
        let empty = std::io::Cursor::new(vec![0u8; 1 << 20]);
        assert!(matches!(
            Volume::open(empty).err(),
            Some(ReadError::NotBtrfs)
        ));
        // A source too short to hold even the first location is the same answer: not ours.
        let tiny = std::io::Cursor::new(vec![0u8; 1024]);
        assert!(matches!(
            Volume::open(tiny).err(),
            Some(ReadError::NotBtrfs)
        ));
    }

    #[test]
    fn a_source_shorter_than_the_device_it_describes_is_reported_as_that() {
        // The image in hand is not the whole of the filesystem it claims to be. The first
        // copy still reads, so this is a statement about the copies that do not.
        let forge = Forge::of_size(TWO_MIRRORS);
        let short = forge.truncated(2 << 20);
        assert!(matches!(
            Volume::open(short).err(),
            Some(ReadError::MirrorDisagreement { mirror: 1, .. })
        ));
        let short = forge.truncated(2 << 20);
        let lenient = Volume::open_with(short, OpenOptions::new().policy(ReadPolicy::Lenient))
            .expect("lenient");
        assert_eq!(lenient.mirrors()[1], Mirror::Truncated);
    }

    #[test]
    fn a_filesystem_inside_a_partition_is_read_from_where_the_caller_says_it_begins() {
        // Every location is relative to the filesystem rather than to the source, so a base
        // shifts all of them — and the self-address check must be made against the offset
        // within the filesystem or a partition would look misplaced.
        const BASE: u64 = 1 << 20;
        let forge = Forge::new();
        let mut device = vec![0u8; BASE as usize];
        let mut source = forge.source();
        std::io::Read::read_to_end(&mut source, &mut device).expect("the forged device");
        let mut volume =
            Volume::open_with(std::io::Cursor::new(device), OpenOptions::new().base(BASE))
                .expect("a filesystem a mebibyte into its source");
        assert!(matches!(volume.mirrors()[0], Mirror::Present { .. }));
        let root = volume.root_tree();
        assert_eq!(root.bytenr, ROOT_TREE_AT);
        volume
            .tree(root)
            .count_items()
            .expect("the root tree reads");
    }

    #[test]
    fn the_chunk_tree_is_read_through_the_bootstrap_and_completes_the_map() {
        // The bootstrap carries the system chunk and the chunk tree repeats it, so meeting it
        // again is the ordinary case rather than an overlap. What must not happen is the map
        // gaining a second entry for one address.
        let volume = Volume::open(Forge::new().source()).expect("a forged filesystem");
        assert_eq!(volume.chunk_map().len(), 1);
        let chunk = &volume.chunk_map().chunks()[0];
        assert_eq!(chunk.logical, CHUNK_LOGICAL);
        assert_eq!(chunk.copies.len(), 1);
        assert_ne!(
            chunk.copies[0], chunk.logical,
            "the mapping is not the identity"
        );
    }

    #[test]
    fn a_checksum_is_only_held_to_hold_for_the_algorithm_that_produced_it() {
        let mut object = vec![0u8; SUPER_INFO_SIZE];
        object[64..72].copy_from_slice(&ondisk::MAGIC);
        let digest = ondisk::checksum(&object);
        object[..4].copy_from_slice(&digest.to_le_bytes());
        assert!(checksum_holds(&object, ChecksumType::CRC32C));

        // A byte anywhere past the field changes it.
        object[100] ^= 0xff;
        assert!(!checksum_holds(&object, ChecksumType::CRC32C));
        object[100] ^= 0xff;
        assert!(checksum_holds(&object, ChecksumType::CRC32C));

        // Something in the padding behind a four-byte digest is a field written by a tool
        // that did not agree about the algorithm.
        object[7] = 1;
        assert!(!checksum_holds(&object, ChecksumType::CRC32C));
        object[7] = 0;

        // And an algorithm this crate does not compute never answers "it holds".
        assert!(!checksum_holds(&object, ChecksumType::SHA256));
    }
}
