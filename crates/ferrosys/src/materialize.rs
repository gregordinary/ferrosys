//! The materializer: turn a plan, an allocator, and an inode model into image
//! bytes.
//!
//! This is the layer that does I/O in the sense of producing the final byte image;
//! everything it decides was decided by the pure layers it consumes. It places each
//! inode's data through the allocator, writes the inode table, block and inode
//! bitmaps, group descriptors, and the primary and backup superblocks, and threads
//! the reserved descriptor blocks through the resize inode's double-indirect map so
//! the image can grow safely.
//!
//! Bytes go to any seekable writer. [`format()`] collects them into an in-memory
//! [`Image`]; [`format_to()`] streams them straight out, touching only the blocks it
//! writes, so a filesystem far larger than memory can be created into a file that
//! stays sparse. Nothing is ever read back from the destination.
//!
//! Every checksum field is written through the [`Checksummer`] seam: with
//! `metadata_csum` set the seam is a real crc32c and each metadata object — the
//! superblock and its backups, the group descriptors, inodes, block and inode
//! bitmaps, directory blocks, and attribute blocks — is checksummed as it is laid
//! down; without it the seam zeroes those fields. Which seam is active is the only
//! thing that changes between the two, not this code.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

use crate::alloc::{AllocError, Allocator};
use crate::csum::{Checksummer, Crc32c, CsumScheme, NullCsum};
use crate::dir::{DirBlock, DirBlockKind, DirError, DirLayout, HtreeDir, LinearDir};
use crate::extent::{
    ExtentError, build_leaves, build_tree, node_capacity, plan_tree, tail_offset, write_node,
};
use crate::feature::{FeatureSet, LARGE_FILE_MIN_SIZE, Profile, resize_inode_size};
use crate::geometry::{
    BlockRange, GeometryError, GrowReservation, InodeCount, Layout, PlanRequest, ReservedRatio,
    plan_layout,
};
use crate::hash::{HashSignedness, HashVersion};
use crate::journal::{self, JournalSize};
use crate::model::{
    Content, FIRST_USER_INO, FsModel, LOST_FOUND_INO, ModelConfig, ModelError, ModelInode,
    build_model,
};
use crate::ondisk::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, DIR_TAIL_LEN, DX_ENTRY_LEN, DX_TAIL_LEN,
    DirEntry, GroupDescriptor, Inode, InodeFlags, ParseError, SuperBlock, Timestamp, Xattr,
    encode_block, encode_device, encode_inline, extra_isize_for, get_u16, orphan_entries_len,
    orphan_tail_bytes, put_u16, put_u32, split_for_storage, write_dir_tail, write_dx_tail,
};
use crate::source::Source;

/// The reserved inode mapping the reserved group-descriptor-table blocks.
const RESIZE_INO: u32 = 7;

/// The reserved inode holding the journal (`s_journal_inum`).
const JOURNAL_INO: u32 = 8;

/// The inode holding the orphan file (`s_orphan_file_inum`). It is not one of the
/// reserved inodes: the orphan file is allocated at format time, so it takes the first
/// inode past `/lost+found` — which is why a source's entries begin one higher when
/// `orphan_file` is on.
const ORPHAN_INO: u32 = FIRST_USER_INO;

/// The inode number a source's entries start at: the first past `/lost+found`, moved up
/// by the inodes the feature set claims for itself at format time.
fn first_user_inode(feature: &FeatureSet) -> u32 {
    if feature.has_orphan_file() {
        ORPHAN_INO + 1
    } else {
        FIRST_USER_INO
    }
}

/// The orphan file's size in blocks: one block per 4096 filesystem blocks, held between
/// 32 and 512 blocks. The floor keeps concurrent deletions on a small filesystem from
/// contending for the few entries a strict ratio would give them, and the ceiling stops
/// a large one from reserving space for far more orphans than can ever exist at once.
///
/// It is a count of blocks, not of bytes, so a filesystem of a given block count is
/// given the same orphan file whatever its block size.
fn orphan_file_blocks(total_blocks: u64) -> u32 {
    const RATIO: u64 = 4096;
    const MIN: u64 = 32;
    const MAX: u64 = 512;
    (total_blocks / RATIO).clamp(MIN, MAX) as u32
}

/// What the kernel does when it detects an error on the mounted filesystem, recorded in
/// the superblock's `s_errors` field (offset `0x3c`) and consulted by the kernel at mount
/// time.
///
/// This is a runtime policy the image carries, not a property of the layout: every value
/// produces a filesystem this crate considers equally correct, differing only in that one
/// superblock field and the checksum computed over it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ErrorBehavior {
    /// Note the error and carry on (`s_errors = 1`) — the kernel's own default, and this
    /// crate's.
    #[default]
    Continue,
    /// Remount the filesystem read-only (`s_errors = 2`), so a detected inconsistency
    /// cannot spread through further writes.
    RemountReadOnly,
    /// Panic the kernel (`s_errors = 3`), halting the machine on any filesystem error.
    Panic,
}

impl ErrorBehavior {
    /// The on-disk `s_errors` value this policy is stored as.
    const fn to_s_errors(self) -> u16 {
        match self {
            Self::Continue => 1,
            Self::RemountReadOnly => 2,
            Self::Panic => 3,
        }
    }
}

/// Options controlling a format that do not come from the source or the size.
///
/// Build one with [`new`](Self::new), which takes the three identity inputs every image
/// needs and defaults the rest, then set the fields a format departs from the default on.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The 16-byte filesystem UUID (`s_uuid`), supplied by the caller.
    pub uuid: [u8; 16],
    /// The filesystem creation and write time.
    pub time: Timestamp,
    /// The 16-byte directory-hash seed (`s_hash_seed`).
    pub hash_seed: [u8; 16],
    /// The algorithm a hash-indexed directory orders its names by
    /// (`s_def_hash_version`). Defaults to [`HashVersion::HalfMd4`].
    pub hash_version: HashVersion,
    /// Whether a name's bytes are read as signed or unsigned when hashed
    /// (`s_flags`). Defaults to [`HashSignedness::Unsigned`], which makes a name's
    /// hash — and so the image's bytes — independent of the machine that wrote it.
    ///
    /// Set it to [`HashSignedness::Signed`] to match an image built by a tool that
    /// takes its signedness from the host's `char`, which is signed on x86 and
    /// unsigned on arm64. An image records the choice, so either is read correctly.
    pub hash_signedness: HashSignedness,
    /// How much reserved descriptor headroom to build in, sizing the reserved GDT
    /// blocks that make the image resize-safe. Defaults to [`GrowReservation::Max`].
    pub grow: GrowReservation,
    /// How many inodes to provide. Defaults to [`InodeCount::Auto`], the size-driven
    /// count; an override sets the density or the count directly.
    pub inodes: InodeCount,
    /// The share of blocks held back for the super-user (`s_r_blocks_count`). Defaults to
    /// [`ReservedRatio::DEFAULT`], 5%.
    pub reserved: ReservedRatio,
    /// The volume label (`s_volume_name`), NUL-padded to sixteen bytes; all zero for an
    /// unlabelled filesystem, which is the default.
    pub volume_name: [u8; 16],
    /// The feature profile to emit.
    pub feature: FeatureSet,
    /// What the kernel does on a detected filesystem error (`s_errors`). Defaults to
    /// [`ErrorBehavior::Continue`], the kernel's own default.
    pub errors: ErrorBehavior,
    /// How large the journal is, when the feature set carries a journal. Ignored when
    /// `has_journal` is off. Defaults to [`JournalSize::Auto`].
    pub journal: JournalSize,
    /// When set, every inode's access, change, modification, and creation time is
    /// forced to this value — the source-derived inodes and the reserved structural
    /// ones (resize, journal, orphan) alike — overriding the per-entry times a source
    /// supplies. This makes output byte-reproducible regardless of the source's
    /// timestamps: the clamp a build takes when reproducibility outranks timestamp
    /// fidelity. Unset, each source-derived inode keeps its own times and the
    /// structural inodes take the format [`time`](Self::time).
    pub fixed_time: Option<Timestamp>,
}

impl FormatOptions {
    /// Reject a format-time clock the superblock's 32-bit time fields cannot hold, so a
    /// far-future creation time is refused rather than silently truncated to 1970-plus.
    fn validate_format_time(&self) -> Result<(), FormatError> {
        let secs = self.time.secs;
        if secs < 0 || secs > u64::from(u32::MAX) as i64 {
            return Err(FormatError::FormatTimeOutOfRange { secs });
        }
        Ok(())
    }

    /// Options for the default feature profile ([`FeatureSet::DEFAULT`]) with the
    /// given identity inputs. The grow reservation defaults to [`GrowReservation::Max`]
    /// — the fail-safe choice that reserves the most online-grow headroom the format
    /// allows; set [`grow`](Self::grow) to [`GrowReservation::UpTo`] for a known
    /// deployment target or [`GrowReservation::None`] to reserve nothing.
    #[must_use]
    pub fn new(uuid: [u8; 16], time: Timestamp, hash_seed: [u8; 16]) -> Self {
        Self {
            uuid,
            time,
            hash_seed,
            hash_version: HashVersion::default(),
            hash_signedness: HashSignedness::default(),
            grow: GrowReservation::default(),
            inodes: InodeCount::default(),
            reserved: ReservedRatio::default(),
            volume_name: [0; 16],
            feature: FeatureSet::default(),
            errors: ErrorBehavior::default(),
            journal: JournalSize::Auto,
            fixed_time: None,
        }
    }

    /// The geometry planner's inputs for a filesystem of `size_bytes` under these
    /// options: the feature set and the three sizing knobs, gathered into the request
    /// [`plan_layout`] takes.
    ///
    /// This is the one place the format options become a plan, so a geometry knob added
    /// here reaches the planner once rather than at every entry point that formats.
    #[must_use]
    pub const fn plan_request(&self, size_bytes: u64) -> PlanRequest {
        PlanRequest::new(size_bytes, self.feature)
            .grow(self.grow)
            .inodes(self.inodes)
            .reserved(self.reserved)
    }

    /// Seed the feature set from an ext filesystem profile, replacing
    /// [`feature`](Self::feature) with the baseline words `mke2fs -t` writes for that
    /// family. Sugar for `options.feature = profile.feature_set()`, chainable from
    /// [`new`](Self::new); set individual features on [`feature`](Self::feature) afterward
    /// to depart from the baseline.
    #[must_use]
    pub fn profile(mut self, profile: Profile) -> Self {
        self.feature = profile.feature_set();
        self
    }
}

/// A failure formatting an image.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// Writing to the destination failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Planning the geometry failed.
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    /// Building the inode model failed.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// Packing a directory failed.
    #[error(transparent)]
    Dir(#[from] DirError),
    /// Building an extent tree failed.
    #[error(transparent)]
    Extent(#[from] ExtentError),
    /// Allocating blocks failed.
    #[error(transparent)]
    Alloc(#[from] AllocError),
    /// Serializing an on-disk structure failed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The source needs more inodes than the geometry provides.
    #[error("source needs {needed} inodes but the filesystem has {available}")]
    #[non_exhaustive]
    TooManyInodes {
        /// Inodes the source needs.
        needed: u32,
        /// Inodes the geometry provides.
        available: u32,
    },
    /// A journal was requested but the size is below the minimum jbd2 accepts, or the
    /// filesystem is too small to hold even the minimum journal.
    #[error("journal of {requested} blocks is below the minimum of {minimum}")]
    #[non_exhaustive]
    JournalTooSmall {
        /// Journal blocks requested (zero when the filesystem is too small for any).
        requested: u32,
        /// The minimum journal size in blocks.
        minimum: u32,
    },
    /// A regular file the filesystem provides for itself reaches
    /// [`LARGE_FILE_MIN_SIZE`] on a feature set without `large_file`, which is the
    /// feature that describes such a file. Only a journal sized past the bound by an
    /// explicit [`JournalSize::Blocks`] reaches this: the resize inode's pairing is
    /// settled at plan time by [`FeatureSet::validate`], the orphan file is bounded far
    /// below it, and a source entry is refused by the model, which can name its path.
    #[error("the {what} is {size} bytes, a large file on a filesystem without large_file")]
    #[non_exhaustive]
    LargeFileWithoutFeature {
        /// The structure whose size crosses the bound.
        what: &'static str,
        /// The size it declares.
        size: u64,
    },
    /// A block the resize inode must map lies past what its block map addresses. The
    /// map is a classic 32-bit block map, and the geometry reserves descriptor blocks
    /// only on a filesystem a 32-bit block number spans, so a block past that reaching
    /// the map means the two disagree. It is refused rather than truncated into a
    /// pointer at the wrong block.
    #[error("the resize inode's 32-bit block map cannot name block {block}")]
    #[non_exhaustive]
    ResizeMapNeeds32BitBlocks {
        /// The block the map would have had to name.
        block: u64,
    },
    /// The inode the orphan file takes is already held by an entry, so writing the file
    /// there would displace it — leaving a directory entry that names the orphan file
    /// rather than the entry it was written for.
    ///
    /// Formatting derives the first entry's inode number from the feature set, so the
    /// two cannot disagree. The check stands guard over that derivation: a feature added
    /// later that claims an inode of its own must move the entries up, and until it does,
    /// this refuses the image rather than writing a directory that points at the wrong
    /// file.
    #[error("the orphan file's inode {inode} is already held by an entry")]
    #[non_exhaustive]
    OrphanInodeInUse {
        /// The contested inode number.
        inode: u32,
    },
    /// The image does not fit in memory on this platform: its byte count exceeds what a
    /// `usize` addresses, which a 32-bit target reaches at 4 GiB. [`format_to`] streams an
    /// image of any size to a seekable destination and is the path for one this large.
    #[error(
        "an image of {bytes} bytes exceeds what this platform addresses in memory; \
         stream it with format_to"
    )]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// The image's size in bytes.
        bytes: u64,
    },
    /// The format-time clock ([`FormatOptions::time`]) lies outside the range the
    /// superblock's 32-bit time fields hold: seconds in `[0, 2^32)`, from 1970 to 2106.
    /// It is refused rather than truncated to a different instant. Per-file timestamps
    /// span a wider range; this bound is on the filesystem's own creation clock.
    #[error("format time of {secs}s is outside the superblock range [0, 2^32) seconds")]
    #[non_exhaustive]
    FormatTimeOutOfRange {
        /// The out-of-range seconds value.
        secs: i64,
    },
}

/// A block number as the resize inode's block map stores it.
///
/// The map is 32 bits wide, so every block it names must be one a 32-bit block number
/// addresses. Converting through this function refuses a block past that rather than
/// silently truncating it into a pointer at the wrong block.
fn map_block(block: u64) -> Result<u32, FormatError> {
    u32::try_from(block).map_err(|_| FormatError::ResizeMapNeeds32BitBlocks { block })
}

/// The classic (ext2/ext3) block map's twelve direct pointers, filling the first twelve
/// of the inode's fifteen block-area words. The remaining three hold the single-,
/// double-, and triple-indirect roots.
const DIRECT_BLOCKS: usize = 12;

/// Levels of indirection above the direct pointers: single, double, and triple.
const INDIRECT_LEVELS: usize = 3;

/// A finished filesystem image: the bytes, and the geometry that produced them.
pub struct Image {
    /// The complete image bytes, `total_blocks * block_size` long.
    bytes: Vec<u8>,
    /// The layout the image was written against.
    layout: Layout,
}

impl Image {
    /// The image bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the image, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The layout the image was written against.
    #[must_use]
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Write the image to `w`.
    ///
    /// # Errors
    ///
    /// Any I/O error from `w`.
    pub fn write_to(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        w.write_all(&self.bytes)
    }
}

/// Format a filesystem of `size_bytes` populated from `source`, assembling the whole
/// image in memory.
///
/// The image is held as one buffer of its full size, so this needs as much memory as the
/// filesystem is large. [`format_to`] writes the same bytes to a seekable destination
/// without ever holding them all.
///
/// # Errors
///
/// A [`FormatError`] if the geometry, model, allocation, or serialization cannot be
/// realized, or [`FormatError::ImageTooLargeInMemory`] if the image is larger than this
/// platform addresses.
pub fn format(
    source: impl Source,
    size_bytes: u64,
    options: FormatOptions,
) -> Result<Image, FormatError> {
    let (layout, model) = prepare(source, size_bytes, &options)?;
    let feature = options.feature;

    // The whole image is one buffer, so its size must be one this platform can address:
    // a 32-bit target holds no 4 GiB image, and a cast would silently size the buffer to
    // the low bits of the count and write a filesystem into the wrong number of bytes.
    let image_bytes = layout.total_blocks * u64::from(layout.block_size);
    let len = usize::try_from(image_bytes)
        .map_err(|_| FormatError::ImageTooLargeInMemory { bytes: image_bytes })?;
    let mut sink = std::io::Cursor::new(vec![0u8; len]);
    let mut writer = Writer::new(&layout, &feature, options, &mut sink);
    writer.materialize(&model)?;
    Ok(Image {
        bytes: sink.into_inner(),
        layout,
    })
}

/// Format a filesystem of `size_bytes` populated from `source`, streaming its bytes
/// into `sink` and returning the layout they realize.
///
/// Only the blocks the filesystem actually uses are written, and nothing is read
/// back, so a file destination stays sparse and the whole image never exists in
/// memory. The sink is extended to the filesystem's full size, and every byte it
/// holds that is not written must read back as zero — a freshly created file, or one
/// truncated to zero length, satisfies that.
///
/// # Memory
///
/// Three things are held while the image streams out, and none of them is the image:
///
/// - **The entry list.** Every [`SourceEntry`](crate::source::SourceEntry) the source yields — its path, metadata,
///   and extended attributes — is materialized before the first block is written, and the
///   inode model built from it is held until the last one is. This grows with the number
///   of entries, not with their size.
/// - **A file's contents, while it is placed.** How long that is depends on what the
///   source supplies. A [`FileContent::Owned`](crate::source::FileContent::Owned) entry
///   holds its bytes from the moment the source is built, so a list of them costs the sum
///   of every file. A [`FileContent::Range`](crate::source::FileContent::Range) is read at
///   placement and dropped after, so a list of them costs the largest single file.
///   [`ArchiveSource::from_path`](crate::archive::ArchiveSource::from_path) is the
///   difference for a tar source.
/// - **The allocator's used-block bitmap**, for the whole run, at one bit per filesystem
///   block: `total_blocks / 8` bytes, 128 MiB for a 4 TiB image at a 4 KiB block.
///
/// So peak memory grows with the entry count, the largest file, and the filesystem's
/// block count — never with the image's size in bytes.
///
/// # Errors
///
/// A [`FormatError`] if the geometry, model, allocation, or serialization cannot be
/// realized, or if writing to `sink` fails.
pub fn format_to(
    source: impl Source,
    size_bytes: u64,
    options: FormatOptions,
    mut sink: impl Write + Seek,
) -> Result<Layout, FormatError> {
    let (layout, model) = prepare(source, size_bytes, &options)?;
    let feature = options.feature;
    let mut writer = Writer::new(&layout, &feature, options, &mut sink);
    writer.materialize(&model)?;
    writer.extend_to_full_size()?;
    Ok(layout)
}

/// Everything a format decides before a byte is written: the layout the geometry planner
/// produces and the inode model the source builds, checked against each other.
///
/// Both entry points call this, so a knob added to [`FormatOptions`] reaches them both at
/// once. Two paths that derived this separately would be two paths that could disagree,
/// and a disagreement between them is not a compile error — it is one entry point
/// formatting differently from the other.
fn prepare(
    source: impl Source,
    size_bytes: u64,
    options: &FormatOptions,
) -> Result<(Layout, FsModel), FormatError> {
    options.validate_format_time()?;
    let feature = options.feature;
    let layout = plan_layout(&options.plan_request(size_bytes))?;
    let mut config = ModelConfig::new(feature, first_user_inode(&feature), options.time);
    config.fixed_time = options.fixed_time;
    let model = build_model(source, config)?;
    if model.used_inode_count() > layout.total_inodes {
        return Err(FormatError::TooManyInodes {
            needed: model.used_inode_count(),
            available: layout.total_inodes,
        });
    }
    Ok((layout, model))
}

/// The mutable state of one format: the destination, the allocator, and the inodes
/// as they are built.
struct Writer<'a, W> {
    layout: &'a Layout,
    feature: &'a FeatureSet,
    options: FormatOptions,
    alloc: Allocator,
    /// Where the bytes go. Written at absolute offsets and never read back.
    sink: W,
    /// One past the highest byte offset written, so the destination can be extended
    /// to the filesystem's full size when the last block holds nothing.
    written_end: u64,
    block_size: usize,
    /// The metadata-checksum seam: [`Crc32c`] when `metadata_csum` is on, otherwise
    /// [`NullCsum`], which zeroes every checksum. Held dynamically so the per-object
    /// checksum construction sites read the same seam regardless of which is active.
    csum: Box<dyn Checksummer>,
    /// The directory-layout seam: [`HtreeDir`] when `dir_index` is on, otherwise
    /// [`LinearDir`]. A directory small enough to need no index is packed linearly
    /// by either.
    dir: Box<dyn DirLayout>,
    /// The serialized inodes, by number.
    inodes: BTreeMap<u32, Inode>,
    /// The primary descriptor table, retained to copy into the backup groups.
    gdt_bytes: Vec<u8>,
    /// The journal inode's block map and size, backed up into the superblock's
    /// `s_jnl_blocks`. `None` until the journal is materialized, and when the feature
    /// set carries no journal.
    journal_backup: Option<[u32; 17]>,
}

impl<'a, W: Write + Seek> Writer<'a, W> {
    fn new(layout: &'a Layout, feature: &'a FeatureSet, options: FormatOptions, sink: W) -> Self {
        let block_size = layout.block_size as usize;
        let csum: Box<dyn Checksummer> = if feature.has_metadata_csum() {
            Box::new(Crc32c::new(&options.uuid))
        } else {
            Box::new(NullCsum)
        };
        let dir: Box<dyn DirLayout> = if feature.has_dir_index() {
            Box::new(HtreeDir {
                seed: options.hash_seed,
                version: options.hash_version,
                signedness: options.hash_signedness,
                checksums: feature.has_metadata_csum(),
            })
        } else {
            Box::new(LinearDir {
                tail_len: if feature.has_metadata_csum() {
                    DIR_TAIL_LEN
                } else {
                    0
                },
            })
        };
        Self {
            layout,
            feature,
            options,
            alloc: Allocator::new(layout),
            sink,
            written_end: 0,
            block_size,
            csum,
            dir,
            inodes: BTreeMap::new(),
            gdt_bytes: Vec::new(),
            journal_backup: None,
        }
    }

    fn materialize(&mut self, model: &FsModel) -> Result<(), FormatError> {
        // Data first: allocating file, directory, symlink, and resize-map blocks
        // settles the allocator before free counts and bitmaps are read back.
        for minode in model.inodes.values() {
            let inode = self.materialize_inode(minode)?;
            self.inodes.insert(minode.number, inode);
        }
        self.materialize_reserved_inodes()?;

        // Then the fixed structures, in any order — they read the settled state.
        self.write_inode_tables()?;
        self.write_bitmaps_and_descriptors(model)?;
        self.write_superblocks(model)?;
        Ok(())
    }

    /// Write `bytes` at absolute byte offset `offset`.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        self.sink.seek(SeekFrom::Start(offset))?;
        self.sink.write_all(bytes)?;
        self.written_end = self.written_end.max(offset + bytes.len() as u64);
        Ok(())
    }

    /// Make the destination as long as the filesystem, for the case where its final
    /// blocks hold nothing and so were never written.
    fn extend_to_full_size(&mut self) -> Result<(), FormatError> {
        let size = self.layout.total_blocks * u64::from(self.layout.block_size);
        if self.written_end < size {
            // The last byte was never written, so it is already zero; writing a zero
            // there only grows the destination.
            self.write_at(size - 1, &[0])?;
        }
        Ok(())
    }

    /// A blank inode carrying the extra area this filesystem's inode size affords.
    ///
    /// Every inode this writer builds starts here, so the extra area is decided in one
    /// place from `s_inode_size` rather than assumed. At 128 bytes there is no extra
    /// area, and the inode carries no creation time, no sub-second timestamps, no
    /// inline attributes, and no `i_checksum_hi`.
    fn new_inode(&self) -> Inode {
        Inode::empty(self.feature.inode_size)
    }

    /// Stamp a reserved structural inode's four timestamps (resize, journal, orphan).
    /// The fixed-time clamp forces the value when set, otherwise the format time stands
    /// — the same resolution the model gives a source-derived inode, so the clamp
    /// reaches every inode and leaves no source-independent time unforced.
    fn stamp_structural_times(&self, inode: &mut Inode) {
        let t = self.options.fixed_time.unwrap_or(self.options.time);
        inode.atime = t;
        inode.ctime = t;
        inode.mtime = t;
        inode.crtime = t;
    }

    /// Build and write one model inode, returning its on-disk form.
    fn materialize_inode(&mut self, minode: &ModelInode) -> Result<Inode, FormatError> {
        let mut inode = self.new_inode();
        inode.mode = minode.mode;
        inode.uid = minode.uid;
        inode.gid = minode.gid;
        inode.links_count = minode.links_count;
        inode.atime = minode.atime;
        inode.ctime = minode.ctime;
        inode.mtime = minode.mtime;
        inode.crtime = minode.crtime;

        match &minode.content {
            Content::Directory(children) => {
                let entries: Vec<DirEntry> = children
                    .iter()
                    .map(|c| DirEntry {
                        inode: c.inode,
                        file_type: c.file_type,
                        name: c.name.clone(),
                    })
                    .collect();
                let mut blocks = self.dir.build_blocks(&entries, self.block_size)?;
                // /lost+found is preallocated to 16 KiB so a repair has room to
                // reconnect orphaned inodes. Its entries fit in one block, so it is
                // never indexed and the padding is plain entry blocks.
                if minode.number == LOST_FOUND_INO {
                    let min_blocks = (16 * 1024usize).div_ceil(self.block_size);
                    while blocks.len() < min_blocks {
                        blocks.push(DirBlock {
                            bytes: self.empty_dir_block(),
                            kind: DirBlockKind::Entries,
                        });
                    }
                }
                let indexed = blocks
                    .iter()
                    .any(|b| matches!(b.kind, DirBlockKind::Index { .. }));
                self.write_dir_checksums(minode.number, &mut blocks);
                let bytes: Vec<Vec<u8>> = blocks.into_iter().map(|b| b.bytes).collect();
                self.place_blocks(minode.number, &mut inode, &bytes)?;
                if indexed {
                    inode.flags = inode.flags | InodeFlags::INDEX;
                }
            }
            Content::File(content) => {
                // The bytes are read here, at placement, rather than held from the moment
                // the source was built: peak memory is the largest single file rather than
                // every file at once. A source that supplied them owned pays nothing extra
                // — the read hands back what it already holds.
                let bytes = content.read()?;
                let blocks = chunk_into_blocks(&bytes, self.block_size);
                self.place_blocks(minode.number, &mut inode, &blocks)?;
                inode.size = content.len();
            }
            Content::SlowSymlink(target) => {
                let blocks = chunk_into_blocks(target, self.block_size);
                self.place_blocks(minode.number, &mut inode, &blocks)?;
                inode.size = target.len() as u64;
            }
            Content::FastSymlink(target) => {
                // The target lives inline in the block area; no data block, no
                // extents flag.
                inode.block[..target.len()].copy_from_slice(target);
                inode.size = target.len() as u64;
            }
            Content::Device { major, minor } => {
                // A device node stores its number in the block area and maps no
                // blocks; the file type (char vs block) is already in the mode.
                let (b0, b1) = encode_device(*major, *minor);
                put_u32(&mut inode.block, 0, b0);
                put_u32(&mut inode.block, 4, b1);
            }
            Content::Special => {
                // A FIFO or socket has no data and no block map.
            }
        }
        self.encode_xattrs(&mut inode, &minode.xattrs)?;
        Ok(inode)
    }

    /// Attach an inode's extended attributes: as many as fit go inline in the inode,
    /// and the rest spill to a freshly allocated external block charged to the inode.
    /// The split is [`split_for_storage`]'s, the same one the model validated against,
    /// so a set that reaches here always fits.
    ///
    /// The model also settled that this filesystem holds attributes at all: a non-empty
    /// set on a feature word without `ext_attr` is refused there, naming the entry, so
    /// what reaches here is a set the emitted feature words describe.
    fn encode_xattrs(&mut self, inode: &mut Inode, xattrs: &[Xattr]) -> Result<(), FormatError> {
        if xattrs.is_empty() {
            return Ok(());
        }
        // What is left of the inode after the classic fields and the extra area. A
        // 128-byte inode has none, so its attributes all spill.
        let region_len = inode.inline_xattr_capacity(self.feature.inode_size);
        let (inline, spilled) = split_for_storage(xattrs, region_len);
        if !inline.is_empty() {
            inode.inline_xattr = encode_inline(&inline, region_len)
                .expect("the inline side of the split fits the region by construction");
        }
        if !spilled.is_empty() {
            // The per-entry name hash follows the image's directory-hash signedness, so
            // one choice governs every name hash the image carries.
            let signed = matches!(self.options.hash_signedness, HashSignedness::Signed);
            let mut block = encode_block(&spilled, self.block_size, signed);
            let phys = self.alloc.allocate_one()?;
            if self.csum.scheme().writes_object_checksums() {
                // The xattr block checksum (`h_checksum` at offset 16, zero in the
                // encoded block) covers the whole block, seeded from the filesystem
                // seed and the block number as a little-endian 64-bit value.
                let mut c = self.csum.crc32c(self.csum.base_seed(), &phys.to_le_bytes());
                c = self.csum.crc32c(c, &block);
                put_u32(&mut block, 16, c);
            }
            self.write_block(phys, &block)?;
            inode.file_acl = phys;
            inode.blocks += self.sectors_per_block();
        }
        Ok(())
    }

    /// Allocate blocks for `blocks`, write their contents, and map them at the inode.
    /// The extent family roots an extent tree; the block-mapped family fills the classic
    /// direct-and-indirect map. An empty content set still gets an empty extent header
    /// (extent family) or an empty map (block-mapped family), so the inode is valid.
    fn place_blocks(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        blocks: &[Vec<u8>],
    ) -> Result<(), FormatError> {
        if self.feature.has_extents() {
            inode.flags = InodeFlags::EXTENTS;
            let ranges = self.alloc.allocate(blocks.len() as u64)?;
            let physical = flatten(&ranges);
            for (data, &phys) in blocks.iter().zip(&physical) {
                self.write_block(phys, data)?;
            }
            let meta = self.root_extent_tree(ino, inode, &ranges)?;
            inode.blocks = (blocks.len() as u64 + meta) * self.sectors_per_block();
        } else {
            let physical = self.build_classic_map(inode, blocks.len())?;
            for (data, &phys) in blocks.iter().zip(&physical) {
                self.write_block(phys, data)?;
            }
        }
        if inode.size == 0 {
            inode.size = (blocks.len() * self.block_size) as u64;
        }
        Ok(())
    }

    /// Lay out a classic (ext2/ext3) block map for `n` logical data blocks: allocate the
    /// data and the indirect blocks that map them, fill the inode's fifteen-word block
    /// area, and write every indirect block. Returns the physical block of each logical
    /// block `0..n`, in order, for the caller to write the data into — the map's
    /// structure and its data are placed in one pass but written separately, so a file
    /// whose blocks are mostly zero (the journal) writes only the blocks it must.
    ///
    /// Indirect blocks are allocated just before the first data block each maps: the map
    /// is a pre-order walk of the block tree with every node allocated the moment it is
    /// first entered, which is the order `mke2fs` writes and the interleaving that fixes
    /// each block's number. Sets `inode.flags` and `inode.blocks`; leaves `inode.size` to
    /// the caller.
    fn build_classic_map(&mut self, inode: &mut Inode, n: usize) -> Result<Vec<u64>, FormatError> {
        inode.flags = InodeFlags::NONE;
        let mut physical = Vec::with_capacity(n);
        let mut meta = 0u64;

        // Twelve direct pointers: logical blocks 0..11 in words 0..11.
        for slot in 0..n.min(DIRECT_BLOCKS) {
            let phys = self.alloc.allocate_one()?;
            physical.push(phys);
            put_u32(&mut inode.block, slot * 4, map_block(phys)?);
        }

        // Single-, double-, and triple-indirect trees hang off words 12, 13, 14. Each is
        // built only when the data reaches it, and allocated at the moment it is entered.
        for level in 1..=INDIRECT_LEVELS {
            if physical.len() >= n {
                break;
            }
            let root = self.build_indirect(level as u32, n, &mut physical, &mut meta)?;
            put_u32(
                &mut inode.block,
                (DIRECT_BLOCKS + level - 1) * 4,
                map_block(root)?,
            );
        }

        inode.blocks = (n as u64 + meta) * self.sectors_per_block();
        Ok(physical)
    }

    /// Build one indirect block `level` levels above the data — `1` single, `2` double,
    /// `3` triple — mapping data blocks from where `physical` left off up to `n` total.
    /// The indirect block itself is allocated first, before any child, so the allocation
    /// order is the pre-order walk `mke2fs` writes; its slots then fill left to right with
    /// data blocks (level 1) or deeper indirect blocks (levels 2 and 3) until this subtree
    /// is full or the data runs out. Appends each data block's physical number to
    /// `physical` and counts every indirect block it roots into `meta`. Returns the
    /// indirect block's own physical number.
    fn build_indirect(
        &mut self,
        level: u32,
        n: usize,
        physical: &mut Vec<u64>,
        meta: &mut u64,
    ) -> Result<u64, FormatError> {
        let ind_block = self.alloc.allocate_one()?;
        *meta += 1;
        let ppb = self.block_size / 4;
        let mut ptrs = vec![0u8; self.block_size];
        for slot in 0..ppb {
            if physical.len() >= n {
                break;
            }
            let child = if level == 1 {
                let phys = self.alloc.allocate_one()?;
                physical.push(phys);
                phys
            } else {
                self.build_indirect(level - 1, n, physical, meta)?
            };
            put_u32(&mut ptrs, slot * 4, map_block(child)?);
        }
        self.write_block(ind_block, &ptrs)?;
        Ok(ind_block)
    }

    /// Map `ranges` with an extent tree rooted in `inode`'s inline block area,
    /// spilling into external node blocks when the leaves outgrow it. Returns the
    /// node blocks the tree consumed — metadata blocks `i_blocks` counts alongside
    /// the file's data.
    fn root_extent_tree(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        ranges: &[BlockRange],
    ) -> Result<u64, FormatError> {
        let inline_capacity = node_capacity(Inode::BLOCK_BYTES);
        let node_capacity = node_capacity(self.block_size);
        let leaves = build_leaves(ranges)?;

        let shape = plan_tree(leaves.len(), inline_capacity, node_capacity)?;
        let mut node_blocks = Vec::with_capacity(shape.node_blocks);
        for _ in 0..shape.node_blocks {
            node_blocks.push(self.alloc.allocate_one()?);
        }
        let tree = build_tree(&leaves, inline_capacity, node_capacity, &node_blocks)?;

        for node in &tree.nodes {
            let mut buf = vec![0u8; self.block_size];
            write_node(&node.node, node_capacity, &mut buf)?;
            self.write_extent_node_checksum(ino, &mut buf);
            self.write_block(node.block, &buf)?;
        }
        write_node(&tree.root, inline_capacity, &mut inode.block)?;
        Ok(shape.node_blocks as u64)
    }

    /// Fill an external extent node's reserved checksum tail. Under `metadata_csum`
    /// the tail's crc32c covers the node's header and its whole entry area, seeded
    /// from the filesystem seed, the owning inode's number, and its generation (zero
    /// here). With checksums off the tail stays zero, as the node reserved it.
    fn write_extent_node_checksum(&self, ino: u32, buf: &mut [u8]) {
        if !self.csum.scheme().writes_object_checksums() {
            return;
        }
        let tail = tail_offset(self.block_size);
        let mut c = self.csum.crc32c(self.csum.base_seed(), &ino.to_le_bytes());
        c = self.csum.crc32c(c, &0u32.to_le_bytes());
        c = self.csum.crc32c(c, &buf[..tail]);
        put_u32(buf, tail, c);
    }

    /// A directory block holding no entries: one empty slot spanning the block up to
    /// the reserved checksum tail. Used to pad a preallocated directory.
    fn empty_dir_block(&self) -> Vec<u8> {
        // The block reserves a checksum tail only under `metadata_csum`; without it the
        // empty slot spans the whole block, as mke2fs writes a non-checksummed directory.
        let tail_len = if self.csum.scheme().writes_object_checksums() {
            DIR_TAIL_LEN
        } else {
            0
        };
        let usable = self.block_size - tail_len;
        let mut block = vec![0u8; self.block_size];
        put_u32(&mut block, 0, 0); // inode 0 — an unused slot
        put_u16(&mut block, 4, usable as u16); // rec_len spans to the tail (or block end)
        if tail_len != 0 {
            // The tail slice is exactly DIR_TAIL_LEN, so this cannot fail.
            write_dir_tail(&mut block[usable..usable + DIR_TAIL_LEN], 0)
                .expect("tail slice is exactly DIR_TAIL_LEN");
        }
        block
    }

    /// Fill each directory block's reserved tail checksum. Under `metadata_csum` the
    /// tail's crc32c is seeded from the filesystem seed, the owning directory's inode
    /// number, and its generation (zero here). With checksums off the tails stay zero,
    /// exactly as they were reserved.
    ///
    /// A block of entries is covered up to its twelve-byte tail. An index block is
    /// covered only through the entries it actually holds, followed by its own
    /// eight-byte tail with the checksum field zeroed — the two tails differ in size,
    /// in position, and in what they cover.
    fn write_dir_checksums(&self, dir_ino: u32, blocks: &mut [DirBlock]) {
        if !self.csum.scheme().writes_object_checksums() {
            return;
        }
        let seed = self.csum.base_seed();
        for block in blocks {
            let mut c = self.csum.crc32c(seed, &dir_ino.to_le_bytes());
            c = self.csum.crc32c(c, &0u32.to_le_bytes());
            match block.kind {
                DirBlockKind::Entries => {
                    let covered = self.block_size - DIR_TAIL_LEN;
                    c = self.csum.crc32c(c, &block.bytes[..covered]);
                    put_u32(&mut block.bytes, self.block_size - 4, c);
                }
                DirBlockKind::Index {
                    count_offset,
                    limit,
                } => {
                    let count = get_u16(&block.bytes, count_offset + 2) as usize;
                    let covered = count_offset + DX_ENTRY_LEN * count;
                    c = self.csum.crc32c(c, &block.bytes[..covered]);
                    // The tail folds in as `dt_reserved` followed by four zero bytes
                    // standing in for `dt_checksum`. Both words are zero here — the
                    // reserved one because `write_dx_tail` writes it so, and the
                    // checksum because it is the field being computed — so the whole
                    // tail folds as zeros, and it is folded before it is written.
                    c = self.csum.crc32c(c, &[0u8; DX_TAIL_LEN]);
                    write_dx_tail(&mut block.bytes, count_offset, limit, c)
                        .expect("the index block reserved its tail");
                }
            }
        }
    }

    /// Write the inodes the filesystem provides for itself: the empty bad-blocks and
    /// unused reserved inodes, the resize inode with its reserved-descriptor map, the
    /// journal, and the orphan file.
    fn materialize_reserved_inodes(&mut self) -> Result<(), FormatError> {
        // Reserved inodes with no content: bad-blocks (1) and the unused range (3-6,
        // 9-10). The journal (8) is empty only when `has_journal` is off.
        for n in [1u32, 3, 4, 5, 6, 9, 10] {
            self.inodes.insert(n, self.new_inode());
        }
        let resize = if self.feature.has_resize_inode() {
            self.materialize_resize_inode()?
        } else {
            self.new_inode()
        };
        self.inodes.insert(RESIZE_INO, resize);
        let journal = if self.feature.has_journal() {
            self.materialize_journal_inode()?
        } else {
            self.new_inode()
        };
        self.inodes.insert(JOURNAL_INO, journal);
        // The orphan file is not a reserved inode: it exists only with the feature, and
        // when it does not, inode 12 is the source's first entry instead. The model was
        // built to leave it free, so finding an entry there means the two disagree about
        // which inodes the feature set claims — the image is refused rather than written
        // with the entry displaced.
        if self.feature.has_orphan_file() {
            if self.inodes.contains_key(&ORPHAN_INO) {
                return Err(FormatError::OrphanInodeInUse { inode: ORPHAN_INO });
            }
            let orphan = self.materialize_orphan_inode()?;
            self.inodes.insert(ORPHAN_INO, orphan);
        }
        Ok(())
    }

    /// Build the orphan file (inode 12): a regular extent-mapped file holding the
    /// inodes awaiting deletion, of which a fresh filesystem has none — so every entry
    /// is zero and each block carries only its magic-and-checksum tail.
    fn materialize_orphan_inode(&mut self) -> Result<Inode, FormatError> {
        let blocks = orphan_file_blocks(self.layout.total_blocks);
        // One contiguous run keeps the file's extents inline in the inode, as its size
        // always fits a single extent.
        let ranges = match self.alloc.allocate_contiguous(u64::from(blocks)) {
            Some(range) => vec![range],
            None => self.alloc.allocate(u64::from(blocks))?,
        };

        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);
        inode.flags = InodeFlags::EXTENTS;
        let meta = self.root_extent_tree(ORPHAN_INO, &mut inode, &ranges)?;
        inode.size = u64::from(blocks) * u64::from(self.feature.block_size);
        inode.blocks = (u64::from(blocks) + meta) * self.sectors_per_block();

        // The image starts zeroed and every entry is zero, so each block needs only its
        // tail written. The checksum covers the entry array — the block but for that
        // tail — behind the file's identity and the block's own number, so it differs
        // from block to block even though their contents are identical.
        let entries_len = orphan_entries_len(self.block_size);
        let entries = vec![0u8; entries_len];
        let seed = self.csum.base_seed();
        for block in ranges.iter().flat_map(|r| r.start..r.start + r.len) {
            let mut c = self.csum.crc32c(seed, &ORPHAN_INO.to_le_bytes());
            c = self.csum.crc32c(c, &inode.generation.to_le_bytes());
            c = self.csum.crc32c(c, &block.to_le_bytes());
            c = self.csum.crc32c(c, &entries);
            let offset = block * u64::from(self.layout.block_size) + entries_len as u64;
            self.write_at(offset, &orphan_tail_bytes(c))?;
        }
        Ok(inode)
    }

    /// Build the journal inode (inode 8): a regular extent-mapped file whose first
    /// block is the jbd2 superblock and whose remaining blocks are the empty log. The
    /// journal maps as one extent whenever a contiguous run is free, falling back to a
    /// fragmented allocation otherwise.
    fn materialize_journal_inode(&mut self) -> Result<Inode, FormatError> {
        let blocks = self.journal_block_count()?;
        // The journal is a regular file, so a log an explicit size pushed to 2 GiB needs
        // `large_file` like any other. The heuristic never reaches that far; an explicit
        // block count can, and the conflict is stated rather than written to disk.
        let size = u64::from(blocks) * u64::from(self.feature.block_size);
        if size >= LARGE_FILE_MIN_SIZE && !self.feature.has_large_file() {
            return Err(FormatError::LargeFileWithoutFeature {
                what: "journal",
                size,
            });
        }
        // The image starts zeroed, so only the first block — the jbd2 superblock — needs
        // writing; the rest of the log is already the zero blocks it must be.
        let sb = journal::build_superblock(&journal::JournalParams::new(
            self.feature.block_size,
            blocks,
            self.options.uuid,
        ));

        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);

        if self.feature.has_extents() {
            // Prefer one contiguous run so the journal maps inline; the sparse_super
            // backup gaps leave runs long enough for any journal size the heuristic picks.
            let ranges = match self.alloc.allocate_contiguous(u64::from(blocks)) {
                Some(range) => vec![range],
                None => self.alloc.allocate(u64::from(blocks))?,
            };
            self.write_block(ranges[0].start, &sb)?;
            inode.flags = InodeFlags::EXTENTS;
            let meta = self.root_extent_tree(JOURNAL_INO, &mut inode, &ranges)?;
            inode.blocks = (u64::from(blocks) + meta) * self.sectors_per_block();
        } else {
            // ext3: the journal maps through the classic block map, its indirect blocks
            // interleaved with the log the same way `mke2fs` writes them. Only the first
            // block, the jbd2 superblock, is written; the rest stays zeroed.
            let physical = self.build_classic_map(&mut inode, blocks as usize)?;
            self.write_block(physical[0], &sb)?;
        }
        inode.size = size;

        // Back the block map up into the superblock: the 15 i_block words, then the
        // high and low halves of the size.
        let mut backup = [0u32; 17];
        for (i, word) in inode.block.chunks_exact(4).enumerate() {
            backup[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        backup[15] = (inode.size >> 32) as u32;
        backup[16] = inode.size as u32;
        self.journal_backup = Some(backup);
        Ok(inode)
    }

    /// The journal size in blocks from the options: the heuristic for
    /// [`JournalSize::Auto`], or the explicit count, rejecting a size below the jbd2
    /// minimum or a filesystem too small to hold one.
    fn journal_block_count(&self) -> Result<u32, FormatError> {
        let minimum = journal::MIN_JOURNAL_BLOCKS;
        match self.options.journal {
            JournalSize::Auto => journal::default_journal_blocks(self.layout.total_blocks).ok_or(
                FormatError::JournalTooSmall {
                    requested: 0,
                    minimum,
                },
            ),
            JournalSize::Blocks(n) if n >= minimum => Ok(n),
            JournalSize::Blocks(n) => Err(FormatError::JournalTooSmall {
                requested: n,
                minimum,
            }),
        }
    }

    /// Build the resize inode (inode 7): a classic double-indirect map whose indirect
    /// blocks are the primary reserved descriptor blocks, each listing the matching
    /// reserved descriptor block in every backup group.
    ///
    /// The double-indirect block exists whenever the `resize_inode` feature does, even
    /// with nothing reserved: an image carrying the feature with an empty resize inode
    /// is not a valid ext4 filesystem. A zero reservation simply leaves the map blank.
    fn materialize_resize_inode(&mut self) -> Result<Inode, FormatError> {
        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);
        // No extents: the resize inode uses the classic block map.
        inode.flags = InodeFlags::NONE;

        let reserved = self.layout.reserved_gdt_blocks;
        let bs = self.block_size;
        let fdb = u64::from(self.layout.first_data_block);
        let gdt = u64::from(self.layout.gdt_blocks);
        let backups = self.layout.backup_groups();

        // A freshly allocated double-indirect block indexes the primary reserved
        // descriptor blocks. A descriptor block's slot is its absolute table slot taken
        // modulo the slots one block holds, so a reservation may fill the map: with
        // `gdt` at 1 and `block_size / 4` blocks reserved, the last slot written wraps
        // back to 0, which the primary descriptor table's own slot never claims. The
        // reservation is therefore bounded by the map's `block_size / 4` slots alone,
        // not by the table's slots plus the reservation's.
        let slots = u64::from(self.layout.block_size) / 4;
        let dind_block = self.alloc.allocate_one()?;
        let mut dind = vec![0u8; bs];
        for r in 0..u64::from(reserved) {
            let primary = fdb + 1 + gdt + r; // the r-th primary reserved GDT block
            let slot = (gdt + r) % slots;
            put_u32(&mut dind, (slot * 4) as usize, map_block(primary)?);
        }
        self.write_block(dind_block, &dind)?;

        // Each primary reserved descriptor block, used as an indirect block, lists
        // the matching reserved descriptor block in every backup group.
        for r in 0..u64::from(reserved) {
            let ind_block = fdb + 1 + gdt + r;
            let mut ind = vec![0u8; bs];
            for (j, &bg) in backups.iter().enumerate() {
                let start = fdb + u64::from(bg) * u64::from(self.layout.blocks_per_group);
                let backup_resv = start + 1 + gdt + r;
                put_u32(&mut ind, j * 4, map_block(backup_resv)?);
            }
            self.write_block(ind_block, &ind)?;
        }

        // The map hangs entirely off the double-indirect slot (index 13). The size records
        // the classic map's reach rather than the blocks reserved, which is what makes the
        // resize inode a large file at a 4096-byte block — the pairing `validate` enforces.
        inode.size = resize_inode_size(self.layout.block_size);
        let data_blocks = 1 + u64::from(reserved) + u64::from(reserved) * backups.len() as u64;
        inode.blocks = data_blocks * self.sectors_per_block();
        put_u32(&mut inode.block, 13 * 4, map_block(dind_block)?);
        Ok(inode)
    }

    /// Write every built inode into its group's inode table.
    fn write_inode_tables(&mut self) -> Result<(), FormatError> {
        let ipg = self.layout.inodes_per_group;
        let inode_size = self.feature.inode_size;
        let isize = inode_size as usize;
        let writes_checksums = self.csum.scheme().writes_object_checksums();
        let seed = self.csum.base_seed();
        // Held aside so each write may borrow the sink mutably; the inodes go back
        // afterwards, because the superblock's accounting still reads them.
        let inodes = std::mem::take(&mut self.inodes);
        let mut bytes = vec![0u8; isize];
        for (&number, inode) in &inodes {
            let group = (number - 1) / ipg;
            let index = ((number - 1) % ipg) as usize;
            let table = self.layout.groups[group as usize].inode_table;
            let offset = table * u64::from(self.layout.block_size) + (index * isize) as u64;
            // On the block-mapped family an unused inode — no mode, no links —
            // serializes as all zeros, the way mke2fs leaves the reserved inodes it does
            // not fill: no `i_extra_isize`, and (there being no checksums) nothing else.
            // Under `metadata_csum` an unused inode still carries the `i_extra_isize` and
            // the crc32c the checksum pass writes below, so the zeroing is confined to the
            // family that has no checksums to write.
            if !writes_checksums && inode.mode == 0 && inode.links_count == 0 {
                bytes.iter_mut().for_each(|b| *b = 0);
                self.write_at(offset, &bytes)?;
                continue;
            }
            inode.write_to(&mut bytes, inode_size)?;
            if writes_checksums {
                // The inode checksum covers the whole inode with its checksum fields
                // taken as zero — they are zero in `bytes` here, because the field this
                // is about to fill in serialized from a zero `Inode::checksum`.
                //
                // The high half only exists when the inode is large enough to hold it.
                // Writing it regardless would land two bytes of checksum in whatever
                // occupies 0x82 on an inode that has no extended area — for a 128-byte
                // inode, past its end and into the next one.
                let mut c = self.csum.crc32c(seed, &number.to_le_bytes());
                c = self.csum.crc32c(c, &inode.generation.to_le_bytes());
                c = self.csum.crc32c(c, &bytes);
                put_u16(&mut bytes, Inode::CHECKSUM_LO_OFFSET, (c & 0xffff) as u16);
                if Inode::has_checksum_hi(inode_size, inode.extra_isize) {
                    put_u16(&mut bytes, Inode::CHECKSUM_HI_OFFSET, (c >> 16) as u16);
                }
            }
            self.write_at(offset, &bytes)?;
        }
        self.inodes = inodes;
        Ok(())
    }

    /// Write each group's block bitmap and inode bitmap, and build and write the
    /// group descriptor table.
    fn write_bitmaps_and_descriptors(&mut self, model: &FsModel) -> Result<(), FormatError> {
        let ipg = self.layout.inodes_per_group;
        let desc_size = self.feature.desc_size() as usize;
        let mut gdt_bytes = vec![0u8; self.layout.gdt_blocks as usize * self.block_size];

        // Directory counts per group, for `bg_used_dirs_count`.
        let mut dir_counts = vec![0u32; self.layout.group_count as usize];
        for minode in model.inodes.values() {
            if minode.is_dir() {
                dir_counts[((minode.number - 1) / ipg) as usize] += 1;
            }
        }

        let uninit_bg = self.csum.scheme().uninit_bg_semantics();
        let last_group = self.layout.group_count - 1;
        let seed = self.csum.base_seed();
        // The bytes of each bitmap the checksum covers, as the kernel measures them:
        // `ext4_block_bitmap_csum_set` takes `clusters_per_group / 8`, which is exact
        // because a group's block count is always a multiple of eight, while
        // `ext4_inode_bitmap_csum_set` takes `(inodes_per_group + 7) / 8` — rounding up,
        // so a count that is not a multiple of eight still has its final partial byte
        // covered. The planner and `mke2fs` both round the inode count down to a multiple
        // of eight, so the two forms agree on every image either writes; the kernel's is
        // used so they also agree on one that does not.
        let bb_len = (self.layout.blocks_per_group / 8) as usize;
        let ib_len = ipg.div_ceil(8) as usize;

        for g in 0..self.layout.group_count {
            let gl = &self.layout.groups[g as usize];
            let used_inodes = used_inodes_in_group(g, ipg, model.first_free_inode);

            // Under metadata_csum a group with no in-use inodes leaves its inode
            // bitmap uninitialized, and one with no data blocks leaves its block
            // bitmap uninitialized — except a flex-group head, which physically holds
            // the packed tables, and the final group. An uninitialized bitmap is
            // written zero and its checksum field left zero; the group is derived from
            // its layout instead.
            let inode_uninit = uninit_bg && used_inodes == 0;
            let block_uninit = uninit_bg
                && !self.layout.is_flex_head(g)
                && g != last_group
                && self.group_is_dataless(g);

            let bbmp = if block_uninit {
                vec![0u8; self.block_size]
            } else {
                // The allocator is built over this layout, so every group the layout
                // has, it has a bitmap for: `g` is never past the last.
                self.alloc
                    .group_bitmap(g)
                    .expect("a group of this layout has a bitmap")
                    .to_vec()
            };
            let ibmp = if inode_uninit {
                vec![0u8; self.block_size]
            } else {
                self.inode_bitmap(g, model.first_free_inode)
            };

            let block_bitmap_csum = if block_uninit {
                0
            } else {
                self.csum.crc32c(seed, &bbmp[..bb_len])
            };
            let inode_bitmap_csum = if inode_uninit {
                0
            } else {
                self.csum.crc32c(seed, &ibmp[..ib_len])
            };

            // `bg_flags` is meaningful only under metadata_csum / uninit_bg: `BG_INODE_ZEROED`
            // marks an initialized inode table, the two UNINIT bits an uninitialized bitmap.
            // Without the feature the whole field is zero, as `mke2fs` writes it, rather than
            // a flag no feature backs.
            let mut flags = if uninit_bg { BG_INODE_ZEROED } else { 0 };
            if inode_uninit {
                flags |= BG_INODE_UNINIT;
            }
            if block_uninit {
                flags |= BG_BLOCK_UNINIT;
            }

            let mut desc = GroupDescriptor {
                block_bitmap: gl.block_bitmap,
                inode_bitmap: gl.inode_bitmap,
                inode_table: gl.inode_table,
                free_blocks_count: self.alloc.group_free_count(g),
                free_inodes_count: ipg - used_inodes,
                used_dirs_count: dir_counts[g as usize],
                flags,
                // The count of never-used inodes at the tail of the table lets a
                // checker skip scanning them; meaningful only under metadata_csum.
                itable_unused: if uninit_bg { ipg - used_inodes } else { 0 },
                checksum: 0,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            // The descriptor checksum covers the two bitmap checksums, so it is
            // computed last, over the otherwise-complete descriptor.
            desc.checksum = self.group_desc_csum(g, &desc, desc_size);

            let off = g as usize * desc_size;
            desc.write_to(&mut gdt_bytes[off..off + desc_size], desc_size)
                .expect("descriptor buffer is sized to the whole table");
            self.write_block(gl.block_bitmap, &bbmp)?;
            self.write_block(gl.inode_bitmap, &ibmp)?;
        }

        // Write the primary group-descriptor table right after the primary superblock.
        let gdt_start =
            (u64::from(self.layout.first_data_block) + 1) * u64::from(self.layout.block_size);
        self.write_at(gdt_start, &gdt_bytes)?;
        // Keep the table for the backup copies.
        self.gdt_bytes = gdt_bytes;
        Ok(())
    }

    /// Whether group `g` holds no data blocks — only its fixed metadata — and so is
    /// eligible for `BLOCK_UNINIT`. A non-flex-head group's only local metadata is its
    /// superblock-and-descriptor backup, if it carries one; anything used beyond that
    /// is data. Called only for non-flex-head groups (a flex head holds the packed
    /// tables and is never treated as dataless).
    fn group_is_dataless(&self, g: u32) -> bool {
        let block_count = u64::from(self.layout.groups[g as usize].block_count);
        let free = u64::from(self.alloc.group_free_count(g));
        let meta = self.layout.super_overhead_region(g).map_or(0, |r| r.len);
        block_count - free == meta
    }

    /// The group descriptor checksum (`bg_checksum`): the low 16 bits of a crc32c
    /// over the filesystem seed, the group number, and the descriptor bytes with the
    /// checksum field taken as zero. Zero when checksums are off.
    ///
    /// This is the one field whose *algorithm* the checksum scheme names rather than
    /// merely switching on and off, so it reads the scheme itself: a scheme added to
    /// [`CsumScheme`] is a compile error here, which is where the choice belongs.
    fn group_desc_csum(&self, group: u32, desc: &GroupDescriptor, desc_size: usize) -> u16 {
        match self.csum.scheme() {
            CsumScheme::None => return 0,
            CsumScheme::Crc32c => {}
        }
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        desc.write_to(&mut buf[..desc_size], desc_size)
            .expect("descriptor buffer holds a full descriptor");
        // `desc.checksum` is zero here, so the two bg_checksum bytes in `buf` already
        // hold the zeros ext4 folds in place of the field.
        let mut c = self
            .csum
            .crc32c(self.csum.base_seed(), &group.to_le_bytes());
        c = self.csum.crc32c(c, &buf[..desc_size]);
        (c & 0xffff) as u16
    }

    /// Build one group's inode bitmap: a used bit per in-use inode, and set padding
    /// past the group's inode count.
    fn inode_bitmap(&self, group: u32, first_free_inode: u32) -> Vec<u8> {
        let ipg = self.layout.inodes_per_group;
        let mut bmp = vec![0u8; self.block_size];
        let base = u64::from(group) * u64::from(ipg);
        for i in 0..ipg {
            let inode = base + u64::from(i) + 1;
            if inode < u64::from(first_free_inode) {
                bmp[(i / 8) as usize] |= 1 << (i % 8);
            }
        }
        // Padding past the group's inodes is marked used.
        for i in ipg..(self.block_size as u32 * 8) {
            bmp[(i / 8) as usize] |= 1 << (i % 8);
        }
        bmp
    }

    /// Write the primary superblock and, in every backup group, a superblock copy
    /// (with its own group number) and a group-descriptor-table copy.
    fn write_superblocks(&mut self, model: &FsModel) -> Result<(), FormatError> {
        let sb = self.build_superblock(model);

        // Primary: 1024 bytes into the image, inside block 0 for a 4 KiB block.
        let mut primary = sb.to_bytes();
        self.finalize_sb_csum(&mut primary);
        self.write_at(1024, &primary)?;

        let gdt = std::mem::take(&mut self.gdt_bytes);
        for g in self.layout.backup_groups() {
            let start = (u64::from(self.layout.first_data_block)
                + u64::from(g) * u64::from(self.layout.blocks_per_group))
                * u64::from(self.layout.block_size);
            // The backup superblock sits at the group's first block, and records its
            // own group number — the one field that differs from the primary, so its
            // checksum is computed over the backup's own bytes.
            //
            // `s_block_group_nr` is sixteen bits, so a backup group past 65535 keeps
            // only the low sixteen. e2fsprogs truncates the same field identically, so
            // the backups this writes stay byte-compatible with it; the truncation is
            // deliberate parity, not a defect.
            let mut backup = sb.clone();
            backup.block_group_nr = g as u16;
            let mut bytes = backup.to_bytes();
            self.finalize_sb_csum(&mut bytes);
            self.write_at(start, &bytes)?;
            // The descriptor-table copy follows in the next block.
            self.write_at(start + u64::from(self.layout.block_size), &gdt)?;
        }
        Ok(())
    }

    /// Write the superblock crc32c (`s_checksum`) into a serialized superblock. The
    /// checksum covers the record up to its own field and, unlike every other
    /// metadata object, ext4 seeds it from `!0` rather than the filesystem seed. With
    /// checksums off the seam returns zero, leaving the field zero.
    fn finalize_sb_csum(&self, bytes: &mut [u8; SuperBlock::SIZE]) {
        let c = self.csum.crc32c(!0, &bytes[..SuperBlock::SIZE - 4]);
        put_u32(bytes, SuperBlock::SIZE - 4, c);
    }

    /// Assemble the superblock from the layout, feature set, and settled counts.
    fn build_superblock(&self, model: &FsModel) -> SuperBlock {
        let mut sb = SuperBlock::new();
        let l = self.layout;
        sb.inodes_count = l.total_inodes;
        sb.blocks_count = l.total_blocks;
        sb.r_blocks_count = l.reserved_blocks;
        sb.free_blocks_count = self.alloc.free_count();
        sb.free_inodes_count = l.total_inodes - model.used_inode_count();
        sb.first_data_block = l.first_data_block;
        sb.log_block_size = l.block_size.trailing_zeros() - 10;
        sb.log_cluster_size = sb.log_block_size;
        sb.blocks_per_group = l.blocks_per_group;
        sb.clusters_per_group = l.blocks_per_group;
        sb.inodes_per_group = l.inodes_per_group;
        sb.wtime = self.options.time.secs as u32;
        sb.max_mnt_count = 0xffff;
        sb.state = 1; // cleanly unmounted
        sb.errors = self.options.errors.to_s_errors();
        sb.lastcheck = self.options.time.secs as u32;
        sb.rev_level = 1; // dynamic
        sb.first_ino = 11;
        sb.inode_size = self.feature.inode_size;
        sb.feature_compat = self.feature.compat.bits();
        sb.feature_incompat = self.feature.incompat.bits();
        sb.feature_ro_compat = self.feature.ro_compat.bits();
        sb.uuid = self.options.uuid;
        sb.volume_name = self.options.volume_name;
        if let Some(backup) = self.journal_backup {
            sb.journal_inum = JOURNAL_INO;
            sb.jnl_backup_type = 1; // the block map is backed up in s_jnl_blocks
            sb.jnl_blocks = backup;
        }
        if self.feature.has_orphan_file() {
            sb.orphan_file_inum = ORPHAN_INO;
        }
        if self.feature.has_csum_seed() {
            // The stored seed is the one the UUID yields, so it changes no checksum;
            // recording it is what lets the UUID change later without rewriting them.
            sb.checksum_seed = self.csum.base_seed();
        }
        sb.reserved_gdt_blocks = l.reserved_gdt_blocks as u16;
        sb.hash_seed = self.options.hash_seed;
        sb.def_hash_version = self.options.hash_version.to_u8();
        sb.flags = self.options.hash_signedness.to_flag();
        // The superblock's `s_desc_size` records the 64-byte descriptor width only under
        // `64bit`; a 32-byte-descriptor filesystem leaves it zero, which every tool reads
        // as the classic 32. The descriptors are still serialized at their real width
        // (`feature.desc_size()`) — this is the advertised field, not the layout.
        sb.desc_size = if self.feature.is_64bit() {
            self.feature.desc_size()
        } else {
            0
        };
        sb.default_mount_opts = 0x0c; // user_xattr | acl
        sb.mkfs_time = self.options.time.secs as u32;
        // The extra area every inode declares. A 128-byte inode has none, and
        // advertising one the inodes do not carry would misdescribe the filesystem.
        sb.min_extra_isize = extra_isize_for(self.feature.inode_size);
        sb.want_extra_isize = sb.min_extra_isize;
        // `s_log_groups_per_flex` describes the flex packing; a non-flex filesystem
        // leaves it zero even though the layout still groups by `flex_bg_size` internally.
        sb.log_groups_per_flex = if self.feature.has_flex_bg() {
            l.flex_bg_size.trailing_zeros() as u8
        } else {
            0
        };
        // `s_checksum_type` names the algorithm: 1 is crc32c, and a filesystem with no
        // object checksums leaves it zero.
        sb.checksum_type = match self.csum.scheme() {
            CsumScheme::None => 0,
            CsumScheme::Crc32c => 1,
        };
        // The filesystem's own bookkeeping as the kernel's ext4_calculate_overhead()
        // accounts it: the per-group metadata plus the internal journal's full footprint
        // (the orphan file is ordinary file data to that accounting). That footprint is
        // the log blocks plus the metadata its own block map costs — the extent-tree
        // nodes on ext4, the indirect blocks on ext3 — which the materialized journal
        // inode already totals in `i_blocks`, so it is read from there rather than
        // re-derived as the log size alone. A recomputable hint (e2fsck ignores it), so
        // saturate rather than wrap at the exabyte scale where the count exceeds a u32.
        let journal_blocks = if self.feature.has_journal() {
            self.inodes
                .get(&JOURNAL_INO)
                .map_or(0, |journal| journal.blocks / self.sectors_per_block())
        } else {
            0
        };
        sb.overhead_clusters =
            u32::try_from(l.overhead_blocks() + journal_blocks).unwrap_or(u32::MAX);
        sb
    }

    /// Blocks-to-512-byte-sectors conversion for `i_blocks`.
    fn sectors_per_block(&self) -> u64 {
        u64::from(self.layout.block_size) / 512
    }

    fn write_block(&mut self, block: u64, data: &[u8]) -> Result<(), FormatError> {
        self.write_at(block * u64::from(self.layout.block_size), data)
    }
}

/// Split content into block-sized chunks, zero-padding the final chunk.
fn chunk_into_blocks(bytes: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    bytes
        .chunks(block_size)
        .map(|chunk| {
            let mut block = vec![0u8; block_size];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Flatten allocated ranges into the physical block numbers they cover, in order.
fn flatten(ranges: &[BlockRange]) -> Vec<u64> {
    let mut out = Vec::new();
    for r in ranges {
        out.extend(r.start..r.end());
    }
    out
}

/// Inodes in use within group `group`, given the first free inode number.
fn used_inodes_in_group(group: u32, ipg: u32, first_free_inode: u32) -> u32 {
    let base = group * ipg; // one below this group's first inode number
    (first_free_inode - 1).saturating_sub(base).min(ipg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::Reader;
    use crate::source::TreeBuilder;

    const MIB: u64 = 1024 * 1024;

    fn opts() -> FormatOptions {
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
        o
    }

    #[test]
    fn the_profile_setter_seeds_the_matching_feature_set() {
        let base = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        assert_eq!(base.profile(Profile::Ext2).feature, FeatureSet::EXT2);
        assert_eq!(base.profile(Profile::Ext3).feature, FeatureSet::EXT3);
        assert_eq!(base.profile(Profile::Ext4).feature, FeatureSet::DEFAULT);
        // Sugar over the feature field only: no other option is disturbed.
        let seeded = base.profile(Profile::Ext3);
        assert_eq!(seeded.uuid, base.uuid);
        assert_eq!(seeded.grow, base.grow);
        assert_eq!(seeded.inodes, base.inodes);
    }

    #[test]
    fn a_volume_label_is_written_into_the_superblock_and_reads_back() {
        let mut o = opts();
        o.volume_name = *b"rootfs\0\0\0\0\0\0\0\0\0\0";
        let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");
        // `s_volume_name` sits at offset 0x78 in the 1024-byte superblock, which begins
        // 1024 bytes into the image.
        assert_eq!(
            &image.as_bytes()[1024 + 0x78..1024 + 0x78 + 16],
            b"rootfs\0\0\0\0\0\0\0\0\0\0"
        );
        // The reader hands the same label back, NUL-padding and all.
        let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        assert_eq!(
            reader.superblock().volume_name,
            *b"rootfs\0\0\0\0\0\0\0\0\0\0"
        );

        // An unlabelled format leaves the field all zero, matching mke2fs's default.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).expect("format");
        assert_eq!(image.as_bytes()[1024 + 0x78..1024 + 0x78 + 16], [0u8; 16]);
    }

    #[test]
    fn the_error_behavior_reaches_the_superblock_and_reads_back() {
        // `s_errors` sits at offset 0x3c in the 1024-byte superblock. Each policy maps to
        // the kernel's value (1 continue, 2 remount-ro, 3 panic); the default is continue.
        let read_errors = |image: &Image| {
            u16::from_le_bytes(
                image.as_bytes()[1024 + 0x3c..1024 + 0x3c + 2]
                    .try_into()
                    .expect("two bytes"),
            )
        };
        assert_eq!(
            read_errors(&format(TreeBuilder::new(), 64 * MIB, opts()).expect("format")),
            1,
            "the default continues, matching the kernel"
        );
        for (policy, expected) in [
            (ErrorBehavior::Continue, 1u16),
            (ErrorBehavior::RemountReadOnly, 2),
            (ErrorBehavior::Panic, 3),
        ] {
            let mut o = opts();
            o.errors = policy;
            let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");
            assert_eq!(
                read_errors(&image),
                expected,
                "{policy:?} in the raw superblock"
            );
            // The reader hands the same value back, and it survives the superblock
            // checksum the metadata_csum profile computes over the field.
            let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
            assert_eq!(reader.superblock().errors, expected, "{policy:?} read back");
        }
    }

    #[test]
    fn the_orphan_file_size_follows_the_block_count_between_its_floor_and_ceiling() {
        // The curve mke2fs 1.47 realizes, in filesystem blocks: one orphan block per 4096
        // of them, no fewer than 32 and no more than 512. It counts blocks, not bytes, so
        // these hold at any block size.
        assert_eq!(orphan_file_blocks(2048), 32, "below the floor");
        assert_eq!(orphan_file_blocks(131_072), 32, "exactly at the floor");
        assert_eq!(orphan_file_blocks(262_144), 64);
        assert_eq!(orphan_file_blocks(524_288), 128);
        assert_eq!(orphan_file_blocks(2_097_152), 512, "exactly at the ceiling");
        assert_eq!(orphan_file_blocks(67_108_864), 512, "above the ceiling");
    }

    #[test]
    fn an_entry_on_the_orphan_files_inode_is_refused() {
        // `format` derives the first entry's inode from the feature set, so this cannot
        // arise through the public API — it is reached here by building the model with a
        // first user inode that ignores the orphan file, which is what a feature added
        // later that claims an inode and forgets to move the entries up would do. The
        // image must be refused: writing it would leave `/f`'s directory entry naming the
        // orphan file.
        let options = opts();
        let feature = options.feature;
        assert!(feature.has_orphan_file());
        let layout = plan_layout(&options.plan_request(64 * MIB)).expect("layout");
        let model = build_model(
            TreeBuilder::new().file(
                b"/f".to_vec(),
                b"x".to_vec(),
                crate::source::Metadata::new(0o644, options.time),
            ),
            // The collision a stale derivation produces: entries starting at the inode
            // the orphan file takes.
            ModelConfig::new(feature, ORPHAN_INO, options.time),
        )
        .expect("model");
        assert!(model.inodes.contains_key(&ORPHAN_INO), "the entry took it");

        let mut sink = std::io::Cursor::new(Vec::new());
        let mut writer = Writer::new(&layout, &feature, options, &mut sink);
        let err = writer
            .materialize(&model)
            .expect_err("the collision is refused");
        assert!(
            matches!(err, FormatError::OrphanInodeInUse { inode } if inode == ORPHAN_INO),
            "expected OrphanInodeInUse, got {err:?}"
        );
    }

    #[test]
    fn the_orphan_file_takes_the_inode_below_the_first_entry() {
        // With the orphan file the source's entries start at 13; without it, at 12. The
        // number is not a detail: it is what a foreign tool reads out of
        // `s_orphan_file_inum`, and what the first user inode has to make room for.
        let with = FeatureSet::default();
        assert!(with.has_orphan_file());
        assert_eq!(first_user_inode(&with), ORPHAN_INO + 1);

        let mut without = FeatureSet::default();
        without.compat = crate::feature::Compat::from_bits(
            without.compat.bits()
                & !(crate::feature::Compat::HAS_JOURNAL.bits()
                    | crate::feature::Compat::ORPHAN_FILE.bits()),
        );
        assert_eq!(first_user_inode(&without), FIRST_USER_INO);
    }

    #[test]
    fn the_block_mapped_family_round_trips_direct_and_indirect_files() {
        // The ext2/ext3 classic block map — twelve direct pointers, then single- and
        // double-indirect trees — must read back exactly what it wrote. Files sized to
        // land in each region prove the writer and the reader agree on the map's shape and
        // that its just-in-time metadata blocks are placed where the reader looks for them.
        use crate::source::Metadata;
        let time = Timestamp::from_secs(1_700_000_000);
        let bs = 4096usize;
        // Direct only (a partial final block); across the single indirect boundary; and
        // across the single into the double indirect (12 + 1024 + 4 blocks).
        let direct = vec![0xa1u8; 5 * bs - 17];
        let single = vec![0xb2u8; 20 * bs];
        let mut double = vec![0u8; 1040 * bs];
        for (i, byte) in double.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        for profile in [Profile::Ext2, Profile::Ext3] {
            let src = TreeBuilder::new()
                .file(
                    b"/direct".to_vec(),
                    direct.clone(),
                    Metadata::new(0o644, time),
                )
                .file(
                    b"/single".to_vec(),
                    single.clone(),
                    Metadata::new(0o644, time),
                )
                .file(
                    b"/double".to_vec(),
                    double.clone(),
                    Metadata::new(0o644, time),
                );
            let mut o = FormatOptions::new([7u8; 16], time, [0u8; 16]).profile(profile);
            o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
            let image = format(src, 64 * MIB, o).expect("format block-mapped");
            let mut r = Reader::open(std::io::Cursor::new(image.into_bytes())).expect("open");
            assert_eq!(
                r.profile(),
                profile,
                "reads back as the family it was written for"
            );
            for (name, want) in [
                (b"/direct".as_slice(), &direct),
                (b"/single".as_slice(), &single),
                (b"/double".as_slice(), &double),
            ] {
                let (_, inode) = r.lookup(name).expect("lookup");
                assert!(
                    !inode.flags.contains(crate::ondisk::InodeFlags::EXTENTS),
                    "{profile} {}: block-mapped inode carries no EXTENTS flag",
                    String::from_utf8_lossy(name)
                );
                let got = r.read_data(&inode).expect("read");
                assert_eq!(got, *want, "{profile} {}", String::from_utf8_lossy(name));
            }
        }
    }

    #[test]
    fn a_checksum_off_profile_writes_zero_group_flags() {
        // bg_flags is meaningful only under metadata_csum / uninit_bg. With the checksum
        // off, every descriptor's flags are zero, as mke2fs writes them — not
        // BG_INODE_ZEROED carried with no feature to back it.
        let mut feature = FeatureSet::default();
        feature.ro_compat = crate::feature::RoCompat::from_bits(
            feature.ro_compat.bits() & !crate::feature::RoCompat::METADATA_CSUM.bits(),
        );
        // metadata_csum_seed cannot stand without metadata_csum, so it is cleared too.
        feature.incompat = crate::feature::Incompat::from_bits(
            feature.incompat.bits() & !crate::feature::Incompat::CSUM_SEED.bits(),
        );
        assert!(!feature.has_metadata_csum());
        feature.validate().expect("a checksum-off profile is valid");

        let mut o = opts();
        o.feature = feature;
        let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");

        let group_count = image.layout().group_count;
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        for g in 0..group_count {
            let desc = r.group_descriptor(g).expect("group descriptor");
            assert_eq!(
                desc.flags, 0,
                "group {g}: bg_flags must be zero without metadata_csum"
            );
        }
    }

    #[test]
    fn the_resize_map_refuses_a_block_past_thirty_two_bits() {
        // The map stores 32-bit block numbers. Converting a block past that must be a
        // typed error, not a truncated pointer at the wrong block — the geometry never
        // reserves such a block, so this guards a future planner change, not today's.
        assert_eq!(map_block(0).unwrap(), 0);
        assert_eq!(map_block(u64::from(u32::MAX)).unwrap(), u32::MAX);
        let err = map_block(u64::from(u32::MAX) + 1).unwrap_err();
        assert!(matches!(
            err,
            FormatError::ResizeMapNeeds32BitBlocks { block } if block == u64::from(u32::MAX) + 1
        ));
    }

    #[test]
    fn a_format_time_past_the_superblock_range_is_rejected() {
        // The superblock's time fields are 32 bits; a format clock past 2106 would
        // truncate to a different instant, so it is refused rather than written wrong.
        let mut o = opts();
        o.time = Timestamp::from_secs(i64::from(u32::MAX) + 1);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected FormatTimeOutOfRange");
        };
        assert!(
            matches!(err, FormatError::FormatTimeOutOfRange { secs } if secs == i64::from(u32::MAX) + 1),
            "expected FormatTimeOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn the_default_max_reservation_formats_and_reads_back() {
        // Every other test overrides `grow`, so the shipped default — Max — is
        // exercised only here: a plain `FormatOptions::new` must format, fill the
        // resize inode's map without running off its block, and read back clean.
        let plain = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        assert_eq!(plain.grow, GrowReservation::Max);
        let image = format(TreeBuilder::new(), 64 * MIB, plain).expect("default format");
        assert_eq!(
            image.layout().reserved_gdt_blocks,
            1024,
            "Max fills the 4 KiB resize map"
        );
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        // The resize inode (7) maps its reservation through the classic block map, so
        // it carries no extents flag and a nonzero double-indirect pointer.
        let resize = r.inode(7).expect("resize inode");
        let dind = u32::from_le_bytes([
            resize.block[52],
            resize.block[53],
            resize.block[54],
            resize.block[55],
        ]);
        assert_ne!(
            dind, 0,
            "the reservation hangs off the double-indirect slot"
        );
    }

    #[test]
    fn streaming_a_format_writes_the_same_bytes_as_collecting_one() {
        // The two entry points share every decision; only the destination differs, so
        // a streamed image must be byte-identical to the collected one.
        use crate::source::Metadata;

        let time = Timestamp::from_secs(1_700_000_000);
        let source = || {
            TreeBuilder::new()
                .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
                .file(
                    b"/etc/hostname".to_vec(),
                    b"ferrosys\n".to_vec(),
                    Metadata::new(0o644, time),
                )
                .symlink(
                    b"/etc/mtab".to_vec(),
                    b"/proc/self/mounts".to_vec(),
                    Metadata::new(0o777, time),
                )
        };

        let collected = format(source(), 64 * MIB, opts()).expect("format");

        let mut streamed = std::io::Cursor::new(Vec::new());
        let layout = format_to(source(), 64 * MIB, opts(), &mut streamed).expect("format_to");
        let streamed = streamed.into_inner();

        assert_eq!(layout, *collected.layout());
        assert_eq!(
            streamed.len(),
            collected.as_bytes().len(),
            "a streamed image is extended to the filesystem's full size"
        );
        assert_eq!(streamed, collected.as_bytes(), "the images differ");
    }

    #[test]
    fn a_streamed_image_leaves_the_blocks_it_never_writes_alone() {
        // Streaming touches only the blocks the filesystem uses, which is what keeps
        // a file destination sparse. The rest read back as the zeros they were.
        let mut sink = std::io::Cursor::new(Vec::new());
        let layout = format_to(TreeBuilder::new(), 64 * MIB, opts(), &mut sink).expect("format_to");
        let bytes = sink.into_inner();
        assert_eq!(
            bytes.len() as u64,
            layout.total_blocks * u64::from(layout.block_size)
        );
        // The final block of a fresh 64 MiB filesystem holds nothing.
        let last = bytes.len() - layout.block_size as usize;
        assert!(bytes[last..].iter().all(|&b| b == 0));
    }

    #[test]
    fn explicit_journal_size_is_honored() {
        let mut o = opts();
        o.journal = JournalSize::Blocks(2048);
        let image = format(TreeBuilder::new(), 512 * MIB, o).expect("format");
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let jsb = r.journal_superblock().unwrap().expect("journal");
        assert_eq!(jsb.max_len, 2048);
        assert_eq!(r.inode(8).unwrap().size, 2048 * 4096);
    }

    #[test]
    fn a_journal_past_the_large_file_bound_is_rejected_without_the_feature() {
        // The journal is a regular file, so a log an explicit size pushed to 2 GiB needs
        // `large_file` like any other. A 1024-byte block keeps the resize inode under the
        // bound, so this profile is otherwise valid without the feature — which is what
        // leaves the journal as the one structure that reaches it. The check runs before
        // any journal block is allocated, so no filesystem large enough to hold the log
        // has to exist for it to fire.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.feature.block_size = 1024;
        o.feature = o
            .feature
            .with_feature("large_file", false)
            .expect("a known name");
        o.grow = GrowReservation::None;
        o.journal = JournalSize::Blocks(2 * 1024 * 1024); // 2 GiB at a 1024-byte block
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected LargeFileWithoutFeature");
        };
        assert!(
            matches!(
                err,
                FormatError::LargeFileWithoutFeature {
                    what: "journal",
                    size
                } if size == 2 * 1024 * MIB
            ),
            "expected LargeFileWithoutFeature for the journal, got {err:?}"
        );

        // The same journal is written where the feature permits it — the rule is about
        // the pairing, not about the size alone.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.feature.block_size = 1024;
        o.grow = GrowReservation::None;
        o.journal = JournalSize::Blocks(2 * 1024 * 1024);
        assert!(o.feature.has_large_file());
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("a 2 GiB log does not fit a 64 MiB image");
        };
        assert!(
            matches!(err, FormatError::Alloc(_)),
            "the feature check must give way to the allocator, got {err:?}"
        );
    }

    #[test]
    fn journal_below_the_minimum_is_rejected() {
        let mut o = opts();
        o.journal = JournalSize::Blocks(512);
        assert!(matches!(
            format(TreeBuilder::new(), 512 * MIB, o),
            Err(FormatError::JournalTooSmall {
                requested: 512,
                minimum: 1024
            })
        ));
    }

    #[test]
    fn auto_journal_maps_as_a_single_extent() {
        // A contiguous run holds any heuristic journal size, so the map stays inline.
        // Streamed to a file rather than held as bytes: the two gigabytes that put
        // the heuristic in its top tier are almost entirely unwritten, and an
        // in-memory image would cost that much resident memory for zeros.
        let file = tempfile::tempfile().expect("temp file");
        format_to(TreeBuilder::new(), 2048 * MIB, opts(), &file).expect("format");
        let mut r = Reader::open(file).unwrap();
        let inode = r.inode(8).unwrap();
        // A single leaf: the inline extent header reports one entry.
        let entries = u16::from_le_bytes([inode.block[2], inode.block[3]]);
        assert_eq!(entries, 1, "journal should map as one contiguous extent");
    }
}
