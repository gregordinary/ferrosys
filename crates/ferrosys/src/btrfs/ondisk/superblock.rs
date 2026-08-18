//! The superblock, the three feature words that say what a reader must understand before it
//! reads anything else, and where on a device the copies of it live.
//!
//! Every other structure in the filesystem is reached from here: the chunk tree that maps
//! logical space onto the device, the root tree that names every other tree, and the bootstrap
//! array that makes the first of those readable at all.
//!
//! # The copies, and how many there are
//!
//! The format defines **three** locations, and only three. The first is a fixed 64 KiB and the
//! rest are `16 KiB << (12 × n)`, an expression that would go on producing them — 1 PiB is the
//! next value it yields — while the count is a separate constant that stops at three. A series
//! and its length are two facts, and reading only the first of them puts a fourth superblock
//! where nothing looks and makes a reader take whatever a volume that large happens to hold
//! there for one. [`MIRRORS`] is the whole list.
//!
//! A copy is written only where the device holds **all** of it, so the boundary at each
//! location is that offset plus a whole superblock: a device of exactly 256 GiB carries two.
//!
//! This module is pure: it moves bytes to and from values and does no I/O. Whether the
//! recovered fields describe a filesystem this crate can read is a separate question, asked
//! one layer out where the answer can name what it would take to read it.

use crate::bytes::{
    get_arr, get_u8, get_u16, get_u32, get_u64, put_arr, put_u16, put_u32, put_u64,
};
use crate::flags::{flag_set, named_flags};

use super::{CSUM_FIELD_LEN, ChecksumType, DevItem, ParseError};

/// Bytes one superblock occupies, wherever it sits.
pub const SUPER_INFO_SIZE: usize = 4096;

/// Every location the format defines for a superblock, in bytes from the start of the device.
///
/// **Three, and there is no fourth.** See the module documentation for why that is a fact
/// separate from the arithmetic that produces the values.
pub const MIRRORS: [u64; 3] = [64 << 10, 64 << 20, 256 << 30];

/// Whether a device this many bytes long holds the whole of the superblock copy at `at`.
///
/// A copy is 4096 bytes and a device carries one only where it has room for every one of them,
/// so the boundary at each location is that offset **plus a superblock**. The two readings of
/// "large enough" differ by one copy, and a device of exactly 256 GiB carries two rather than
/// three.
///
/// A writer decides which copies to lay down by this rule and a reader decides which absences
/// are ordinary by it, so it is stated once: the two answering it differently would make a
/// reader report a copy missing at a threshold where a writer had correctly declined to write
/// one.
#[must_use]
pub const fn holds_mirror(device_bytes: u64, at: u64) -> bool {
    match at.checked_add(SUPER_INFO_SIZE as u64) {
        Some(end) => end <= device_bytes,
        None => false,
    }
}

/// The first eight bytes past the checksum and the filesystem id: `_BHRfS_M`.
///
/// The format declares the field a little-endian 64-bit integer, and the value it holds is
/// these eight bytes in this order. Comparing the bytes is the same test and says what it is
/// testing.
pub const MAGIC: [u8; 8] = *b"_BHRfS_M";

/// Bytes the bootstrap array occupies, whatever it uses of them.
pub const SYS_CHUNK_ARRAY_SIZE: usize = 2048;

/// Bytes a volume label may occupy, the terminator included.
pub const LABEL_SIZE: usize = 256;

/// The smallest and largest node or sector size the format defines.
///
/// Both are powers of two within this range, and the pinned baseline accepts exactly it on
/// every architecture — what varies between machines is which value a format with no `-s`
/// picks, not which values it will take.
pub const MIN_BLOCK_SIZE: u32 = 4096;

/// The upper end of that range.
pub const MAX_BLOCK_SIZE: u32 = 65536;

/// Settings a filesystem records about its own state, in the superblock's flag word.
///
/// These say what has happened to the filesystem rather than what a reader must understand,
/// which is what the three feature words below are for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SuperFlags(u64);

flag_set!(SuperFlags: u64);

impl SuperFlags {
    /// A driver recorded an error against this filesystem.
    pub const ERROR: Self = Self(1 << 2);
    /// The filesystem is a seed: read-only, and other filesystems may be layered over it.
    pub const SEEDING: Self = Self(1 << 32);
    /// The image is a metadata-only dump rather than a filesystem — what `btrfs-image`
    /// produces, whose data extents are absent rather than empty.
    pub const METADUMP: Self = Self(1 << 33);
    /// The same, in the second dump format.
    pub const METADUMP_V2: Self = Self(1 << 34);
    /// A change of filesystem id was interrupted.
    pub const CHANGING_FSID: Self = Self(1 << 35);
    /// The same, for the form that leaves the metadata id in place.
    pub const CHANGING_FSID_V2: Self = Self(1 << 36);
    /// A conversion to or from the block-group tree was interrupted.
    pub const CHANGING_BG_TREE: Self = Self(1 << 38);
    /// A change of the data checksum algorithm was interrupted.
    pub const CHANGING_DATA_CSUM: Self = Self(1 << 39);
    /// A change of the metadata checksum algorithm was interrupted.
    pub const CHANGING_META_CSUM: Self = Self(1 << 40);
}

named_flags! {
    /// Features a reader may ignore: a filesystem carrying one it does not know is still fully
    /// readable and writable.
    ///
    /// The word is zero on every filesystem the pinned baseline writes, and this crate reads it
    /// so that a bit arriving in it can be reported rather than discarded. No release of the
    /// format has defined a bit here, which is why the table below is empty and every bit the
    /// word carries is [`unknown_bits`](Self::unknown_bits).
    CompatFlags: u64 {}
}

named_flags! {
    /// Features a reader may ignore only if it never writes: a filesystem carrying one this
    /// crate does not know is readable, and writing to it would corrupt whatever the feature
    /// records.
    CompatRoFlags: u64 {
        /// Free space is recorded in a tree of its own rather than in the extent tree.
        FREE_SPACE_TREE("free-space-tree") = 1 << 0,
        /// That tree is up to date and may be trusted.
        FREE_SPACE_TREE_VALID("free-space-tree-valid") = 1 << 1,
        /// Files carry fs-verity Merkle trees.
        VERITY("verity") = 1 << 2,
        /// Block groups live in a tree of their own rather than in the extent tree — a default
        /// since the release before the one this crate is written against, so it is set on
        /// essentially every filesystem a reader will now be pointed at.
        BLOCK_GROUP_TREE("block-group-tree") = 1 << 3,
    }
}

named_flags! {
    /// Features a reader must understand: a filesystem carrying one this crate does not know
    /// cannot be read at all, because the bit says the on-disk form differs from what a reader
    /// without it expects.
    ///
    /// This is the word that makes an unknown bit a hard failure rather than a remark. btrfs
    /// adds to it every few releases — three of the bits below arrived within two of them — so
    /// the list is what a reader is measured against, and a bit outside it is refused by name.
    IncompatFlags: u64 {
        /// Back-references carry the tree that owns them. Set on every filesystem in use.
        MIXED_BACKREF("mixed-backref") = 1 << 0,
        /// A subvolume other than the top-level one is mounted by default.
        DEFAULT_SUBVOL("default-subvol") = 1 << 1,
        /// Data and metadata share block groups, which small filesystems once used.
        MIXED_GROUPS("mixed-bg") = 1 << 2,
        /// Some extents are LZO-compressed.
        COMPRESS_LZO("compress-lzo") = 1 << 3,
        /// Some extents are zstd-compressed.
        COMPRESS_ZSTD("compress-zstd") = 1 << 4,
        /// Metadata blocks may be larger than a page.
        BIG_METADATA("big-metadata") = 1 << 5,
        /// An inode's names may be held in the extended reference form, for files with many
        /// links.
        EXTENDED_IREF("extref") = 1 << 6,
        /// Parity-striped block groups are present.
        RAID56("raid56") = 1 << 7,
        /// Metadata extents are recorded in the shorter form that leaves the level in the key.
        SKINNY_METADATA("skinny-metadata") = 1 << 8,
        /// A file's holes are the absence of an extent rather than an extent recording a hole.
        NO_HOLES("no-holes") = 1 << 9,
        /// Tree blocks carry a metadata id distinct from the filesystem id, which is what lets
        /// the filesystem id be changed without rewriting every block.
        METADATA_UUID("metadata-uuid") = 1 << 10,
        /// Three- and four-copy mirrored block groups are present.
        RAID1C34("raid1c34") = 1 << 11,
        /// The filesystem is on a zoned device.
        ZONED("zoned") = 1 << 12,
        /// The second-generation extent tree, whose items differ from the first's.
        EXTENT_TREE_V2("extent-tree-v2") = 1 << 13,
        /// Stripe placement is recorded in a tree of its own.
        RAID_STRIPE_TREE("raid-stripe-tree") = 1 << 14,
        /// File contents are encrypted.
        ENCRYPT("encrypt") = 1 << 15,
        /// Quota accounting in the form that charges an extent to one subvolume.
        SIMPLE_QUOTA("squota") = 1 << 16,
        /// Logical addresses are remapped through a tree of their own.
        REMAP_TREE("remap-tree") = 1 << 17,
    }
}

/// The structure every read of a btrfs begins at.
///
/// Coverage is deliberately partial and the attribute is what keeps widening it a patch: the
/// three regions past [`remap_root_level`](Self::remap_root_level) — 199 reserved bytes, four
/// backup root records, and the padding to 4096 — are not modelled, and
/// [`write_to`](Self::write_to) leaves them as it found them in the buffer it was handed.
///
/// **Nothing here re-serializes a superblock to check its checksum.** The bytes a checksum
/// covers are the bytes that were read, unmodelled regions included, so verification takes the
/// buffer and never a value round-tripped through this type — a structure whose coverage is
/// partial cannot reproduce a foreign tool's bytes, and a verifier built on one would report
/// every filesystem it did not write as damaged.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SuperBlock {
    /// Offset 0, 32 bytes. The checksum over everything after it.
    pub csum: [u8; CSUM_FIELD_LEN],
    /// Offset 32, 16 bytes. The filesystem's id, as a person sees it.
    pub fsid: [u8; 16],
    /// Offset 48. Where this copy of the superblock sits, in bytes from the start of the
    /// device — so a copy read at one of the [`MIRRORS`] says which one it is, and a copy
    /// that says something else was not read from where it thinks it lives.
    pub bytenr: u64,
    /// Offset 56. What has happened to this filesystem.
    pub flags: SuperFlags,
    /// Offset 64, 8 bytes. [`MAGIC`], checked by [`read_from`](Self::read_from).
    pub magic: [u8; 8],
    /// Offset 72. The transaction this superblock was written by. The newest across the
    /// copies is the live one.
    pub generation: u64,
    /// Offset 80. The root tree's logical address.
    pub root: u64,
    /// Offset 88. The chunk tree's logical address, reachable only through
    /// [`sys_chunk_array`](Self::sys_chunk_array).
    pub chunk_root: u64,
    /// Offset 96. The log tree's logical address, and zero on a filesystem that was shut
    /// down cleanly. Nonzero means the committed trees are behind what the filesystem holds.
    pub log_root: u64,
    /// Offset 112. How many bytes of device the filesystem spans, across every device.
    pub total_bytes: u64,
    /// Offset 120. How many of them are allocated to chunks.
    pub bytes_used: u64,
    /// Offset 128. The objectid of the root tree's own directory, which is 6.
    pub root_dir_objectid: u64,
    /// Offset 136. How many devices the filesystem spans. Anything but one means the image
    /// in hand is a part of the filesystem rather than the whole of it.
    pub num_devices: u64,
    /// Offset 144. The smallest unit of data addressing, and what a data checksum covers.
    pub sectorsize: u32,
    /// Offset 148. How long one tree block is.
    pub nodesize: u32,
    /// Offset 156. The stripe unit, which equals the sector size on every filesystem this
    /// crate reads.
    pub stripesize: u32,
    /// Offset 160. How many of [`sys_chunk_array`](Self::sys_chunk_array)'s bytes are in use.
    pub sys_chunk_array_size: u32,
    /// Offset 164. The transaction the chunk tree's root was written by.
    pub chunk_root_generation: u64,
    /// Offset 172. Features a reader may ignore entirely.
    pub compat_flags: CompatFlags,
    /// Offset 180. Features a reader may ignore only if it never writes.
    pub compat_ro_flags: CompatRoFlags,
    /// Offset 188. Features a reader must understand.
    pub incompat_flags: IncompatFlags,
    /// Offset 196. Which algorithm fills every checksum field in the filesystem.
    pub csum_type: ChecksumType,
    /// Offset 198. The root tree's height, zero where its root block is a leaf.
    pub root_level: u8,
    /// Offset 199. The chunk tree's height.
    pub chunk_root_level: u8,
    /// Offset 200. The log tree's height.
    pub log_root_level: u8,
    /// Offset 201, 98 bytes. The device this superblock was read off.
    pub dev_item: DevItem,
    /// Offset 299, 256 bytes. The volume label, NUL-padded. Bytes rather than text: nothing
    /// records the encoding, and a label off an image is untrusted input.
    pub label: [u8; LABEL_SIZE],
    /// Offset 555. The transaction the free-space cache was written by.
    pub cache_generation: u64,
    /// Offset 563. The transaction the UUID tree was written by.
    pub uuid_tree_generation: u64,
    /// Offset 571, 16 bytes. The id **every tree block carries**, which is the filesystem id
    /// unless `METADATA_UUID` is set — and all-zero on a filesystem where it is not.
    /// [`metadata_id`](Self::metadata_id) is what resolves the two into the value a block is
    /// actually checked against.
    pub metadata_uuid: [u8; 16],
    /// Offset 587. How many global roots each of the shared trees has, under
    /// `extent-tree-v2`.
    pub nr_global_roots: u64,
    /// Offset 595. The remap tree's logical address.
    pub remap_root: u64,
    /// Offset 603. The transaction the remap tree's root was written by.
    pub remap_root_generation: u64,
    /// Offset 611. The remap tree's height.
    pub remap_root_level: u8,
    /// Offset 811, 2048 bytes. The bootstrap: enough `(key, chunk)` pairs to translate the
    /// chunk tree's own address, since nothing else can be read until it has been. Only the
    /// first [`sys_chunk_array_size`](Self::sys_chunk_array_size) bytes are in use.
    pub sys_chunk_array: [u8; SYS_CHUNK_ARRAY_SIZE],
}

impl SuperBlock {
    /// Bytes on disk.
    pub const SIZE: usize = SUPER_INFO_SIZE;

    /// Byte offset of the checksum field, which the checksum recipe covers from the end of.
    pub const CHECKSUM_OFFSET: usize = 0;

    /// Byte offset of [`bytenr`](Self::bytenr), which says where a copy believes it lives.
    pub const BYTENR_OFFSET: usize = 48;

    /// Byte offset of [`MAGIC`], which is what a classifier looks at first.
    pub const MAGIC_OFFSET: usize = 64;

    /// Byte offset of [`generation`](Self::generation), which decides between copies.
    pub const GENERATION_OFFSET: usize = 72;

    /// Recover a superblock from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The magic is checked here and nowhere else, so a classifier and a reader cannot come to
    /// different conclusions about whether some bytes are a btrfs superblock at all.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a superblock, and
    /// [`ParseError::BadMagic`] where it does not carry [`MAGIC`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_super_block",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        let magic: [u8; 8] = get_arr(buf, Self::MAGIC_OFFSET);
        if magic != MAGIC {
            return Err(ParseError::BadMagic {
                structure: "btrfs_super_block",
                found: magic,
            });
        }
        Ok(Self {
            csum: get_arr(buf, 0),
            fsid: get_arr(buf, 32),
            bytenr: get_u64(buf, 48),
            flags: SuperFlags::from_bits(get_u64(buf, 56)),
            magic,
            generation: get_u64(buf, 72),
            root: get_u64(buf, 80),
            chunk_root: get_u64(buf, 88),
            log_root: get_u64(buf, 96),
            total_bytes: get_u64(buf, 112),
            bytes_used: get_u64(buf, 120),
            root_dir_objectid: get_u64(buf, 128),
            num_devices: get_u64(buf, 136),
            sectorsize: get_u32(buf, 144),
            nodesize: get_u32(buf, 148),
            stripesize: get_u32(buf, 156),
            sys_chunk_array_size: get_u32(buf, 160),
            chunk_root_generation: get_u64(buf, 164),
            compat_flags: CompatFlags::from_bits(get_u64(buf, 172)),
            compat_ro_flags: CompatRoFlags::from_bits(get_u64(buf, 180)),
            incompat_flags: IncompatFlags::from_bits(get_u64(buf, 188)),
            csum_type: ChecksumType::from_value(get_u16(buf, 196)),
            root_level: get_u8(buf, 198),
            chunk_root_level: get_u8(buf, 199),
            log_root_level: get_u8(buf, 200),
            dev_item: DevItem::read_from(&buf[201..201 + DevItem::SIZE])?,
            label: get_arr(buf, 299),
            cache_generation: get_u64(buf, 555),
            uuid_tree_generation: get_u64(buf, 563),
            metadata_uuid: get_arr(buf, 571),
            nr_global_roots: get_u64(buf, 587),
            remap_root: get_u64(buf, 595),
            remap_root_generation: get_u64(buf, 603),
            remap_root_level: get_u8(buf, 611),
            sys_chunk_array: get_arr(buf, 811),
        })
    }

    /// Write the superblock into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The three regions this type does not model — the reserved bytes, the backup roots, and
    /// the padding — are left exactly as they were in `buf`, so a superblock read into a
    /// buffer and written back into that same buffer is unchanged. Into a zeroed buffer they
    /// stay zero.
    ///
    /// The checksum field is written as the value the structure holds. Recomputing it is the
    /// caller's, and belongs after every other field is in place.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a superblock.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a superblock needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_arr(buf, 0, &self.csum);
        put_arr(buf, 32, &self.fsid);
        put_u64(buf, 48, self.bytenr);
        put_u64(buf, 56, self.flags.bits());
        put_arr(buf, 64, &self.magic);
        put_u64(buf, 72, self.generation);
        put_u64(buf, 80, self.root);
        put_u64(buf, 88, self.chunk_root);
        put_u64(buf, 96, self.log_root);
        // Offset 104 is the log root's transaction id, which no version of the format has
        // ever used and which is therefore always zero. Written as such rather than modelled.
        put_u64(buf, 104, 0);
        put_u64(buf, 112, self.total_bytes);
        put_u64(buf, 120, self.bytes_used);
        put_u64(buf, 128, self.root_dir_objectid);
        put_u64(buf, 136, self.num_devices);
        put_u32(buf, 144, self.sectorsize);
        put_u32(buf, 148, self.nodesize);
        // Offset 152 is the leaf size, which the format kept after node and leaf sizes
        // stopped differing. It equals the node size on every filesystem in existence.
        put_u32(buf, 152, self.nodesize);
        put_u32(buf, 156, self.stripesize);
        put_u32(buf, 160, self.sys_chunk_array_size);
        put_u64(buf, 164, self.chunk_root_generation);
        put_u64(buf, 172, self.compat_flags.bits());
        put_u64(buf, 180, self.compat_ro_flags.bits());
        put_u64(buf, 188, self.incompat_flags.bits());
        put_u16(buf, 196, self.csum_type.value());
        buf[198] = self.root_level;
        buf[199] = self.chunk_root_level;
        buf[200] = self.log_root_level;
        self.dev_item.write_to(&mut buf[201..201 + DevItem::SIZE]);
        put_arr(buf, 299, &self.label);
        put_u64(buf, 555, self.cache_generation);
        put_u64(buf, 563, self.uuid_tree_generation);
        put_arr(buf, 571, &self.metadata_uuid);
        put_u64(buf, 587, self.nr_global_roots);
        put_u64(buf, 595, self.remap_root);
        put_u64(buf, 603, self.remap_root_generation);
        buf[611] = self.remap_root_level;
        put_arr(buf, 811, &self.sys_chunk_array);
    }

    /// The id every tree block of this filesystem carries in its header.
    ///
    /// It is [`metadata_uuid`](Self::metadata_uuid) where `METADATA_UUID` is set and
    /// [`fsid`](Self::fsid) otherwise — because the field exists so that changing the
    /// filesystem id a person sees does not mean rewriting every block, and a filesystem that
    /// has never had one changed leaves it zero. Checking a block against the wrong one of the
    /// two refuses a healthy filesystem.
    #[must_use]
    pub fn metadata_id(&self) -> [u8; 16] {
        if self.incompat_flags.contains(IncompatFlags::METADATA_UUID) {
            self.metadata_uuid
        } else {
            self.fsid
        }
    }

    /// The label as it was stored, with the NUL padding removed.
    ///
    /// Bytes rather than text: nothing in the filesystem records what encoding a label is in,
    /// and it is untrusted input either way.
    #[must_use]
    pub fn label_bytes(&self) -> &[u8] {
        let end = self
            .label
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.label.len());
        &self.label[..end]
    }

    /// The bytes of the bootstrap array that are in use, or [`None`] where the recorded length
    /// is longer than the array itself.
    ///
    /// A length past the array is the only way this field can lie, and it is a number an image
    /// supplies — so the answer is no slice rather than a shorter one, and the caller reports
    /// what was wrong instead of parsing whatever the clamp left.
    #[must_use]
    pub fn sys_chunk_bytes(&self) -> Option<&[u8]> {
        let len = self.sys_chunk_array_size as usize;
        (len <= SYS_CHUNK_ARRAY_SIZE).then(|| &self.sys_chunk_array[..len])
    }
}

/// Where in a superblock the ring of [`RootBackup`] records begins.
pub const BACKUP_ROOTS_OFFSET: usize = 2859;

/// How many of them there are.
///
/// A ring rather than a list: each commit overwrites the oldest, so the four together are the
/// last four transactions and nothing older.
pub const NUM_BACKUP_ROOTS: usize = 4;

/// Where the roots of six trees stood at the end of one transaction.
///
/// The superblock carries [`NUM_BACKUP_ROOTS`] of these, so a filesystem whose current trees
/// cannot be read has somewhere else to be read from. Nothing this crate does consults them —
/// recovery is not in scope — and a filesystem is written with them because a filesystem
/// without them has no fallback rather than a clean one.
///
/// **The fields here group by tree and the bytes group by field.** Six addresses and their
/// transactions come first as pairs, then the three totals, then thirty-two unused bytes, and
/// only then the six levels together. So a copy of this structure over the bytes would be
/// wrong, which is true of every structure in this module and worth saying where the two
/// orders visibly differ.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RootBackup {
    /// Offset 0. The root tree's address.
    pub tree_root: u64,
    /// Offset 8. The transaction that wrote it.
    pub tree_root_gen: u64,
    /// Offset 16. The chunk tree's address.
    pub chunk_root: u64,
    /// Offset 24. The transaction that wrote it.
    pub chunk_root_gen: u64,
    /// Offset 32. The extent tree's address.
    pub extent_root: u64,
    /// Offset 40. The transaction that wrote it.
    pub extent_root_gen: u64,
    /// Offset 48. The filesystem tree's address.
    pub fs_root: u64,
    /// Offset 56. The transaction that wrote it.
    pub fs_root_gen: u64,
    /// Offset 64. The device tree's address.
    pub dev_root: u64,
    /// Offset 72. The transaction that wrote it.
    pub dev_root_gen: u64,
    /// Offset 80. The checksum tree's address.
    pub csum_root: u64,
    /// Offset 88. The transaction that wrote it.
    pub csum_root_gen: u64,
    /// Offset 96. How many bytes of device the filesystem spanned.
    pub total_bytes: u64,
    /// Offset 104. How many of them were allocated.
    pub bytes_used: u64,
    /// Offset 112. How many devices it spanned.
    pub num_devices: u64,
    /// Offset 152. The root tree's height.
    pub tree_root_level: u8,
    /// Offset 153. The chunk tree's height.
    pub chunk_root_level: u8,
    /// Offset 154. The extent tree's height.
    pub extent_root_level: u8,
    /// Offset 155. The filesystem tree's height.
    pub fs_root_level: u8,
    /// Offset 156. The device tree's height.
    pub dev_root_level: u8,
    /// Offset 157. The checksum tree's height.
    pub csum_root_level: u8,
}

impl RootBackup {
    /// Bytes on disk.
    pub const SIZE: usize = 168;

    /// Where the record for `slot` begins within a superblock, or [`None`] past the ring.
    #[must_use]
    pub const fn offset_of(slot: usize) -> Option<usize> {
        if slot < NUM_BACKUP_ROOTS {
            Some(BACKUP_ROOTS_OFFSET + slot * Self::SIZE)
        } else {
            None
        }
    }

    /// Recover a backup record from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_root_backup",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            tree_root: get_u64(buf, 0),
            tree_root_gen: get_u64(buf, 8),
            chunk_root: get_u64(buf, 16),
            chunk_root_gen: get_u64(buf, 24),
            extent_root: get_u64(buf, 32),
            extent_root_gen: get_u64(buf, 40),
            fs_root: get_u64(buf, 48),
            fs_root_gen: get_u64(buf, 56),
            dev_root: get_u64(buf, 64),
            dev_root_gen: get_u64(buf, 72),
            csum_root: get_u64(buf, 80),
            csum_root_gen: get_u64(buf, 88),
            total_bytes: get_u64(buf, 96),
            bytes_used: get_u64(buf, 104),
            num_devices: get_u64(buf, 112),
            tree_root_level: get_u8(buf, 152),
            chunk_root_level: get_u8(buf, 153),
            extent_root_level: get_u8(buf, 154),
            fs_root_level: get_u8(buf, 155),
            dev_root_level: get_u8(buf, 156),
            csum_root_level: get_u8(buf, 157),
        })
    }

    /// Write the backup record into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The thirty-two unused bytes between the totals and the levels, and the ten past them,
    /// are left as they were found — the same rule [`SuperBlock::write_to`] follows for the
    /// regions it does not model, and for the same reason.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a root backup needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.tree_root);
        put_u64(buf, 8, self.tree_root_gen);
        put_u64(buf, 16, self.chunk_root);
        put_u64(buf, 24, self.chunk_root_gen);
        put_u64(buf, 32, self.extent_root);
        put_u64(buf, 40, self.extent_root_gen);
        put_u64(buf, 48, self.fs_root);
        put_u64(buf, 56, self.fs_root_gen);
        put_u64(buf, 64, self.dev_root);
        put_u64(buf, 72, self.dev_root_gen);
        put_u64(buf, 80, self.csum_root);
        put_u64(buf, 88, self.csum_root_gen);
        put_u64(buf, 96, self.total_bytes);
        put_u64(buf, 104, self.bytes_used);
        put_u64(buf, 112, self.num_devices);
        buf[152] = self.tree_root_level;
        buf[153] = self.chunk_root_level;
        buf[154] = self.extent_root_level;
        buf[155] = self.fs_root_level;
        buf[156] = self.dev_root_level;
        buf[157] = self.csum_root_level;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A superblock whose every modelled field holds a value no other field holds.
    ///
    /// Distinct rather than realistic, and deliberately: a fixture of plausible values has
    /// zero in a dozen fields, and a round trip that transposed two of them would pass. The
    /// two feature words are the exception — they are asserted against what the pinned
    /// baseline writes, so they hold that rather than a counter.
    fn a_superblock() -> SuperBlock {
        /// A distinct value per field, from a counter, so no two fields can be confused.
        fn n(k: u64) -> u64 {
            0x1000_0000_0000_0000 + k
        }
        /// The same for a byte array, filled with its own number.
        fn fill<const N: usize>(k: u8) -> [u8; N] {
            [k; N]
        }
        SuperBlock {
            csum: fill(1),
            fsid: fill(2),
            bytenr: n(3),
            flags: SuperFlags::from_bits(n(4)),
            magic: MAGIC,
            generation: n(5),
            root: n(6),
            chunk_root: n(7),
            log_root: n(8),
            total_bytes: n(9),
            bytes_used: n(10),
            root_dir_objectid: n(11),
            num_devices: n(12),
            sectorsize: 0x1111_0001,
            nodesize: 0x1111_0002,
            stripesize: 0x1111_0003,
            sys_chunk_array_size: 129,
            chunk_root_generation: n(13),
            compat_flags: CompatFlags::from_bits(n(14)),
            // The two words the pinned baseline writes with no options at all, asserted
            // below rather than counted like the rest.
            compat_ro_flags: CompatRoFlags::FREE_SPACE_TREE
                | CompatRoFlags::FREE_SPACE_TREE_VALID
                | CompatRoFlags::BLOCK_GROUP_TREE,
            incompat_flags: IncompatFlags::MIXED_BACKREF
                | IncompatFlags::BIG_METADATA
                | IncompatFlags::EXTENDED_IREF
                | IncompatFlags::SKINNY_METADATA
                | IncompatFlags::NO_HOLES,
            csum_type: ChecksumType::CRC32C,
            root_level: 21,
            chunk_root_level: 22,
            log_root_level: 23,
            dev_item: DevItem {
                devid: n(24),
                total_bytes: n(25),
                bytes_used: n(26),
                io_align: 0x1111_0004,
                io_width: 0x1111_0005,
                sector_size: 0x1111_0006,
                ty: n(27),
                generation: n(28),
                start_offset: n(29),
                dev_group: 0x1111_0007,
                seek_speed: 30,
                bandwidth: 31,
                uuid: fill(32),
                fsid: fill(33),
            },
            label: fill(34),
            cache_generation: n(35),
            uuid_tree_generation: n(36),
            metadata_uuid: fill(37),
            nr_global_roots: n(38),
            remap_root: n(39),
            remap_root_generation: n(40),
            remap_root_level: 41,
            sys_chunk_array: fill(42),
        }
    }

    #[test]
    fn a_superblock_round_trips_through_its_four_thousand_and_ninety_six_bytes() {
        let sb = a_superblock();
        let mut buf = [0u8; SuperBlock::SIZE];
        sb.write_to(&mut buf);
        assert_eq!(SuperBlock::read_from(&buf).expect("a full superblock"), sb);
        // The two words that decide what a reader may do, at the offsets the format puts them.
        assert_eq!(&buf[180..188], &0xbu64.to_le_bytes());
        assert_eq!(&buf[188..196], &0x361u64.to_le_bytes());
        // And the values the pinned baseline writes with no options at all, which is what
        // those two words are.
        assert_eq!(sb.compat_ro_flags.bits(), 0xb);
        assert_eq!(sb.incompat_flags.bits(), 0x361);
    }

    #[test]
    fn the_two_deprecated_fields_are_written_as_the_format_leaves_them() {
        // Neither is modelled: one has never been used by any kernel, and the other stopped
        // differing from the node size long ago. Both are written rather than skipped, so a
        // buffer this crate fills is a superblock rather than one with holes in it.
        let sb = a_superblock();
        let mut buf = [0xffu8; SuperBlock::SIZE];
        sb.write_to(&mut buf);
        assert_eq!(
            &buf[104..112],
            &0u64.to_le_bytes(),
            "the log root transaction id"
        );
        assert_eq!(&buf[152..156], &sb.nodesize.to_le_bytes(), "the leaf size");
    }

    #[test]
    fn the_regions_this_type_does_not_model_survive_a_write() {
        // The reserved bytes, the four backup roots, and the padding. A write that zeroed
        // them would make a re-serialized superblock differ from the one that was read, which
        // is exactly the thing the checksum must never be computed over.
        let sb = a_superblock();
        let mut buf = [0u8; SuperBlock::SIZE];
        for (index, byte) in buf.iter_mut().enumerate().take(SuperBlock::SIZE).skip(612) {
            if !(811..2859).contains(&index) {
                *byte = 0x77;
            }
        }
        sb.write_to(&mut buf);
        assert!(
            buf[612..811].iter().all(|&b| b == 0x77),
            "the reserved bytes"
        );
        assert!(
            buf[2859..].iter().all(|&b| b == 0x77),
            "the backups and the padding"
        );
    }

    #[test]
    fn bytes_that_do_not_carry_the_magic_are_not_a_superblock() {
        let sb = a_superblock();
        let mut buf = [0u8; SuperBlock::SIZE];
        sb.write_to(&mut buf);
        buf[SuperBlock::MAGIC_OFFSET] ^= 0xff;
        let err = SuperBlock::read_from(&buf).expect_err("a flipped magic");
        assert!(matches!(err, ParseError::BadMagic { .. }));
        // And a buffer too short is short rather than unrecognized: the two say different
        // things about a source, and a classifier reads a short one as "not ours".
        assert!(matches!(
            SuperBlock::read_from(&buf[..SuperBlock::SIZE - 1]),
            Err(ParseError::TooShort {
                need: 4096,
                got: 4095,
                ..
            })
        ));
    }

    #[test]
    fn the_metadata_id_is_the_filesystem_id_until_the_feature_says_otherwise() {
        // A filesystem that has never had its id changed leaves `metadata_uuid` zero, so a
        // reader that checked tree blocks against it unconditionally would refuse every
        // healthy filesystem it opened.
        let mut sb = a_superblock();
        sb.metadata_uuid = [0; 16];
        assert_eq!(sb.metadata_id(), sb.fsid);

        sb.metadata_uuid = [0x99; 16];
        sb.incompat_flags |= IncompatFlags::METADATA_UUID;
        assert_eq!(sb.metadata_id(), [0x99; 16]);
    }

    #[test]
    fn a_bootstrap_array_longer_than_the_array_is_no_array() {
        let mut sb = a_superblock();
        assert_eq!(sb.sys_chunk_bytes().expect("in range").len(), 129);
        sb.sys_chunk_array_size = SYS_CHUNK_ARRAY_SIZE as u32;
        assert_eq!(sb.sys_chunk_bytes().expect("exactly the array").len(), 2048);
        sb.sys_chunk_array_size = SYS_CHUNK_ARRAY_SIZE as u32 + 1;
        assert_eq!(
            sb.sys_chunk_bytes(),
            None,
            "a length past the array is not clamped"
        );
    }

    #[test]
    fn a_label_is_the_bytes_before_its_padding() {
        let mut sb = a_superblock();
        sb.label = [0; LABEL_SIZE];
        assert_eq!(sb.label_bytes(), b"");
        sb.label[..5].copy_from_slice(b"root\x00");
        assert_eq!(sb.label_bytes(), b"root");
        // A label filling the field has no terminator, and is still the whole field.
        sb.label = [b'x'; LABEL_SIZE];
        assert_eq!(sb.label_bytes().len(), LABEL_SIZE);
    }

    #[test]
    fn an_incompatible_word_names_every_bit_it_carries_including_ones_nothing_defines() {
        // The words a person types, not the constants the format's header spells them with.
        // A rendering and the option that accepts one have to agree, and the layer that has
        // to accept a word is the layer that owns which word it is.
        let mut out = String::new();
        a_superblock().incompat_flags.describe(&mut out);
        assert_eq!(
            out,
            "mixed-backref, big-metadata, extref, skinny-metadata, no-holes"
        );

        // The case the rendering exists for. A bit the format grows after this release is
        // exactly what a reader must refuse by name, and a renderer that skipped it would
        // report a filesystem refused for nothing.
        let mut out = String::new();
        IncompatFlags::from_bits(1 << 40).describe(&mut out);
        assert_eq!(out, "bit 40");

        let mut out = String::new();
        IncompatFlags::NONE.describe(&mut out);
        assert_eq!(out, "none");
    }

    #[test]
    fn a_feature_word_reads_back_exactly_the_names_it_writes() {
        // The property one table exists for, on the two words that have one: every name a
        // word emits resolves to the bit that emitted it, and a name no word defines
        // resolves to nothing. A word that printed a name it then refused would be a report
        // telling a caller a word to type and an option refusing it.
        for bit in 0..u64::BITS {
            let one = IncompatFlags::from_bits(1 << bit);
            match one.names().as_slice() {
                [name] => assert_eq!(IncompatFlags::from_name(name), Some(one)),
                [] => assert_ne!(one.unknown_bits(), 0, "a bit with no name and no report"),
                many => panic!("one bit named {many:?}"),
            }
            let one = CompatRoFlags::from_bits(1 << bit);
            match one.names().as_slice() {
                [name] => assert_eq!(CompatRoFlags::from_name(name), Some(one)),
                [] => assert_ne!(one.unknown_bits(), 0, "a bit with no name and no report"),
                many => panic!("one bit named {many:?}"),
            }
        }
        assert_eq!(IncompatFlags::from_name("SKINNY_METADATA"), None);
        assert_eq!(IncompatFlags::from_name(""), None);
    }

    #[test]
    fn no_word_is_defined_by_two_of_the_three_feature_words() {
        // What lets a list of feature names be read without saying which word each belongs
        // to: the name decides. Two words claiming one name would make the meaning of a
        // feature list depend on the order they were consulted in.
        let all = IncompatFlags::from_bits(u64::MAX).names();
        for name in &all {
            assert_eq!(
                CompatRoFlags::from_name(name),
                None,
                "{name} is defined by two feature words"
            );
            assert_eq!(CompatFlags::from_name(name), None);
        }
        for name in CompatRoFlags::from_bits(u64::MAX).names() {
            assert_eq!(CompatFlags::from_name(name), None);
        }
        // And no word defines a name twice, which the round-trip above cannot see: it asks
        // one bit at a time, and two bits sharing a name both resolve to the first of them.
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "a repeated name in {all:?}");
    }

    #[test]
    fn the_format_defines_three_superblock_locations_and_the_third_is_a_quarter_terabyte_in() {
        assert_eq!(MIRRORS, [65_536, 67_108_864, 274_877_906_944]);
        // The expression the values come from goes on producing them; the count does not. A
        // fourth would be at a petabyte, and there is no fourth.
        for (index, &offset) in MIRRORS.iter().enumerate().skip(1) {
            assert_eq!(offset, (16u64 << 10) << (12 * index as u32));
        }
        assert_eq!(
            MIRRORS[0],
            64 << 10,
            "the first is fixed, not the expression"
        );
    }

    #[test]
    fn a_backup_record_round_trips_and_its_levels_sit_past_the_bytes_it_does_not_model() {
        let backup = RootBackup {
            tree_root: 1,
            tree_root_gen: 2,
            chunk_root: 3,
            chunk_root_gen: 4,
            extent_root: 5,
            extent_root_gen: 6,
            fs_root: 7,
            fs_root_gen: 8,
            dev_root: 9,
            dev_root_gen: 10,
            csum_root: 11,
            csum_root_gen: 12,
            total_bytes: 13,
            bytes_used: 14,
            num_devices: 15,
            tree_root_level: 21,
            chunk_root_level: 22,
            extent_root_level: 23,
            fs_root_level: 24,
            dev_root_level: 25,
            csum_root_level: 26,
        };
        let mut buf = [0u8; RootBackup::SIZE];
        backup.write_to(&mut buf);
        assert_eq!(RootBackup::read_from(&buf), Ok(backup));
        // The fields group by tree and the bytes group by field: thirty-two bytes this
        // structure does not model sit between the last total and the first level, so the six
        // levels are at 152 and not at 120.
        assert_eq!(&buf[120..152], &[0u8; 32]);
        assert_eq!(&buf[152..158], &[21, 22, 23, 24, 25, 26]);

        // Four of them, end to end, and the last one finishes where the padding starts.
        assert_eq!(RootBackup::offset_of(0), Some(BACKUP_ROOTS_OFFSET));
        assert_eq!(RootBackup::offset_of(3), Some(2859 + 3 * 168));
        assert_eq!(RootBackup::offset_of(NUM_BACKUP_ROOTS), None);
        assert_eq!(
            BACKUP_ROOTS_OFFSET + NUM_BACKUP_ROOTS * RootBackup::SIZE,
            3531
        );

        for got in 0..RootBackup::SIZE {
            assert!(RootBackup::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
    }
}
