//! The superblock (`struct ext2_super_block`), in its 1024-byte form.
//!
//! The superblock is the filesystem's root record: block and inode counts, the
//! block and group geometry, the three feature words, the UUID, and the long tail
//! of tunables ext4 tracks. It lives 1024 bytes into the image (inside block 0 for
//! a 4 KiB block size) and is copied into every backup group, differing there only
//! in `s_block_group_nr` and, under `metadata_csum`, in `s_checksum` — recomputed
//! over each backup's own bytes.
//!
//! This model carries the fields the emitted profile sets; the rest of the
//! 1024-byte record is reserved and serialized as zero. Split block counts keep
//! their high halves so widening to 64-bit addressing writes a different value,
//! not a different type.

use super::{ParseError, split64};
use super::{get_arr, get_u8, get_u16, get_u32, join64, put_arr, put_u8, put_u16, put_u32};

/// The ext4 superblock magic (`s_magic`): `0xEF53`.
pub const SUPERBLOCK_MAGIC: u16 = 0xef53;

/// The name a NUL-padded superblock text field holds: its bytes up to the first NUL.
///
/// ext writes `s_volume_name` and `s_last_mounted` into fixed-width fields and pads what is
/// left with NULs, so the field is not the name — a sixteen-byte volume field holding
/// `rootfs` carries ten bytes that are not part of the label. Every consumer that reads one
/// of those fields wants the name, and this is where the padding rule is stated.
///
/// The result is bytes, not text: a label is whatever the formatter that wrote it put there,
/// so rendering it for a person goes through [`printable`](crate::printable) afterwards.
///
/// ```
/// # use ferrosys::ext::ondisk::unpadded;
/// assert_eq!(unpadded(b"rootfs\0\0\0\0\0\0\0\0\0\0"), b"rootfs");
/// // A field filled to its width has no terminator, and is all name.
/// assert_eq!(unpadded(b"0123456789abcdef"), b"0123456789abcdef");
/// // An empty field is no name at all.
/// assert_eq!(unpadded(&[0u8; 16]), b"");
/// ```
#[must_use]
pub fn unpadded(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// The crc32c a superblock's bytes compute to: over the record up to its own checksum field
/// at [`SuperBlock::CHECKSUM_OFFSET`].
///
/// Unlike every other metadata object, ext4 seeds this from `!0` rather than from the
/// filesystem seed — so it does not go through the checksum seam, takes no per-filesystem
/// state, and is the same function for the writer stamping a copy, the reader verifying one,
/// and a re-identification recomputing one after moving the UUID. Whether the field is
/// written at all is a question about the feature set, and stays with each caller.
///
/// The checksum covers the bytes an object *has*, so this takes the record's own bytes rather
/// than a re-serialized [`SuperBlock`]: the format carries fields no formatter is obliged to
/// leave zero and this crate does not model, and recomputing from a parsed record would
/// silently zero every one of them.
///
/// # Panics
///
/// If `bytes` is shorter than [`SuperBlock::SIZE`].
#[must_use]
pub fn superblock_checksum(bytes: &[u8]) -> u32 {
    assert!(
        bytes.len() >= SuperBlock::SIZE,
        "a whole superblock record is needed"
    );
    crate::crc32c::crc32c(!0, &bytes[..SuperBlock::CHECKSUM_OFFSET])
}

/// The `64bit` bit of `s_feature_incompat`, the feature that gives the block counts
/// their high halves. Parsing consults it in the raw word rather than through the
/// typed feature set, so the superblock stays decodable from its bytes alone.
const INCOMPAT_64BIT: u32 = 0x0080;

/// The superblock: filesystem-wide geometry, features, and tunables.
///
/// Fields are named for their `s_*` on-disk counterparts. Counts that ext4 splits
/// into low and high words are held here as single logical values.
///
/// # Constructing one
///
/// Start from [`SuperBlock::default`] and assign the fields that differ. A
/// `#[non_exhaustive]` structure cannot be written as a literal from outside
/// this crate, and that is about the Rust type, not the format: the byte layout is
/// [`read_from`](Self::read_from) and [`SIZE`](Self::SIZE), and neither of them
/// changes. What the attribute buys is that this crate can widen its
/// coverage of the on-disk structure — the fields it does not model — without that
/// being a breaking change for everyone reading an image.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SuperBlock {
    /// Total inodes (`s_inodes_count`).
    pub inodes_count: u32,
    /// Total blocks (`s_blocks_count_lo` + `s_blocks_count_hi`).
    pub blocks_count: u64,
    /// Blocks reserved for the super-user (`s_r_blocks_count`).
    pub r_blocks_count: u64,
    /// Free blocks (`s_free_blocks_count`).
    pub free_blocks_count: u64,
    /// Free inodes (`s_free_inodes_count`).
    pub free_inodes_count: u32,
    /// Block number of the first data block (`s_first_data_block`): 0 for a 4 KiB
    /// block size, 1 for 1 KiB.
    pub first_data_block: u32,
    /// Block size as `log2(size) - 10` (`s_log_block_size`): 2 for 4096.
    pub log_block_size: u32,
    /// Cluster size as `log2(size) - 10` (`s_log_cluster_size`); equal to
    /// `log_block_size` without bigalloc.
    pub log_cluster_size: u32,
    /// Blocks per group (`s_blocks_per_group`): `8 * block_size`.
    pub blocks_per_group: u32,
    /// Clusters per group (`s_clusters_per_group`).
    pub clusters_per_group: u32,
    /// Inodes per group (`s_inodes_per_group`).
    pub inodes_per_group: u32,
    /// Last mount time (`s_mtime`); zero for a never-mounted image.
    pub mtime: u32,
    /// Last write time (`s_wtime`).
    pub wtime: u32,
    /// Mounts since the last check (`s_mnt_count`).
    pub mnt_count: u16,
    /// Mounts permitted before a forced check (`s_max_mnt_count`); `0xFFFF` (−1)
    /// disables the count.
    pub max_mnt_count: u16,
    /// Magic number (`s_magic`), always [`SUPERBLOCK_MAGIC`].
    pub magic: u16,
    /// Filesystem state (`s_state`): 1 when cleanly unmounted.
    pub state: u16,
    /// Error behavior (`s_errors`): 1 to continue.
    pub errors: u16,
    /// Minor revision (`s_minor_rev_level`).
    pub minor_rev_level: u16,
    /// Last check time (`s_lastcheck`).
    pub lastcheck: u32,
    /// Seconds between forced checks (`s_checkinterval`); zero disables them.
    pub checkinterval: u32,
    /// Creating OS (`s_creator_os`): 0 for Linux.
    pub creator_os: u32,
    /// Revision level (`s_rev_level`): 1 (dynamic), which the 256-byte inode and
    /// feature words require.
    pub rev_level: u32,
    /// Default reserved-block uid (`s_def_resuid`).
    pub def_resuid: u16,
    /// Default reserved-block gid (`s_def_resgid`).
    pub def_resgid: u16,
    /// First non-reserved inode (`s_first_ino`): 11.
    pub first_ino: u32,
    /// Inode size in bytes (`s_inode_size`): 256.
    pub inode_size: u16,
    /// Group number of this superblock copy (`s_block_group_nr`): 0 in the primary,
    /// the group's own number in each backup.
    pub block_group_nr: u16,
    /// `compat` feature word (`s_feature_compat`).
    pub feature_compat: u32,
    /// `incompat` feature word (`s_feature_incompat`).
    pub feature_incompat: u32,
    /// `ro_compat` feature word (`s_feature_ro_compat`).
    pub feature_ro_compat: u32,
    /// Filesystem UUID (`s_uuid`), a 16-byte input.
    pub uuid: [u8; 16],
    /// Volume label (`s_volume_name`), NUL-padded to sixteen bytes; all zero when the
    /// filesystem is unlabelled.
    pub volume_name: [u8; 16],
    /// Path last mounted on (`s_last_mounted`); empty here.
    pub last_mounted: [u8; 64],
    /// Reserved GDT blocks kept for growth (`s_reserved_gdt_blocks`).
    pub reserved_gdt_blocks: u16,
    /// Journal inode (`s_journal_inum`): 8 with a journal, 0 without.
    pub journal_inum: u32,
    /// Journal backup type (`s_jnl_backup_type`): 1 when [`jnl_blocks`](Self::jnl_blocks)
    /// holds the journal inode's block map, 0 without a journal.
    pub jnl_backup_type: u8,
    /// Backup of the journal inode's block map (`s_jnl_blocks`): its 15 `i_block`
    /// words followed by the high and low halves of its size, so a repair can find
    /// the journal even if inode 8 is damaged. All zero without a journal.
    pub jnl_blocks: [u32; 17],
    /// Directory-hash seed (`s_hash_seed`), four little-endian words.
    pub hash_seed: [u8; 16],
    /// Default directory-hash algorithm (`s_def_hash_version`): 0 legacy, 1 half-MD4,
    /// 2 TEA.
    pub def_hash_version: u8,
    /// Group-descriptor size in bytes (`s_desc_size`): 64 with `64bit`.
    pub desc_size: u16,
    /// Default mount options (`s_default_mount_opts`): `user_xattr | acl`.
    pub default_mount_opts: u32,
    /// First meta-block group (`s_first_meta_bg`). The writer never sets `meta_bg`, so
    /// it writes zero here; the field is parsed on read and may be nonzero in a
    /// foreign image.
    pub first_meta_bg: u32,
    /// Filesystem creation time (`s_mkfs_time`).
    pub mkfs_time: u32,
    /// Minimum extra-inode bytes (`s_min_extra_isize`): 32.
    pub min_extra_isize: u16,
    /// Desired extra-inode bytes (`s_want_extra_isize`): 32.
    pub want_extra_isize: u16,
    /// Miscellaneous flags (`s_flags`). Bit 0 records that directory names hash as
    /// signed bytes, bit 1 that they hash as unsigned; exactly one is set, and it
    /// tells a reader how to reproduce a name's hash.
    pub flags: u32,
    /// `log2` of groups per flex block group (`s_log_groups_per_flex`): 4, i.e. 16
    /// groups.
    pub log_groups_per_flex: u8,
    /// Metadata checksum algorithm (`s_checksum_type`): 0 while `metadata_csum` is
    /// off, 1 (crc32c) when on.
    pub checksum_type: u8,
    /// Lifetime kibibytes written (`s_kbytes_written`); a statistic, not geometry.
    pub kbytes_written: u64,
    /// Blocks the filesystem's own metadata occupies (`s_overhead_clusters`); a
    /// checker recomputes it, so it is a hint rather than an authority.
    pub overhead_clusters: u32,
    /// The seed every metadata checksum derives from (`s_checksum_seed`):
    /// `crc32c(!0, uuid)` when `metadata_csum_seed` is set, zero when it is not. Storing it
    /// decouples the checksums from the UUID; the value is the one the UUID yields, so
    /// the checksums are identical either way.
    pub checksum_seed: u32,
    /// The inode holding the orphan file (`s_orphan_file_inum`): the first inode past
    /// `/lost+found` when `orphan_file` is set, zero when it is not.
    pub orphan_file_inum: u32,
    /// Superblock crc32c (`s_checksum`), written through the checksum seam; zero
    /// while `metadata_csum` is off.
    pub checksum: u32,
}

impl SuperBlock {
    /// On-disk size of the superblock record.
    pub const SIZE: usize = 1024;

    // The offsets of the fields something outside this module reaches by address rather than
    // through the parsed record: identifying an image from its bytes, patching an identity in
    // place, and checksumming the record all work on the raw 1024 bytes. Every other field's
    // offset is named in its own documentation and written only here, because nothing else
    // addresses it.

    /// Byte offset of `s_magic`, which is what identifies the record as a superblock at all.
    pub const MAGIC_OFFSET: usize = 0x38;
    /// Byte offset of `s_feature_incompat`.
    pub const FEATURE_INCOMPAT_OFFSET: usize = 0x60;
    /// Byte offset of `s_uuid`, sixteen bytes.
    pub const UUID_OFFSET: usize = 0x68;
    /// Byte offset of `s_volume_name`, sixteen bytes.
    pub const VOLUME_NAME_OFFSET: usize = 0x78;
    /// Byte offset of `s_checksum_seed`.
    pub const CHECKSUM_SEED_OFFSET: usize = 0x270;
    /// Byte offset of `s_checksum`, the last word of the record — and so the length of what
    /// its checksum covers, which is why the two are one constant rather than
    /// [`SIZE`](Self::SIZE)` - 4` in one place and `0x3fc` in another.
    pub const CHECKSUM_OFFSET: usize = Self::SIZE - 4;

    /// A superblock with every field zero and the magic set. The materializer fills
    /// in geometry and features.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inodes_count: 0,
            blocks_count: 0,
            r_blocks_count: 0,
            free_blocks_count: 0,
            free_inodes_count: 0,
            first_data_block: 0,
            log_block_size: 0,
            log_cluster_size: 0,
            blocks_per_group: 0,
            clusters_per_group: 0,
            inodes_per_group: 0,
            mtime: 0,
            wtime: 0,
            mnt_count: 0,
            max_mnt_count: 0,
            magic: SUPERBLOCK_MAGIC,
            state: 0,
            errors: 0,
            minor_rev_level: 0,
            lastcheck: 0,
            checkinterval: 0,
            creator_os: 0,
            rev_level: 0,
            def_resuid: 0,
            def_resgid: 0,
            first_ino: 0,
            inode_size: 0,
            block_group_nr: 0,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
            uuid: [0; 16],
            volume_name: [0; 16],
            last_mounted: [0; 64],
            reserved_gdt_blocks: 0,
            journal_inum: 0,
            jnl_backup_type: 0,
            jnl_blocks: [0; 17],
            hash_seed: [0; 16],
            def_hash_version: 0,
            desc_size: 0,
            default_mount_opts: 0,
            first_meta_bg: 0,
            mkfs_time: 0,
            min_extra_isize: 0,
            want_extra_isize: 0,
            flags: 0,
            log_groups_per_flex: 0,
            checksum_type: 0,
            kbytes_written: 0,
            overhead_clusters: 0,
            checksum_seed: 0,
            orphan_file_inum: 0,
            checksum: 0,
        }
    }

    /// Serialize to the 1024-byte on-disk form. Reserved regions are written zero.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        let (blocks_lo, blocks_hi) = split64(self.blocks_count);
        let (r_blocks_lo, r_blocks_hi) = split64(self.r_blocks_count);
        let (free_lo, free_hi) = split64(self.free_blocks_count);

        put_u32(&mut b, 0x00, self.inodes_count);
        put_u32(&mut b, 0x04, blocks_lo);
        put_u32(&mut b, 0x08, r_blocks_lo);
        put_u32(&mut b, 0x0c, free_lo);
        put_u32(&mut b, 0x10, self.free_inodes_count);
        put_u32(&mut b, 0x14, self.first_data_block);
        put_u32(&mut b, 0x18, self.log_block_size);
        put_u32(&mut b, 0x1c, self.log_cluster_size);
        put_u32(&mut b, 0x20, self.blocks_per_group);
        put_u32(&mut b, 0x24, self.clusters_per_group);
        put_u32(&mut b, 0x28, self.inodes_per_group);
        put_u32(&mut b, 0x2c, self.mtime);
        put_u32(&mut b, 0x30, self.wtime);
        put_u16(&mut b, 0x34, self.mnt_count);
        put_u16(&mut b, 0x36, self.max_mnt_count);
        put_u16(&mut b, Self::MAGIC_OFFSET, self.magic);
        put_u16(&mut b, 0x3a, self.state);
        put_u16(&mut b, 0x3c, self.errors);
        put_u16(&mut b, 0x3e, self.minor_rev_level);
        put_u32(&mut b, 0x40, self.lastcheck);
        put_u32(&mut b, 0x44, self.checkinterval);
        put_u32(&mut b, 0x48, self.creator_os);
        put_u32(&mut b, 0x4c, self.rev_level);
        put_u16(&mut b, 0x50, self.def_resuid);
        put_u16(&mut b, 0x52, self.def_resgid);
        put_u32(&mut b, 0x54, self.first_ino);
        put_u16(&mut b, 0x58, self.inode_size);
        put_u16(&mut b, 0x5a, self.block_group_nr);
        put_u32(&mut b, 0x5c, self.feature_compat);
        put_u32(&mut b, Self::FEATURE_INCOMPAT_OFFSET, self.feature_incompat);
        put_u32(&mut b, 0x64, self.feature_ro_compat);
        put_arr(&mut b, Self::UUID_OFFSET, &self.uuid);
        put_arr(&mut b, Self::VOLUME_NAME_OFFSET, &self.volume_name);
        put_arr(&mut b, 0x88, &self.last_mounted);
        put_u16(&mut b, 0xce, self.reserved_gdt_blocks);
        put_u32(&mut b, 0xe0, self.journal_inum);
        put_arr(&mut b, 0xec, &self.hash_seed);
        put_u8(&mut b, 0xfc, self.def_hash_version);
        put_u8(&mut b, 0xfd, self.jnl_backup_type);
        put_u16(&mut b, 0xfe, self.desc_size);
        put_u32(&mut b, 0x100, self.default_mount_opts);
        put_u32(&mut b, 0x104, self.first_meta_bg);
        put_u32(&mut b, 0x108, self.mkfs_time);
        for (i, &w) in self.jnl_blocks.iter().enumerate() {
            put_u32(&mut b, 0x10c + i * 4, w);
        }
        put_u32(&mut b, 0x150, blocks_hi);
        put_u32(&mut b, 0x154, r_blocks_hi);
        put_u32(&mut b, 0x158, free_hi);
        put_u16(&mut b, 0x15c, self.min_extra_isize);
        put_u16(&mut b, 0x15e, self.want_extra_isize);
        put_u32(&mut b, 0x160, self.flags);
        put_u8(&mut b, 0x174, self.log_groups_per_flex);
        put_u8(&mut b, 0x175, self.checksum_type);
        let (kb_lo, kb_hi) = split64(self.kbytes_written);
        put_u32(&mut b, 0x178, kb_lo);
        put_u32(&mut b, 0x17c, kb_hi);
        put_u32(&mut b, 0x248, self.overhead_clusters);
        put_u32(&mut b, Self::CHECKSUM_SEED_OFFSET, self.checksum_seed);
        put_u32(&mut b, 0x280, self.orphan_file_inum);
        put_u32(&mut b, Self::CHECKSUM_OFFSET, self.checksum);
        b
    }

    /// Parse from the on-disk form, validating the magic number.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] if `buf` is shorter than [`SIZE`](Self::SIZE);
    /// [`ParseError::BadMagic`] if `s_magic` is not [`SUPERBLOCK_MAGIC`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "SuperBlock",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        let magic = get_u16(buf, Self::MAGIC_OFFSET);
        if magic != SUPERBLOCK_MAGIC {
            return Err(ParseError::BadMagic {
                structure: "SuperBlock",
                found: u32::from(magic),
                expected: u32::from(SUPERBLOCK_MAGIC),
            });
        }
        // The three block counts carry a high half only under `64bit`. Without that
        // feature the words at 0x150-0x158 are outside the format's reach and hold
        // whatever an older tool left there, so joining them would inflate a healthy
        // 32-bit filesystem's size — and with it every bound derived from it. The
        // feature word decides, read from the buffer being parsed.
        let hi = |off| {
            if get_u32(buf, Self::FEATURE_INCOMPAT_OFFSET) & INCOMPAT_64BIT != 0 {
                get_u32(buf, off)
            } else {
                0
            }
        };
        Ok(Self {
            inodes_count: get_u32(buf, 0x00),
            blocks_count: join64(get_u32(buf, 0x04), hi(0x150)),
            r_blocks_count: join64(get_u32(buf, 0x08), hi(0x154)),
            free_blocks_count: join64(get_u32(buf, 0x0c), hi(0x158)),
            free_inodes_count: get_u32(buf, 0x10),
            first_data_block: get_u32(buf, 0x14),
            log_block_size: get_u32(buf, 0x18),
            log_cluster_size: get_u32(buf, 0x1c),
            blocks_per_group: get_u32(buf, 0x20),
            clusters_per_group: get_u32(buf, 0x24),
            inodes_per_group: get_u32(buf, 0x28),
            mtime: get_u32(buf, 0x2c),
            wtime: get_u32(buf, 0x30),
            mnt_count: get_u16(buf, 0x34),
            max_mnt_count: get_u16(buf, 0x36),
            magic,
            state: get_u16(buf, 0x3a),
            errors: get_u16(buf, 0x3c),
            minor_rev_level: get_u16(buf, 0x3e),
            lastcheck: get_u32(buf, 0x40),
            checkinterval: get_u32(buf, 0x44),
            creator_os: get_u32(buf, 0x48),
            rev_level: get_u32(buf, 0x4c),
            def_resuid: get_u16(buf, 0x50),
            def_resgid: get_u16(buf, 0x52),
            first_ino: get_u32(buf, 0x54),
            inode_size: get_u16(buf, 0x58),
            block_group_nr: get_u16(buf, 0x5a),
            feature_compat: get_u32(buf, 0x5c),
            feature_incompat: get_u32(buf, Self::FEATURE_INCOMPAT_OFFSET),
            feature_ro_compat: get_u32(buf, 0x64),
            uuid: get_arr(buf, Self::UUID_OFFSET),
            volume_name: get_arr(buf, Self::VOLUME_NAME_OFFSET),
            last_mounted: get_arr(buf, 0x88),
            reserved_gdt_blocks: get_u16(buf, 0xce),
            journal_inum: get_u32(buf, 0xe0),
            jnl_backup_type: get_u8(buf, 0xfd),
            jnl_blocks: {
                let mut w = [0u32; 17];
                for (i, slot) in w.iter_mut().enumerate() {
                    *slot = get_u32(buf, 0x10c + i * 4);
                }
                w
            },
            hash_seed: get_arr(buf, 0xec),
            def_hash_version: get_u8(buf, 0xfc),
            desc_size: get_u16(buf, 0xfe),
            default_mount_opts: get_u32(buf, 0x100),
            first_meta_bg: get_u32(buf, 0x104),
            mkfs_time: get_u32(buf, 0x108),
            min_extra_isize: get_u16(buf, 0x15c),
            want_extra_isize: get_u16(buf, 0x15e),
            flags: get_u32(buf, 0x160),
            log_groups_per_flex: get_u8(buf, 0x174),
            checksum_type: get_u8(buf, 0x175),
            kbytes_written: join64(get_u32(buf, 0x178), get_u32(buf, 0x17c)),
            overhead_clusters: get_u32(buf, 0x248),
            checksum_seed: get_u32(buf, Self::CHECKSUM_SEED_OFFSET),
            orphan_file_inum: get_u32(buf, 0x280),
            checksum: get_u32(buf, Self::CHECKSUM_OFFSET),
        })
    }
}

impl Default for SuperBlock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A superblock carrying the header field values from the 64 MiB
    /// baseline, for both round-trip and ground-truth checks.
    fn baseline() -> SuperBlock {
        let mut s = SuperBlock::new();
        s.inodes_count = 16384;
        s.blocks_count = 16384;
        s.r_blocks_count = 819;
        s.free_blocks_count = 15347;
        s.free_inodes_count = 16373;
        s.first_data_block = 0;
        s.log_block_size = 2;
        s.log_cluster_size = 2;
        s.blocks_per_group = 32768;
        s.clusters_per_group = 32768;
        s.inodes_per_group = 16384;
        s.wtime = 1_700_000_000;
        s.max_mnt_count = 0xffff;
        s.state = 1;
        s.errors = 1;
        s.lastcheck = 1_700_000_000;
        s.rev_level = 1;
        s.first_ino = 11;
        s.inode_size = 256;
        s.feature_compat = 0x18;
        s.feature_incompat = 0x2c2;
        s.feature_ro_compat = 0x46b;
        s.checksum_type = 1;
        s.uuid = [
            0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
        ];
        s.reserved_gdt_blocks = 3;
        s.def_hash_version = 1;
        s.desc_size = 64;
        s.default_mount_opts = 0x0c;
        s.mkfs_time = 1_700_000_000;
        s.min_extra_isize = 32;
        s.want_extra_isize = 32;
        s.flags = 1;
        s.log_groups_per_flex = 4;
        s
    }

    #[test]
    fn round_trips() {
        let s = baseline();
        assert_eq!(SuperBlock::read_from(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn matches_ground_truth_offsets() {
        // Field-for-field against the decoded 64 MiB baseline superblock.
        let b = baseline().to_bytes();
        assert_eq!(get_u16(&b, 0x38), 0xef53, "magic");
        assert_eq!(get_u32(&b, 0x18), 2, "log_block_size");
        assert_eq!(get_u32(&b, 0x20), 32768, "blocks_per_group");
        assert_eq!(get_u32(&b, 0x54), 11, "first_ino");
        assert_eq!(get_u16(&b, 0x58), 256, "inode_size");
        assert_eq!(get_u32(&b, 0x5c), 0x18, "feature_compat");
        assert_eq!(get_u32(&b, 0x60), 0x2c2, "feature_incompat");
        assert_eq!(get_u32(&b, 0x64), 0x46b, "feature_ro_compat");
        assert_eq!(get_u8(&b, 0x175), 1, "checksum_type: crc32c");
        assert_eq!(get_u16(&b, 0xce), 3, "reserved_gdt_blocks");
        assert_eq!(get_u16(&b, 0xfe), 64, "desc_size");
        assert_eq!(get_u32(&b, 0x100), 0x0c, "default_mount_opts");
        assert_eq!(get_u16(&b, 0x15c), 32, "min_extra_isize");
        assert_eq!(get_u32(&b, 0x160), 1, "flags: signed hash");
        assert_eq!(get_u8(&b, 0x174), 4, "log_groups_per_flex");
        assert_eq!(&b[0x68..0x6c], &[0xf0, 0xe1, 0x70, 0x55], "uuid prefix");
    }

    #[test]
    fn the_block_counts_take_their_high_words_only_under_64bit() {
        // The words at 0x150-0x158 belong to the format only when `64bit` is set. On a
        // filesystem without it they are outside the format's reach and hold whatever an
        // older tool left there, so a reader that joins them unconditionally inflates a
        // healthy 32-bit filesystem's size — and every bound derived from it, including
        // the one that decides whether a block pointer is in range.
        let mut b = baseline().to_bytes(); // feature_incompat 0x2c2 carries 64bit
        put_u32(&mut b, 0x150, 1);
        put_u32(&mut b, 0x154, 2);
        put_u32(&mut b, 0x158, 3);

        let wide = SuperBlock::read_from(&b).unwrap();
        assert_eq!(wide.blocks_count, 16384 + (1 << 32));
        assert_eq!(wide.r_blocks_count, 819 + (2 << 32));
        assert_eq!(wide.free_blocks_count, 15347 + (3 << 32));

        // The same bytes with `64bit` cleared: the low words stand alone.
        put_u32(&mut b, 0x60, 0x2c2 & !INCOMPAT_64BIT);
        let narrow = SuperBlock::read_from(&b).unwrap();
        assert_eq!(narrow.blocks_count, 16384);
        assert_eq!(narrow.r_blocks_count, 819);
        assert_eq!(narrow.free_blocks_count, 15347);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = baseline().to_bytes();
        b[0x38] = 0;
        b[0x39] = 0;
        assert!(matches!(
            SuperBlock::read_from(&b),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(
            SuperBlock::read_from(&[0u8; 512]),
            Err(ParseError::TooShort { .. })
        ));
    }
}
