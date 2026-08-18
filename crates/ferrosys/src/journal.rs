//! The format-time jbd2 journal: sizing and the v2 journal superblock.
//!
//! A journal is a regular file (inode 8) whose data blocks hold the jbd2 log. At
//! format time the log is empty: its first block is the journal superblock and every
//! following block is zero, so there is nothing to replay. This module decides how
//! large that file is and produces the superblock block; the materializer allocates
//! the blocks and roots the extent tree that maps them.
//!
//! Unlike every other on-disk structure in the crate, the jbd2 superblock is
//! **big-endian** — jbd2 fixes its byte order rather than following the host or the
//! ext4 little-endian convention — so it serializes through [`get_u32_be`] and
//! [`put_u32_be`] rather than the little-endian accessors every other structure in the
//! crate reads. Both live beside those, so this module names the byte order it needs
//! rather than spelling it a second time.

use crate::bytes::{get_u32_be, put_u32_be};

/// The jbd2 superblock magic (`h_magic`).
pub const JBD2_MAGIC: u32 = 0xc03b_3998;

/// The v2 journal-superblock block type (`h_blocktype`).
pub const JBD2_SUPERBLOCK_V2: u32 = 4;

/// The smallest journal jbd2 accepts, in filesystem blocks.
pub const MIN_JOURNAL_BLOCKS: u32 = 1024;

/// The size of `journal_superblock_t`, the record at the front of the journal's first
/// block.
///
/// A log's block is at least this large, and the record's own checksum covers exactly
/// these bytes rather than the whole block.
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;

/// Byte offsets within the journal superblock of the fields a re-identification reads and
/// writes.
///
/// A module rather than constants on a type, which is what every other on-disk structure here
/// gets, because this is the one structure the crate does not model: the log's superblock is
/// built and patched as raw bytes, since nothing reads its fields back as a record. A module
/// of offsets is what an unmodelled structure has instead of a type to hang them on.
pub(crate) mod offset {
    /// `s_feature_incompat`.
    pub const FEATURE_INCOMPAT: usize = 0x28;
    /// `s_uuid`: the filesystem this log serves, as the log records it.
    pub const UUID: usize = 0x30;
    /// `s_checksum_type`.
    pub const CHECKSUM_TYPE: usize = 0x50;
    /// `s_checksum`, which covers the whole record.
    pub const CHECKSUM: usize = 0xfc;
}

/// `JBD2_FEATURE_INCOMPAT_CSUM_V2`: the log's blocks and its superblock carry crc32c.
pub(crate) const INCOMPAT_CSUM_V2: u32 = 0x0000_0008;

/// `JBD2_FEATURE_INCOMPAT_CSUM_V3`: the same, with a wider block tag.
pub(crate) const INCOMPAT_CSUM_V3: u32 = 0x0000_0010;

/// `JBD2_CRC32C_CHKSUM`: the checksum type a `csum_v2` or `csum_v3` log names, and the only
/// one jbd2 accepts for either.
pub(crate) const CRC32C_CHKSUM: u8 = 4;

/// Whether a log whose superblock is `record` carries a checksum in that superblock.
///
/// `csum_v2` and `csum_v3` each put one there. `JBD2_FEATURE_COMPAT_CHECKSUM` — the older
/// scheme, a compat feature — checksums a commit block and leaves the superblock without
/// one, so a log carrying only that has nothing here to keep in agreement.
///
/// Linux sets `csum_v3` on the log of any filesystem carrying `metadata_csum` the first
/// time it mounts it, so a log without either is one that has never been mounted.
///
/// # Panics
///
/// If `record` is shorter than [`SUPERBLOCK_SIZE`].
pub(crate) fn superblock_is_checksummed(record: &[u8]) -> bool {
    assert!(record.len() >= SUPERBLOCK_SIZE, "a whole record is needed");
    get_u32_be(record, offset::FEATURE_INCOMPAT) & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) != 0
}

/// The checksum a journal superblock's bytes compute to: crc32c over the whole
/// [`SUPERBLOCK_SIZE`]-byte record, seeded from `!0`, with the checksum field itself read
/// as zero.
///
/// jbd2 stores the result big-endian at [`offset::CHECKSUM`], as it stores every other word
/// of this record — the one structure in the format whose byte order is not ext's.
///
/// # Panics
///
/// If `record` is shorter than [`SUPERBLOCK_SIZE`].
pub(crate) fn superblock_checksum(record: &[u8]) -> u32 {
    use crate::crc32c::crc32c;
    assert!(record.len() >= SUPERBLOCK_SIZE, "a whole record is needed");
    let c = crc32c(!0, &record[..offset::CHECKSUM]);
    let c = crc32c(c, &[0u8; 4]);
    crc32c(c, &record[offset::CHECKSUM + 4..SUPERBLOCK_SIZE])
}

/// How large the journal should be.
///
/// [`Auto`](JournalSize::Auto) sizes it from the filesystem's block count with the
/// standard heuristic; [`Blocks`](JournalSize::Blocks) fixes an explicit size. To
/// build a filesystem with no journal at all, clear
/// [`Compat::HAS_JOURNAL`](crate::feature::Compat::HAS_JOURNAL) from the feature set
/// rather than choosing a size here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum JournalSize {
    /// Size the journal from the filesystem's block count.
    #[default]
    Auto,
    /// Use an explicit journal size in filesystem blocks. Must be at least
    /// [`MIN_JOURNAL_BLOCKS`].
    Blocks(u32),
}

/// The journal size the standard heuristic picks for a filesystem of `num_blocks`
/// filesystem blocks, or `None` when the filesystem is too small to hold even the
/// minimum journal.
///
/// The size grows in steps for small and medium filesystems and then scales as
/// `num_blocks / 128`, bounded to `[16384, 262144]` blocks.
#[must_use]
pub fn default_journal_blocks(num_blocks: u64) -> Option<u32> {
    if num_blocks < 2048 {
        None
    } else if num_blocks < 32_768 {
        Some(1024)
    } else if num_blocks < 262_144 {
        Some(4096)
    } else if num_blocks < 524_288 {
        Some(8192)
    } else {
        Some((num_blocks / 128).clamp(16_384, 262_144) as u32)
    }
}

/// What a journal superblock records: the log's geometry and the filesystem it serves.
///
/// Every input to [`build_superblock`] is a field here rather than a parameter. The
/// superblock's fixed fields are the ones a plain v2 log needs; the words the format
/// reserves beside them — the journal feature words, the checksum type and seed a
/// `csum_v3` log carries, the user array an external journal shares — arrive as fields
/// when they are written, not as arguments every caller must pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct JournalParams {
    /// The log's block size (`s_blocksize`), which is the filesystem's.
    pub block_size: u32,
    /// Total blocks in the log, including the superblock (`s_maxlen`).
    pub journal_blocks: u32,
    /// The filesystem UUID, which the journal records as its own (`s_uuid`).
    pub uuid: [u8; 16],
}

impl JournalParams {
    /// Parameters for an internal journal of `journal_blocks` blocks serving the
    /// filesystem with UUID `uuid`.
    #[must_use]
    pub const fn new(block_size: u32, journal_blocks: u32, uuid: [u8; 16]) -> Self {
        Self {
            block_size,
            journal_blocks,
            uuid,
        }
    }
}

/// Build the jbd2 journal superblock — the journal's first block.
///
/// The block is `block_size` bytes: the big-endian v2 superblock at its front and
/// zero after. The log is freshly formatted, so `s_start` is zero (nothing to
/// replay) and `s_sequence` is one. The filesystem UUID is what the journal records
/// as its own.
#[must_use]
pub fn build_superblock(params: &JournalParams) -> Vec<u8> {
    let &JournalParams {
        block_size,
        journal_blocks,
        uuid,
    } = params;
    let mut b = vec![0u8; block_size as usize];
    // journal_header_t.
    put_u32_be(&mut b, 0x00, JBD2_MAGIC);
    put_u32_be(&mut b, 0x04, JBD2_SUPERBLOCK_V2);
    // 0x08 h_sequence — zero in the superblock header.
    // journal_superblock_t.
    put_u32_be(&mut b, 0x0c, block_size);
    put_u32_be(&mut b, 0x10, journal_blocks);
    put_u32_be(&mut b, 0x14, 1); // s_first: the first log block, after this superblock
    put_u32_be(&mut b, 0x18, 1); // s_sequence: the first transaction is sequence 1
    // 0x1c s_start — zero: an empty log with no transactions to replay.
    // 0x20 s_errno, 0x24..0x2c s_feature_{compat,incompat,ro_compat} — all zero: no
    // journal features on a plain v2 log.
    b[0x30..0x40].copy_from_slice(&uuid); // s_uuid
    put_u32_be(&mut b, 0x40, 1); // s_nr_users: one filesystem uses this journal
    // 0x44 s_dynsuper, 0x48 s_max_transaction, 0x4c s_max_trans_data — zero.
    // 0x50 s_checksum_type — zero: a v2 log carries no superblock checksum.
    // 0x100.. s_users — zero for a single internal journal.
    b
}

/// The parsed head of a jbd2 journal superblock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct JournalSuperblock {
    /// Log block size (`s_blocksize`).
    pub block_size: u32,
    /// Total blocks in the log, including this superblock (`s_maxlen`).
    pub max_len: u32,
    /// First log block after the superblock (`s_first`).
    pub first: u32,
    /// Sequence number of the first expected transaction (`s_sequence`).
    pub sequence: u32,
    /// Block number where the log starts, or zero for an empty log (`s_start`).
    pub start: u32,
    /// Number of filesystems sharing the log (`s_nr_users`).
    pub nr_users: u32,
    /// The journal UUID (`s_uuid`).
    pub uuid: [u8; 16],
}

impl JournalSuperblock {
    /// Parse a jbd2 journal superblock from the front of `buf`.
    ///
    /// # Errors
    ///
    /// [`crate::ondisk::ParseError`] if `buf` is shorter than a superblock header,
    /// its magic is not [`JBD2_MAGIC`], or its block type is not
    /// [`JBD2_SUPERBLOCK_V2`].
    pub fn read_from(buf: &[u8]) -> Result<Self, crate::ondisk::ParseError> {
        use crate::ondisk::ParseError;
        // The last field read is `s_nr_users` at 0x40, which occupies bytes [0x40, 0x44),
        // so the guard covers 0x44 — not the 0x40 the header's fixed fields end at. A
        // buffer of 0x40..=0x43 bytes reaches every field up to the UUID but stops one
        // word short of `nr_users`, and must be refused rather than indexed past its end.
        if buf.len() < 0x44 {
            return Err(ParseError::TooShort {
                structure: "JournalSuperblock",
                need: 0x44,
                got: buf.len(),
            });
        }
        let magic = get_u32_be(buf, 0x00);
        if magic != JBD2_MAGIC {
            return Err(ParseError::BadMagic {
                structure: "JournalSuperblock",
                found: magic,
                expected: JBD2_MAGIC,
            });
        }
        let blocktype = get_u32_be(buf, 0x04);
        if blocktype != JBD2_SUPERBLOCK_V2 {
            return Err(ParseError::BadMagic {
                structure: "JournalSuperblock blocktype",
                found: blocktype,
                expected: JBD2_SUPERBLOCK_V2,
            });
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[0x30..0x40]);
        Ok(Self {
            block_size: get_u32_be(buf, 0x0c),
            max_len: get_u32_be(buf, 0x10),
            first: get_u32_be(buf, 0x14),
            sequence: get_u32_be(buf, 0x18),
            start: get_u32_be(buf, 0x1c),
            nr_users: get_u32_be(buf, 0x40),
            uuid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_heuristic_matches_mke2fs_across_the_range() {
        // Each pair pinned against mke2fs 1.47.0 output.
        assert_eq!(default_journal_blocks(2047), None);
        assert_eq!(default_journal_blocks(2048), Some(1024));
        assert_eq!(default_journal_blocks(16_384), Some(1024)); // 64 MiB
        assert_eq!(default_journal_blocks(32_767), Some(1024));
        assert_eq!(default_journal_blocks(32_768), Some(4096));
        assert_eq!(default_journal_blocks(131_072), Some(4096)); // 512 MiB
        assert_eq!(default_journal_blocks(261_888), Some(4096));
        assert_eq!(default_journal_blocks(262_144), Some(8192));
        assert_eq!(default_journal_blocks(393_216), Some(8192));
        assert_eq!(default_journal_blocks(524_288), Some(16_384));
        assert_eq!(default_journal_blocks(1_048_576), Some(16_384));
        assert_eq!(default_journal_blocks(1_572_864), Some(16_384));
        assert_eq!(default_journal_blocks(2_097_152), Some(16_384));
        assert_eq!(default_journal_blocks(4_194_304), Some(32_768));
        assert_eq!(default_journal_blocks(8_388_608), Some(65_536));
        assert_eq!(default_journal_blocks(33_554_432), Some(262_144));
        assert_eq!(default_journal_blocks(67_108_864), Some(262_144)); // capped
    }

    #[test]
    fn superblock_pins_the_mke2fs_byte_layout() {
        // The 64 MiB reference image: block size 4096, 1024-block journal, fs UUID.
        let uuid = [0x11u8; 16];
        let sb = build_superblock(&JournalParams::new(4096, 1024, uuid));
        assert_eq!(sb.len(), 4096);
        assert_eq!(get_u32_be(&sb, 0x00), 0xc03b_3998);
        assert_eq!(get_u32_be(&sb, 0x04), 4);
        assert_eq!(get_u32_be(&sb, 0x08), 0);
        assert_eq!(get_u32_be(&sb, 0x0c), 4096);
        assert_eq!(get_u32_be(&sb, 0x10), 1024);
        assert_eq!(get_u32_be(&sb, 0x14), 1);
        assert_eq!(get_u32_be(&sb, 0x18), 1);
        assert_eq!(get_u32_be(&sb, 0x1c), 0);
        assert_eq!(&sb[0x30..0x40], &uuid);
        assert_eq!(get_u32_be(&sb, 0x40), 1);
        // Everything past the header is zero: no features, no checksum.
        assert!(sb[0x50..].iter().all(|&x| x == 0));
    }

    #[test]
    fn superblock_round_trips_through_the_reader() {
        let uuid = [0xabu8; 16];
        let sb = build_superblock(&JournalParams::new(4096, 8192, uuid));
        let parsed = JournalSuperblock::read_from(&sb).unwrap();
        assert_eq!(
            parsed,
            JournalSuperblock {
                block_size: 4096,
                max_len: 8192,
                first: 1,
                sequence: 1,
                start: 0,
                nr_users: 1,
                uuid,
            }
        );
    }

    #[test]
    fn a_log_declares_its_superblock_checksum_through_the_incompat_word() {
        let mut sb = build_superblock(&JournalParams::new(4096, 1024, [0; 16]));
        // A freshly written log declares no features, so it carries no checksum here.
        assert!(!superblock_is_checksummed(&sb));
        // Every incompat feature that is not a checksum leaves it that way; `revoke`,
        // `64bit`, and `async_commit` are the ones an ordinary log picks up.
        for bit in [0x1u32, 0x2, 0x4, 0x20] {
            put_u32_be(&mut sb, offset::FEATURE_INCOMPAT, bit);
            assert!(
                !superblock_is_checksummed(&sb),
                "{bit:#x} is not a checksum"
            );
        }
        for bit in [INCOMPAT_CSUM_V2, INCOMPAT_CSUM_V3] {
            put_u32_be(&mut sb, offset::FEATURE_INCOMPAT, bit);
            assert!(superblock_is_checksummed(&sb), "{bit:#x} is a checksum");
        }
    }

    #[test]
    fn the_superblock_checksum_covers_the_record_and_not_its_own_field() {
        let mut sb = build_superblock(&JournalParams::new(4096, 1024, [0x33; 16]));
        let sealed = superblock_checksum(&sb);
        // Whatever the field holds, the value computed is the same — which is what lets a
        // stored checksum be verified by recomputing rather than by clearing first.
        sb[offset::CHECKSUM..offset::CHECKSUM + 4].copy_from_slice(&sealed.to_be_bytes());
        assert_eq!(superblock_checksum(&sb), sealed);
        sb[offset::CHECKSUM..offset::CHECKSUM + 4].copy_from_slice(&[0xff; 4]);
        assert_eq!(superblock_checksum(&sb), sealed);
        // Every other byte of the record is covered, including the last one before the
        // checksum field and the last one of the record itself.
        for moved in [0x00usize, offset::UUID, offset::CHECKSUM - 1, 0x100, 0x3ff] {
            let mut other = sb.clone();
            other[moved] ^= 0xff;
            assert_ne!(
                superblock_checksum(&other),
                sealed,
                "byte {moved:#x} is not covered"
            );
        }
        // And nothing past the record is: the checksum covers `journal_superblock_t`, not
        // the block it sits at the front of.
        let mut past = sb.clone();
        past[SUPERBLOCK_SIZE] ^= 0xff;
        assert_eq!(superblock_checksum(&past), sealed);
    }

    #[test]
    fn reader_rejects_a_non_journal_block() {
        let mut sb = build_superblock(&JournalParams::new(4096, 1024, [0; 16]));
        sb[0] ^= 0xff;
        assert!(JournalSuperblock::read_from(&sb).is_err());
    }

    #[test]
    fn reader_refuses_a_buffer_too_short_for_nr_users() {
        // The header's fixed fields end at 0x40, but `s_nr_users` occupies [0x40, 0x44).
        // A buffer that reaches the UUID yet stops short of `nr_users` — with a valid
        // magic and block type, so parsing gets past the early checks — must be refused
        // as too short rather than reading past its end.
        let sb = build_superblock(&JournalParams::new(4096, 1024, [0; 16]));
        for len in 0x40..0x44 {
            let err = JournalSuperblock::read_from(&sb[..len]).unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::ondisk::ParseError::TooShort {
                        structure: "JournalSuperblock",
                        need: 0x44,
                        got,
                    } if got == len
                ),
                "length {len} gave {err:?}"
            );
        }
        // The exact boundary parses.
        assert!(JournalSuperblock::read_from(&sb[..0x44]).is_ok());
    }
}
