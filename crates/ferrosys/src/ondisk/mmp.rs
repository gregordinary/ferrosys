//! The multiple-mount protection block: the record a host keeps current while it has the
//! filesystem open, laid out as the ext4 documentation's "Multiple Mount Protection" page
//! gives it.

use crate::bytes::get_u32;

/// The block's magic number, `"MMP"` (documented).
pub(crate) const MMP_MAGIC: u32 = 0x004D_4D50;

/// Where the block's checksum sits: the last word of its 1024-byte structure (documented). It
/// covers every byte before it, seeded as the filesystem's other metadata checksums are
/// (observed on the pinned `mke2fs`).
pub(crate) const MMP_CHECKSUM_OFFSET: usize = 0x3FC;

/// The sequence a filesystem no host has open records: the one the pinned `mke2fs` writes and
/// `e2fsck` checks without waiting (observed).
pub(crate) const MMP_SEQ_CLEAN: u32 = 0xFF4D_4D50;

/// The sequence a checker records while it runs: the pinned `e2fsck` refuses a filesystem
/// holding it, saying a check is running (observed).
pub(crate) const MMP_SEQ_FSCK: u32 = 0xE24D_4D50;

/// The largest sequence a host with the filesystem open records: the pinned `e2fsck` waits on
/// one at or below it to see whether it changes, and refuses one above it that is neither of
/// the two above (observed).
pub(crate) const MMP_SEQ_MAX: u32 = 0xE24D_4D4F;

/// The fields a reader holds the block to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mmp {
    /// `mmp_magic`.
    pub(crate) magic: u32,
    /// `mmp_seq`.
    pub(crate) sequence: u32,
    /// `mmp_checksum`.
    pub(crate) checksum: u32,
}

impl Mmp {
    /// The record at the start of `block`, which is at least [`MMP_CHECKSUM_OFFSET`] + 4
    /// bytes, as every block size ext4 has is.
    pub(crate) fn read_from(block: &[u8]) -> Self {
        Self {
            magic: get_u32(block, 0x0),
            sequence: get_u32(block, 0x4),
            checksum: get_u32(block, MMP_CHECKSUM_OFFSET),
        }
    }
}
