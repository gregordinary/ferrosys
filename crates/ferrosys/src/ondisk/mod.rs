//! On-disk structures: the pure byte layer where a one-byte offset error is a
//! silent corruption.
//!
//! Every ext4 metadata object — superblock, group descriptor, inode, extent-tree
//! node, directory entry — is defined here as a Rust value with symmetric
//! serialization: a `to_bytes`/`write_to` that produces its little-endian on-disk
//! form and a `read_from` that recovers it. ext4 is little-endian on disk
//! regardless of host byte order, so serialization goes through the explicit
//! accessors in this module rather than any reinterpret-cast; there is no
//! `unsafe`, no `transmute`, and no `#[repr(C)]` reliance.
//!
//! This module is pure: it moves bytes to and from values and validates what it
//! parses. It allocates no blocks and performs no I/O. Split 32/64-bit fields
//! carry their high halves in the model even where a value fits in 32 bits, so
//! widening addressing is a change of the value written, not of the type.
//!
//! The `get_*`/`put_*` helpers every field goes through are
//! [`crate::bytes`], re-exported here so a layer module reaches them
//! through the on-disk module it belongs to. They index at struct-internal constant
//! offsets into a buffer the caller has already sized to at least the struct's `SIZE`
//! (`from_bytes` takes a fixed-size array; `read_from` length-checks first).

mod dirent;
mod extent;
mod group_desc;
mod htree;
mod inode;
mod orphan;
mod superblock;
mod xattr;

pub use dirent::{
    DIR_TAIL_LEN, DirEntry, FileType, min_rec_len, rec_len_from_disk, rec_len_to_disk,
    write_dir_tail,
};
pub use extent::{
    EXTENT_ENTRY_SIZE, EXTENT_MAGIC, EXTENT_TAIL_LEN, ExtentHeader, ExtentIdx, ExtentLeaf,
};
pub use group_desc::{BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, GroupDescriptor};
pub use htree::{
    DX_CHECKSUM_OFFSET, DX_ENTRY_LEN, DX_HASH_CONTINUED, DX_MAX_INDIRECT_LEVELS,
    DX_NODE_COUNT_OFFSET, DX_ROOT_COUNT_OFFSET, DX_TAIL_LEN, DxEntry, dx_limit, dx_tail_offset,
    read_dx_countlimit, read_dx_entries, read_dx_root_info, write_dx_entries, write_dx_node_header,
    write_dx_root_header, write_dx_tail,
};
pub use inode::{
    GOOD_OLD_FIRST_INODE, GOOD_OLD_SIZE as GOOD_OLD_INODE_SIZE, Inode, InodeFlags, ROOT_INODE_MODE,
    TIME_SECS_MAX, TIME_SECS_MIN, decode_time, encode_time, extra_isize_for, time_is_representable,
};
pub(crate) use inode::{decode_device, encode_device};
pub use orphan::{
    ORPHAN_BLOCK_MAGIC, ORPHAN_TAIL_LEN, orphan_entries_len, orphan_tail_bytes, read_orphan_tail,
};
pub use superblock::{SUPERBLOCK_MAGIC, SuperBlock};
pub(crate) use xattr::{
    block_len as xattr_block_len, encode_block, encode_inline, has_empty_name, longest_stored_name,
    parse_block, parse_inline, split_for_storage,
};
pub use xattr::{decode_acl, encode_acl};

/// A failure parsing an on-disk structure from bytes.
///
/// Each variant names the on-disk context that makes the failure diagnosable: the
/// structure whose length fell short, or the magic number that did not match.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was shorter than the structure requires.
    #[error("{structure}: need {need} bytes, got {got}")]
    #[non_exhaustive]
    TooShort {
        /// The structure being parsed.
        structure: &'static str,
        /// Bytes the structure requires.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// A magic-number field did not hold its required value.
    #[error("{structure}: bad magic {found:#06x}, expected {expected:#06x}")]
    #[non_exhaustive]
    BadMagic {
        /// The structure being parsed.
        structure: &'static str,
        /// The value found on disk.
        found: u32,
        /// The value the format requires.
        expected: u32,
    },
    /// A field held a value the format does not allow (e.g. a directory record
    /// length that runs past its block).
    #[error("{structure}: field {field} has invalid value {value}")]
    #[non_exhaustive]
    InvalidField {
        /// The structure being parsed.
        structure: &'static str,
        /// The offending field.
        field: &'static str,
        /// The value found on disk.
        value: u64,
    },
}

pub(crate) use crate::bytes::{
    get_arr, get_u8, get_u16, get_u32, put_arr, put_u8, put_u16, put_u32,
};

/// Split a 64-bit value into `(lo, hi)` 32-bit halves for the split fields ext4
/// stores as separate low and high words.
#[inline]
pub(crate) fn split64(v: u64) -> (u32, u32) {
    (v as u32, (v >> 32) as u32)
}

/// Recombine a value ext4 stores as separate low and high 32-bit words.
#[inline]
pub(crate) fn join64(lo: u32, hi: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_join_are_inverse() {
        let v = 0x1234_5678_9abc_def0u64;
        let (lo, hi) = split64(v);
        assert_eq!(lo, 0x9abc_def0);
        assert_eq!(hi, 0x1234_5678);
        assert_eq!(join64(lo, hi), v);
    }
}
