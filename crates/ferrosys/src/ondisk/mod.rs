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
//! # Accessor bounds
//!
//! The `get_*`/`put_*` helpers index at struct-internal constant offsets into a
//! buffer the caller has already sized to at least the struct's `SIZE`
//! (`from_bytes` takes a fixed-size array; `read_from` length-checks first). Every
//! offset used is smaller than that `SIZE`, so the indexing cannot exceed the
//! slice and no access here can panic on a correctly sized buffer.

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
    Timestamp, extra_isize_for,
};
pub(crate) use inode::{decode_device, encode_device};
pub use orphan::{
    ORPHAN_BLOCK_MAGIC, ORPHAN_TAIL_LEN, orphan_entries_len, orphan_tail_bytes, read_orphan_tail,
};
pub use superblock::{SUPERBLOCK_MAGIC, SuperBlock};
pub use xattr::Xattr;
pub(crate) use xattr::{
    block_len as xattr_block_len, encode_block, encode_inline, has_empty_name, longest_stored_name,
    parse_block, parse_inline, split_for_storage,
};

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

/// Read one `u8` at `off`.
#[inline]
pub(crate) fn get_u8(buf: &[u8], off: usize) -> u8 {
    buf[off]
}

/// Read one little-endian `u16` at `off`.
#[inline]
pub(crate) fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read one little-endian `u32` at `off`.
#[inline]
pub(crate) fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a fixed-size byte array at `off`.
#[inline]
pub(crate) fn get_arr<const N: usize>(buf: &[u8], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[off..off + N]);
    out
}

/// Write one `u8` at `off`.
#[inline]
pub(crate) fn put_u8(buf: &mut [u8], off: usize, v: u8) {
    buf[off] = v;
}

/// Write one little-endian `u16` at `off`.
#[inline]
pub(crate) fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Write one little-endian `u32` at `off`.
#[inline]
pub(crate) fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Write a byte slice at `off`.
#[inline]
pub(crate) fn put_arr(buf: &mut [u8], off: usize, v: &[u8]) {
    buf[off..off + v.len()].copy_from_slice(v);
}

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
    fn scalar_round_trips() {
        let mut buf = [0u8; 16];
        put_u8(&mut buf, 0, 0x12);
        put_u16(&mut buf, 1, 0x3456);
        put_u32(&mut buf, 3, 0x789a_bcde);
        assert_eq!(get_u8(&buf, 0), 0x12);
        assert_eq!(get_u16(&buf, 1), 0x3456);
        assert_eq!(get_u32(&buf, 3), 0x789a_bcde);
        // Little-endian on disk regardless of host.
        assert_eq!(&buf[3..7], &[0xde, 0xbc, 0x9a, 0x78]);
    }

    #[test]
    fn array_round_trips() {
        let mut buf = [0u8; 8];
        put_arr(&mut buf, 2, &[1, 2, 3, 4]);
        assert_eq!(get_arr::<4>(&buf, 2), [1, 2, 3, 4]);
    }

    #[test]
    fn split_and_join_are_inverse() {
        let v = 0x1234_5678_9abc_def0u64;
        let (lo, hi) = split64(v);
        assert_eq!(lo, 0x9abc_def0);
        assert_eq!(hi, 0x1234_5678);
        assert_eq!(join64(lo, hi), v);
    }
}
