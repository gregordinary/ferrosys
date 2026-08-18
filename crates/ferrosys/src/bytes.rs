//! Byte accessors: the primitive every family's on-disk layer serializes through.
//!
//! Filesystem metadata is little-endian on disk regardless of host byte order, and this
//! crate spells that out at every field rather than reinterpreting memory. These helpers
//! are what "spelled out" means: a read or a write names its offset, its width, and its
//! byte order, so a one-byte offset error is visible at the call site instead of hidden in
//! a struct definition.
//!
//! The unsuffixed helpers are little-endian, because nearly every word this crate touches is.
//! The `_be` pair is for the jbd2 log superblock, which is the one structure in any of these
//! formats whose byte order is not its filesystem's — and it is here rather than beside that
//! structure for the same reason the rest are here: a second spelling of "four bytes, most
//! significant first" is a second place for an offset to be wrong.
//!
//! # What is compiled where
//!
//! [`get_u16`] and [`get_u32`] are always compiled, because the POSIX ACL boundary form is a
//! fixed little-endian record and the family-agnostic substrate parses one whether or not a
//! family is present. Everything else serializes a family's on-disk structures and is
//! compiled where a family is — the 64-bit pair where exFAT or btrfs is, those being the
//! formats here whose fields are 64 bits wide rather than split across two 32-bit halves.
//!
//! They live at the crate root because the families compute them identically — the same
//! bytes in the same order with nothing interpreted — which is the whole test for whether
//! something is a shared primitive rather than a shared seam. A checksum scheme, a feature
//! word, and a directory layout each look alike across families and are implemented
//! differently by every one of them; these do not.
//!
//! This module is pure: it moves bytes to and from scalars and does no I/O.
//!
//! # Bounds
//!
//! Every helper indexes at an offset its caller has already sized the buffer for — an
//! on-disk structure's `read_from` length-checks against its `SIZE` before reading any
//! field, and every offset a structure uses is smaller than that `SIZE`. So the indexing
//! cannot exceed the slice, and no access here can panic on a correctly sized buffer.

/// Read one `u8` at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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

/// Read one little-endian `u64` at `off`.
#[inline]
#[cfg(any(feature = "exfat", feature = "btrfs"))]
pub(crate) fn get_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Read one big-endian `u32` at `off`.
#[inline]
#[cfg(feature = "ext")]
pub(crate) fn get_u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a fixed-size byte array at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn get_arr<const N: usize>(buf: &[u8], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[off..off + N]);
    out
}

/// Write one `u8` at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn put_u8(buf: &mut [u8], off: usize, v: u8) {
    buf[off] = v;
}

/// Write one little-endian `u16` at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Write one little-endian `u32` at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Write one little-endian `u64` at `off`.
#[inline]
#[cfg(any(feature = "exfat", feature = "btrfs"))]
pub(crate) fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Write one big-endian `u32` at `off`.
#[inline]
#[cfg(feature = "ext")]
pub(crate) fn put_u32_be(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Write a byte slice at `off`.
#[inline]
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn put_arr(buf: &mut [u8], off: usize, v: &[u8]) {
    buf[off..off + v.len()].copy_from_slice(v);
}

#[cfg(all(
    test,
    any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs")
))]
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
    #[cfg(any(feature = "exfat", feature = "btrfs"))]
    fn the_sixty_four_bit_pair_round_trips_and_writes_the_low_byte_first() {
        // exFAT's volume length and partition offset, and every address and length btrfs
        // records, are single 64-bit fields rather than pairs of 32-bit halves, so the width
        // is genuinely eight bytes at one offset. The bytes are asserted as well as the round
        // trip: a pair that read and wrote the same wrong order would round-trip perfectly
        // and put every such field backwards on disk.
        let mut buf = [0u8; 16];
        put_u64(&mut buf, 3, 0x0123_4567_89ab_cdef);
        assert_eq!(
            &buf[3..11],
            &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(get_u64(&buf, 3), 0x0123_4567_89ab_cdef);
        // The whole width is used: a value past 32 bits survives, which is what a volume
        // longer than four gibibytes of sectors needs.
        put_u64(&mut buf, 0, u64::MAX);
        assert_eq!(get_u64(&buf, 0), u64::MAX);
    }

    #[test]
    #[cfg(feature = "ext")]
    fn the_big_endian_pair_writes_the_other_order() {
        // The jbd2 log superblock's order, which is the one structure in either format whose
        // byte order is not its filesystem's. The bytes are asserted rather than only the
        // round trip: a pair that read and wrote the *same wrong* order would round-trip
        // perfectly and put every word of the log backwards on disk.
        let mut buf = [0u8; 8];
        put_u32_be(&mut buf, 1, 0x789a_bcde);
        assert_eq!(&buf[1..5], &[0x78, 0x9a, 0xbc, 0xde]);
        assert_eq!(get_u32_be(&buf, 1), 0x789a_bcde);
        // And it is genuinely the other order from the unsuffixed pair beside it.
        put_u32(&mut buf, 1, 0x789a_bcde);
        assert_eq!(get_u32_be(&buf, 1), 0xdebc_9a78);
    }
}
