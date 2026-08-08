//! Little-endian byte accessors: the primitive every family's on-disk layer serializes
//! through.
//!
//! Filesystem metadata is little-endian on disk regardless of host byte order, and this
//! crate spells that out at every field rather than reinterpreting memory. These helpers
//! are what "spelled out" means: a read or a write names its offset, its width, and its
//! byte order, so a one-byte offset error is visible at the call site instead of hidden in
//! a struct definition.
//!
//! They live at the crate root because two families compute them identically — the same
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
}
