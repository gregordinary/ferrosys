//! crc32c (Castagnoli CRC-32): the reflected, table-driven CRC-32C primitive.
//!
//! This is the reflected CRC-32C — the Castagnoli polynomial, least-significant-bit
//! first, table-driven, and pure-safe — that filesystem metadata checksums are built
//! from. The function is a *continuation*: `seed` is the starting CRC state and the
//! result is returned with no final inversion, so a caller chains a base seed, an
//! object's identity, and the object's bytes into one running checksum. The standalone
//! CRC-32C "check" value — the reflected form with an initial and final XOR of
//! `0xFFFF_FFFF` — is asserted in the tests to pin the polynomial and bit order.
//!
//! This module is pure and allocates nothing.

/// The reflected Castagnoli polynomial: `0x1EDC_6F41` reflected is `0x82F6_3B78`.
const POLY: u32 = 0x82F6_3B78;

/// The 256-entry lookup table, one byte's worth of polynomial division per entry,
/// built at compile time.
const TABLE: [u32; 256] = build_table();

/// Build the reflected byte-wise CRC table for [`POLY`].
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut crc = n as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 {
                POLY ^ (crc >> 1)
            } else {
                crc >> 1
            };
            k += 1;
        }
        table[n] = crc;
        n += 1;
    }
    table
}

/// crc32c of `data`, continued from `seed`.
///
/// No final inversion is applied: the raw CRC state is returned so a caller chains a
/// base seed, an object's identity, and its bytes into one running checksum. With an
/// empty `data` the seed is returned unchanged. To obtain the standalone CRC-32C check
/// value of a message, seed with `!0` and invert the result.
#[must_use]
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_check_value() {
        // The CRC-32C check value: reflected, init and xor-out of 0xFFFFFFFF over
        // the nine ASCII bytes "123456789". This pins the polynomial and bit order.
        assert_eq!(crc32c(!0, b"123456789") ^ !0, 0xE306_9283);
    }

    #[test]
    fn empty_input_returns_the_seed() {
        assert_eq!(crc32c(0, b""), 0);
        assert_eq!(crc32c(0xdead_beef, b""), 0xdead_beef);
    }

    #[test]
    fn continuation_equals_a_single_pass() {
        // Feeding the seed forward across two calls equals one pass over the join —
        // the property the per-object constructions rely on.
        let whole = crc32c(!0, b"ferrosys");
        let split = crc32c(crc32c(!0, b"ferro"), b"sys");
        assert_eq!(whole, split);
    }

    #[test]
    fn known_seed_over_a_single_zero_byte() {
        // A regression anchor independent of the check value: one zero byte folds the
        // table entry for the low seed byte.
        assert_eq!(crc32c(0, &[0]), TABLE[0]);
        assert_eq!(crc32c(0, &[0]), 0);
    }
}
