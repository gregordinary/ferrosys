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
//! The bytes are consumed eight at a time through eight tables, the slicing-by-8 method
//! of Kounavis and Berry ("A Systematic Approach to Building High Performance Software-based
//! CRC Generators", ISCC 2005). Table `k` holds, for each byte value, the CRC that byte
//! contributes when `k` further bytes follow it, so one step folds eight bytes with eight
//! independent lookups where a byte-at-a-time loop makes eight dependent ones. The tail of
//! fewer than eight bytes goes through the first table a byte at a time, which is the same
//! arithmetic with `k` zero.
//!
//! This module is pure and allocates nothing.

/// The reflected Castagnoli polynomial: `0x1EDC_6F41` reflected is `0x82F6_3B78`.
const POLY: u32 = 0x82F6_3B78;

/// The eight lookup tables, built at compile time. `TABLES[0]` is one byte's worth of
/// polynomial division per entry, and `TABLES[k]` is that byte followed by `k` zero bytes.
const TABLES: [[u32; 256]; 8] = build_tables();

/// Build the reflected tables for [`POLY`].
const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut n = 0usize;
    while n < 256 {
        let mut crc = n as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                POLY ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][n] = crc;
        n += 1;
    }
    // One more zero byte after each entry of the table before: shift it a byte along and
    // fold the byte that falls out back in through the first table.
    let mut k = 1usize;
    while k < 8 {
        let mut n = 0usize;
        while n < 256 {
            let prev = tables[k - 1][n];
            tables[k][n] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            n += 1;
        }
        k += 1;
    }
    tables
}

/// crc32c of `data`, continued from `seed`.
///
/// No final inversion is applied: the raw CRC state is returned so a caller chains a
/// base seed, an object's identity, and its bytes into one running checksum. With an
/// empty `data` the seed is returned unchanged. To obtain the standalone CRC-32C check
/// value of a message, seed with `!0` and invert the result.
#[must_use]
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let [t0, t1, t2, t3, t4, t5, t6, t7] = &TABLES;
    let (words, tail) = data.as_chunks::<8>();
    let mut crc = seed;
    for word in words {
        // The first four bytes meet the running CRC, so they are looked up through it; the
        // last four are looked up as themselves. The table index is how many bytes follow.
        let low = crc ^ crate::bytes::get_u32(word, 0);
        crc = t7[(low & 0xff) as usize]
            ^ t6[((low >> 8) & 0xff) as usize]
            ^ t5[((low >> 16) & 0xff) as usize]
            ^ t4[(low >> 24) as usize]
            ^ t3[usize::from(word[4])]
            ^ t2[usize::from(word[5])]
            ^ t1[usize::from(word[6])]
            ^ t0[usize::from(word[7])];
    }
    for &byte in tail {
        crc = (crc >> 8) ^ t0[((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The polynomial division itself, a bit at a time: the definition every table is a
    /// precomputation of, and so the reference the tables are held to.
    fn bitwise(seed: u32, data: &[u8]) -> u32 {
        let mut crc = seed;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    POLY ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    /// Bytes that are not a pattern a table could get right by accident: a linear
    /// congruential sequence, so every run differs from the next.
    fn noise(len: usize, mut state: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 56) as u8
            })
            .collect()
    }

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
        assert_eq!(crc32c(0, &[0]), TABLES[0][0]);
        assert_eq!(crc32c(0, &[0]), 0);
    }

    #[test]
    fn every_table_is_its_byte_followed_by_that_many_zero_bytes() {
        for (k, table) in TABLES.iter().enumerate() {
            for byte in 0..=255u8 {
                let mut message = vec![0u8; k + 1];
                message[0] = byte;
                assert_eq!(table[usize::from(byte)], bitwise(0, &message), "table {k}");
            }
        }
    }

    #[test]
    fn every_length_and_alignment_matches_the_bitwise_definition() {
        // Every length across several eight-byte steps, so each count of tail bytes meets each
        // count of whole steps, and every starting offset inside a word, so a slice that does
        // not begin on an eight-byte boundary is covered too.
        let bytes = noise(4096 + 8, 0x5eed);
        for start in 0..8 {
            for len in 0..80 {
                let data = &bytes[start..start + len];
                for seed in [0, !0, 0x1234_5678] {
                    assert_eq!(
                        crc32c(seed, data),
                        bitwise(seed, data),
                        "start {start}, length {len}, seed {seed:#x}"
                    );
                }
            }
        }
        // And one long run, the size of a tree block.
        assert_eq!(crc32c(!0, &bytes[3..4099]), bitwise(!0, &bytes[3..4099]));
    }
}
