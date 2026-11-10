//! XXH64, from the xxHash specification (Yann Collet, "xxHash fast digest algorithm", version
//! 0.2.0, section "XXH64 algorithm description").
//!
//! Every operation is modulo 2^64, input words are read little-endian, and the steps below are
//! named and ordered as the specification names and orders them.

/// The five constants the specification fixes.
const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// Bytes one stripe consumes: four lanes of eight.
const STRIPE: usize = 32;

/// Step 2's round: fold one lane into one accumulator.
const fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

/// Step 3's merge: fold one accumulator into the converged value.
const fn merge(acc: u64, value: u64) -> u64 {
    (acc ^ round(0, value))
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

/// The little-endian `u64` at `at`.
fn lane64(bytes: &[u8], at: usize) -> u64 {
    crate::bytes::get_u64(bytes, at)
}

/// The little-endian `u32` at `at`, widened.
fn lane32(bytes: &[u8], at: usize) -> u64 {
    u64::from(crate::bytes::get_u32(bytes, at))
}

/// The XXH64 digest of `bytes` under `seed`.
#[must_use]
pub(crate) fn xxh64(seed: u64, bytes: &[u8]) -> u64 {
    let len = bytes.len();
    let mut at = 0;
    // Steps 1 to 3: an input of a stripe or more runs four accumulators over its whole
    // stripes and converges them; a shorter one starts from the seed alone.
    let mut acc = if len >= STRIPE {
        let mut acc1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut acc2 = seed.wrapping_add(PRIME64_2);
        let mut acc3 = seed;
        let mut acc4 = seed.wrapping_sub(PRIME64_1);
        while at + STRIPE <= len {
            acc1 = round(acc1, lane64(bytes, at));
            acc2 = round(acc2, lane64(bytes, at + 8));
            acc3 = round(acc3, lane64(bytes, at + 16));
            acc4 = round(acc4, lane64(bytes, at + 24));
            at += STRIPE;
        }
        let mut acc = acc1
            .rotate_left(1)
            .wrapping_add(acc2.rotate_left(7))
            .wrapping_add(acc3.rotate_left(12))
            .wrapping_add(acc4.rotate_left(18));
        for value in [acc1, acc2, acc3, acc4] {
            acc = merge(acc, value);
        }
        acc
    } else {
        seed.wrapping_add(PRIME64_5)
    };
    // Step 4: the input's length.
    acc = acc.wrapping_add(len as u64);
    // Step 5: what no stripe took, eight bytes at a time, then four, then one.
    while at + 8 <= len {
        acc = (acc ^ round(0, lane64(bytes, at)))
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        at += 8;
    }
    if at + 4 <= len {
        acc = (acc ^ lane32(bytes, at).wrapping_mul(PRIME64_1))
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        at += 4;
    }
    while at < len {
        acc = (acc ^ u64::from(bytes[at]).wrapping_mul(PRIME64_5))
            .rotate_left(11)
            .wrapping_mul(PRIME64_1);
        at += 1;
    }
    // Step 6: the avalanche.
    acc ^= acc >> 33;
    acc = acc.wrapping_mul(PRIME64_2);
    acc ^= acc >> 29;
    acc = acc.wrapping_mul(PRIME64_3);
    acc ^= acc >> 32;
    acc
}
