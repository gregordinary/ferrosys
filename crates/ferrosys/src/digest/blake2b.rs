//! BLAKE2b, unkeyed, from RFC 7693 ("The BLAKE2 Cryptographic Hash and Message Authentication
//! Code (MAC)", 2015): section 2.6 for the initialization vector, 2.7 for the message schedule,
//! 3.1 for the mixing function, 3.2 for the compression function, and 3.3 for padding and the
//! parameter block. Words are little-endian 64-bit, as the RFC specifies.

use crate::bytes::{get_u64, put_u64};

/// The initialization vector of section 2.6.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The message word schedule of section 2.7, one row per round modulo ten.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Bytes one message block holds.
const BLOCK: usize = 128;

/// Rounds the compression function runs.
const ROUNDS: usize = 12;

/// The mixing function G of section 3.1, over four words of the working vector.
fn mix(v: &mut [u64; 16], [a, b, c, d]: [usize; 4], x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The compression function F of section 3.2: fold one block into the state, given the count
/// of bytes compressed so far including this block's, and whether it is the last.
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK], count: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        *word = get_u64(block, i * 8);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for round in 0..ROUNDS {
        let s = &SIGMA[round % 10];
        mix(&mut v, [0, 4, 8, 12], m[s[0]], m[s[1]]);
        mix(&mut v, [1, 5, 9, 13], m[s[2]], m[s[3]]);
        mix(&mut v, [2, 6, 10, 14], m[s[4]], m[s[5]]);
        mix(&mut v, [3, 7, 11, 15], m[s[6]], m[s[7]]);
        mix(&mut v, [0, 5, 10, 15], m[s[8]], m[s[9]]);
        mix(&mut v, [1, 6, 11, 12], m[s[10]], m[s[11]]);
        mix(&mut v, [2, 7, 8, 13], m[s[12]], m[s[13]]);
        mix(&mut v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
    }
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
}

/// The unkeyed BLAKE2b digest of `bytes`, `N` bytes long.
///
/// # Panics
///
/// At compile time of a caller asking for a digest outside the 1 to 64 bytes the RFC
/// defines.
#[must_use]
pub(crate) fn blake2b<const N: usize>(bytes: &[u8]) -> [u8; N] {
    const { assert!(N >= 1 && N <= 64, "a BLAKE2b digest is 1 to 64 bytes") };
    let mut h = IV;
    // Section 3.3's parameter block, for no key and an N-byte digest.
    h[0] ^= 0x0101_0000 ^ N as u64;
    // Every block but the last is compressed as not last; an empty message is one block of
    // zeros, compressed as last with a count of zero.
    let blocks = bytes.len().div_ceil(BLOCK).max(1);
    let mut block = [0u8; BLOCK];
    for i in 0..blocks - 1 {
        block.copy_from_slice(&bytes[i * BLOCK..(i + 1) * BLOCK]);
        compress(&mut h, &block, ((i + 1) * BLOCK) as u128, false);
    }
    let rest = &bytes[(blocks - 1) * BLOCK..];
    block = [0u8; BLOCK];
    block[..rest.len()].copy_from_slice(rest);
    compress(&mut h, &block, bytes.len() as u128, true);
    let mut full = [0u8; 64];
    for (i, word) in h.into_iter().enumerate() {
        put_u64(&mut full, i * 8, word);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}
