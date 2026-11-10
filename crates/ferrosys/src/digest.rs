//! The digests btrfs may checksum with besides crc32c: XXH64, SHA-256 and BLAKE2b.
//!
//! Here at the crate root beside [`crc32c`](crate::crc32c()) for the reason it is here: a digest
//! is a property of a run of bytes rather than of the format that stores it. How a format places
//! one in its own fields stays with the format.
//!
//! Each is written from its published specification, in safe Rust, a word at a time, with no
//! path that depends on what the processor offers. That makes a digest the same on every target
//! the crate builds for, including one with no vector unit at all.
//!
//! This module is pure and allocates nothing.

mod blake2b;
mod sha256;
mod xxh64;

pub(crate) use blake2b::blake2b;
pub(crate) use sha256::sha256;
pub(crate) use xxh64::xxh64;

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer every vector below is taken from the start of.
    fn buffer() -> Vec<u8> {
        (0..4096u32).map(|i| ((i * 131 + 17) % 256) as u8).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn xxh64_agrees_with_an_independent_implementation() {
        // Computed by `twox-hash` 2.1.5 (MIT) over the same buffer. The lengths cover every
        // path the specification has: under one stripe and over it, and every tail of eight,
        // four and single bytes after either.
        let buf = buffer();
        for (seed, len, want) in XXH64_VECTORS {
            assert_eq!(
                xxh64(seed, &buf[..len]),
                want,
                "seed {seed:#x}, {len} bytes"
            );
        }
    }

    #[test]
    fn sha256_gives_the_standards_examples() {
        // The examples FIPS 180-2's appendix B works through: one block, and two.
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_agrees_with_an_independent_implementation_at_every_length() {
        // Every length up to five blocks, which crosses each place the padding spills into a
        // second block.
        use sha2::Digest as _;
        let buf = buffer();
        for len in 0..=320 {
            let want: [u8; 32] = sha2::Sha256::digest(&buf[..len]).into();
            assert_eq!(sha256(&buf[..len]), want, "{len} bytes");
        }
    }

    #[test]
    fn blake2b_gives_the_rfcs_example() {
        // RFC 7693, appendix A: BLAKE2b-512 of "abc".
        assert_eq!(
            hex(&blake2b::<64>(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn blake2b_256_agrees_with_an_independent_implementation() {
        // Computed by CPython's `hashlib.blake2b(digest_size=32)` over the same buffer. The
        // lengths straddle the block, where the last full block is compressed as the last.
        let buf = buffer();
        for (len, want) in BLAKE2B_256_VECTORS {
            assert_eq!(hex(&blake2b::<32>(&buf[..len])), want, "{len} bytes");
        }
    }

    const XXH64_VECTORS: [(u64, usize, u64); 94] = [
        (0x0, 0, 0xef46db3751d8e999),
        (0x0, 1, 0xad10cd9780ac4ff7),
        (0x0, 2, 0xb22635899e8f2235),
        (0x0, 3, 0x40626d96276e4594),
        (0x0, 4, 0x882207c122c76e23),
        (0x0, 5, 0xa3da885eec618bb4),
        (0x0, 6, 0xad9c2ecd863325f1),
        (0x0, 7, 0xcfc90033aa9dac4f),
        (0x0, 8, 0x90fda2f089fa86de),
        (0x0, 9, 0xa80deb192b8c5215),
        (0x0, 10, 0x3aaf07fc10721c6d),
        (0x0, 11, 0xd2953e1354caef18),
        (0x0, 12, 0x333861b25fd6348b),
        (0x0, 13, 0x4e8f0d349a6f20ef),
        (0x0, 14, 0x4df943fe248c8bba),
        (0x0, 15, 0x59f95bad12d14c9d),
        (0x0, 16, 0x3a5b1165d151aa50),
        (0x0, 17, 0xc0bbb6ac5dbefe29),
        (0x0, 18, 0xa43333c50c99a7b9),
        (0x0, 19, 0xf919c24061c10223),
        (0x0, 20, 0xbd5c3b7ace1cf9c6),
        (0x0, 21, 0x2718c52bdd650abf),
        (0x0, 22, 0x955bdfdeb57244d6),
        (0x0, 23, 0xb2d26d6e52e62480),
        (0x0, 24, 0x22a0f61abe725bf4),
        (0x0, 25, 0x2e7d73f3896a812e),
        (0x0, 26, 0x05286f7b4d3669ba),
        (0x0, 27, 0x581e8369415863b4),
        (0x0, 28, 0x3bee93d5a57498ca),
        (0x0, 29, 0x186a89bd8a211c92),
        (0x0, 30, 0xc2fe19097a329de7),
        (0x0, 31, 0x44cc9efe5d2d0233),
        (0x0, 32, 0x0e1aab1d173cf196),
        (0x0, 33, 0x5c820b4b4fe28fdc),
        (0x0, 34, 0x674271278616ab41),
        (0x0, 35, 0x22de45605909b372),
        (0x0, 36, 0x4085f13b32c5feb0),
        (0x0, 37, 0x92e43d6d89a524de),
        (0x0, 38, 0x36bd670cd3955867),
        (0x0, 39, 0xd0ab734277760e45),
        (0x0, 40, 0xc0441297b12d2395),
        (0x0, 63, 0x1153d36cade87066),
        (0x0, 64, 0xd4c20ef54cbc9f67),
        (0x0, 65, 0xac086c9b87baea67),
        (0x0, 100, 0x7f8375f3e09d8123),
        (0x0, 1000, 0x9fb3251bef67c2b5),
        (0x0, 4096, 0xa78a1899df4ccfdc),
        (0x9e3779b185ebca87, 0, 0x6ec6d05f61c7e7a7),
        (0x9e3779b185ebca87, 1, 0x5867524421aebd0e),
        (0x9e3779b185ebca87, 2, 0x7223629da1da55ee),
        (0x9e3779b185ebca87, 3, 0xb87923c77e8177f6),
        (0x9e3779b185ebca87, 4, 0x271aa5cc21fa7e38),
        (0x9e3779b185ebca87, 5, 0x317e6fdd8c2a1901),
        (0x9e3779b185ebca87, 6, 0x366419fe3ec052d5),
        (0x9e3779b185ebca87, 7, 0x1992042573d827bc),
        (0x9e3779b185ebca87, 8, 0x061c72d60546d61c),
        (0x9e3779b185ebca87, 9, 0xf006e396fc6cff8c),
        (0x9e3779b185ebca87, 10, 0xb0737943df6e84cd),
        (0x9e3779b185ebca87, 11, 0x2f9f4a0df7e6cc9a),
        (0x9e3779b185ebca87, 12, 0x5621159cdfcf35aa),
        (0x9e3779b185ebca87, 13, 0xb0cec8be1caeeea3),
        (0x9e3779b185ebca87, 14, 0x0d4daca8cf11e6e8),
        (0x9e3779b185ebca87, 15, 0x275572f3f7e78a1d),
        (0x9e3779b185ebca87, 16, 0x649d4100efaf7380),
        (0x9e3779b185ebca87, 17, 0x8a3c8de311e4236e),
        (0x9e3779b185ebca87, 18, 0x15d2aa8f937b29cf),
        (0x9e3779b185ebca87, 19, 0x400d8639c7eb658d),
        (0x9e3779b185ebca87, 20, 0xc2e873741f6b2118),
        (0x9e3779b185ebca87, 21, 0x6cfa7453e4563d18),
        (0x9e3779b185ebca87, 22, 0xe2081db74c4a7cfa),
        (0x9e3779b185ebca87, 23, 0x4b29491a34e70ab9),
        (0x9e3779b185ebca87, 24, 0xf10d1caa715c4b2a),
        (0x9e3779b185ebca87, 25, 0xf79defe0a0b96a17),
        (0x9e3779b185ebca87, 26, 0xb9b4ddc9bc980d17),
        (0x9e3779b185ebca87, 27, 0x1f7c66ceff3309d4),
        (0x9e3779b185ebca87, 28, 0xf580450bc3d18d92),
        (0x9e3779b185ebca87, 29, 0x14dc69d62c1b0062),
        (0x9e3779b185ebca87, 30, 0x1d3f42bd2ca3cae0),
        (0x9e3779b185ebca87, 31, 0x72360fc425549dcf),
        (0x9e3779b185ebca87, 32, 0x4c2970ccfa63828f),
        (0x9e3779b185ebca87, 33, 0x33f9d7bfdd2a924c),
        (0x9e3779b185ebca87, 34, 0x1584932152f6d46b),
        (0x9e3779b185ebca87, 35, 0x883603b430d747d4),
        (0x9e3779b185ebca87, 36, 0x1ca669fae48af7d1),
        (0x9e3779b185ebca87, 37, 0x2a14e18f09d410f5),
        (0x9e3779b185ebca87, 38, 0x17b7f890cfb2b250),
        (0x9e3779b185ebca87, 39, 0x237597709de0fda9),
        (0x9e3779b185ebca87, 40, 0x150d6a567faa89a7),
        (0x9e3779b185ebca87, 63, 0xacf49d1661d50b05),
        (0x9e3779b185ebca87, 64, 0xe577c67b2b8d6d3b),
        (0x9e3779b185ebca87, 65, 0xc037bf65d4bb3ade),
        (0x9e3779b185ebca87, 100, 0x4d18db2f7d5d44d3),
        (0x9e3779b185ebca87, 1000, 0x4d092485abedc2a7),
        (0x9e3779b185ebca87, 4096, 0xfdd20839bb70e184),
    ];

    const BLAKE2B_256_VECTORS: [(usize, &str); 12] = [
        (
            0,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        ),
        (
            1,
            "4c54f47d69e097eed691c686ac18444a10d4abe934c311d0fffba9a3928f9e71",
        ),
        (
            63,
            "70ae26819b9615373c6508942964c5603ce870114e241c2c86f3ee039bd01adb",
        ),
        (
            64,
            "18c07789402ab4e288c81209880fc425fc302c762b1c7be17fc5024d5a63bac8",
        ),
        (
            127,
            "1497d032633f561d5960ac490cef47430a08d34883320896ae465e7e9afdc70d",
        ),
        (
            128,
            "2e370c5a09c310e42a7550357d010c29dfe02dc964f0c60b65a5e9efabe07009",
        ),
        (
            129,
            "06753da225904d334f996106264b76d0008efda6f90a3f71146ea5a645491da6",
        ),
        (
            255,
            "e347b837f1d812d6f0851cee17e2838ad1d8cce701eb92083645850caeaa58d6",
        ),
        (
            256,
            "45d20db7eee88ba7b6bc6af12cefa4e562b9ad07bf81b610c73574722f05ee5b",
        ),
        (
            257,
            "e5d7964db1215bd640353c02143258168a1ee5582ed66a2984d7fbd464fc8079",
        ),
        (
            1000,
            "3c8704d982518c48444c5b40f145a1438511adb3409acc313ac1b8df422f3d34",
        ),
        (
            4096,
            "a2fae02b9b668ba8dd8d37c2f0f0066d1eff2d0d9080d69530749578a59e7be5",
        ),
    ];
}
