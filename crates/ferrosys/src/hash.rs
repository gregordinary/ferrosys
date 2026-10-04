//! The directory-name hashes a hash-indexed directory is ordered by.
//!
//! A hash-indexed directory stores each name under a 32-bit major hash and a 32-bit
//! minor hash. ext4 defines three algorithms — a legacy hash, a half-MD4, and a TEA
//! — and each interprets a name's bytes either as signed or as unsigned, giving six
//! variants in all. The filesystem records the algorithm in `s_def_hash_version` and
//! the interpretation in `s_flags`, so an image is self-describing and a reader
//! honors what it finds.
//!
//! The signedness exists because a name's bytes are hashed as C `char`, whose
//! signedness varies by architecture; the two interpretations hash the same name
//! differently. Recording it explicitly, as [`HashSignedness`] does, keeps a name's
//! hash a property of the image, not of the machine that wrote it.
//!
//! This module is pure. The major hash always has its low bit clear: that bit is
//! reserved in a directory index to mark a hash that continues into the next block.
//!
//! # Sources
//!
//! MD4's functions, round constants, shifts, and initial registers are RFC 1320's, and the
//! TEA round is Wheeler and Needham's (*TEA, a Tiny Encryption Algorithm*, 1994). How the two
//! are applied to a name — the words of each round, the packing of a name into words, and the
//! sixteen TEA cycles — follows ext4-view (MIT OR Apache-2.0). The legacy hash, the unsigned
//! forms, the minor hash, and the end of the hash space follow FreeBSD's ext2fs
//! (BSD-2-Clause). Every variant is held to what e2fsprogs's `debugfs dx_hash` reports.

/// The hash algorithm a directory index is ordered by (`s_def_hash_version`).
///
/// Three of the codes the format defines are named here. Codes 3 to 5 are the
/// `_UNSIGNED` forms of these same three algorithms, which this crate models more
/// directly as [`HashSignedness`] beside the algorithm, so an image using one is read
/// through the algorithm it names and the signedness it records. Code 6 is siphash, used
/// only by `casefold`, which this crate does not write. [`from_u8`](Self::from_u8)
/// answers `None` for all four.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum HashVersion {
    /// The original ext2 directory hash. It has no minor hash and ignores the seed.
    Legacy,
    /// A half-MD4 transform. The algorithm `mke2fs` selects.
    #[default]
    HalfMd4,
    /// A TEA transform.
    Tea,
}

impl HashVersion {
    /// The value stored in `s_def_hash_version` and in a directory index's root.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::HalfMd4 => 1,
            Self::Tea => 2,
        }
    }

    /// Parse the value stored in `s_def_hash_version`, or `None` for a code this crate
    /// does not name.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Legacy),
            1 => Some(Self::HalfMd4),
            2 => Some(Self::Tea),
            _ => None,
        }
    }
}

// The names every ext tool prints and accepts, in the order `mke2fs` documents them.
crate::naming::named_choice!(HashVersion {
    HashVersion::HalfMd4 => "half_md4",
    HashVersion::Tea => "tea",
    HashVersion::Legacy => "legacy",
});

impl core::fmt::Display for HashVersion {
    /// The name in [`HashVersion::as_str`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a name's bytes are interpreted when hashed.
///
/// Recorded in `s_flags`. [`Unsigned`](Self::Unsigned) treats each byte as its
/// numeric value; [`Signed`](Self::Signed) treats a byte at or above `0x80` as
/// negative. Names of pure ASCII hash identically under both.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HashSignedness {
    /// Bytes are unsigned. Byte-reproducible across architectures.
    #[default]
    Unsigned,
    /// Bytes are signed, as a `char` is on x86.
    Signed,
}

impl HashSignedness {
    /// `EXT2_FLAGS_SIGNED_HASH`: names hash as signed bytes.
    pub const SIGNED_FLAG: u32 = 0x0000_0001;
    /// `EXT2_FLAGS_UNSIGNED_HASH`: names hash as unsigned bytes.
    pub const UNSIGNED_FLAG: u32 = 0x0000_0002;

    /// The `s_flags` bit that records this choice.
    #[must_use]
    pub const fn to_flag(self) -> u32 {
        match self {
            Self::Unsigned => Self::UNSIGNED_FLAG,
            Self::Signed => Self::SIGNED_FLAG,
        }
    }

    /// Read the choice out of `s_flags`. A superblock that records neither bit
    /// leaves the interpretation to the reader, which takes it as unsigned.
    ///
    /// This is the one place the bit becomes the choice. A caller describing a superblock
    /// asks here rather than testing [`SIGNED_FLAG`](Self::SIGNED_FLAG) itself, so that
    /// what a report says an image does is what a read of that image does.
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        if flags & Self::SIGNED_FLAG != 0 {
            Self::Signed
        } else {
            Self::Unsigned
        }
    }
}

// The two words a `-D` value takes and a report prints.
crate::naming::named_choice!(HashSignedness {
    HashSignedness::Signed => "signed",
    HashSignedness::Unsigned => "unsigned",
});

impl core::fmt::Display for HashSignedness {
    /// The name in [`HashSignedness::as_str`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name's place in a directory index: the major hash the index is keyed by, and
/// the minor hash that orders names sharing a major hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct DirHash {
    /// The hash the index keys on. Its low bit is always clear.
    pub major: u32,
    /// Orders names that collide on `major`. Always zero for [`HashVersion::Legacy`].
    pub minor: u32,
}

/// The state a hash starts from where the filesystem's hash seed is all zero: MD4's initial
/// registers.
const MD4_INITIAL: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// The end of a directory's hash space, which an index uses to mean past every name. No major
/// hash takes this value; see [`off_the_end`].
const END_OF_SPACE: u32 = 0x7fff_ffff << 1;

/// Hash `name` for a directory index.
///
/// `seed` is the filesystem's `s_hash_seed`, four little-endian 32-bit words. An
/// all-zero seed selects the transform's built-in initial state, as ext4 defines.
#[must_use]
pub fn dir_hash(
    name: &[u8],
    version: HashVersion,
    signedness: HashSignedness,
    seed: &[u8; 16],
) -> DirHash {
    let (major, minor) = match version {
        HashVersion::Legacy => (legacy(name, signedness), 0),
        HashVersion::HalfMd4 => {
            let mut state = initial_state(seed);
            for chunk in name.chunks(32) {
                half_md4(&mut state, &pack(chunk, signedness));
            }
            (state[1], state[2])
        }
        HashVersion::Tea => {
            let mut state = initial_state(seed);
            for chunk in name.chunks(16) {
                tea(&mut state, &pack(chunk, signedness));
            }
            (state[0], state[1])
        }
    };
    // The low bit of a major hash marks a hash continued into the next index block,
    // so it is never part of the hash itself.
    DirHash {
        major: off_the_end(major & !1),
        minor,
    }
}

/// The state a hash of a name starts from: the seed's four words, or MD4's initial registers
/// where the seed is all zero.
fn initial_state(seed: &[u8; 16]) -> [u32; 4] {
    let state: [u32; 4] = std::array::from_fn(|word| crate::bytes::get_u32(seed, 4 * word));
    if state == [0; 4] { MD4_INITIAL } else { state }
}

/// Move a major hash off [`END_OF_SPACE`]: that value becomes the one below it with the low
/// bit still clear, so it is never mistaken for a hash continued into the next index block,
/// and every other hash is returned as it is.
///
/// The end of the hash space is where a directory's position reads as past its last name, so
/// no name may hash there. A Linux kernel moves such a hash the same way, which is observed in
/// the positions its `readdir` reports.
const fn off_the_end(major: u32) -> u32 {
    if major == END_OF_SPACE {
        (0x7fff_ffff - 1) << 1
    } else {
        major
    }
}

/// The major hash a name has where a writer leaves a hash where it fell, for a name this
/// crate hashes to `major`: the end of the hash space where `major` is the value
/// [`off_the_end`] moves it to, and nothing otherwise.
///
/// A lookup asks this so it finds a name in an index whichever way its writer read the end of
/// the space. Only the end of the space is in question; every other hash is the same either
/// way.
pub(crate) const fn unmoved_major(major: u32) -> Option<u32> {
    if major == off_the_end(END_OF_SPACE) {
        Some(END_OF_SPACE)
    } else {
        None
    }
}

impl HashSignedness {
    /// A name's byte as a hash reads it: its value, or sign-extended where names hash as
    /// signed.
    const fn widen(self, byte: u8) -> u32 {
        match self {
            Self::Unsigned => byte as u32,
            Self::Signed => byte as i8 as u32,
        }
    }
}

/// The legacy hash: no seed and no minor hash, and the whole name consumed a byte at a time.
///
/// Two running values. Each byte makes a new one out of the older value and the newer one
/// mixed with the byte, folded back below the top bit; the newest, shifted left one, is the
/// hash.
fn legacy(name: &[u8], signedness: HashSignedness) -> u32 {
    let (mut newer, mut older) = (0x12a3_fe2d_u32, 0x37ab_e8f9_u32);
    for &byte in name {
        let mut next = older.wrapping_add(newer ^ signedness.widen(byte).wrapping_mul(0x006d_22f5));
        if next & 0x8000_0000 != 0 {
            next = next.wrapping_sub(0x7fff_ffff);
        }
        older = newer;
        newer = next;
    }
    newer << 1
}

/// Pack one chunk of a name into `N` words, the first of each four bytes the most significant.
///
/// Every word starts from a pad that repeats the chunk's length in all four of its bytes, and
/// each byte of the chunk is added in after shifting the word left by eight. So a word the
/// chunk fills keeps none of the pad, a word the chunk ends inside keeps some, and every word
/// past the chunk is the pad.
fn pack<const N: usize>(chunk: &[u8], signedness: HashSignedness) -> [u32; N] {
    // A chunk is at most thirty-two bytes, so its length is one byte.
    let pad = u32::from(chunk.len() as u8) * 0x0101_0101;
    let mut words = [pad; N];
    for (word, bytes) in words.iter_mut().zip(chunk.chunks(4)) {
        *word = bytes.iter().fold(pad, |word, &byte| {
            (word << 8).wrapping_add(signedness.widen(byte))
        });
    }
    words
}

/// MD4's three boolean functions, each applied bit by bit.
#[derive(Clone, Copy)]
enum Mix {
    /// Where the first bit is set, the second; otherwise the third.
    Conditional,
    /// Whichever value at least two of the three bits hold.
    Majority,
    /// Set where an odd number of the three bits are.
    Parity,
}

impl Mix {
    const fn of(self, x: u32, y: u32, z: u32) -> u32 {
        match self {
            Self::Conditional => (x & y) | (!x & z),
            Self::Majority => (x & y) | (x & z) | (y & z),
            Self::Parity => x ^ y ^ z,
        }
    }
}

/// One of half-MD4's three rounds.
struct Round {
    /// The round's boolean function.
    mix: Mix,
    /// What is added with each word.
    constant: u32,
    /// The rotations its steps cycle through.
    shifts: [u32; 4],
    /// The order it reads the eight words in.
    order: [usize; 8],
}

/// MD4's three rounds, eight steps each over eight words.
const HALF_MD4: [Round; 3] = [
    Round {
        mix: Mix::Conditional,
        constant: 0,
        shifts: [3, 7, 11, 19],
        order: [0, 1, 2, 3, 4, 5, 6, 7],
    },
    Round {
        mix: Mix::Majority,
        constant: 0x5a82_7999,
        shifts: [3, 5, 9, 13],
        order: [1, 3, 5, 7, 0, 2, 4, 6],
    },
    Round {
        mix: Mix::Parity,
        constant: 0x6ed9_eba1,
        shifts: [3, 9, 11, 15],
        order: [3, 7, 2, 6, 1, 5, 0, 4],
    },
];

/// Fold eight words into `state` through half-MD4.
///
/// Each step replaces the first of the four registers with itself plus the round's function
/// of the other three, a word, and the round's constant, rotated; then the four turn one
/// place, so the register replaced cycles A, D, C, B and a round of eight steps ends where it
/// began. Once every round has run, each register is added into the state.
fn half_md4(state: &mut [u32; 4], words: &[u32; 8]) {
    let [mut a, mut b, mut c, mut d] = *state;
    for round in &HALF_MD4 {
        for (step, &word) in round.order.iter().enumerate() {
            let replaced = a
                .wrapping_add(round.mix.of(b, c, d))
                .wrapping_add(words[word])
                .wrapping_add(round.constant)
                .rotate_left(round.shifts[step % 4]);
            (a, b, c, d) = (d, replaced, b, c);
        }
    }
    for (held, register) in state.iter_mut().zip([a, b, c, d]) {
        *held = held.wrapping_add(register);
    }
}

/// TEA's cycle constant.
const TEA_DELTA: u32 = 0x9e37_79b9;

/// Sixteen cycles of TEA over the state's first two words, keyed by the chunk's four words,
/// and the result added into those two.
fn tea(state: &mut [u32; 4], key: &[u32; 4]) {
    let (mut v0, mut v1) = (state[0], state[1]);
    let mut sum = 0u32;
    for _ in 0..16 {
        sum = sum.wrapping_add(TEA_DELTA);
        v0 = v0.wrapping_add(
            (v1 << 4).wrapping_add(key[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(key[1]),
        );
        v1 = v1.wrapping_add(
            (v0 << 4).wrapping_add(key[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(key[3]),
        );
    }
    state[0] = state[0].wrapping_add(v0);
    state[1] = state[1].wrapping_add(v1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The all-zero seed, which selects the transform's built-in initial state.
    const SEED_Z: [u8; 16] = [0; 16];
    /// A non-zero seed: the UUID 11111111-2222-3333-4444-555555555555.
    const SEED_NZ: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex pair"))
            .collect()
    }

    /// Decode the numeric hash variant e2fsprogs uses: the algorithm, plus three
    /// when names hash as unsigned bytes.
    fn variant(v: u8) -> (HashVersion, HashSignedness) {
        let signedness = if v >= 3 {
            HashSignedness::Unsigned
        } else {
            HashSignedness::Signed
        };
        let version = HashVersion::from_u8(v % 3).expect("a defined algorithm");
        (version, signedness)
    }

    /// Every hash variant, pinned against e2fsprogs 1.47.0's own implementation as
    /// reported by `dx_hash`. The names cross the sixteen- and thirty-two-byte chunk
    /// boundaries the TEA and half-MD4 transforms consume, and two carry bytes at or
    /// above 0x80 -- the only thing that separates the signed variants from the
    /// unsigned ones.
    #[rustfmt::skip]
    const VECTORS: &[(&str, u8, bool, u32, u32)] = &[
        ("61", 0, true, 0xe74b53e2, 0x0),
        ("61", 1, true, 0xd5fa7d7a, 0xacb48187),
        ("61", 2, true, 0x6d0ea4c0, 0xc18922df),
        ("61", 3, true, 0xe74b53e2, 0x0),
        ("61", 4, true, 0xd5fa7d7a, 0xacb48187),
        ("61", 5, true, 0x6d0ea4c0, 0xc18922df),
        ("68656c6c6f", 0, true, 0x32252546, 0x0),
        ("68656c6c6f", 1, true, 0x1746da32, 0x420013b5),
        ("68656c6c6f", 2, true, 0x6f5bb1a8, 0x231917c2),
        ("68656c6c6f", 3, true, 0x32252546, 0x0),
        ("68656c6c6f", 4, true, 0x1746da32, 0x420013b5),
        ("68656c6c6f", 5, true, 0x6f5bb1a8, 0x231917c2),
        ("68656c6c6f2e747874", 0, true, 0x65a05776, 0x0),
        ("68656c6c6f2e747874", 1, true, 0xa26e1d86, 0x133b3f98),
        ("68656c6c6f2e747874", 2, true, 0x5107c3f2, 0x3840cb7),
        ("68656c6c6f2e747874", 3, true, 0x65a05776, 0x0),
        ("68656c6c6f2e747874", 4, true, 0xa26e1d86, 0x133b3f98),
        ("68656c6c6f2e747874", 5, true, 0x5107c3f2, 0x3840cb7),
        ("636166c3a9", 0, true, 0x96ca5a2c, 0x0),
        ("636166c3a9", 1, true, 0xfb9c5e5c, 0x573e8b8),
        ("636166c3a9", 2, true, 0x105842ea, 0xfb9165ca),
        ("636166c3a9", 3, true, 0x6dde4230, 0x0),
        ("636166c3a9", 4, true, 0x9d72aed6, 0xf6138c6a),
        ("636166c3a9", 5, true, 0x6621f032, 0xf86699c6),
        ("c3bfc3bf", 0, true, 0xc2a01a0a, 0x0),
        ("c3bfc3bf", 1, true, 0xe5395746, 0x9e27808f),
        ("c3bfc3bf", 2, true, 0x96fe57c2, 0x7037f6c8),
        ("c3bfc3bf", 3, true, 0xdcfefc04, 0x0),
        ("c3bfc3bf", 4, true, 0x98a296ce, 0xcd764095),
        ("c3bfc3bf", 5, true, 0x8ca01134, 0xee3de2b4),
        ("6162636465666768696a6b6c6d6e6f70", 0, true, 0xf2b18e8a, 0x0),
        ("6162636465666768696a6b6c6d6e6f70", 1, true, 0x89e0be, 0xd74fb59c),
        ("6162636465666768696a6b6c6d6e6f70", 2, true, 0xf4ac8cb4, 0x664dabe7),
        ("6162636465666768696a6b6c6d6e6f70", 3, true, 0xf2b18e8a, 0x0),
        ("6162636465666768696a6b6c6d6e6f70", 4, true, 0x89e0be, 0xd74fb59c),
        ("6162636465666768696a6b6c6d6e6f70", 5, true, 0xf4ac8cb4, 0x664dabe7),
        ("6162636465666768696a6b6c6d6e6f7071", 0, true, 0xbe0c8a3c, 0x0),
        ("6162636465666768696a6b6c6d6e6f7071", 1, true, 0xd3213974, 0x18a2e961),
        ("6162636465666768696a6b6c6d6e6f7071", 2, true, 0x972a82e6, 0xf52ed8c0),
        ("6162636465666768696a6b6c6d6e6f7071", 3, true, 0xbe0c8a3c, 0x0),
        ("6162636465666768696a6b6c6d6e6f7071", 4, true, 0xd3213974, 0x18a2e961),
        ("6162636465666768696a6b6c6d6e6f7071", 5, true, 0x972a82e6, 0xf52ed8c0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 0, true, 0x8be22c02, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 1, true, 0x19643b1a, 0xdde3a0bf),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 2, true, 0xe78c76dc, 0x94dd872b),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 3, true, 0x8be22c02, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 4, true, 0x19643b1a, 0xdde3a0bf),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 5, true, 0xe78c76dc, 0x94dd872b),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 0, true, 0xcfbc04f6, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 1, true, 0x16ed9a9c, 0x2fb8454f),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 2, true, 0x521eac64, 0xffc99004),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 3, true, 0xcfbc04f6, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 4, true, 0x16ed9a9c, 0x2fb8454f),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 5, true, 0x521eac64, 0xffc99004),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 0, true, 0xe54ebe5e, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 1, true, 0x91b0c29c, 0x6e686987),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 2, true, 0x6b4def20, 0x1f6b8b36),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 3, true, 0xe54ebe5e, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 4, true, 0x91b0c29c, 0x6e686987),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 5, true, 0x6b4def20, 0x1f6b8b36),
        ("61", 0, false, 0xe74b53e2, 0x0),
        ("61", 1, false, 0x61ab28ce, 0x4ffe6d79),
        ("61", 2, false, 0xc60ef7d0, 0xf8261194),
        ("61", 3, false, 0xe74b53e2, 0x0),
        ("61", 4, false, 0x61ab28ce, 0x4ffe6d79),
        ("61", 5, false, 0xc60ef7d0, 0xf8261194),
        ("68656c6c6f", 0, false, 0x32252546, 0x0),
        ("68656c6c6f", 1, false, 0xe4a977aa, 0xb8f2ce63),
        ("68656c6c6f", 2, false, 0x4ad5910a, 0x413ecd8c),
        ("68656c6c6f", 3, false, 0x32252546, 0x0),
        ("68656c6c6f", 4, false, 0xe4a977aa, 0xb8f2ce63),
        ("68656c6c6f", 5, false, 0x4ad5910a, 0x413ecd8c),
        ("68656c6c6f2e747874", 0, false, 0x65a05776, 0x0),
        ("68656c6c6f2e747874", 1, false, 0x8d4f0414, 0x6b916974),
        ("68656c6c6f2e747874", 2, false, 0xf97f49a0, 0x5f1b7594),
        ("68656c6c6f2e747874", 3, false, 0x65a05776, 0x0),
        ("68656c6c6f2e747874", 4, false, 0x8d4f0414, 0x6b916974),
        ("68656c6c6f2e747874", 5, false, 0xf97f49a0, 0x5f1b7594),
        ("636166c3a9", 0, false, 0x96ca5a2c, 0x0),
        ("636166c3a9", 1, false, 0xa01bc648, 0x1fd0d51b),
        ("636166c3a9", 2, false, 0x4691753e, 0x5b367fb3),
        ("636166c3a9", 3, false, 0x6dde4230, 0x0),
        ("636166c3a9", 4, false, 0x26e36cc2, 0x6ed368f5),
        ("636166c3a9", 5, false, 0x702acd98, 0x90f9b72d),
        ("c3bfc3bf", 0, false, 0xc2a01a0a, 0x0),
        ("c3bfc3bf", 1, false, 0xb0113274, 0x5e26916e),
        ("c3bfc3bf", 2, false, 0xc50a46f2, 0x6a004bc0),
        ("c3bfc3bf", 3, false, 0xdcfefc04, 0x0),
        ("c3bfc3bf", 4, false, 0x60fc491e, 0x999eb4ac),
        ("c3bfc3bf", 5, false, 0x5fd18e04, 0xcd0bd4a6),
        ("6162636465666768696a6b6c6d6e6f70", 0, false, 0xf2b18e8a, 0x0),
        ("6162636465666768696a6b6c6d6e6f70", 1, false, 0x1f183b46, 0xdcb3b565),
        ("6162636465666768696a6b6c6d6e6f70", 2, false, 0xf8b02dba, 0xd6e6da53),
        ("6162636465666768696a6b6c6d6e6f70", 3, false, 0xf2b18e8a, 0x0),
        ("6162636465666768696a6b6c6d6e6f70", 4, false, 0x1f183b46, 0xdcb3b565),
        ("6162636465666768696a6b6c6d6e6f70", 5, false, 0xf8b02dba, 0xd6e6da53),
        ("6162636465666768696a6b6c6d6e6f7071", 0, false, 0xbe0c8a3c, 0x0),
        ("6162636465666768696a6b6c6d6e6f7071", 1, false, 0xbb071b22, 0x1ab72232),
        ("6162636465666768696a6b6c6d6e6f7071", 2, false, 0xf41472ca, 0x2ed8b639),
        ("6162636465666768696a6b6c6d6e6f7071", 3, false, 0xbe0c8a3c, 0x0),
        ("6162636465666768696a6b6c6d6e6f7071", 4, false, 0xbb071b22, 0x1ab72232),
        ("6162636465666768696a6b6c6d6e6f7071", 5, false, 0xf41472ca, 0x2ed8b639),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 0, false, 0x8be22c02, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 1, false, 0x22320a02, 0x898c3e38),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 2, false, 0x151c1fbe, 0x53dda84e),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 3, false, 0x8be22c02, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 4, false, 0x22320a02, 0x898c3e38),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435", 5, false, 0x151c1fbe, 0x53dda84e),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 0, false, 0xcfbc04f6, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 1, false, 0x9399c468, 0xbe9b6cf4),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 2, false, 0x419cc4ec, 0x6500f359),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 3, false, 0xcfbc04f6, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 4, false, 0x9399c468, 0xbe9b6cf4),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536", 5, false, 0x419cc4ec, 0x6500f359),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 0, false, 0xe54ebe5e, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 1, false, 0xd2246134, 0xc0d84b19),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 2, false, 0x8b032028, 0xbbb1b88f),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 3, false, 0xe54ebe5e, 0x0),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 4, false, 0xd2246134, 0xc0d84b19),
        ("6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768", 5, false, 0x8b032028, 0xbbb1b88f),
    ];

    #[test]
    fn every_variant_matches_e2fsprogs() {
        for &(name_hex, v, zero_seed, major, minor) in VECTORS {
            let name = unhex(name_hex);
            let seed = if zero_seed { SEED_Z } else { SEED_NZ };
            let (version, signedness) = variant(v);
            let got = dir_hash(&name, version, signedness, &seed);
            assert_eq!(
                (got.major, got.minor),
                (major, minor),
                "variant {v} of {name_hex:?} (zero_seed={zero_seed})"
            );
        }
    }

    #[test]
    fn ascii_names_hash_the_same_signed_and_unsigned() {
        // Signedness only bites on bytes at or above 0x80.
        for version in [HashVersion::Legacy, HashVersion::HalfMd4, HashVersion::Tea] {
            let signed = dir_hash(b"hello.txt", version, HashSignedness::Signed, &SEED_NZ);
            let unsigned = dir_hash(b"hello.txt", version, HashSignedness::Unsigned, &SEED_NZ);
            assert_eq!(signed, unsigned);
        }
    }

    #[test]
    fn high_bit_names_hash_differently_signed_and_unsigned() {
        // An e-acute in UTF-8: the bytes 0xc3 0xa9 are negative read as signed.
        let name = b"caf\xc3\xa9";
        for version in [HashVersion::Legacy, HashVersion::HalfMd4, HashVersion::Tea] {
            let signed = dir_hash(name, version, HashSignedness::Signed, &SEED_Z);
            let unsigned = dir_hash(name, version, HashSignedness::Unsigned, &SEED_Z);
            assert_ne!(signed, unsigned, "{version:?} ignores byte signedness");
        }
    }

    #[test]
    fn a_major_hash_never_has_its_low_bit_set() {
        // The low bit marks a hash continued into the next index block, so it is
        // never part of the hash itself.
        for name in [
            &b"a"[..],
            b"hello",
            b"lost+found",
            b"zzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            for version in [HashVersion::Legacy, HashVersion::HalfMd4, HashVersion::Tea] {
                let h = dir_hash(name, version, HashSignedness::Unsigned, &SEED_NZ);
                assert_eq!(h.major & 1, 0, "{name:?} {version:?}");
            }
        }
    }

    #[test]
    fn the_end_of_the_hash_space_is_never_a_major_hash() {
        // Three names found by search, one per algorithm, whose major hash under the all-zero
        // seed lands on the end of the hash space before the rule moves it. The minor hash is
        // untouched. A Linux 7.1 kernel's directory positions put each at the moved value, and
        // e2fsprogs 1.47.0's `dx_hash` reports each at 0xFFFF_FFFE, unmoved; an index split at
        // the moved value is reached by either.
        for (name, version, minor) in [
            (&b"i9zfid0q"[..], HashVersion::Legacy, 0),
            (b"s29n0k5q", HashVersion::HalfMd4, 0x3272_81df),
            (b"48w0qib1", HashVersion::Tea, 0xde74_5bee),
        ] {
            for signedness in [HashSignedness::Signed, HashSignedness::Unsigned] {
                let hash = dir_hash(name, version, signedness, &SEED_Z);
                assert_eq!(
                    (hash.major, hash.minor),
                    (0xFFFF_FFFC, minor),
                    "{version:?}"
                );
            }
        }
        // Every other value passes through untouched.
        assert_eq!(off_the_end(END_OF_SPACE), 0xFFFF_FFFC);
        assert_eq!(off_the_end(0), 0);
        assert_eq!(off_the_end(0x1234_5678), 0x1234_5678);
        assert_eq!(off_the_end(0xFFFF_FFFC), 0xFFFF_FFFC);
    }

    #[test]
    fn the_legacy_hash_has_no_minor_hash_and_ignores_the_seed() {
        let a = dir_hash(
            b"hello",
            HashVersion::Legacy,
            HashSignedness::Unsigned,
            &SEED_Z,
        );
        let b = dir_hash(
            b"hello",
            HashVersion::Legacy,
            HashSignedness::Unsigned,
            &SEED_NZ,
        );
        assert_eq!(a, b);
        assert_eq!(a.minor, 0);
    }

    #[test]
    fn a_seeded_hash_differs_from_an_unseeded_one() {
        for version in [HashVersion::HalfMd4, HashVersion::Tea] {
            let a = dir_hash(b"hello", version, HashSignedness::Unsigned, &SEED_Z);
            let b = dir_hash(b"hello", version, HashSignedness::Unsigned, &SEED_NZ);
            assert_ne!(a, b, "{version:?} ignores the hash seed");
        }
    }

    #[test]
    fn the_flag_bits_round_trip() {
        assert_eq!(HashSignedness::Signed.to_flag(), 1);
        assert_eq!(HashSignedness::Unsigned.to_flag(), 2);
        assert_eq!(HashSignedness::from_flags(1), HashSignedness::Signed);
        assert_eq!(HashSignedness::from_flags(2), HashSignedness::Unsigned);
        // A superblock recording neither bit reads as unsigned.
        assert_eq!(HashSignedness::from_flags(0), HashSignedness::Unsigned);
    }

    #[test]
    fn the_stored_algorithm_round_trips() {
        for v in [HashVersion::Legacy, HashVersion::HalfMd4, HashVersion::Tea] {
            assert_eq!(HashVersion::from_u8(v.to_u8()), Some(v));
        }
        assert_eq!(HashVersion::from_u8(3), None);
        assert_eq!(HashVersion::default(), HashVersion::HalfMd4);
    }
}
