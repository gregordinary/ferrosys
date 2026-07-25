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

    /// The algorithm's name as every ext tool prints it: `legacy`, `half_md4`, or `tea`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::HalfMd4 => "half_md4",
            Self::Tea => "tea",
        }
    }
}

impl core::fmt::Display for HashVersion {
    /// The name in [`HashVersion::name`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
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
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        if flags & Self::SIGNED_FLAG != 0 {
            Self::Signed
        } else {
            Self::Unsigned
        }
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

/// The transform's initial state when the filesystem's hash seed is all zero.
const DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// The value a major hash may not take: it marks the end of a directory's hash
/// space. A hash landing here is nudged down to the previous even value by
/// [`clamp_from_eof`].
const EOF_HASH: u32 = 0x7fff_ffff << 1;

/// Move a major hash off the end-of-space sentinel. A hash equal to [`EOF_HASH`] is
/// replaced by the previous representable value, `(0x7fff_fffe) << 1`, which — like
/// every valid major hash — keeps its low bit clear so it is never mistaken for a
/// hash continued into the next index block. Any other hash is returned unchanged.
#[must_use]
const fn clamp_from_eof(major: u32) -> u32 {
    if major == EOF_HASH {
        (0x7fff_ffff - 1) << 1
    } else {
        major
    }
}

const TEA_DELTA: u32 = 0x9e37_79b9;
const MD4_K2: u32 = 0x5a82_7999;
const MD4_K3: u32 = 0x6ed9_eba1;

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
    let signed = matches!(signedness, HashSignedness::Signed);
    let mut buf = decode_seed(seed);

    let (mut major, minor) = match version {
        HashVersion::Legacy => (legacy_hash(name, signed), 0),
        HashVersion::HalfMd4 => {
            let mut input = [0u32; 8];
            let mut off = 0;
            while off < name.len() {
                str2hashbuf(&name[off..], signed, &mut input);
                half_md4_transform(&mut buf, &input);
                off += 32;
            }
            (buf[1], buf[2])
        }
        HashVersion::Tea => {
            let mut input = [0u32; 4];
            let mut off = 0;
            while off < name.len() {
                str2hashbuf(&name[off..], signed, &mut input);
                tea_transform(&mut buf, &input);
                off += 16;
            }
            (buf[0], buf[1])
        }
    };

    // The low bit of a major hash marks a hash continued into the next index block,
    // so it is never part of the hash itself.
    major &= !1;
    major = clamp_from_eof(major);
    DirHash { major, minor }
}

/// The four seed words, or the transform's built-in state when the seed is all zero.
fn decode_seed(seed: &[u8; 16]) -> [u32; 4] {
    let mut buf = [0u32; 4];
    for (word, chunk) in buf.iter_mut().zip(seed.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
    }
    if buf == [0; 4] { DEFAULT_SEED } else { buf }
}

/// One name byte as the hash sees it: sign-extended when names hash as signed.
fn byte(b: u8, signed: bool) -> u32 {
    if signed { b as i8 as u32 } else { u32::from(b) }
}

/// The legacy hash. It consumes the whole name a byte at a time and has no minor
/// hash and no seed.
fn legacy_hash(name: &[u8], signed: bool) -> u32 {
    let (mut hash0, mut hash1) = (0x12a3_fe2du32, 0x37ab_e8f9u32);
    for &b in name {
        let mut hash = hash1.wrapping_add(hash0 ^ byte(b, signed).wrapping_mul(7_152_373));
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    hash0 << 1
}

/// Pack the front of `name` into `out` as big-endian words, padding the remainder
/// with a word derived from the name's remaining length.
///
/// The pad encodes the length *before* the name is clipped to what `out` holds, so
/// a long name's first chunk pads differently from its last.
fn str2hashbuf(name: &[u8], signed: bool, out: &mut [u32]) {
    let num = out.len();
    let pad = {
        let len = name.len() as u32;
        let p = len | (len << 8);
        p | (p << 16)
    };

    let mut val = pad;
    let mut written = 0usize;
    for (i, &b) in name.iter().take(num * 4).enumerate() {
        val = byte(b, signed).wrapping_add(val << 8);
        if i % 4 == 3 {
            out[written] = val;
            written += 1;
            val = pad;
        }
    }
    // The partial final word, then pad out whatever remains.
    if written < num {
        out[written] = val;
        written += 1;
    }
    for slot in &mut out[written..] {
        *slot = pad;
    }
}

fn rol32(x: u32, s: u32) -> u32 {
    x.rotate_left(s)
}

fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y).wrapping_add((x ^ y) & z)
}

fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// The half-MD4 transform: three rounds over eight input words, folded into `buf`.
///
/// The first round adds nothing to each input word; the second and third add the
/// two MD4 round constants. Within a round the four working words rotate, so each
/// takes a turn as the accumulator.
fn half_md4_transform(buf: &mut [u32; 4], input: &[u32; 8]) {
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);

    macro_rules! round {
        ($f:expr, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:expr) => {
            $a = rol32($a.wrapping_add($f($b, $c, $d)).wrapping_add($x), $s);
        };
    }

    round!(md4_f, a, b, c, d, input[0], 3);
    round!(md4_f, d, a, b, c, input[1], 7);
    round!(md4_f, c, d, a, b, input[2], 11);
    round!(md4_f, b, c, d, a, input[3], 19);
    round!(md4_f, a, b, c, d, input[4], 3);
    round!(md4_f, d, a, b, c, input[5], 7);
    round!(md4_f, c, d, a, b, input[6], 11);
    round!(md4_f, b, c, d, a, input[7], 19);

    round!(md4_g, a, b, c, d, input[1].wrapping_add(MD4_K2), 3);
    round!(md4_g, d, a, b, c, input[3].wrapping_add(MD4_K2), 5);
    round!(md4_g, c, d, a, b, input[5].wrapping_add(MD4_K2), 9);
    round!(md4_g, b, c, d, a, input[7].wrapping_add(MD4_K2), 13);
    round!(md4_g, a, b, c, d, input[0].wrapping_add(MD4_K2), 3);
    round!(md4_g, d, a, b, c, input[2].wrapping_add(MD4_K2), 5);
    round!(md4_g, c, d, a, b, input[4].wrapping_add(MD4_K2), 9);
    round!(md4_g, b, c, d, a, input[6].wrapping_add(MD4_K2), 13);

    round!(md4_h, a, b, c, d, input[3].wrapping_add(MD4_K3), 3);
    round!(md4_h, d, a, b, c, input[7].wrapping_add(MD4_K3), 9);
    round!(md4_h, c, d, a, b, input[2].wrapping_add(MD4_K3), 11);
    round!(md4_h, b, c, d, a, input[6].wrapping_add(MD4_K3), 15);
    round!(md4_h, a, b, c, d, input[1].wrapping_add(MD4_K3), 3);
    round!(md4_h, d, a, b, c, input[5].wrapping_add(MD4_K3), 9);
    round!(md4_h, c, d, a, b, input[0].wrapping_add(MD4_K3), 11);
    round!(md4_h, b, c, d, a, input[4].wrapping_add(MD4_K3), 15);

    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

/// The TEA transform: sixteen rounds over four input words, folded into `buf`.
fn tea_transform(buf: &mut [u32; 4], input: &[u32; 4]) {
    let mut sum = 0u32;
    let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (input[0], input[1], input[2], input[3]);

    for _ in 0..16 {
        sum = sum.wrapping_add(TEA_DELTA);
        b0 = b0.wrapping_add(
            ((b1 << 4).wrapping_add(a)) ^ b1.wrapping_add(sum) ^ ((b1 >> 5).wrapping_add(b)),
        );
        b1 = b1.wrapping_add(
            ((b0 << 4).wrapping_add(c)) ^ b0.wrapping_add(sum) ^ ((b0 >> 5).wrapping_add(d)),
        );
    }

    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
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
    fn the_eof_sentinel_is_nudged_down_to_the_previous_even_value() {
        // A major hash landing on the end-of-space sentinel (0xFFFF_FFFE) must move to
        // the previous representable value (0xFFFF_FFFC), keeping its low bit clear —
        // the kernel's convention. Setting the low bit (0xFFFF_FFFF) would both pick the
        // wrong value and collide with the continued-hash flag. The branch is ~2^-31 per
        // name, so it is exercised through the clamp directly.
        assert_eq!(clamp_from_eof(EOF_HASH), 0xFFFF_FFFC);
        assert_eq!(clamp_from_eof(EOF_HASH) & 1, 0, "the low bit stays clear");
        // Every other value passes through untouched.
        assert_eq!(clamp_from_eof(0), 0);
        assert_eq!(clamp_from_eof(0x1234_5678), 0x1234_5678);
        assert_eq!(clamp_from_eof(0xFFFF_FFFC), 0xFFFF_FFFC);
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
