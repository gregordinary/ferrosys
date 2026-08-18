//! The checksum every btrfs metadata object carries, and the algorithms a filesystem may
//! choose between.
//!
//! One recipe covers the superblock and every tree block, because the format gives them the
//! same first field: a 32-byte checksum, then everything it protects. So the covered range is
//! "from the end of the field to the end of the object", and the object's own length is what
//! decides where that is — 4096 bytes for a superblock, the filesystem's node size for a tree
//! block.
//!
//! # The seeding is btrfs's own
//!
//! The polynomial is the one ext4 uses and nothing else about the construction is. This
//! filesystem seeds with all-ones and inverts the result, which is the standalone CRC-32C of
//! the covered bytes; ext4 chains a base seed through an object's identity and never inverts.
//! Two filesystems agreeing on a polynomial is not two filesystems agreeing on a checksum, so
//! the values here are held against an image the pinned baseline wrote rather than carried
//! across.
//!
//! This module is pure and allocates nothing.

use crate::bytes::{get_u32, put_u32};
use crate::crc32c;

/// Bytes the checksum field occupies, whatever algorithm fills it.
///
/// The field is one width for every algorithm and the digest is not: crc32c fills four bytes
/// and leaves twenty-eight zero, xxhash64 fills eight, and the two 256-bit algorithms fill it.
/// A reader that compared the whole field without knowing the algorithm's digest length would
/// be comparing padding.
pub const CSUM_FIELD_LEN: usize = 32;

/// The first byte a checksum covers, in every object that carries one.
///
/// Everything before it is the field itself, which cannot cover itself.
pub const CHECKSUM_COVERED_FROM: usize = CSUM_FIELD_LEN;

/// Which algorithm fills the checksum field of every object in one filesystem.
///
/// The choice is made at format time, recorded in the superblock, and never mixed within a
/// filesystem. Only [`CRC32C`](Self::CRC32C) is computed here; the rest are named so a reader
/// meeting one reports the algorithm it cannot verify rather than comparing bytes against a
/// digest it did not produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChecksumType(u16);

impl ChecksumType {
    /// Reflected CRC-32C, four bytes. The default, and what the pinned baseline writes.
    pub const CRC32C: Self = Self(0);
    /// xxhash64, eight bytes.
    pub const XXHASH64: Self = Self(1);
    /// SHA-256, thirty-two bytes.
    pub const SHA256: Self = Self(2);
    /// BLAKE2b-256, thirty-two bytes.
    pub const BLAKE2B: Self = Self(3);

    /// The on-disk value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Wrap an on-disk value, whatever it holds.
    #[must_use]
    pub const fn from_value(value: u16) -> Self {
        Self(value)
    }

    /// The name the algorithm is known by, or [`None`] where the value is one this release of
    /// the format has not defined.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::CRC32C => "crc32c",
            Self::XXHASH64 => "xxhash64",
            Self::SHA256 => "sha256",
            Self::BLAKE2B => "blake2b",
            _ => return None,
        })
    }

    /// How many bytes of the field this algorithm fills, or [`None`] where the value is
    /// undefined.
    ///
    /// The remainder of the field is zero, and is not part of the comparison.
    #[must_use]
    pub const fn digest_len(self) -> Option<usize> {
        Some(match self {
            Self::CRC32C => 4,
            Self::XXHASH64 => 8,
            Self::SHA256 | Self::BLAKE2B => 32,
            _ => return None,
        })
    }
}

/// The crc32c checksum of a metadata object, in the seeding and finalization btrfs uses.
///
/// `object` is the whole object, checksum field included: the covered range begins at
/// [`CHECKSUM_COVERED_FROM`] and runs to the end of what was passed, so the caller decides how
/// long the object is by how much it hands over. Four bytes come back, stored
/// little-endian in the first four bytes of the field with the rest left zero.
///
/// # Panics
///
/// Where `object` is shorter than the checksum field it begins with. Every caller reads a
/// whole object — a superblock, or a block of the filesystem's node size — before asking.
#[must_use]
pub fn checksum(object: &[u8]) -> u32 {
    assert!(
        object.len() > CHECKSUM_COVERED_FROM,
        "a checksummed object is longer than the field holding its checksum: got {} bytes",
        object.len()
    );
    crc32c_over(&object[CHECKSUM_COVERED_FROM..])
}

/// The crc32c of a run of bytes, in the seeding and finalization btrfs uses.
///
/// The recipe rather than the object: a metadata block hands over everything past its own
/// checksum field, and a sector of file data hands over the sector. One filesystem checksums
/// both the same way, so this is where the seeding and the inversion are written down and
/// [`checksum`] is the metadata caller of it.
#[must_use]
pub fn crc32c_over(bytes: &[u8]) -> u32 {
    crc32c(!0, bytes) ^ !0
}

/// Write an object's own checksum into the field it begins with.
///
/// The last thing done to every tree block and every superblock the format writes, and it is
/// last because the checksum covers everything after the field: a field set before the object
/// is finished is a field covering bytes that then changed.
///
/// The four bytes of a crc32c go in little-endian and the twenty-eight behind them are cleared,
/// which is what [`padding_is_clear`] then finds. A wider algorithm fills more of the field, and
/// this crate writes the one the format's own default writes.
///
/// # Panics
///
/// Where `object` is shorter than the checksum field it begins with.
pub fn seal(object: &mut [u8]) {
    let digest = checksum(object);
    put_u32(object, 0, digest);
    object[4..CSUM_FIELD_LEN].fill(0);
}

/// The checksum an object records for itself, read out of its own first bytes.
///
/// Only the leading [`digest_len`](ChecksumType::digest_len) bytes are the digest, so a
/// comparison against a crc32c takes four of them and the twenty-eight zeros behind are
/// separately worth checking: a field with something in its padding is a field written by
/// something that did not agree about the algorithm.
///
/// # Panics
///
/// Where `object` is shorter than the checksum field.
#[must_use]
pub fn stored_crc32c(object: &[u8]) -> u32 {
    assert!(
        object.len() >= CSUM_FIELD_LEN,
        "a checksummed object holds a whole checksum field: got {} bytes",
        object.len()
    );
    get_u32(object, 0)
}

/// Whether the bytes of the field past this algorithm's digest are the zeros the format
/// leaves there.
///
/// # Panics
///
/// Where `object` is shorter than the checksum field.
#[must_use]
pub fn padding_is_clear(object: &[u8], digest_len: usize) -> bool {
    assert!(
        object.len() >= CSUM_FIELD_LEN,
        "a checksummed object holds a whole checksum field: got {} bytes",
        object.len()
    );
    object[digest_len.min(CSUM_FIELD_LEN)..CSUM_FIELD_LEN]
        .iter()
        .all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_is_the_standalone_crc_of_everything_past_the_field() {
        // Held against `crc32c`'s own documented standalone form rather than against a second
        // spelling of the seeding: seed with all-ones, invert the result.
        let mut object = [0u8; 64];
        object[CHECKSUM_COVERED_FROM..CHECKSUM_COVERED_FROM + 9].copy_from_slice(b"123456789");
        // Only the nine bytes and the zeros behind them are covered; whatever is in the field
        // itself is not.
        object[..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let over_all = crc32c(!0, &object[CHECKSUM_COVERED_FROM..]) ^ !0;
        assert_eq!(checksum(&object), over_all);
        // And the field is genuinely excluded: changing it changes nothing.
        object[..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(checksum(&object), over_all);
    }

    #[test]
    fn the_covered_range_ends_where_the_object_does() {
        // The object's length is the caller's statement of how long it is, which is what lets
        // one recipe cover a 4096-byte superblock and a node-sized tree block.
        let object = [0u8; 4096];
        assert_ne!(checksum(&object), checksum(&object[..2048]));
    }

    #[test]
    fn a_stored_checksum_is_the_first_four_bytes_and_the_rest_are_padding() {
        let mut object = [0u8; 64];
        object[..4].copy_from_slice(&0x836b_4a11u32.to_le_bytes());
        assert_eq!(stored_crc32c(&object), 0x836b_4a11);
        assert!(padding_is_clear(&object, 4));
        // Something in the padding is a field written by a tool that did not agree about the
        // algorithm, which is worth telling apart from a checksum that simply differs.
        object[10] = 1;
        assert!(!padding_is_clear(&object, 4));
        assert_eq!(
            stored_crc32c(&object),
            0x836b_4a11,
            "the digest is unaffected"
        );
    }

    #[test]
    fn every_algorithm_the_format_defines_is_named_and_sized_and_no_other_is() {
        for (ty, name, len) in [
            (ChecksumType::CRC32C, "crc32c", 4),
            (ChecksumType::XXHASH64, "xxhash64", 8),
            (ChecksumType::SHA256, "sha256", 32),
            (ChecksumType::BLAKE2B, "blake2b", 32),
        ] {
            assert_eq!(ty.name(), Some(name));
            assert_eq!(ty.digest_len(), Some(len));
        }
        let unknown = ChecksumType::from_value(4);
        assert_eq!(unknown.name(), None);
        assert_eq!(
            unknown.digest_len(),
            None,
            "a length nothing defined is not a length"
        );
        assert_eq!(unknown.value(), 4);
    }
}
