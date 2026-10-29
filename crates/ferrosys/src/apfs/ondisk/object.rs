//! The header every APFS object begins with, and the checksum that covers it.
//!
//! Every structure this family reads from a container — a superblock, an object map, a node of
//! any tree — is an *object*: one block whose first 32 bytes say what it is, which identifier
//! it has, which transaction wrote it, and what checksum covers the rest (Apple File System
//! Reference, pp. 10-21).
//!
//! # The checksum
//!
//! The reference names the checksum "Fletcher 64" (p. 11) and specifies nothing further. The
//! reading every object macOS writes verifies under is this one, observed on 3,309 objects of
//! the images made by each of macOS 15, 26 and 27, at 4, 8, 16 and 64 KiB blocks: the object
//! after its eight-byte checksum field is taken as little-endian 32-bit words, summed modulo
//! 2^32 - 1 into a running sum and a sum of sums, and the two stored words are the check values
//! that, summed after the rest of the object, bring both sums to zero. Each check word lies
//! between one and 2^32 - 1, so a block nothing was ever written to, whose field holds zeros,
//! does not verify.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u32, get_u64, put_u32, put_u64};

use super::ParseError;

/// The modulus both running sums are kept under.
const MODULUS: u64 = 0xFFFF_FFFF;

/// The object types this crate names, as the low 16 bits of the type word carry them
/// (Apple File System Reference, pp. 14-19).
///
/// A type outside this list is a value the reader hands back as it found it; whether an object
/// of that type is acceptable where it was found is the caller's judgment.
pub mod kind {
    /// A container superblock.
    pub const CONTAINER_SUPERBLOCK: u16 = 0x01;
    /// The root node of a B-tree.
    pub const BTREE_ROOT: u16 = 0x02;
    /// A node of a B-tree other than its root.
    pub const BTREE_NODE: u16 = 0x03;
    /// The space manager.
    pub const SPACE_MANAGER: u16 = 0x05;
    /// A block of chunk-info block addresses.
    pub const SPACE_MANAGER_CAB: u16 = 0x06;
    /// A block of chunk information.
    pub const SPACE_MANAGER_CIB: u16 = 0x07;
    /// As a subtype: a free queue's tree.
    pub const SPACE_MANAGER_FREE_QUEUE: u16 = 0x09;
    /// An object map.
    pub const OBJECT_MAP: u16 = 0x0B;
    /// A checkpoint-mapping block.
    pub const CHECKPOINT_MAP: u16 = 0x0C;
    /// A volume superblock.
    pub const VOLUME_SUPERBLOCK: u16 = 0x0D;
    /// As a subtype: a tree of file-system records.
    pub const FS_TREE: u16 = 0x0E;
    /// As a subtype: a tree of extent references.
    pub const EXTENT_REF_TREE: u16 = 0x0F;
    /// As a subtype: a tree of a volume's snapshots.
    pub const SNAPSHOT_TREE: u16 = 0x10;
    /// The reaper.
    pub const REAPER: u16 = 0x11;
    /// A block of the reaper's list.
    pub const REAP_LIST: u16 = 0x12;
    /// As a subtype: an object map's tree of the snapshots it keeps versions for.
    pub const OBJECT_MAP_SNAPSHOT: u16 = 0x13;
    /// The extension object holding each snapshot's identifier.
    pub const SNAPSHOT_EXTENSION: u16 = 0x1D;
    /// A sealed volume's integrity metadata.
    pub const INTEGRITY_META: u16 = 0x1E;
    /// As a subtype: a sealed volume's tree of file extents.
    pub const FILE_EXTENT_TREE: u16 = 0x1F;
}

/// How an object is found from its identifier: the top two bits of its type word
/// (Apple File System Reference, p. 20).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    /// Neither bit: the identifier is looked up in an object map, at a transaction.
    Virtual,
    /// `0x8000_0000`: the object lives in a checkpoint and is found through its mapping.
    Ephemeral,
    /// `0x4000_0000`: the identifier is the block address.
    Physical,
    /// Both bits, which the format defines as invalid.
    Invalid,
}

impl Storage {
    /// The bits of a type word that say this: the top two, as
    /// [`ObjectHeader::storage`] reads them.
    #[must_use]
    pub const fn type_bits(self) -> u32 {
        match self {
            Self::Virtual => 0,
            Self::Ephemeral => 0x8000_0000,
            Self::Physical => 0x4000_0000,
            Self::Invalid => 0xC000_0000,
        }
    }
}

/// The 32 bytes every object begins with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectHeader {
    /// Offset 0. The checksum over the rest of the object: the first check word in the low 32
    /// bits, the second in the high 32.
    pub checksum: u64,
    /// Offset 8. The object's identifier: its block address for a physical object, a number
    /// looked up in an object map for a virtual one.
    pub oid: u64,
    /// Offset 16. The transaction that last wrote the object.
    pub xid: u64,
    /// Offset 24. The type in the low 16 bits and the flags, storage among them, in the high 16.
    pub type_word: u32,
    /// Offset 28. What a container such as a B-tree holds, as an object type.
    pub subtype: u32,
}

impl ObjectHeader {
    /// Bytes on disk.
    pub const SIZE: usize = 32;

    /// Recover a header from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a header.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("object header", Self::SIZE, buf)?;
        Ok(Self {
            checksum: get_u64(buf, 0),
            oid: get_u64(buf, 8),
            xid: get_u64(buf, 16),
            type_word: get_u32(buf, 24),
            subtype: get_u32(buf, 28),
        })
    }

    /// Write the header into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a header.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an object header needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.checksum);
        put_u64(buf, 8, self.oid);
        put_u64(buf, 16, self.xid);
        put_u32(buf, 24, self.type_word);
        put_u32(buf, 28, self.subtype);
    }

    /// The object's type: the low 16 bits of the type word.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        (self.type_word & 0xFFFF) as u16
    }

    /// How the object is found from its identifier.
    #[must_use]
    pub const fn storage(&self) -> Storage {
        match self.type_word & 0xC000_0000 {
            0 => Storage::Virtual,
            0x8000_0000 => Storage::Ephemeral,
            0x4000_0000 => Storage::Physical,
            _ => Storage::Invalid,
        }
    }

    /// The type word's flags other than storage: `0x2000_0000` stored without a header,
    /// `0x1000_0000` encrypted, `0x0800_0000` never persisted (Apple File System Reference,
    /// pp. 20-21). None is set on any object this crate reads.
    #[must_use]
    pub const fn other_flags(&self) -> u32 {
        self.type_word & 0x3FFF_0000
    }
}

/// The checksum an object of these bytes carries, as the header's
/// [`checksum`](ObjectHeader::checksum) field holds it.
///
/// `object` is the whole object, one block long. The field itself, its first eight bytes, is
/// not covered; the words after it are, to the end of the object. A length that is not a
/// multiple of four leaves its last bytes uncovered, and no object the format defines has one.
#[must_use]
pub fn checksum(object: &[u8]) -> u64 {
    let (mut sum, mut sum_of_sums) = (0u64, 0u64);
    for word in object.get(8..).unwrap_or_default().as_chunks::<4>().0 {
        let word = u64::from(get_u32(word, 0));
        // Each operand is below the modulus or equal to it, so one subtraction brings each
        // sum back under it.
        sum += word;
        if sum >= MODULUS {
            sum -= MODULUS;
        }
        sum_of_sums += sum;
        if sum_of_sums >= MODULUS {
            sum_of_sums -= MODULUS;
        }
    }
    let first = MODULUS - (sum + sum_of_sums) % MODULUS;
    let second = MODULUS - (sum + first) % MODULUS;
    (second << 32) | first
}

/// Whether `object`'s stored checksum is the one its bytes carry.
///
/// The comparison is exact. Under the sums' arithmetic all-ones and zero are one value, and a
/// check word computed here is never zero; every object macOS 15, 26 and 27 wrote carries
/// exactly the words computed here, and a block of zeros carries words it cannot.
#[must_use]
pub fn verify(object: &[u8]) -> bool {
    object.len() >= ObjectHeader::SIZE && get_u64(object, 0) == checksum(object)
}

/// Write the checksum `object`'s bytes carry into its first eight bytes. The last thing done
/// to an object before it is written.
///
/// # Panics
///
/// Where `object` is shorter than a header.
pub fn seal(object: &mut [u8]) {
    assert!(
        object.len() >= ObjectHeader::SIZE,
        "an object needs at least {} bytes and was given {}",
        ObjectHeader::SIZE,
        object.len()
    );
    let sum = checksum(object);
    put_u64(object, 0, sum);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips() {
        let header = ObjectHeader {
            checksum: 0x1122_3344_5566_7788,
            oid: 0x0400,
            xid: 7,
            type_word: 0x4000_0002,
            subtype: u32::from(kind::OBJECT_MAP),
        };
        let mut buf = [0u8; ObjectHeader::SIZE];
        header.write_to(&mut buf);
        assert_eq!(ObjectHeader::read_from(&buf), Ok(header));
        assert_eq!(header.kind(), kind::BTREE_ROOT);
        assert_eq!(header.storage(), Storage::Physical);
        assert_eq!(header.other_flags(), 0);
    }

    #[test]
    fn a_short_buffer_is_too_short_rather_than_a_header() {
        assert!(matches!(
            ObjectHeader::read_from(&[0u8; 31]),
            Err(ParseError::TooShort { need: 32, .. })
        ));
    }

    #[test]
    fn storage_is_the_top_two_bits_and_both_together_are_invalid() {
        let at = |word| ObjectHeader {
            checksum: 0,
            oid: 0,
            xid: 0,
            type_word: word,
            subtype: 0,
        };
        assert_eq!(at(0x0000_000D).storage(), Storage::Virtual);
        assert_eq!(at(0x8000_0005).storage(), Storage::Ephemeral);
        assert_eq!(at(0x4000_0002).storage(), Storage::Physical);
        assert_eq!(at(0xC000_0002).storage(), Storage::Invalid);
    }

    #[test]
    fn a_sealed_object_verifies_and_one_changed_byte_does_not() {
        let mut block = vec![0u8; 4096];
        for (i, b) in block.iter_mut().enumerate().skip(8) {
            *b = (i * 7 + 3) as u8;
        }
        seal(&mut block);
        assert!(verify(&block));
        block[100] ^= 1;
        assert!(!verify(&block));
    }

    #[test]
    fn the_sums_over_a_sealed_object_and_then_its_check_words_come_to_zero() {
        // What the check words are for: summed after the rest of the object, both running
        // sums are zero modulo the modulus.
        let mut block = vec![0u8; 4096];
        for (i, b) in block.iter_mut().enumerate().skip(8) {
            *b = (i % 251) as u8;
        }
        seal(&mut block);
        let (mut a, mut b) = (0u64, 0u64);
        let words = block[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .chain(block[..8].as_chunks::<4>().0);
        for word in words {
            a = (a + u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))) % MODULUS;
            b = (b + a) % MODULUS;
        }
        assert_eq!((a, b), (0, 0));
    }

    #[test]
    fn a_block_of_zeros_is_not_an_object() {
        // A zero checksum field over zero bytes would verify under a plain sum; the check words
        // of zero bytes are all ones, so a block nothing was ever written to is refused.
        assert!(!verify(&[0u8; 4096]));
        assert_eq!(checksum(&[0u8; 4096]), u64::MAX);
    }

    #[test]
    fn a_check_word_the_sums_bring_to_zero_is_all_ones() {
        // Steer the last word so the body's two sums add to a multiple of the modulus. The
        // last word enters each sum once, so moving it by `d` moves their total by `2d`, and
        // two has an inverse modulo an odd modulus.
        let mut block = vec![0u8; 4096];
        block[8] = 1;
        let last = block.len() - 4;
        let total = (MODULUS - (checksum(&block) & MODULUS)) % MODULUS;
        let half = MODULUS.div_ceil(2);
        let d = (MODULUS - total) % MODULUS * half % MODULUS;
        put_u32(&mut block, last, d as u32);
        seal(&mut block);
        assert_eq!(
            get_u64(&block, 0) & MODULUS,
            MODULUS,
            "all ones, never zero"
        );
        assert!(verify(&block));
        // The same sums with the word written as zero is not what this checksum writes.
        put_u32(&mut block, 0, 0);
        assert!(!verify(&block));
    }
}
