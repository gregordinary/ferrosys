//! The three structures a tree block is made of: its header, a leaf's item array, and an
//! internal node's child pointers.
//!
//! Every block of every btrfs tree begins with the same 101-byte header, and what follows is
//! decided by one byte of it. At level 0 the block is a **leaf**: an array of
//! [`Item`] growing forward from the header, and the items' data growing *backward* from the
//! end of the block, so a leaf fills from both ends and the free space is in the middle. At
//! any higher level it is an internal **node**: an array of [`KeyPtr`], each a key and the
//! address of the child that holds it.
//!
//! This module is pure: it moves bytes to and from values and does no I/O. It forms no
//! judgment about whether the recovered fields describe a well-formed block — an `nritems`
//! larger than the block could hold is a value this layer hands back and the layer above
//! refuses, because a classifier and a reader want that question asked with different
//! strictness.

use crate::bytes::{get_arr, get_u8, get_u32, get_u64, put_arr, put_u8, put_u32, put_u64};

use super::{CSUM_FIELD_LEN, DiskKey, ParseError};

/// The deepest a btrfs tree may be, counting the leaf as level 0.
///
/// The format's own ceiling. A descent is bounded by it independently of the visited set, so a
/// block whose level does not decrease on the way down is refused rather than followed.
pub const MAX_LEVEL: u8 = 8;

/// The level a leaf carries, and the only level at which a block holds items.
pub const LEAF_LEVEL: u8 = 0;

/// The block has been written by a filesystem that considers it live.
pub const HEADER_FLAG_WRITTEN: u64 = 1 << 0;

/// The block belongs to a relocation tree.
pub const HEADER_FLAG_RELOC: u64 = 1 << 1;

/// The bit position of the backref revision within [`Header::flags`].
///
/// The top byte of the flag word is not a flag at all: it is a small integer saying which
/// generation of back-reference format the block's tree uses. Reading it as flags would report
/// a block as carrying eight settings the format never defined.
pub const BACKREF_REV_SHIFT: u32 = 56;

/// The revision every block of a filesystem with `MIXED_BACKREF` carries, which is every
/// filesystem this crate reads.
pub const BACKREF_REV_MIXED: u8 = 1;

/// The 101 bytes every node and every leaf begins with.
///
/// The first four fields are laid out exactly as a superblock's are, which is the format's own
/// arrangement and the reason one checksum recipe covers both ([`super::checksum`]).
///
/// Three of the fields are the block saying who it is, and each is worth checking against what
/// the reader believed when it went to fetch it. [`bytenr`](Self::bytenr) is the block's own
/// logical address, so a read that landed somewhere else says so; [`fsid`](Self::fsid) is the
/// filesystem's, so a block from another filesystem — a stale image under a new one, a
/// mis-mapped chunk — says so; and [`generation`](Self::generation) is the transaction that
/// wrote it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// Offset 0, 32 bytes. The checksum over everything after it. Only the leading bytes the
    /// filesystem's algorithm produces are meaningful; the rest are zero.
    pub csum: [u8; CSUM_FIELD_LEN],
    /// Offset 32, 16 bytes. The filesystem this block belongs to — which is
    /// [`SuperBlock::metadata_uuid`](super::SuperBlock::metadata_uuid) rather than the
    /// filesystem id where `METADATA_UUID` is set.
    pub fsid: [u8; 16],
    /// Offset 48. This block's own logical address.
    pub bytenr: u64,
    /// Offset 56. [`HEADER_FLAG_WRITTEN`], [`HEADER_FLAG_RELOC`], and the backref revision in
    /// the top byte.
    pub flags: u64,
    /// Offset 64, 16 bytes. The chunk tree's own id, which every block carries and which
    /// `btrfstune -U` leaves alone when it rewrites the filesystem id.
    pub chunk_tree_uuid: [u8; 16],
    /// Offset 80. The transaction that wrote this block.
    pub generation: u64,
    /// Offset 88. The objectid of the tree this block belongs to.
    pub owner: u64,
    /// Offset 96. How many items or child pointers follow. Unbounded by anything in this
    /// layer: what a block has room for is a question for the caller that knows its size.
    pub nritems: u32,
    /// Offset 100. Zero for a leaf; the height above the leaves otherwise.
    pub level: u8,
}

impl Header {
    /// Bytes on disk.
    pub const SIZE: usize = 101;

    /// Recover a header from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a header.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_header",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            csum: get_arr(buf, 0),
            fsid: get_arr(buf, 32),
            bytenr: get_u64(buf, 48),
            flags: get_u64(buf, 56),
            chunk_tree_uuid: get_arr(buf, 64),
            generation: get_u64(buf, 80),
            owner: get_u64(buf, 88),
            nritems: get_u32(buf, 96),
            level: get_u8(buf, 100),
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
            "a tree block header needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_arr(buf, 0, &self.csum);
        put_arr(buf, 32, &self.fsid);
        put_u64(buf, 48, self.bytenr);
        put_u64(buf, 56, self.flags);
        put_arr(buf, 64, &self.chunk_tree_uuid);
        put_u64(buf, 80, self.generation);
        put_u64(buf, 88, self.owner);
        put_u32(buf, 96, self.nritems);
        put_u8(buf, 100, self.level);
    }

    /// Whether this block holds items rather than child pointers.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        self.level == LEAF_LEVEL
    }

    /// The back-reference format revision from the top byte of [`flags`](Self::flags).
    #[must_use]
    pub const fn backref_rev(self) -> u8 {
        (self.flags >> BACKREF_REV_SHIFT) as u8
    }
}

/// One entry of a leaf's item array: a key, and where in the block its data sits.
///
/// [`offset`](Self::offset) is measured from the **end of the header** rather than from the
/// start of the block, so the data begins at `Header::SIZE + offset`. It counts down from the
/// end of the block as the leaf fills, which is why the items in a leaf appear in descending
/// offset order and why the free space is between the array and the data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Item {
    /// Offset 0, 17 bytes. What record this is.
    pub key: DiskKey,
    /// Offset 17. Where the data begins, counted from the end of the header.
    pub offset: u32,
    /// Offset 21. How many bytes of data.
    pub size: u32,
}

impl Item {
    /// Bytes on disk.
    pub const SIZE: usize = 25;

    /// Recover an item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than an item.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            key: DiskKey::read_from(buf)?,
            offset: get_u32(buf, 17),
            size: get_u32(buf, 21),
        })
    }

    /// Write the item into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than an item.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a leaf item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.key.write_to(buf);
        put_u32(buf, 17, self.offset);
        put_u32(buf, 21, self.size);
    }
}

/// One entry of an internal node: the lowest key of a child, and where that child is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyPtr {
    /// Offset 0, 17 bytes. The lowest key in the subtree below.
    pub key: DiskKey,
    /// Offset 17. The child's logical address.
    pub blockptr: u64,
    /// Offset 25. The transaction that wrote the child, which the child's own header repeats.
    pub generation: u64,
}

impl KeyPtr {
    /// Bytes on disk.
    pub const SIZE: usize = 33;

    /// Recover a child pointer from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a child pointer.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_key_ptr",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            key: DiskKey::read_from(buf)?,
            blockptr: get_u64(buf, 17),
            generation: get_u64(buf, 25),
        })
    }

    /// Write the child pointer into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a child pointer.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a node key pointer needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.key.write_to(buf);
        put_u64(buf, 17, self.blockptr);
        put_u64(buf, 25, self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::super::ItemType;
    use super::*;

    fn a_header() -> Header {
        Header {
            csum: [0xa5; CSUM_FIELD_LEN],
            fsid: [0x11; 16],
            bytenr: 22_036_480,
            flags: HEADER_FLAG_WRITTEN | (u64::from(BACKREF_REV_MIXED) << BACKREF_REV_SHIFT),
            chunk_tree_uuid: [0x22; 16],
            generation: 8,
            owner: 3,
            nritems: 4,
            level: LEAF_LEVEL,
        }
    }

    #[test]
    fn a_header_round_trips_through_its_hundred_and_one_bytes() {
        let header = a_header();
        let mut buf = [0u8; Header::SIZE];
        header.write_to(&mut buf);
        assert_eq!(Header::read_from(&buf).expect("a full header"), header);
        // The offsets are asserted against the bytes, not only against each other: an
        // accessor pair that read and wrote the same wrong offset would round-trip and put
        // every field of every tree block in the wrong place.
        assert_eq!(&buf[48..56], &22_036_480u64.to_le_bytes());
        assert_eq!(&buf[88..96], &3u64.to_le_bytes());
        assert_eq!(&buf[96..100], &4u32.to_le_bytes());
        assert_eq!(buf[100], 0);
    }

    #[test]
    fn the_top_byte_of_the_flag_word_is_a_revision_and_not_eight_flags() {
        let header = a_header();
        assert_eq!(header.backref_rev(), BACKREF_REV_MIXED);
        assert_eq!(header.flags & HEADER_FLAG_WRITTEN, HEADER_FLAG_WRITTEN);
        // The value the pinned baseline writes into every block it lays down.
        assert_eq!(header.flags, 0x0100_0000_0000_0001);
        assert!(header.is_leaf());
    }

    #[test]
    fn a_buffer_shorter_than_a_header_holds_no_header() {
        let err = Header::read_from(&[0u8; Header::SIZE - 1]).expect_err("a hundred bytes");
        assert!(matches!(
            err,
            ParseError::TooShort {
                need: 101,
                got: 100,
                ..
            }
        ));
    }

    #[test]
    fn an_item_round_trips_and_its_offset_is_measured_from_the_end_of_the_header() {
        let item = Item {
            key: DiskKey::new(1, ItemType::DEV_ITEM, 1),
            offset: 16_185,
            size: 98,
        };
        let mut buf = [0u8; Item::SIZE];
        item.write_to(&mut buf);
        assert_eq!(Item::read_from(&buf).expect("a full item"), item);
        assert_eq!(&buf[17..21], &16_185u32.to_le_bytes());
        assert_eq!(&buf[21..25], &98u32.to_le_bytes());
        // Which is what the offset means: the first item of the pinned baseline's chunk tree
        // sits at 101 + 16185 in a 16 KiB block, ending exactly at the block's last byte.
        assert_eq!(
            Header::SIZE + item.offset as usize + item.size as usize,
            16_384
        );
    }

    #[test]
    fn a_child_pointer_round_trips_through_its_thirty_three_bytes() {
        let ptr = KeyPtr {
            key: DiskKey::new(5, ItemType::ROOT_ITEM, 0),
            blockptr: 30_441_472,
            generation: 5,
        };
        let mut buf = [0u8; KeyPtr::SIZE];
        ptr.write_to(&mut buf);
        assert_eq!(KeyPtr::read_from(&buf).expect("a full pointer"), ptr);
        assert_eq!(&buf[17..25], &30_441_472u64.to_le_bytes());
        assert_eq!(&buf[25..33], &5u64.to_le_bytes());
    }

    #[test]
    fn a_buffer_shorter_than_an_item_or_a_pointer_holds_neither() {
        assert!(matches!(
            Item::read_from(&[0u8; Item::SIZE - 1]),
            Err(ParseError::TooShort {
                need: 25,
                got: 24,
                ..
            })
        ));
        assert!(matches!(
            KeyPtr::read_from(&[0u8; KeyPtr::SIZE - 1]),
            Err(ParseError::TooShort {
                need: 33,
                got: 32,
                ..
            })
        ));
    }
}
