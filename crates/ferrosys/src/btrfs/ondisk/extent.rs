//! Space accounting: what is allocated, which tree or file holds it, and what is free.
//!
//! Three trees share this vocabulary and the records below are what they hold:
//!
//! - The **extent tree** records one [`ExtentItem`] per allocated run of logical space, and
//!   packs its references into the same item behind it. A reference is an [`InlineRef`]: a byte
//!   saying which kind it is and an eight-byte value whose meaning follows from that byte.
//! - The **block-group tree** — or the extent tree, on a filesystem without that feature —
//!   records one [`BlockGroupItem`] per block group, saying how much of it is spoken for.
//! - The **free-space tree** records one [`FreeSpaceInfo`] per block group saying how its free
//!   space is written down, followed by the runs themselves. A run is a key and nothing else:
//!   `FREE_SPACE_EXTENT` carries a start and a length in its key and has no data at all, which
//!   is why no type here corresponds to one.
//!
//! # Where an extent's own address is
//!
//! Not in any of these structures. Every one of them is keyed by the address it is about — the
//! logical address of an extent, the start of a block group, the start of a free run — so a
//! record read without its key is half a fact. That is the same arrangement [`Chunk`](super::Chunk)
//! is in, and it is the format's way throughout.
//!
//! # The two shapes a metadata extent takes
//!
//! Under `skinny-metadata` a tree block's extent is keyed `METADATA_ITEM` with the block's
//! *level* as the key's offset, and the item is an [`ExtentItem`] followed by its references.
//! Without the feature it is keyed `EXTENT_ITEM` with the block's *length* as the offset, and a
//! 33-byte block-info record sits between the item and its references. The skinny form is what
//! every filesystem this crate writes uses, and [`ExtentItem`] is the head of both.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u8, get_u32, get_u64, put_u8, put_u32, put_u64};
use crate::flags::flag_set;

use super::{BlockGroupFlags, ItemType, ParseError};

/// What an allocated extent holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentFlags(u64);

flag_set!(ExtentFlags: u64);

impl ExtentFlags {
    /// File contents.
    pub const DATA: Self = Self(1 << 0);
    /// A tree block.
    pub const TREE_BLOCK: Self = Self(1 << 1);
    /// The extent's references are to the block that shares it rather than to the tree that
    /// owns it — the form a snapshot leaves behind.
    pub const FULL_BACKREF: Self = Self(1 << 8);
}

/// One allocated run of logical space, and how many references there are to it.
///
/// The references themselves follow this head inside the same item, as many [`InlineRef`]s as
/// [`refs`](Self::refs) counts — so an item is this structure and then a list, and the list is
/// what says *who* holds the extent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentItem {
    /// Offset 0. How many references there are to this extent.
    pub refs: u64,
    /// Offset 8. The transaction that allocated it.
    pub generation: u64,
    /// Offset 16. What it holds.
    pub flags: ExtentFlags,
}

impl ExtentItem {
    /// Bytes on disk, the references behind it excluded.
    pub const SIZE: usize = 24;

    /// Recover an extent item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_extent_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            refs: get_u64(buf, 0),
            generation: get_u64(buf, 8),
            flags: ExtentFlags::from_bits(get_u64(buf, 16)),
        })
    }

    /// Write the extent item into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an extent item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.refs);
        put_u64(buf, 8, self.generation);
        put_u64(buf, 16, self.flags.bits());
    }
}

/// One reference to an extent, stored inside the extent's own item.
///
/// The kind byte is what the same reference would be keyed by if it were an item of its own, and
/// the value's meaning follows from it: for `TREE_BLOCK_REF` it is the objectid of the tree that
/// owns the block, and for `SHARED_BLOCK_REF` the address of the block that points at it. The
/// two data forms are longer than this and are not this structure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InlineRef {
    /// Offset 0. Which kind of reference this is.
    pub kind: ItemType,
    /// Offset 1. Eight bytes whose meaning [`kind`](Self::kind) decides.
    ///
    /// Unaligned on disk — the byte before it is the kind — which is one more reason every
    /// field in this crate is read through an accessor naming its offset rather than by
    /// reinterpreting bytes as a structure.
    pub offset: u64,
}

impl InlineRef {
    /// Bytes on disk.
    pub const SIZE: usize = 9;

    /// Recover an inline reference from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_extent_inline_ref",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            kind: ItemType::from_value(get_u8(buf, 0)),
            offset: get_u64(buf, 1),
        })
    }

    /// Write the reference into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an inline extent reference needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u8(buf, 0, self.kind.value());
        put_u64(buf, 1, self.offset);
    }
}

/// One reference to a *data* extent, naming the file that holds it.
///
/// It is an inline reference like [`InlineRef`], and it is a different shape: the kind byte is
/// followed by these four fields where the block form is followed by a single eight-byte value.
/// So an inline data reference is a kind byte and one of these, and nothing about the byte says
/// how many bytes come after it — the kind is what says, which is why the two forms are named
/// apart here rather than being one structure with a wider tail.
///
/// The same four fields are the *data* of a standalone `EXTENT_DATA_REF` item, whose key offset
/// is a hash of the first three. This crate writes only the inline form, where nothing is
/// hashed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentDataRef {
    /// Offset 0. The subvolume whose tree holds the file.
    pub root: u64,
    /// Offset 8. The file's inode number within that tree.
    pub objectid: u64,
    /// Offset 16. Where in the file the extent's first byte sits.
    pub offset: u64,
    /// Offset 24. How many of that file's extent records point at this extent.
    pub count: u32,
}

impl ExtentDataRef {
    /// Bytes on disk.
    pub const SIZE: usize = 28;

    /// Recover a data reference from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_extent_data_ref",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            root: get_u64(buf, 0),
            objectid: get_u64(buf, 8),
            offset: get_u64(buf, 16),
            count: get_u32(buf, 24),
        })
    }

    /// Write the reference into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an extent data reference needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.root);
        put_u64(buf, 8, self.objectid);
        put_u64(buf, 16, self.offset);
        put_u32(buf, 24, self.count);
    }
}

/// One block group: how much of a chunk's logical space is spoken for, and what for.
///
/// The block group's own start and length are its key's objectid and offset. What is here is
/// the accounting, and the [`flags`](Self::flags) repeat the chunk's — a block group and the
/// chunk covering it are one run of space described by two trees, and a driver reads the
/// allocator's view from this one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockGroupItem {
    /// Offset 0. Bytes of this block group that are allocated.
    pub used: u64,
    /// Offset 8. The chunk objectid, which is
    /// [`FIRST_CHUNK_TREE`](super::objectid::FIRST_CHUNK_TREE) on every filesystem in
    /// existence.
    pub chunk_objectid: u64,
    /// Offset 16. What the block group holds and how it is replicated.
    pub flags: BlockGroupFlags,
}

impl BlockGroupItem {
    /// Bytes on disk.
    pub const SIZE: usize = 24;

    /// Recover a block group item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_block_group_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            used: get_u64(buf, 0),
            chunk_objectid: get_u64(buf, 8),
            flags: BlockGroupFlags::from_bits(get_u64(buf, 16)),
        })
    }

    /// Write the block group item into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a block group item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.used);
        put_u64(buf, 8, self.chunk_objectid);
        put_u64(buf, 16, self.flags.bits());
    }
}

/// How one block group's free space is written down, and how many records it takes.
///
/// The free-space tree records a block group's free space either as a list of runs or as a
/// bitmap, whichever is smaller, and this is the record that says which and how many follow.
/// The block group it is about is its key's objectid and offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FreeSpaceInfo {
    /// Offset 0. How many `FREE_SPACE_EXTENT` or `FREE_SPACE_BITMAP` items follow this one for
    /// this block group.
    pub extent_count: u32,
    /// Offset 4. [`USING_BITMAPS`](Self::USING_BITMAPS), or nothing.
    pub flags: u32,
}

impl FreeSpaceInfo {
    /// Bytes on disk.
    pub const SIZE: usize = 8;

    /// The one flag defined: the free space that follows is a bitmap rather than a list of
    /// runs.
    pub const USING_BITMAPS: u32 = 1;

    /// Recover a free-space record from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_free_space_info",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            extent_count: get_u32(buf, 0),
            flags: get_u32(buf, 4),
        })
    }

    /// Write the free-space record into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a free space info record needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u32(buf, 0, self.extent_count);
        put_u32(buf, 4, self.flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::ondisk::objectid;

    #[test]
    fn an_extent_item_and_its_reference_round_trip_through_their_bytes() {
        let item = ExtentItem {
            refs: 1,
            generation: 7,
            flags: ExtentFlags::TREE_BLOCK,
        };
        let reference = InlineRef {
            kind: ItemType::TREE_BLOCK_REF,
            offset: objectid::FS_TREE,
        };
        let mut bytes = vec![0u8; ExtentItem::SIZE + InlineRef::SIZE];
        item.write_to(&mut bytes);
        reference.write_to(&mut bytes[ExtentItem::SIZE..]);

        assert_eq!(ExtentItem::read_from(&bytes), Ok(item));
        assert_eq!(
            InlineRef::read_from(&bytes[ExtentItem::SIZE..]),
            Ok(reference)
        );
        // The reference's value straddles the alignment its own width would want, the kind byte
        // being in front of it. Reading it back at the right offset is the whole of this claim.
        assert_eq!(bytes[ExtentItem::SIZE], ItemType::TREE_BLOCK_REF.value());
    }

    #[test]
    fn a_block_group_and_a_free_space_record_round_trip_through_their_bytes() {
        let group = BlockGroupItem {
            used: 147_456,
            chunk_objectid: objectid::FIRST_CHUNK_TREE,
            flags: BlockGroupFlags::METADATA | BlockGroupFlags::DUP,
        };
        let mut bytes = [0u8; BlockGroupItem::SIZE];
        group.write_to(&mut bytes);
        assert_eq!(BlockGroupItem::read_from(&bytes), Ok(group));

        let info = FreeSpaceInfo {
            extent_count: 3,
            flags: 0,
        };
        let mut bytes = [0u8; FreeSpaceInfo::SIZE];
        info.write_to(&mut bytes);
        assert_eq!(FreeSpaceInfo::read_from(&bytes), Ok(info));
    }

    #[test]
    fn every_record_here_refuses_a_buffer_too_short_to_hold_it() {
        for got in 0..ExtentItem::SIZE {
            assert!(ExtentItem::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
        for got in 0..InlineRef::SIZE {
            assert!(InlineRef::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
        for got in 0..BlockGroupItem::SIZE {
            assert!(BlockGroupItem::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
        for got in 0..FreeSpaceInfo::SIZE {
            assert!(FreeSpaceInfo::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
    }
}
