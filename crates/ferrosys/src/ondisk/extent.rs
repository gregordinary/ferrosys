//! On-disk extent-tree nodes: the 12-byte header, index entry, and leaf entry.
//!
//! An ext4 extent tree begins with an [`ExtentHeader`]. When the header's depth is
//! zero the entries that follow are [`ExtentLeaf`] records, each mapping a
//! contiguous run of logical blocks to a physical run; when the depth is positive
//! they are [`ExtentIdx`] records pointing at deeper nodes. All three records are
//! twelve bytes, so a node's capacity is `(node_bytes - 12) / 12` entries.
//!
//! These are the byte structs only; assembling them into a tree — inline in an
//! inode or spilled into external blocks — is the extent layer's job.
//!
//! An external node ends with `struct ext4_extent_tail`, a single `crc32c` that
//! `metadata_csum` fills. It sits after the last entry the node declares room for,
//! in the bytes a full node leaves over, so it costs no entry capacity. A tree
//! rooted inline in an inode has no external node and no tail: the inode's own
//! checksum covers it.

use super::{ParseError, get_u16, get_u32, join64, put_u16, put_u32};

/// Magic number in every extent header (`eh_magic`): `0xF30A`, little-endian on
/// disk.
pub const EXTENT_MAGIC: u16 = 0xf30a;

/// The on-disk size of an extent header, index entry, or leaf entry — all three
/// are twelve bytes.
pub const EXTENT_ENTRY_SIZE: usize = 12;

/// The on-disk size of an external node's checksum tail (`struct ext4_extent_tail`).
pub const EXTENT_TAIL_LEN: usize = 4;

/// Threshold above which a leaf's raw length field denotes an uninitialized
/// extent: a stored `ee_len` greater than this encodes an uninitialized run of
/// `ee_len - 32768` blocks.
const UNINIT_LEN_LIMIT: u16 = 32768;

/// The header at the start of every extent-tree node (`struct ext4_extent_header`).
///
/// It records how many entries follow, how many could fit, and whether those
/// entries are leaves (`depth == 0`) or index nodes (`depth > 0`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentHeader {
    /// Valid entries following this header (`eh_entries`).
    pub entries: u16,
    /// Entries that fit after this header (`eh_max`), fixed by the node's capacity.
    pub max: u16,
    /// Tree depth (`eh_depth`): zero means leaves follow, positive means index
    /// nodes point at nodes one level shallower.
    pub depth: u16,
    /// Generation (`eh_generation`); zero in the images this crate writes.
    pub generation: u32,
}

impl ExtentHeader {
    /// On-disk size in bytes.
    pub const SIZE: usize = EXTENT_ENTRY_SIZE;

    /// Serialize to the twelve-byte on-disk form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        put_u16(&mut b, 0, EXTENT_MAGIC);
        put_u16(&mut b, 2, self.entries);
        put_u16(&mut b, 4, self.max);
        put_u16(&mut b, 6, self.depth);
        put_u32(&mut b, 8, self.generation);
        b
    }

    /// Parse from the twelve-byte on-disk form, validating the magic number.
    ///
    /// # Errors
    ///
    /// [`ParseError::BadMagic`] if `eh_magic` is not [`EXTENT_MAGIC`].
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Result<Self, ParseError> {
        let magic = get_u16(b, 0);
        if magic != EXTENT_MAGIC {
            return Err(ParseError::BadMagic {
                structure: "ExtentHeader",
                found: u32::from(magic),
                expected: u32::from(EXTENT_MAGIC),
            });
        }
        Ok(Self {
            entries: get_u16(b, 2),
            max: get_u16(b, 4),
            depth: get_u16(b, 6),
            generation: get_u32(b, 8),
        })
    }
}

/// An interior-node entry (`struct ext4_extent_idx`) pointing at a deeper node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentIdx {
    /// First logical block this subtree covers (`ei_block`).
    pub block: u32,
    /// Physical block of the child node (`ei_leaf_lo` + `ei_leaf_hi`).
    pub leaf: u64,
}

impl ExtentIdx {
    /// On-disk size in bytes.
    pub const SIZE: usize = EXTENT_ENTRY_SIZE;

    /// Serialize to the twelve-byte on-disk form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        put_u32(&mut b, 0, self.block);
        put_u32(&mut b, 4, self.leaf as u32);
        put_u16(&mut b, 8, (self.leaf >> 32) as u16);
        b
    }

    /// Parse from the twelve-byte on-disk form.
    #[must_use]
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        Self {
            block: get_u32(b, 0),
            leaf: join64(get_u32(b, 4), u32::from(get_u16(b, 8))),
        }
    }
}

/// A leaf entry (`struct ext4_extent`) mapping a logical run to a physical run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentLeaf {
    /// First logical block of the run (`ee_block`).
    pub block: u32,
    /// Length of the run in blocks. An initialized run holds at most 32768 blocks; an
    /// uninitialized run at most 32767, since its length is stored offset by 32768.
    pub len: u16,
    /// First physical block of the run (`ee_start_lo` + `ee_start_hi`).
    pub start: u64,
    /// Whether the run holds valid data. An uninitialized run reads back as zeros
    /// and is encoded with a length past `32768`; the images this crate writes use
    /// initialized runs only.
    pub initialized: bool,
}

impl ExtentLeaf {
    /// On-disk size in bytes.
    pub const SIZE: usize = EXTENT_ENTRY_SIZE;

    /// Serialize to the twelve-byte on-disk form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let raw_len = if self.initialized {
            self.len
        } else {
            // An uninitialized run stores its length offset by 32768, so its own length
            // is at most 32767. The writer emits initialized runs only, so a longer
            // uninitialized run is a caller contract violation; saturate rather than
            // overflow the field.
            debug_assert!(
                self.len < UNINIT_LEN_LIMIT,
                "an uninitialized extent run holds at most 32767 blocks"
            );
            self.len.saturating_add(UNINIT_LEN_LIMIT)
        };
        let mut b = [0u8; Self::SIZE];
        put_u32(&mut b, 0, self.block);
        put_u16(&mut b, 4, raw_len);
        put_u16(&mut b, 6, (self.start >> 32) as u16);
        put_u32(&mut b, 8, self.start as u32);
        b
    }

    /// Parse from the twelve-byte on-disk form, decoding the initialized/length
    /// split of `ee_len`.
    #[must_use]
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        let raw_len = get_u16(b, 4);
        let (len, initialized) = if raw_len > UNINIT_LEN_LIMIT {
            (raw_len - UNINIT_LEN_LIMIT, false)
        } else {
            (raw_len, true)
        };
        Self {
            block: get_u32(b, 0),
            len,
            start: join64(get_u32(b, 8), u32::from(get_u16(b, 6))),
            initialized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let h = ExtentHeader {
            entries: 1,
            max: 4,
            depth: 0,
            generation: 0,
        };
        assert_eq!(ExtentHeader::from_bytes(&h.to_bytes()).unwrap(), h);
        // Magic is written little-endian: 0x0a 0xf3.
        assert_eq!(&h.to_bytes()[0..2], &[0x0a, 0xf3]);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut b = ExtentHeader {
            entries: 0,
            max: 4,
            depth: 0,
            generation: 0,
        }
        .to_bytes();
        b[0] = 0;
        assert!(matches!(
            ExtentHeader::from_bytes(&b),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn idx_round_trips_with_high_bits() {
        let e = ExtentIdx {
            block: 0x1234,
            leaf: 0x1_0000_5678,
        };
        assert_eq!(ExtentIdx::from_bytes(&e.to_bytes()), e);
    }

    #[test]
    fn leaf_round_trips_initialized() {
        let e = ExtentLeaf {
            block: 0,
            len: 4,
            start: 7,
            initialized: true,
        };
        assert_eq!(ExtentLeaf::from_bytes(&e.to_bytes()), e);
    }

    #[test]
    fn leaf_round_trips_uninitialized_and_high_start() {
        let e = ExtentLeaf {
            block: 100,
            len: 8,
            start: 0x1_0000_0000,
            initialized: false,
        };
        let d = ExtentLeaf::from_bytes(&e.to_bytes());
        assert_eq!(d, e);
        // Uninitialized runs are encoded above the 32768 threshold.
        assert_eq!(get_u16(&e.to_bytes(), 4), 8 + UNINIT_LEN_LIMIT);
    }
}
