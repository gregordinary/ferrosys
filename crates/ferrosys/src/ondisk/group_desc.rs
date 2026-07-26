//! The block-group descriptor (`struct ext4_group_desc`), in both its 32-byte and
//! 64-byte forms.
//!
//! One descriptor per block group records where that group's block bitmap, inode
//! bitmap, and inode table live and how many blocks, inodes, and directories the
//! group holds free or in use. With the `64bit` feature the descriptor is 64 bytes
//! and every address and count has a high half; without it the descriptor is 32
//! bytes and only the low halves exist. This model always carries the high halves
//! so widening addressing writes a different value, not a different type; the width
//! actually serialized is chosen per call by the descriptor size.

use super::{ParseError, get_u16, get_u32, join64, put_u16, put_u32};

/// `EXT2_BG_INODE_UNINIT` (`0x0001`): the group's inode bitmap is not initialized on
/// disk and is derived from the group's fixed layout. Set under `metadata_csum` on a
/// group with no in-use inodes; the on-disk inode bitmap is written zero and its
/// checksum field is left zero.
pub const BG_INODE_UNINIT: u16 = 0x0001;

/// `EXT2_BG_BLOCK_UNINIT` (`0x0002`): the group's block bitmap is not initialized on
/// disk and is derived from the group's fixed layout. Set under `metadata_csum` on a
/// group holding no data blocks — excluding a flex-group head (which physically
/// carries the packed tables) and the final group; the on-disk block bitmap is
/// written zero and its checksum field is left zero.
pub const BG_BLOCK_UNINIT: u16 = 0x0002;

/// `EXT2_BG_INODE_ZEROED` (`0x0004`): the group's inode table has been zeroed on
/// disk. This crate zeroes every inode table it writes, so it sets this flag on
/// every group. (The `BG_*_UNINIT` flags this field can also carry take their
/// checksummed meaning only under `metadata_csum`.)
pub const BG_INODE_ZEROED: u16 = 0x0004;

/// A block-group descriptor: the placement and accounting for one block group.
///
/// Addresses and counts are held as their full logical values; [`write_to`] splits
/// them into the low and high halves ext4 stores, and [`read_from`] recombines
/// them.
///
/// [`write_to`]: GroupDescriptor::write_to
/// [`read_from`]: GroupDescriptor::read_from
///
/// # Constructing one
///
/// Start from [`GroupDescriptor::default`] and assign the fields that differ. A
/// `#[non_exhaustive]` structure cannot be written as a literal from outside
/// this crate, and that is about the Rust type, not the format: the byte layout is
/// [`read_from`](Self::read_from), [`write_to`](Self::write_to), and the
/// [`SIZE_32`](Self::SIZE_32) / [`SIZE_64`](Self::SIZE_64) widths, and none of them
/// changes. What the attribute buys is that this crate can widen its
/// coverage of the on-disk structure — the fields it does not yet model — without that
/// being a breaking change for everyone reading an image.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct GroupDescriptor {
    /// Block number of this group's block bitmap (`bg_block_bitmap`).
    pub block_bitmap: u64,
    /// Block number of this group's inode bitmap (`bg_inode_bitmap`).
    pub inode_bitmap: u64,
    /// First block of this group's inode table (`bg_inode_table`).
    pub inode_table: u64,
    /// Free blocks in this group (`bg_free_blocks_count`).
    pub free_blocks_count: u32,
    /// Free inodes in this group (`bg_free_inodes_count`).
    pub free_inodes_count: u32,
    /// Directories in this group (`bg_used_dirs_count`), used to spread new
    /// directories across groups.
    pub used_dirs_count: u32,
    /// Descriptor flags (`bg_flags`): the `BG_*_UNINIT`/`BG_INODE_ZEROED` set.
    pub flags: u16,
    /// Count of inodes at the tail of this group's table never yet used
    /// (`bg_itable_unused`); lets a checker skip scanning them.
    pub itable_unused: u32,
    /// Checksum of this descriptor (`bg_checksum`), written through the checksum
    /// seam; the low 16 bits of a crc32c under `metadata_csum`, zero while it is off.
    pub checksum: u16,
    /// crc32c of the block bitmap (`bg_block_bitmap_csum`); zero while checksums
    /// are off.
    pub block_bitmap_csum: u32,
    /// crc32c of the inode bitmap (`bg_inode_bitmap_csum`); zero while checksums
    /// are off.
    pub inode_bitmap_csum: u32,
}

impl GroupDescriptor {
    /// On-disk size of the 32-byte (non-`64bit`) descriptor form.
    pub const SIZE_32: usize = 32;
    /// On-disk size of the 64-byte (`64bit`) descriptor form.
    pub const SIZE_64: usize = 64;
    /// Byte offset of `bg_checksum`, which participates in its own checksum as zero.
    pub const CHECKSUM_OFFSET: usize = 0x1e;

    /// Serialize into the first `desc_size` bytes of `buf`.
    ///
    /// `desc_size` is [`SIZE_32`](Self::SIZE_32) or [`SIZE_64`](Self::SIZE_64). The
    /// 64-byte form additionally writes the high halves; the 32-byte form writes
    /// only the low halves, so any value that does not fit in 32/16 bits is
    /// truncated by the caller's choice of width. A size between the two writes the
    /// 32-byte form and leaves the rest of `buf` alone.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidField`] if `desc_size` is below [`SIZE_32`](Self::SIZE_32),
    /// which is the smallest descriptor the format has: every field this writes lies
    /// within those 32 bytes. [`ParseError::TooShort`] if `buf` is smaller than
    /// `desc_size`.
    pub fn write_to(&self, buf: &mut [u8], desc_size: usize) -> Result<(), ParseError> {
        Self::check_desc_size(desc_size)?;
        if buf.len() < desc_size {
            return Err(ParseError::TooShort {
                structure: "GroupDescriptor",
                need: desc_size,
                got: buf.len(),
            });
        }
        put_u32(buf, 0x00, self.block_bitmap as u32);
        put_u32(buf, 0x04, self.inode_bitmap as u32);
        put_u32(buf, 0x08, self.inode_table as u32);
        put_u16(buf, 0x0c, self.free_blocks_count as u16);
        put_u16(buf, 0x0e, self.free_inodes_count as u16);
        put_u16(buf, 0x10, self.used_dirs_count as u16);
        put_u16(buf, 0x12, self.flags);
        // 0x14 bg_exclude_bitmap_lo — unused, left zero.
        put_u16(buf, 0x18, self.block_bitmap_csum as u16);
        put_u16(buf, 0x1a, self.inode_bitmap_csum as u16);
        put_u16(buf, 0x1c, self.itable_unused as u16);
        put_u16(buf, 0x1e, self.checksum);

        if desc_size >= Self::SIZE_64 {
            put_u32(buf, 0x20, (self.block_bitmap >> 32) as u32);
            put_u32(buf, 0x24, (self.inode_bitmap >> 32) as u32);
            put_u32(buf, 0x28, (self.inode_table >> 32) as u32);
            put_u16(buf, 0x2c, (self.free_blocks_count >> 16) as u16);
            put_u16(buf, 0x2e, (self.free_inodes_count >> 16) as u16);
            put_u16(buf, 0x30, (self.used_dirs_count >> 16) as u16);
            put_u16(buf, 0x32, (self.itable_unused >> 16) as u16);
            // 0x34 bg_exclude_bitmap_hi — unused, left zero.
            put_u16(buf, 0x38, (self.block_bitmap_csum >> 16) as u16);
            put_u16(buf, 0x3a, (self.inode_bitmap_csum >> 16) as u16);
            // 0x3c bg_reserved — left zero.
        }
        Ok(())
    }

    /// Parse `desc_size` bytes from `buf`.
    ///
    /// A size between [`SIZE_32`](Self::SIZE_32) and [`SIZE_64`](Self::SIZE_64) reads the
    /// 32-byte form and leaves the high halves zero.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidField`] if `desc_size` is below [`SIZE_32`](Self::SIZE_32),
    /// which is the smallest descriptor the format has: every field this reads lies
    /// within those 32 bytes. [`ParseError::TooShort`] if `buf` is smaller than
    /// `desc_size`.
    pub fn read_from(buf: &[u8], desc_size: usize) -> Result<Self, ParseError> {
        Self::check_desc_size(desc_size)?;
        if buf.len() < desc_size {
            return Err(ParseError::TooShort {
                structure: "GroupDescriptor",
                need: desc_size,
                got: buf.len(),
            });
        }
        let (bb_hi, ib_hi, it_hi, fb_hi, fi_hi, ud_hi, iu_hi, bbc_hi, ibc_hi) =
            if desc_size >= Self::SIZE_64 {
                (
                    get_u32(buf, 0x20),
                    get_u32(buf, 0x24),
                    get_u32(buf, 0x28),
                    get_u16(buf, 0x2c),
                    get_u16(buf, 0x2e),
                    get_u16(buf, 0x30),
                    get_u16(buf, 0x32),
                    get_u16(buf, 0x38),
                    get_u16(buf, 0x3a),
                )
            } else {
                (0, 0, 0, 0, 0, 0, 0, 0, 0)
            };
        Ok(Self {
            block_bitmap: join64(get_u32(buf, 0x00), bb_hi),
            inode_bitmap: join64(get_u32(buf, 0x04), ib_hi),
            inode_table: join64(get_u32(buf, 0x08), it_hi),
            free_blocks_count: u32::from(get_u16(buf, 0x0c)) | (u32::from(fb_hi) << 16),
            free_inodes_count: u32::from(get_u16(buf, 0x0e)) | (u32::from(fi_hi) << 16),
            used_dirs_count: u32::from(get_u16(buf, 0x10)) | (u32::from(ud_hi) << 16),
            flags: get_u16(buf, 0x12),
            itable_unused: u32::from(get_u16(buf, 0x1c)) | (u32::from(iu_hi) << 16),
            checksum: get_u16(buf, 0x1e),
            block_bitmap_csum: u32::from(get_u16(buf, 0x18)) | (u32::from(bbc_hi) << 16),
            inode_bitmap_csum: u32::from(get_u16(buf, 0x1a)) | (u32::from(ibc_hi) << 16),
        })
    }

    /// Reject a `desc_size` the structure cannot occupy.
    ///
    /// `desc_size` is a width the caller chooses, and the two directions above address
    /// every field within the first 32 bytes unconditionally — so a smaller size is not a
    /// shorter descriptor, it is a value the format has no form for. Checking it against
    /// the structure's own minimum is what separates that from `buf` merely being too
    /// small to hold the size asked for, which [`ParseError::TooShort`] reports.
    fn check_desc_size(desc_size: usize) -> Result<(), ParseError> {
        if desc_size < Self::SIZE_32 {
            return Err(ParseError::InvalidField {
                structure: "GroupDescriptor",
                field: "s_desc_size",
                value: desc_size as u64,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GroupDescriptor {
        GroupDescriptor {
            block_bitmap: 5,
            inode_bitmap: 9,
            inode_table: 13,
            free_blocks_count: 30701,
            free_inodes_count: 8181,
            used_dirs_count: 2,
            flags: BG_INODE_ZEROED,
            itable_unused: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        }
    }

    #[test]
    fn round_trips_64_byte_form() {
        let d = sample();
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        d.write_to(&mut buf, GroupDescriptor::SIZE_64).unwrap();
        assert_eq!(
            GroupDescriptor::read_from(&buf, GroupDescriptor::SIZE_64).unwrap(),
            d
        );
    }

    #[test]
    fn matches_ground_truth_group0_bytes() {
        // Group 0 of the 512 MiB mke2fs baseline (dumped): block_bitmap 5,
        // inode_bitmap 9, inode_table 13, free_blocks 30701, free_inodes 8181,
        // used_dirs 2, flags 0x0004.
        let d = sample();
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        d.write_to(&mut buf, GroupDescriptor::SIZE_64).unwrap();
        assert_eq!(&buf[0x00..0x04], &5u32.to_le_bytes());
        assert_eq!(&buf[0x04..0x08], &9u32.to_le_bytes());
        assert_eq!(&buf[0x08..0x0c], &13u32.to_le_bytes());
        assert_eq!(get_u16(&buf, 0x0c), 30701);
        assert_eq!(get_u16(&buf, 0x0e), 8181);
        assert_eq!(get_u16(&buf, 0x10), 2);
        assert_eq!(get_u16(&buf, 0x12), 0x0004);
    }

    #[test]
    fn round_trips_high_halves() {
        let d = GroupDescriptor {
            block_bitmap: 0x1_0000_0005,
            inode_bitmap: 0x2_0000_0009,
            inode_table: 0x3_0000_000d,
            free_blocks_count: 0x1_2345,
            free_inodes_count: 0x2_3456,
            used_dirs_count: 0x0003,
            flags: BG_INODE_ZEROED,
            itable_unused: 0x1_0000,
            checksum: 0xabcd,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        d.write_to(&mut buf, GroupDescriptor::SIZE_64).unwrap();
        assert_eq!(
            GroupDescriptor::read_from(&buf, GroupDescriptor::SIZE_64).unwrap(),
            d
        );
    }

    #[test]
    fn thirty_two_byte_form_drops_high_halves() {
        // In the 32-byte form only the low halves exist; reading back yields the
        // low-half values with high halves zero.
        let d = sample();
        let mut buf = [0u8; GroupDescriptor::SIZE_32];
        d.write_to(&mut buf, GroupDescriptor::SIZE_32).unwrap();
        let back = GroupDescriptor::read_from(&buf, GroupDescriptor::SIZE_32).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn rejects_short_buffer() {
        let d = sample();
        let mut buf = [0u8; 16];
        assert!(matches!(
            d.write_to(&mut buf, GroupDescriptor::SIZE_64),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn rejects_a_descriptor_size_below_the_smallest_form() {
        // The width is the caller's to choose, and both directions address every field in
        // the first 32 bytes. A smaller size names no descriptor the format has, so it is
        // refused as the field it is rather than reaching an offset past the buffer.
        let d = sample();
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        for desc_size in [0, 1, 16, GroupDescriptor::SIZE_32 - 1] {
            assert!(
                matches!(
                    d.write_to(&mut buf, desc_size),
                    Err(ParseError::InvalidField {
                        structure: "GroupDescriptor",
                        field: "s_desc_size",
                        ..
                    })
                ),
                "write_to accepted desc_size {desc_size}"
            );
            assert!(
                matches!(
                    GroupDescriptor::read_from(&buf, desc_size),
                    Err(ParseError::InvalidField {
                        structure: "GroupDescriptor",
                        field: "s_desc_size",
                        ..
                    })
                ),
                "read_from accepted desc_size {desc_size}"
            );
        }
        // The size is checked before the buffer, so a short buffer at a refused size is
        // still reported as the size being wrong — that is the fault a caller can fix.
        assert!(matches!(
            GroupDescriptor::read_from(&[0u8; 16], 16),
            Err(ParseError::InvalidField { .. })
        ));
    }

    #[test]
    fn round_trips_a_width_between_the_two_forms() {
        // A size at or above the minimum but below the 64-byte form writes and reads the
        // 32-byte one: the high halves are absent, so they round-trip as zero.
        let d = sample();
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        for desc_size in [GroupDescriptor::SIZE_32, 40, GroupDescriptor::SIZE_64 - 1] {
            d.write_to(&mut buf, desc_size)
                .expect("a serializable width");
            assert_eq!(
                GroupDescriptor::read_from(&buf, desc_size).expect("read back"),
                d,
                "desc_size {desc_size}"
            );
        }
    }
}
