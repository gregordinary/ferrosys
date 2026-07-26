//! The hash-index blocks of a directory: the root, its interior nodes, and their
//! entries and checksum tail.
//!
//! A hash-indexed directory keeps its names in ordinary directory blocks and adds a
//! search tree over them. The tree's root is the directory's first block: it opens
//! with the `"."` and `".."` entries a directory must have, whose record lengths
//! cover the index that follows, so a reader that knows nothing of the index walks
//! the directory correctly and simply finds no names there. An interior node opens
//! with a single unused entry spanning its whole block, for the same reason.
//!
//! After that header come the index entries, each a hash and the logical block of
//! the child it names. The first entry is special: the bytes that would hold its
//! hash instead hold the entry count and the capacity, because the first child's
//! hash is implied by the parent. Under `metadata_csum` the capacity is one short of
//! what the block holds, and the entry slot that frees up carries the checksum tail.
//!
//! The low bit of an entry's hash marks a hash whose names continue from the
//! previous block, so a lookup that lands on it looks back one block. The hashes
//! themselves always have that bit clear.

use super::{ParseError, get_u16, get_u32, put_u8, put_u16, put_u32};

/// On-disk size of one index entry (`struct ext4_dx_entry`): a hash and a block.
pub const DX_ENTRY_LEN: usize = 8;

/// On-disk size of the index checksum tail (`struct ext4_dx_tail`).
pub const DX_TAIL_LEN: usize = 8;

/// Byte offset of `dt_checksum` within the index checksum tail, past the
/// `dt_reserved` word that opens it. The checksum covers the tail up to this offset
/// and then four zero bytes in place of the field itself.
pub const DX_CHECKSUM_OFFSET: usize = 4;

/// Byte offset of the entry count within a root block: past `"."`, `".."`, and the
/// eight-byte root info.
pub const DX_ROOT_COUNT_OFFSET: usize = 32;

/// Byte offset of the entry count within an interior node: past its one unused entry.
pub const DX_NODE_COUNT_OFFSET: usize = 8;

/// The bit an index entry's hash carries when its names continue from the previous
/// block.
pub const DX_HASH_CONTINUED: u32 = 1;

/// The deepest index this crate builds, counted in levels below the root. A
/// directory without the `largedir` feature is limited to a hash tree of at most
/// one interior level — two levels including the root — so the reader follows at
/// most one level of indirection.
pub const DX_MAX_INDIRECT_LEVELS: u8 = 1;

/// One index entry: the lowest hash found in the child it names, and that child's
/// logical block within the directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DxEntry {
    /// Lowest hash in the child, with [`DX_HASH_CONTINUED`] set when the child's
    /// first name shares a hash with the previous child's last. The first entry of a
    /// node has no stored hash and reads back as zero.
    pub hash: u32,
    /// The child's logical block within the directory file.
    pub block: u32,
}

/// Index entries a block holds, given where its count begins. Under `metadata_csum`
/// one slot is given up to the checksum tail.
///
/// Both sizes are the caller's, and a block whose count begins past its own end — or
/// whose only slot is the one the tail claims — holds no entries: the answer is zero
/// rather than a count that would index outside the block.
#[must_use]
pub const fn dx_limit(block_size: usize, count_offset: usize, checksums: bool) -> usize {
    let slots = block_size.saturating_sub(count_offset) / DX_ENTRY_LEN;
    if checksums {
        slots.saturating_sub(1)
    } else {
        slots
    }
}

/// Byte offset of the checksum tail: immediately past the last entry slot the block
/// declares room for.
#[must_use]
pub const fn dx_tail_offset(count_offset: usize, limit: usize) -> usize {
    count_offset + DX_ENTRY_LEN * limit
}

/// Write a root block's header: the `"."` and `".."` entries whose record lengths
/// hide the index, and the root info naming the hash algorithm and the depth.
///
/// `buf.len()` is the directory block size, at most 4096, so a record length that
/// spans the block fits the sixteen-bit `rec_len` field directly — the 64 KiB block
/// convention that stores a full-block length as `0xFFFF` is not needed here.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` is smaller than the root header these fields
/// occupy.
pub fn write_dx_root_header(
    buf: &mut [u8],
    dir_ino: u32,
    parent_ino: u32,
    hash_version: u8,
    indirect_levels: u8,
) -> Result<(), ParseError> {
    if buf.len() < DX_ROOT_COUNT_OFFSET {
        return Err(ParseError::TooShort {
            structure: "DxRoot",
            need: DX_ROOT_COUNT_OFFSET,
            got: buf.len(),
        });
    }
    let block_size = buf.len();

    // "." — a twelve-byte record.
    put_u32(buf, 0, dir_ino);
    put_u16(buf, 4, 12);
    put_u8(buf, 6, 1);
    put_u8(buf, 7, super::FileType::Dir.to_u8());
    buf[8] = b'.';

    // ".." — its record covers the whole index that follows it.
    put_u32(buf, 12, parent_ino);
    put_u16(buf, 16, (block_size - 12) as u16);
    put_u8(buf, 18, 2);
    put_u8(buf, 19, super::FileType::Dir.to_u8());
    buf[20] = b'.';
    buf[21] = b'.';

    // struct ext4_dx_root_info.
    put_u32(buf, 24, 0); // reserved_zero
    put_u8(buf, 28, hash_version);
    put_u8(buf, 29, 8); // info_length
    put_u8(buf, 30, indirect_levels);
    put_u8(buf, 31, 0); // unused_flags
    Ok(())
}

/// Write an interior node's header: one unused entry spanning the block, so a
/// reader walking the directory linearly steps over the index it introduces.
///
/// `buf.len()` is the block size, at most 4096, so the spanning record length fits the
/// sixteen-bit `rec_len` field without the 64 KiB `0xFFFF` convention.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` is smaller than the node header.
pub fn write_dx_node_header(buf: &mut [u8]) -> Result<(), ParseError> {
    if buf.len() < DX_NODE_COUNT_OFFSET {
        return Err(ParseError::TooShort {
            structure: "DxNode",
            need: DX_NODE_COUNT_OFFSET,
            got: buf.len(),
        });
    }
    let block_size = buf.len();
    put_u32(buf, 0, 0); // inode 0 — an unused slot
    put_u16(buf, 4, block_size as u16); // rec_len spans the block
    put_u8(buf, 6, 0); // name_len
    put_u8(buf, 7, 0); // file_type
    Ok(())
}

/// Write `entries` into the index area beginning at `count_offset`, declaring room
/// for `limit`. The first entry's hash is not stored: those bytes carry the count
/// and the limit, so it must be zero.
///
/// # Errors
///
/// [`ParseError::InvalidField`] if there are no entries, more than `limit` of them,
/// or the first carries a hash; [`ParseError::TooShort`] if `buf` cannot hold the
/// declared limit.
pub fn write_dx_entries(
    buf: &mut [u8],
    count_offset: usize,
    limit: usize,
    entries: &[DxEntry],
) -> Result<(), ParseError> {
    if entries.is_empty() || entries.len() > limit {
        return Err(ParseError::InvalidField {
            structure: "DxEntries",
            field: "count",
            value: entries.len() as u64,
        });
    }
    if entries[0].hash != 0 {
        return Err(ParseError::InvalidField {
            structure: "DxEntries",
            field: "hash",
            value: u64::from(entries[0].hash),
        });
    }
    if buf.len() < dx_tail_offset(count_offset, limit) {
        return Err(ParseError::TooShort {
            structure: "DxEntries",
            need: dx_tail_offset(count_offset, limit),
            got: buf.len(),
        });
    }

    put_u16(buf, count_offset, limit as u16);
    put_u16(buf, count_offset + 2, entries.len() as u16);
    put_u32(buf, count_offset + 4, entries[0].block);
    for (i, entry) in entries.iter().enumerate().skip(1) {
        let off = count_offset + DX_ENTRY_LEN * i;
        put_u32(buf, off, entry.hash);
        put_u32(buf, off + 4, entry.block);
    }
    Ok(())
}

/// Write the index checksum tail. `checksum` is zero while `metadata_csum` is off,
/// in which case the block declares no tail and this is not called.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` cannot hold the tail at its offset.
pub fn write_dx_tail(
    buf: &mut [u8],
    count_offset: usize,
    limit: usize,
    checksum: u32,
) -> Result<(), ParseError> {
    let off = dx_tail_offset(count_offset, limit);
    if buf.len() < off + DX_TAIL_LEN {
        return Err(ParseError::TooShort {
            structure: "DxTail",
            need: off + DX_TAIL_LEN,
            got: buf.len(),
        });
    }
    put_u32(buf, off, 0); // dt_reserved
    put_u32(buf, off + DX_CHECKSUM_OFFSET, checksum);
    Ok(())
}

/// Read the entry count and capacity an index block declares.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` does not reach the count;
/// [`ParseError::InvalidField`] if the count exceeds the capacity.
pub fn read_dx_countlimit(buf: &[u8], count_offset: usize) -> Result<(u16, u16), ParseError> {
    if buf.len() < count_offset + 4 {
        return Err(ParseError::TooShort {
            structure: "DxCountLimit",
            need: count_offset + 4,
            got: buf.len(),
        });
    }
    let limit = get_u16(buf, count_offset);
    let count = get_u16(buf, count_offset + 2);
    if count > limit || count == 0 {
        return Err(ParseError::InvalidField {
            structure: "DxCountLimit",
            field: "count",
            value: u64::from(count),
        });
    }
    Ok((limit, count))
}

/// Read an index block's entries. The first entry's hash is not stored and reads
/// back as zero.
///
/// # Errors
///
/// The errors of [`read_dx_countlimit`], or [`ParseError::TooShort`] if the entries
/// overrun `buf`.
pub fn read_dx_entries(buf: &[u8], count_offset: usize) -> Result<Vec<DxEntry>, ParseError> {
    let (_, count) = read_dx_countlimit(buf, count_offset)?;
    let need = count_offset + DX_ENTRY_LEN * count as usize;
    if buf.len() < need {
        return Err(ParseError::TooShort {
            structure: "DxEntries",
            need,
            got: buf.len(),
        });
    }
    let mut out = Vec::with_capacity(count as usize);
    out.push(DxEntry {
        hash: 0,
        block: get_u32(buf, count_offset + 4),
    });
    for i in 1..count as usize {
        let off = count_offset + DX_ENTRY_LEN * i;
        out.push(DxEntry {
            hash: get_u32(buf, off),
            block: get_u32(buf, off + 4),
        });
    }
    Ok(out)
}

/// The hash algorithm and depth an index root declares.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` does not reach the root info.
pub fn read_dx_root_info(buf: &[u8]) -> Result<(u8, u8), ParseError> {
    if buf.len() < DX_ROOT_COUNT_OFFSET {
        return Err(ParseError::TooShort {
            structure: "DxRootInfo",
            need: DX_ROOT_COUNT_OFFSET,
            got: buf.len(),
        });
    }
    Ok((buf[28], buf[30]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: usize = 4096;

    #[test]
    fn a_root_reserves_five_hundred_and_seven_entries_under_checksums() {
        // 4064 bytes of index area hold 508 slots; the checksum tail takes one.
        assert_eq!(dx_limit(BS, DX_ROOT_COUNT_OFFSET, false), 508);
        assert_eq!(dx_limit(BS, DX_ROOT_COUNT_OFFSET, true), 507);
        assert_eq!(dx_tail_offset(DX_ROOT_COUNT_OFFSET, 507), 4088);
        assert_eq!(dx_tail_offset(DX_ROOT_COUNT_OFFSET, 507) + DX_TAIL_LEN, BS);
    }

    #[test]
    fn a_node_reserves_five_hundred_and_ten_entries_under_checksums() {
        assert_eq!(dx_limit(BS, DX_NODE_COUNT_OFFSET, false), 511);
        assert_eq!(dx_limit(BS, DX_NODE_COUNT_OFFSET, true), 510);
        assert_eq!(dx_tail_offset(DX_NODE_COUNT_OFFSET, 510), 4088);
    }

    #[test]
    fn a_block_with_no_room_for_an_entry_holds_none() {
        // Both sizes are the caller's. A count that begins at or past the block's end
        // leaves nothing to divide, and a block whose one slot is the tail's leaves
        // nothing to index — each answers zero, so nothing derived from the count
        // reaches outside the block.
        assert_eq!(dx_limit(32, 32, false), 0);
        assert_eq!(dx_limit(32, 64, false), 0);
        assert_eq!(dx_limit(0, DX_ROOT_COUNT_OFFSET, true), 0);
        // Exactly one slot: none of it survives the tail.
        assert_eq!(dx_limit(DX_ENTRY_LEN + 8, 8, false), 1);
        assert_eq!(dx_limit(DX_ENTRY_LEN + 8, 8, true), 0);
    }

    /// The exact bytes e2fsprogs writes for a three-child root over inode 12 whose
    /// parent is the root directory, taken from an `e2fsck -fD` rebuilt directory.
    #[test]
    fn a_root_block_matches_e2fsprogs_byte_for_byte() {
        let entries = [
            DxEntry { hash: 0, block: 1 },
            DxEntry {
                hash: 0x5c92_21be,
                block: 2,
            },
            DxEntry {
                hash: 0xac20_57fe,
                block: 3,
            },
        ];
        let mut buf = vec![0u8; BS];
        write_dx_root_header(&mut buf, 12, 2, 1, 0).unwrap();
        write_dx_entries(&mut buf, DX_ROOT_COUNT_OFFSET, 507, &entries).unwrap();
        write_dx_tail(&mut buf, DX_ROOT_COUNT_OFFSET, 507, 0xa42b_897b).unwrap();

        #[rustfmt::skip]
        let expect_head: [u8; 56] = [
            // "." : inode 12, rec_len 12, name_len 1, type dir
            0x0c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x02, b'.', 0x00, 0x00, 0x00,
            // ".." : inode 2, rec_len 4084, name_len 2, type dir
            0x02, 0x00, 0x00, 0x00, 0xf4, 0x0f, 0x02, 0x02, b'.', b'.', 0x00, 0x00,
            // root info: reserved_zero, hash_version 1, info_length 8, levels 0, flags 0
            0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00,
            // limit 507, count 3, first child block 1
            0xfb, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
            // hash 0x5c9221be -> block 2
            0xbe, 0x21, 0x92, 0x5c, 0x02, 0x00, 0x00, 0x00,
            // hash 0xac2057fe -> block 3
            0xfe, 0x57, 0x20, 0xac, 0x03, 0x00, 0x00, 0x00,
        ];
        assert_eq!(&buf[..56], &expect_head[..]);
        // The tail closes the block: four reserved bytes, then the checksum.
        assert_eq!(&buf[4088..4092], &[0, 0, 0, 0]);
        assert_eq!(&buf[4092..], &0xa42b_897bu32.to_le_bytes()[..]);
        // Everything between the last entry and the tail is untouched.
        assert!(buf[56..4088].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_root_block_reads_back_as_a_dot_entry_hiding_the_index() {
        use super::super::DirEntry;
        let entries = [DxEntry { hash: 0, block: 1 }, DxEntry { hash: 8, block: 2 }];
        let mut buf = vec![0u8; BS];
        write_dx_root_header(&mut buf, 12, 2, 1, 0).unwrap();
        write_dx_entries(&mut buf, DX_ROOT_COUNT_OFFSET, 507, &entries).unwrap();

        // A reader that knows nothing of the index sees "." and "..", and "..'s"
        // record carries it past the entire index to the end of the block.
        let (dot, dot_len) = DirEntry::read_from(&buf, 4096).unwrap();
        assert_eq!(dot.name, b".");
        assert_eq!(dot_len, 12);
        let (dotdot, dotdot_len) = DirEntry::read_from(&buf[12..], 4096).unwrap();
        assert_eq!(dotdot.name, b"..");
        assert_eq!(dotdot.inode, 2);
        assert_eq!(12 + dotdot_len, BS, "the index is not walked");
    }

    #[test]
    fn a_node_block_reads_back_as_one_unused_slot() {
        use super::super::DirEntry;
        let mut buf = vec![0u8; BS];
        write_dx_node_header(&mut buf).unwrap();
        write_dx_entries(
            &mut buf,
            DX_NODE_COUNT_OFFSET,
            510,
            &[DxEntry { hash: 0, block: 5 }],
        )
        .unwrap();
        let (entry, rec_len) = DirEntry::read_from(&buf, 4096).unwrap();
        assert_eq!(entry.inode, 0, "an unused slot a linear walk skips");
        assert_eq!(rec_len, BS);
    }

    #[test]
    fn entries_round_trip_with_the_first_hash_implied() {
        let entries = vec![
            DxEntry { hash: 0, block: 1 },
            DxEntry {
                hash: 0xdead_be00,
                block: 7,
            },
        ];
        let mut buf = vec![0u8; BS];
        write_dx_entries(&mut buf, DX_ROOT_COUNT_OFFSET, 507, &entries).unwrap();
        assert_eq!(
            read_dx_countlimit(&buf, DX_ROOT_COUNT_OFFSET).unwrap(),
            (507, 2)
        );
        assert_eq!(
            read_dx_entries(&buf, DX_ROOT_COUNT_OFFSET).unwrap(),
            entries
        );
    }

    #[test]
    fn the_root_info_reads_back() {
        let mut buf = vec![0u8; BS];
        write_dx_root_header(&mut buf, 12, 2, 2, 1).unwrap();
        assert_eq!(read_dx_root_info(&buf).unwrap(), (2, 1));
    }

    #[test]
    fn a_stored_hash_on_the_first_entry_is_rejected() {
        let mut buf = vec![0u8; BS];
        assert!(matches!(
            write_dx_entries(
                &mut buf,
                DX_ROOT_COUNT_OFFSET,
                507,
                &[DxEntry { hash: 4, block: 1 }]
            ),
            Err(ParseError::InvalidField { field: "hash", .. })
        ));
    }

    #[test]
    fn more_entries_than_the_limit_are_rejected() {
        let mut buf = vec![0u8; BS];
        let entries: Vec<DxEntry> = (0..3)
            .map(|i| DxEntry {
                hash: if i == 0 { 0 } else { i * 8 },
                block: i + 1,
            })
            .collect();
        assert!(matches!(
            write_dx_entries(&mut buf, DX_ROOT_COUNT_OFFSET, 2, &entries),
            Err(ParseError::InvalidField { field: "count", .. })
        ));
    }
}
