//! Directory entries (`struct ext4_dir_entry_2`) and the checksum-tail slot.
//!
//! A linear directory block is a sequence of variable-length entries. Each entry
//! is an inode number, a record length that spans the entry and any slack before
//! the next one, a name length, a file-type byte (the `filetype` feature), and the
//! name. The entries tile the block exactly: each `rec_len` is a multiple of four
//! and the final entry's `rec_len` reaches the end of the usable area.
//!
//! Under `metadata_csum`, the last twelve bytes of a directory block are a tail
//! slot rather than an entry: a zero-inode fake entry that spans the slot and
//! carries the block's crc32c. Without `metadata_csum` there is no tail — the kernel
//! tiles real entries across the whole block, so a final entry can begin in those
//! last twelve bytes. A walk that reads to the end of the block and skips every
//! zero-inode slot is correct either way: with a checksum the tail is such a slot
//! and is skipped; without one there is a real entry to read there instead.

use super::{ParseError, get_u8, get_u16, get_u32, put_u8, put_u16, put_u32};

/// Bytes occupied by the directory checksum tail (`struct ext4_dir_entry_tail`).
pub const DIR_TAIL_LEN: usize = 12;

/// The file-type byte marking the checksum tail's fake dirent (`det_reserved_ft`):
/// `0xDE`, a value outside the valid file-type range so the tail is never mistaken
/// for a real entry.
const DIR_TAIL_FT: u8 = 0xde;

/// Minimum bytes an entry with a name of `name_len` bytes occupies: the 8-byte
/// header plus the name, rounded up to a four-byte boundary. A directory name is at
/// most 255 bytes (`e_name_len` is one byte wide), so the result fits a `u16`; an
/// out-of-range length saturates rather than truncating to a smaller wrong value.
#[must_use]
pub fn min_rec_len(name_len: usize) -> u16 {
    debug_assert!(name_len <= 255, "a directory name is at most 255 bytes");
    (8 + name_len).next_multiple_of(4).min(u16::MAX as usize) as u16
}

/// Decode an on-disk `rec_len` for a directory block of `block_size` bytes
/// (`ext4_rec_len_from_disk`).
///
/// Below 65536 bytes the field is the record length verbatim. At 65536 a record spanning
/// the whole block is 65536 bytes, which does not fit the 16-bit field, so ext4 stores the
/// sentinel `0xFFFF` (or `0`) for it and packs a length's two high bits into the field's
/// low two bits for every other length. The decode is total: every value maps to a length
/// that is a multiple of four, so a 64 KiB block never trips the multiple-of-four check.
#[must_use]
pub fn rec_len_from_disk(disk: u16, block_size: usize) -> usize {
    if block_size < 65536 {
        return disk as usize;
    }
    if disk == 0xffff || disk == 0 {
        return block_size;
    }
    (disk as usize & 0xfffc) | ((disk as usize & 3) << 16)
}

/// Encode a record length for a directory block of `block_size` bytes
/// (`ext4_rec_len_to_disk`), the inverse of [`rec_len_from_disk`].
///
/// Below 65536 bytes the length is the field verbatim. At 65536 a record spanning the
/// whole block is 65536 bytes, which does not fit the 16-bit field, so it is stored as
/// the sentinel `0xFFFF` — the value [`rec_len_from_disk`] maps back to a full block.
/// Every shorter record is a multiple of four below 65536 and so encodes, and reads
/// back, unchanged. A block size never exceeds 65536, so a record never does either,
/// and no length reaches the high-bit packing that decode inverts on foreign input.
///
/// Pairing this with [`rec_len_from_disk`] keeps [`DirEntry::write_to`] and
/// [`DirEntry::read_from`] a true inverse at every block size the format allows, so the
/// serialization stays symmetric independently of the block-size ceiling the writer
/// currently enforces elsewhere.
#[must_use]
pub fn rec_len_to_disk(len: usize, block_size: usize) -> u16 {
    if block_size < 65536 || len < 65536 {
        return len as u16;
    }
    0xffff
}

/// The type of the file a directory entry names, as stored in the entry's
/// file-type byte when the `filetype` feature is set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileType {
    /// Type not known from the directory entry.
    Unknown,
    /// Regular file.
    RegFile,
    /// Directory.
    Dir,
    /// Character device.
    CharDev,
    /// Block device.
    BlockDev,
    /// Named pipe (FIFO).
    Fifo,
    /// Unix-domain socket.
    Socket,
    /// Symbolic link.
    Symlink,
}

impl FileType {
    /// The on-disk file-type byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            FileType::Unknown => 0,
            FileType::RegFile => 1,
            FileType::Dir => 2,
            FileType::CharDev => 3,
            FileType::BlockDev => 4,
            FileType::Fifo => 5,
            FileType::Socket => 6,
            FileType::Symlink => 7,
        }
    }

    /// Interpret an on-disk file-type byte; unrecognized values map to
    /// [`FileType::Unknown`].
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => FileType::RegFile,
            2 => FileType::Dir,
            3 => FileType::CharDev,
            4 => FileType::BlockDev,
            5 => FileType::Fifo,
            6 => FileType::Socket,
            7 => FileType::Symlink,
            _ => FileType::Unknown,
        }
    }

    /// The file type implied by an inode mode's `S_IFMT` bits.
    #[must_use]
    pub const fn from_mode(mode: u16) -> Self {
        match mode & 0o170000 {
            0o100000 => FileType::RegFile,
            0o040000 => FileType::Dir,
            0o020000 => FileType::CharDev,
            0o060000 => FileType::BlockDev,
            0o010000 => FileType::Fifo,
            0o140000 => FileType::Socket,
            0o120000 => FileType::Symlink,
            _ => FileType::Unknown,
        }
    }
}

/// One directory entry: the inode it names, its file type, and its name.
///
/// The record length is not stored here because it is a property of the entry's
/// placement in a block, not of the entry itself; [`write_to`](DirEntry::write_to)
/// takes it and [`read_from`](DirEntry::read_from) returns it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// Inode the entry points at; zero marks an unused slot.
    pub inode: u32,
    /// File type of the named inode.
    pub file_type: FileType,
    /// Entry name (not NUL-terminated); at most 255 bytes.
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Serialize this entry into the first bytes of `buf`, claiming a record of
    /// `rec_len` bytes in a directory block of `block_size` bytes. The name must be at
    /// most 255 bytes and `rec_len` a multiple of four large enough for the header and
    /// name. The stored length is encoded through [`rec_len_to_disk`], so it round-trips
    /// through the [`read_from`](Self::read_from) decode at every block size — the full-
    /// block record of a 65536-byte block included.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidField`] if the name exceeds 255 bytes or `rec_len` is
    /// too small or not a multiple of four; [`ParseError::TooShort`] if `buf`
    /// cannot hold `rec_len` bytes.
    pub fn write_to(
        &self,
        buf: &mut [u8],
        rec_len: usize,
        block_size: usize,
    ) -> Result<(), ParseError> {
        if self.name.len() > 255 {
            return Err(ParseError::InvalidField {
                structure: "DirEntry",
                field: "name_len",
                value: self.name.len() as u64,
            });
        }
        if rec_len < min_rec_len(self.name.len()) as usize || !rec_len.is_multiple_of(4) {
            return Err(ParseError::InvalidField {
                structure: "DirEntry",
                field: "rec_len",
                value: rec_len as u64,
            });
        }
        if buf.len() < rec_len {
            return Err(ParseError::TooShort {
                structure: "DirEntry",
                need: rec_len,
                got: buf.len(),
            });
        }
        put_u32(buf, 0, self.inode);
        put_u16(buf, 4, rec_len_to_disk(rec_len, block_size));
        put_u8(buf, 6, self.name.len() as u8);
        put_u8(buf, 7, self.file_type.to_u8());
        buf[8..8 + self.name.len()].copy_from_slice(&self.name);
        Ok(())
    }

    /// Parse the entry at the start of `buf`, returning the entry and its decoded
    /// `rec_len` so a caller can advance to the next. `block_size` selects the `rec_len`
    /// decoding: a 65536-byte block packs a full-block record's length specially (see
    /// [`rec_len_from_disk`]), so the returned length is a `usize` that reaches 65536.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] if `buf` is shorter than the header or the entry's
    /// `rec_len`; [`ParseError::InvalidField`] if `rec_len` is not a multiple of
    /// four or is too small for the name.
    pub fn read_from(buf: &[u8], block_size: usize) -> Result<(Self, usize), ParseError> {
        if buf.len() < 8 {
            return Err(ParseError::TooShort {
                structure: "DirEntry",
                need: 8,
                got: buf.len(),
            });
        }
        let inode = get_u32(buf, 0);
        let rec_len = rec_len_from_disk(get_u16(buf, 4), block_size);
        let name_len = get_u8(buf, 6) as usize;
        let file_type = FileType::from_u8(get_u8(buf, 7));
        if !rec_len.is_multiple_of(4) || rec_len < 8 + name_len {
            return Err(ParseError::InvalidField {
                structure: "DirEntry",
                field: "rec_len",
                value: rec_len as u64,
            });
        }
        if buf.len() < rec_len {
            return Err(ParseError::TooShort {
                structure: "DirEntry",
                need: rec_len,
                got: buf.len(),
            });
        }
        Ok((
            Self {
                inode,
                file_type,
                name: buf[8..8 + name_len].to_vec(),
            },
            rec_len,
        ))
    }
}

/// Write the twelve-byte checksum tail into the first [`DIR_TAIL_LEN`] bytes of
/// `buf`: a zero-inode fake dirent whose file-type marker is `0xDE` (a value
/// outside the valid file-type range) and whose crc32c field holds `checksum`
/// (zero while `metadata_csum` is off).
///
/// # Errors
///
/// [`ParseError::TooShort`] if `buf` cannot hold the tail.
pub fn write_dir_tail(buf: &mut [u8], checksum: u32) -> Result<(), ParseError> {
    if buf.len() < DIR_TAIL_LEN {
        return Err(ParseError::TooShort {
            structure: "DirEntryTail",
            need: DIR_TAIL_LEN,
            got: buf.len(),
        });
    }
    put_u32(buf, 0, 0); // det_reserved_zero1 — reads as inode 0 (unused slot).
    put_u16(buf, 4, DIR_TAIL_LEN as u16); // det_rec_len.
    put_u8(buf, 6, 0); // det_reserved_zero2 — name_len 0.
    put_u8(buf, 7, DIR_TAIL_FT); // det_reserved_ft — the 0xDE marker.
    put_u32(buf, 8, checksum); // det_checksum.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_rec_len_rounds_up_to_four() {
        assert_eq!(min_rec_len(1), 12); // 8 + 1 -> 9 -> 12
        assert_eq!(min_rec_len(2), 12); // "." (via ".." usually) -> 12
        assert_eq!(min_rec_len(4), 12); // 8 + 4 = 12
        assert_eq!(min_rec_len(5), 16); // 8 + 5 -> 13 -> 16
        assert_eq!(min_rec_len(255), 264);
    }

    #[test]
    fn entry_round_trips() {
        let e = DirEntry {
            inode: 11,
            file_type: FileType::Dir,
            name: b"lost+found".to_vec(),
        };
        let mut buf = [0u8; 32];
        e.write_to(&mut buf, 20, 4096).unwrap();
        let (back, rec_len) = DirEntry::read_from(&buf, 4096).unwrap();
        assert_eq!(back, e);
        assert_eq!(rec_len, 20);
    }

    #[test]
    fn dot_entries_round_trip() {
        for (name, ino) in [(b"." as &[u8], 2u32), (b".." as &[u8], 2u32)] {
            let e = DirEntry {
                inode: ino,
                file_type: FileType::Dir,
                name: name.to_vec(),
            };
            let mut buf = [0u8; 12];
            e.write_to(&mut buf, 12, 4096).unwrap();
            let (back, rec_len) = DirEntry::read_from(&buf, 4096).unwrap();
            assert_eq!(back, e);
            assert_eq!(rec_len, 12);
        }
    }

    #[test]
    fn oversize_name_and_bad_rec_len_are_rejected() {
        let e = DirEntry {
            inode: 1,
            file_type: FileType::RegFile,
            name: vec![b'a'; 300],
        };
        let mut buf = [0u8; 512];
        assert!(matches!(
            e.write_to(&mut buf, 320, 4096),
            Err(ParseError::InvalidField {
                field: "name_len",
                ..
            })
        ));

        let e = DirEntry {
            inode: 1,
            file_type: FileType::RegFile,
            name: b"abc".to_vec(),
        };
        assert!(matches!(
            e.write_to(&mut buf, 10, 4096),
            Err(ParseError::InvalidField {
                field: "rec_len",
                ..
            })
        ));
    }

    #[test]
    fn tail_is_a_zero_inode_slot_with_the_marker() {
        let mut buf = [0xffu8; DIR_TAIL_LEN];
        write_dir_tail(&mut buf, 0).unwrap();
        assert_eq!(get_u32(&buf, 0), 0, "reads as an unused slot");
        assert_eq!(get_u16(&buf, 4), DIR_TAIL_LEN as u16);
        assert_eq!(get_u8(&buf, 6), 0);
        assert_eq!(get_u8(&buf, 7), DIR_TAIL_FT);
        // Parsing the tail as an entry yields a zero-inode, empty-name slot.
        let (entry, rec_len) = DirEntry::read_from(&buf, 4096).unwrap();
        assert_eq!(entry.inode, 0);
        assert_eq!(rec_len, DIR_TAIL_LEN);
        assert!(entry.name.is_empty());
    }

    #[test]
    fn file_type_from_mode() {
        assert_eq!(FileType::from_mode(0o100644), FileType::RegFile);
        assert_eq!(FileType::from_mode(0o040755), FileType::Dir);
        assert_eq!(FileType::from_mode(0o120777), FileType::Symlink);
        assert_eq!(FileType::from_mode(0o020600), FileType::CharDev);
        assert_eq!(
            FileType::from_u8(FileType::Symlink.to_u8()),
            FileType::Symlink
        );
    }

    #[test]
    fn rec_len_decodes_the_64k_block_encoding() {
        // Below 65536 the field is verbatim.
        assert_eq!(rec_len_from_disk(20, 4096), 20);
        assert_eq!(rec_len_from_disk(0, 4096), 0);
        assert_eq!(rec_len_from_disk(0xffff, 4096), 0xffff);

        // At 65536 a full-block record is the `0xffff` (or `0`) sentinel, and every other
        // length packs its two high bits into the field's low two bits.
        const BS: usize = 65536;
        assert_eq!(
            rec_len_from_disk(0xffff, BS),
            BS,
            "sentinel spans the block"
        );
        assert_eq!(rec_len_from_disk(0, BS), BS, "zero also spans the block");
        assert_eq!(
            rec_len_from_disk(12, BS),
            12,
            "a short record decodes plainly"
        );
        // 65532 = 0xfffc: high bits 0, low 12 bits full -> the largest sub-block length.
        assert_eq!(rec_len_from_disk(0xfffc, BS), 65532);
        // 65540 (> u16) is stored as (65540 & 0xfffc) | ((65540 >> 16) & 3) = 4 | 1 = 5.
        assert_eq!(rec_len_from_disk(5, BS), 65540);
    }

    #[test]
    fn rec_len_encode_is_the_decode_inverse() {
        // Below 65536 every length is verbatim in both directions.
        for &bs in &[1024usize, 2048, 4096] {
            for len in (4..=bs).step_by(4) {
                assert_eq!(rec_len_to_disk(len, bs) as usize, len);
                assert_eq!(rec_len_from_disk(rec_len_to_disk(len, bs), bs), len);
            }
        }
        // At 65536 a full-block record does not fit the field: it stores the sentinel,
        // which decodes back to the block size. Every shorter multiple-of-four record
        // still round-trips unchanged, so a `write_to` at this block size and the
        // matching `read_from` remain a true inverse.
        const BS: usize = 65536;
        assert_eq!(rec_len_to_disk(BS, BS), 0xffff);
        assert_eq!(rec_len_from_disk(rec_len_to_disk(BS, BS), BS), BS);
        for len in [12usize, 4096, 32768, 65532] {
            assert_eq!(rec_len_from_disk(rec_len_to_disk(len, BS), BS), len);
        }
    }

    #[test]
    fn a_full_block_record_in_a_64k_directory_parses() {
        // A foreign 64 KiB directory block with no checksum tail can hold one record that
        // spans the whole block: an empty slot stored as the `0xffff` sentinel. It reads
        // back as a 65536-byte record rather than failing the multiple-of-four check.
        const BS: usize = 65536;
        let mut buf = vec![0u8; BS];
        put_u16(&mut buf, 4, 0xffff); // rec_len sentinel: the record spans the block
        // inode 0, name_len 0: an unused slot.
        let (entry, rec_len) = DirEntry::read_from(&buf, BS).expect("the sentinel decodes");
        assert_eq!(rec_len, BS, "the record spans the whole 64 KiB block");
        assert_eq!(entry.inode, 0);
        assert!(entry.name.is_empty());
    }
}
