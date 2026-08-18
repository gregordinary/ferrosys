//! Where a file's bytes are: the extent record, in the two shapes it takes.
//!
//! An `EXTENT_DATA` item is keyed by `(inode, EXTENT_DATA, the file offset it begins at)`, so
//! a file's extents are a contiguous run of its subvolume's tree in file order and reading a
//! range is one descent.
//!
//! # The two shapes, and the field that is not what it sounds like
//!
//! A **small file lives inside its own record**: the head is 21 bytes and the bytes follow it,
//! so the file costs one item and no data extent at all. A larger one is
//! [`Regular`](ExtentKind::Regular) or [`Prealloc`](ExtentKind::Prealloc), where the head is
//! the full 53 bytes and names a run of logical space.
//!
//! For those, [`offset`](FileExtentItem::offset) is **not** the file offset — the key holds
//! that. It is how far into the extent this record's bytes begin, which is what a write into
//! the middle of a file leaves behind: one extent on disk, referenced by two records that take
//! different parts of it. Reading it as a position in the file works perfectly on every file
//! written once and returns the wrong bytes for every file written twice.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u8, get_u16, get_u64, put_u8, put_u16, put_u64};

use super::ParseError;

/// Which of the two shapes an extent record takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ExtentKind {
    /// The file's bytes are inside the item, behind the head.
    Inline,
    /// The record names a run of logical space holding the file's bytes.
    Regular,
    /// The record names a run of logical space that has been allocated and holds nothing yet,
    /// so the file reads back as zeros there.
    Prealloc,
    /// A value the format has not defined.
    Unknown(u8),
}

impl ExtentKind {
    /// The on-disk byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            ExtentKind::Inline => 0,
            ExtentKind::Regular => 1,
            ExtentKind::Prealloc => 2,
            ExtentKind::Unknown(value) => value,
        }
    }

    /// Interpret an on-disk byte, keeping one the format has not defined.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => ExtentKind::Inline,
            1 => ExtentKind::Regular,
            2 => ExtentKind::Prealloc,
            other => ExtentKind::Unknown(other),
        }
    }

    /// Whether the record's bytes are inside the item rather than out in logical space.
    #[must_use]
    pub const fn is_inline(self) -> bool {
        matches!(self, ExtentKind::Inline)
    }
}

/// How an extent's bytes are encoded on the volume.
///
/// A compressed extent stores [`FileExtentItem::disk_num_bytes`] bytes of compressed data that
/// expand to [`FileExtentItem::ram_bytes`], so the two lengths are what says compression
/// happened at all — the algorithm says which one to undo it with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Compression {
    /// The bytes on the volume are the file's bytes.
    None,
    /// DEFLATE, as `zlib` frames it.
    Zlib,
    /// LZO, in the block format btrfs wraps it in.
    Lzo,
    /// Zstandard.
    Zstd,
    /// A value the format has not defined.
    Unknown(u8),
}

impl Compression {
    /// The on-disk byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Compression::None => 0,
            Compression::Zlib => 1,
            Compression::Lzo => 2,
            Compression::Zstd => 3,
            Compression::Unknown(value) => value,
        }
    }

    /// Interpret an on-disk byte, keeping one the format has not defined.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Compression::None,
            1 => Compression::Zlib,
            2 => Compression::Lzo,
            3 => Compression::Zstd,
            other => Compression::Unknown(other),
        }
    }

    /// The name this algorithm is known by, or [`None`] for a byte the format has not defined.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Compression::None => "none",
            Compression::Zlib => "zlib",
            Compression::Lzo => "lzo",
            Compression::Zstd => "zstd",
            Compression::Unknown(_) => return None,
        })
    }
}

/// One run of a file's bytes, and where they are.
///
/// The four fields after [`kind`](Self::kind) are present only in the
/// [`Regular`](ExtentKind::Regular) and [`Prealloc`](ExtentKind::Prealloc) shapes; an inline
/// record ends at [`INLINE_DATA_START`](Self::INLINE_DATA_START) and the file's bytes follow.
/// [`read_from`](Self::read_from) fills them with zeros for an inline record, which is what
/// the format's own accessors do, and [`inline_data`](Self::inline_data) is how the bytes are
/// reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FileExtentItem {
    /// Offset 0. The transaction that wrote it.
    pub generation: u64,
    /// Offset 8. How many bytes the whole extent holds once decompressed — **the extent's
    /// length, not this record's share of it**.
    pub ram_bytes: u64,
    /// Offset 16. How the bytes on the volume are encoded.
    pub compression: Compression,
    /// Offset 17. How they are encrypted, which is zero on every filesystem this crate reads.
    pub encryption: u8,
    /// Offset 18. A further encoding, which no release defines a value for.
    pub other_encoding: u16,
    /// Offset 20. Which shape the record takes.
    pub kind: ExtentKind,
    /// Offset 21. The logical address the extent begins at, or **zero for a hole** — a run of
    /// the file that was never written and reads back as zeros.
    pub disk_bytenr: u64,
    /// Offset 29. How many bytes of the volume the extent occupies, which is the compressed
    /// length where the extent is compressed.
    pub disk_num_bytes: u64,
    /// Offset 37. How far into the extent this record's bytes begin. **Not a position in the
    /// file** — the key holds that.
    pub offset: u64,
    /// Offset 45. How many bytes of the file this record covers.
    pub num_bytes: u64,
}

impl FileExtentItem {
    /// Bytes a record of the addressed shapes occupies.
    pub const SIZE: usize = 53;

    /// Where an inline record's bytes begin, which is also how long its head is.
    pub const INLINE_DATA_START: usize = 21;

    /// Recover an extent record from the front of `buf`.
    ///
    /// How many bytes are required depends on what the record turns out to be, and the
    /// discriminating byte is inside the shorter head — so an inline record needs
    /// [`INLINE_DATA_START`](Self::INLINE_DATA_START) bytes and any other needs
    /// [`SIZE`](Self::SIZE).
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than the shape it declares.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::INLINE_DATA_START {
            return Err(ParseError::TooShort {
                structure: "btrfs_file_extent_item",
                need: Self::INLINE_DATA_START,
                got: buf.len(),
            });
        }
        let kind = ExtentKind::from_u8(get_u8(buf, 20));
        let mut item = Self {
            generation: get_u64(buf, 0),
            ram_bytes: get_u64(buf, 8),
            compression: Compression::from_u8(get_u8(buf, 16)),
            encryption: get_u8(buf, 17),
            other_encoding: get_u16(buf, 18),
            kind,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            offset: 0,
            num_bytes: 0,
        };
        if kind.is_inline() {
            return Ok(item);
        }
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_file_extent_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        item.disk_bytenr = get_u64(buf, 21);
        item.disk_num_bytes = get_u64(buf, 29);
        item.offset = get_u64(buf, 37);
        item.num_bytes = get_u64(buf, 45);
        Ok(item)
    }

    /// Write the record into the front of `buf`: the head alone for an inline record, and the
    /// whole of it otherwise.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than the shape being written.
    pub fn write_to(&self, buf: &mut [u8]) {
        let need = if self.kind.is_inline() {
            Self::INLINE_DATA_START
        } else {
            Self::SIZE
        };
        assert!(
            buf.len() >= need,
            "an extent record needs {need} bytes and was given {}",
            buf.len()
        );
        put_u64(buf, 0, self.generation);
        put_u64(buf, 8, self.ram_bytes);
        put_u8(buf, 16, self.compression.to_u8());
        put_u8(buf, 17, self.encryption);
        put_u16(buf, 18, self.other_encoding);
        put_u8(buf, 20, self.kind.to_u8());
        if self.kind.is_inline() {
            return;
        }
        put_u64(buf, 21, self.disk_bytenr);
        put_u64(buf, 29, self.disk_num_bytes);
        put_u64(buf, 37, self.offset);
        put_u64(buf, 45, self.num_bytes);
    }

    /// The bytes of an inline record, taken out of the item that held them.
    ///
    /// `data` is the whole item, head included, so what comes back is everything past the
    /// head — however long the item is. An item's length is what says how much there is:
    /// nothing inside the record repeats it.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the item does not even hold a head.
    pub fn inline_data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], ParseError> {
        if data.len() < Self::INLINE_DATA_START {
            return Err(ParseError::TooShort {
                structure: "btrfs_file_extent_item",
                need: Self::INLINE_DATA_START,
                got: data.len(),
            });
        }
        Ok(&data[Self::INLINE_DATA_START..])
    }

    /// Whether this record covers a run of the file that was never written.
    ///
    /// A hole is an addressed record whose extent address is zero, which is how a file with
    /// `no-holes` cleared spells a gap. With `no-holes` set the gap has no record at all, and
    /// a reader has to notice the *absence* — so both forms exist and a reader handles both.
    #[must_use]
    pub const fn is_hole(&self) -> bool {
        !self.kind.is_inline() && self.disk_bytenr == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_regular_extent() -> FileExtentItem {
        FileExtentItem {
            generation: 8,
            ram_bytes: 8192,
            compression: Compression::None,
            encryption: 0,
            other_encoding: 0,
            kind: ExtentKind::Regular,
            disk_bytenr: 13_631_488,
            disk_num_bytes: 8192,
            offset: 4096,
            num_bytes: 4096,
        }
    }

    #[test]
    fn an_addressed_extent_round_trips_through_its_fifty_three_bytes() {
        let item = a_regular_extent();
        let mut buf = [0u8; FileExtentItem::SIZE];
        item.write_to(&mut buf);
        assert_eq!(FileExtentItem::read_from(&buf).expect("a full item"), item);
        // The four addressed fields sit behind an unaligned one-byte discriminator, which is
        // the offset an alignment assumption gets wrong.
        assert_eq!(buf[20], 1, "a regular extent");
        assert_eq!(&buf[21..29], &13_631_488u64.to_le_bytes(), "disk_bytenr");
        assert_eq!(
            &buf[37..45],
            &4096u64.to_le_bytes(),
            "offset into the extent"
        );
        assert_eq!(&buf[45..53], &4096u64.to_le_bytes(), "num_bytes");
    }

    #[test]
    fn an_inline_extent_is_a_head_and_the_files_bytes() {
        // The shorter shape, and the thing that makes it a shape rather than a flag: the
        // record ends after 21 bytes and everything past that is the file.
        let item = FileExtentItem {
            ram_bytes: 5,
            kind: ExtentKind::Inline,
            ..a_regular_extent()
        };
        let mut data = vec![0u8; FileExtentItem::INLINE_DATA_START];
        item.write_to(&mut data);
        data.extend_from_slice(b"hello");
        let read = FileExtentItem::read_from(&data).expect("an inline record");
        assert_eq!(read.kind, ExtentKind::Inline);
        assert_eq!(read.inline_data(&data).expect("the bytes"), b"hello");
        // The addressed fields are not in the record at all, and read back as zeros rather
        // than as whatever the file's first bytes happen to be.
        assert_eq!(read.disk_bytenr, 0);
        assert_eq!(read.num_bytes, 0);
        // An item exactly a head long is an empty file rather than a failure.
        let empty = &data[..FileExtentItem::INLINE_DATA_START];
        assert_eq!(read.inline_data(empty).expect("no bytes"), b"");
    }

    #[test]
    fn an_inline_record_is_readable_from_an_item_too_short_for_an_addressed_one() {
        // Why the length required depends on the shape: an inline record 21 bytes long is
        // complete, and a reader that demanded 53 would refuse every small file.
        let item = FileExtentItem {
            kind: ExtentKind::Inline,
            ..a_regular_extent()
        };
        let mut buf = [0u8; FileExtentItem::INLINE_DATA_START];
        item.write_to(&mut buf);
        assert!(FileExtentItem::read_from(&buf).is_ok());
        // And an addressed record that short is refused rather than completed with zeros,
        // which would be a file reading back as a hole.
        let mut truncated = [0u8; FileExtentItem::SIZE - 1];
        a_regular_extent().write_to(&mut [0u8; FileExtentItem::SIZE]);
        truncated[20] = 1;
        assert!(matches!(
            FileExtentItem::read_from(&truncated),
            Err(ParseError::TooShort {
                structure: "btrfs_file_extent_item",
                need: 53,
                got: 52,
            })
        ));
    }

    #[test]
    fn a_hole_is_an_addressed_record_whose_extent_address_is_zero() {
        let hole = FileExtentItem {
            disk_bytenr: 0,
            disk_num_bytes: 0,
            offset: 0,
            num_bytes: 4096,
            ..a_regular_extent()
        };
        assert!(hole.is_hole());
        assert!(!a_regular_extent().is_hole());
        // An inline record is never a hole, whatever its unused address field holds: its
        // bytes are in the item.
        let inline = FileExtentItem {
            kind: ExtentKind::Inline,
            disk_bytenr: 0,
            ..a_regular_extent()
        };
        assert!(!inline.is_hole());
    }

    #[test]
    fn a_compressed_extent_is_two_lengths_and_a_named_algorithm() {
        // What says compression happened: the bytes on the volume are fewer than the bytes
        // the file has there.
        let item = FileExtentItem {
            compression: Compression::Zstd,
            ram_bytes: 1 << 16,
            disk_num_bytes: 4096,
            num_bytes: 1 << 16,
            offset: 0,
            ..a_regular_extent()
        };
        let mut buf = [0u8; FileExtentItem::SIZE];
        item.write_to(&mut buf);
        assert_eq!(buf[16], 3);
        let read = FileExtentItem::read_from(&buf).expect("a full item");
        assert_eq!(read.compression, Compression::Zstd);
        assert_eq!(read.compression.name(), Some("zstd"));
        assert!(read.disk_num_bytes < read.ram_bytes);
        // A byte no release defines keeps its value and has no name, so a refusal can say
        // what it was.
        assert_eq!(Compression::from_u8(9), Compression::Unknown(9));
        assert_eq!(Compression::from_u8(9).name(), None);
        assert_eq!(Compression::from_u8(9).to_u8(), 9);
    }

    #[test]
    fn an_extent_shape_the_format_has_not_defined_keeps_its_byte() {
        assert_eq!(ExtentKind::from_u8(7), ExtentKind::Unknown(7));
        assert_eq!(ExtentKind::from_u8(7).to_u8(), 7);
        assert!(!ExtentKind::from_u8(7).is_inline());
    }
}
