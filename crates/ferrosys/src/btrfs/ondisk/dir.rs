//! The directory entry, which is also the extended attribute: one record shape under three
//! item types.
//!
//! btrfs writes a name-to-something record once and keys it three ways. A directory holds each
//! entry twice — as a `DIR_ITEM` keyed by the hash of its name, which is what a lookup
//! descends to, and as a `DIR_INDEX` keyed by the entry's sequence number, which is what a
//! readdir walks in creation order. An extended attribute is the same record again as an
//! `XATTR_ITEM`, keyed by the hash of the attribute's name, with the attribute's value in the
//! bytes a directory entry leaves empty.
//!
//! One item may hold several of these packed, because a key can be shared: two names whose
//! hash collides land under one key, and both records go in one item. Framing them is
//! [`for_each_packed`](super::for_each_packed).
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u8, get_u16, get_u64, put_u8, put_u16, put_u64};

use super::{DiskKey, Packed, ParseError};

/// What a directory entry says the thing it names is.
///
/// The byte is the Linux directory-entry convention every filesystem that carries one uses,
/// with one value the convention does not have: [`Xattr`](Self::Xattr), which marks the record
/// as an extended attribute rather than a name in a directory.
///
/// An unrecognized byte is [`Unknown`](Self::Unknown), which is also the value the format
/// gives zero. A reader that refused one would refuse a filesystem over a byte it could ask
/// the inode about instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum DirEntryType {
    /// The entry says nothing about what it names.
    Unknown,
    /// A regular file.
    RegFile,
    /// A directory, or the directory a subvolume's root is mounted at.
    Dir,
    /// A character-special device node.
    CharDev,
    /// A block-special device node.
    BlockDev,
    /// A named pipe.
    Fifo,
    /// A Unix-domain socket node.
    Socket,
    /// A symbolic link.
    Symlink,
    /// An extended attribute, which is the record's other use.
    Xattr,
}

impl DirEntryType {
    /// The on-disk byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            DirEntryType::Unknown => 0,
            DirEntryType::RegFile => 1,
            DirEntryType::Dir => 2,
            DirEntryType::CharDev => 3,
            DirEntryType::BlockDev => 4,
            DirEntryType::Fifo => 5,
            DirEntryType::Socket => 6,
            DirEntryType::Symlink => 7,
            DirEntryType::Xattr => 8,
        }
    }

    /// Interpret an on-disk byte; anything the format has not defined is
    /// [`Unknown`](Self::Unknown).
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => DirEntryType::RegFile,
            2 => DirEntryType::Dir,
            3 => DirEntryType::CharDev,
            4 => DirEntryType::BlockDev,
            5 => DirEntryType::Fifo,
            6 => DirEntryType::Socket,
            7 => DirEntryType::Symlink,
            8 => DirEntryType::Xattr,
            _ => DirEntryType::Unknown,
        }
    }
}

/// One name, and what it names: a directory entry, or an extended attribute and its value.
///
/// The head is fixed and the tail is the name followed by [`data_len`](Self::data_len) bytes
/// of value — empty for a directory entry, and the attribute's value for an extended
/// attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirItem {
    /// The key of what this names.
    ///
    /// For an entry in a directory it is `(inode, INODE_ITEM, 0)` within the same tree, and
    /// for an entry a subvolume is mounted at it is `(subvolume, ROOT_ITEM, ...)` — which is
    /// how a subvolume appears as a directory without being one. For an extended attribute it
    /// is all zeros, since the record names nothing.
    pub location: DiskKey,
    /// The transaction that wrote the entry.
    pub transid: u64,
    /// How many bytes of value follow the name: an extended attribute's value, and zero for a
    /// directory entry.
    pub data_len: u16,
    /// How many bytes of name follow the head.
    pub name_len: u16,
    /// What the entry says it names.
    pub kind: DirEntryType,
}

impl DirItem {
    /// Bytes the fixed head occupies, before the name and the value.
    pub const SIZE: usize = 30;

    /// Recover the head from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a head.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_dir_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            location: DiskKey::read_from(buf)?,
            transid: get_u64(buf, 17),
            data_len: get_u16(buf, 25),
            name_len: get_u16(buf, 27),
            kind: DirEntryType::from_u8(get_u8(buf, 29)),
        })
    }

    /// Write the head into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a head.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a directory item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.location.write_to(buf);
        put_u64(buf, 17, self.transid);
        put_u16(buf, 25, self.data_len);
        put_u16(buf, 27, self.name_len);
        put_u8(buf, 29, self.kind.to_u8());
    }

    /// Split a record's tail into its name and its value.
    ///
    /// The tail is what [`for_each_packed`](super::for_each_packed) hands the visitor, and it
    /// is already bounded by the item that held it — so the only thing left to check is that
    /// the name and the value together are exactly the tail, which they are by construction.
    ///
    /// # Panics
    ///
    /// Where `tail` is shorter than the head declared, which
    /// [`for_each_packed`](super::for_each_packed) has already refused.
    #[must_use]
    pub fn split<'a>(&self, tail: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let name = self.name_len as usize;
        (&tail[..name], &tail[name..])
    }
}

impl Packed for DirItem {
    const STRUCTURE: &'static str = "btrfs_dir_item";
    const HEAD: usize = Self::SIZE;

    fn read_head(buf: &[u8]) -> Result<Self, ParseError> {
        Self::read_from(buf)
    }

    fn encoded_len(&self) -> usize {
        Self::SIZE + self.name_len as usize + self.data_len as usize
    }
}

/// A subvolume's link to the directory it is reachable through, and the name it appears under.
///
/// Written twice, as the format writes every link: a `ROOT_REF` in the parent's row of the
/// root tree, and a `ROOT_BACKREF` in the child's. Both are this record, and reading either
/// gives the same three things — which directory, which entry, and what the subvolume is
/// called there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RootRef {
    /// The inode of the directory the subvolume appears in, within the referring subvolume's
    /// own tree.
    pub dirid: u64,
    /// The entry's sequence number in that directory.
    pub sequence: u64,
    /// How many bytes of name follow the head.
    pub name_len: u16,
}

impl RootRef {
    /// Bytes the fixed head occupies, before the name.
    pub const SIZE: usize = 18;

    /// Recover the head from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a head.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_root_ref",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            dirid: get_u64(buf, 0),
            sequence: get_u64(buf, 8),
            name_len: get_u16(buf, 16),
        })
    }

    /// Write the head into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a head.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a root ref needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.dirid);
        put_u64(buf, 8, self.sequence);
        put_u16(buf, 16, self.name_len);
    }
}

impl Packed for RootRef {
    const STRUCTURE: &'static str = "btrfs_root_ref";
    const HEAD: usize = Self::SIZE;

    fn read_head(buf: &[u8]) -> Result<Self, ParseError> {
        Self::read_from(buf)
    }

    fn encoded_len(&self) -> usize {
        Self::SIZE + self.name_len as usize
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ItemType, for_each_packed, objectid};
    use super::*;

    /// A record with `name` pointing at `location`, and `value` behind it.
    fn record(location: DiskKey, kind: DirEntryType, name: &[u8], value: &[u8]) -> Vec<u8> {
        let head = DirItem {
            location,
            transid: 8,
            data_len: value.len() as u16,
            name_len: name.len() as u16,
            kind,
        };
        let mut out = vec![0u8; DirItem::SIZE];
        head.write_to(&mut out);
        out.extend_from_slice(name);
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn a_directory_entry_round_trips_through_its_thirty_byte_head() {
        let head = DirItem {
            location: DiskKey::new(257, ItemType::INODE_ITEM, 0),
            transid: 8,
            data_len: 0,
            name_len: 5,
            kind: DirEntryType::RegFile,
        };
        let mut buf = [0u8; DirItem::SIZE];
        head.write_to(&mut buf);
        assert_eq!(DirItem::read_from(&buf).expect("a full head"), head);
        // The key is the first field and the three that follow it are packed with no
        // alignment, which is what an offset transcribed from a padded structure gets wrong.
        assert_eq!(&buf[0..8], &257u64.to_le_bytes(), "the location's objectid");
        assert_eq!(buf[8], 1, "the location's type");
        assert_eq!(&buf[25..27], &0u16.to_le_bytes(), "data_len");
        assert_eq!(&buf[27..29], &5u16.to_le_bytes(), "name_len");
        assert_eq!(buf[29], 1, "a regular file");
    }

    #[test]
    fn two_names_whose_hash_collides_are_two_records_in_one_item() {
        // The reason these are packed at all: the key is the hash of the name, so a
        // collision puts both names under one key — and a reader that took the first would
        // report one of two files as missing, on a filesystem nothing is wrong with.
        let mut data = record(
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
            b"one",
            b"",
        );
        data.extend(record(
            DiskKey::new(258, ItemType::INODE_ITEM, 0),
            DirEntryType::Dir,
            b"two",
            b"",
        ));
        let mut found = Vec::new();
        for_each_packed::<DirItem, _>(&data, |head, tail| {
            let (name, value) = head.split(tail);
            found.push((
                head.location.objectid,
                head.kind,
                name.to_vec(),
                value.len(),
            ));
            true
        })
        .expect("two entries");
        assert_eq!(
            found,
            vec![
                (257, DirEntryType::RegFile, b"one".to_vec(), 0),
                (258, DirEntryType::Dir, b"two".to_vec(), 0),
            ]
        );
    }

    #[test]
    fn an_extended_attribute_is_the_same_record_with_its_value_behind_the_name() {
        // One record shape, three item types. The value lives in the bytes a directory entry
        // leaves empty, and a reader that ignored `data_len` would hand back the next
        // record's head as part of this one's name.
        let data = record(
            DiskKey::new(0, ItemType::from_value(0), 0),
            DirEntryType::Xattr,
            b"user.comment",
            b"hello",
        );
        let mut seen = None;
        for_each_packed::<DirItem, _>(&data, |head, tail| {
            let (name, value) = head.split(tail);
            seen = Some((head.kind, name.to_vec(), value.to_vec()));
            true
        })
        .expect("one attribute");
        assert_eq!(
            seen,
            Some((
                DirEntryType::Xattr,
                b"user.comment".to_vec(),
                b"hello".to_vec()
            ))
        );
    }

    #[test]
    fn an_entry_a_subvolume_is_mounted_at_points_at_a_root_rather_than_an_inode() {
        // How a subvolume appears as a directory without being one: the entry's location
        // names a `ROOT_ITEM`, and the tree it belongs to is a different tree entirely.
        let data = record(
            DiskKey::new(256, ItemType::ROOT_ITEM, u64::MAX),
            DirEntryType::Dir,
            b"snap",
            b"",
        );
        let head = DirItem::read_from(&data).expect("a full head");
        assert_eq!(head.location.kind, ItemType::ROOT_ITEM);
        assert_eq!(head.location.objectid, objectid::FIRST_FREE);
    }

    #[test]
    fn an_entry_type_the_format_has_not_defined_reads_as_unknown() {
        assert_eq!(DirEntryType::from_u8(9), DirEntryType::Unknown);
        assert_eq!(DirEntryType::from_u8(0), DirEntryType::Unknown);
        // And every byte the format does define round-trips, so a value is never quietly
        // mapped onto its neighbour.
        for value in 0u8..=8 {
            let kind = DirEntryType::from_u8(value);
            if kind != DirEntryType::Unknown {
                assert_eq!(kind.to_u8(), value);
            }
        }
    }

    #[test]
    fn a_root_ref_round_trips_and_names_the_directory_the_subvolume_is_in() {
        let head = RootRef {
            dirid: 256,
            sequence: 2,
            name_len: 4,
        };
        let mut data = vec![0u8; RootRef::SIZE];
        head.write_to(&mut data);
        data.extend_from_slice(b"snap");
        assert_eq!(RootRef::read_from(&data).expect("a full head"), head);
        assert_eq!(&data[0..8], &256u64.to_le_bytes());
        assert_eq!(&data[16..18], &4u16.to_le_bytes());
        let mut name = Vec::new();
        for_each_packed::<RootRef, _>(&data, |_, tail| {
            name = tail.to_vec();
            true
        })
        .expect("one reference");
        assert_eq!(name, b"snap");
    }

    #[test]
    fn a_head_shorter_than_the_format_writes_is_refused() {
        assert!(matches!(
            DirItem::read_from(&[0u8; DirItem::SIZE - 1]),
            Err(ParseError::TooShort {
                structure: "btrfs_dir_item",
                need: 30,
                got: 29,
            })
        ));
        assert!(matches!(
            RootRef::read_from(&[0u8; RootRef::SIZE - 1]),
            Err(ParseError::TooShort {
                structure: "btrfs_root_ref",
                ..
            })
        ));
    }
}
