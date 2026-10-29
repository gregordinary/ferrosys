//! The records of a volume's file-system tree: inodes, the names they are known by, their
//! attributes, and where their bytes are.
//!
//! A file is not one structure but a run of records sharing its identifier, sorted together:
//! the inode, then its attributes, then its directory entries if it is a directory
//! (Apple File System Reference, pp. 71-116). Its data is a second run, keyed by the data
//! stream's identifier rather than the inode's, which is what lets two inodes share one stream
//! after a clone.
//!
//! Every key begins with eight bytes: the object's identifier in the low 60 bits and the
//! record's kind in the high four. Records sort by identifier, then by kind, then by a third
//! part that is the kind's own: a directory entry's name hash, an attribute's name byte by byte,
//! a file extent's logical offset. Each order is observed on every image macOS writes, and so is
//! one record per key; two entries of one directory under one hash have no observed order.
//!
//! Each value here is recovered from the bytes the tree's table of contents located, and
//! every length inside one is checked against those bytes: a name that runs past its key, an
//! extended field that runs past its value. A failed check is a [`ParseError`].
//!
//! This module is pure: it reads bytes and does no I/O.

use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};

use super::ParseError;

/// The record kinds a file-system tree holds, the high four bits of a key's first word
/// (Apple File System Reference, p. 84; the shift and mask that place them, pp. 72-73).
pub mod record_kind {
    /// A snapshot's metadata, in the snapshot tree.
    pub const SNAPSHOT_META: u8 = 1;
    /// A physical extent's reference count, in the extent-reference tree.
    pub const PHYSICAL_EXTENT: u8 = 2;
    /// An inode.
    pub const INODE: u8 = 3;
    /// An extended attribute.
    pub const XATTR: u8 = 4;
    /// One name of a hard-linked inode.
    pub const SIBLING_LINK: u8 = 5;
    /// A data stream's reference count.
    pub const DATA_STREAM_ID: u8 = 6;
    /// Per-file encryption state.
    pub const CRYPTO_STATE: u8 = 7;
    /// A run of a data stream's bytes.
    pub const FILE_EXTENT: u8 = 8;
    /// A directory entry.
    pub const DIR_ENTRY: u8 = 9;
    /// A directory's statistics.
    pub const DIR_STATS: u8 = 10;
    /// A snapshot's name, in the snapshot tree.
    pub const SNAPSHOT_NAME: u8 = 11;
    /// A map from a hard link's sibling identifier to its inode.
    pub const SIBLING_MAP: u8 = 12;
    /// Information about a file's data, on a sealed volume.
    pub const FILE_INFO: u8 = 13;
}

/// The low 60 bits of a key's first word.
pub const ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

/// Where a key's kind begins in its first word.
pub const KIND_SHIFT: u32 = 60;

/// The inode numbers the format fixes (Apple File System Reference, pp. 96-97).
pub mod inode_number {
    /// The parent recorded by the root directory and by the private directory.
    pub const ROOT_PARENT: u64 = 1;
    /// The root directory.
    pub const ROOT: u64 = 2;
    /// The private directory, which holds what no path reaches.
    pub const PRIVATE: u64 = 3;
    /// The first number an ordinary file takes.
    pub const FIRST_USER: u64 = 16;
}

/// The bit of an inode's BSD flags saying its data is compressed into its attributes, as BSD's
/// `UF_COMPRESSED` defines it.
pub const BSD_COMPRESSED: u32 = 0x20;

/// The bit of an inode's internal flags saying it has been cloned at least once, so the
/// blocks holding its data may be in use by another inode as well (`INODE_WAS_EVER_CLONED`,
/// Apple File System Reference, p. 91). macOS sets it on both the clone and the inode cloned.
/// It is exact only for an inode whose identifier is larger than the volume's
/// [`clone_info_epoch`](super::VolumeSuperblock::clone_info_epoch), on a volume whose
/// [`clone_info_xid`](super::VolumeSuperblock::clone_info_xid) is the newest
/// [`modified_by`](super::VolumeSuperblock::modified_by) entry's transaction.
pub const INTERNAL_EVER_CLONED: u64 = 0x400;

/// The internal flag saying an inode has no resource fork (`INODE_NO_RSRC_FORK`, Apple File
/// System Reference, p. 92). Every inode macOS 15, 26 and 27 write without a
/// `com.apple.ResourceFork` attribute carries it: 247,000 of 247,000 in the images on hand
/// (observed). `fsck_apfs` there asks for it to be cleared on an inode with one.
pub const INTERNAL_WITHOUT_RESOURCE_FORK: u64 = 0x8000;

/// The internal flag saying an inode has a resource fork (`INODE_HAS_RSRC_FORK`, Apple File
/// System Reference, p. 92). Every inode macOS 15, 26 and 27 write with a
/// `com.apple.ResourceFork` attribute carries it in place of [`INTERNAL_WITHOUT_RESOURCE_FORK`]:
/// 71 of 71 in the images on hand (observed). `fsck_apfs` there asks for it to be set on an
/// inode with one, and the kernel answers a `stat` of an inode with one and without it
/// `EBADMSG`. macOS 14 adds an attribute of that name through `setxattr` without changing either
/// flag.
pub const INTERNAL_WITH_RESOURCE_FORK: u64 = 0x4000;

/// The internal flag the reference names as an inode having an access control list
/// (`INODE_HAS_SECURITY_EA`, Apple File System Reference, p. 90). Every inode macOS 26 and 27
/// write with a [`SECURITY_XATTR`] attribute carries it beside the rest: 50 of 50 in the corpus,
/// and none of the 266,433 inodes without one (observed).
pub const INTERNAL_WITH_SECURITY_ATTRIBUTE: u64 = 0x40;

/// The internal flag saying an inode records its uncompressed size in its
/// `uncompressed_size` field (`INODE_HAS_UNCOMPRESSED_SIZE`, Apple File System Reference,
/// p. 92). macOS sets it on a compressed file, beside one of the two flags saying whether it
/// holds a resource fork: on 4,368 of the 4,382 compressed files in the images macOS 14 to 27
/// wrote, each with no data stream (observed).
pub const INTERNAL_COMPRESSED: u64 = 0x40000;

/// The bit of an inode's internal flags saying a truncation of it began and has not finished,
/// so a crash cut it short (`INODE_BEING_TRUNCATED`, Apple File System Reference, p. 90).
pub const INTERNAL_BEING_TRUNCATED: u64 = 0x80;

/// The attribute holding a symbolic link's target.
pub const SYMLINK_XATTR: &[u8] = b"com.apple.fs.symlink";

/// The attribute holding a compressed file's header, and its data where it is small.
pub const DECMPFS_XATTR: &[u8] = b"com.apple.decmpfs";

/// The attribute holding a compressed file's data where it is large.
pub const RESOURCE_FORK_XATTR: &[u8] = b"com.apple.ResourceFork";

/// The attribute `listxattr` leaves out of what it returns, which macOS 26 and 27 give
/// `/.fseventsd`.
pub const SECURITY_XATTR: &[u8] = b"com.apple.system.Security";

/// The extended-field types of an inode (Apple File System Reference, pp. 110-112).
pub mod inode_field {
    /// The inode's name, where it is a hard link's primary.
    pub const NAME: u8 = 4;
    /// The file's size before a truncation a crash cut short, where one was.
    pub const PREV_FSIZE: u8 = 5;
    /// The inode's data stream: its size and allocation.
    pub const DATA_STREAM: u8 = 8;
    /// Bytes of a sparse file not backed by storage.
    pub const SPARSE_BYTES: u8 = 13;
    /// A device node's device number.
    pub const DEVICE: u8 = 14;
}

/// The extended-field type of a directory entry carrying a hard link's sibling identifier.
pub const SIBLING_ID_FIELD: u8 = 1;

/// The attribute flags (Apple File System Reference, pp. 94-95).
pub mod xattr_flags {
    /// The data is a stream of its own, found by an identifier.
    pub const STREAM: u16 = 0x1;
    /// The data is in the record.
    pub const EMBEDDED: u16 = 0x2;
    /// The attribute belongs to the file system rather than to the file.
    pub const FILESYSTEM_OWNED: u16 = 0x4;
    /// Beside [`STREAM`] on the stream of an attribute set through `setxattr`, in every one
    /// macOS 14 to 27 wrote. A stream the file system writes itself, a resource fork's or a
    /// compressed file's header, carries [`STREAM`] alone.
    pub const SET_THROUGH_SETXATTR: u16 = 0x10;
}

/// The mask of a directory entry's flags that holds the entry's type.
pub const ENTRY_TYPE_MASK: u16 = 0x000F;

/// The mask of a file extent's first word that holds its length in bytes.
pub const EXTENT_LENGTH_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

/// The first eight bytes of every key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct KeyHeader {
    /// The object the record belongs to.
    pub id: u64,
    /// The record's kind: one of [`record_kind`].
    pub kind: u8,
}

impl KeyHeader {
    /// Bytes on disk.
    pub const SIZE: usize = 8;

    /// Recover a key header from the first eight bytes of `key`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the key is shorter than eight bytes.
    pub fn read_from(key: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("record key", Self::SIZE, key)?;
        let word = get_u64(key, 0);
        Ok(Self {
            id: word & ID_MASK,
            kind: (word >> KIND_SHIFT) as u8,
        })
    }

    /// The key's first word.
    #[must_use]
    pub const fn word(&self) -> u64 {
        (self.id & ID_MASK) | ((self.kind as u64) << KIND_SHIFT)
    }

    /// Write the header into the first eight bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than eight bytes.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "a record key needs 8 bytes");
        put_u64(buf, 0, self.word());
    }

    /// A whole key: this header, then `tail`, the kind's own part.
    #[must_use]
    pub fn key(&self, tail: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(Self::SIZE + tail.len());
        key.extend_from_slice(&self.word().to_le_bytes());
        key.extend_from_slice(tail);
        key
    }
}

/// One extended field of an inode or a directory entry: its type, its flags, and its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtendedField<'a> {
    /// The field's type.
    pub kind: u8,
    /// The field's flags.
    pub flags: u8,
    /// The field's data, its stated size long.
    pub data: &'a [u8],
}

/// The extended fields at the end of an inode or directory entry value
/// (Apple File System Reference, pp. 108-112).
///
/// Four bytes give the count and the bytes of data used; then one four-byte descriptor per
/// field, its type, flags and size; then each field's data in the same order. Each field's data
/// takes its size rounded up to a multiple of eight, and the first begins directly after the
/// descriptors: that placement is the one every inode macOS 15, 26 and 27 wrote decodes under.
/// The bytes used are the fields' data with its padding, without the descriptors, and the
/// record ends where they do; this reads the fields by their sizes and leaves that total to
/// [`scan`](super::super::Reader::scan).
///
/// An empty `blob` holds no fields.
///
/// # Errors
///
/// [`ParseError::TooShort`] where the descriptors or a field's data run past `blob`.
pub fn extended_fields(blob: &[u8]) -> Result<Vec<ExtendedField<'_>>, ParseError> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    ParseError::need("extended fields", 4, blob)?;
    let count = usize::from(get_u16(blob, 0));
    let descriptors_end = 4 + 4 * count;
    ParseError::need("extended field descriptors", descriptors_end, blob)?;
    let mut fields = Vec::with_capacity(count);
    let mut at = descriptors_end;
    for i in 0..count {
        let d = 4 + 4 * i;
        let size = usize::from(get_u16(blob, d + 2));
        let end = at + size;
        ParseError::need("extended field data", end, blob)?;
        fields.push(ExtendedField {
            kind: blob[d],
            flags: blob[d + 1],
            data: &blob[at..end],
        });
        at += size.next_multiple_of(8);
    }
    Ok(fields)
}

/// The extended fields `fields`, in their order, as the blob at the end of an inode or
/// directory entry value: what [`extended_fields`] reads back.
///
/// The count, the bytes of data used, one descriptor per field, then each field's data padded
/// to a multiple of eight. No fields is no blob, which is how a value without them ends.
///
/// # Panics
///
/// Where there are more fields than the count's 16 bits hold, or the fields' data is longer
/// than the 16 bits of each size and of the total, which no value a tree node holds reaches.
#[must_use]
pub fn extended_field_blob(fields: &[ExtendedField<'_>]) -> Vec<u8> {
    if fields.is_empty() {
        return Vec::new();
    }
    let narrow = |n: usize| u16::try_from(n).expect("an extended-field count or size fits 16 bits");
    let descriptors_end = 4 + 4 * fields.len();
    let mut out = vec![0u8; descriptors_end];
    put_u16(&mut out, 0, narrow(fields.len()));
    for (i, f) in fields.iter().enumerate() {
        let d = 4 + 4 * i;
        out[d] = f.kind;
        out[d + 1] = f.flags;
        put_u16(&mut out, d + 2, narrow(f.data.len()));
    }
    for f in fields {
        out.extend_from_slice(f.data);
        out.resize(
            out.len() + f.data.len().next_multiple_of(8) - f.data.len(),
            0,
        );
    }
    let used = narrow(out.len() - descriptors_end);
    put_u16(&mut out, 2, used);
    out
}

/// The data of the field of type `kind`, where `fields` has one.
#[must_use]
pub fn field<'a>(fields: &[ExtendedField<'a>], kind: u8) -> Option<&'a [u8]> {
    fields.iter().find(|f| f.kind == kind).map(|f| f.data)
}

/// A data stream's size and allocation (Apple File System Reference, p. 106).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DataStream {
    /// Offset 0. The stream's logical size in bytes.
    pub size: u64,
    /// Offset 8. Bytes allocated to it.
    pub allocated: u64,
    /// Offset 16. The default encryption identifier of its extents.
    pub crypto_id: u64,
    /// Offset 24. Bytes ever written to it.
    pub bytes_written: u64,
    /// Offset 32. Bytes ever read from it.
    pub bytes_read: u64,
}

impl DataStream {
    /// Bytes on disk.
    pub const SIZE: usize = 40;

    /// Recover a data stream from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("data stream", Self::SIZE, buf)?;
        Ok(Self {
            size: get_u64(buf, 0),
            allocated: get_u64(buf, 8),
            crypto_id: get_u64(buf, 16),
            bytes_written: get_u64(buf, 24),
            bytes_read: get_u64(buf, 32),
        })
    }

    /// Write the stream into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "a data stream needs 40 bytes");
        put_u64(buf, 0, self.size);
        put_u64(buf, 8, self.allocated);
        put_u64(buf, 16, self.crypto_id);
        put_u64(buf, 24, self.bytes_written);
        put_u64(buf, 32, self.bytes_read);
    }
}

/// An inode record's value (Apple File System Reference, pp. 74-77).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InodeValue {
    /// Offset 0. The directory holding the inode's primary name.
    pub parent_id: u64,
    /// Offset 8. The identifier its data stream's records are keyed by.
    pub private_id: u64,
    /// Offset 16. When it was created, in nanoseconds since 1970. The reference declares the
    /// four times unsigned; macOS stores times before 1970 as negative values, and they are
    /// read as such.
    pub create_time: i64,
    /// Offset 24. When its data last changed.
    pub modify_time: i64,
    /// Offset 32. When its attributes last changed.
    pub change_time: i64,
    /// Offset 40. When it was last read.
    pub access_time: i64,
    /// Offset 48. The implementation's flags.
    pub internal_flags: u64,
    /// Offset 56. A directory's child count, or any other inode's link count.
    pub links_or_children: i32,
    /// Offset 60. The default protection class.
    pub protection_class: u32,
    /// Offset 64. A counter bumped on every write.
    pub write_generation: u32,
    /// Offset 68. BSD flags: `UF_*` and `SF_*`.
    pub bsd_flags: u32,
    /// Offset 72. The owner.
    pub owner: u32,
    /// Offset 76. The group.
    pub group: u32,
    /// Offset 80. Type and permission bits, as `st_mode` holds them.
    pub mode: u16,
    /// Offset 82. Padding.
    pub pad: u16,
    /// Offset 84. A compressed file's uncompressed size.
    pub uncompressed_size: u64,
}

impl InodeValue {
    /// Bytes before the extended fields.
    pub const SIZE: usize = 92;

    /// Recover an inode from the first [`SIZE`](Self::SIZE) bytes of `value`. The extended
    /// fields follow, at `value[SIZE..]`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `value` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(value: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("inode", Self::SIZE, value)?;
        Ok(Self {
            parent_id: get_u64(value, 0),
            private_id: get_u64(value, 8),
            create_time: get_u64(value, 16) as i64,
            modify_time: get_u64(value, 24) as i64,
            change_time: get_u64(value, 32) as i64,
            access_time: get_u64(value, 40) as i64,
            internal_flags: get_u64(value, 48),
            links_or_children: get_u32(value, 56) as i32,
            protection_class: get_u32(value, 60),
            write_generation: get_u32(value, 64),
            bsd_flags: get_u32(value, 68),
            owner: get_u32(value, 72),
            group: get_u32(value, 76),
            mode: get_u16(value, 80),
            pad: get_u16(value, 82),
            uncompressed_size: get_u64(value, 84),
        })
    }

    /// Write the inode into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "an inode needs 92 bytes");
        put_u64(buf, 0, self.parent_id);
        put_u64(buf, 8, self.private_id);
        put_u64(buf, 16, self.create_time as u64);
        put_u64(buf, 24, self.modify_time as u64);
        put_u64(buf, 32, self.change_time as u64);
        put_u64(buf, 40, self.access_time as u64);
        put_u64(buf, 48, self.internal_flags);
        put_u32(buf, 56, self.links_or_children as u32);
        put_u32(buf, 60, self.protection_class);
        put_u32(buf, 64, self.write_generation);
        put_u32(buf, 68, self.bsd_flags);
        put_u32(buf, 72, self.owner);
        put_u32(buf, 76, self.group);
        put_u16(buf, 80, self.mode);
        put_u16(buf, 82, self.pad);
        put_u64(buf, 84, self.uncompressed_size);
    }
}

/// A directory entry's key: the entry's name, and the hash it is sorted by
/// (Apple File System Reference, p. 78).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EntryKey<'a> {
    /// The 22-bit hash of the name, as stored.
    pub hash: u32,
    /// The name's bytes, without the terminating NUL the key stores.
    pub name: &'a [u8],
}

impl<'a> EntryKey<'a> {
    /// Recover a hashed directory-entry key: after the eight-byte header, a word whose low 10
    /// bits are the name's length with its NUL and whose high 22 are the hash, then the name.
    ///
    /// The reference's mask for the hash keeps 21 of those 22 bits; every hash macOS stores
    /// uses all 22, and this reads all 22.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the name runs past the key, and
    /// [`ParseError::Unterminated`] where the stored name does not end in its NUL.
    pub fn read_from(key: &'a [u8]) -> Result<Self, ParseError> {
        ParseError::need("directory entry key", 12, key)?;
        let word = get_u32(key, 8);
        let len = (word & 0x3FF) as usize;
        let end = 12 + len;
        ParseError::need("directory entry name", end, key)?;
        let stored = &key[12..end];
        let Some((&0, name)) = stored.split_last() else {
            return Err(ParseError::Unterminated {
                structure: "directory entry name",
            });
        };
        Ok(Self {
            hash: word >> 10,
            name,
        })
    }
}

impl EntryKey<'_> {
    /// The whole key of this entry in directory `parent`: the key header, the word holding the
    /// name's length with its NUL in its low 10 bits and the hash in its high 22, then the name
    /// and its NUL, where [`read_from`](Self::read_from) finds each.
    ///
    /// # Panics
    ///
    /// Where the hash is wider than 22 bits, or the name with its NUL longer than the 10 bits
    /// of its length hold.
    #[must_use]
    pub fn to_key(&self, parent: u64) -> Vec<u8> {
        assert!(self.hash < 1 << 22, "a directory entry's hash is 22 bits");
        let len = u32::try_from(self.name.len() + 1)
            .ok()
            .filter(|len| *len < 1 << 10)
            .expect("a directory entry's name with its NUL fits 10 bits");
        let mut key = vec![0u8; 12];
        KeyHeader {
            id: parent,
            kind: record_kind::DIR_ENTRY,
        }
        .write_to(&mut key);
        put_u32(&mut key, 8, (self.hash << 10) | len);
        key.extend_from_slice(self.name);
        key.push(0);
        key
    }
}

/// A directory entry's value (Apple File System Reference, pp. 79-81).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntryValue {
    /// Offset 0. The inode the entry names.
    pub file_id: u64,
    /// Offset 8. When the entry was added, in nanoseconds since 1970.
    pub date_added: i64,
    /// Offset 16. The entry's flags; the low four bits are its `DT_*` type.
    pub flags: u16,
}

impl EntryValue {
    /// Bytes before the extended fields.
    pub const SIZE: usize = 18;

    /// Recover an entry's value from the first [`SIZE`](Self::SIZE) bytes of `value`. The
    /// extended fields follow, at `value[SIZE..]`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `value` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(value: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("directory entry", Self::SIZE, value)?;
        Ok(Self {
            file_id: get_u64(value, 0),
            date_added: get_u64(value, 8) as i64,
            flags: get_u16(value, 16),
        })
    }

    /// The entry's type, as the low four bits of its flags give it.
    #[must_use]
    pub const fn entry_type(&self) -> u8 {
        (self.flags & ENTRY_TYPE_MASK) as u8
    }

    /// Write the value into the first [`SIZE`](Self::SIZE) bytes of `buf`. Its extended fields,
    /// where it has any, follow.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "a directory entry needs 18 bytes");
        put_u64(buf, 0, self.file_id);
        put_u64(buf, 8, self.date_added as u64);
        put_u16(buf, 16, self.flags);
    }
}

/// An extended attribute's key: its name (Apple File System Reference, p. 82).
///
/// # Errors
///
/// [`ParseError::TooShort`] where the name runs past the key, and
/// [`ParseError::Unterminated`] where the stored name does not end in its NUL.
pub fn xattr_name(key: &[u8]) -> Result<&[u8], ParseError> {
    ParseError::need("attribute key", 10, key)?;
    let end = 10 + usize::from(get_u16(key, 8));
    ParseError::need("attribute name", end, key)?;
    match key[10..end].split_last() {
        Some((&0, name)) => Ok(name),
        _ => Err(ParseError::Unterminated {
            structure: "attribute name",
        }),
    }
}

/// The key of inode `id`'s attribute `name`, as [`xattr_name`] reads it: the key header, the
/// name's length with its NUL, then the name and its NUL.
///
/// # Panics
///
/// Where the name with its NUL is longer than its 16-bit length holds.
#[must_use]
pub fn xattr_key(id: u64, name: &[u8]) -> Vec<u8> {
    let len = u16::try_from(name.len() + 1).expect("an attribute's name with its NUL fits 16 bits");
    let mut tail = Vec::with_capacity(xattr_key_size(name.len()) - KeyHeader::SIZE);
    tail.extend_from_slice(&len.to_le_bytes());
    tail.extend_from_slice(name);
    tail.push(0);
    KeyHeader {
        id,
        kind: record_kind::XATTR,
    }
    .key(&tail)
}

/// Bytes in the key [`xattr_key`] makes of a name of `len` bytes: the key header, the name's
/// length, the name and its NUL.
#[must_use]
pub const fn xattr_key_size(len: usize) -> usize {
    KeyHeader::SIZE + 2 + len + 1
}

/// An extended attribute's value: its flags and its data (Apple File System Reference, p. 82).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct XattrValue<'a> {
    /// Offset 0. [`xattr_flags`].
    pub flags: u16,
    /// Offset 4. The attribute's bytes where they are embedded, or the stream that holds them.
    pub data: &'a [u8],
}

impl<'a> XattrValue<'a> {
    /// Bytes of a value before its data: the flags and the data's length.
    pub const HEADER_SIZE: usize = 4;

    /// Bytes of a stream attribute's data: the stream's identifier, then the stream.
    pub const STREAM_SIZE: usize = 8 + DataStream::SIZE;

    /// Recover an attribute's value: flags, a length, and that many bytes.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the data runs past the value.
    pub fn read_from(value: &'a [u8]) -> Result<Self, ParseError> {
        ParseError::need("attribute", Self::HEADER_SIZE, value)?;
        let end = Self::HEADER_SIZE + usize::from(get_u16(value, 2));
        ParseError::need("attribute data", end, value)?;
        Ok(Self {
            flags: get_u16(value, 0),
            data: &value[Self::HEADER_SIZE..end],
        })
    }

    /// The value [`read_from`](Self::read_from) reads: the flags, the data's length, then the
    /// data.
    ///
    /// # Panics
    ///
    /// Where the data is longer than its 16-bit length holds.
    #[must_use]
    pub fn to_value(&self) -> Vec<u8> {
        let len = u16::try_from(self.data.len()).expect("an attribute's data fits 16 bits");
        let mut value = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        value.extend_from_slice(&self.flags.to_le_bytes());
        value.extend_from_slice(&len.to_le_bytes());
        value.extend_from_slice(self.data);
        value
    }

    /// Where a stream attribute's bytes are: the stream's identifier and its size.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the data is shorter than an identifier and a stream.
    pub fn stream(&self) -> Result<(u64, DataStream), ParseError> {
        ParseError::need("attribute stream", Self::STREAM_SIZE, self.data)?;
        Ok((
            get_u64(self.data, 0),
            DataStream::read_from(&self.data[8..])?,
        ))
    }
}

/// A file extent: a run of a data stream's bytes and the blocks that hold them
/// (Apple File System Reference, pp. 103-104).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileExtent {
    /// From the key. Where in the stream the run begins, in bytes.
    pub logical: u64,
    /// Offset 0. The run's length in bytes, the low 56 bits of its first word.
    pub length: u64,
    /// Offset 0. The high eight bits of the first word, zero in every extent seen.
    pub flags: u8,
    /// Offset 8. The first block holding the run, or zero for a run never written.
    pub physical_block: u64,
    /// Offset 16. The encryption identifier.
    pub crypto_id: u64,
}

impl FileExtent {
    /// Bytes in the value.
    pub const VALUE_SIZE: usize = 24;

    /// Recover an extent from its key and value.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the key is shorter than 16 bytes or the value than 24.
    pub fn read_from(key: &[u8], value: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("file extent key", 16, key)?;
        ParseError::need("file extent", Self::VALUE_SIZE, value)?;
        let word = get_u64(value, 0);
        Ok(Self {
            logical: get_u64(key, 8),
            length: word & EXTENT_LENGTH_MASK,
            flags: (word >> 56) as u8,
            physical_block: get_u64(value, 8),
            crypto_id: get_u64(value, 16),
        })
    }
}

impl FileExtent {
    /// The record of this extent of stream `stream`: its key, the logical offset after the
    /// header, and its value, the length and flags, the first block, and the encryption
    /// identifier.
    #[must_use]
    pub fn to_record(&self, stream: u64) -> (Vec<u8>, Vec<u8>) {
        let key = KeyHeader {
            id: stream,
            kind: record_kind::FILE_EXTENT,
        }
        .key(&self.logical.to_le_bytes());
        let mut value = vec![0u8; Self::VALUE_SIZE];
        put_u64(
            &mut value,
            0,
            (self.length & EXTENT_LENGTH_MASK) | (u64::from(self.flags) << 56),
        );
        put_u64(&mut value, 8, self.physical_block);
        put_u64(&mut value, 16, self.crypto_id);
        (key, value)
    }
}

/// The mask of a physical extent's first word that holds its length in blocks.
pub const PHYSICAL_LENGTH_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

/// A physical extent record of a volume's extent-reference tree: a run of blocks, the record
/// that wrote it, and its reference count (Apple File System Reference, p. 102).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PhysicalExtent {
    /// From the key's identifier. The run's first block.
    pub start: u64,
    /// Offset 0. The run's length in blocks, the low 60 bits of its first word.
    pub blocks: u64,
    /// Offset 0. The high four bits: `1` a run and its count, `2` a change to the count a tree
    /// before this one records for the run (observed, macOS 14 to 27).
    pub kind: u8,
    /// Offset 8. The record that wrote the run: a stream's identifier for the blocks a file's
    /// data was first written to, the identifier of the inode an attribute stream belongs to,
    /// and the clone's inode for the blocks a clone wrote; all ones on a change of kind `2`.
    /// It keeps naming that record after the record stops using the run or is removed, so it
    /// says who wrote a run and not who uses it (observed, macOS 14 to 27).
    pub owner: u64,
    /// Offset 16. The reference count for a run of kind `1`: two or more for a run clones
    /// share. For a change of kind `2`, the signed amount it changes the count by.
    pub references: i32,
}

impl PhysicalExtent {
    /// Bytes in the value.
    pub const VALUE_SIZE: usize = 20;

    /// Recover a physical extent from its key and value.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the key is shorter than 8 bytes or the value than 20.
    pub fn read_from(key: &[u8], value: &[u8]) -> Result<Self, ParseError> {
        let header = KeyHeader::read_from(key)?;
        ParseError::need("physical extent", Self::VALUE_SIZE, value)?;
        let word = get_u64(value, 0);
        Ok(Self {
            start: header.id,
            blocks: word & PHYSICAL_LENGTH_MASK,
            kind: (word >> 60) as u8,
            owner: get_u64(value, 8),
            references: get_u32(value, 16) as i32,
        })
    }
}

impl PhysicalExtent {
    /// The record of this extent: its key, the run's first block in the header, and its value,
    /// the length and kind, the owner, and the reference count.
    #[must_use]
    pub fn to_record(&self) -> (Vec<u8>, Vec<u8>) {
        let key = KeyHeader {
            id: self.start,
            kind: record_kind::PHYSICAL_EXTENT,
        }
        .key(&[]);
        let mut value = vec![0u8; Self::VALUE_SIZE];
        put_u64(
            &mut value,
            0,
            (self.blocks & PHYSICAL_LENGTH_MASK) | (u64::from(self.kind) << 60),
        );
        put_u64(&mut value, 8, self.owner);
        put_u32(&mut value, 16, self.references as u32);
        (key, value)
    }
}

/// A hard link's sibling record: the directory holding one of the inode's names, and the name
/// (Apple File System Reference, p. 115).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SiblingLink<'a> {
    /// From the key. The sibling's identifier, which the directory entry carries as well.
    pub sibling_id: u64,
    /// Offset 0. The directory holding this name.
    pub parent_id: u64,
    /// Offset 10. The name, without its terminating NUL.
    pub name: &'a [u8],
}

impl<'a> SiblingLink<'a> {
    /// Recover a sibling record from its key and value.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the key or the name is short, and
    /// [`ParseError::Unterminated`] where the name does not end in its NUL.
    pub fn read_from(key: &[u8], value: &'a [u8]) -> Result<Self, ParseError> {
        ParseError::need("sibling key", 16, key)?;
        ParseError::need("sibling", 10, value)?;
        let end = 10 + usize::from(get_u16(value, 8));
        ParseError::need("sibling name", end, value)?;
        let Some((&0, name)) = value[10..end].split_last() else {
            return Err(ParseError::Unterminated {
                structure: "sibling name",
            });
        };
        Ok(Self {
            sibling_id: get_u64(key, 8),
            parent_id: get_u64(value, 0),
            name,
        })
    }
}

impl SiblingLink<'_> {
    /// The sibling record of inode `inode` this link is: its key, the inode in the header and
    /// the sibling identifier after it, and its value, the directory, the name's length with its
    /// NUL, then the name and its NUL.
    ///
    /// # Panics
    ///
    /// Where the name with its NUL is longer than its 16-bit length holds.
    #[must_use]
    pub fn to_record(&self, inode: u64) -> (Vec<u8>, Vec<u8>) {
        let key = KeyHeader {
            id: inode,
            kind: record_kind::SIBLING_LINK,
        }
        .key(&self.sibling_id.to_le_bytes());
        let len = u16::try_from(self.name.len() + 1).expect("a name with its NUL fits 16 bits");
        let mut value = Vec::with_capacity(10 + self.name.len() + 1);
        value.extend_from_slice(&self.parent_id.to_le_bytes());
        value.extend_from_slice(&len.to_le_bytes());
        value.extend_from_slice(self.name);
        value.push(0);
        (key, value)
    }
}

/// The sibling map record of sibling identifier `sibling`: its key, and its value, the inode the
/// sibling names.
#[must_use]
pub fn sibling_map_record(sibling: u64, inode: u64) -> (Vec<u8>, Vec<u8>) {
    (
        KeyHeader {
            id: sibling,
            kind: record_kind::SIBLING_MAP,
        }
        .key(&[]),
        inode.to_le_bytes().to_vec(),
    )
}

/// The little-endian `u64` at `off` of a key, where the key reaches that far.
///
/// # Errors
///
/// [`ParseError::TooShort`] where the key is shorter than `off + 8` bytes.
pub fn key_u64(key: &[u8], off: usize) -> Result<u64, ParseError> {
    ParseError::need("record key", off + 8, key)?;
    Ok(get_u64(key, off))
}

/// A device number as Darwin's 32-bit `dev_t` packs it: the major in the high eight bits and
/// the minor in the low 24, observed on device nodes macOS created.
#[must_use]
pub const fn split_device(dev: u32) -> (u32, u32) {
    (dev >> 24, dev & 0x00FF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_header_splits_its_word_into_identifier_and_kind() {
        let mut key = [0u8; 8];
        KeyHeader {
            id: 0x1234,
            kind: record_kind::DIR_ENTRY,
        }
        .write_to(&mut key);
        assert_eq!(get_u64(&key, 0), 0x9000_0000_0000_1234);
        let header = KeyHeader::read_from(&key).expect("a header");
        assert_eq!((header.id, header.kind), (0x1234, 9));
    }

    #[test]
    fn extended_fields_pad_each_field_to_eight_bytes_after_the_descriptors() {
        // Two fields: a five-byte name and a 40-byte data stream. The descriptors take 8
        // bytes after the 4-byte head, so the name begins at 12 and the stream at 12 + 8.
        let mut blob = vec![0u8; 12 + 8 + 40];
        put_u16(&mut blob, 0, 2);
        put_u16(&mut blob, 2, (8 + 40) as u16);
        blob[4] = inode_field::NAME;
        put_u16(&mut blob, 6, 5);
        blob[8] = inode_field::DATA_STREAM;
        put_u16(&mut blob, 10, 40);
        blob[12..17].copy_from_slice(b"name\0");
        put_u64(&mut blob, 20, 4096);
        let fields = extended_fields(&blob).expect("frames");
        assert_eq!(fields.len(), 2);
        assert_eq!(field(&fields, inode_field::NAME), Some(&b"name\0"[..]));
        let stream = DataStream::read_from(field(&fields, inode_field::DATA_STREAM).unwrap());
        assert_eq!(stream.map(|s| s.size), Ok(4096));
    }

    #[test]
    fn a_field_running_past_its_value_is_refused() {
        let mut blob = vec![0u8; 16];
        put_u16(&mut blob, 0, 1);
        blob[4] = inode_field::DATA_STREAM;
        put_u16(&mut blob, 6, 40);
        assert!(matches!(
            extended_fields(&blob),
            Err(ParseError::TooShort { .. })
        ));
        // Descriptors alone claiming more fields than the blob has room for.
        put_u16(&mut blob, 0, 100);
        assert!(extended_fields(&blob).is_err());
    }

    #[test]
    fn an_inode_round_trips_with_times_before_1970() {
        let inode = InodeValue {
            parent_id: 2,
            private_id: 20,
            create_time: -1,
            modify_time: -2_208_988_800_000_000_000,
            change_time: 3,
            access_time: i64::MAX,
            internal_flags: 0x8000,
            links_or_children: 1,
            protection_class: 0,
            write_generation: 0,
            bsd_flags: 0,
            owner: 501,
            group: 20,
            mode: 0o100_644,
            pad: 0,
            uncompressed_size: 0,
        };
        let mut buf = [0u8; InodeValue::SIZE];
        inode.write_to(&mut buf);
        assert_eq!(InodeValue::read_from(&buf), Ok(inode));
        assert_eq!(get_u16(&buf, 80), 0o100_644, "the mode at 80");
    }

    #[test]
    fn a_directory_entry_key_carries_a_22_bit_hash_and_a_terminated_name() {
        let mut key = vec![0u8; 12 + 4];
        put_u32(&mut key, 8, (0x3F_FFFF << 10) | 4);
        key[12..16].copy_from_slice(b"abc\0");
        let entry = EntryKey::read_from(&key).expect("an entry");
        assert_eq!(entry.hash, 0x3F_FFFF, "all 22 bits of the hash");
        assert_eq!(entry.name, b"abc");
        // Without its NUL the name is refused rather than read short.
        key[15] = b'd';
        assert!(matches!(
            EntryKey::read_from(&key),
            Err(ParseError::Unterminated { .. })
        ));
        // A length past the key.
        put_u32(&mut key, 8, 9);
        assert!(matches!(
            EntryKey::read_from(&key),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn an_attribute_value_frames_its_data_and_a_stream_its_identifier() {
        let mut value = vec![0u8; 4 + 48];
        put_u16(&mut value, 0, xattr_flags::STREAM | 0x10);
        put_u16(&mut value, 2, 48);
        put_u64(&mut value, 4, 77);
        put_u64(&mut value, 12, 8000);
        let xattr = XattrValue::read_from(&value).expect("frames");
        assert_eq!(xattr.stream().map(|(id, s)| (id, s.size)), Ok((77, 8000)));
        put_u16(&mut value, 2, 49);
        assert!(XattrValue::read_from(&value).is_err());
    }

    #[test]
    fn an_extent_splits_its_length_from_its_flags() {
        let mut key = [0u8; 16];
        put_u64(&mut key, 8, 8192);
        let mut value = [0u8; 24];
        put_u64(&mut value, 0, 0x0100_0000_0000_1000);
        put_u64(&mut value, 8, 500);
        let extent = FileExtent::read_from(&key, &value).expect("an extent");
        assert_eq!(
            (
                extent.logical,
                extent.length,
                extent.flags,
                extent.physical_block
            ),
            (8192, 4096, 1, 500)
        );
    }

    #[test]
    fn a_sibling_record_names_the_directory_and_the_name_it_links() {
        // The key: inode 20, kind 5, then the sibling's identifier. The value: the directory,
        // the name's length with its terminator, then the name.
        let mut key = vec![0u8; 16];
        put_u64(
            &mut key,
            0,
            20 | (u64::from(record_kind::SIBLING_LINK) << KIND_SHIFT),
        );
        put_u64(&mut key, 8, 30);
        let mut value = vec![0u8; 10];
        put_u64(&mut value, 0, 17);
        put_u16(&mut value, 8, 6);
        value.extend_from_slice(b"hard2\0");
        let link = SiblingLink::read_from(&key, &value).expect("a sibling record");
        assert_eq!(
            (link.sibling_id, link.parent_id, link.name),
            (30, 17, &b"hard2"[..])
        );
        // A name past the value, a name without its terminator, and a key too short to hold
        // the identifier.
        assert!(SiblingLink::read_from(&key, &value[..15]).is_err());
        let mut unended = value.clone();
        *unended.last_mut().expect("a byte") = b'!';
        assert!(matches!(
            SiblingLink::read_from(&key, &unended),
            Err(ParseError::Unterminated { .. })
        ));
        assert!(SiblingLink::read_from(&key[..12], &value).is_err());
    }

    #[test]
    fn a_darwin_device_number_has_its_major_in_the_top_byte() {
        assert_eq!(split_device(0x0300_0004), (3, 4));
        assert_eq!(split_device(0x00FF_FFFF), (0, 0x00FF_FFFF));
    }
}
