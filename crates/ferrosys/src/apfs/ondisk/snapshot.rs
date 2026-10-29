//! A volume's snapshots: the records of its snapshot tree, and the object holding each one's
//! identifier.
//!
//! A snapshot is a volume's state at one transaction, kept by not releasing what that state
//! reaches (Apple File System Reference, pp. 117-121). The volume superblock names a physical
//! tree holding two records per snapshot: one keyed by the snapshot's transaction, holding its
//! metadata, and one keyed by its name, holding the transaction. Each layout below was also
//! located on images macOS wrote, by searching for the name, transaction, identifier and
//! creation time that macOS's own tools printed for each snapshot, and each sat at one offset
//! in every image on macOS 15, 26 and 27.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_arr, get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};

use super::{KeyHeader, ParseError, record_kind};

/// The identifier a snapshot-name record's key carries: every bit of the 60 an identifier has.
pub const SNAPSHOT_NAME_ID: u64 = 0x0FFF_FFFF_FFFF_FFFF;

/// A snapshot's metadata record: what its key's identifier, the snapshot's transaction, leads
/// to (Apple File System Reference, p. 117).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SnapshotMeta {
    /// From the key. The transaction that records the snapshot.
    pub xid: u64,
    /// Offset 0. The extent-reference tree the volume held until the snapshot.
    pub extent_ref_tree_oid: u64,
    /// Offset 8. The block holding the copy of the volume superblock the snapshot keeps.
    pub superblock: u64,
    /// Offset 16. When the snapshot was created, in nanoseconds since 1970.
    pub create_time: i64,
    /// Offset 24. When it was last changed; observed equal to the creation time.
    pub change_time: i64,
    /// Offset 32. The volume's next object identifier when the snapshot was taken.
    pub next_object_id: u64,
    /// Offset 40. The type word of the extent-reference tree at offset 0.
    pub extent_ref_tree_type: u32,
    /// Offset 44. `0x1` dataless and pending, `0x2` a merge in progress; zero on every
    /// snapshot macOS was observed to keep.
    pub flags: u32,
    /// Offset 50. The snapshot's name, without the terminating NUL the record stores.
    pub name: Vec<u8>,
}

impl SnapshotMeta {
    /// Bytes before the name.
    pub const SIZE: usize = 50;

    /// Recover a metadata record from its key and value.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the key or value is short or the name runs past the
    /// value, and [`ParseError::Unterminated`] where the name does not end in its NUL.
    pub fn read_from(key: &[u8], value: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("snapshot metadata key", 8, key)?;
        ParseError::need("snapshot metadata", Self::SIZE, value)?;
        let end = Self::SIZE + usize::from(get_u16(value, 48));
        ParseError::need("snapshot name", end, value)?;
        let Some((&0, name)) = value[Self::SIZE..end].split_last() else {
            return Err(ParseError::Unterminated {
                structure: "snapshot name",
            });
        };
        Ok(Self {
            xid: get_u64(key, 0) & super::ID_MASK,
            extent_ref_tree_oid: get_u64(value, 0),
            superblock: get_u64(value, 8),
            create_time: get_u64(value, 16) as i64,
            change_time: get_u64(value, 24) as i64,
            next_object_id: get_u64(value, 32),
            extent_ref_tree_type: get_u32(value, 40),
            flags: get_u32(value, 44),
            name: name.to_vec(),
        })
    }

    /// The record's key and value, as [`read_from`](Self::read_from) reads them.
    ///
    /// # Panics
    ///
    /// Where the name with its NUL is longer than the 16 bits that count it.
    #[must_use]
    pub fn to_record(&self) -> (Vec<u8>, Vec<u8>) {
        let key = KeyHeader {
            id: self.xid,
            kind: record_kind::SNAPSHOT_META,
        }
        .key(&[]);
        let mut value = vec![0u8; Self::SIZE];
        put_u64(&mut value, 0, self.extent_ref_tree_oid);
        put_u64(&mut value, 8, self.superblock);
        put_u64(&mut value, 16, self.create_time as u64);
        put_u64(&mut value, 24, self.change_time as u64);
        put_u64(&mut value, 32, self.next_object_id);
        put_u32(&mut value, 40, self.extent_ref_tree_type);
        put_u32(&mut value, 44, self.flags);
        put_u16(&mut value, 48, name_len(&self.name));
        value.extend_from_slice(&self.name);
        value.push(0);
        (key, value)
    }
}

/// A snapshot's name record: the key carries the name, counted with its NUL in a u16 at 8 and
/// stored with it from 10, under [`SNAPSHOT_NAME_ID`], and the value is the snapshot's
/// transaction.
///
/// # Panics
///
/// Where the name with its NUL is longer than the 16 bits that count it.
#[must_use]
pub fn snapshot_name_record(name: &[u8], xid: u64) -> (Vec<u8>, Vec<u8>) {
    let mut tail = name_len(name).to_le_bytes().to_vec();
    tail.extend_from_slice(name);
    tail.push(0);
    let key = KeyHeader {
        id: SNAPSHOT_NAME_ID,
        kind: record_kind::SNAPSHOT_NAME,
    }
    .key(&tail);
    (key, xid.to_le_bytes().to_vec())
}

/// The length a snapshot's name is recorded with: its bytes and the NUL after them.
fn name_len(name: &[u8]) -> u16 {
    u16::try_from(name.len() + 1).expect("a snapshot's name with its NUL fits 16 bits")
}

/// The object holding a snapshot's identifier, one version of it per snapshot, each written at
/// that snapshot's transaction (Apple File System Reference, p. 120).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotExtension {
    /// Offset 32. The layout's version; 1 on every one seen.
    pub version: u32,
    /// Offset 36. Flags; zero on every one seen.
    pub flags: u32,
    /// Offset 40. The snapshot's transaction.
    pub xid: u64,
    /// Offset 48. The snapshot's identifier, in the byte order macOS prints it.
    pub uuid: [u8; 16],
    /// Offset 64. An opaque value.
    pub token: u64,
}

impl SnapshotExtension {
    /// Bytes on disk, header included.
    pub const SIZE: usize = 72;

    /// Recover the extension object from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("snapshot extension", Self::SIZE, buf)?;
        Ok(Self {
            version: get_u32(buf, 32),
            flags: get_u32(buf, 36),
            xid: get_u64(buf, 40),
            uuid: get_arr(buf, 48),
            token: get_u64(buf, 64),
        })
    }

    /// Write the fields past the object header into the first [`SIZE`](Self::SIZE) bytes of
    /// `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a snapshot extension needs 72 bytes"
        );
        put_u32(buf, 32, self.version);
        put_u32(buf, 36, self.flags);
        put_u64(buf, 40, self.xid);
        buf[48..64].copy_from_slice(&self.uuid);
        put_u64(buf, 64, self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{put_u16, put_u64};

    #[test]
    fn a_metadata_record_carries_its_name_after_fifty_bytes() {
        let mut key = [0u8; 8];
        put_u64(&mut key, 0, (1 << 60) | 34);
        let mut value = vec![0u8; 50];
        put_u64(&mut value, 8, 900);
        put_u64(&mut value, 16, 1_700_000_000_000_000_000);
        put_u16(&mut value, 48, 5);
        value.extend_from_slice(b"snap\0");
        let meta = SnapshotMeta::read_from(&key, &value).expect("a record");
        assert_eq!((meta.xid, meta.superblock), (34, 900));
        assert_eq!(meta.name, b"snap");
        value.pop();
        assert!(SnapshotMeta::read_from(&key, &value).is_err());
    }

    #[test]
    fn a_metadata_record_reads_back_as_it_was_written() {
        let meta = SnapshotMeta {
            xid: 2,
            extent_ref_tree_oid: 1063,
            superblock: 1410,
            create_time: 1_700_000_000_000_000_000,
            change_time: 1_700_000_000_000_000_000,
            next_object_id: 76,
            extent_ref_tree_type: 0x4000_0002,
            flags: 0,
            name: b"root".to_vec(),
        };
        let (key, value) = meta.to_record();
        assert_eq!(value.len(), SnapshotMeta::SIZE + 5);
        assert_eq!(
            SnapshotMeta::read_from(&key, &value).expect("a record"),
            meta
        );
    }

    #[test]
    fn a_name_record_carries_its_counted_name_after_ten_bytes() {
        let (key, value) = snapshot_name_record(b"root", 2);
        assert_eq!(
            get_u64(&key, 0) >> 60,
            u64::from(record_kind::SNAPSHOT_NAME)
        );
        assert_eq!(get_u64(&key, 0) & super::super::ID_MASK, SNAPSHOT_NAME_ID);
        assert_eq!(get_u16(&key, 8), 5);
        assert_eq!(&key[10..], b"root\0");
        assert_eq!(value, 2u64.to_le_bytes());
    }

    #[test]
    fn an_extension_holds_the_identifier_at_forty_eight() {
        let mut buf = [0u8; 72];
        put_u64(&mut buf, 40, 34);
        buf[48..64].copy_from_slice(&[0xAB; 16]);
        let ext = SnapshotExtension::read_from(&buf).expect("an extension");
        assert_eq!((ext.xid, ext.uuid), (34, [0xAB; 16]));
        let mut written = [0u8; 72];
        ext.write_to(&mut written);
        assert_eq!(written, buf);
    }
}
