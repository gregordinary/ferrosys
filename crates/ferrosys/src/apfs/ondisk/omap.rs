//! The object map: what turns a virtual object's identifier, at a transaction, into a block.
//!
//! The container has one object map and every volume has its own (Apple File System
//! Reference, pp. 44-50). Each is a small header object pointing at a B-tree whose records are
//! keyed by identifier and transaction and whose values give the block. A virtual object is
//! never rewritten in place: a change writes a new copy elsewhere and adds a record at the new
//! transaction, so the map holds every version some snapshot or the live tree still reaches.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u32, get_u64, put_u32, put_u64};

use super::{ObjectHeader, ParseError};

/// The object map's header object (Apple File System Reference, p. 44).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectMap {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. The map's flags. `0x1` marks a map that keeps no snapshots; `0x2`, `0x4`
    /// and `0x8` mark one in the middle of encrypting, decrypting or changing keys.
    pub flags: u32,
    /// Offset 36. How many snapshots the map keeps versions for; observed equal to the number
    /// of snapshots macOS lists for the volume.
    pub snapshot_count: u32,
    /// Offset 40. The type word of the mapping tree's root.
    pub tree_type: u32,
    /// Offset 44. The type word of the snapshot tree's root.
    pub snapshot_tree_type: u32,
    /// Offset 48. The mapping tree's root, a physical address.
    pub tree_oid: u64,
    /// Offset 56. The tree of snapshots, keyed by transaction, or zero with none.
    pub snapshot_tree_oid: u64,
    /// Offset 64. The newest snapshot's transaction, or zero with none.
    pub most_recent_snapshot: u64,
    /// Offset 72. The oldest transaction a revert in progress is undoing.
    pub pending_revert_min: u64,
    /// Offset 80. The newest.
    pub pending_revert_max: u64,
}

/// The flag of a record that stands for a deleted object (Apple File System Reference, p. 48).
/// Its address is the block of the version it replaces, which the main free queue holds as
/// freed: observed on volumes holding snapshots, macOS 14, 15 and 26, where every such address
/// is in the queue and none is a block anything else reaches.
pub const MAP_VALUE_DELETED: u32 = 0x1;

/// The object map flags that say a change of its volume's encryption is in progress: its
/// objects being encrypted, decrypted, or re-keyed (Apple File System Reference, p. 49).
pub const MAP_CRYPTO_CHANGING: u32 = 0x2 | 0x4 | 0x8;

/// The flag of an object map, and of each record in it, that names the encryption configuration
/// the object was last written under (Apple File System Reference, pp. 48 and 50). Whether an
/// object is encrypted is its record's own flag, `0x4`. Clear on every map and record macOS 14,
/// 15, 26 and 27 were observed to write, through two encryptions and two decryptions of one
/// volume and on volumes made encrypted.
pub const CRYPTO_GENERATION: u32 = 0x10;

impl ObjectMap {
    /// Bytes on disk.
    pub const SIZE: usize = 88;

    /// Recover an object map header from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("object map", Self::SIZE, buf)?;
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            flags: get_u32(buf, 32),
            snapshot_count: get_u32(buf, 36),
            tree_type: get_u32(buf, 40),
            snapshot_tree_type: get_u32(buf, 44),
            tree_oid: get_u64(buf, 48),
            snapshot_tree_oid: get_u64(buf, 56),
            most_recent_snapshot: get_u64(buf, 64),
            pending_revert_min: get_u64(buf, 72),
            pending_revert_max: get_u64(buf, 80),
        })
    }

    /// Write the header object into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an object map needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.header.write_to(buf);
        put_u32(buf, 32, self.flags);
        put_u32(buf, 36, self.snapshot_count);
        put_u32(buf, 40, self.tree_type);
        put_u32(buf, 44, self.snapshot_tree_type);
        put_u64(buf, 48, self.tree_oid);
        put_u64(buf, 56, self.snapshot_tree_oid);
        put_u64(buf, 64, self.most_recent_snapshot);
        put_u64(buf, 72, self.pending_revert_min);
        put_u64(buf, 80, self.pending_revert_max);
    }
}

/// A mapping record's key: an identifier and the transaction its version was written in.
/// Records sort by identifier and then by transaction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MapKey {
    /// Offset 0. The virtual object's identifier.
    pub oid: u64,
    /// Offset 8. The transaction this version of it was written in.
    pub xid: u64,
}

impl MapKey {
    /// Bytes on disk.
    pub const SIZE: usize = 16;

    /// Recover a key from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a key.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("object map key", Self::SIZE, buf)?;
        Ok(Self {
            oid: get_u64(buf, 0),
            xid: get_u64(buf, 8),
        })
    }

    /// Write the key into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a key.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "an object map key needs 16 bytes");
        put_u64(buf, 0, self.oid);
        put_u64(buf, 8, self.xid);
    }
}

/// A mapping record's value: where that version of the object is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MapValue {
    /// Offset 0. Flags on this version: zero in every record of an unencrypted volume macOS
    /// 14, 15, 26 and 27 were observed to write but a deleted object's ([`MAP_VALUE_DELETED`]),
    /// and `0x4` encrypted in every record of an encrypted one. The reference defines `0x1`
    /// deleted, `0x2` saved, `0x4` encrypted, `0x8` stored without a header and
    /// [`CRYPTO_GENERATION`] (p. 48).
    pub flags: u32,
    /// Offset 4. The object's size in bytes, a whole number of blocks.
    pub size: u32,
    /// Offset 8. The block it begins at.
    pub address: u64,
}

impl MapValue {
    /// Bytes on disk.
    pub const SIZE: usize = 16;

    /// Recover a value from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a value.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("object map value", Self::SIZE, buf)?;
        Ok(Self {
            flags: get_u32(buf, 0),
            size: get_u32(buf, 4),
            address: get_u64(buf, 8),
        })
    }

    /// Write the value into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a value.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an object map value needs 16 bytes"
        );
        put_u32(buf, 0, self.flags);
        put_u32(buf, 4, self.size);
        put_u64(buf, 8, self.address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_header_round_trips() {
        let map = ObjectMap {
            header: ObjectHeader {
                checksum: 1,
                oid: 300,
                xid: 4,
                type_word: 0x4000_000B,
                subtype: 0,
            },
            flags: 1,
            snapshot_count: 2,
            tree_type: 0x4000_0002,
            snapshot_tree_type: 0x4000_0002,
            tree_oid: 301,
            snapshot_tree_oid: 302,
            most_recent_snapshot: 40,
            pending_revert_min: 0,
            pending_revert_max: 0,
        };
        let mut buf = [0u8; ObjectMap::SIZE];
        map.write_to(&mut buf);
        assert_eq!(ObjectMap::read_from(&buf), Ok(map));
        assert_eq!(get_u64(&buf, 48), 301, "the tree at 48");
    }

    #[test]
    fn a_record_round_trips_and_keys_sort_by_identifier_then_transaction() {
        let key = MapKey { oid: 1026, xid: 7 };
        let value = MapValue {
            flags: 0,
            size: 4096,
            address: 900,
        };
        let (mut k, mut v) = ([0u8; 16], [0u8; 16]);
        key.write_to(&mut k);
        value.write_to(&mut v);
        assert_eq!(MapKey::read_from(&k), Ok(key));
        assert_eq!(MapValue::read_from(&v), Ok(value));
        assert!(MapKey { oid: 1, xid: 9 } < MapKey { oid: 2, xid: 1 });
        assert!(MapKey { oid: 2, xid: 1 } < MapKey { oid: 2, xid: 3 });
    }
}
