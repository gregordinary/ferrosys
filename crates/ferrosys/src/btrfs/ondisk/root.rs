//! The root item: one record in the root tree per tree the filesystem has, saying where that
//! tree's top block is.
//!
//! Everything except the chunk tree is reached through one of these. The superblock names the
//! root tree and the chunk tree; the root tree names the extent, device, checksum, uuid,
//! free-space, and block-group trees, the top-level filesystem tree, and one more per
//! subvolume.
//!
//! # The two halves, and why only one is modelled
//!
//! A root item opens with a whole embedded inode item — 160 bytes describing the subvolume's
//! root directory — and continues with the fields below. The embedded half is not modelled
//! here: reading it is reading an inode, which is the filesystem view's work rather than the
//! address space's, and the offsets below are stated from the start of the item so that adding
//! it later moves nothing.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::Timestamp;
use crate::bytes::{get_arr, get_u8, get_u32, get_u64, put_arr, put_u8, put_u32, put_u64};
use crate::flags::flag_set;

use super::{DiskKey, ParseError};

/// A `btrfs_timespec`: seconds since the epoch and nanoseconds within the second.
///
/// Twelve bytes — a 64-bit second and a 32-bit fraction — which is what lets btrfs hold every
/// property a host file's times carry, where a format storing whole seconds cannot.
pub const TIMESPEC_SIZE: usize = 12;

/// Recover a `btrfs_timespec` at `off` in `buf`.
///
/// The seconds are read as signed, which is how the format spells a date before the epoch and
/// what the baseline's own rendering shows for a root item whose times were never set.
///
/// # Panics
///
/// Where `buf` does not hold [`TIMESPEC_SIZE`] bytes at `off`. Every caller has already
/// length-checked the record the field sits in.
#[must_use]
pub fn read_timespec(buf: &[u8], off: usize) -> Timestamp {
    Timestamp {
        secs: get_u64(buf, off) as i64,
        nanos: get_u32(buf, off + 8),
    }
}

/// Write a `btrfs_timespec` at `off` in `buf`.
///
/// # Panics
///
/// Where `buf` does not hold [`TIMESPEC_SIZE`] bytes at `off`.
pub fn write_timespec(buf: &mut [u8], off: usize, time: Timestamp) {
    put_u64(buf, off, time.secs as u64);
    put_u32(buf, off + 8, time.nanos);
}

/// What a subvolume's root item says about the subvolume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RootFlags(u64);

flag_set!(RootFlags: u64);

impl RootFlags {
    /// The subvolume is read-only — what a snapshot taken for sending carries.
    pub const SUBVOL_RDONLY: Self = Self(1 << 0);
    /// The subvolume has been deleted and is still visible as a directory until the deletion
    /// finishes.
    pub const SUBVOL_DEAD: Self = Self(1 << 48);
}

/// Where one tree's top block is, and what the tree is.
///
/// Coverage is partial and the attribute is what makes widening it a patch: the embedded inode
/// item at the front and the eight reserved words at the back are not modelled, and
/// [`write_to`](Self::write_to) leaves both exactly as it found them in the buffer it was
/// handed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct RootItem {
    /// Offset 160. The transaction that last wrote this tree.
    pub generation: u64,
    /// Offset 168. The objectid of this subvolume's root directory, which is 256 for a
    /// subvolume and 0 for a tree with no directory in it.
    pub root_dirid: u64,
    /// Offset 176. The logical address of the tree's top block.
    pub bytenr: u64,
    /// Offset 184. A size limit, unused by any kernel.
    pub byte_limit: u64,
    /// Offset 192. How many bytes the tree occupies.
    pub bytes_used: u64,
    /// Offset 200. The transaction of the last snapshot taken of this tree.
    pub last_snapshot: u64,
    /// Offset 208. What the subvolume is.
    pub flags: RootFlags,
    /// Offset 216. How many references the tree has.
    pub refs: u32,
    /// Offset 220, 17 bytes. How far a deletion of this tree has got.
    pub drop_progress: DiskKey,
    /// Offset 237. The level that deletion had reached.
    pub drop_level: u8,
    /// Offset 238. The height of the tree's top block, zero where it is a leaf.
    pub level: u8,
    /// Offset 239. A copy of [`generation`](Self::generation) made when the fields after it
    /// were written. Where the two differ, an older kernel wrote the item and everything
    /// below is stale.
    pub generation_v2: u64,
    /// Offset 247, 16 bytes. This subvolume's own id.
    pub uuid: [u8; 16],
    /// Offset 263, 16 bytes. The subvolume this one was snapshotted from.
    pub parent_uuid: [u8; 16],
    /// Offset 279, 16 bytes. The id this subvolume carried when it was sent, for one received
    /// from elsewhere.
    pub received_uuid: [u8; 16],
    /// Offset 295. The transaction an inode of this subvolume last changed in.
    pub ctransid: u64,
    /// Offset 303. The transaction the subvolume was created in.
    pub otransid: u64,
    /// Offset 311. The transaction it was sent in.
    pub stransid: u64,
    /// Offset 319. The transaction it was received in.
    pub rtransid: u64,
    /// Offset 327. When an inode of it last changed.
    pub ctime: Timestamp,
    /// Offset 339. When it was created.
    pub otime: Timestamp,
    /// Offset 351. When it was sent.
    pub stime: Timestamp,
    /// Offset 363. When it was received.
    pub rtime: Timestamp,
}

impl RootItem {
    /// Bytes on disk, the unmodelled halves included.
    pub const SIZE: usize = 439;

    /// Bytes the embedded inode item occupies at the front, which this type does not model.
    pub const INODE_LEN: usize = 160;

    /// Recover a root item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a root item. A root item written
    /// by a kernel older than the fields after `generation_v2` is genuinely shorter, and is
    /// refused rather than filled in: this crate reads filesystems the pinned baseline and
    /// any current kernel produce, and a short item would otherwise be completed with values
    /// nothing on the disk supports.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_root_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            generation: get_u64(buf, 160),
            root_dirid: get_u64(buf, 168),
            bytenr: get_u64(buf, 176),
            byte_limit: get_u64(buf, 184),
            bytes_used: get_u64(buf, 192),
            last_snapshot: get_u64(buf, 200),
            flags: RootFlags::from_bits(get_u64(buf, 208)),
            refs: get_u32(buf, 216),
            drop_progress: DiskKey::read_from(&buf[220..220 + DiskKey::SIZE])?,
            drop_level: get_u8(buf, 237),
            level: get_u8(buf, 238),
            generation_v2: get_u64(buf, 239),
            uuid: get_arr(buf, 247),
            parent_uuid: get_arr(buf, 263),
            received_uuid: get_arr(buf, 279),
            ctransid: get_u64(buf, 295),
            otransid: get_u64(buf, 303),
            stransid: get_u64(buf, 311),
            rtransid: get_u64(buf, 319),
            ctime: read_timespec(buf, 327),
            otime: read_timespec(buf, 339),
            stime: read_timespec(buf, 351),
            rtime: read_timespec(buf, 363),
        })
    }

    /// Write the modelled fields into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The embedded inode item and the reserved words are left exactly as they were.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a root item.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a root item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 160, self.generation);
        put_u64(buf, 168, self.root_dirid);
        put_u64(buf, 176, self.bytenr);
        put_u64(buf, 184, self.byte_limit);
        put_u64(buf, 192, self.bytes_used);
        put_u64(buf, 200, self.last_snapshot);
        put_u64(buf, 208, self.flags.bits());
        put_u32(buf, 216, self.refs);
        self.drop_progress
            .write_to(&mut buf[220..220 + DiskKey::SIZE]);
        put_u8(buf, 237, self.drop_level);
        put_u8(buf, 238, self.level);
        put_u64(buf, 239, self.generation_v2);
        put_arr(buf, 247, &self.uuid);
        put_arr(buf, 263, &self.parent_uuid);
        put_arr(buf, 279, &self.received_uuid);
        put_u64(buf, 295, self.ctransid);
        put_u64(buf, 303, self.otransid);
        put_u64(buf, 311, self.stransid);
        put_u64(buf, 319, self.rtransid);
        write_timespec(buf, 327, self.ctime);
        write_timespec(buf, 339, self.otime);
        write_timespec(buf, 351, self.stime);
        write_timespec(buf, 363, self.rtime);
    }
}

#[cfg(test)]
mod tests {
    use super::super::ItemType;
    use super::*;

    fn a_root_item() -> RootItem {
        RootItem {
            generation: 5,
            root_dirid: 256,
            bytenr: 30_441_472,
            byte_limit: 0,
            bytes_used: 16_384,
            last_snapshot: 0,
            flags: RootFlags::NONE,
            refs: 1,
            drop_progress: DiskKey::new(0, ItemType::from_value(0), 0),
            drop_level: 0,
            level: 0,
            generation_v2: 5,
            uuid: [0x17; 16],
            parent_uuid: [0; 16],
            received_uuid: [0; 16],
            ctransid: 0,
            otransid: 0,
            stransid: 0,
            rtransid: 0,
            ctime: Timestamp {
                secs: 1_786_392_177,
                nanos: 0,
            },
            otime: Timestamp {
                secs: 1_786_392_177,
                nanos: 0,
            },
            stime: Timestamp::from_secs(0),
            rtime: Timestamp::from_secs(0),
        }
    }

    #[test]
    fn a_root_item_round_trips_through_its_four_hundred_and_thirty_nine_bytes() {
        let item = a_root_item();
        let mut buf = [0u8; RootItem::SIZE];
        item.write_to(&mut buf);
        assert_eq!(RootItem::read_from(&buf).expect("a full item"), item);
        // The three fields that make a tree reachable, at the offsets the format puts them.
        assert_eq!(&buf[176..184], &30_441_472u64.to_le_bytes());
        assert_eq!(buf[238], 0, "the level");
        assert_eq!(&buf[160..168], &5u64.to_le_bytes(), "the generation");
    }

    #[test]
    fn the_unmodelled_halves_survive_a_write() {
        // The embedded inode at the front and the reserved words at the back. A write that
        // zeroed either would make a re-serialized item differ from the one that was read,
        // which is what a checksum over a leaf would then disagree about.
        let item = a_root_item();
        let mut buf = [0x77u8; RootItem::SIZE];
        item.write_to(&mut buf);
        assert!(buf[..RootItem::INODE_LEN].iter().all(|&b| b == 0x77));
        assert!(buf[375..].iter().all(|&b| b == 0x77), "the reserved words");
    }

    #[test]
    fn a_time_before_the_epoch_is_read_as_one() {
        // The seconds are signed on the way in, which is how the baseline renders a root item
        // whose times were never set on a machine west of Greenwich.
        let mut buf = [0u8; RootItem::SIZE];
        a_root_item().write_to(&mut buf);
        write_timespec(
            &mut buf,
            327,
            Timestamp {
                secs: -18_000,
                nanos: 500,
            },
        );
        let item = RootItem::read_from(&buf).expect("a full item");
        assert_eq!(
            item.ctime,
            Timestamp {
                secs: -18_000,
                nanos: 500
            }
        );
    }

    #[test]
    fn an_item_shorter_than_the_format_writes_is_refused_rather_than_completed() {
        assert!(matches!(
            RootItem::read_from(&[0u8; RootItem::SIZE - 1]),
            Err(ParseError::TooShort {
                need: 439,
                got: 438,
                ..
            })
        ));
    }

    #[test]
    fn a_read_only_subvolume_says_so_in_the_bit_the_format_gives_it() {
        let item = RootItem {
            flags: RootFlags::SUBVOL_RDONLY,
            ..a_root_item()
        };
        let mut buf = [0u8; RootItem::SIZE];
        item.write_to(&mut buf);
        assert_eq!(&buf[208..216], &1u64.to_le_bytes());
        assert!(
            RootItem::read_from(&buf)
                .expect("a full item")
                .flags
                .contains(RootFlags::SUBVOL_RDONLY)
        );
    }
}
