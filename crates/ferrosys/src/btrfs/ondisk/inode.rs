//! The inode item and the two records that give an inode its names.
//!
//! A btrfs inode is a record in a filesystem tree, keyed by `(inode number, INODE_ITEM, 0)`.
//! It holds what a `stat` reports and nothing about where the file's bytes are or what the
//! file is called: names are [`InodeRef`] and [`InodeExtref`] records, and bytes are
//! `EXTENT_DATA` records, each keyed under the same inode number so all three are one
//! contiguous run of the tree.
//!
//! # Four times, all of them whole
//!
//! Every time is a 64-bit second and a 32-bit nanosecond, and there are four rather than
//! three: btrfs is one of the few formats that records **when a file was created**. So an
//! inode read here loses nothing a host file's timestamps carry, and a birth time survives a
//! round trip through an image.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::Timestamp;
use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};
use crate::flags::flag_set;

use super::{Packed, ParseError, read_timespec, write_timespec};

/// What an inode's `flags` word says about how the filesystem treats it.
///
/// These are the flags a filesystem *acts* on rather than the ones `chattr` reports back
/// unchanged, and two of them change what a reader must do:
/// [`NODATASUM`](Self::NODATASUM) says the file's bytes have no checksums to verify, and
/// [`PREALLOC`](Self::PREALLOC) says an extent may be allocated and hold nothing yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InodeFlags(u64);

flag_set!(InodeFlags: u64);

impl InodeFlags {
    /// The file's data extents carry no checksums, so there is nothing in the checksum tree
    /// to hold them against.
    pub const NODATASUM: Self = Self(1 << 0);
    /// The file's data is written in place rather than copied on write.
    pub const NODATACOW: Self = Self(1 << 1);
    /// The file is read-only.
    pub const READONLY: Self = Self(1 << 2);
    /// The file is never compressed.
    pub const NOCOMPRESS: Self = Self(1 << 3);
    /// The file has extents that are allocated and hold nothing, which read back as zeros.
    pub const PREALLOC: Self = Self(1 << 4);
    /// Writes to the file are synchronous.
    pub const SYNC: Self = Self(1 << 5);
    /// The file cannot be changed at all.
    pub const IMMUTABLE: Self = Self(1 << 6);
    /// The file can only be added to.
    pub const APPEND: Self = Self(1 << 7);
    /// The file is not to be included in a dump.
    pub const NODUMP: Self = Self(1 << 8);
    /// The file's access time is not updated.
    pub const NOATIME: Self = Self(1 << 9);
    /// Directory changes are written synchronously.
    pub const DIRSYNC: Self = Self(1 << 10);
    /// The file is compressed whether or not the mount asked for compression.
    pub const COMPRESS: Self = Self(1 << 11);
}

/// What a `stat` of one file, directory, or device node reports, as the filesystem tree
/// records it.
///
/// Coverage is partial in one place and the attribute is what makes widening it a patch: the
/// four reserved words at offset 80 are not modelled, and [`write_to`](Self::write_to) leaves
/// them exactly as it found them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct InodeItem {
    /// Offset 0. The transaction the inode was created in.
    pub generation: u64,
    /// Offset 8. The transaction it was last changed in.
    pub transid: u64,
    /// Offset 16. The file's length in bytes — the length of a symlink's target for a link,
    /// and the length of the entry records for a directory.
    pub size: u64,
    /// Offset 24. How many bytes of the volume the file occupies, which is below
    /// [`size`](Self::size) for a sparse or compressed file.
    pub nbytes: u64,
    /// Offset 32. A block group hint no current kernel reads.
    pub block_group: u64,
    /// Offset 40. How many names the inode has.
    pub nlink: u32,
    /// Offset 44. Owning user.
    pub uid: u32,
    /// Offset 48. Owning group.
    pub gid: u32,
    /// Offset 52. The file type and permission bits. **A 32-bit field**, where a host's mode
    /// is 16 bits: the type and permission bits are all in the low half, and the high half is
    /// zero on every filesystem in circulation.
    pub mode: u32,
    /// Offset 56. The device a character- or block-special node names, in the kernel's
    /// encoding.
    pub rdev: u64,
    /// Offset 64. How the filesystem treats the file.
    pub flags: InodeFlags,
    /// Offset 72. A modification sequence number.
    pub sequence: u64,
    /// Offset 112. When the file was last read.
    pub atime: Timestamp,
    /// Offset 124. When its inode last changed.
    pub ctime: Timestamp,
    /// Offset 136. When its contents last changed.
    pub mtime: Timestamp,
    /// Offset 148. **When it was created** — the time a format with three timestamps has no
    /// field for.
    pub otime: Timestamp,
}

impl InodeItem {
    /// Bytes on disk, the reserved words included.
    pub const SIZE: usize = 160;

    /// The file-type bits of [`mode`](Self::mode), which say what the inode is; the rest are
    /// the permission bits and the `setuid`, `setgid`, and sticky bits.
    pub const MODE_TYPE_MASK: u32 = 0o170000;

    /// How many low bits of [`rdev`](Self::rdev) are a device's minor number.
    pub const MINOR_BITS: u32 = 20;

    /// Those bits, as a mask.
    pub const MINOR_MASK: u32 = (1 << Self::MINOR_BITS) - 1;

    /// Recover an inode item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than an inode item.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_inode_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            generation: get_u64(buf, 0),
            transid: get_u64(buf, 8),
            size: get_u64(buf, 16),
            nbytes: get_u64(buf, 24),
            block_group: get_u64(buf, 32),
            nlink: get_u32(buf, 40),
            uid: get_u32(buf, 44),
            gid: get_u32(buf, 48),
            mode: get_u32(buf, 52),
            rdev: get_u64(buf, 56),
            flags: InodeFlags::from_bits(get_u64(buf, 64)),
            sequence: get_u64(buf, 72),
            atime: read_timespec(buf, 112),
            ctime: read_timespec(buf, 124),
            mtime: read_timespec(buf, 136),
            otime: read_timespec(buf, 148),
        })
    }

    /// Write the modelled fields into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The reserved words are left exactly as they were.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than an inode item.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "an inode item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.generation);
        put_u64(buf, 8, self.transid);
        put_u64(buf, 16, self.size);
        put_u64(buf, 24, self.nbytes);
        put_u64(buf, 32, self.block_group);
        put_u32(buf, 40, self.nlink);
        put_u32(buf, 44, self.uid);
        put_u32(buf, 48, self.gid);
        put_u32(buf, 52, self.mode);
        put_u64(buf, 56, self.rdev);
        put_u64(buf, 64, self.flags.bits());
        put_u64(buf, 72, self.sequence);
        write_timespec(buf, 112, self.atime);
        write_timespec(buf, 124, self.ctime);
        write_timespec(buf, 136, self.mtime);
        write_timespec(buf, 148, self.otime);
    }

    /// The file-type bits of [`mode`](Self::mode), alone.
    #[must_use]
    pub const fn mode_type(&self) -> u32 {
        self.mode & Self::MODE_TYPE_MASK
    }

    /// The device number a character- or block-special node names, as `(major, minor)`.
    ///
    /// btrfs stores the kernel's own encoding of a device number rather than the two halves,
    /// so this is where it is taken apart: **the low twenty bits are the minor and everything
    /// above is the major**. That is one encoding, unlike the pair a format predating 20-bit
    /// minors carries, and a node whose minor is above 255 round-trips through it.
    #[must_use]
    pub const fn device(&self) -> (u32, u32) {
        let raw = self.rdev as u32;
        (raw >> Self::MINOR_BITS, raw & Self::MINOR_MASK)
    }

    /// The kernel's encoding of `(major, minor)`, which is what [`rdev`](Self::rdev) holds.
    #[must_use]
    pub const fn encode_device(major: u32, minor: u32) -> u64 {
        ((major << Self::MINOR_BITS) | (minor & Self::MINOR_MASK)) as u64
    }
}

/// One name an inode has in one directory, packed with any others it has in that same
/// directory.
///
/// An `INODE_REF` is keyed by `(inode, INODE_REF, parent directory)`, so one item covers every
/// name an inode has in one parent — a file hard-linked twice into the same directory has one
/// item holding two of these.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InodeRef {
    /// The entry's sequence number in the parent directory, which is what a `DIR_INDEX` is
    /// keyed by.
    pub index: u64,
    /// How many bytes of name follow the head.
    pub name_len: u16,
}

impl InodeRef {
    /// Bytes the fixed head occupies, before the name.
    pub const SIZE: usize = 10;

    /// Recover the head from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a head.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_inode_ref",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            index: get_u64(buf, 0),
            name_len: get_u16(buf, 8),
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
            "an inode ref needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.index);
        put_u16(buf, 8, self.name_len);
    }
}

impl Packed for InodeRef {
    const STRUCTURE: &'static str = "btrfs_inode_ref";
    const HEAD: usize = Self::SIZE;

    fn read_head(buf: &[u8]) -> Result<Self, ParseError> {
        Self::read_from(buf)
    }

    fn encoded_len(&self) -> usize {
        Self::SIZE + self.name_len as usize
    }
}

/// One name an inode has, for an inode with more names than an [`InodeRef`] item can hold.
///
/// A leaf bounds an item, so an inode hard-linked into one directory enough times overflows
/// the `INODE_REF` for that directory. `extended-iref` is the feature that answers it: the
/// name moves to an `INODE_EXTREF`, keyed by `(inode, INODE_EXTREF, hash of parent and name)`
/// so that one item holds few names and the parent moves into the record itself.
///
/// The pinned baseline sets `extended-iref` on every filesystem it writes, so both forms are
/// live and an inode may have some of its names in each.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InodeExtref {
    /// The directory this name is in — the field an [`InodeRef`] keeps in its key instead.
    pub parent_objectid: u64,
    /// The entry's sequence number in that directory.
    pub index: u64,
    /// How many bytes of name follow the head.
    pub name_len: u16,
}

impl InodeExtref {
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
                structure: "btrfs_inode_extref",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            parent_objectid: get_u64(buf, 0),
            index: get_u64(buf, 8),
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
            "an inode extref needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.parent_objectid);
        put_u64(buf, 8, self.index);
        put_u16(buf, 16, self.name_len);
    }
}

impl Packed for InodeExtref {
    const STRUCTURE: &'static str = "btrfs_inode_extref";
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
    use super::super::for_each_packed;
    use super::*;

    fn an_inode() -> InodeItem {
        InodeItem {
            generation: 8,
            transid: 8,
            size: 1234,
            nbytes: 4096,
            block_group: 0,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            mode: 0o100_644,
            rdev: 0,
            flags: InodeFlags::NONE,
            sequence: 3,
            atime: Timestamp {
                secs: 1_786_392_177,
                nanos: 123_456_789,
            },
            ctime: Timestamp {
                secs: 1_786_392_178,
                nanos: 0,
            },
            mtime: Timestamp {
                secs: 1_786_392_179,
                nanos: 1,
            },
            otime: Timestamp {
                secs: 1_786_392_100,
                nanos: 999_999_999,
            },
        }
    }

    #[test]
    fn an_inode_item_round_trips_through_its_hundred_and_sixty_bytes() {
        let inode = an_inode();
        let mut buf = [0u8; InodeItem::SIZE];
        inode.write_to(&mut buf);
        assert_eq!(InodeItem::read_from(&buf).expect("a full item"), inode);
        // The offsets a round trip through one accessor pair cannot check, at the fields a
        // stat reports. `mode` is four bytes here where a host's is two, and reading it as
        // two would work on every filesystem and be the wrong field.
        assert_eq!(&buf[16..24], &1234u64.to_le_bytes(), "size");
        assert_eq!(&buf[40..44], &1u32.to_le_bytes(), "nlink");
        assert_eq!(&buf[52..56], &0o100_644u32.to_le_bytes(), "mode");
        assert_eq!(&buf[112..120], &1_786_392_177u64.to_le_bytes(), "atime");
        assert_eq!(&buf[120..124], &123_456_789u32.to_le_bytes(), "atime nanos");
    }

    #[test]
    fn the_birth_time_is_a_field_of_its_own_and_survives_the_round_trip() {
        // The property that makes this family lossless where a three-timestamp format is not:
        // the time a file was created is recorded rather than derived.
        let mut buf = [0u8; InodeItem::SIZE];
        an_inode().write_to(&mut buf);
        assert_eq!(&buf[148..156], &1_786_392_100u64.to_le_bytes());
        let read = InodeItem::read_from(&buf).expect("a full item");
        assert_eq!(read.otime.secs, 1_786_392_100);
        assert_eq!(read.otime.nanos, 999_999_999);
        // And the four are four distinct instants rather than one written four times.
        assert_ne!(read.atime, read.mtime);
        assert_ne!(read.ctime, read.otime);
    }

    #[test]
    fn the_reserved_words_survive_a_write() {
        let mut buf = [0x77u8; InodeItem::SIZE];
        an_inode().write_to(&mut buf);
        assert!(buf[80..112].iter().all(|&b| b == 0x77));
    }

    #[test]
    fn a_device_number_is_split_the_way_the_kernel_encodes_it() {
        // `/dev/null` is 1:3 and `/dev/sda` is 8:0 — neither symmetric, so a split that read
        // the halves the wrong way round gets both wrong rather than one.
        let null = InodeItem {
            mode: 0o020_666,
            rdev: InodeItem::encode_device(1, 3),
            ..an_inode()
        };
        assert_eq!(null.rdev, 0x0010_0003, "twenty bits of minor");
        assert_eq!(null.device(), (1, 3));
        let sda = InodeItem {
            mode: 0o060_660,
            rdev: InodeItem::encode_device(8, 0),
            ..an_inode()
        };
        assert_eq!(sda.device(), (8, 0));
        // A minor of twenty bits is what this encoding is for, and the value that a
        // twelve-and-eight split — the one a format predating it carries — silently truncates.
        let big = InodeItem {
            rdev: InodeItem::encode_device(1, 0xf_ffff),
            ..an_inode()
        };
        assert_eq!(big.device(), (1, 0xf_ffff));
    }

    #[test]
    fn a_mode_says_what_the_inode_is_in_its_type_bits() {
        assert_eq!(an_inode().mode_type(), 0o100_000);
        let dir = InodeItem {
            mode: 0o040_755,
            ..an_inode()
        };
        assert_eq!(dir.mode_type(), 0o040_000);
    }

    #[test]
    fn an_item_shorter_than_the_format_writes_is_refused() {
        assert!(matches!(
            InodeItem::read_from(&[0u8; InodeItem::SIZE - 1]),
            Err(ParseError::TooShort {
                structure: "btrfs_inode_item",
                need: 160,
                got: 159,
            })
        ));
    }

    #[test]
    fn every_name_an_inode_has_in_one_directory_is_in_one_item() {
        // What packing is for: a file hard-linked twice into one directory has one
        // `INODE_REF` item holding both names, and a reader that took the first and stopped
        // would report the file as having one name.
        let mut data = Vec::new();
        for (index, name) in [(2u64, &b"one"[..]), (5, &b"another"[..])] {
            let head = InodeRef {
                index,
                name_len: name.len() as u16,
            };
            let mut buf = [0u8; InodeRef::SIZE];
            head.write_to(&mut buf);
            data.extend_from_slice(&buf);
            data.extend_from_slice(name);
        }
        let mut found = Vec::new();
        for_each_packed::<InodeRef, _>(&data, |head, name| {
            found.push((head.index, name.to_vec()));
            true
        })
        .expect("two names");
        assert_eq!(found, vec![(2, b"one".to_vec()), (5, b"another".to_vec())]);
    }

    #[test]
    fn an_extended_ref_carries_the_parent_a_plain_ref_keeps_in_its_key() {
        // The one field that differs between the two forms, and the reason the extended one
        // exists: the parent moves out of the key so one item holds few names.
        let head = InodeExtref {
            parent_objectid: 256,
            index: 9,
            name_len: 4,
        };
        let mut data = [0u8; InodeExtref::SIZE + 4];
        head.write_to(&mut data);
        data[InodeExtref::SIZE..].copy_from_slice(b"name");
        assert_eq!(&data[0..8], &256u64.to_le_bytes());
        assert_eq!(&data[16..18], &4u16.to_le_bytes());
        let mut seen = None;
        for_each_packed::<InodeExtref, _>(&data, |head, name| {
            seen = Some((head.parent_objectid, name.to_vec()));
            true
        })
        .expect("one name");
        assert_eq!(seen, Some((256, b"name".to_vec())));
    }

    #[test]
    fn a_name_longer_than_the_item_holding_it_is_refused() {
        let head = InodeRef {
            index: 1,
            name_len: 40,
        };
        let mut data = [0u8; InodeRef::SIZE + 4];
        head.write_to(&mut data);
        assert!(matches!(
            for_each_packed::<InodeRef, _>(&data, |_, _| true),
            Err(ParseError::TooShort {
                structure: "btrfs_inode_ref",
                need: 50,
                got: 14,
            })
        ));
    }

    #[test]
    fn a_file_with_no_checksums_says_so_in_the_bit_the_format_gives_it() {
        let inode = InodeItem {
            flags: InodeFlags::NODATASUM | InodeFlags::NODATACOW,
            ..an_inode()
        };
        let mut buf = [0u8; InodeItem::SIZE];
        inode.write_to(&mut buf);
        assert_eq!(&buf[64..72], &3u64.to_le_bytes());
        let read = InodeItem::read_from(&buf).expect("a full item");
        assert!(read.flags.contains(InodeFlags::NODATASUM));
        assert!(!read.flags.contains(InodeFlags::PREALLOC));
    }
}
