//! Where logical space lives: a device, a chunk of the address space, one copy of that chunk on
//! a device, and the same mapping written down the other way round.
//!
//! Every address above this layer is logical, and the chunk tree is what turns one into a
//! place on a device. A [`Chunk`] covers a run of logical space; each of its [`Stripe`]s says
//! where a copy of that run sits, on which device. How the copies relate is decided by the
//! chunk's profile: for `single` there is one, for `DUP` and the RAID1 family each stripe is a
//! whole copy, and for the striped profiles a stripe holds every *n*th piece.
//!
//! The device tree holds the reverse: a [`DevExtent`] per copy, saying what occupies a run of
//! one disk, and a [`DevStats`] per device saying what has gone wrong with it. Two trees
//! recording one mapping is what lets a driver ask the question from either end, and what lets
//! a checker notice the two disagreeing.
//!
//! A chunk is a variable-length record — a fixed 48-byte head and then one stripe per copy —
//! so it is recovered in two calls rather than one: [`Chunk::read_from`] takes the head, and
//! [`Chunk::stripe_at`] takes one stripe out of the same buffer. That keeps the parse
//! allocation-free and lets the caller stop as soon as the stripe count is one it refuses.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{
    get_arr, get_u8, get_u16, get_u32, get_u64, put_arr, put_u16, put_u32, put_u64,
};
use crate::flags::flag_set;

use super::ParseError;

/// What a block group holds and how it is replicated.
///
/// The word carries two independent things: the *kind* of space — data, metadata, or the
/// system space the chunk tree itself lives in — and the *profile* it is replicated under. A
/// chunk with no profile bit at all is `single`, one copy and nothing else, which is why the
/// unreplicated case is an absence rather than a bit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockGroupFlags(u64);

flag_set!(BlockGroupFlags: u64);

impl BlockGroupFlags {
    /// File contents.
    pub const DATA: Self = Self(1 << 0);
    /// The chunk tree and the space it needs to describe itself.
    pub const SYSTEM: Self = Self(1 << 1);
    /// Every tree but the chunk tree.
    pub const METADATA: Self = Self(1 << 2);
    /// Striped across devices with no redundancy.
    pub const RAID0: Self = Self(1 << 3);
    /// Two copies, on different devices.
    pub const RAID1: Self = Self(1 << 4);
    /// Two copies, which may be on one device — the single-device redundancy profile, and
    /// what the pinned baseline gives metadata and system space by default.
    pub const DUP: Self = Self(1 << 5);
    /// Striped across mirrored pairs.
    pub const RAID10: Self = Self(1 << 6);
    /// Striped with one parity.
    pub const RAID5: Self = Self(1 << 7);
    /// Striped with two parities.
    pub const RAID6: Self = Self(1 << 8);
    /// Three copies, on different devices.
    pub const RAID1C3: Self = Self(1 << 9);
    /// Four copies, on different devices.
    pub const RAID1C4: Self = Self(1 << 10);
    /// The block group's logical space has been remapped.
    pub const REMAPPED: Self = Self(1 << 11);
    /// The block group's metadata has been remapped.
    pub const METADATA_REMAP: Self = Self(1 << 12);

    /// The three bits saying what a block group holds.
    pub const TYPE_MASK: Self = Self(Self::DATA.0 | Self::SYSTEM.0 | Self::METADATA.0);

    /// Every bit saying how a block group is replicated. An empty intersection is `single`.
    pub const PROFILE_MASK: Self = Self(
        Self::RAID0.0
            | Self::RAID1.0
            | Self::DUP.0
            | Self::RAID10.0
            | Self::RAID5.0
            | Self::RAID6.0
            | Self::RAID1C3.0
            | Self::RAID1C4.0,
    );

    /// Whether every stripe of this chunk holds the same bytes — which is true of `single` as
    /// well as of the mirrored profiles, since one copy is trivially every copy.
    ///
    /// The question is asked of the *exact* profile rather than through a mask, and the
    /// difference matters in the direction that costs. Two profile bits at once is a
    /// combination the format does not define, and a mask test would answer "mirrored" for
    /// `RAID1|DUP` — which would have a reader take one stripe for the whole chunk on a word
    /// whose meaning nothing states. An undefined profile is not read as copies.
    #[must_use]
    pub const fn is_mirrored(self) -> bool {
        let profile = self.0 & Self::PROFILE_MASK.0;
        profile == 0
            || profile == Self::DUP.0
            || profile == Self::RAID1.0
            || profile == Self::RAID1C3.0
            || profile == Self::RAID1C4.0
    }

    /// Whether a stripe of this chunk holds every *n*th piece of it rather than a copy, so
    /// reading a run means gathering it from several devices.
    ///
    /// Exact for the same reason [`is_mirrored`](Self::is_mirrored) is. The two are not
    /// complements: an undefined profile is neither.
    #[must_use]
    pub const fn is_striped(self) -> bool {
        let profile = self.0 & Self::PROFILE_MASK.0;
        profile == Self::RAID0.0
            || profile == Self::RAID10.0
            || profile == Self::RAID5.0
            || profile == Self::RAID6.0
    }

    /// The name the profile is known by, or [`None`] where the word carries a combination the
    /// format does not define.
    #[must_use]
    pub const fn profile_name(self) -> Option<&'static str> {
        Some(match Self(self.0 & Self::PROFILE_MASK.0) {
            Self::NONE => "single",
            Self::RAID0 => "raid0",
            Self::RAID1 => "raid1",
            Self::DUP => "dup",
            Self::RAID10 => "raid10",
            Self::RAID5 => "raid5",
            Self::RAID6 => "raid6",
            Self::RAID1C3 => "raid1c3",
            Self::RAID1C4 => "raid1c4",
            _ => return None,
        })
    }
}

/// One copy of a chunk, and where it sits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stripe {
    /// Offset 0. Which device this copy is on.
    pub devid: u64,
    /// Offset 8. Where on that device it begins, in bytes.
    pub offset: u64,
    /// Offset 16, 16 bytes. That device's own id, which the device item repeats — so a stripe
    /// naming a device number that belongs to another disk says so.
    pub dev_uuid: [u8; 16],
}

impl Stripe {
    /// Bytes on disk.
    pub const SIZE: usize = 32;

    /// Recover a stripe from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a stripe.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_stripe",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            devid: get_u64(buf, 0),
            offset: get_u64(buf, 8),
            dev_uuid: get_arr(buf, 16),
        })
    }

    /// Write the stripe into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a stripe.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a chunk stripe needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.devid);
        put_u64(buf, 8, self.offset);
        put_arr(buf, 16, &self.dev_uuid);
    }
}

/// A run of logical space, and how many copies of it there are.
///
/// The logical address this chunk begins at is **not** a field: it is the key's offset, so a
/// chunk read out of the chunk tree or out of the superblock's bootstrap array is only half a
/// mapping until its key is beside it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chunk {
    /// Offset 0. How much logical space this chunk covers.
    pub length: u64,
    /// Offset 8. The tree that owns it, which is the extent tree on every filesystem this
    /// crate reads.
    pub owner: u64,
    /// Offset 16. How much of a striped chunk lands on one device before the next.
    pub stripe_len: u64,
    /// Offset 24. What the chunk holds and how it is replicated.
    pub ty: BlockGroupFlags,
    /// Offset 32. The alignment the allocator prefers, in bytes.
    pub io_align: u32,
    /// Offset 36. The width the allocator prefers, in bytes.
    pub io_width: u32,
    /// Offset 40. The sector size in force when the chunk was made.
    pub sector_size: u32,
    /// Offset 44. How many stripes follow the fixed head. Never zero on a well-formed
    /// filesystem, and unbounded by this layer: what a buffer has room for is a question for
    /// the caller holding it.
    pub num_stripes: u16,
    /// Offset 46. How many stripes make one mirror, under the striped-and-mirrored profiles.
    pub sub_stripes: u16,
}

impl Chunk {
    /// Bytes of the fixed head, before the first stripe.
    pub const SIZE: usize = 48;

    /// Recover the fixed head of a chunk from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The stripes are not read here: [`stripe_at`](Self::stripe_at) takes one out of the same
    /// buffer, and [`encoded_len`](Self::encoded_len) says how long the whole record is.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than the head.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_chunk",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            length: get_u64(buf, 0),
            owner: get_u64(buf, 8),
            stripe_len: get_u64(buf, 16),
            ty: BlockGroupFlags::from_bits(get_u64(buf, 24)),
            io_align: get_u32(buf, 32),
            io_width: get_u32(buf, 36),
            sector_size: get_u32(buf, 40),
            num_stripes: get_u16(buf, 44),
            sub_stripes: get_u16(buf, 46),
        })
    }

    /// Write the fixed head into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The stripes are the caller's to write, each through [`Stripe::write_to`] at
    /// `Chunk::SIZE + index * Stripe::SIZE`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than the head.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a chunk head needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.length);
        put_u64(buf, 8, self.owner);
        put_u64(buf, 16, self.stripe_len);
        put_u64(buf, 24, self.ty.bits());
        put_u32(buf, 32, self.io_align);
        put_u32(buf, 36, self.io_width);
        put_u32(buf, 40, self.sector_size);
        put_u16(buf, 44, self.num_stripes);
        put_u16(buf, 46, self.sub_stripes);
    }

    /// How many bytes the whole record occupies: the head and one stripe per copy.
    ///
    /// A `usize` rather than a `u16`: the product reaches two megabytes at the widest stripe
    /// count the field can hold, which is far past what any buffer here offers and exactly the
    /// number a bounds check needs.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::SIZE + self.num_stripes as usize * Stripe::SIZE
    }

    /// The stripe at `index`, taken out of the same `buf` the head was read from.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` does not hold that stripe — which is the check
    /// that stands between a `num_stripes` an image inflated and a read past the record.
    pub fn stripe_at(&self, buf: &[u8], index: u16) -> Result<Stripe, ParseError> {
        if index >= self.num_stripes {
            return Err(ParseError::TooShort {
                structure: "btrfs_stripe",
                need: self.encoded_len(),
                got: buf.len(),
            });
        }
        let at = Self::SIZE + index as usize * Stripe::SIZE;
        let end = at + Stripe::SIZE;
        if buf.len() < end {
            return Err(ParseError::TooShort {
                structure: "btrfs_stripe",
                need: end,
                got: buf.len(),
            });
        }
        Stripe::read_from(&buf[at..end])
    }
}

/// One device of the filesystem.
///
/// It appears twice: once inside the superblock, describing the device that superblock was
/// read off, and once per device in the chunk tree. The two agree on a healthy filesystem, and
/// the [`fsid`](Self::fsid) it carries is what says a device belongs to the filesystem
/// claiming it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DevItem {
    /// Offset 0. This device's number within the filesystem, which every stripe names.
    pub devid: u64,
    /// Offset 8. How many bytes of the device the filesystem may use.
    pub total_bytes: u64,
    /// Offset 16. How many of them chunks currently occupy.
    pub bytes_used: u64,
    /// Offset 24. The alignment the allocator prefers, in bytes.
    pub io_align: u32,
    /// Offset 28. The width the allocator prefers, in bytes.
    pub io_width: u32,
    /// Offset 32. The device's sector size.
    pub sector_size: u32,
    /// Offset 36. Device flags, zero on every device this crate reads.
    pub ty: u64,
    /// Offset 44. The transaction that last wrote this item.
    pub generation: u64,
    /// Offset 52. Where in the device the filesystem's own space begins.
    pub start_offset: u64,
    /// Offset 60. Which group of devices this belongs to, for allocation.
    pub dev_group: u32,
    /// Offset 64. A hint about the device's seek cost.
    pub seek_speed: u8,
    /// Offset 65. A hint about the device's bandwidth.
    pub bandwidth: u8,
    /// Offset 66, 16 bytes. This device's own id, which every stripe naming it repeats.
    pub uuid: [u8; 16],
    /// Offset 82, 16 bytes. The filesystem this device belongs to.
    pub fsid: [u8; 16],
}

impl DevItem {
    /// Bytes on disk.
    pub const SIZE: usize = 98;

    /// Recover a device item from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a device item.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_dev_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            devid: get_u64(buf, 0),
            total_bytes: get_u64(buf, 8),
            bytes_used: get_u64(buf, 16),
            io_align: get_u32(buf, 24),
            io_width: get_u32(buf, 28),
            sector_size: get_u32(buf, 32),
            ty: get_u64(buf, 36),
            generation: get_u64(buf, 44),
            start_offset: get_u64(buf, 52),
            dev_group: get_u32(buf, 60),
            seek_speed: get_u8(buf, 64),
            bandwidth: get_u8(buf, 65),
            uuid: get_arr(buf, 66),
            fsid: get_arr(buf, 82),
        })
    }

    /// Write the device item into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a device item.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a device item needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.devid);
        put_u64(buf, 8, self.total_bytes);
        put_u64(buf, 16, self.bytes_used);
        put_u32(buf, 24, self.io_align);
        put_u32(buf, 28, self.io_width);
        put_u32(buf, 32, self.sector_size);
        put_u64(buf, 36, self.ty);
        put_u64(buf, 44, self.generation);
        put_u64(buf, 52, self.start_offset);
        put_u32(buf, 60, self.dev_group);
        buf[64] = self.seek_speed;
        buf[65] = self.bandwidth;
        put_arr(buf, 66, &self.uuid);
        put_arr(buf, 82, &self.fsid);
    }
}

/// A run of one device's bytes, and the chunk occupying it.
///
/// The device tree holds one of these per copy of every chunk, keyed by the device number and
/// the offset into it — so a chunk replicated twice has one chunk item and two of these, and
/// they are the map read the other way round. That redundancy is the point: it is how a driver
/// asks what occupies a place on a disk without walking every chunk, and how a checker notices
/// two chunks claiming one run.
///
/// Where the run begins on the device is the key's offset rather than a field here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DevExtent {
    /// Offset 0. The tree recording the chunk, which is
    /// [`CHUNK_TREE`](super::objectid::CHUNK_TREE) on every filesystem in existence.
    pub chunk_tree: u64,
    /// Offset 8. The chunk's objectid, which is
    /// [`FIRST_CHUNK_TREE`](super::objectid::FIRST_CHUNK_TREE) on every filesystem in
    /// existence.
    pub chunk_objectid: u64,
    /// Offset 16. The chunk's logical address, which is what makes this the reverse mapping.
    pub chunk_offset: u64,
    /// Offset 24. How many bytes of the device the run covers.
    pub length: u64,
    /// Offset 32, 16 bytes. The chunk tree's own id, repeated here so a device carrying a run
    /// from another filesystem says so.
    pub chunk_tree_uuid: [u8; 16],
}

impl DevExtent {
    /// Bytes on disk.
    pub const SIZE: usize = 48;

    /// Recover a device extent from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_dev_extent",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            chunk_tree: get_u64(buf, 0),
            chunk_objectid: get_u64(buf, 8),
            chunk_offset: get_u64(buf, 16),
            length: get_u64(buf, 24),
            chunk_tree_uuid: get_arr(buf, 32),
        })
    }

    /// Write the device extent into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a device extent needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.chunk_tree);
        put_u64(buf, 8, self.chunk_objectid);
        put_u64(buf, 16, self.chunk_offset);
        put_u64(buf, 24, self.length);
        put_arr(buf, 32, &self.chunk_tree_uuid);
    }
}

/// What has gone wrong with one device, counted across the filesystem's whole life.
///
/// The device tree carries one of these per device as a `PERSISTENT_ITEM`, keyed by
/// [`DEV_STATS`](Self::DEV_STATS) and the device number. Every counter is zero on a filesystem
/// that has never been mounted, and it is the record rather than the zeros: a driver increments
/// these in place, and a filesystem written without one has a device whose history is missing
/// rather than clean.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DevStats {
    /// Offset 0. Writes that failed.
    pub write_errs: u64,
    /// Offset 8. Reads that failed.
    pub read_errs: u64,
    /// Offset 16. Cache flushes that failed.
    pub flush_errs: u64,
    /// Offset 24. Blocks whose checksum did not cover them.
    pub corruption_errs: u64,
    /// Offset 32. Blocks whose recorded transaction was not the one expected.
    pub generation_errs: u64,
}

impl DevStats {
    /// Bytes on disk.
    pub const SIZE: usize = 40;

    /// The objectid a device's statistics are keyed by, the device number being the key's
    /// offset.
    ///
    /// Zero, which is also the objectid a `TEMPORARY_ITEM` uses for something else entirely —
    /// the two are told apart by their type byte, which is the format's way throughout.
    pub const DEV_STATS: u64 = 0;

    /// Recover a device's statistics from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than one.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_dev_stats_item",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            write_errs: get_u64(buf, 0),
            read_errs: get_u64(buf, 8),
            flush_errs: get_u64(buf, 16),
            corruption_errs: get_u64(buf, 24),
            generation_errs: get_u64(buf, 32),
        })
    }

    /// Write the statistics into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than one.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a device statistics record needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.write_errs);
        put_u64(buf, 8, self.read_errs);
        put_u64(buf, 16, self.flush_errs);
        put_u64(buf, 24, self.corruption_errs);
        put_u64(buf, 32, self.generation_errs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system chunk the pinned baseline puts in the bootstrap array of a 1 GiB image:
    /// eight mebibytes of `SYSTEM|DUP`, two stripes on the one device.
    fn a_chunk() -> Chunk {
        Chunk {
            length: 8 << 20,
            owner: 2,
            stripe_len: 64 << 10,
            ty: BlockGroupFlags::SYSTEM | BlockGroupFlags::DUP,
            io_align: 64 << 10,
            io_width: 64 << 10,
            sector_size: 4096,
            num_stripes: 2,
            sub_stripes: 1,
        }
    }

    #[test]
    fn a_chunk_head_round_trips_and_the_type_word_is_the_baselines() {
        let chunk = a_chunk();
        let mut buf = [0u8; Chunk::SIZE];
        chunk.write_to(&mut buf);
        assert_eq!(Chunk::read_from(&buf).expect("a full head"), chunk);
        // The word `dump-tree` prints as `SYSTEM|DUP` for this chunk.
        assert_eq!(chunk.ty.bits(), 0x22);
        assert_eq!(&buf[24..32], &0x22u64.to_le_bytes());
        assert_eq!(&buf[44..46], &2u16.to_le_bytes());
        assert_eq!(chunk.encoded_len(), 112);
    }

    #[test]
    fn a_stripe_is_taken_out_of_the_record_the_head_came_from() {
        let chunk = a_chunk();
        let mut buf = vec![0u8; chunk.encoded_len()];
        chunk.write_to(&mut buf);
        let stripes = [
            Stripe {
                devid: 1,
                offset: 22_020_096,
                dev_uuid: [0xec; 16],
            },
            Stripe {
                devid: 1,
                offset: 30_408_704,
                dev_uuid: [0xec; 16],
            },
        ];
        for (index, stripe) in stripes.iter().enumerate() {
            stripe.write_to(&mut buf[Chunk::SIZE + index * Stripe::SIZE..]);
        }
        assert_eq!(chunk.stripe_at(&buf, 0).expect("stripe 0"), stripes[0]);
        assert_eq!(chunk.stripe_at(&buf, 1).expect("stripe 1"), stripes[1]);
    }

    #[test]
    fn a_stripe_past_the_count_or_past_the_buffer_is_no_stripe() {
        let chunk = a_chunk();
        let buf = vec![0u8; chunk.encoded_len()];
        // Past what the chunk says it has.
        assert!(matches!(
            chunk.stripe_at(&buf, 2),
            Err(ParseError::TooShort { .. })
        ));
        // And within the count but past what the buffer holds, which is the case a
        // `num_stripes` an image inflated produces: the count is believed and the buffer is
        // what stands between it and a read past the record.
        let inflated = Chunk {
            num_stripes: 64,
            ..chunk
        };
        assert!(matches!(
            inflated.stripe_at(&buf, 63),
            Err(ParseError::TooShort { .. })
        ));
        assert_eq!(inflated.stripe_at(&buf, 1).expect("still inside").devid, 0);
    }

    #[test]
    fn single_is_the_absence_of_a_profile_and_still_reads_as_one_copy() {
        // The case a mask cannot express, and the one every data chunk of the pinned
        // baseline is: no profile bit at all.
        let single = BlockGroupFlags::DATA;
        assert_eq!(single.profile_name(), Some("single"));
        assert!(single.is_mirrored(), "one copy is trivially every copy");
        assert!(!single.contains(BlockGroupFlags::PROFILE_MASK));

        for mirrored in [
            BlockGroupFlags::DUP,
            BlockGroupFlags::RAID1,
            BlockGroupFlags::RAID1C3,
            BlockGroupFlags::RAID1C4,
        ] {
            assert!((BlockGroupFlags::METADATA | mirrored).is_mirrored());
        }
        for striped in [
            BlockGroupFlags::RAID0,
            BlockGroupFlags::RAID10,
            BlockGroupFlags::RAID5,
            BlockGroupFlags::RAID6,
        ] {
            let chunk = BlockGroupFlags::DATA | striped;
            assert!(
                !chunk.is_mirrored(),
                "a stripe of a striped chunk is a piece, not a copy"
            );
            assert!(chunk.is_striped());
        }
        assert!(!single.is_striped());
    }

    #[test]
    fn a_profile_word_the_format_does_not_define_is_neither_copies_nor_stripes() {
        // Two profiles at once is not a profile. Naming it after the lower bit would report a
        // replication scheme the filesystem does not have, and answering "mirrored" through a
        // mask would have a reader take one stripe for the whole chunk on a word whose
        // meaning nothing states.
        let both = BlockGroupFlags::DATA | BlockGroupFlags::RAID1 | BlockGroupFlags::DUP;
        assert_eq!(both.profile_name(), None);
        assert!(
            !both.is_mirrored(),
            "an undefined profile is not read as copies"
        );
        assert!(!both.is_striped(), "and the two are not complements");
    }

    #[test]
    fn a_device_item_round_trips_through_its_ninety_eight_bytes() {
        let dev = DevItem {
            devid: 1,
            total_bytes: 1 << 30,
            bytes_used: 132_513_792,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            ty: 0,
            generation: 0,
            start_offset: 0,
            dev_group: 0,
            seek_speed: 0,
            bandwidth: 0,
            uuid: [0xec; 16],
            fsid: [0x11; 16],
        };
        let mut buf = [0u8; DevItem::SIZE];
        dev.write_to(&mut buf);
        assert_eq!(DevItem::read_from(&buf).expect("a full item"), dev);
        // The two identities are at the tail, which is where a transcription goes stale
        // first, so their offsets are asserted against the bytes.
        assert_eq!(&buf[66..82], &[0xec; 16]);
        assert_eq!(&buf[82..98], &[0x11; 16]);
    }

    #[test]
    fn a_device_extent_round_trips_and_carries_the_chunk_tree_at_its_tail() {
        let extent = DevExtent {
            chunk_tree: 3,
            chunk_objectid: 256,
            chunk_offset: 30_408_704,
            length: 53_673_984,
            chunk_tree_uuid: [0xc7; 16],
        };
        let mut buf = [0u8; DevExtent::SIZE];
        extent.write_to(&mut buf);
        assert_eq!(DevExtent::read_from(&buf).expect("a full record"), extent);
        assert_eq!(&buf[32..48], &[0xc7; 16]);
        for got in 0..DevExtent::SIZE {
            assert!(DevExtent::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
    }

    #[test]
    fn a_devices_statistics_round_trip_and_are_five_counters_rather_than_forty_zeros() {
        // Written as zeros on every filesystem this crate produces, and read back as five
        // named numbers — a driver increments them in place, so the record is the structure
        // and not the value it happens to hold on the day it is written.
        let stats = DevStats {
            write_errs: 1,
            read_errs: 2,
            flush_errs: 3,
            corruption_errs: 4,
            generation_errs: 5,
        };
        let mut buf = [0u8; DevStats::SIZE];
        stats.write_to(&mut buf);
        assert_eq!(DevStats::read_from(&buf).expect("a full record"), stats);
        assert_eq!(
            DevStats::default(),
            DevStats::read_from(&[0u8; 40]).unwrap()
        );
        for got in 0..DevStats::SIZE {
            assert!(DevStats::read_from(&vec![0u8; got]).is_err(), "{got}");
        }
    }
}
