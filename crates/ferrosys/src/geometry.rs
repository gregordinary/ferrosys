//! The geometry planner: a pure function from a size, a feature set, and a
//! maximum grow target to a complete [`Layout`].
//!
//! This module is pure and deterministic — no I/O, no clock, no allocation of
//! disk blocks. It decides every placement an external checker verifies: how many
//! block groups there are, which groups carry superblock and descriptor backups
//! (the `sparse_super` rule), how many group-descriptor-table blocks to reserve
//! for growth (sized to the grow target), how the block
//! bitmaps and inode tables of a flex block group pack into its first group, how
//! dense the inodes are, and how large the final, possibly partial, group is.
//!
//! Planning before writing is the whole point: the reserved descriptor blocks and
//! backups that make growth safe cannot be added to a filesystem after its layout
//! is fixed, so the layout is computed as a value first and the materializer only
//! obeys it.

use std::num::NonZeroU64;

use crate::feature::FeatureSet;

/// A contiguous run of blocks, `[start, start + len)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BlockRange {
    /// First block in the run.
    pub start: u64,
    /// Number of blocks in the run.
    pub len: u64,
}

impl BlockRange {
    /// One past the last block in the run.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.len
    }

    /// Whether the run contains no blocks.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// A geometry that cannot be realized safely.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GeometryError {
    /// The filesystem is smaller than the minimum that can hold group 0's fixed
    /// overhead (superblock, descriptor table, bitmaps, inode table, root).
    ///
    /// The growth reservation is part of that overhead, and on a small filesystem it can be
    /// most of it, so it is named separately: the two ways out of this are a smaller
    /// [`GrowReservation`] and a larger filesystem, and the number says which is worth
    /// trying. [`GrowReservation::Max`] never contributes here — it is bounded by the
    /// filesystem it is reserved from — so a non-zero share of the overhead is always a
    /// reservation the caller asked for by name.
    #[error(
        "filesystem of {blocks} blocks is too small: group 0 needs {overhead} for metadata, \
         {reserved_gdt_blocks} of them reserved to grow into"
    )]
    #[non_exhaustive]
    TooSmall {
        /// Total blocks requested.
        blocks: u64,
        /// Blocks group 0's metadata requires.
        overhead: u64,
        /// How many of those blocks are the descriptor blocks reserved for online growth —
        /// the part of the overhead a [`GrowReservation`] decides.
        reserved_gdt_blocks: u64,
    },
    /// The grow target is smaller than the filesystem being created.
    #[error("grow target {target} blocks is below the initial size {initial} blocks")]
    #[non_exhaustive]
    GrowTargetTooSmall {
        /// The requested grow target in blocks.
        target: u64,
        /// The initial size in blocks.
        initial: u64,
    },
    /// The grow target needs more reserved descriptor blocks than the resize
    /// inode's double-indirect map can represent. Growing to it would force the
    /// `meta_bg` conversion this crate exists to avoid, so it is rejected rather
    /// than silently under-reserved.
    ///
    /// The map is one block of 4-byte slots, so it holds at most `block_size / 4`
    /// descriptor blocks.
    #[error(
        "grow target needs {needed} reserved GDT blocks but the resize inode can \
         represent at most {limit}; a larger target would require meta_bg"
    )]
    #[non_exhaustive]
    GrowTargetTooLarge {
        /// Reserved GDT blocks the target would need.
        needed: u64,
        /// The most reserved GDT blocks the resize inode's map holds.
        limit: u64,
    },
    /// A [`GrowReservation::UpTo`] target was given for a filesystem whose blocks a
    /// 32-bit block number cannot address. The resize inode's map is a 32-bit block
    /// map, so it cannot point at the reserved descriptor blocks in the backup groups
    /// of a filesystem this large; the reservation is refused rather than truncated.
    ///
    /// [`GrowReservation::Max`] reserves nothing at this size instead of failing.
    #[error(
        "a filesystem of {blocks} blocks cannot reserve descriptor blocks: the resize \
         inode's block map is 32 bits wide and addresses at most {limit} blocks"
    )]
    #[non_exhaustive]
    ReservationNeeds32BitBlocks {
        /// Blocks the filesystem would have.
        blocks: u64,
        /// The most blocks a 32-bit block number addresses.
        limit: u64,
    },
    /// A [`GrowReservation::UpTo`] target was given for a feature set without
    /// `resize_inode`, the inode that maps the reserved descriptor blocks. Nothing
    /// would map the reservation, so it is refused rather than written unreachable.
    ///
    /// [`GrowReservation::Max`] reserves nothing under such a feature set instead of
    /// failing.
    #[error("a grow target needs the resize_inode feature to map the reserved GDT blocks")]
    GrowTargetNeedsResizeInode,
    /// The geometry needs more block groups than the 32-bit group number the
    /// superblock and every group descriptor address them by can hold.
    #[error("filesystem of {blocks} blocks needs {groups} block groups, past the {limit} limit")]
    #[non_exhaustive]
    TooManyGroups {
        /// Blocks the filesystem would have.
        blocks: u64,
        /// Block groups the geometry needs.
        groups: u64,
        /// The most block groups a 32-bit group number addresses.
        limit: u64,
    },
    /// The geometry needs more inodes than the superblock's 32-bit `s_inodes_count`
    /// holds. The inode count follows from the size and the bytes-per-inode ratio, so
    /// this is reached by sizing alone, and it is rejected rather than wrapped.
    #[error("filesystem of {blocks} blocks needs {inodes} inodes, past the {limit} limit")]
    #[non_exhaustive]
    TooManyInodes {
        /// Blocks the filesystem would have.
        blocks: u64,
        /// Inodes the geometry needs.
        inodes: u64,
        /// The most inodes a 32-bit inode count holds.
        limit: u64,
    },
    /// A requested inode count needs more inodes in a group than its one-block inode
    /// bitmap indexes. A group holds at most `8 * block_size` inodes, and a density past
    /// that would need a smaller block group than this crate builds, so it is refused
    /// rather than silently capped to fewer inodes than were asked for. Only an explicit
    /// [`InodeCount`] override reaches this; the size-derived default never does.
    #[error(
        "inode density needs {inodes_per_group} inodes per group but a group's bitmap \
         indexes at most {limit}"
    )]
    #[non_exhaustive]
    InodesTooDense {
        /// Inodes per group the requested count would need.
        inodes_per_group: u64,
        /// The most inodes a one-block inode bitmap indexes.
        limit: u64,
    },
    /// The filesystem has more blocks than a 32-bit block number addresses, but the
    /// `64bit` feature is clear. Without it the superblock's block count, every
    /// group descriptor's bitmap and table addresses, and the resize inode's map are
    /// all 32 bits wide, so the geometry is rejected rather than silently truncated.
    #[error(
        "filesystem of {blocks} blocks needs the 64bit feature: a 32-bit block \
         number addresses at most {limit}"
    )]
    #[non_exhaustive]
    BlockCountNeeds64Bit {
        /// Blocks the filesystem would have.
        blocks: u64,
        /// The most a 32-bit block number addresses.
        limit: u64,
    },
    /// The filesystem has more blocks than an extent maps. An extent leaf stores a
    /// 48-bit physical block number, so no file could reach the blocks past it.
    #[error("filesystem of {blocks} blocks exceeds the {limit} an extent addresses")]
    #[non_exhaustive]
    BlockCountTooLarge {
        /// Blocks the filesystem would have.
        blocks: u64,
        /// The most an extent's physical block number addresses.
        limit: u64,
    },
    /// The final group is too small to hold the metadata its position requires (a
    /// backup copy, or the flex block group's packed tables).
    #[error("final group of {blocks} blocks cannot hold its {overhead} metadata blocks")]
    #[non_exhaustive]
    FinalGroupTooSmall {
        /// Blocks in the final group.
        blocks: u64,
        /// Metadata blocks the final group must hold.
        overhead: u64,
    },
    /// A feature combination or size that must never reach disk.
    #[error(transparent)]
    Feature(#[from] crate::feature::FeatureError),
}

/// The placement of one block group.
///
/// The bitmap and inode-table addresses are absolute block numbers. Under
/// `flex_bg` they point into the group at the head of this group's flex block
/// group, not into this group itself; only that head group physically holds the
/// packed tables.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GroupLayout {
    /// Group number.
    pub index: u32,
    /// First block of this group's block range.
    pub start_block: u64,
    /// Blocks in this group; less than `blocks_per_group` for a partial final
    /// group.
    pub block_count: u32,
    /// Whether this group holds a superblock and descriptor-table copy — the
    /// primary in group 0, a backup in the `sparse_super` groups.
    pub has_super: bool,
    /// Block holding this group's block bitmap.
    pub block_bitmap: u64,
    /// Block holding this group's inode bitmap.
    pub inode_bitmap: u64,
    /// First block of this group's inode table.
    pub inode_table: u64,
}

/// A complete, materializable filesystem layout.
///
/// Every field is a decision the materializer obeys rather than recomputes. The
/// per-group placements are in [`groups`](Layout::groups); the whole-filesystem
/// geometry — group size, descriptor and reserved-descriptor block counts, inode
/// density, and the grow target that sized the reservation — is on the struct.
///
/// [`plan_layout`] is how one is obtained, and it is the only way. The fields are not
/// independent — the group count follows from the block count and the group size, the
/// per-group bitmap and inode-table addresses follow from the flex-group packing, the
/// reserved descriptor count follows from the grow target — and a set of them assembled
/// by hand can satisfy every type in the struct while describing a filesystem no checker
/// accepts. Planning is what makes them consistent, so it is the constructor; the fields
/// stay public because reading them is exactly what the allocator, the materializer, and
/// a caller inspecting a plan all do.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Layout {
    /// The feature set this layout is planned for.
    pub feature: FeatureSet,
    /// Block size in bytes.
    pub block_size: u32,
    /// Total blocks in the filesystem.
    pub total_blocks: u64,
    /// Blocks per group (`8 * block_size`).
    pub blocks_per_group: u32,
    /// Block number of the first data block (0 for a 4 KiB block size).
    pub first_data_block: u32,
    /// Number of block groups.
    pub group_count: u32,
    /// Inodes per group.
    pub inodes_per_group: u32,
    /// Inode-table blocks per group.
    pub inode_table_blocks: u32,
    /// Total inodes (`inodes_per_group * group_count`).
    pub total_inodes: u32,
    /// Descriptor-table blocks the current group count needs.
    pub gdt_blocks: u32,
    /// Descriptor-table blocks reserved past `gdt_blocks` for growth.
    pub reserved_gdt_blocks: u32,
    /// Groups per flex block group.
    pub flex_bg_size: u32,
    /// The grow target in blocks that sized [`reserved_gdt_blocks`](Self::reserved_gdt_blocks).
    pub max_grow_blocks: u64,
    /// Blocks held back for the super-user (`s_r_blocks_count`), the [`ReservedRatio`]
    /// applied to `total_blocks`.
    pub reserved_blocks: u64,
    /// Per-group placements, indexed by group number.
    pub groups: Vec<GroupLayout>,
}

/// The most blocks a filesystem without the `64bit` feature addresses: its block
/// numbers are 32 bits wide.
pub const MAX_32BIT_BLOCKS: u64 = u32::MAX as u64;

/// The most blocks any filesystem this crate writes addresses. An extent leaf stores
/// a physical block number in 48 bits, so a block past this could hold no file data
/// however wide the group descriptors are.
pub const MAX_EXTENT_BLOCKS: u64 = 1 << 48;

/// The share of a filesystem [`GrowReservation::Max`] will spend on growth headroom: at
/// most one block in this many.
///
/// This is policy rather than a property of the format, and it is what makes `Max` a
/// defensible default at every size. Filling the resize inode's map costs a fixed number
/// of blocks — 1024 at a 4096-byte block — whatever the filesystem's size, which is
/// negligible on a large image and a quarter of a 16 MiB one. Sixty-four puts the whole
/// map within reach from 256 MiB up while holding the cost below 1.6% beneath that, under
/// the 5% [`ReservedRatio`] reserves by default. An explicit [`GrowReservation::UpTo`]
/// target is not held to it.
const GROW_MAX_SHARE: u64 = 64;

/// The fewest inodes a block group holds.
///
/// A group's inode count is rounded to a multiple of eight so its inodes end on a byte
/// boundary in the inode bitmap, and a per-group share below that step would round to none
/// at all — a group every tool divides by and no checker accepts. Eight is where `mke2fs`
/// holds it too, so an explicit [`InodeCount::Count`] spread thinly over many groups yields
/// the same geometry from either.
const MIN_INODES_PER_GROUP: u64 = 8;

/// Blocks of superblock-plus-descriptor overhead at the start of a group that
/// carries a copy: one superblock block, the descriptor table, and the reserved
/// descriptor blocks.
#[must_use]
fn super_overhead(gdt_blocks: u32, reserved_gdt_blocks: u32) -> u64 {
    1 + u64::from(gdt_blocks) + u64::from(reserved_gdt_blocks)
}

impl Layout {
    /// Whether group `index` begins a flex block group.
    #[must_use]
    pub fn is_flex_head(&self, index: u32) -> bool {
        index.is_multiple_of(self.flex_bg_size)
    }

    /// Number of groups in the flex block group headed by `head`.
    #[must_use]
    fn flex_members(&self, head: u32) -> u32 {
        (self.group_count - head).min(self.flex_bg_size)
    }

    /// Number of per-group table slots reserved in a flex head. A flex block group
    /// with a single member reserves a full [`flex_bg_size`](Self::flex_bg_size)
    /// slots; otherwise it reserves one per member.
    #[must_use]
    fn flex_slots(&self, head: u32) -> u32 {
        let members = self.flex_members(head);
        if members == 1 {
            self.flex_bg_size
        } else {
            members
        }
    }

    /// Blocks the packed bitmaps and inode tables of the flex block group headed by
    /// `head` span, if nothing displaced them. The tables are placed around the
    /// backup superblocks they meet, so this is the reservation the head needs, not
    /// the run they occupy.
    #[must_use]
    fn flex_meta_span(&self, head: u32) -> u64 {
        let slots = u64::from(self.flex_slots(head));
        let members = u64::from(self.flex_members(head));
        2 * slots + members * u64::from(self.inode_table_blocks)
    }

    /// The superblock-plus-descriptor overhead run at the start of group `index`, or
    /// `None` if the group carries no copy or `index` is past the last group.
    #[must_use]
    pub fn super_overhead_region(&self, index: u32) -> Option<BlockRange> {
        let g = self.groups.get(index as usize)?;
        if !g.has_super {
            return None;
        }
        Some(BlockRange {
            start: g.start_block,
            len: super_overhead(self.gdt_blocks, self.reserved_gdt_blocks),
        })
    }

    /// The groups that carry a superblock-and-descriptor backup: every group with
    /// a copy except the primary in group 0. These are the groups the resize inode
    /// threads its reserved descriptor blocks through.
    #[must_use]
    pub fn backup_groups(&self) -> Vec<u32> {
        self.groups
            .iter()
            .filter(|g| g.has_super && g.index != 0)
            .map(|g| g.index)
            .collect()
    }

    /// Every block occupied by fixed metadata — superblock and descriptor copies,
    /// reserved descriptor blocks, and each group's block bitmap, inode bitmap, and
    /// inode table — as sorted, non-overlapping runs. The complement is the space
    /// the allocator hands out for file data.
    ///
    /// Only the bitmap and table blocks a group actually uses are marked; the
    /// unused table slots a single-member flex block group reserves for future
    /// growth stay free and available for data, matching how mke2fs fills them.
    #[must_use]
    pub fn metadata_regions(&self) -> Vec<BlockRange> {
        let mut runs = Vec::new();
        for g in &self.groups {
            if let Some(r) = self.super_overhead_region(g.index) {
                runs.push(r);
            }
            runs.push(BlockRange {
                start: g.block_bitmap,
                len: 1,
            });
            runs.push(BlockRange {
                start: g.inode_bitmap,
                len: 1,
            });
            runs.push(BlockRange {
                start: g.inode_table,
                len: u64::from(self.inode_table_blocks),
            });
        }
        runs.sort_by_key(|r| r.start);
        runs
    }

    /// Total blocks the per-group metadata occupies: superblock and descriptor
    /// copies, bitmaps, and inode tables. The `s_overhead_clusters` field the
    /// superblock carries adds the internal journal's blocks on top of this.
    #[must_use]
    pub fn overhead_blocks(&self) -> u64 {
        self.metadata_regions().iter().map(|r| r.len).sum()
    }
}

/// `true` when `g` is a power of `base` (including `base^0 == 1`).
fn is_power_of(mut g: u32, base: u32) -> bool {
    if g == 0 {
        return false;
    }
    while g > 1 {
        if !g.is_multiple_of(base) {
            return false;
        }
        g /= base;
    }
    true
}

/// Whether group `g` carries a superblock-and-descriptor copy under `sparse_super`:
/// group 0 (the primary), group 1, and the powers of 3, 5, and 7.
///
/// The planner applies this to decide a layout's placements; a caller working from an
/// image's own superblock rather than from a plan applies it to find the same groups.
#[must_use]
pub(crate) fn sparse_super_has_copy(g: u32) -> bool {
    g == 0 || g == 1 || is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7)
}

/// The `mke2fs.conf` bytes-per-inode ratio for a filesystem of `total_blocks`
/// blocks, selected by the size-thresholded `fs_types` buckets.
fn inode_ratio(total_blocks: u64, block_size: u32) -> u64 {
    let meg = u64::from((1024 * 1024) / block_size);
    if total_blocks < 3 * meg {
        8192 // floppy
    } else if total_blocks < 512 * meg {
        4096 // small
    } else if total_blocks < 4 * 1024 * 1024 * meg {
        16384 // default
    } else if total_blocks < 16 * 1024 * 1024 * meg {
        32768 // big
    } else {
        65536 // huge
    }
}

/// Descriptor-table blocks needed for `groups` group descriptors of `desc_size`
/// bytes each in `block_size`-byte blocks.
fn gdt_blocks_for(groups: u64, desc_size: u16, block_size: u32) -> u64 {
    let per_block = u64::from(block_size) / u64::from(desc_size);
    groups.div_ceil(per_block)
}

/// How much reserved group-descriptor headroom a format builds in.
///
/// The reserved descriptor blocks are what let a filesystem grow online without
/// relocating its descriptor table — the `meta_bg` conversion this crate avoids — so
/// this is the single input that bounds "resize-safe". It expresses intent, a
/// deployment target or a policy, rather than a raw block count.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum GrowReservation {
    /// Reserve nothing beyond the initial size: format at the final size, with no
    /// online-grow headroom. An unmounted `resize2fs` can still grow the image later,
    /// relocating descriptor blocks offline.
    None,
    /// Reserve exactly enough to grow online up to this many bytes — the largest
    /// device the image will be flashed to. A target past the resize inode's ceiling
    /// is rejected with [`GeometryError::GrowTargetTooLarge`] rather than silently
    /// under-reserved, and a target on a filesystem whose blocks the resize inode's
    /// 32-bit map cannot address is rejected with
    /// [`GeometryError::ReservationNeeds32BitBlocks`].
    UpTo(u64),
    /// Reserve as much online headroom as the format allows without spending more than
    /// one block in sixty-four of the filesystem on it. The fail-safe default — an image
    /// built without a known target still grows onto any device the format can address,
    /// as soon as that costs a fraction of the filesystem rather than a quarter of it.
    ///
    /// Three bounds, and the smallest wins: the resize inode's double-indirect map
    /// filled, the last block that map can name, and one sixty-fourth of the filesystem.
    /// The first two are the format's own ceiling — at a 4096-byte block the map holds
    /// 1024 descriptor blocks, each describing about 8 GiB, so the reach is about 8 TiB.
    /// The third is what keeps the ceiling from dominating a small filesystem: reaching
    /// 8 TiB costs 1024 blocks whatever the image's size, which is a quarter of a 16 MiB
    /// image and a sixty-fourth of a 256 MiB one. So a filesystem of 256 MiB or more takes
    /// the whole map, and a smaller one takes the share it can spare — a 16 MiB image
    /// reserves 64 blocks and still grows online to 520 GiB, which is past any device such
    /// an image is flashed to. Growth headroom therefore never costs more than 1.6% of a
    /// filesystem, comfortably under the 5% [`ReservedRatio`] holds back by default.
    ///
    /// It never fails, and it never turns a filesystem that would format into one that
    /// does not. On a filesystem already at the ceiling, and on one whose blocks the resize
    /// inode's 32-bit map cannot address, it reserves nothing; such a filesystem is grown
    /// offline by `resize2fs` instead. The feature set is still written as it was named, so
    /// `resize_inode` stays set over an inode that maps nothing — the state a filesystem is
    /// in once a resize has consumed every block it had reserved.
    /// [`Layout::reserved_gdt_blocks`] reports what was actually reserved, and
    /// [`Layout::max_grow_blocks`] how far it reaches.
    ///
    /// A larger reservation than this buys exactly one thing, a higher online-grow
    /// ceiling, and it is [`UpTo`](Self::UpTo) that buys it: an explicit target is honored
    /// to the format's ceiling and never reduced to fit this share.
    #[default]
    Max,
}

/// How many inodes a format provides.
///
/// The count fixes the size of every group's inode table, and with it how the groups
/// pack, so it is a planning input rather than a field set after the fact.
/// [`Auto`](Self::Auto) reproduces the size-driven bytes-per-inode ratio; the two
/// overrides name the ratio or the count directly.
///
/// A group's inodes are indexed by a one-block bitmap, so a group holds at most
/// `8 * block_size` of them. A density past that is refused with
/// [`GeometryError::InodesTooDense`] rather than capped, so an override that will not fit
/// is an error, not a silently smaller filesystem. The size-driven default never reaches
/// that ceiling.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum InodeCount {
    /// Derive the count from the filesystem size and a bytes-per-inode ratio chosen from
    /// size-thresholded buckets, the way an inode table is sized by default.
    #[default]
    Auto,
    /// One inode for every this many bytes of filesystem, overriding the size-driven
    /// ratio: a larger value yields fewer inodes, a smaller value more.
    BytesPerInode(NonZeroU64),
    /// A target inode count, spread across the groups. Each group's share is rounded up to
    /// fill whole inode-table blocks, then down to a multiple of eight so the group's
    /// inodes end on a byte boundary in the inode bitmap, and held at eight — the same
    /// `s_inodes_per_group` that `mke2fs` derives for the request.
    /// [`Layout::total_inodes`] reports the realized total.
    ///
    /// It meets or exceeds the request wherever an inode-table block holds a multiple of
    /// eight inodes. Where a block holds fewer than eight — `block_size / inode_size < 8`,
    /// which is the 1024-byte block at the default 256-byte inode and the 2048-byte block
    /// once the inode is 512 bytes — the multiple-of-eight step can leave the realized total
    /// a few inodes short of the request, and the floor of eight per group can put it above:
    /// a count spread thinly enough that a group's share falls under the step yields eight
    /// times the group count, whatever was asked for.
    Count(u32),
}

/// The share of a filesystem's blocks held back for the super-user (`s_r_blocks_count`).
///
/// A reserved fraction keeps a filesystem that has filled up usable by root — room to log
/// in and clear space — and keeps an unprivileged writer from consuming the last of it.
/// The reservation is a soft accounting limit the kernel enforces at allocation time; it
/// occupies no fixed region and changes no block placement, only this one superblock
/// count.
///
/// It is stored in hundredths of one percent so a fractional reservation stays exact
/// integer arithmetic: `500` is the 5% default, `150` is 1.5%, and `5000` (50%) is the
/// most the reservation may be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReservedRatio {
    /// Hundredths of one percent, in `0..=5000`.
    hundredths_of_percent: u16,
}

impl ReservedRatio {
    /// The largest reservation: half the filesystem.
    const MAX_HUNDREDTHS: u16 = 5000;

    /// The 5% reservation a format uses when the caller names none.
    pub const DEFAULT: Self = Self {
        hundredths_of_percent: 500,
    };

    /// A reservation of `hundredths` hundredths of one percent — `500` for 5%, `150` for
    /// 1.5% — or `None` past the 50% (`5000`) ceiling.
    #[must_use]
    pub fn from_hundredths_of_percent(hundredths: u16) -> Option<Self> {
        (hundredths <= Self::MAX_HUNDREDTHS).then_some(Self {
            hundredths_of_percent: hundredths,
        })
    }

    /// The reservation in hundredths of one percent.
    #[must_use]
    pub fn hundredths_of_percent(self) -> u16 {
        self.hundredths_of_percent
    }

    /// The blocks this reservation holds back from a filesystem of `total_blocks`:
    /// `floor(total_blocks * ratio)`, as exact integer arithmetic, for every block count a
    /// `u64` can hold.
    ///
    /// The multiplication is carried in 128 bits, so the exact product exists whatever the
    /// count — a 64-bit product would wrap above `2^64 / 5000` blocks, and a reservation
    /// that wrapped would be a silently wrong number of blocks rather than a refusal.
    /// Narrowing the quotient back is lossless because the ratio is capped at 50%, so the
    /// result is at most half of `total_blocks`.
    #[must_use]
    pub fn blocks(self, total_blocks: u64) -> u64 {
        let reserved = u128::from(total_blocks) * u128::from(self.hundredths_of_percent) / 10_000;
        reserved as u64
    }
}

impl Default for ReservedRatio {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Everything the planner needs to lay out a filesystem: its size, its feature set, and
/// the three sizing knobs a caller may name.
///
/// Every input to [`plan_layout`] is a field here rather than a parameter, so a geometry
/// knob the planner grows — a cluster size, an explicit blocks-per-group, a RAID stride —
/// arrives as a field a caller may ignore instead of as an argument every caller must
/// pass. [`new`](Self::new) takes the two inputs that have no default and defaults the
/// rest to what the size alone implies.
///
/// ```
/// # use ferrosys::ext::{FeatureSet, GrowReservation, PlanRequest, plan_layout};
/// let request = PlanRequest::new(64 << 20, FeatureSet::DEFAULT).grow(GrowReservation::UpTo(32 << 30));
/// let layout = plan_layout(&request).expect("plan a 64 MiB filesystem");
/// assert_eq!(layout.block_size, 4096);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PlanRequest {
    /// Size of the filesystem in bytes. The block count is this divided by the feature
    /// set's block size, so a size that is not a whole number of blocks is rounded down.
    pub size_bytes: u64,
    /// The feature set the layout is planned for, carrying the block and inode sizes.
    pub feature: FeatureSet,
    /// How much reserved descriptor headroom to build in, sizing the reserved GDT blocks
    /// that make the image resize-safe. This is the only thing that bounds "resize-safe",
    /// so it is named outright rather than derived from the size by a multiplier.
    /// Defaults to [`GrowReservation::Max`], which reserves as much as the format allows.
    pub grow: GrowReservation,
    /// How many inodes to provide. Defaults to [`InodeCount::Auto`], the size-driven
    /// count.
    pub inodes: InodeCount,
    /// The share of blocks held back for the super-user. Defaults to
    /// [`ReservedRatio::DEFAULT`], 5%.
    pub reserved: ReservedRatio,
}

impl PlanRequest {
    /// A request for a filesystem of `size_bytes` under `feature`, with every sizing knob
    /// at the value the size alone implies.
    #[must_use]
    pub const fn new(size_bytes: u64, feature: FeatureSet) -> Self {
        Self {
            size_bytes,
            feature,
            grow: GrowReservation::Max,
            inodes: InodeCount::Auto,
            reserved: ReservedRatio::DEFAULT,
        }
    }

    /// This request with the grow reservation replaced.
    #[must_use]
    pub const fn grow(mut self, grow: GrowReservation) -> Self {
        self.grow = grow;
        self
    }

    /// This request with the inode count replaced.
    #[must_use]
    pub const fn inodes(mut self, inodes: InodeCount) -> Self {
        self.inodes = inodes;
        self
    }

    /// This request with the super-user reservation replaced.
    #[must_use]
    pub const fn reserved(mut self, reserved: ReservedRatio) -> Self {
        self.reserved = reserved;
        self
    }
}

/// Plan the complete layout for a filesystem that may later grow.
///
/// # Errors
///
/// - [`GeometryError::Feature`] if the feature set is invalid.
/// - [`GeometryError::GrowTargetTooSmall`] if a [`GrowReservation::UpTo`] target is
///   below the requested size.
/// - [`GeometryError::TooSmall`] if the filesystem cannot hold group 0's metadata.
/// - [`GeometryError::GrowTargetTooLarge`] if a [`GrowReservation::UpTo`] target needs
///   more reserved blocks than the resize inode can represent.
/// - [`GeometryError::ReservationNeeds32BitBlocks`] if a [`GrowReservation::UpTo`]
///   target is given for a filesystem whose blocks the resize inode's 32-bit map
///   cannot address.
/// - [`GeometryError::BlockCountNeeds64Bit`] or [`GeometryError::BlockCountTooLarge`]
///   if the block count outruns the block numbers that describe it.
/// - [`GeometryError::TooManyGroups`] or [`GeometryError::TooManyInodes`] if the size
///   needs more block groups or inodes than the 32-bit counts on disk hold.
/// - [`GeometryError::InodesTooDense`] if an [`InodeCount`] override needs more inodes in
///   a group than its one-block bitmap indexes.
/// - [`GeometryError::FinalGroupTooSmall`] if the last group cannot hold its
///   metadata.
pub fn plan_layout(request: &PlanRequest) -> Result<Layout, GeometryError> {
    let &PlanRequest {
        size_bytes,
        feature,
        grow: reservation,
        inodes,
        reserved,
    } = request;
    feature.validate()?;

    let block_size = feature.block_size;
    let total_blocks = size_bytes / u64::from(block_size);

    // Only an explicit `UpTo` target can fall below the initial size; `None` and
    // `Max` are always realizable.
    if let GrowReservation::UpTo(bytes) = reservation {
        let target = bytes / u64::from(block_size);
        if target < total_blocks {
            return Err(GeometryError::GrowTargetTooSmall {
                target,
                initial: total_blocks,
            });
        }
    }

    if !feature.is_64bit() && total_blocks > MAX_32BIT_BLOCKS {
        return Err(GeometryError::BlockCountNeeds64Bit {
            blocks: total_blocks,
            limit: MAX_32BIT_BLOCKS,
        });
    }
    if total_blocks > MAX_EXTENT_BLOCKS {
        return Err(GeometryError::BlockCountTooLarge {
            blocks: total_blocks,
            limit: MAX_EXTENT_BLOCKS,
        });
    }

    // For 4 KiB (and larger) blocks the superblock sits inside block 0, so the
    // first data block is 0; for a 1 KiB block it is 1.
    let first_data_block = if block_size == 1024 { 1 } else { 0 };
    let fdb = u64::from(first_data_block);
    let blocks_per_group = 8 * block_size;
    let bpg = u64::from(blocks_per_group);
    let desc_size = feature.desc_size();
    let ipb = u64::from(feature.inodes_per_block());
    let inode_cap = u64::from(8 * block_size);
    // Sixteen groups per flex block group (`s_log_groups_per_flex = 4`). The layout below
    // packs each flex group's bitmaps and inode tables into its first member, which is a
    // valid layout only because `flex_bg` is set: `feature.validate()` above refuses to
    // clear it, so this fixed size never describes a filesystem the superblock advertises
    // as non-flex.
    let flex_bg_size: u32 = 16;
    // The resize inode threads the reserved blocks through a double-indirect map of
    // 4-byte slots, so one block of it holds this many descriptor blocks. The map is
    // indexed by descriptor-table slot modulo this count, so the reservation may fill
    // the map completely and is bounded only by it.
    let reserved_limit = u64::from(block_size) / 4;
    // The map holds 32-bit block numbers, and the blocks it points at are the reserved
    // descriptor blocks of the backup groups — which lie anywhere in the filesystem. A
    // filesystem whose blocks a 32-bit number cannot address therefore cannot have a
    // reservation at all, however small, and neither can one whose feature set has no
    // resize inode to hold the map. The same bound caps how far a reservation can
    // reach: growth mapped by the resize inode ends at the last block it can name.
    let resize_ceiling = MAX_32BIT_BLOCKS;
    let reservation_representable = total_blocks <= resize_ceiling;
    let can_reserve = feature.has_resize_inode() && reservation_representable;

    // The descriptor-table block count an `UpTo` target aims to fill, computed once.
    let up_to_gdt = if let GrowReservation::UpTo(bytes) = reservation {
        let target = bytes / u64::from(block_size);
        let groups = target.saturating_sub(fdb).div_ceil(bpg);
        Some(gdt_blocks_for(groups, desc_size, block_size))
    } else {
        None
    };
    // The descriptor-table block count that reaches the resize inode's own ceiling,
    // which bounds a `Max` reservation so it never reserves headroom no block the map
    // can name would use.
    let ceiling_gdt = gdt_blocks_for((resize_ceiling - fdb).div_ceil(bpg), desc_size, block_size);

    // The inode count follows the block count the filesystem keeps: a size-derived ratio
    // describes the groups actually built, so when a too-small final group is dropped the
    // count is recomputed from the smaller size rather than left describing the size first
    // asked for. `Auto` and a bytes-per-inode override scale with the size; an absolute
    // count does not. The floor of sixteen holds even a tiny filesystem to one inode-table
    // block's worth, matching how a small `-N`-style request rounds up to a full block.
    let inode_count_for = |blocks: u64| -> u64 {
        match inodes {
            InodeCount::Auto => blocks * u64::from(block_size) / inode_ratio(blocks, block_size),
            InodeCount::BytesPerInode(bytes) => blocks * u64::from(block_size) / bytes.get(),
            InodeCount::Count(count) => u64::from(count),
        }
        .max(16)
    };

    // Size the groups, descriptor reservation, and inode density together, dropping a
    // trailing partial group that cannot hold the metadata its position assigns it.
    // Each drop shrinks the filesystem to a whole number of usable groups, so the loop
    // runs at most twice.
    let mut total_blocks = total_blocks;
    let (group_count_u64, gdt_blocks, reserved_gdt_blocks, inodes_per_group, inode_table_blocks) = loop {
        // A filesystem below one full block plans as a single, empty group; the
        // group-0 overhead check below rejects it once the overhead is known.
        let addressable = total_blocks.saturating_sub(fdb);
        let group_count = addressable.div_ceil(bpg).max(1);
        if group_count > u64::from(u32::MAX) {
            return Err(GeometryError::TooManyGroups {
                blocks: total_blocks,
                groups: group_count,
                limit: u64::from(u32::MAX),
            });
        }

        // Reserved descriptor blocks past the table the current group count needs,
        // bounded by the resize inode's map.
        let gdt = gdt_blocks_for(group_count, desc_size, block_size);
        let reserved = match reservation {
            GrowReservation::None => 0,
            GrowReservation::UpTo(_) => {
                let want = up_to_gdt.unwrap_or(gdt).saturating_sub(gdt);
                if want > 0 && !feature.has_resize_inode() {
                    return Err(GeometryError::GrowTargetNeedsResizeInode);
                }
                if want > 0 && !reservation_representable {
                    return Err(GeometryError::ReservationNeeds32BitBlocks {
                        blocks: total_blocks,
                        limit: resize_ceiling,
                    });
                }
                if want > reserved_limit {
                    return Err(GeometryError::GrowTargetTooLarge {
                        needed: want,
                        limit: reserved_limit,
                    });
                }
                want
            }
            GrowReservation::Max if !can_reserve => 0,
            // The format's own ceiling, bounded by the share of the filesystem a
            // reservation may occupy. Filling the map costs the same 1024 blocks (at a
            // 4 KiB block) whatever the size, which is a quarter of a 16 MiB filesystem
            // and nothing at all on a large one — so past the knee this is the ceiling
            // and below it the share, and `Max` cannot make a format fail for lack of the
            // room its own headroom took.
            GrowReservation::Max => reserved_limit
                .min(ceiling_gdt.saturating_sub(gdt))
                .min(total_blocks / GROW_MAX_SHARE),
        };

        // Spread the inode count for the current block count across the groups. A group's
        // inodes are indexed by a one-block bitmap, so it holds at most `inode_cap` of
        // them; a density that needs more is refused rather than silently capped to fewer
        // inodes than were asked for. `Auto` and a bytes-per-inode ratio never trip this,
        // because the count is recomputed from the kept block count and a whole number of
        // groups holds its own size-derived inodes; only an explicit count that overflows
        // a group reaches it.
        let num_inodes = inode_count_for(total_blocks);
        let mut ipg = num_inodes.div_ceil(group_count);
        if ipg > inode_cap {
            return Err(GeometryError::InodesTooDense {
                inodes_per_group: ipg,
                limit: inode_cap,
            });
        }
        // Round up to fill whole inode-table blocks, then mask down to a multiple of eight
        // so a group's inodes end on a byte boundary in the inode bitmap, and hold the
        // result at eight. This reproduces how `mke2fs` sizes `s_inodes_per_group` byte for
        // byte, mask and floor included. The mask changes the value only when an inode-table
        // block holds fewer than eight inodes (`ipb < 8`: a 1024- or 2048-byte block at a
        // large inode size); there it can trim the group by one inode-table block, which is
        // why an explicit `Count` can realize a few inodes short of the request. The floor
        // catches the end of that: a per-group share below the step masks to zero, and a
        // group with no inodes is a group every tool divides by — so eight is the smallest a
        // group holds, and a filesystem carries at least eight inodes per group whatever
        // count was asked for. Two invariants survive the mask: `inode_cap` is a multiple of
        // both `ipb` and eight, so the rounded, masked value never exceeds the bitmap; and
        // `ipb` is a power of two no greater than eight, so a multiple of eight is a
        // multiple of `ipb` and `itb = ipg / ipb` stays a whole number of blocks.
        ipg = ((ipg.div_ceil(ipb) * ipb) & !7).max(MIN_INODES_PER_GROUP);
        let itb = ipg / ipb;

        // A partial final group is kept whenever it can physically hold the metadata
        // its position assigns it and still leave a data block free, so the filesystem
        // addresses the whole device. Only a final group that cannot is dropped, and
        // the blocks it would have held leave the filesystem with it.
        //
        // Under flex_bg a group's bitmaps and inode table live in its flex head, so a
        // non-head group needs only its superblock backup locally; a group that heads
        // its own flex block group must hold that flex group's packed tables. The
        // threshold is exactly what the post-placement check below demands, so a group
        // this keeps is a group that check accepts.
        let rem = addressable % bpg;
        if group_count >= 2 && rem != 0 {
            let last = (group_count - 1) as u32;
            let mut required = 0u64;
            if !feature.is_sparse_super() || sparse_super_has_copy(last) {
                required += 1 + gdt + reserved;
            }
            if feature.has_flex_bg() {
                // Under flex_bg only a group that heads its own flex block group holds
                // packed tables; a non-head group needs just its backup copy.
                if last.is_multiple_of(flex_bg_size) {
                    let members = group_count - u64::from(last);
                    let slots = if members == 1 {
                        u64::from(flex_bg_size)
                    } else {
                        members
                    };
                    required += 2 * slots + members * itb;
                }
            } else {
                // The block-mapped family places each group's own block bitmap, inode
                // bitmap, and inode table inside that group, so every group carries them.
                required += 2 + itb;
            }
            if rem < required + 1 {
                total_blocks -= rem;
                continue;
            }
        }
        break (
            group_count,
            gdt as u32,
            reserved as u32,
            ipg as u32,
            itb as u32,
        );
    };
    // The group count is bounded above inside the loop, so it fits a 32-bit group
    // number. The inode count follows from the size and the bytes-per-inode ratio, and
    // is bounded only here.
    let group_count = group_count_u64 as u32;
    let total_inodes_u64 = u64::from(inodes_per_group) * group_count_u64;
    if total_inodes_u64 > u64::from(u32::MAX) {
        return Err(GeometryError::TooManyInodes {
            blocks: total_blocks,
            inodes: total_inodes_u64,
            limit: u64::from(u32::MAX),
        });
    }
    let total_inodes = total_inodes_u64 as u32;

    // The grow target the reservation sized the reserved blocks for, in blocks. The
    // descriptor table can describe `(gdt_blocks + reserved_gdt_blocks)` blocks' worth
    // of groups; `Max` reports that ceiling, `UpTo` the requested target, `None` the
    // unchanged size.
    let max_grow_blocks = match reservation {
        GrowReservation::None => total_blocks,
        GrowReservation::UpTo(bytes) => bytes / u64::from(block_size),
        GrowReservation::Max => {
            let per_block = u64::from(block_size) / u64::from(desc_size);
            let describable = (u64::from(gdt_blocks) + u64::from(reserved_gdt_blocks)) * per_block;
            (describable * bpg + fdb)
                .min(resize_ceiling)
                .max(total_blocks)
        }
    };

    // Reject a filesystem too small for group 0's fixed metadata: superblock and
    // descriptors, the reserved GDT, the bitmaps and inode tables group 0 physically
    // holds, and one data block for the root.
    let group0_tables = if feature.has_flex_bg() {
        // Group 0 heads the first flex block group and holds every member's packed
        // bitmaps and tables; a single-member flex reserves a full set of table slots.
        let g0_members = group_count_u64.min(u64::from(flex_bg_size));
        let g0_slots = if g0_members == 1 {
            u64::from(flex_bg_size)
        } else {
            g0_members
        };
        2 * g0_slots + g0_members * u64::from(inode_table_blocks)
    } else {
        // The block-mapped family: group 0 holds only its own block bitmap, inode
        // bitmap, and inode table.
        2 + u64::from(inode_table_blocks)
    };
    let group0_overhead = super_overhead(gdt_blocks, reserved_gdt_blocks) + group0_tables + 1;
    if total_blocks < group0_overhead {
        return Err(GeometryError::TooSmall {
            blocks: total_blocks,
            overhead: group0_overhead,
            reserved_gdt_blocks: u64::from(reserved_gdt_blocks),
        });
    }

    let reserved_blocks = reserved.blocks(total_blocks);

    let mut layout = Layout {
        feature,
        block_size,
        total_blocks,
        blocks_per_group,
        first_data_block,
        group_count,
        inodes_per_group,
        inode_table_blocks,
        total_inodes,
        gdt_blocks,
        reserved_gdt_blocks,
        flex_bg_size,
        max_grow_blocks,
        reserved_blocks,
        groups: Vec::with_capacity(group_count as usize),
    };

    // First pass: block ranges and which groups carry a copy. The bitmap and
    // inode-table addresses depend on the flex head's placement, so they are filled
    // in the second pass once every group's `has_super` is known.
    for index in 0..group_count {
        let start_block = fdb + u64::from(index) * u64::from(blocks_per_group);
        let end_block = (start_block + u64::from(blocks_per_group)).min(total_blocks);
        let block_count = (end_block - start_block) as u32;
        let has_super = if feature.is_sparse_super() {
            sparse_super_has_copy(index)
        } else {
            true
        };
        layout.groups.push(GroupLayout {
            index,
            start_block,
            block_count,
            has_super,
            block_bitmap: 0,
            inode_bitmap: 0,
            inode_table: 0,
        });
    }

    // Second pass: place each group's bitmaps and inode tables.
    let itb = u64::from(inode_table_blocks);
    let mut placed_end = 0u64;

    if feature.has_flex_bg() {
        // Pack each flex block group's bitmaps and inode tables into its head group.
        // They begin after the head group's own superblock copy and run forward, but no
        // table straddles a backup superblock's window — a run that would is pushed past
        // it. At a 4096-byte block a flex block group's tables fit inside its head and
        // never meet one; at 1024 they routinely do.
        let backups: Vec<BlockRange> = (0..group_count)
            .filter_map(|g| layout.super_overhead_region(g))
            .collect();

        let mut head = 0u32;
        while head < group_count {
            let members = layout.flex_members(head);
            // A flex block group reserves a slot per member for each bitmap, so the two
            // bitmap runs and the tables keep their relative positions even when a group
            // is displaced.
            let slots = u64::from(layout.flex_slots(head));
            let overhead = layout.super_overhead_region(head).map_or(0, |r| r.len);
            let mut cursor = (layout.groups[head as usize].start_block + overhead).max(placed_end);

            let mut block_bitmaps = Vec::with_capacity(members as usize);
            for _ in 0..members {
                let b = first_fit(cursor, 1, &backups);
                block_bitmaps.push(b);
                cursor = b + 1;
            }
            cursor = cursor.max(block_bitmaps[0] + slots);

            let mut inode_bitmaps = Vec::with_capacity(members as usize);
            for _ in 0..members {
                let b = first_fit(cursor, 1, &backups);
                inode_bitmaps.push(b);
                cursor = b + 1;
            }
            cursor = cursor.max(inode_bitmaps[0] + slots);

            for m in 0..members {
                let table = first_fit(cursor, itb, &backups);
                cursor = table + itb;
                let g = &mut layout.groups[(head + m) as usize];
                g.block_bitmap = block_bitmaps[m as usize];
                g.inode_bitmap = inode_bitmaps[m as usize];
                g.inode_table = table;
            }
            placed_end = cursor;
            head += layout.flex_bg_size;
        }
    } else {
        // The block-mapped family (ext2/ext3): each group holds its own block bitmap,
        // inode bitmap, and inode table, in that fixed order, immediately after its
        // superblock-and-descriptor overhead. Nothing is packed or displaced — a group's
        // metadata never leaves the group — so there is no stepping around backups.
        for index in 0..group_count {
            let overhead = layout.super_overhead_region(index).map_or(0, |r| r.len);
            let base = layout.groups[index as usize].start_block + overhead;
            let g = &mut layout.groups[index as usize];
            g.block_bitmap = base;
            g.inode_bitmap = base + 1;
            g.inode_table = base + 2;
            placed_end = base + 2 + itb;
        }
    }

    // The final group must physically hold whatever metadata its position assigns it:
    // a backup copy, and — if it heads a flex block group — the packed tables. The drop
    // threshold above already leaves a partial final group room for both, so what this
    // catches is a table that placement pushed past the end of the filesystem while
    // stepping around a backup superblock near it.
    let last = group_count - 1;
    let last_group = &layout.groups[last as usize];
    let mut last_overhead = 0u64;
    if let Some(r) = layout.super_overhead_region(last) {
        last_overhead += r.len;
    }
    if feature.has_flex_bg() {
        if layout.is_flex_head(last) {
            last_overhead += layout.flex_meta_span(last);
        }
    } else {
        // The block-mapped family: the final group holds its own bitmaps and table.
        last_overhead += 2 + u64::from(inode_table_blocks);
    }
    if u64::from(last_group.block_count) < last_overhead + 1 || placed_end > layout.total_blocks {
        return Err(GeometryError::FinalGroupTooSmall {
            blocks: u64::from(last_group.block_count),
            overhead: last_overhead,
        });
    }

    Ok(layout)
}

/// The first block at or after `from` where `len` consecutive blocks clear every
/// window in `windows`, which are sorted and do not overlap. A run that would
/// straddle a window starts again past its end.
fn first_fit(from: u64, len: u64, windows: &[BlockRange]) -> u64 {
    let mut start = from;
    'restart: loop {
        for w in windows {
            if w.start < start + len && start < w.end() {
                start = w.end();
                continue 'restart;
            }
        }
        return start;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GROW_32G: u64 = 32 * 1024 * MIB;

    fn plan(mib: u64) -> Layout {
        plan_layout(
            &PlanRequest::new(mib * MIB, FeatureSet::default())
                .grow(GrowReservation::UpTo(GROW_32G)),
        )
        .expect("plan")
    }

    /// Plan at a block size other than the default.
    fn plan_at(block_size: u32, mib: u64) -> Layout {
        let fs = FeatureSet {
            block_size,
            ..FeatureSet::default()
        };
        plan_layout(&PlanRequest::new(mib * MIB, fs).grow(GrowReservation::UpTo(GROW_32G)))
            .expect("plan")
    }

    /// Plan with the default inode density and reserved ratio: the two inputs every test
    /// that exercises only the size, grow target, and feature set leaves alone.
    fn plan_geo(
        size_bytes: u64,
        reservation: GrowReservation,
        feature: FeatureSet,
    ) -> Result<Layout, GeometryError> {
        plan_layout(&PlanRequest::new(size_bytes, feature).grow(reservation))
    }

    /// Plan with a specific inode count and no grow reservation, isolating the inode
    /// density from the reserved descriptor blocks.
    fn plan_inodes(mib: u64, inodes: InodeCount) -> Layout {
        plan_layout(
            &PlanRequest::new(mib * MIB, FeatureSet::default())
                .grow(GrowReservation::None)
                .inodes(inodes),
        )
        .expect("plan")
    }

    /// Plan with a specific inode count at a block size other than the 4096-byte default.
    /// The default 256-byte inode fits four to a 1024-byte block (`ipb = 4`), the regime
    /// where the multiple-of-eight step in the inode-count rounding is not a no-op.
    fn plan_bs_inodes(block_size: u32, mib: u64, inodes: InodeCount) -> Layout {
        let fs = FeatureSet {
            block_size,
            ..FeatureSet::default()
        };
        plan_layout(
            &PlanRequest::new(mib * MIB, fs)
                .grow(GrowReservation::None)
                .inodes(inodes),
        )
        .expect("plan")
    }

    /// Plan with a specific reserved ratio and no grow reservation.
    fn plan_reserved(mib: u64, reserved: ReservedRatio) -> Layout {
        plan_layout(
            &PlanRequest::new(mib * MIB, FeatureSet::default())
                .grow(GrowReservation::None)
                .reserved(reserved),
        )
        .expect("plan")
    }

    #[test]
    fn a_flex_block_groups_tables_step_around_the_backups_they_meet() {
        // At 1024-byte blocks a group spans 8 MiB, so a sixteen-member flex block
        // group's inode tables outgrow their head group and run into the backup
        // superblock of the group after it. A table never straddles that window.
        let l = plan_at(1024, 200);
        let itb = u64::from(l.inode_table_blocks);
        let backups: Vec<BlockRange> = (0..l.group_count)
            .filter_map(|g| l.super_overhead_region(g))
            .collect();
        assert!(backups.len() > 1, "this size has backup superblocks");

        for g in &l.groups {
            let table = BlockRange {
                start: g.inode_table,
                len: itb,
            };
            for w in &backups {
                assert!(
                    table.end() <= w.start || table.start >= w.end(),
                    "group {}'s inode table {table:?} straddles the backup at {w:?}",
                    g.index
                );
            }
        }

        // The tables do not all abut: one was pushed past a backup window.
        assert!(
            l.groups
                .windows(2)
                .any(|w| w[1].inode_table > w[0].inode_table + itb),
            "no table was displaced, so this size does not exercise the rule"
        );
    }

    /// Plan a block-mapped (ext2/ext3) layout: no `extent`, no `flex_bg`, no `64bit`, so
    /// each group carries its own bitmaps and inode table and the non-flex placement
    /// branch runs. The grow reservation is left off to isolate the placement from the
    /// reserved descriptor blocks.
    fn plan_block_mapped(feature: FeatureSet, block_size: u32, mib: u64) -> Layout {
        let fs = FeatureSet {
            block_size,
            ..feature
        };
        plan_layout(&PlanRequest::new(mib * MIB, fs).grow(GrowReservation::None)).expect("plan")
    }

    #[test]
    fn block_mapped_metadata_stays_within_each_group() {
        // The ext2/ext3 family has neither flex_bg nor extents, so planning takes the
        // per-group placement branch the flex families never reach: each group holds its
        // own block bitmap, inode bitmap, and inode table, in that fixed order, right
        // after its superblock-and-descriptor overhead, and no group's metadata leaves
        // the group. 1024- and 2048-byte blocks are the sizes where the geometry's edges
        // bite, so they run alongside the 4096 default, and against both baselines —
        // ext3's classic-mapped journal shares this placement with ext2's.
        for feature in [FeatureSet::EXT2, FeatureSet::EXT3] {
            for bs in [1024u32, 2048, 4096] {
                // Enough blocks to span several groups and reach the first sparse_super
                // backups (groups 1 and 3): a group is 8 * bs blocks, many groups at 1024
                // and a handful at 4096.
                let l = plan_block_mapped(feature, bs, 600);
                assert!(!l.feature.has_flex_bg(), "the family is non-flex (bs={bs})");
                assert!(
                    !l.feature.has_extents(),
                    "the family is block-mapped (bs={bs})"
                );
                assert_eq!(
                    l.feature.desc_size(),
                    32,
                    "32-byte descriptors without 64bit"
                );
                assert!(
                    l.group_count >= 4,
                    "need at least four groups for the group-3 backup (bs={bs}, groups={})",
                    l.group_count
                );
                assert!(
                    l.super_overhead_region(1).is_some() && l.super_overhead_region(3).is_some(),
                    "sparse_super keeps backups in groups 1 and 3 (bs={bs})"
                );

                let itb = u64::from(l.inode_table_blocks);
                for g in &l.groups {
                    // The metadata sits in fixed order immediately after this group's own
                    // superblock-and-descriptor overhead — zero for a group without a copy.
                    let overhead = l.super_overhead_region(g.index).map_or(0, |r| r.len);
                    let base = g.start_block + overhead;
                    assert_eq!(
                        g.block_bitmap, base,
                        "group {} block bitmap (bs={bs})",
                        g.index
                    );
                    assert_eq!(
                        g.inode_bitmap,
                        base + 1,
                        "group {} inode bitmap (bs={bs})",
                        g.index
                    );
                    assert_eq!(
                        g.inode_table,
                        base + 2,
                        "group {} inode table (bs={bs})",
                        g.index
                    );

                    // None of it leaves the group — the block-mapped invariant the reader's
                    // MetadataOutsideGroup check enforces on the way back in. The loop runs
                    // over the final group too, so this also proves the final-group guard's
                    // success path: its own metadata fits inside its (possibly partial) span.
                    let group_end = g.start_block + u64::from(g.block_count);
                    assert!(
                        g.block_bitmap >= g.start_block && g.inode_table + itb <= group_end,
                        "group {}'s metadata {}..{} leaves the group {}..{} (bs={bs})",
                        g.index,
                        g.block_bitmap,
                        g.inode_table + itb,
                        g.start_block,
                        group_end
                    );
                }

                // And the placements tile the filesystem without collision.
                let runs = l.metadata_regions();
                for pair in runs.windows(2) {
                    assert!(
                        pair[0].end() <= pair[1].start,
                        "block-mapped metadata overlaps at bs={bs}: {:?} then {:?}",
                        pair[0],
                        pair[1]
                    );
                }
            }
        }
    }

    #[test]
    fn metadata_never_overlaps_at_any_block_size() {
        // Bitmaps, inode tables, and the superblock backups they step around must
        // tile the filesystem without collision, or the allocator hands out a block
        // that metadata already owns.
        for bs in [1024u32, 2048, 4096] {
            for mib in [16u64, 33, 64, 120, 200, 512] {
                let l = plan_at(bs, mib);
                let runs = l.metadata_regions();
                for pair in runs.windows(2) {
                    assert!(
                        pair[0].end() <= pair[1].start,
                        "{bs}-byte blocks, {mib} MiB: {:?} overlaps {:?}",
                        pair[0],
                        pair[1]
                    );
                }
                let last = runs.last().expect("a filesystem has metadata");
                assert!(last.end() <= l.total_blocks, "metadata runs past the end");
            }
        }
    }

    #[test]
    fn a_groups_inode_count_ends_on_a_byte_boundary() {
        // A group's inodes must be a whole number of bytes in the inode bitmap, or
        // the bitmap's padding cannot be written. Only a 1024-byte block, which fits
        // four inodes, can round to a value that is not a multiple of eight.
        for bs in [1024u32, 2048, 4096] {
            for mib in [16u64, 33, 64, 120, 200, 512, 2048] {
                let l = plan_at(bs, mib);
                assert!(
                    l.inodes_per_group.is_multiple_of(8),
                    "{bs}-byte blocks, {mib} MiB: inodes_per_group {} is not a multiple of 8",
                    l.inodes_per_group
                );
                assert!(l.inodes_per_group > 0);
            }
        }
    }

    #[test]
    fn only_a_1024_byte_block_reserves_block_zero() {
        assert_eq!(plan_at(1024, 64).first_data_block, 1);
        assert_eq!(plan_at(2048, 64).first_data_block, 0);
        assert_eq!(plan_at(4096, 64).first_data_block, 0);
    }

    #[test]
    fn a_filesystem_past_thirty_two_bits_needs_the_64bit_feature() {
        // Without `64bit` every block number on disk is 32 bits wide, so a larger
        // filesystem would write truncated bitmap and inode-table addresses. It must
        // be refused, not silently corrupted.
        let bytes = 20_000_000_000_000u64; // an 18.2 TiB "20 TB" drive
        let no_64bit = FeatureSet {
            incompat: crate::feature::Incompat::from_bits(
                FeatureSet::default().incompat.bits()
                    & !crate::feature::Incompat::SIXTY_FOUR_BIT.bits(),
            ),
            ..FeatureSet::default()
        };
        assert!(!no_64bit.is_64bit());
        assert!(matches!(
            plan_geo(bytes, GrowReservation::UpTo(bytes), no_64bit),
            Err(GeometryError::BlockCountNeeds64Bit { .. })
        ));

        // Just under the limit plans; the feature is only needed past it.
        let under = MAX_32BIT_BLOCKS * 4096;
        assert!(plan_geo(under, GrowReservation::UpTo(under), no_64bit).is_ok());
    }

    #[test]
    fn the_planner_addresses_a_drive_past_thirty_two_bits_exactly() {
        // The block numbers are already 64 bits wide throughout, so a filesystem past
        // 2^32 blocks plans without loss. Its inode count must still fit the 32-bit
        // field the superblock stores it in.
        for bytes in [
            20_000_000_000_000u64, // an 18.2 TiB "20 TB" drive
            64 * 1024 * 1024 * MIB,
        ] {
            let l =
                plan_geo(bytes, GrowReservation::UpTo(bytes), FeatureSet::default()).expect("plan");
            assert_eq!(l.total_blocks, bytes / 4096, "block count is exact");
            assert!(
                l.total_blocks > MAX_32BIT_BLOCKS,
                "this size is past 32 bits"
            );
            assert_eq!(
                u64::from(l.total_inodes),
                u64::from(l.inodes_per_group) * u64::from(l.group_count)
            );
        }
    }

    #[test]
    fn a_filesystem_past_what_an_extent_addresses_is_refused() {
        // An extent leaf holds 48 bits of physical block number, so blocks past that
        // could hold no file data.
        let bytes = (MAX_EXTENT_BLOCKS + 1) * 4096;
        assert!(matches!(
            plan_geo(bytes, GrowReservation::UpTo(bytes), FeatureSet::default()),
            Err(GeometryError::BlockCountTooLarge { .. })
        ));
    }

    #[test]
    fn is_power_of_matches_sparse_super_backups() {
        // sparse_super backups: 1, powers of 3, 5, 7.
        for g in [1u32, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343] {
            assert!(sparse_super_has_copy(g), "group {g} should carry a copy");
        }
        for g in [2u32, 4, 6, 8, 10, 11, 15, 16, 24, 26, 48] {
            assert!(!sparse_super_has_copy(g), "group {g} should not");
        }
        assert!(sparse_super_has_copy(0), "primary");
    }

    #[test]
    fn single_group_64mib_matches_ground_truth() {
        // 64 MiB baseline: 16384 blocks, 1 group, ipg 16384, itb 1024, reserved GDT
        // 3, block bitmap 5, inode bitmap 21, inode table 37.
        let l = plan(64);
        assert_eq!(l.total_blocks, 16384);
        assert_eq!(l.group_count, 1);
        assert_eq!(l.inodes_per_group, 16384);
        assert_eq!(l.inode_table_blocks, 1024);
        assert_eq!(l.total_inodes, 16384);
        assert_eq!(l.gdt_blocks, 1);
        assert_eq!(l.reserved_gdt_blocks, 3);
        assert_eq!(l.reserved_blocks, 819);
        let g0 = &l.groups[0];
        assert!(g0.has_super);
        assert_eq!(g0.block_bitmap, 5);
        assert_eq!(g0.inode_bitmap, 21, "single-group flex reserves 16 slots");
        assert_eq!(g0.inode_table, 37);
        assert!(l.backup_groups().is_empty(), "one group: no backups");
    }

    #[test]
    fn an_absolute_inode_count_rounds_up_to_fill_the_group_tables() {
        // A count is spread across the groups and each group's share rounded up to a whole
        // inode-table block, so the realized total can exceed the request. On the 64 MiB
        // single group, 5000 fills 313 blocks of 16 inodes: 5008 inodes.
        let l = plan_inodes(64, InodeCount::Count(5000));
        assert_eq!(l.group_count, 1);
        assert_eq!(l.inodes_per_group, 5008);
        assert_eq!(l.total_inodes, 5008);

        // Across two groups (256 MiB) the count is split first, then each half rounded up:
        // 2500 per group fills 157 blocks, 2512 inodes, 5024 total.
        let l = plan_inodes(256, InodeCount::Count(5000));
        assert_eq!(l.group_count, 2);
        assert_eq!(l.inodes_per_group, 2512);
        assert_eq!(l.total_inodes, 5024);
    }

    #[test]
    fn an_absolute_inode_count_at_1024_byte_blocks_matches_mke2fs() {
        // At 1024-byte blocks the default 256-byte inode fits four to a block (ipb = 4), so
        // a group's inode count fills whole inode-table blocks and is then masked down to a
        // multiple of eight. Each pair is pinned against `mke2fs 1.47.0 -b 1024 -I 256 -N`
        // on a single-group (8 MiB) image: `s_inodes_per_group` is byte-identical to what
        // mke2fs sizes, mask included. The realized count can therefore land a few below
        // the request — the documented contract for `InodeCount::Count` at this block size,
        // not "at least this many".
        for (request, want_ipg) in [
            (2040u32, 2040u32),
            (2041, 2040),
            (2044, 2040), // fill 2044 (511 blocks) masks down to 2040 (510 blocks)
            (2046, 2048),
            (2048, 2048),
            (2049, 2048),
            (2050, 2048), // two below the request, exactly as mke2fs sizes it
            (2052, 2048),
            (2053, 2056),
        ] {
            let l = plan_bs_inodes(1024, 8, InodeCount::Count(request));
            assert_eq!(l.group_count, 1, "8 MiB at 1024-byte blocks is one group");
            assert_eq!(
                l.inodes_per_group, want_ipg,
                "Count({request}) at 1024-byte blocks: inodes_per_group",
            );
            assert_eq!(
                l.total_inodes, want_ipg,
                "single group: total equals per-group",
            );
        }
    }

    #[test]
    fn an_absolute_inode_count_at_2048_byte_blocks_masks_to_eight() {
        // The other regime where a block holds four inodes: a 2048-byte block with a
        // 512-byte inode. The mask behaves the same. Pinned against
        // `mke2fs 1.47.0 -b 2048 -I 512 -N` on a single-group (16 MiB) image.
        let fs = FeatureSet {
            block_size: 2048,
            inode_size: 512,
            ..FeatureSet::default()
        };
        for (request, want_ipg) in [(4090u32, 4088u32), (4094, 4096), (4097, 4096)] {
            let l = plan_layout(
                &PlanRequest::new(16 * MIB, fs)
                    .grow(GrowReservation::None)
                    .inodes(InodeCount::Count(request)),
            )
            .expect("plan");
            assert_eq!(l.group_count, 1, "16 MiB at 2048-byte blocks is one group");
            assert_eq!(
                l.inodes_per_group, want_ipg,
                "Count({request}) at 2048-byte blocks: inodes_per_group",
            );
        }
    }

    #[test]
    fn a_count_spread_below_the_rounding_step_still_leaves_every_group_inodes() {
        // The end of the range the mask trims: a count spread over enough groups that a
        // group's share falls below the multiple-of-eight step. Masking alone would take it
        // to zero, and a group with no inodes is a filesystem with an inode table of no
        // blocks, an inodes-per-group of nothing for every tool to divide by, and no room
        // for the eleven inodes a filesystem's own structures occupy.
        //
        // Each row is pinned against `mke2fs 1.47.0 -b 1024 -I 256 -N <count>` at the same
        // size, which floors `s_inodes_per_group` at eight for exactly this reason — so the
        // floor keeps the geometry byte-identical rather than departing from it.
        for (mib, request, want_ipg, want_total) in [
            (8u64, 16u32, 16u32, 16u32), // one group: the share is the count
            (16, 16, 8, 16),             // two groups, eight each
            (32, 16, 8, 32),             // four groups: masking alone would give none
            (64, 32, 8, 64),             // eight groups
            (128, 64, 8, 128),           // sixteen groups
        ] {
            let l = plan_bs_inodes(1024, mib, InodeCount::Count(request));
            assert_eq!(
                (l.inodes_per_group, l.total_inodes),
                (want_ipg, want_total),
                "Count({request}) on {mib} MiB at 1024-byte blocks",
            );
            assert!(
                l.inode_table_blocks > 0,
                "Count({request}) on {mib} MiB: a group's inode table has no blocks",
            );
        }
    }

    #[test]
    fn a_bytes_per_inode_ratio_overrides_the_size_driven_one() {
        // One inode per N bytes. On 64 MiB (16384 blocks, 67108864 bytes), 16384
        // bytes/inode is 4096 inodes; 65536 is 1024. Both override the 4096-byte ratio the
        // size alone would pick.
        let bpi = |n: u64| InodeCount::BytesPerInode(NonZeroU64::new(n).unwrap());
        assert_eq!(plan_inodes(64, bpi(16384)).total_inodes, 4096);
        assert_eq!(plan_inodes(64, bpi(65536)).total_inodes, 1024);
    }

    #[test]
    fn a_density_past_one_groups_bitmap_is_refused() {
        // A group's inode bitmap indexes 32768 inodes at a 4 KiB block. An absolute count
        // that needs more per group is refused rather than silently reduced.
        let too_many = plan_layout(
            &PlanRequest::new(64 * MIB, FeatureSet::default())
                .grow(GrowReservation::None)
                .inodes(InodeCount::Count(40000)),
        )
        .unwrap_err();
        assert!(matches!(
            too_many,
            GeometryError::InodesTooDense { limit: 32768, .. }
        ));

        // A ratio of one inode per 1024 bytes is four per block, 131072 in a single group
        // — four times what the bitmap holds — and is refused the same way, not capped.
        let too_dense = plan_layout(
            &PlanRequest::new(64 * MIB, FeatureSet::default())
                .grow(GrowReservation::None)
                .inodes(InodeCount::BytesPerInode(NonZeroU64::new(1024).unwrap())),
        )
        .unwrap_err();
        assert!(matches!(too_dense, GeometryError::InodesTooDense { .. }));
    }

    #[test]
    fn auto_density_never_overflows_a_group_at_the_drop_boundary() {
        // A filesystem one block past a whole group drops that block's group; were the
        // inode count fixed from the pre-drop size, it would leave one inode too many for
        // the single group that remains. The count follows the kept blocks instead, so
        // `Auto` plans cleanly at every size around the boundary rather than refusing one.
        let bpg = 8 * 4096u64;
        for extra in [0u64, 1, 2, 7] {
            let blocks = bpg + extra;
            let l = plan_geo(blocks * 4096, GrowReservation::None, FeatureSet::default())
                .unwrap_or_else(|e| panic!("Auto refused {blocks} blocks: {e}"));
            assert!(u64::from(l.inodes_per_group) <= bpg);
        }
    }

    #[test]
    fn the_reserved_ratio_holds_back_an_exact_share() {
        // The default is 5% of the block count, floored.
        let l = plan_reserved(64, ReservedRatio::DEFAULT);
        assert_eq!(l.total_blocks, 16384);
        assert_eq!(l.reserved_blocks, 819); // floor(16384 * 0.05)

        // A fractional ratio stays exact integer arithmetic: 1.5% of 16384 is 245.76,
        // floored to 245 — what a floating-point formatter computes, without the float.
        let r = ReservedRatio::from_hundredths_of_percent(150).unwrap();
        assert_eq!(plan_reserved(64, r).reserved_blocks, 245);

        // Zero holds nothing back; the 50% ceiling holds back half.
        let none = ReservedRatio::from_hundredths_of_percent(0).unwrap();
        assert_eq!(plan_reserved(64, none).reserved_blocks, 0);
        let half = ReservedRatio::from_hundredths_of_percent(5000).unwrap();
        assert_eq!(plan_reserved(64, half).reserved_blocks, 8192);

        // The ratio is capped at 50%.
        assert!(ReservedRatio::from_hundredths_of_percent(5001).is_none());

        // The share is exact for every block count a `u64` can hold, not only for the ones
        // an ext4 filesystem reaches. A 64-bit product would wrap above `2^64 / 5000`
        // blocks and hand back a reservation smaller than the one asked for.
        assert_eq!(half.blocks(u64::MAX), u64::MAX / 2);
        assert_eq!(ReservedRatio::DEFAULT.blocks(u64::MAX), u64::MAX / 20);
        // One block over the widest count a 64-bit multiply survives at the default ratio.
        let past_the_64_bit_product = u64::MAX / 500 + 1;
        assert_eq!(
            ReservedRatio::DEFAULT.blocks(past_the_64_bit_product),
            past_the_64_bit_product / 20
        );
    }

    #[test]
    fn four_groups_512mib_matches_ground_truth() {
        // 512 MiB: 131072 blocks, 4 groups, ipg 8192, itb 512, backups at 1 and 3.
        let l = plan(512);
        assert_eq!(l.total_blocks, 131072);
        assert_eq!(l.group_count, 4);
        assert_eq!(l.inodes_per_group, 8192);
        assert_eq!(l.inode_table_blocks, 512);
        assert_eq!(l.total_inodes, 32768);
        assert_eq!(l.reserved_gdt_blocks, 3);
        assert_eq!(l.backup_groups(), vec![1, 3]);

        // Group placements from dumpe2fs.
        let bmp: Vec<_> = l.groups.iter().map(|g| g.block_bitmap).collect();
        assert_eq!(bmp, vec![5, 6, 7, 8]);
        let ibmp: Vec<_> = l.groups.iter().map(|g| g.inode_bitmap).collect();
        assert_eq!(ibmp, vec![9, 10, 11, 12]);
        let itbl: Vec<_> = l.groups.iter().map(|g| g.inode_table).collect();
        assert_eq!(itbl, vec![13, 525, 1037, 1549]);
    }

    #[test]
    fn drop_is_flex_aware() {
        // A partial final group that heads its own flex block group and cannot hold
        // that group's packed tables is dropped: 2049 MiB starts as 17 groups but
        // group 16 (256 blocks) cannot hold its ~515 table blocks, so the group is
        // excluded and the filesystem is 16 groups.
        let l = plan(2049);
        assert_eq!(l.group_count, 16);
        assert_eq!(l.total_blocks, 524288);
        // The inode count follows the kept block count, so density reflects the 16 whole
        // groups that survive the drop — 2048 MiB — not the 2049 MiB first asked for. Those
        // sixteen groups hold exactly one full inode table each at the default ratio.
        assert_eq!(l.inodes_per_group, 8192);
        assert_eq!(l.inode_table_blocks, 512);

        // A partial final group that is *not* a flex head keeps only its own backup
        // locally, so it survives even when small: 129 MiB stays 2 groups, its final
        // group holding 256 blocks (its bitmaps and table live in group 0).
        let l = plan(129);
        assert_eq!(l.group_count, 2);
        assert_eq!(l.groups[1].block_count, 256);
        assert!(l.groups[1].has_super, "group 1 is a sparse_super backup");
    }

    #[test]
    fn partial_final_group() {
        // 200 MiB = 51200 blocks: 2 groups, last group holds 51200 - 32768 = 18432.
        let l = plan(200);
        assert_eq!(l.total_blocks, 51200);
        assert_eq!(l.group_count, 2);
        assert_eq!(l.groups[0].block_count, 32768);
        assert_eq!(l.groups[1].block_count, 18432);
    }

    #[test]
    fn seventeen_groups_partial_trailing_flex_reserves_full_slots() {
        // 2176 MiB = 17 groups: flex 1 holds only group 16, so it reserves 16
        // slots — block bitmap at group start, inode bitmap at +16, table at +32.
        let l = plan(2176);
        assert_eq!(l.group_count, 17);
        let g16 = &l.groups[16];
        assert_eq!(g16.start_block, 16 * 32768);
        assert_eq!(g16.block_bitmap, 16 * 32768);
        assert_eq!(g16.inode_bitmap, 16 * 32768 + 16);
        assert_eq!(g16.inode_table, 16 * 32768 + 32);
    }

    #[test]
    fn reserved_gdt_is_zero_at_the_grow_target() {
        // A filesystem already at the 32 GiB grow target reserves no GDT blocks.
        let l = plan_geo(
            GROW_32G,
            GrowReservation::UpTo(GROW_32G),
            FeatureSet::default(),
        )
        .unwrap();
        assert_eq!(l.group_count, 256);
        assert_eq!(l.gdt_blocks, 4);
        assert_eq!(l.reserved_gdt_blocks, 0);
    }

    #[test]
    fn none_reserves_no_descriptor_headroom() {
        // GrowReservation::None formats at the final size: no reserved GDT blocks, and
        // the reported grow target is the initial size itself.
        let l = plan_geo(64 * MIB, GrowReservation::None, FeatureSet::default()).unwrap();
        assert_eq!(l.reserved_gdt_blocks, 0);
        assert_eq!(l.max_grow_blocks, l.total_blocks);
    }

    #[test]
    fn max_reserves_the_ceiling_it_can_afford() {
        // Max takes the resize inode's whole map — block_size / 4, so 1024 at a 4 KiB
        // block, the meta_bg-free ceiling — as soon as that costs no more than a
        // sixty-fourth of the filesystem, and the share it can spare below that. The knee
        // is where the two meet: 1024 blocks is a sixty-fourth of 65536, which is 256 MiB.
        let at =
            |mib: u64| plan_geo(mib * MIB, GrowReservation::Max, FeatureSet::default()).unwrap();

        // At and above the knee: the whole map. With gdt 1 that table describes 1025
        // blocks' worth of groups — roughly 8 TiB.
        let l = at(256);
        assert_eq!(l.gdt_blocks, 1);
        assert_eq!(l.reserved_gdt_blocks, 1024);
        assert_eq!(l.max_grow_blocks, 1025 * 64 * 32768);
        assert_eq!(at(1024).reserved_gdt_blocks, 1024);
        assert_eq!(at(16 * 1024).reserved_gdt_blocks, 1024);

        // Below it, the share — pinned per size, since the numbers are what a small image
        // actually pays. Each still grows online far past any device it would be written
        // to: one reserved descriptor block describes about 8 GiB.
        for (mib, expect) in [(16u64, 64u32), (32, 128), (64, 256), (128, 512)] {
            let l = at(mib);
            assert_eq!(l.reserved_gdt_blocks, expect, "{mib} MiB");
            assert!(
                u64::from(l.reserved_gdt_blocks) <= l.total_blocks / 64,
                "{mib} MiB spends more than a sixty-fourth on headroom"
            );
            assert!(
                l.max_grow_blocks > 32 * l.total_blocks,
                "{mib} MiB grow reach"
            );
        }
    }

    #[test]
    fn max_never_makes_a_small_filesystem_unplannable() {
        // The share is what keeps `Max` from being most of a small filesystem: filling the
        // map costs 1024 blocks, which is four times a one-megabyte filesystem, so an
        // unbounded `Max` is exactly why such a size failed to plan at all. Nothing here
        // may fail. ext2 is the profile a filesystem this small carries, since a journal
        // needs 1024 blocks of its own whatever the reservation does.
        for mib in [1u64, 2, 4, 8, 16] {
            let l = plan_geo(mib * MIB, GrowReservation::Max, FeatureSet::EXT2)
                .unwrap_or_else(|e| panic!("{mib} MiB must plan under Max: {e}"));
            assert!(
                u64::from(l.reserved_gdt_blocks) <= l.total_blocks / 64,
                "{mib} MiB spends more than a sixty-fourth on headroom"
            );
            assert!(l.max_grow_blocks > l.total_blocks, "{mib} MiB still grows");
        }
    }

    #[test]
    fn an_explicit_target_is_not_held_to_the_share() {
        // The share bounds `Max`, which is a default, and not `UpTo`, which is a stated
        // intent: a 16 MiB image told to reserve for 8 TiB spends a quarter of itself on
        // headroom, because that is what was asked for. Silently reserving less is the one
        // outcome the reservation vocabulary exists to prevent.
        let l = plan_geo(
            16 * MIB,
            GrowReservation::UpTo(8 * 1024 * 1024 * MIB),
            FeatureSet::default(),
        )
        .expect("an explicit target at the format's ceiling is honored");
        assert_eq!(l.reserved_gdt_blocks, 1023);
        assert!(u64::from(l.reserved_gdt_blocks) > l.total_blocks / 64);
    }

    #[test]
    fn a_reservation_that_cannot_fit_names_its_share_of_the_overhead() {
        // An explicit target too large for the filesystem holding it is refused, and the
        // error says how much of the overhead the reservation is — which is what tells a
        // caller that the size is not the thing to change.
        let err = plan_geo(
            4 * MIB,
            GrowReservation::UpTo(8 * 1024 * 1024 * MIB),
            FeatureSet::default(),
        )
        .expect_err("a 4 MiB filesystem cannot reserve 1023 descriptor blocks");
        let GeometryError::TooSmall {
            reserved_gdt_blocks,
            overhead,
            ..
        } = err
        else {
            panic!("expected TooSmall, got {err:?}");
        };
        assert_eq!(reserved_gdt_blocks, 1023);
        assert!(overhead > reserved_gdt_blocks);
        // And it reaches the rendered message, which is the whole of what a caller sees
        // through a transparent error.
        let text = err.to_string();
        assert!(
            text.contains("1023 of them reserved to grow into"),
            "{text}"
        );
    }

    #[test]
    fn max_never_errors_deep_in_the_tib_range() {
        // Max is the fail-safe default: on a filesystem already at 4 TiB it still
        // plans, reserving no more than the resize inode's ceiling.
        let huge = 4 * 1024 * 1024 * MIB;
        let l =
            plan_geo(huge, GrowReservation::Max, FeatureSet::default()).expect("Max never errors");
        assert!(l.reserved_gdt_blocks <= 1024);
    }

    #[test]
    fn up_to_past_the_resize_ceiling_is_rejected() {
        // An UpTo target needing more than block_size / 4 reserved blocks would force
        // meta_bg; it is refused rather than silently under-reserved.
        let err = plan_geo(
            64 * MIB,
            GrowReservation::UpTo(16 * 1024 * 1024 * MIB),
            FeatureSet::default(),
        )
        .unwrap_err();
        assert!(matches!(err, GeometryError::GrowTargetTooLarge { .. }));
    }

    #[test]
    fn max_past_thirty_two_bits_reserves_nothing() {
        // The resize inode's block map is 32 bits wide, so a filesystem whose blocks a
        // 32-bit number cannot address can hold no reservation the map could name. Max
        // never fails, so at that size it reserves nothing and is grown offline instead.
        // The feature word is untouched: `resize_inode` stays set over an inode that maps
        // nothing. `host_tools::a_filesystem_past_thirty_two_bits_streams_and_passes_e2fsck`
        // is where that pair meets `e2fsck`.
        let past = (MAX_32BIT_BLOCKS + 1) * 4096; // one block past the 32-bit ceiling
        let l =
            plan_geo(past, GrowReservation::Max, FeatureSet::default()).expect("Max never errors");
        assert!(
            l.total_blocks > MAX_32BIT_BLOCKS,
            "this size is past 32 bits"
        );
        assert_eq!(
            l.reserved_gdt_blocks, 0,
            "no reserved blocks the 32-bit map could name"
        );
    }

    #[test]
    fn up_to_past_thirty_two_bits_is_rejected() {
        // An explicit UpTo target on a filesystem past the 32-bit ceiling cannot be
        // honored: the reserved blocks would live in backup groups the map cannot point
        // at. It is a typed error, never a truncated pointer. A target equal to the
        // size needs no reserved blocks and is therefore not this case.
        let past = (MAX_32BIT_BLOCKS + 1) * 4096;
        let err =
            plan_geo(past, GrowReservation::UpTo(past * 2), FeatureSet::default()).unwrap_err();
        assert!(
            matches!(err, GeometryError::ReservationNeeds32BitBlocks { .. }),
            "expected ReservationNeeds32BitBlocks, got {err:?}"
        );
    }

    #[test]
    fn the_default_reservation_is_max() {
        assert_eq!(GrowReservation::default(), GrowReservation::Max);
    }

    #[test]
    fn metadata_regions_are_sorted_and_disjoint() {
        for mib in [64u64, 200, 512, 2048, 2176] {
            let l = plan(mib);
            let runs = l.metadata_regions();
            for w in runs.windows(2) {
                assert!(w[0].end() <= w[1].start, "overlap at {mib} MiB: {w:?}");
            }
            // Overhead is a positive, sane fraction of the filesystem.
            assert!(l.overhead_blocks() > 0);
            assert!(l.overhead_blocks() < l.total_blocks);
        }
    }

    #[test]
    fn grow_target_below_size_is_rejected() {
        let err = plan_geo(
            512 * MIB,
            GrowReservation::UpTo(64 * MIB),
            FeatureSet::default(),
        )
        .unwrap_err();
        assert!(matches!(err, GeometryError::GrowTargetTooSmall { .. }));
    }

    #[test]
    fn tiny_filesystem_is_rejected() {
        let err = plan_geo(
            64 * 1024,
            GrowReservation::UpTo(64 * MIB),
            FeatureSet::default(),
        )
        .unwrap_err();
        assert!(matches!(err, GeometryError::TooSmall { .. }));
    }

    #[test]
    fn invalid_feature_set_propagates() {
        let mut fs = FeatureSet::default();
        fs.incompat |= crate::feature::Incompat::META_BG;
        let err = plan_geo(64 * MIB, GrowReservation::UpTo(GROW_32G), fs).unwrap_err();
        assert!(matches!(err, GeometryError::Feature(_)));
    }

    #[test]
    fn overhead_blocks_and_final_group_are_consistent_across_sizes() {
        // The final-group guard never trips for the sizes the resize matrix walks.
        for mib in [64u64, 120, 129, 200, 384, 640, 2048, 2049] {
            assert!(
                plan_geo(
                    mib * MIB,
                    GrowReservation::UpTo(GROW_32G),
                    FeatureSet::default()
                )
                .is_ok(),
                "sizing {mib} MiB should plan cleanly"
            );
        }
    }
}
