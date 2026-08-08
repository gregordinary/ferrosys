//! The geometry planner: a pure function from a volume size and a handful of parameters to
//! a complete [`FatLayout`].
//!
//! This module is pure and deterministic — no I/O, no clock, no allocation of clusters. It
//! decides every placement a checker verifies: how many sectors each file allocation table
//! occupies, where the root directory sits, where the data region begins, how many clusters
//! there are, and — following from that count and from nothing else — which of the three
//! FATs the volume is.
//!
//! # Why the count is the whole problem
//!
//! An image does not record its type. FAT12, FAT16, and FAT32 differ in how wide an entry
//! of the file allocation table is, and every driver decides which to use by counting
//! clusters and comparing against two thresholds. So a formatter that computes the count
//! differently from a driver does not produce a mislabelled filesystem: it produces one
//! whose every chain resolves to a different place than intended.
//!
//! The count is also circular. It is the data sectors divided by the cluster size; the data
//! sectors are what remains after the tables; and the tables are sized to hold one entry per
//! cluster. [`plan_layout`] resolves it the way the format's own reference computation does
//! — estimate the count, size the table for it, then recompute the count from the space the
//! sized table actually left — and the estimate is deliberately the low one, so the second
//! pass never needs a third.
//!
//! # Alignment
//!
//! The reserved region, the root directory region, and each file allocation table are
//! rounded up to a whole number of clusters, so the data region begins on a cluster
//! boundary. On flash media that boundary is what keeps a cluster write from spanning two
//! erase blocks. The rounding is skipped on a volume of 8192 sectors or fewer, where the
//! sectors it would spend are a large share of the volume and there is no erase block to
//! align to.
//!
//! A volume's sector count is used whole. The tail sectors that do not complete a cluster
//! are unreachable — that is true of any cluster-addressed format — but nothing above that
//! is discarded, so the volume the caller gave is the volume the filesystem describes.

#[cfg(feature = "serde")]
use serde::Serialize;

use super::ondisk::{BootSector, BootSectorTail, DIR_ENTRY_SIZE};

/// Bytes one directory entry occupies, as the arithmetic below needs it.
const DIR_ENTRY_BYTES: u64 = DIR_ENTRY_SIZE as u64;

/// The most clusters a FAT12 volume may hold.
///
/// The three above it up to `0xFF6` are not reserved by the format, and a count of 4085 or
/// 4086 would be read as FAT16 by the specification and as FAT12 by Windows — see
/// [`GeometryError::AmbiguousClusterCount`]. The largest count no driver disputes is this
/// one.
pub const MAX_CLUSTERS_FAT12: u32 = 4084;

/// The fewest clusters a FAT16 volume may hold.
///
/// The specification's own threshold is 4085, but Windows reads anything below 4087 as
/// FAT12, so the two counts in between are refused rather than written — a volume there is
/// read as two different filesystems by two mainstream drivers, and nothing can be put in
/// an image to settle it.
pub const MIN_CLUSTERS_FAT16: u32 = 4087;

/// The most clusters a FAT16 volume may hold. Entries `0xFFF7` and above are reserved for
/// the bad-cluster mark and the end-of-chain marks.
pub const MAX_CLUSTERS_FAT16: u32 = 65524;

/// The fewest clusters a FAT32 volume holds without an explicit acknowledgement.
///
/// A volume below it is read as FAT32 by every mainstream driver all the same, because they
/// recognize FAT32 by a zero 16-bit table size before counting anything. So it is refused
/// by default and reachable through [`FatTypeRequest::UndersizedFat32`], rather than
/// refused outright or written silently.
pub const MIN_CLUSTERS_FAT32: u32 = 65525;

/// The most clusters a FAT32 volume may hold. A FAT32 entry is 28 bits wide, and the top
/// values from `0x0FFFFFF7` up are reserved for the bad-cluster mark and the end-of-chain
/// marks. The highest cluster *number* on a volume is one past its count, so a count of
/// `0x0FFFFFF5` is the largest whose last cluster is still an ordinary one.
pub const MAX_CLUSTERS_FAT32: u32 = 268_435_445;

/// The largest allocation unit this crate writes, in bytes.
///
/// The format's own guidance is that a cluster of 64 KiB or more misbehaves, because more
/// than one widely deployed driver holds a cluster's byte count in sixteen bits. A reader
/// accepts a larger cluster; a writer does not create one.
pub const MAX_BYTES_PER_CLUSTER: u32 = 32_768;

/// The volume size at or above which [`FatTypeRequest::Auto`] selects FAT32 outright rather
/// than letting the cluster count choose between the smaller two.
pub(crate) const FAT32_AUTO_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;

/// The volume size, in sectors, at or below which the cluster alignment of the reserved,
/// root, and table regions is skipped.
const ALIGNMENT_THRESHOLD_SECTORS: u32 = 8192;

/// Which reserved sector holds the FAT32 information sector. Every FAT32 volume in
/// circulation uses the first, and a driver reads
/// [`Fat32Params::fs_info_sector`](crate::fat::ondisk::Fat32Params::fs_info_sector) rather
/// than assuming it, so nothing is gained by making this a knob.
const FS_INFO_SECTOR: u16 = 1;

/// Which of the three FATs a volume is.
///
/// The type is derived from the cluster count and from nothing else — not from the media
/// byte, not from the type string in the boot sector, and not from what a caller asked for.
/// The domain is closed and the type is exhaustive: these three are the whole format, and a
/// fourth *should* break a caller that switches on it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum FatType {
    /// A 12-bit table entry: the entries are packed three bytes to two clusters, so an
    /// entry may straddle a sector boundary.
    Fat12,
    /// A 16-bit table entry.
    Fat16,
    /// A 32-bit table entry of which 28 bits are the cluster number; the top four are
    /// reserved and preserved on update.
    Fat32,
}

impl FatType {
    /// The lowercase name of the type, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FatType::Fat12 => "fat12",
            FatType::Fat16 => "fat16",
            FatType::Fat32 => "fat32",
        }
    }

    /// Bits in one file allocation table entry.
    #[must_use]
    pub const fn entry_bits(self) -> u32 {
        match self {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 32,
        }
    }

    /// The string a conformant formatter records in the boot sector's type field.
    ///
    /// No driver reads it — the type follows from the count — so it is documentation. It is
    /// written correctly all the same, because it is the formatter stating its own
    /// conclusion, and a conclusion that can be compared against a count-derived answer is
    /// worth having.
    #[must_use]
    pub const fn label(self) -> [u8; 8] {
        match self {
            FatType::Fat12 => *b"FAT12   ",
            FatType::Fat16 => *b"FAT16   ",
            FatType::Fat32 => *b"FAT32   ",
        }
    }

    /// The fewest clusters this type may hold, as this crate writes it.
    #[must_use]
    pub const fn min_clusters(self) -> u32 {
        match self {
            FatType::Fat12 => 1,
            FatType::Fat16 => MIN_CLUSTERS_FAT16,
            FatType::Fat32 => MIN_CLUSTERS_FAT32,
        }
    }

    /// The most clusters this type may hold.
    #[must_use]
    pub const fn max_clusters(self) -> u32 {
        match self {
            FatType::Fat12 => MAX_CLUSTERS_FAT12,
            FatType::Fat16 => MAX_CLUSTERS_FAT16,
            FatType::Fat32 => MAX_CLUSTERS_FAT32,
        }
    }

    /// Which type a cluster count derives to, by the one rule the format states normatively.
    ///
    /// Both thresholds are exclusive below, which is the reading a transcription from prose
    /// gets wrong, and the off-by-one at either is the canonical FAT defect. A count of 4085
    /// or 4086 answers `Fat16` here, agreeing with the specification and with Linux; this
    /// crate never writes one, and a reader that meets one says so
    /// ([`GeometryError::AmbiguousClusterCount`]).
    #[must_use]
    pub const fn of_cluster_count(clusters: u32) -> FatType {
        if clusters < MAX_CLUSTERS_FAT12 + 1 {
            FatType::Fat12
        } else if clusters < MIN_CLUSTERS_FAT32 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }
}

/// Which type to produce.
///
/// The type is derived from the geometry rather than chosen, so this states what the
/// derivation must arrive at rather than what to write into the image.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum FatTypeRequest {
    /// Whatever the geometry reaches: FAT32 on a volume of half a gibibyte or more, and
    /// otherwise whichever of FAT12 and FAT16 the cluster size that fits arrives at.
    #[default]
    Auto,
    /// Exactly this type, refused where the geometry does not reach it.
    Exactly(FatType),
    /// FAT32 even where the volume holds fewer than [`MIN_CLUSTERS_FAT32`] clusters.
    ///
    /// Such a volume is not conformant and is read as FAT32 everywhere regardless, since
    /// every mainstream driver recognizes the type by a zero 16-bit table size before it
    /// counts a cluster. That combination — works everywhere, satisfies nothing — is why it
    /// is neither refused outright nor produced without being asked for.
    ///
    /// The acknowledgement names FAT32 rather than taking a type because FAT32 is the only
    /// type with a readable region below its minimum. A FAT16 volume with fewer than
    /// [`MAX_CLUSTERS_FAT12`]` + 1` clusters is not a non-conformant FAT16: it is a volume
    /// every driver reads as FAT12, resolving every chain through a table of the wrong
    /// entry width.
    UndersizedFat32,
}

/// The size of the allocation unit, in sectors.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ClusterSize {
    /// The smallest power of two that lets the requested type fit, starting from the size
    /// convention selects for the volume: one sector on a small FAT32 volume, growing with
    /// the volume, and four sectors on FAT12 and FAT16.
    #[default]
    Auto,
    /// Exactly this many sectors, a power of two from 1 to 128. The planner does not search
    /// past it, so a volume that no type fits at this size is refused rather than quietly
    /// given a larger cluster.
    Sectors(u32),
}

/// How many entries the fixed-capacity root directory region holds. FAT32 has no such
/// region, so this is refused there rather than ignored.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum RootEntries {
    /// 512 entries on FAT12 and FAT16 — the convention every formatter follows — and none
    /// on FAT32.
    #[default]
    Auto,
    /// Exactly this many, before the rounding that aligns the region to a cluster boundary.
    Count(u32),
}

/// How many sectors precede the first file allocation table, the boot sector included.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ReservedSectors {
    /// One on FAT12 and FAT16, and 32 on FAT32 — enough for the information sector, the
    /// backup boot sector, and the room a boot loader is conventionally given.
    #[default]
    Auto,
    /// Exactly this many, before the rounding that aligns the region to a cluster boundary.
    Count(u32),
}

/// A geometry that cannot be realized.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GeometryError {
    /// The sector size is not one the format defines.
    #[error("sector size {bytes_per_sector} is not 512, 1024, 2048, or 4096")]
    #[non_exhaustive]
    SectorSizeUnsupported {
        /// The size requested, in bytes.
        bytes_per_sector: u32,
    },
    /// The cluster size is not a power of two in the range the format defines.
    #[error("cluster size {sectors_per_cluster} is not a power of two from 1 to 128 sectors")]
    #[non_exhaustive]
    ClusterSizeUnsupported {
        /// The size requested, in sectors.
        sectors_per_cluster: u32,
    },
    /// The allocation unit exceeds [`MAX_BYTES_PER_CLUSTER`]. More than one widely deployed
    /// driver holds a cluster's byte count in sixteen bits, so a larger one is refused
    /// rather than written for a driver to truncate.
    #[error("cluster of {bytes} bytes exceeds the {limit} a driver is guaranteed to handle")]
    #[non_exhaustive]
    ClusterTooLarge {
        /// Bytes the requested allocation unit would occupy.
        bytes: u64,
        /// The most this crate writes.
        limit: u32,
    },
    /// The volume has no file allocation table, or more copies than this crate writes.
    ///
    /// The format permits any number and every implementation writes two. One is accepted
    /// because a read-only image has no mirror to keep consistent; beyond two the copies
    /// stop being something a checker or this crate's own classifier expects.
    #[error("{fats} file allocation tables: the count must be 1 or 2")]
    #[non_exhaustive]
    FatCountUnsupported {
        /// The count requested.
        fats: u32,
    },
    /// FAT32 needs at least two reserved sectors — the boot sector and the information
    /// sector — and every type needs at least one.
    #[error("{reserved} reserved sectors: {minimum} is the fewest this geometry allows")]
    #[non_exhaustive]
    ReservedSectorsTooFew {
        /// The count requested.
        reserved: u32,
        /// The fewest the geometry allows.
        minimum: u32,
    },
    /// The reserved region is larger than the boot sector's 16-bit count records.
    ///
    /// A count that did not fit would be written truncated, and a driver would then place
    /// the data region 65536 sectors before the formatter did — so every cluster on the
    /// volume would resolve somewhere else. The count reported is the one after the rounding
    /// that aligns the region to a cluster boundary, so a request one below the limit can
    /// still land above it.
    #[error(
        "{reserved} reserved sectors: the boot sector records the count in sixteen bits, so \
         at most {limit}"
    )]
    #[non_exhaustive]
    ReservedSectorsTooMany {
        /// The count, after any rounding to a cluster boundary.
        reserved: u32,
        /// The most the boot sector's field holds.
        limit: u32,
    },
    /// The root directory region has no entries, or more than its 16-bit count holds.
    #[error("{root_entries} root directory entries: the count must be 1 to {limit}")]
    #[non_exhaustive]
    RootEntriesUnsupported {
        /// The count requested, after any rounding to a cluster boundary.
        root_entries: u32,
        /// The most the boot sector's field holds.
        limit: u32,
    },
    /// Root directory entries were requested for a FAT32 volume, which has no fixed root
    /// region — its root is an ordinary cluster chain. The request is refused rather than
    /// ignored, because ignoring it would produce a volume whose root capacity is nothing
    /// like what was asked for.
    #[error(
        "FAT32 has no fixed root directory region, so {root_entries} entries cannot be reserved in one"
    )]
    #[non_exhaustive]
    RootEntriesOnFat32 {
        /// The count requested.
        root_entries: u32,
    },
    /// The volume has more sectors than the boot sector's 32-bit count holds.
    #[error("volume of {sectors} sectors exceeds the {limit} a 32-bit sector count holds")]
    #[non_exhaustive]
    VolumeTooLarge {
        /// Sectors the volume holds.
        sectors: u64,
        /// The most a 32-bit sector count holds.
        limit: u64,
    },
    /// No FAT type fits the volume at any cluster size the planner may use. On a small
    /// volume this is a volume with no room left for a data region after its tables; on a
    /// large one with the cluster size pinned, it is a cluster too small to address the
    /// volume.
    #[error(
        "no FAT type fits a volume of {sectors} sectors at {sectors_per_cluster} sectors \
         per cluster"
    )]
    #[non_exhaustive]
    NoTypeFits {
        /// Sectors the volume holds.
        sectors: u32,
        /// The largest cluster size the planner was allowed to try.
        sectors_per_cluster: u32,
    },
    /// The parameters reach a cluster count that two mainstream drivers read as two
    /// different filesystems, and the request left the planner nothing to move.
    ///
    /// A count of 4085 or 4086 is FAT16 to the specification and to Linux, and FAT12 to
    /// Windows. A file allocation table is a packed array whose entry width differs between
    /// the two, so one of those readers resolves every chain past the second cluster to
    /// nonsense. Nothing written into the image settles it, because no driver reads a type
    /// from the image.
    ///
    /// [`FatTypeRequest::Auto`] and [`FatTypeRequest::Exactly`]`(`[`FatType::Fat12`]`)`
    /// never reach this: the planner shortens the filesystem by a cluster or two and
    /// produces the largest undisputed FAT12 instead, which always fits in the volume it
    /// was already given. Only a request for FAT16 at this count does, because the way out
    /// of the range in that direction needs a larger volume.
    #[error(
        "a FAT16 of {clusters} clusters is read as FAT12 by Windows and as FAT16 by Linux; \
         {low} to {high} clusters cannot be written unambiguously, so the volume must be \
         large enough for {high_plus_one} or the type must be FAT12"
    )]
    #[non_exhaustive]
    AmbiguousClusterCount {
        /// The count the parameters reach.
        clusters: u32,
        /// The lowest disputed count.
        low: u32,
        /// The highest disputed count.
        high: u32,
        /// The lowest count above the dispute — the first unambiguous FAT16.
        high_plus_one: u32,
    },
    /// The requested type needs more clusters than the volume reaches at this cluster size.
    ///
    /// For FAT16 the fix is a larger volume or a smaller cluster; for FAT32 the volume is
    /// genuinely small and [`FatTypeRequest::UndersizedFat32`] is the acknowledgement that
    /// produces it anyway.
    #[error("a {requested} of {clusters} clusters is below the {minimum} the type requires")]
    #[non_exhaustive]
    ClustersBelowMinimum {
        /// The type requested.
        requested: FatType,
        /// Clusters the volume reaches.
        clusters: u32,
        /// The fewest the type requires.
        minimum: u32,
    },
    /// The requested type cannot address as many clusters as the volume holds at this
    /// cluster size. A larger cluster is the fix, and
    /// [`ClusterSize::Auto`] finds one on its own.
    #[error(
        "a {requested} cannot address the {clusters} clusters this geometry reaches; the \
         type holds at most {maximum}"
    )]
    #[non_exhaustive]
    ClustersAboveMaximum {
        /// The type requested.
        requested: FatType,
        /// Clusters the volume reaches.
        clusters: u32,
        /// The most the type addresses.
        maximum: u32,
    },
}

impl core::fmt::Display for FatType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The FAT32 placements that have no counterpart on the smaller two types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Fat32Layout {
    /// The first cluster of the root directory chain. FAT32's root is an ordinary chain
    /// rather than a fixed region, and it conventionally starts at the first cluster that
    /// exists.
    pub root_cluster: u32,
    /// Which reserved sector holds the information sector.
    pub fs_info_sector: u16,
    /// Which reserved sector holds the backup boot sector, or `None` where the reserved
    /// region is too small to hold one — which needs three sectors, since the backup may
    /// share a sector with neither the boot sector nor the information sector.
    pub backup_boot_sector: Option<u16>,
    /// Which reserved sector holds the backup of the information sector, or `None` where
    /// there is no room for one.
    ///
    /// The backup pair sits at the same spacing as the primary pair, so this is the backup
    /// boot sector plus [`fs_info_sector`](Self::fs_info_sector). A reserved region that ends
    /// before that offset gets no backup: the sector after it is the first file allocation
    /// table, and a copy written there would destroy the volume it was meant to protect.
    pub backup_fs_info_sector: Option<u16>,
}

/// A complete, materializable FAT layout.
///
/// Every field is a decision the materializer obeys rather than recomputes. [`plan_layout`]
/// is how one is obtained and the only way: the fields are not independent — the table size
/// follows from the cluster count, the cluster count from the space the sized tables leave,
/// and the type from the count — and a set of them assembled by hand can satisfy every type
/// here while describing a volume every driver reads as a different filesystem. Planning is
/// what makes them consistent, so it is the constructor; the fields stay public because
/// reading them is exactly what a materializer, a reader, and a caller inspecting a plan all
/// do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct FatLayout {
    /// Which of the three FATs the cluster count derives to. Recorded because everything
    /// downstream reads it, never because it was chosen.
    pub fat_type: FatType,
    /// Bytes per logical sector.
    pub bytes_per_sector: u32,
    /// Sectors per cluster, a power of two.
    pub sectors_per_cluster: u32,
    /// Sectors before the first file allocation table, the boot sector included, rounded up
    /// to a cluster boundary where the volume is large enough to align.
    pub reserved_sectors: u32,
    /// Copies of the file allocation table.
    pub fats: u32,
    /// Entries in the fixed-capacity root directory region, zero on FAT32. This is the
    /// count *after* the rounding that aligns the region, so it may exceed what was asked
    /// for, and it is the value the boot sector records.
    pub root_entries: u32,
    /// Sectors the filesystem describes.
    ///
    /// This is the volume's whole sector count, except where the planner shortened the
    /// filesystem to keep its cluster count out of the range two drivers dispute — the one
    /// case in which a volume holds more sectors than its filesystem claims.
    pub total_sectors: u32,
    /// Sectors in one file allocation table.
    pub fat_sectors: u32,
    /// Sectors in the fixed-capacity root directory region, zero on FAT32.
    pub root_dir_sectors: u32,
    /// The first sector of the data region, which is where cluster 2 begins. Clusters 0 and
    /// 1 have entries in the table and no storage, so the data region's first cluster is
    /// numbered 2.
    pub first_data_sector: u32,
    /// Clusters in the data region — the number the type is derived from, and the number
    /// every driver recomputes from the fields above.
    pub clusters: u32,
    /// The FAT32 placements, present on exactly the FAT32 layouts.
    ///
    /// `Some` if and only if [`fat_type`](Self::fat_type) is [`FatType::Fat32`], whether the
    /// layout was planned or recovered from a parameter block — so a consumer that matches on
    /// the type and reads this is reading one description of one volume rather than two that
    /// may disagree. The same pairing runs the other way: a FAT32 layout has no fixed root
    /// region, so [`root_entries`](Self::root_entries) and
    /// [`root_dir_sectors`](Self::root_dir_sectors) are zero on exactly the layouts this is
    /// `Some` on.
    pub fat32: Option<Fat32Layout>,
}

impl FatLayout {
    /// Bytes in one allocation unit.
    #[must_use]
    pub const fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// The first sector of file allocation table `index`, counting from zero.
    ///
    /// Returns `None` for an index past [`fats`](Self::fats), so a caller iterating the
    /// copies cannot address a table that is not there.
    #[must_use]
    pub const fn fat_start_sector(&self, index: u32) -> Option<u32> {
        if index >= self.fats {
            return None;
        }
        Some(self.reserved_sectors + index * self.fat_sectors)
    }

    /// The first sector of the fixed-capacity root directory region, or `None` on FAT32,
    /// where the root is a cluster chain and has no region of its own.
    #[must_use]
    pub const fn root_dir_start_sector(&self) -> Option<u32> {
        if self.root_dir_sectors == 0 {
            return None;
        }
        Some(self.reserved_sectors + self.fats * self.fat_sectors)
    }

    /// The first sector of cluster `n`, or `None` where `n` is not a cluster this volume
    /// has. Clusters number from 2.
    #[must_use]
    pub const fn cluster_start_sector(&self, n: u32) -> Option<u32> {
        if n < 2 || n - 2 >= self.clusters {
            return None;
        }
        Some(self.first_data_sector + (n - 2) * self.sectors_per_cluster)
    }

    /// Sectors in the data region. The tail that does not complete a cluster is not
    /// included, since no cluster addresses it.
    #[must_use]
    pub const fn data_sectors(&self) -> u32 {
        self.clusters * self.sectors_per_cluster
    }

    /// Bytes the filesystem describes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_sectors as u64 * self.bytes_per_sector as u64
    }

    /// The most entries one file allocation table indexes, from its size alone.
    ///
    /// A table is sized for the clusters that exist and rounded to whole sectors, so this is
    /// at least [`clusters`](Self::clusters)` + 2` and usually a little more. A reader uses
    /// it to refuse a cluster number the table cannot hold an entry for, before computing
    /// where that entry would be.
    #[must_use]
    pub const fn max_table_entries(&self) -> u32 {
        let bytes = self.fat_sectors as u64 * self.bytes_per_sector as u64;
        let entries = match self.fat_type {
            FatType::Fat12 => bytes * 2 / 3,
            FatType::Fat16 => bytes / 2,
            FatType::Fat32 => bytes / 4,
        };
        if entries > u32::MAX as u64 {
            u32::MAX
        } else {
            entries as u32
        }
    }
}

/// What to plan.
///
/// Every input is a field rather than a parameter, so a knob the planner grows arrives as a
/// field a caller may ignore. The knobs that are genuinely a caller's are here; the type is
/// not one of them, because it is derived — [`fat_type`](Self::fat_type) states what the
/// derivation must arrive at.
///
/// ```
/// # use ferrosys::fat::{ClusterSize, FatType, FatTypeRequest, PlanRequest, plan_layout};
/// // A 256 MiB volume, formatted the way convention formats one.
/// let request = PlanRequest::new(256 << 20);
/// let layout = plan_layout(&request).expect("plan");
/// assert_eq!(layout.fat_type, FatType::Fat16);
///
/// // The same volume asked for FAT32, with a cluster of one sector.
/// let request = PlanRequest::new(256 << 20)
///     .fat_type(FatTypeRequest::Exactly(FatType::Fat32))
///     .cluster_size(ClusterSize::Sectors(1));
/// let layout = plan_layout(&request).expect("plan");
/// assert_eq!(layout.fat_type, FatType::Fat32);
/// assert_eq!(layout.clusters, 516_190);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PlanRequest {
    /// The volume's size in bytes. A size that is not a whole number of sectors is rounded
    /// down, since a partial sector is not addressable.
    pub volume_bytes: u64,
    /// Bytes per logical sector: 512, 1024, 2048, or 4096. Defaults to 512, which is what
    /// every FAT driver has always supported.
    pub bytes_per_sector: u32,
    /// The allocation unit. Defaults to [`ClusterSize::Auto`].
    pub sectors_per_cluster: ClusterSize,
    /// Copies of the file allocation table, 1 or 2. Defaults to 2, which is what every
    /// implementation writes.
    pub fats: u32,
    /// The fixed-capacity root directory region's size. Defaults to [`RootEntries::Auto`].
    pub root_entries: RootEntries,
    /// Sectors before the first file allocation table. Defaults to
    /// [`ReservedSectors::Auto`].
    pub reserved_sectors: ReservedSectors,
    /// What the type derivation must arrive at. Defaults to [`FatTypeRequest::Auto`].
    pub fat_type: FatTypeRequest,
}

impl PlanRequest {
    /// A request for a volume of `volume_bytes`, with every knob at the value convention
    /// selects for a volume that size.
    #[must_use]
    pub const fn new(volume_bytes: u64) -> Self {
        Self {
            volume_bytes,
            bytes_per_sector: 512,
            sectors_per_cluster: ClusterSize::Auto,
            fats: 2,
            root_entries: RootEntries::Auto,
            reserved_sectors: ReservedSectors::Auto,
            fat_type: FatTypeRequest::Auto,
        }
    }

    /// This request with the sector size replaced.
    #[must_use]
    pub const fn bytes_per_sector(mut self, bytes: u32) -> Self {
        self.bytes_per_sector = bytes;
        self
    }

    /// This request with the allocation unit replaced.
    #[must_use]
    pub const fn cluster_size(mut self, size: ClusterSize) -> Self {
        self.sectors_per_cluster = size;
        self
    }

    /// This request with the number of file allocation tables replaced.
    #[must_use]
    pub const fn fats(mut self, fats: u32) -> Self {
        self.fats = fats;
        self
    }

    /// This request with the root directory region's size replaced.
    #[must_use]
    pub const fn root_entries(mut self, entries: RootEntries) -> Self {
        self.root_entries = entries;
        self
    }

    /// This request with the reserved sector count replaced.
    #[must_use]
    pub const fn reserved_sectors(mut self, reserved: ReservedSectors) -> Self {
        self.reserved_sectors = reserved;
        self
    }

    /// This request with the type requirement replaced.
    #[must_use]
    pub const fn fat_type(mut self, fat_type: FatTypeRequest) -> Self {
        self.fat_type = fat_type;
        self
    }

    /// Refuse what no volume size could rescue: a sector size the format does not define, a
    /// table count it does not allow, or a cluster larger than one it addresses.
    ///
    /// [`plan_layout`] runs this first, so a caller reaching it directly needs nothing else.
    /// It is separate because a search over candidate sizes should refuse such a request
    /// once, at the size the caller can act on, rather than at every size it would have
    /// tried — and because these are the only checks whose answer does not depend on the
    /// volume, so nothing else could be lifted here without becoming wrong at some size.
    ///
    /// # Errors
    ///
    /// [`GeometryError::SectorSizeUnsupported`], [`GeometryError::FatCountUnsupported`],
    /// [`GeometryError::ClusterSizeUnsupported`], or [`GeometryError::ClusterTooLarge`].
    pub(crate) fn validate(&self) -> Result<(), GeometryError> {
        if !matches!(self.bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(GeometryError::SectorSizeUnsupported {
                bytes_per_sector: self.bytes_per_sector,
            });
        }
        if !matches!(self.fats, 1 | 2) {
            return Err(GeometryError::FatCountUnsupported { fats: self.fats });
        }
        if let ClusterSize::Sectors(n) = self.sectors_per_cluster {
            if !n.is_power_of_two() || n > 128 {
                return Err(GeometryError::ClusterSizeUnsupported {
                    sectors_per_cluster: n,
                });
            }
            let bytes = u64::from(n) * u64::from(self.bytes_per_sector);
            if bytes > u64::from(MAX_BYTES_PER_CLUSTER) {
                return Err(GeometryError::ClusterTooLarge {
                    bytes,
                    limit: MAX_BYTES_PER_CLUSTER,
                });
            }
        }
        Ok(())
    }
}

/// One type's candidate geometry at one cluster size: how large its table would be, and how
/// many clusters would remain once that table was subtracted.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    fat_sectors: u32,
    clusters: u32,
}

/// Round `sectors` up to a whole number of clusters when the volume is large enough for the
/// alignment to be worth its cost, and leave it alone otherwise.
const fn align(sectors: u32, sectors_per_cluster: u32, aligning: bool) -> u32 {
    if aligning {
        sectors.div_ceil(sectors_per_cluster) * sectors_per_cluster
    } else {
        sectors
    }
}

/// Size a table for `clusters` clusters of `bits`-wide entries, plus the two entries every
/// table reserves at its head, rounded up to whole sectors and then to a cluster boundary.
fn table_sectors(clusters: u32, bits: u32, bytes_per_sector: u32, spc: u32, aligning: bool) -> u32 {
    let entries = u64::from(clusters) + 2;
    // 12-bit entries pack three bytes to two entries, so the byte count rounds up on an odd
    // entry count. The other two widths divide exactly.
    let bytes = match bits {
        12 => (entries * 3).div_ceil(2),
        16 => entries * 2,
        _ => entries * 4,
    };
    let sectors = bytes.div_ceil(u64::from(bytes_per_sector));
    // A table that needed more sectors than a 32-bit count holds would need more clusters
    // than any type addresses, which the caller of this has already excluded.
    let sectors = u32::try_from(sectors).unwrap_or(u32::MAX);
    align(sectors, spc, aligning)
}

/// The clusters that would fit in `fat_data_sectors` if every cluster paid for its own entry
/// in every table, before any table has been sized.
///
/// This deliberately understates the count: the unused remainder of the tables and of the
/// data region can together make room for one more cluster than it charges for. That is what
/// makes the circular computation converge in one pass — size a table for this, then
/// recompute the count from the space that table actually left — rather than oscillating.
///
/// Everything is carried at twice scale. A 12-bit entry is a byte and a half, and on a
/// volume with a single table that half is the difference between the right count and one
/// too few.
fn cluster_estimate(
    fat_data_sectors: u32,
    bits: u32,
    bytes_per_sector: u32,
    spc: u32,
    fats: u32,
) -> u32 {
    // Bytes two table entries occupy: 3, 4, and 8 for the three widths.
    let two_entries = u64::from(bits) / 4;
    let sector_bytes = u64::from(bytes_per_sector);
    // The two entries every table reserves at its head are charged once per table, which is
    // the term added to the numerator; the per-cluster cost is a cluster's own bytes plus one
    // entry in each table, which is the denominator.
    let numerator =
        2 * u64::from(fat_data_sectors) * sector_bytes + 2 * u64::from(fats) * two_entries;
    let denominator = 2 * u64::from(spc) * sector_bytes + u64::from(fats) * two_entries;
    u32::try_from(numerator / denominator).unwrap_or(u32::MAX)
}

/// The clusters and table size one type reaches, given the sectors available to the tables
/// and the data region together.
fn candidate(
    fat_data_sectors: u32,
    bits: u32,
    bytes_per_sector: u32,
    spc: u32,
    fats: u32,
    aligning: bool,
) -> Option<Candidate> {
    let estimate = cluster_estimate(fat_data_sectors, bits, bytes_per_sector, spc, fats);
    let fat_sectors = table_sectors(estimate, bits, bytes_per_sector, spc, aligning);
    // Recompute from the space the sized tables actually left. The unused remainder of the
    // tables and of the data region can together make room for one more cluster than the
    // estimate charged for, so this is the count, not the estimate.
    let data = fat_data_sectors.checked_sub(fats.checked_mul(fat_sectors)?)?;
    let clusters = data / spc;
    if clusters == 0 {
        return None;
    }
    Some(Candidate {
        fat_sectors,
        clusters,
    })
}

/// The cluster size convention starts from for a volume of `sectors` sectors.
///
/// FAT32 follows the table Microsoft's own formatter uses, keyed on the sector count; the
/// smaller two start at four sectors and grow from there if nothing fits. The planner
/// doubles from here, so this is a floor rather than a choice.
const fn starting_cluster_size(fat32: bool, sectors: u64) -> u32 {
    if !fat32 {
        return 4;
    }
    if sectors > 32 * 1024 * 1024 * 2 {
        64
    } else if sectors > 16 * 1024 * 1024 * 2 {
        32
    } else if sectors > 8 * 1024 * 1024 * 2 {
        16
    } else if sectors > 260 * 1024 * 2 {
        8
    } else {
        1
    }
}

/// Which reserved sector holds the backup boot sector, or `None` where the reserved region
/// cannot hold one.
///
/// The backup goes in sector 6 wherever there is room, which is where every FAT32 volume in
/// circulation puts it and where a driver recovering a damaged volume looks first. A smaller
/// reserved region falls back to the last sector that is neither the boot sector nor the
/// information sector.
const fn backup_boot_sector(reserved: u32, info: u16) -> Option<u16> {
    let info32 = info as u32;
    if reserved >= 7 && info32 != 6 {
        Some(6)
    } else if reserved >= 3 + info32 && info32 != reserved - 2 && info32 != reserved - 1 {
        Some((reserved - 2) as u16)
    } else if reserved >= 3 && info32 != reserved - 1 {
        Some((reserved - 1) as u16)
    } else {
        None
    }
}

/// Plan the complete layout of a FAT volume.
///
/// The returned [`FatLayout`] is self-consistent: its cluster count is exactly what a driver
/// computes from its own fields, and its type is exactly what that count derives to. A
/// materializer obeys it without recomputing anything.
///
/// # Errors
///
/// - [`GeometryError::SectorSizeUnsupported`], [`GeometryError::ClusterSizeUnsupported`],
///   [`GeometryError::ClusterTooLarge`], [`GeometryError::FatCountUnsupported`],
///   [`GeometryError::ReservedSectorsTooFew`], [`GeometryError::RootEntriesUnsupported`],
///   [`GeometryError::RootEntriesOnFat32`], and [`GeometryError::VolumeTooLarge`] for a
///   parameter the format or this crate does not allow.
/// - [`GeometryError::NoTypeFits`] when no type reaches a data region at any cluster size
///   the request permits.
/// - [`GeometryError::ClustersBelowMinimum`] and [`GeometryError::ClustersAboveMaximum`]
///   when a requested type is not what the geometry reaches.
/// - [`GeometryError::AmbiguousClusterCount`] when FAT16 was requested at a count two
///   mainstream drivers read differently.
pub fn plan_layout(request: &PlanRequest) -> Result<FatLayout, GeometryError> {
    let &PlanRequest {
        volume_bytes,
        bytes_per_sector,
        sectors_per_cluster,
        fats,
        root_entries,
        reserved_sectors,
        fat_type,
    } = request;

    request.validate()?;
    let volume_sectors = volume_bytes / u64::from(bytes_per_sector);
    if volume_sectors > u64::from(u32::MAX) {
        return Err(GeometryError::VolumeTooLarge {
            sectors: volume_sectors,
            limit: u64::from(u32::MAX),
        });
    }
    // A volume with no sectors has no boot sector, so nothing below it is meaningful.
    let total_sectors = volume_sectors as u32;

    // Whether FAT32 is what the request is heading for. This is settled before the search
    // because the reserved-sector and cluster-size defaults differ between FAT32 and the
    // smaller two, and a default cannot wait for the answer it helps produce.
    let fat32_intended = match fat_type {
        FatTypeRequest::Exactly(FatType::Fat32) | FatTypeRequest::UndersizedFat32 => true,
        FatTypeRequest::Exactly(_) => false,
        FatTypeRequest::Auto => volume_bytes >= FAT32_AUTO_THRESHOLD_BYTES,
    };

    let reserved = match reserved_sectors {
        ReservedSectors::Auto if fat32_intended => 32,
        ReservedSectors::Auto => 1,
        ReservedSectors::Count(n) => n,
    };
    let reserved_minimum = if fat32_intended { 2 } else { 1 };
    if reserved < reserved_minimum {
        return Err(GeometryError::ReservedSectorsTooFew {
            reserved,
            minimum: reserved_minimum,
        });
    }
    // Bounded before it reaches the alignment arithmetic below, which multiplies it by a
    // cluster size. The rounding can still carry a count just under the limit past it, which
    // is checked again once the cluster size is settled.
    if reserved > u32::from(u16::MAX) {
        return Err(GeometryError::ReservedSectorsTooMany {
            reserved,
            limit: u32::from(u16::MAX),
        });
    }

    let requested_entries = match root_entries {
        RootEntries::Auto => None,
        RootEntries::Count(n) => Some(n),
    };
    if fat32_intended && let Some(n) = requested_entries.filter(|&n| n != 0) {
        return Err(GeometryError::RootEntriesOnFat32 { root_entries: n });
    }
    // The root region's size before alignment. FAT32 has none; the smaller two default to
    // the 512 entries every formatter writes.
    let root_entries_requested = if fat32_intended {
        0
    } else {
        let n = requested_entries.unwrap_or(512);
        if n == 0 || n > u32::from(u16::MAX) {
            return Err(GeometryError::RootEntriesUnsupported {
                root_entries: n,
                limit: u32::from(u16::MAX),
            });
        }
        n
    };
    let root_dir_sectors_unaligned = (root_entries_requested * 32).div_ceil(bytes_per_sector);

    // Alignment costs sectors, and on a volume this small it costs a share of it that a
    // cluster-aligned data region does not repay.
    let aligning = total_sectors > ALIGNMENT_THRESHOLD_SECTORS;

    let (first_size, last_size) = match sectors_per_cluster {
        ClusterSize::Auto => {
            // The search stops where the allocation unit would pass what a driver is
            // guaranteed to handle. It is a ceiling on the search rather than a refusal,
            // since nothing was asked for that could be refused.
            let ceiling = (MAX_BYTES_PER_CLUSTER / bytes_per_sector).clamp(1, 128);
            (
                starting_cluster_size(fat32_intended, volume_sectors).min(ceiling),
                ceiling,
            )
        }
        // Already checked by `validate`, which every path here runs first.
        ClusterSize::Sectors(n) => (n, n),
    };

    // Convention selects FAT32 outright for a volume of half a gibibyte or more rather than
    // letting the cluster count choose between the smaller two, so from here the search is
    // for a FAT32 and a failure is reported as one — which is the accurate thing to say,
    // since that is what the size selected.
    let fat_type = match fat_type {
        FatTypeRequest::Auto if fat32_intended => FatTypeRequest::Exactly(FatType::Fat32),
        other => other,
    };

    // The search. Each pass computes what every type would reach at one cluster size and
    // stops at the first size the request can be satisfied at; a pinned cluster size makes
    // it a single pass. A failure reports the last pass's candidates, so it can say what the
    // geometry actually reached rather than only that it did not fit.
    let mut spc = first_size;
    let chosen = loop {
        let reserved_aligned = align(reserved, spc, aligning);
        let root_aligned = align(root_dir_sectors_unaligned, spc, aligning);
        let candidates =
            match total_sectors
                .checked_sub(reserved_aligned)
                .and_then(|after_reserved| {
                    Some((after_reserved, after_reserved.checked_sub(root_aligned)?))
                }) {
                Some((fat_data_32, fat_data_1216)) => [
                    candidate(fat_data_1216, 12, bytes_per_sector, spc, fats, aligning),
                    candidate(fat_data_1216, 16, bytes_per_sector, spc, fats, aligning),
                    candidate(fat_data_32, 32, bytes_per_sector, spc, fats, aligning),
                ],
                None => [None, None, None],
            };

        if let Some(chosen) = select(fat_type, &candidates) {
            break chosen;
        }
        if spc >= last_size {
            // Nothing fits at any size the request permits. The last resort is a FAT12
            // shortened out of the range two drivers dispute — which is only reached here,
            // after a larger cluster has been tried and failed, because a larger cluster is
            // what every other formatter reaches for first and matching it is what keeps
            // two formatters' output comparable.
            if let Some(c) = step_down(fat_type, &candidates) {
                break (FatType::Fat12, c);
            }
            return Err(diagnose(fat_type, total_sectors, spc, &candidates));
        }
        spc *= 2;
    };

    let (fat_type, mut candidate) = chosen;
    let reserved_aligned = align(reserved, spc, aligning);
    let root_aligned = align(root_dir_sectors_unaligned, spc, aligning);

    // The one place the filesystem is made smaller than the volume: a FAT12 whose count
    // lands where two drivers disagree is shortened to the largest count neither disputes.
    // Stepping down always fits in the volume already given, where stepping up past the
    // range would need a larger one.
    let mut total_sectors = total_sectors;
    if fat_type == FatType::Fat12 && candidate.clusters > MAX_CLUSTERS_FAT12 {
        candidate.clusters = MAX_CLUSTERS_FAT12;
        candidate.fat_sectors =
            table_sectors(MAX_CLUSTERS_FAT12, 12, bytes_per_sector, spc, aligning);
        total_sectors = reserved_aligned
            + fats * candidate.fat_sectors
            + root_aligned
            + MAX_CLUSTERS_FAT12 * spc;
    }

    let first_data_sector = reserved_aligned + fats * candidate.fat_sectors + root_aligned;
    // One division per plan, held in every build: a plan whose count disagrees with what a
    // driver derives is a volume where every table entry is for a different cluster than the
    // one the driver is asking about.
    assert_eq!(
        (total_sectors - first_data_sector) / spc,
        candidate.clusters,
        "the planned cluster count and the count a driver derives from the planned fields \
         must be the same number"
    );

    // The count the boot sector records must describe the region that was actually placed: a
    // driver recomputes the region's size from it, and a count naming fewer sectors than were
    // left for it would put the start of the data region somewhere the formatter did not.
    //
    // On a volume small enough that the regions are not aligned, the region is exactly the
    // requested count's worth and that count is what is recorded, so a caller who asked for
    // 224 entries has 224. On one large enough to align, the region's full capacity is
    // recorded instead: the alignment has already spent the sectors, and a count naming fewer
    // of them would leave part of a region the data region does not begin until after.
    let root_entries = if aligning {
        root_aligned * (bytes_per_sector / 32)
    } else {
        root_entries_requested
    };
    if root_entries > u32::from(u16::MAX) {
        return Err(GeometryError::RootEntriesUnsupported {
            root_entries,
            limit: u32::from(u16::MAX),
        });
    }
    // The aligned count, which the rounding can have carried past the limit the request
    // itself was held to.
    if reserved_aligned > u32::from(u16::MAX) {
        return Err(GeometryError::ReservedSectorsTooMany {
            reserved: reserved_aligned,
            limit: u32::from(u16::MAX),
        });
    }

    Ok(FatLayout {
        fat_type,
        bytes_per_sector,
        sectors_per_cluster: spc,
        reserved_sectors: reserved_aligned,
        fats,
        root_entries,
        total_sectors,
        fat_sectors: candidate.fat_sectors,
        root_dir_sectors: root_aligned,
        first_data_sector,
        clusters: candidate.clusters,
        fat32: (fat_type == FatType::Fat32).then(|| {
            let backup = backup_boot_sector(reserved_aligned, FS_INFO_SECTOR);
            Fat32Layout {
                root_cluster: 2,
                fs_info_sector: FS_INFO_SECTOR,
                backup_boot_sector: backup,
                backup_fs_info_sector: backup
                    .map(|b| b + FS_INFO_SECTOR)
                    .filter(|&b| u32::from(b) < reserved_aligned),
            }
        }),
    })
}

/// The three candidates in the order [`FatType::Fat12`], [`FatType::Fat16`],
/// [`FatType::Fat32`], filtered to those the request would accept, and the one it picks.
///
/// A candidate is acceptable when its count lies in the type's range, which is the whole of
/// the rule. Nothing here reaches for the shortened FAT12 of [`step_down`]: that is a last
/// resort and only applies once every cluster size has been tried.
fn select(
    request: FatTypeRequest,
    candidates: &[Option<Candidate>; 3],
) -> Option<(FatType, Candidate)> {
    let fits = |kind: FatType| -> Option<Candidate> {
        let c = candidates[kind as usize]?;
        let low = match (request, kind) {
            (FatTypeRequest::UndersizedFat32, FatType::Fat32) => 1,
            _ => kind.min_clusters(),
        };
        (c.clusters >= low && c.clusters <= kind.max_clusters()).then_some(c)
    };
    match request {
        FatTypeRequest::Exactly(kind) => fits(kind).map(|c| (kind, c)),
        FatTypeRequest::UndersizedFat32 => fits(FatType::Fat32).map(|c| (FatType::Fat32, c)),
        FatTypeRequest::Auto => {
            // Convention picks the type that addresses the volume in the fewest clusters it
            // can: FAT16 wherever it reaches more clusters than FAT12 would, which is
            // wherever FAT12 has run out of range.
            let twelve = fits(FatType::Fat12);
            let sixteen = fits(FatType::Fat16);
            match (twelve, sixteen) {
                (Some(a), Some(b)) if b.clusters > a.clusters => Some((FatType::Fat16, b)),
                (Some(a), _) => Some((FatType::Fat12, a)),
                (None, Some(b)) => Some((FatType::Fat16, b)),
                (None, None) => None,
            }
        }
    }
}

/// The FAT12 candidate to shorten, where shortening is the way out and nothing else was.
///
/// A volume whose FAT12 count has passed 4084 while its FAT16 count has not yet reached 4087
/// falls between the two types: too large for one, too small for the other. The gap is a
/// handful of clusters wide — a FAT16 table is a few sectors larger than a FAT12 one at that
/// size, and those sectors are the whole of the difference — so declaring the largest
/// undisputed FAT12 and leaving the remainder unused costs single-digit clusters and always
/// fits in the volume already given. Growing past the range instead needs a larger volume,
/// which the planner does not have.
///
/// It applies only where FAT12 is what the request permits. A caller who named FAT16 is
/// asking for the thing that cannot be delivered, and is told so
/// ([`GeometryError::AmbiguousClusterCount`]).
///
/// **And only where the volume is genuinely between the two types.** A FAT12 count above 4084
/// is the entry condition for the gap and is not by itself evidence of one: a volume large
/// enough that FAT16 has also run past *its* maximum is not between the types at all, it is
/// simply too large for the cluster size it was pinned to. Shortening that to 4084 clusters
/// would report success while describing a fraction of a percent of the volume as a
/// filesystem, which is why the FAT16 candidate has to be below its own minimum for this to
/// be the way out.
fn step_down(request: FatTypeRequest, candidates: &[Option<Candidate>; 3]) -> Option<Candidate> {
    if !matches!(
        request,
        FatTypeRequest::Auto | FatTypeRequest::Exactly(FatType::Fat12)
    ) {
        return None;
    }
    let twelve = candidates[FatType::Fat12 as usize]?;
    if twelve.clusters <= MAX_CLUSTERS_FAT12 {
        return None;
    }
    match candidates[FatType::Fat16 as usize] {
        Some(sixteen) if sixteen.clusters < MIN_CLUSTERS_FAT16 => Some(twelve),
        _ => None,
    }
}

/// Why nothing fit, said as precisely as the candidates allow.
///
/// A bare "it did not fit" is the least useful thing a planner can say, so this names the
/// count the geometry actually reached and how it missed: too few clusters for the type, too
/// many for it, in the range two drivers dispute, or no data region at all.
fn diagnose(
    request: FatTypeRequest,
    sectors: u32,
    spc: u32,
    candidates: &[Option<Candidate>; 3],
) -> GeometryError {
    let named = match request {
        FatTypeRequest::Exactly(kind) => Some(kind),
        FatTypeRequest::UndersizedFat32 => Some(FatType::Fat32),
        FatTypeRequest::Auto => None,
    };
    let Some(kind) = named else {
        return GeometryError::NoTypeFits {
            sectors,
            sectors_per_cluster: spc,
        };
    };
    let Some(c) = candidates[kind as usize] else {
        return GeometryError::NoTypeFits {
            sectors,
            sectors_per_cluster: spc,
        };
    };
    if c.clusters > kind.max_clusters() {
        return GeometryError::ClustersAboveMaximum {
            requested: kind,
            clusters: c.clusters,
            maximum: kind.max_clusters(),
        };
    }
    // A FAT16 in the disputed range gets its own answer: the fix is not "a few more
    // clusters", it is a volume large enough to clear the range entirely.
    if kind == FatType::Fat16 && c.clusters > MAX_CLUSTERS_FAT12 && c.clusters < MIN_CLUSTERS_FAT16
    {
        return GeometryError::AmbiguousClusterCount {
            clusters: c.clusters,
            low: MAX_CLUSTERS_FAT12 + 1,
            high: MIN_CLUSTERS_FAT16 - 1,
            high_plus_one: MIN_CLUSTERS_FAT16,
        };
    }
    GeometryError::ClustersBelowMinimum {
        requested: kind,
        clusters: c.clusters,
        minimum: kind.min_clusters(),
    }
}

/// The field of a parameter block that stopped a volume from being read as a FAT volume,
/// and the number the check was about.
///
/// Internal, because it is one half of a question with two public answers: detection
/// discards it and says "not ours", while the reader renders it into a
/// [`ReadError::BadBootSector`](crate::fat::ReadError::BadBootSector) that names what was
/// wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct BootDefect {
    /// The parameter block field the check was about, in the format's own spelling.
    pub field: &'static str,
    /// That field's value, or the number derived from it that failed.
    pub value: u64,
}

/// The layout a boot sector describes, or the field that stops it describing one.
///
/// **This is the single definition of "these bytes are a FAT volume".** Detection and the
/// reader both go through it, so a reader can never refuse an image detection claimed, and
/// detection can never claim one the reader cannot open — the false-negative pairing that a
/// classifier and a reader written separately produce by default.
///
/// `available` is how many bytes the source holds from the volume's start, which is what
/// makes "the sector count fits" answerable. A volume may be smaller than the region it sits
/// in, since a partition is usually larger than its filesystem, so the test is that the count
/// fits rather than that it matches.
///
/// Every check is the parameter block agreeing with itself. FAT carries no magic — the two
/// bytes at the end of sector 0 are the boot signature, which is on every bootable sector
/// ever written, including the master boot record of a disk whose partitions hold something
/// else — so the evidence is the fields being jointly possible. Each check is weak alone; a
/// sector that is really a master boot record fails several.
pub(crate) fn layout_from_boot(boot: &BootSector, available: u64) -> Result<FatLayout, BootDefect> {
    let defect = |field: &'static str, value: u64| BootDefect { field, value };

    // A boot sector begins with a jump over the parameter block. Both encodings are in use:
    // a short jump followed by a no-op, and a near jump.
    let jump_ok = (boot.jump[0] == 0xEB && boot.jump[2] == 0x90) || boot.jump[0] == 0xE9;
    if !jump_ok {
        return Err(defect(
            "BS_jmpBoot",
            u64::from(u32::from_be_bytes([
                0,
                boot.jump[0],
                boot.jump[1],
                boot.jump[2],
            ])),
        ));
    }
    if !matches!(boot.bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(defect("BPB_BytsPerSec", u64::from(boot.bytes_per_sector)));
    }
    let spc = u32::from(boot.sectors_per_cluster);
    if spc == 0 || !spc.is_power_of_two() || spc > 128 {
        return Err(defect("BPB_SecPerClus", u64::from(spc)));
    }
    // Any table count is legal by the specification and every implementation writes two.
    // One is accepted because a read-only image has no mirror to keep consistent; a count
    // past that is weak evidence of anything and is where a false positive would come from.
    if !matches!(boot.fats, 1 | 2) {
        return Err(defect("BPB_NumFATs", u64::from(boot.fats)));
    }
    if boot.reserved_sectors == 0 {
        return Err(defect("BPB_RsvdSecCnt", 0));
    }
    if !super::materialize::is_media_descriptor(boot.media) {
        return Err(defect("BPB_Media", u64::from(boot.media)));
    }
    // Exactly one of the two sector-count fields carries the count on a conformant volume,
    // and a volume with neither has no size at all.
    let total_sectors = boot.total_sectors();
    if total_sectors == 0 {
        return Err(defect("BPB_TotSec32", 0));
    }
    let volume_bytes = u64::from(total_sectors) * u64::from(boot.bytes_per_sector);
    if volume_bytes > available {
        return Err(defect("BPB_TotSec32", volume_bytes));
    }

    let fat_sectors = boot.fat_sectors();
    if fat_sectors == 0 {
        return Err(defect("BPB_FATSz32", 0));
    }
    // The two shapes disagree about the root directory, and each is the other's strongest
    // check: a FAT32 volume has no fixed root region and a FAT12 or FAT16 volume must have
    // one.
    match boot.tail {
        BootSectorTail::Fat1216 { .. } => {
            if boot.root_entries == 0 {
                return Err(defect("BPB_RootEntCnt", 0));
            }
        }
        BootSectorTail::Fat32 { params, .. } => {
            if boot.root_entries != 0 {
                return Err(defect("BPB_RootEntCnt", u64::from(boot.root_entries)));
            }
            // The root is a cluster chain, so its first cluster must be one that exists.
            // Clusters number from 2, and the upper bound is checked below once the count
            // is known.
            if params.root_cluster < 2 {
                return Err(defect("BPB_RootClus", u64::from(params.root_cluster)));
            }
        }
    }

    let root_bytes = u64::from(boot.root_entries) * DIR_ENTRY_BYTES;
    let root_dir_sectors =
        u32::try_from(root_bytes.div_ceil(u64::from(boot.bytes_per_sector))).unwrap_or(u32::MAX);
    let overhead = u32::from(boot.reserved_sectors)
        .checked_add(
            u32::from(boot.fats)
                .checked_mul(fat_sectors)
                .ok_or_else(|| defect("BPB_FATSz32", u64::from(fat_sectors)))?,
        )
        .and_then(|n| n.checked_add(root_dir_sectors))
        .ok_or_else(|| defect("BPB_RsvdSecCnt", u64::from(boot.reserved_sectors)))?;
    let data_sectors = total_sectors
        .checked_sub(overhead)
        .ok_or_else(|| defect("BPB_TotSec32", u64::from(total_sectors)))?;
    let clusters = data_sectors / spc;
    if clusters == 0 {
        return Err(defect("BPB_SecPerClus", u64::from(spc)));
    }

    // The type. The cluster count decides it, with one exception that is not a deviation
    // from the rule so much as the order the rule is applied in: a zero 16-bit table size is
    // what every mainstream driver recognizes FAT32 by, and it is tested *before* anything
    // is counted. So a FAT32 volume below the cluster minimum — which a formatter will write
    // when asked directly — is read as FAT32 everywhere despite a count that would otherwise
    // derive to FAT16. Classifying it by the count alone would name a filesystem no driver
    // sees, and would read every chain through a table of the wrong entry width.
    //
    // The two tests meet where a 12/16 tail counts into the FAT32 band, and that shape is
    // refused rather than derived: the tail says the volume is not FAT32, so a count only
    // FAT32 addresses means the two halves of the header describe different filesystems.
    // Deriving `Fat32` there would set the entry width to 32 bits over a table the parameter
    // block sizes for 16, and would produce a layout no planner reaches — the FAT32 type
    // beside the fixed root region only the other two have. Linux refuses the same bytes,
    // reaching it from the other side: it takes "is it FAT32" from the table size, sets the
    // width to sixteen, and then finds the count above what sixteen bits address.
    let fat_type = match boot.tail {
        BootSectorTail::Fat32 { .. } => FatType::Fat32,
        BootSectorTail::Fat1216 { .. } => match FatType::of_cluster_count(clusters) {
            FatType::Fat32 => return Err(defect("BPB_TotSec32", u64::from(clusters))),
            twelve_or_sixteen => twelve_or_sixteen,
        },
    };
    // A count above what the type's entries address is not a volume that type describes: the
    // numbers at and above the end-of-chain floor are marks rather than clusters, so a chain
    // reaching one would be read as ending there and every file past it would truncate at a
    // cluster boundary and report success. This is the reader holding a count to the bound
    // the planner refuses to cross, so the two halves of the family agree on what a volume
    // of each type is.
    if clusters > fat_type.max_clusters() {
        return Err(defect("BPB_TotSec32", u64::from(clusters)));
    }
    // A table too small to hold an entry for every cluster the geometry implies is not a
    // filesystem a driver could follow: every chain past the table's end resolves to
    // whatever follows it. This is the check that ties the two halves of the header
    // together, since the table's size and the cluster count are computed from disjoint
    // fields.
    let table_entries = u64::from(fat_sectors) * u64::from(boot.bytes_per_sector) * 8
        / u64::from(fat_type.entry_bits());
    if table_entries < u64::from(clusters) + 2 {
        return Err(defect("BPB_FATSz32", table_entries));
    }

    let fat32 = match boot.tail {
        BootSectorTail::Fat1216 { .. } => None,
        BootSectorTail::Fat32 { params, .. } => {
            // A root cluster past the last one that exists would leave a driver with nowhere
            // to start reading, which is not a FAT32 volume however plausible the rest of it
            // looks.
            if params.root_cluster - 2 >= clusters {
                return Err(defect("BPB_RootClus", u64::from(params.root_cluster)));
            }
            // A backup of the information sector sits one field's distance past the backup
            // boot sector. Where that lands outside the reserved region there is no such
            // sector, which is a placement rather than a fault — the region simply had no
            // room for it.
            let backup_boot = (params.backup_boot_sector != 0).then_some(params.backup_boot_sector);
            let backup_fs_info = backup_boot.and_then(|b| {
                let at = u32::from(b) + u32::from(params.fs_info_sector);
                (at < u32::from(boot.reserved_sectors)).then_some(at as u16)
            });
            Some(Fat32Layout {
                root_cluster: params.root_cluster,
                fs_info_sector: params.fs_info_sector,
                backup_boot_sector: backup_boot,
                backup_fs_info_sector: backup_fs_info,
            })
        }
    };

    Ok(FatLayout {
        fat_type,
        bytes_per_sector: u32::from(boot.bytes_per_sector),
        sectors_per_cluster: spc,
        reserved_sectors: u32::from(boot.reserved_sectors),
        fats: u32::from(boot.fats),
        root_entries: u32::from(boot.root_entries),
        total_sectors,
        fat_sectors,
        root_dir_sectors,
        first_data_sector: overhead,
        clusters,
        fat32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::ondisk::{Fat32Params, VolumeInfo};
    use crate::fat::table;

    /// The parameters of one row of the type-determination table, and the count it reaches.
    ///
    /// These are the same rows the oracle tier drives the pinned `mkfs.fat` with, so the two
    /// derivations of every number here are independent: this module computes them, and the
    /// gate in `tests/fat_oracle.rs` reads them out of an image a foreign formatter wrote.
    struct Edge {
        what: &'static str,
        total_sectors: u64,
        reserved: u32,
        root_entries: u32,
        force: Option<FatType>,
        clusters: u32,
        kind: FatType,
    }

    const EDGES: &[Edge] = &[
        Edge {
            what: "one below the largest FAT12",
            total_sectors: 4160,
            reserved: 21,
            root_entries: 512,
            force: None,
            clusters: 4083,
            kind: FatType::Fat12,
        },
        Edge {
            what: "the largest FAT12",
            total_sectors: 4160,
            reserved: 20,
            root_entries: 512,
            force: None,
            clusters: 4084,
            kind: FatType::Fat12,
        },
        Edge {
            what: "the smallest FAT16 any formatter will write",
            total_sectors: 4160,
            reserved: 9,
            root_entries: 512,
            force: None,
            clusters: 4087,
            kind: FatType::Fat16,
        },
        Edge {
            what: "one above the smallest FAT16",
            total_sectors: 4160,
            reserved: 8,
            root_entries: 512,
            force: None,
            clusters: 4088,
            kind: FatType::Fat16,
        },
        Edge {
            what: "one below the largest FAT16",
            total_sectors: 66080,
            reserved: 13,
            root_entries: 512,
            force: None,
            clusters: 65523,
            kind: FatType::Fat16,
        },
        Edge {
            what: "the largest FAT16",
            total_sectors: 66080,
            reserved: 12,
            root_entries: 512,
            force: None,
            clusters: 65524,
            kind: FatType::Fat16,
        },
        Edge {
            what: "the smallest FAT32",
            total_sectors: 66592,
            reserved: 43,
            root_entries: 0,
            force: Some(FatType::Fat32),
            clusters: 65525,
            kind: FatType::Fat32,
        },
        Edge {
            what: "one above the smallest FAT32",
            total_sectors: 66592,
            reserved: 42,
            root_entries: 0,
            force: Some(FatType::Fat32),
            clusters: 65526,
            kind: FatType::Fat32,
        },
    ];

    fn request_for(edge: &Edge) -> PlanRequest {
        let mut r = PlanRequest::new(edge.total_sectors * 512)
            .cluster_size(ClusterSize::Sectors(1))
            .reserved_sectors(ReservedSectors::Count(edge.reserved))
            .fats(2);
        if edge.root_entries != 0 {
            r = r.root_entries(RootEntries::Count(edge.root_entries));
        }
        if let Some(kind) = edge.force {
            r = r.fat_type(FatTypeRequest::Exactly(kind));
        }
        r
    }

    #[test]
    fn the_planner_reaches_every_type_boundary() {
        for edge in EDGES {
            let layout = plan_layout(&request_for(edge))
                .unwrap_or_else(|e| panic!("{}: the planner refused the row: {e}", edge.what));
            assert_eq!(
                layout.clusters, edge.clusters,
                "{}: the cluster count is not the one these parameters reach",
                edge.what
            );
            assert_eq!(
                layout.fat_type, edge.kind,
                "{}: {} clusters derives the wrong type",
                edge.what, edge.clusters
            );
            // The count a driver recomputes from the planned fields, which is the only
            // count that decides anything.
            assert_eq!(
                (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster,
                edge.clusters,
                "{}: the planned count and the count the planned fields derive to disagree",
                edge.what
            );
            assert_eq!(FatType::of_cluster_count(layout.clusters), edge.kind);
        }
    }

    #[test]
    fn the_cluster_estimate_is_the_reference_computation() {
        // The three expressions the format's reference formatter uses, transcribed here in
        // the shape it writes them — a separate 12-bit form with a leading factor of two,
        // and 16- and 32-bit forms without one. [`cluster_estimate`] carries all three at a
        // single scale, which is the same value and is not obviously the same value.
        //
        // This is checked directly rather than through the differential gate because the
        // gate cannot see it. The estimate only seeds a table size, and the count is then
        // recomputed from the space that table left, so an estimate off by one is invisible
        // unless it crosses a sector boundary in the table as well — measured at well under
        // a hundredth of a percent of parameter sets, which no practical sweep of a foreign
        // formatter reaches. A second transcription reaches all of them.
        fn reference(d: u64, ss: u64, spc: u64, f: u64, bits: u32) -> u64 {
            match bits {
                12 => 2 * (d * ss + f * 3) / (2 * spc * ss + f * 3),
                16 => (d * ss + f * 4) / (spc * ss + f * 2),
                _ => (d * ss + f * 8) / (spc * ss + f * 4),
            }
        }
        let mut checked = 0u32;
        for bits in [12u32, 16, 32] {
            for bytes_per_sector in [512u32, 4096] {
                for spc in [1u32, 2, 8] {
                    for fats in [1u32, 2] {
                        for sectors in (1u32..12_000).step_by(1) {
                            assert_eq!(
                                u64::from(cluster_estimate(
                                    sectors,
                                    bits,
                                    bytes_per_sector,
                                    spc,
                                    fats
                                )),
                                reference(
                                    u64::from(sectors),
                                    u64::from(bytes_per_sector),
                                    u64::from(spc),
                                    u64::from(fats),
                                    bits
                                ),
                                "{bits}-bit, {bytes_per_sector}-byte sectors, {spc} per \
                                 cluster, {fats} tables, {sectors} sectors of table and data"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert!(checked > 400_000, "only {checked} inputs were checked");
    }

    #[test]
    fn the_thresholds_are_exclusive_below() {
        // The two off-by-ones that are the canonical FAT defect, stated directly rather than
        // only through the geometry that reaches them.
        assert_eq!(FatType::of_cluster_count(4084), FatType::Fat12);
        assert_eq!(FatType::of_cluster_count(4085), FatType::Fat16);
        assert_eq!(FatType::of_cluster_count(65524), FatType::Fat16);
        assert_eq!(FatType::of_cluster_count(65525), FatType::Fat32);
    }

    #[test]
    fn the_last_cluster_of_a_maximal_volume_is_an_ordinary_cluster() {
        // The property the three maxima are really about: a volume's highest cluster
        // *number* is one past its count, so the count must stop far enough below the
        // reserved values that the last cluster is not one of them. Stated over the three
        // types rather than left implicit in three constants, so it cannot drift again.
        for kind in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            let last = kind.max_clusters() + 1;
            assert!(
                table::is_cluster(kind, last),
                "{kind:?}: cluster {last:#x} is the highest on a maximal volume and is not an \
                 ordinary cluster",
            );
        }
        // FAT32 is the type whose maximum is set by that boundary and by nothing else, so it
        // sits exactly one below it. The other two stop earlier for reasons of their own —
        // the disputed FAT12/FAT16 range, and FAT16's reserved values — so neither is tight.
        assert!(!table::is_cluster(FatType::Fat32, MAX_CLUSTERS_FAT32 + 2));
        assert_eq!(MAX_CLUSTERS_FAT32 + 2, table::bad_cluster(FatType::Fat32));
    }

    #[test]
    fn the_defaults_reproduce_a_conventional_two_hundred_and_fifty_six_mebibyte_fat32() {
        // The fixture the oracle tier measured from the pinned formatter: a 256 MiB volume
        // asked for FAT32, everything else left to convention.
        let layout = plan_layout(
            &PlanRequest::new(256 << 20).fat_type(FatTypeRequest::Exactly(FatType::Fat32)),
        )
        .expect("plan");
        assert_eq!(layout.bytes_per_sector, 512);
        assert_eq!(layout.sectors_per_cluster, 1);
        assert_eq!(layout.reserved_sectors, 32);
        assert_eq!(layout.fats, 2);
        assert_eq!(layout.root_entries, 0);
        assert_eq!(layout.root_dir_sectors, 0);
        assert_eq!(layout.fat_sectors, 4033);
        assert_eq!(layout.total_sectors, 524_288);
        assert_eq!(layout.clusters, 516_190);
        let fat32 = layout
            .fat32
            .expect("a FAT32 layout carries its own placements");
        assert_eq!(fat32.root_cluster, 2);
        assert_eq!(fat32.fs_info_sector, 1);
        assert_eq!(fat32.backup_boot_sector, Some(6));
    }

    #[test]
    fn the_planner_steps_down_out_of_the_disputed_range() {
        // These are the two reserved-sector counts the oracle tier drives the pinned
        // `mkfs.fat` with and observes it refuse: at each, the FAT12 count has passed 4084
        // while the FAT16 count has not reached 4087, so the volume falls between the two
        // types. The planner declares the largest undisputed FAT12 and leaves the remainder
        // unused, which always fits in the volume already given.
        for reserved in [19u32, 10] {
            let layout = plan_layout(
                &PlanRequest::new(4160 * 512)
                    .cluster_size(ClusterSize::Sectors(1))
                    .reserved_sectors(ReservedSectors::Count(reserved))
                    .root_entries(RootEntries::Count(512)),
            )
            .unwrap_or_else(|e| panic!("{reserved} reserved: the step down must succeed: {e}"));
            assert_eq!(layout.fat_type, FatType::Fat12);
            assert_eq!(layout.clusters, MAX_CLUSTERS_FAT12);
            // The volume is longer than the filesystem, which is the only case in which that
            // is true, and the filesystem is still self-consistent.
            assert!(layout.total_sectors < 4160);
            assert_eq!(
                (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster,
                MAX_CLUSTERS_FAT12
            );
            // The remainder given up is single-digit clusters: the two types' tables differ
            // by a few sectors at this size, and that difference is the whole of the gap.
            assert!(4160 - layout.total_sectors < 16 * layout.sectors_per_cluster);
        }
    }

    #[test]
    fn a_fat16_in_the_disputed_range_is_refused_by_name() {
        let fat16_at = |reserved: u32| {
            plan_layout(
                &PlanRequest::new(4160 * 512)
                    .cluster_size(ClusterSize::Sectors(1))
                    .reserved_sectors(ReservedSectors::Count(reserved))
                    .root_entries(RootEntries::Count(512))
                    .fat_type(FatTypeRequest::Exactly(FatType::Fat16)),
            )
        };
        // 9 reserved sectors is the smallest FAT16 that is *not* disputed, so it succeeds.
        assert_eq!(fat16_at(9).expect("plan").clusters, MIN_CLUSTERS_FAT16);

        // Stepping down would make it a FAT12, which is not what was asked for, and stepping
        // up needs a larger volume. So this is the one request that cannot be satisfied, and
        // the error names the range it landed in rather than only that it did not fit. Both
        // disputed counts are reachable from this volume.
        for (reserved, expected) in [(11u32, 4085u32), (10, 4086)] {
            match fat16_at(reserved).expect_err("a disputed FAT16 has no way out here") {
                GeometryError::AmbiguousClusterCount {
                    clusters,
                    low,
                    high,
                    high_plus_one,
                } => {
                    assert_eq!(clusters, expected);
                    assert_eq!(
                        (low, high),
                        (MAX_CLUSTERS_FAT12 + 1, MIN_CLUSTERS_FAT16 - 1)
                    );
                    assert_eq!(high_plus_one, MIN_CLUSTERS_FAT16);
                }
                other => panic!("expected the disputed range to be named, got {other}"),
            }
        }
    }

    #[test]
    fn an_undersized_fat32_needs_the_acknowledgement() {
        // Small enough that FAT32 is far below its cluster minimum, and every mainstream
        // driver reads it as FAT32 all the same.
        let base = PlanRequest::new(8 << 20)
            .cluster_size(ClusterSize::Sectors(1))
            .reserved_sectors(ReservedSectors::Count(32));

        let err = plan_layout(&base.fat_type(FatTypeRequest::Exactly(FatType::Fat32)))
            .expect_err("a conformant FAT32 does not fit here");
        assert!(matches!(
            err,
            GeometryError::ClustersBelowMinimum {
                requested: FatType::Fat32,
                minimum: MIN_CLUSTERS_FAT32,
                ..
            }
        ));

        let layout = plan_layout(&base.fat_type(FatTypeRequest::UndersizedFat32))
            .expect("the acknowledgement produces it");
        assert_eq!(layout.fat_type, FatType::Fat32);
        assert!(layout.clusters < MIN_CLUSTERS_FAT32);
        assert!(layout.fat32.is_some());
    }

    #[test]
    fn there_is_no_acknowledgement_for_an_undersized_fat16() {
        // A FAT16 below the FAT12 ceiling is not a non-conformant FAT16: it is a volume
        // every driver reads through a 12-bit table. There is no opt-in, and the refusal is
        // the only answer.
        let err = plan_layout(
            &PlanRequest::new(1 << 20)
                .cluster_size(ClusterSize::Sectors(1))
                .fat_type(FatTypeRequest::Exactly(FatType::Fat16)),
        )
        .expect_err("a FAT16 this small is unreachable");
        assert!(matches!(
            err,
            GeometryError::ClustersBelowMinimum {
                requested: FatType::Fat16,
                ..
            }
        ));
    }

    #[test]
    fn auto_grows_the_cluster_until_a_type_fits() {
        // A volume far past what FAT16 addresses at one sector per cluster. The search
        // doubles until the count comes back into range rather than refusing.
        let layout = plan_layout(&PlanRequest::new(1 << 30)).expect("plan");
        assert_eq!(layout.fat_type, FatType::Fat32);
        assert!(layout.clusters <= MAX_CLUSTERS_FAT32);
        assert!(layout.sectors_per_cluster.is_power_of_two());

        // With the cluster pinned at one sector, FAT16 cannot address it and the error says
        // so rather than silently choosing a larger cluster.
        let err = plan_layout(
            &PlanRequest::new(1 << 30)
                .cluster_size(ClusterSize::Sectors(1))
                .fat_type(FatTypeRequest::Exactly(FatType::Fat16)),
        )
        .expect_err("FAT16 cannot address a gibibyte in 512-byte clusters");
        assert!(matches!(
            err,
            GeometryError::ClustersAboveMaximum {
                requested: FatType::Fat16,
                maximum: MAX_CLUSTERS_FAT16,
                ..
            }
        ));
    }

    #[test]
    fn auto_selects_fat32_from_half_a_gibibyte_up() {
        // The threshold convention uses, and one either side of it.
        assert_eq!(
            plan_layout(&PlanRequest::new(FAT32_AUTO_THRESHOLD_BYTES))
                .expect("plan")
                .fat_type,
            FatType::Fat32
        );
        assert_eq!(
            plan_layout(&PlanRequest::new(FAT32_AUTO_THRESHOLD_BYTES - (1 << 20)))
                .expect("plan")
                .fat_type,
            FatType::Fat16
        );
    }

    #[test]
    fn the_layout_is_consistent_at_every_sector_size_the_format_defines() {
        for bytes_per_sector in [512u32, 1024, 2048, 4096] {
            let layout =
                plan_layout(&PlanRequest::new(512 << 20).bytes_per_sector(bytes_per_sector))
                    .unwrap_or_else(|e| panic!("{bytes_per_sector}-byte sectors: {e}"));
            assert_eq!(layout.bytes_per_sector, bytes_per_sector);
            assert_eq!(
                (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster,
                layout.clusters,
                "{bytes_per_sector}-byte sectors: the planned count and the derived count \
                 disagree"
            );
            assert_eq!(FatType::of_cluster_count(layout.clusters), layout.fat_type);
            // The whole volume is described, up to the tail that does not complete a
            // cluster.
            let volume_sectors = (512 << 20) / u64::from(bytes_per_sector);
            assert_eq!(u64::from(layout.total_sectors), volume_sectors);
        }
        for bad in [128u32, 256, 8192, 0, 513] {
            assert!(matches!(
                plan_layout(&PlanRequest::new(64 << 20).bytes_per_sector(bad)),
                Err(GeometryError::SectorSizeUnsupported { .. })
            ));
        }
    }

    #[test]
    fn the_whole_volume_is_described() {
        // Nothing is rounded away from the sector count the caller gave: a volume of an
        // awkward size still describes every sector of itself. Only the disputed-range step
        // down shortens a filesystem, and it is not reached here.
        for sectors in [20_001u64, 66_081, 524_289] {
            let layout = plan_layout(&PlanRequest::new(sectors * 512)).expect("plan");
            assert_eq!(u64::from(layout.total_sectors), sectors);
        }
        // A size that is not a whole number of sectors rounds down to one.
        let layout = plan_layout(&PlanRequest::new(20_001 * 512 + 511)).expect("plan");
        assert_eq!(layout.total_sectors, 20_001);
    }

    #[test]
    fn the_regions_are_cluster_aligned_above_the_threshold_and_not_below_it() {
        // Above the threshold, the data region starts on a cluster boundary, which is what
        // keeps a cluster write from straddling two erase blocks on flash.
        let layout = plan_layout(
            &PlanRequest::new(64 << 20)
                .cluster_size(ClusterSize::Sectors(8))
                .reserved_sectors(ReservedSectors::Count(3)),
        )
        .expect("plan");
        assert!(layout.total_sectors > ALIGNMENT_THRESHOLD_SECTORS);
        assert_eq!(layout.reserved_sectors % 8, 0);
        assert_eq!(layout.fat_sectors % 8, 0);
        assert_eq!(layout.root_dir_sectors % 8, 0);
        assert_eq!(layout.first_data_sector % 8, 0);

        // At or below it the alignment is skipped, because the sectors it would spend are a
        // large share of the volume and there is no erase block to align to.
        let layout = plan_layout(
            &PlanRequest::new(ALIGNMENT_THRESHOLD_SECTORS as u64 * 512)
                .cluster_size(ClusterSize::Sectors(8))
                .reserved_sectors(ReservedSectors::Count(3)),
        )
        .expect("plan");
        assert_eq!(layout.reserved_sectors, 3);
    }

    #[test]
    fn the_root_entry_count_recorded_is_the_one_the_region_holds() {
        // Alignment can only grow the region, and the count in the boot sector has to match
        // it -- a driver recomputes the region's size from the count, so a count describing
        // a smaller region would put the data region in the wrong place.
        let layout = plan_layout(
            &PlanRequest::new(64 << 20)
                .cluster_size(ClusterSize::Sectors(8))
                .root_entries(RootEntries::Count(512)),
        )
        .expect("plan");
        assert_eq!(
            (layout.root_entries * 32).div_ceil(layout.bytes_per_sector),
            layout.root_dir_sectors
        );
        assert!(layout.root_entries >= 512);

        // The invariant, over every count and geometry: whatever is recorded has to describe
        // exactly the region that was placed, in both directions.
        for entries in [1u32, 16, 17, 100, 200, 224, 512, 1000] {
            for bytes_per_sector in [512u32, 4096] {
                for (volume, spc) in [(2u64 << 20, 1u32), (64 << 20, 1), (64 << 20, 8)] {
                    let layout = plan_layout(
                        &PlanRequest::new(volume)
                            .bytes_per_sector(bytes_per_sector)
                            .cluster_size(ClusterSize::Sectors(spc))
                            .root_entries(RootEntries::Count(entries))
                            .fat_type(FatTypeRequest::Exactly(FatType::Fat16)),
                    );
                    let Ok(layout) = layout else { continue };
                    let what = format!(
                        "{entries} entries, {bytes_per_sector}-byte sectors, {spc} \
                                        sectors per cluster, {volume} bytes"
                    );
                    assert_eq!(
                        (layout.root_entries * 32).div_ceil(layout.bytes_per_sector),
                        layout.root_dir_sectors,
                        "{what}: the recorded count describes a different region than was placed"
                    );
                    assert!(
                        layout.root_entries >= entries,
                        "{what}: the recorded count is below what was asked for"
                    );
                }
            }
        }

        // On a volume too small to align, the count is exactly what was asked for. A region
        // sized for a caller's count and then reported as larger hands over slots the caller
        // did not ask for, and the two conventional formatters do not do that either.
        let layout = plan_layout(
            &PlanRequest::new(2 << 20)
                .cluster_size(ClusterSize::Sectors(1))
                .root_entries(RootEntries::Count(200)),
        )
        .expect("plan");
        assert!(layout.total_sectors <= ALIGNMENT_THRESHOLD_SECTORS);
        assert_eq!(layout.root_entries, 200);
        assert_eq!(layout.root_dir_sectors, 13);
    }

    #[test]
    fn the_step_down_applies_only_where_the_volume_is_between_the_two_types() {
        // The step down shortens a filesystem, and shortening the wrong volume is the worst
        // thing this planner could do quietly: a caller who asked for a 256 MiB volume and
        // got a 2 MiB filesystem with no error has lost 99% of what they asked for and been
        // told the format succeeded.
        //
        // The entry condition -- a FAT12 count past 4084 -- is met by every large volume with
        // a small cluster, and is not by itself evidence of the gap. What makes it the gap is
        // that FAT16 has not reached its own minimum either.
        for volume in [64u64 << 20, 256 << 20, 511 << 20] {
            let err = plan_layout(&PlanRequest::new(volume).cluster_size(ClusterSize::Sectors(1)))
                .expect_err("a volume no type fits at one sector per cluster must be refused");
            assert!(
                matches!(err, GeometryError::NoTypeFits { .. }),
                "{volume} bytes: {err}"
            );
        }

        // And the gap itself still steps down, which is what the exclusion above must not
        // have cost. At this fixture the FAT12 candidate has passed 4084 while the FAT16
        // candidate has not reached 4087, so neither type covers the volume.
        let mut stepped = 0;
        for reserved in 1..=48u32 {
            let layout = plan_layout(
                &PlanRequest::new(4160 * 512)
                    .cluster_size(ClusterSize::Sectors(1))
                    .reserved_sectors(ReservedSectors::Count(reserved))
                    .root_entries(RootEntries::Count(512)),
            )
            .unwrap_or_else(|e| panic!("{reserved} reserved: {e}"));
            if layout.total_sectors < 4160 {
                assert_eq!(layout.fat_type, FatType::Fat12, "{reserved} reserved");
                assert_eq!(layout.clusters, MAX_CLUSTERS_FAT12, "{reserved} reserved");
                stepped += 1;
            }
        }
        assert!(
            stepped > 0,
            "no reserved count reached the range between the two types, so this fixture no \
             longer exercises the step down"
        );
    }

    #[test]
    fn the_addressing_helpers_refuse_what_is_not_there() {
        let layout = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        assert_eq!(layout.fat_start_sector(0), Some(layout.reserved_sectors));
        assert_eq!(
            layout.fat_start_sector(1),
            Some(layout.reserved_sectors + layout.fat_sectors)
        );
        assert_eq!(layout.fat_start_sector(layout.fats), None);
        // Clusters number from 2, and the last one that exists is `clusters + 1`.
        assert_eq!(layout.cluster_start_sector(0), None);
        assert_eq!(layout.cluster_start_sector(1), None);
        assert_eq!(
            layout.cluster_start_sector(2),
            Some(layout.first_data_sector)
        );
        assert!(layout.cluster_start_sector(layout.clusters + 1).is_some());
        assert_eq!(layout.cluster_start_sector(layout.clusters + 2), None);
        // The table is large enough for every cluster that exists plus the two reserved
        // entries at its head.
        assert!(layout.max_table_entries() >= layout.clusters + 2);
    }

    #[test]
    fn a_fat32_layout_carries_the_fat32_placements_and_no_other_does() {
        let small = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        assert_eq!(small.fat_type, FatType::Fat16);
        assert!(small.fat32.is_none());
        assert!(small.root_dir_start_sector().is_some());

        let large = plan_layout(&PlanRequest::new(1 << 30)).expect("plan");
        assert_eq!(large.fat_type, FatType::Fat32);
        assert!(large.fat32.is_some());
        assert_eq!(large.root_entries, 0);
        assert_eq!(large.root_dir_sectors, 0);
        assert!(large.root_dir_start_sector().is_none());
    }

    #[test]
    fn the_backup_boot_sector_falls_back_as_the_reserved_region_shrinks() {
        // Sector 6 wherever there is room for it, which is where a driver recovering a
        // damaged volume looks first.
        assert_eq!(backup_boot_sector(32, 1), Some(6));
        assert_eq!(backup_boot_sector(7, 1), Some(6));
        // Below that, the last reserved sector that is neither the boot sector nor the
        // information sector.
        assert_eq!(backup_boot_sector(6, 1), Some(4));
        assert_eq!(backup_boot_sector(4, 1), Some(2));
        assert_eq!(backup_boot_sector(3, 1), Some(2));
        // And a reserved region with no room for one at all.
        assert_eq!(backup_boot_sector(2, 1), None);
    }

    #[test]
    fn the_parameters_the_format_does_not_allow_are_named() {
        let base = PlanRequest::new(64 << 20);
        assert!(matches!(
            plan_layout(&base.fats(0)),
            Err(GeometryError::FatCountUnsupported { fats: 0 })
        ));
        assert!(matches!(
            plan_layout(&base.fats(3)),
            Err(GeometryError::FatCountUnsupported { fats: 3 })
        ));
        assert!(matches!(
            plan_layout(&base.cluster_size(ClusterSize::Sectors(3))),
            Err(GeometryError::ClusterSizeUnsupported { .. })
        ));
        assert!(matches!(
            plan_layout(&base.cluster_size(ClusterSize::Sectors(256))),
            Err(GeometryError::ClusterSizeUnsupported { .. })
        ));
        // 128 sectors is a legal cluster size, but at 512 bytes it is a 64 KiB allocation
        // unit, which the format's own guidance says a driver may not handle.
        assert!(matches!(
            plan_layout(&base.cluster_size(ClusterSize::Sectors(128))),
            Err(GeometryError::ClusterTooLarge {
                limit: MAX_BYTES_PER_CLUSTER,
                ..
            })
        ));
        assert!(matches!(
            plan_layout(&base.reserved_sectors(ReservedSectors::Count(0))),
            Err(GeometryError::ReservedSectorsTooFew { minimum: 1, .. })
        ));
        assert!(matches!(
            plan_layout(
                &base
                    .fat_type(FatTypeRequest::Exactly(FatType::Fat32))
                    .reserved_sectors(ReservedSectors::Count(1))
            ),
            Err(GeometryError::ReservedSectorsTooFew { minimum: 2, .. })
        ));
        // A reserved region wider than the boot sector's own 16-bit count. Truncating it
        // would put a driver's data region 65536 sectors before the formatter's, so every
        // cluster on the volume would resolve somewhere else.
        assert!(matches!(
            plan_layout(
                &PlanRequest::new(1 << 30).reserved_sectors(ReservedSectors::Count(70_000))
            ),
            Err(GeometryError::ReservedSectorsTooMany {
                reserved: 70_000,
                ..
            })
        ));
        // And the count the alignment carries past the limit, which the check on the request
        // alone does not catch: 65535 rounded up to a 64-sector cluster is 65536. The volume
        // is large enough for the type to fit, so what refuses this is the field's width and
        // not the geometry running out of clusters.
        let wide = PlanRequest::new(4 << 30).cluster_size(ClusterSize::Sectors(64));
        let aligned_past =
            plan_layout(&wide.reserved_sectors(ReservedSectors::Count(u32::from(u16::MAX))));
        assert!(
            matches!(
                aligned_past,
                Err(GeometryError::ReservedSectorsTooMany {
                    reserved: 65_536,
                    ..
                })
            ),
            "{aligned_past:?}"
        );
        // One cluster below it is a count the alignment leaves in range, which is what says
        // the refusal above is about the boundary rather than about the size.
        assert_eq!(
            plan_layout(&wide.reserved_sectors(ReservedSectors::Count(65_472)))
                .expect("plan")
                .reserved_sectors,
            65_472
        );
        assert!(matches!(
            plan_layout(&base.root_entries(RootEntries::Count(0))),
            Err(GeometryError::RootEntriesUnsupported { .. })
        ));
        assert!(matches!(
            plan_layout(&base.root_entries(RootEntries::Count(100_000))),
            Err(GeometryError::RootEntriesUnsupported { .. })
        ));
        // FAT32's root is a chain, so entries reserved in a region it does not have is a
        // refusal rather than a value quietly ignored — a knob that did nothing is not
        // something a caller should have to discover from the output. It is refused whether
        // FAT32 was named or selected by the volume's size, since the count means no more
        // in one case than the other.
        for request in [
            FatTypeRequest::Exactly(FatType::Fat32),
            FatTypeRequest::UndersizedFat32,
            FatTypeRequest::Auto,
        ] {
            assert!(
                matches!(
                    plan_layout(
                        &PlanRequest::new(1 << 30)
                            .fat_type(request)
                            .root_entries(RootEntries::Count(512))
                    ),
                    Err(GeometryError::RootEntriesOnFat32 { root_entries: 512 })
                ),
                "{request:?} on a volume this size reaches FAT32, so a root entry count \
                 must be refused rather than ignored"
            );
        }
    }

    #[test]
    fn a_volume_with_no_room_for_a_data_region_is_refused() {
        // The floor is where the reserved sector, the root region, and one table leave
        // nothing behind, and nowhere above it. There is no minimum useful size here: a
        // volume that holds a handful of clusters holds a filesystem, and refusing it would
        // be this crate imposing a limit the format does not have.
        for bytes in [0u64, 512, 4096, 16 << 10] {
            assert!(
                matches!(
                    plan_layout(&PlanRequest::new(bytes)),
                    Err(GeometryError::NoTypeFits { .. })
                ),
                "a volume of {bytes} bytes must be refused rather than planned"
            );
        }
        // And just above it, a very small but entirely valid FAT12.
        let layout = plan_layout(&PlanRequest::new(32 << 10)).expect("plan");
        assert_eq!(layout.fat_type, FatType::Fat12);
        assert!(layout.clusters > 0);
        assert_eq!(
            (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster,
            layout.clusters
        );
    }

    #[test]
    fn a_volume_past_a_thirty_two_bit_sector_count_is_refused() {
        let sectors = u64::from(u32::MAX) + 1;
        assert!(matches!(
            plan_layout(&PlanRequest::new(sectors * 512)),
            Err(GeometryError::VolumeTooLarge { .. })
        ));
        // At a larger sector size the same byte count fits, since it is the sector count
        // that is bounded and not the volume.
        assert!(plan_layout(&PlanRequest::new(sectors * 512).bytes_per_sector(4096)).is_ok());
    }

    #[test]
    fn planning_is_deterministic() {
        // Two plans of one request are the same plan. Nothing here reads a clock or a
        // random source, and the reproducibility of an image rests on that.
        let request = PlanRequest::new(3 << 30).bytes_per_sector(1024);
        assert_eq!(plan_layout(&request), plan_layout(&request));
    }

    #[test]
    fn every_planned_volume_is_self_consistent() {
        // A sweep rather than a table: whatever the planner produces, a driver's own
        // derivation of the count and of the type has to agree with it, and the regions have
        // to tile the volume in order without overlapping.
        for mib in [1u64, 3, 8, 33, 64, 260, 511, 512, 1024, 4096, 16384] {
            for bytes_per_sector in [512u32, 4096] {
                let request = PlanRequest::new(mib << 20).bytes_per_sector(bytes_per_sector);
                let Ok(layout) = plan_layout(&request) else {
                    continue;
                };
                let derived =
                    (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster;
                assert_eq!(derived, layout.clusters, "{mib} MiB at {bytes_per_sector}");
                assert_eq!(
                    FatType::of_cluster_count(layout.clusters),
                    layout.fat_type,
                    "{mib} MiB at {bytes_per_sector}"
                );
                assert_eq!(
                    layout.first_data_sector,
                    layout.reserved_sectors
                        + layout.fats * layout.fat_sectors
                        + layout.root_dir_sectors,
                    "{mib} MiB at {bytes_per_sector}"
                );
                assert!(
                    layout.first_data_sector + layout.data_sectors() <= layout.total_sectors,
                    "{mib} MiB at {bytes_per_sector}: the data region runs past the volume"
                );
                assert!(
                    layout.max_table_entries() >= layout.clusters + 2,
                    "{mib} MiB at {bytes_per_sector}: the table cannot index its own clusters"
                );
                assert!(
                    layout.clusters >= layout.fat_type.min_clusters()
                        && layout.clusters <= layout.fat_type.max_clusters(),
                    "{mib} MiB at {bytes_per_sector}: {} clusters is outside {}'s range",
                    layout.clusters,
                    layout.fat_type
                );
                assert!(
                    u64::from(layout.bytes_per_cluster()) <= u64::from(MAX_BYTES_PER_CLUSTER),
                    "{mib} MiB at {bytes_per_sector}: the allocation unit is too large"
                );
                assert_layout_is_coherent(&layout, &format!("{mib} MiB at {bytes_per_sector}"));
            }
        }
    }

    // -- what a parameter block may describe -------------------------------------------

    /// The pairing [`FatLayout::fat32`] states, checked wherever a layout comes from.
    ///
    /// A layout that broke it would be three fields that cannot all be true at once, and a
    /// consumer matching on the type and reading the placements would be reading a
    /// description that contradicts itself.
    fn assert_layout_is_coherent(layout: &FatLayout, what: &str) {
        assert_eq!(
            layout.fat32.is_some(),
            layout.fat_type == FatType::Fat32,
            "{what}: {} beside {:?} placements",
            layout.fat_type,
            layout.fat32.map(|_| "FAT32"),
        );
        assert_eq!(
            layout.fat32.is_none(),
            layout.root_entries != 0,
            "{what}: {} root entries on a {} volume",
            layout.root_entries,
            layout.fat_type,
        );
        assert_eq!(
            layout.root_dir_sectors == 0,
            layout.fat32.is_some(),
            "{what}: {} root sectors on a {} volume",
            layout.root_dir_sectors,
            layout.fat_type,
        );
    }

    fn volume_info(fs_type: &[u8; 8]) -> VolumeInfo {
        VolumeInfo {
            drive_number: 0x80,
            ext_boot_signature: 0x29,
            volume_id: 0x1234_abcd,
            label: VolumeInfo::NO_NAME,
            fs_type: *fs_type,
        }
    }

    /// A parameter block of the 12/16 shape — a non-zero 16-bit table size, a non-zero root
    /// entry count, a `FAT16   ` type string — sized so its cluster count comes to
    /// `clusters`, and the bytes such a volume occupies.
    ///
    /// Everything here agrees with everything else: this is a well-formed header whose only
    /// question is which type its count derives to.
    fn fat1216_counting(clusters: u32, fat_sectors: u16) -> (BootSector, u64) {
        let root_entries = 512u16;
        let root_dir_sectors = u32::from(root_entries) * DIR_ENTRY_BYTES as u32 / 512;
        let total = 1 + u32::from(fat_sectors) + root_dir_sectors + clusters;
        let boot = BootSector {
            jump: [0xEB, 0x3C, 0x90],
            oem_name: *b"ferrosys",
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 1,
            fats: 1,
            root_entries,
            total_sectors_16: 0,
            media: 0xF8,
            fat_sectors_16: fat_sectors,
            sectors_per_track: 32,
            heads: 64,
            hidden_sectors: 0,
            total_sectors_32: total,
            tail: BootSectorTail::Fat1216 {
                volume: volume_info(b"FAT16   "),
            },
        };
        (boot, u64::from(total) * 512)
    }

    /// The same for the FAT32 shape: a zero 16-bit table size, no root region, and the table
    /// size in the tail.
    fn fat32_counting(clusters: u32, fat_sectors: u32) -> (BootSector, u64) {
        let total = 32 + fat_sectors + clusters;
        let boot = BootSector {
            jump: [0xEB, 0x58, 0x90],
            oem_name: *b"ferrosys",
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 1,
            root_entries: 0,
            total_sectors_16: 0,
            media: 0xF8,
            fat_sectors_16: 0,
            sectors_per_track: 32,
            heads: 64,
            hidden_sectors: 0,
            total_sectors_32: total,
            tail: BootSectorTail::Fat32 {
                params: Fat32Params {
                    fat_sectors,
                    ext_flags: 0,
                    version: 0,
                    root_cluster: 2,
                    fs_info_sector: 1,
                    backup_boot_sector: 6,
                },
                volume: volume_info(b"FAT32   "),
            },
        };
        (boot, u64::from(total) * 512)
    }

    #[test]
    fn a_twelve_or_sixteen_tail_never_derives_to_fat32() {
        // The tail says the volume is not FAT32 and the count says only FAT32 addresses it,
        // so the two halves of the header describe different filesystems. Deriving `Fat32`
        // there would follow every chain through 32-bit entries over a table the block sizes
        // for 16, and would produce a layout no planner reaches: the FAT32 type beside the
        // fixed root region only the other two have.
        //
        // The table is sized to hold an entry per cluster at *either* width, so what refuses
        // the volume is the derivation rather than a table that does not fit.
        let (boot, available) = fat1216_counting(MIN_CLUSTERS_FAT32, 512);
        let defect = layout_from_boot(&boot, available).expect_err("the shape is refused");
        assert_eq!(defect.value, u64::from(MIN_CLUSTERS_FAT32));

        // One cluster fewer is the same header at the largest count FAT16 addresses, and it
        // is an ordinary FAT16 volume — which is what says the refusal is about the band and
        // not about the shape.
        let (boot, available) = fat1216_counting(MAX_CLUSTERS_FAT16, 512);
        let layout = layout_from_boot(&boot, available).expect("an ordinary FAT16 volume");
        assert_eq!(layout.fat_type, FatType::Fat16);
        assert_eq!(layout.clusters, MAX_CLUSTERS_FAT16);
        assert_layout_is_coherent(&layout, "a recovered FAT16");
    }

    #[test]
    fn a_count_above_what_the_type_addresses_is_refused() {
        // The numbers at and above the end-of-chain floor are marks rather than clusters. A
        // volume counting past them has clusters no chain can name: a chain reaching one
        // would be read as ending there, so a file would truncate at a cluster boundary and
        // the short read would come back as success.
        let over = MAX_CLUSTERS_FAT32 + 1;
        let (boot, available) = fat32_counting(over, 2_097_152);
        let defect = layout_from_boot(&boot, available).expect_err("the count is refused");
        assert_eq!(defect.value, u64::from(over));

        // The maximum itself is a volume, which is where the bound sits rather than one
        // short of it.
        let (boot, available) = fat32_counting(MAX_CLUSTERS_FAT32, 2_097_152);
        let layout = layout_from_boot(&boot, available).expect("the largest FAT32 there is");
        assert_eq!(layout.fat_type, FatType::Fat32);
        assert_eq!(layout.clusters, MAX_CLUSTERS_FAT32);
        assert_layout_is_coherent(&layout, "a recovered FAT32");
        // Every cluster it counts is one a chain can name, which is what the bound buys.
        assert!(layout.clusters + 1 < table::end_of_chain(FatType::Fat32));
        assert!(layout.clusters + 1 < table::bad_cluster(FatType::Fat32));
    }

    #[test]
    fn the_reader_holds_a_count_to_the_bound_the_planner_refuses_to_cross() {
        // The writer and the reader applying one rule to one field. Whatever the planner
        // will not produce for a type, the reader will not accept for it either.
        for kind in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            let err = plan_layout(
                &PlanRequest::new(u64::from(kind.max_clusters()) * 512 * 2)
                    .cluster_size(ClusterSize::Sectors(1))
                    .fat_type(FatTypeRequest::Exactly(kind)),
            )
            .expect_err("a volume past what the type addresses");
            assert!(
                matches!(err, GeometryError::ClustersAboveMaximum { requested, maximum, .. }
                    if requested == kind && maximum == kind.max_clusters()),
                "{kind}: {err}"
            );
        }
    }
}
