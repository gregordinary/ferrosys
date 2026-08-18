//! Geometry: from a volume size to where every region of an exFAT filesystem begins and how
//! long it is.
//!
//! [`plan_layout`] is the whole of it. It takes what a caller can state — how large the
//! volume is, how large a sector is, how large an allocation unit should be, and what
//! boundary the regions align to — and derives what the format records: where the allocation
//! table sits, how long it is, where the cluster heap begins, how many clusters it holds,
//! and which of those the three residents a format writes occupy.
//!
//! `layout_from_boot` is the same arithmetic run backwards, and it is the crate's single
//! definition of "these bytes are an exFAT volume". Detection and reading both go through
//! it, so it is impossible for detection to claim a volume the reader then refuses, or for
//! the reader to open one detection called unrecognized.
//!
//! This module is pure and deterministic: it computes numbers from numbers and performs no
//! I/O.
//!
//! # The order the derivation runs in
//!
//! The allocation table's size depends on how many clusters there are, and how many clusters
//! there are depends on how much room the table left. That is circular, and it is resolved
//! the way the format's own tooling resolves it: bound the clusters from above by charging
//! each one for its own table entry *before* any table has been sized, size a table for that
//! bound, and then count the clusters that actually fit behind it. The bound is never low, so
//! the table is never too small; it may be a few entries long, which costs a sector at most
//! and is what every implementation writes.

use super::ondisk::{
    BOOT_REGION_SECTORS, FILE_SYSTEM_MAJOR_REVISION, MAX_CLUSTER_SHIFT, MainBootSector,
    RECOMMENDED_UPCASE_BYTES,
};

#[cfg(feature = "serde")]
use serde::Serialize;

/// The first cluster of the heap. Numbers 0 and 1 have entries in the allocation table and
/// no storage, so the heap's first cluster is numbered 2.
pub const FIRST_CLUSTER: u32 = 2;

/// The most clusters a volume may hold.
///
/// A cluster number is 32 bits and the top ten values are reserved for the end-of-chain and
/// bad-cluster marks, so the highest ordinary cluster number is `0xFFFFFFF6` — and the count
/// is one less than that, the numbering starting at [`FIRST_CLUSTER`].
pub const MAX_CLUSTER_COUNT: u32 = 0xFFFF_FFF5;

/// The fewest sectors a volume may span.
///
/// Two boot regions are 24 sectors, and what remains has to hold an allocation table, an
/// allocation bitmap, an up-case table and a root directory. Every implementation draws the
/// line here.
pub const MIN_VOLUME_SECTORS: u64 = 2048;

/// The largest allocation unit the format defines, in bytes.
///
/// It follows from the two shifts a boot sector records: their sum is capped at
/// [`MAX_CLUSTER_SHIFT`], and 2^25 is 32 mebibytes.
pub const MAX_BYTES_PER_CLUSTER: u32 = 1 << MAX_CLUSTER_SHIFT;

/// The boundary every region of a volume aligns to unless a caller names another.
///
/// One mebibyte, which is a byte quantity rather than a sector count: the allocation table
/// begins 2048 sectors into a volume with 512-byte sectors and 256 sectors into one with
/// 4096-byte sectors, and both are the same place.
pub const DEFAULT_BOUNDARY_ALIGN: u32 = 1 << 20;

/// Sectors reserved ahead of the first aligned region, the two boot regions included.
///
/// Twenty-four is the two regions themselves; the alignment then pushes the allocation table
/// out to the next boundary, so on any volume with an alignment worth the name there is
/// space behind them that nothing uses.
const RESERVED_SECTORS: u64 = 2 * BOOT_REGION_SECTORS;

/// The size of the allocation unit.
///
/// The unit is bytes, which is what the variant says and what the format caps: a cluster may
/// not exceed [`MAX_BYTES_PER_CLUSTER`] however many sectors that is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ClusterSize {
    /// The size convention selects for a volume this large: 512 bytes below 7 mebibytes,
    /// 4 kibibytes to 256 mebibytes, 32 kibibytes to 32 gibibytes, and 128 kibibytes above
    /// that.
    #[default]
    Auto,
    /// Exactly this many bytes: a power of two, at least the sector size, and at most
    /// [`MAX_BYTES_PER_CLUSTER`].
    Bytes(u32),
}

/// The boundary the allocation table and the cluster heap each begin on.
///
/// It is a placement decision rather than a recorded field, and it shows up in the two
/// offsets a boot sector does record. Aligning to the erase block of the medium a volume is
/// going onto is what it is for, which is why removable media are formatted this way.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum BoundaryAlign {
    /// [`DEFAULT_BOUNDARY_ALIGN`].
    #[default]
    Auto,
    /// Exactly this many bytes: a power of two, at least the sector size.
    Bytes(u32),
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
    /// The allocation unit is not a power of two, or is smaller than a sector.
    #[error(
        "cluster size {bytes_per_cluster} bytes is not a power of two at least as large as \
         the {bytes_per_sector}-byte sector"
    )]
    #[non_exhaustive]
    ClusterSizeUnsupported {
        /// The size requested, in bytes.
        bytes_per_cluster: u32,
        /// The sector size it was requested against.
        bytes_per_sector: u32,
    },
    /// The allocation unit exceeds what the format's two shifts can express.
    #[error("cluster size {bytes_per_cluster} bytes exceeds the {limit}-byte maximum")]
    #[non_exhaustive]
    ClusterTooLarge {
        /// The size requested, in bytes.
        bytes_per_cluster: u32,
        /// [`MAX_BYTES_PER_CLUSTER`].
        limit: u32,
    },
    /// The alignment boundary is not a power of two, or is smaller than a sector.
    #[error(
        "boundary alignment {bytes} is not a power of two at least as large as the \
         {bytes_per_sector}-byte sector"
    )]
    #[non_exhaustive]
    BoundaryAlignUnsupported {
        /// The alignment requested, in bytes.
        bytes: u32,
        /// The sector size it was requested against.
        bytes_per_sector: u32,
    },
    /// The volume is too small to hold a filesystem at all.
    #[error("a volume of {sectors} sectors is below the {minimum}-sector minimum")]
    #[non_exhaustive]
    VolumeTooSmall {
        /// Sectors the volume spans.
        sectors: u64,
        /// [`MIN_VOLUME_SECTORS`].
        minimum: u64,
    },
    /// The regions ahead of the cluster heap leave no room for the heap.
    ///
    /// Reached by an alignment large enough to push the heap past the end of the volume, and
    /// by a cluster small enough that its allocation table is most of the volume.
    #[error(
        "the allocation table and the alignment leave no cluster heap: the heap would begin \
         at byte {heap_at} of a {volume_bytes}-byte volume"
    )]
    #[non_exhaustive]
    NoClusterHeap {
        /// Where the heap would have begun, in bytes from the volume's start.
        heap_at: u64,
        /// Bytes the volume spans.
        volume_bytes: u64,
    },
    /// The cluster is small enough that the volume holds more clusters than a 32-bit number
    /// addresses.
    #[error("{clusters} clusters exceeds the {limit} a cluster number can address")]
    #[non_exhaustive]
    TooManyClusters {
        /// Clusters the heap would have held.
        clusters: u64,
        /// [`MAX_CLUSTER_COUNT`].
        limit: u32,
    },
    /// The heap is too small to hold the three residents a format writes: the allocation
    /// bitmap, the up-case table, and the root directory.
    #[error(
        "a heap of {clusters} clusters cannot hold the allocation bitmap, the up-case table \
         and the root directory, which need {needed}"
    )]
    #[non_exhaustive]
    HeapTooSmall {
        /// Clusters the heap holds.
        clusters: u32,
        /// Clusters the three residents need.
        needed: u32,
    },
}

/// A complete, materializable exFAT layout.
///
/// Every field is a decision a materializer obeys rather than recomputes. [`plan_layout`] is
/// how one is obtained from a size, and `layout_from_boot` how one is recovered from a
/// volume; the fields are not independent — the table's length follows from the cluster
/// count, the cluster count from the room the table left, and where each resident sits from
/// the cluster size — so a set of them assembled by hand can satisfy every type here while
/// describing a volume no driver reads. Deriving them is what makes them consistent, so it
/// is the constructor; the fields stay public because reading them is exactly what a
/// materializer, a reader, and a caller inspecting a plan all do.
///
/// Sector counts are counted from the volume's own start, not from the medium's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ExfatLayout {
    /// Bytes per sector: 512, 1024, 2048, or 4096.
    pub bytes_per_sector: u32,
    /// Bytes per cluster, a power of two at least as large as a sector.
    pub bytes_per_cluster: u32,
    /// Sectors the volume spans, the two boot regions included. This is the whole volume
    /// rather than the part the filesystem uses, and it is what the boot sector records.
    pub volume_length: u64,
    /// The first sector of the allocation table.
    pub fat_offset: u32,
    /// Sectors in the allocation table. It has an entry for every cluster and for the two
    /// reserved numbers ahead of them, rounded up to whole sectors.
    pub fat_length: u32,
    /// The first sector of the cluster heap, which is where cluster [`FIRST_CLUSTER`]
    /// begins.
    pub cluster_heap_offset: u32,
    /// Clusters in the heap.
    pub cluster_count: u32,
    /// The first cluster of the root directory's chain.
    pub first_cluster_of_root: u32,
    /// The allocation bitmap's first cluster, which is always [`FIRST_CLUSTER`] — the bitmap
    /// is the first thing a format puts in the heap.
    pub bitmap_cluster: u32,
    /// Bytes the allocation bitmap occupies: one bit per cluster, rounded up to whole bytes.
    /// The clusters it takes up are its own bits like any other.
    pub bitmap_bytes: u64,
    /// The up-case table's first cluster, immediately behind the bitmap.
    pub upcase_cluster: u32,
    /// Bytes the up-case table occupies. It does not vary with the geometry, so how many
    /// clusters it takes is a property of the cluster size — which is what moves the root
    /// directory's number between two volumes of different shapes.
    pub upcase_bytes: u64,
}

impl ExfatLayout {
    /// Sectors per cluster.
    #[must_use]
    pub const fn sectors_per_cluster(&self) -> u32 {
        self.bytes_per_cluster / self.bytes_per_sector
    }

    /// The base-2 logarithm of the sector size, which is what the boot sector records.
    #[must_use]
    pub const fn bytes_per_sector_shift(&self) -> u8 {
        self.bytes_per_sector.trailing_zeros() as u8
    }

    /// The base-2 logarithm of the cluster size in sectors, which is what the boot sector
    /// records.
    #[must_use]
    pub const fn sectors_per_cluster_shift(&self) -> u8 {
        self.sectors_per_cluster().trailing_zeros() as u8
    }

    /// Bytes the volume spans.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.volume_length * self.bytes_per_sector as u64
    }

    /// The first sector of boot region `which` — zero for the main region, one for its
    /// backup — or `None` for any other index, there being exactly two.
    #[must_use]
    pub const fn boot_region_sector(&self, which: u32) -> Option<u64> {
        match which {
            0 => Some(0),
            1 => Some(BOOT_REGION_SECTORS),
            _ => None,
        }
    }

    /// The first sector of cluster `n`, or `None` where `n` is not a cluster this volume
    /// has. Clusters number from [`FIRST_CLUSTER`].
    #[must_use]
    pub const fn cluster_start_sector(&self, n: u32) -> Option<u64> {
        if n < FIRST_CLUSTER || n - FIRST_CLUSTER >= self.cluster_count {
            return None;
        }
        Some(
            self.cluster_heap_offset as u64
                + (n - FIRST_CLUSTER) as u64 * self.sectors_per_cluster() as u64,
        )
    }

    /// Where cluster `n` begins, in bytes from the volume's start, or `None` where `n` is
    /// not a cluster this volume has.
    #[must_use]
    pub const fn cluster_start_byte(&self, n: u32) -> Option<u64> {
        match self.cluster_start_sector(n) {
            Some(sector) => Some(sector * self.bytes_per_sector as u64),
            None => None,
        }
    }

    /// Where cluster `n`'s allocation table entry begins, in bytes from the volume's start,
    /// or `None` where the table has no entry at that number.
    ///
    /// The table's first two entries belong to the reserved numbers 0 and 1, so an entry
    /// exists for every number from zero up to the last cluster — which is one more than the
    /// count, the numbering starting at [`FIRST_CLUSTER`].
    #[must_use]
    pub const fn fat_entry_byte(&self, n: u32) -> Option<u64> {
        if n as u64 >= FIRST_CLUSTER as u64 + self.cluster_count as u64 {
            return None;
        }
        Some(self.fat_offset as u64 * self.bytes_per_sector as u64 + n as u64 * 4)
    }

    /// How many clusters a run of `bytes` occupies.
    #[must_use]
    pub const fn clusters_for(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.bytes_per_cluster as u64)
    }

    /// Bytes the cluster heap holds, which is what bounds every stream on the volume.
    ///
    /// exFAT has no holes: a stream's bytes are its allocation, so a length past this is a
    /// length no allocation could hold. That makes it the bound a reader holds a declared
    /// `DataLength` to, and it is a bound a conformant volume satisfies by construction —
    /// the whole heap is the most anything in it could occupy.
    #[must_use]
    pub const fn heap_bytes(&self) -> u64 {
        self.cluster_count as u64 * self.bytes_per_cluster as u64
    }
}

/// What to plan.
///
/// Every input is a field rather than a parameter, so a knob the planner grows arrives as a
/// field a caller may ignore.
///
/// ```
/// # use ferrosys::exfat::{ClusterSize, PlanRequest, plan_layout};
/// // A 512 MiB volume, formatted the way convention formats one.
/// let layout = plan_layout(&PlanRequest::new(512 << 20))?;
/// assert_eq!(layout.bytes_per_sector, 512);
/// assert_eq!(layout.bytes_per_cluster, 32 << 10);
///
/// // The same volume with the allocation unit pinned, which moves everything behind it.
/// let small = plan_layout(&PlanRequest::new(512 << 20).cluster_size(ClusterSize::Bytes(512)))?;
/// assert_eq!(small.cluster_count, 1_038_336);
/// assert!(small.cluster_count > layout.cluster_count);
/// # Ok::<(), ferrosys::exfat::GeometryError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PlanRequest {
    /// The volume's size in bytes. A size that is not a whole number of sectors is rounded
    /// down, since a partial sector is not addressable.
    pub volume_bytes: u64,
    /// Bytes per logical sector: 512, 1024, 2048, or 4096. Defaults to 512.
    pub bytes_per_sector: u32,
    /// The allocation unit. Defaults to [`ClusterSize::Auto`].
    pub cluster_size: ClusterSize,
    /// The boundary the allocation table and the cluster heap begin on. Defaults to
    /// [`BoundaryAlign::Auto`].
    pub boundary_align: BoundaryAlign,
}

impl PlanRequest {
    /// A request for a volume of `volume_bytes`, with every knob at the value convention
    /// selects for a volume that size.
    #[must_use]
    pub const fn new(volume_bytes: u64) -> Self {
        Self {
            volume_bytes,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Auto,
            boundary_align: BoundaryAlign::Auto,
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
        self.cluster_size = size;
        self
    }

    /// This request with the alignment boundary replaced.
    #[must_use]
    pub const fn boundary_align(mut self, align: BoundaryAlign) -> Self {
        self.boundary_align = align;
        self
    }
}

/// The allocation unit convention selects for a volume of `volume_bytes`.
///
/// The table is keyed on the volume's size alone and is what every current formatter writes,
/// so a volume planned at the default is one a person comparing against another tool
/// recognizes. Pinning [`ClusterSize::Bytes`] leaves the table unconsulted.
#[must_use]
pub const fn conventional_cluster_size(volume_bytes: u64) -> u32 {
    if volume_bytes < 7 << 20 {
        512
    } else if volume_bytes <= 256 << 20 {
        4 << 10
    } else if volume_bytes <= 32 << 30 {
        32 << 10
    } else {
        128 << 10
    }
}

/// Plan an exFAT layout for `request`.
///
/// The result is complete: every field the boot sector records, and where each of the three
/// residents a format writes lands in the heap.
///
/// # Errors
///
/// [`GeometryError::SectorSizeUnsupported`], [`GeometryError::ClusterSizeUnsupported`], or
/// [`GeometryError::BoundaryAlignUnsupported`] where an input is not one the format defines;
/// [`GeometryError::ClusterTooLarge`] where the allocation unit exceeds what the two shifts
/// express; [`GeometryError::VolumeTooSmall`], [`GeometryError::NoClusterHeap`],
/// [`GeometryError::TooManyClusters`], or [`GeometryError::HeapTooSmall`] where the volume
/// and the unit do not fit each other.
pub fn plan_layout(request: &PlanRequest) -> Result<ExfatLayout, GeometryError> {
    let bytes_per_sector = request.bytes_per_sector;
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(GeometryError::SectorSizeUnsupported { bytes_per_sector });
    }
    let sector = u64::from(bytes_per_sector);

    // A partial sector is not addressable, so the volume is what its whole sectors span.
    let volume_length = request.volume_bytes / sector;
    if volume_length < MIN_VOLUME_SECTORS {
        return Err(GeometryError::VolumeTooSmall {
            sectors: volume_length,
            minimum: MIN_VOLUME_SECTORS,
        });
    }
    let volume_bytes = volume_length * sector;

    let bytes_per_cluster = match request.cluster_size {
        ClusterSize::Auto => conventional_cluster_size(volume_bytes),
        ClusterSize::Bytes(bytes) => bytes,
    };
    if !bytes_per_cluster.is_power_of_two() || bytes_per_cluster < bytes_per_sector {
        return Err(GeometryError::ClusterSizeUnsupported {
            bytes_per_cluster,
            bytes_per_sector,
        });
    }
    if bytes_per_cluster > MAX_BYTES_PER_CLUSTER {
        return Err(GeometryError::ClusterTooLarge {
            bytes_per_cluster,
            limit: MAX_BYTES_PER_CLUSTER,
        });
    }
    let cluster = u64::from(bytes_per_cluster);

    let align = match request.boundary_align {
        BoundaryAlign::Auto => DEFAULT_BOUNDARY_ALIGN,
        BoundaryAlign::Bytes(bytes) => bytes,
    };
    if !align.is_power_of_two() || align < bytes_per_sector {
        return Err(GeometryError::BoundaryAlignUnsupported {
            bytes: align,
            bytes_per_sector,
        });
    }
    let align = u64::from(align);

    // The allocation table begins at the first boundary past the two boot regions. Aligning
    // a byte quantity rather than a sector count is what puts the table one mebibyte in
    // whether a sector is 512 bytes or 4096.
    let fat_at = round_up(RESERVED_SECTORS * sector, align);

    // The bound that breaks the circularity: charge every cluster for its own four-byte
    // table entry before any table has been sized, and see how many the space behind the
    // table's start could hold. It is never low, so the table sized from it is never short;
    // it can be high by an entry or two, which costs a sector at most.
    let Some(for_table_and_heap) = volume_bytes.checked_sub(fat_at + TABLE_TAIL) else {
        return Err(GeometryError::NoClusterHeap {
            heap_at: fat_at,
            volume_bytes,
        });
    };
    let max_clusters = for_table_and_heap / (cluster + 4) + 1;
    let fat_bytes = round_up((max_clusters + 2) * 4, sector);
    let fat_length =
        u32::try_from(fat_bytes / sector).map_err(|_| GeometryError::TooManyClusters {
            clusters: max_clusters,
            limit: MAX_CLUSTER_COUNT,
        })?;

    // The heap begins at the first boundary past the table, so the space between the two is
    // padding no cluster addresses.
    let heap_at = round_up(fat_at + fat_bytes, align);
    if heap_at >= volume_bytes {
        return Err(GeometryError::NoClusterHeap {
            heap_at,
            volume_bytes,
        });
    }
    let clusters = (volume_bytes - heap_at) / cluster;
    if clusters > u64::from(MAX_CLUSTER_COUNT) {
        return Err(GeometryError::TooManyClusters {
            clusters,
            limit: MAX_CLUSTER_COUNT,
        });
    }
    // Bounded above by MAX_CLUSTER_COUNT immediately above, so the conversion cannot lose a
    // value.
    let cluster_count = clusters as u32;

    // The three residents, laid down in the order every implementation writes them: the
    // bitmap first, the up-case table behind it, and the root directory behind that. Each
    // starts on a cluster boundary, so what the one before it occupies is rounded up.
    let bitmap_bytes = u64::from(cluster_count).div_ceil(8);
    let bitmap_clusters = bitmap_bytes.div_ceil(cluster);
    let upcase_bytes = RECOMMENDED_UPCASE_BYTES;
    let upcase_clusters = upcase_bytes.div_ceil(cluster);
    let residents = bitmap_clusters + upcase_clusters + 1;
    if residents > u64::from(cluster_count) {
        return Err(GeometryError::HeapTooSmall {
            clusters: cluster_count,
            // Bounded by the comparison itself: a value larger than a cluster count that
            // fits in 32 bits is at most one greater, so it fits too.
            needed: residents.min(u64::from(u32::MAX)) as u32,
        });
    }
    let bitmap_cluster = FIRST_CLUSTER;
    // Every addend is bounded by `residents`, which the check above holds below the cluster
    // count, so none of these sums can leave 32 bits.
    let upcase_cluster = bitmap_cluster + bitmap_clusters as u32;
    let first_cluster_of_root = upcase_cluster + upcase_clusters as u32;

    Ok(ExfatLayout {
        bytes_per_sector,
        bytes_per_cluster,
        volume_length,
        // Both are byte offsets rounded to the alignment, which is at least a sector, and
        // both are below `volume_bytes`, which the checks above establish. A volume whose
        // sector count exceeds 32 bits therefore cannot reach here with either past it.
        fat_offset: sectors_of(fat_at, sector),
        fat_length,
        cluster_heap_offset: sectors_of(heap_at, sector),
        cluster_count,
        first_cluster_of_root,
        bitmap_cluster,
        bitmap_bytes,
        upcase_cluster,
        upcase_bytes,
    })
}

/// The bytes the cluster-count bound subtracts before dividing: the two entries every
/// allocation table reserves, less one, so that the division rounds the way the derivation
/// needs.
///
/// It is a constant of the arithmetic rather than a region of the volume — the two reserved
/// entries are added back when the table is sized — and it is named so the subtraction below
/// is not a literal nine.
const TABLE_TAIL: u64 = 4 * 2 + 1;

/// Round `value` up to a multiple of `to`, which must be a power of two.
const fn round_up(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

/// `bytes` as a sector count, saturating at what the field holds.
///
/// The saturation is unreachable from [`plan_layout`], which establishes that every offset
/// it converts is below a volume length that fits in the field. It is here rather than as an
/// assertion because a saturated offset is a wrong number a later check can catch, and a
/// panic in a planner is not.
const fn sectors_of(bytes: u64, sector: u64) -> u32 {
    let sectors = bytes / sector;
    if sectors > u32::MAX as u64 {
        u32::MAX
    } else {
        sectors as u32
    }
}

/// A boot sector that does not describe an exFAT volume, and what about it does not.
///
/// This is the refusal reason a classifier discards and a reader keeps. Detection needs only
/// a yes or a no; a reader that answers "not exFAT" for a volume that plainly is one owes an
/// account of why.
/// The three fixed values that say a sector is meant to be one of these at all — the
/// magic, the 53 zero bytes beside it, and the boot signature — are not here, because
/// [`MainBootSector::read_from`] has already refused a sector missing any of them. What
/// remains is every way a sector that passed those can still fail to describe a volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BootDefect {
    /// The volume records a major revision of the format other than
    /// [`FILE_SYSTEM_MAJOR_REVISION`].
    ///
    /// The format states this as a `shall`: an implementation mounts major revision 1 and no
    /// other. A major revision is how the format says the structures behind the boot sector
    /// are not the ones a reader knows, so nothing past this field can be claimed — which is
    /// why it is judged ahead of every geometry field rather than beside them.
    #[error("a volume of revision {major}.{minor} is not one this reads; the format defines 1")]
    #[non_exhaustive]
    FileSystemRevision {
        /// The major revision found on disk.
        major: u8,
        /// The minor revision found on disk.
        minor: u8,
    },
    /// The sector shift is outside the 9 through 12 the format defines.
    #[error("sector size shift {shift} is outside the 9 to 12 the format defines")]
    #[non_exhaustive]
    SectorShift {
        /// The shift found on disk.
        shift: u8,
    },
    /// The two shifts together exceed what the format allows, which caps a cluster at 32
    /// mebibytes.
    #[error(
        "sector shift {sector_shift} and cluster shift {cluster_shift} sum past the \
         {limit} the format allows"
    )]
    #[non_exhaustive]
    ClusterShift {
        /// The sector shift found on disk.
        sector_shift: u8,
        /// The cluster shift found on disk.
        cluster_shift: u8,
        /// [`MAX_CLUSTER_SHIFT`].
        limit: u8,
    },
    /// The volume records a length of fewer sectors than a filesystem needs, or more than
    /// the source holds.
    #[error("a volume of {sectors} sectors does not fit: {why}")]
    #[non_exhaustive]
    VolumeLength {
        /// The length found on disk, in sectors.
        sectors: u64,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A region begins or ends outside the volume, or two regions overlap.
    #[error("{region} does not fit within the volume: {why}")]
    #[non_exhaustive]
    RegionOutsideVolume {
        /// The region at fault.
        region: &'static str,
        /// What is wrong with it.
        why: &'static str,
    },
    /// The allocation table is too short to hold an entry for every cluster the volume
    /// claims.
    #[error(
        "an allocation table of {table_bytes} bytes cannot hold entries for {cluster_count} \
         clusters and the two reserved numbers"
    )]
    #[non_exhaustive]
    TableTooShort {
        /// Bytes the table spans.
        table_bytes: u64,
        /// Clusters the volume claims.
        cluster_count: u32,
    },
    /// The root directory's first cluster is not a cluster the volume has.
    #[error("the root directory begins at cluster {cluster}, which the volume does not have")]
    #[non_exhaustive]
    RootOutsideHeap {
        /// The cluster number found on disk.
        cluster: u32,
    },
}

/// Recover a layout from a volume's Main Boot Sector, checking it against itself.
///
/// This is the crate's single definition of "these bytes are an exFAT volume", and it is
/// what both the classifier and the reader go through. `available` is how many bytes the
/// source holds from the volume's start, which is what makes "the volume fits" answerable: a
/// volume may be smaller than the region it sits in — a partition is usually larger than its
/// filesystem — so the test is that the recorded length fits, not that it matches.
///
/// The three residents are not recovered, because nothing in the boot sector records where
/// they are: the allocation bitmap and the up-case table are found by reading the root
/// directory. So the fields describing them are filled with what a conformant volume must
/// have — the bitmap at [`FIRST_CLUSTER`], sized one bit per cluster — and a reader replaces
/// them with what the directory actually says.
///
/// # Errors
///
/// [`BootDefect`], naming which of the sector's fields does not agree with the others.
pub(crate) fn layout_from_boot(
    boot: &MainBootSector,
    available: u64,
) -> Result<ExfatLayout, BootDefect> {
    // Asked first, and of the major half alone. Every field below is a field of *this*
    // revision's boot sector, so a volume claiming another has not agreed to be read that
    // far; a minor revision above zero is a volume this reader is asked to honour, and the
    // reader remarks on it rather than refusing.
    if boot.major_revision() != FILE_SYSTEM_MAJOR_REVISION {
        return Err(BootDefect::FileSystemRevision {
            major: boot.major_revision(),
            minor: boot.minor_revision(),
        });
    }
    let Some(bytes_per_sector) = boot.bytes_per_sector() else {
        return Err(BootDefect::SectorShift {
            shift: boot.bytes_per_sector_shift,
        });
    };
    let Some(bytes_per_cluster) = boot.bytes_per_cluster() else {
        return Err(BootDefect::ClusterShift {
            sector_shift: boot.bytes_per_sector_shift,
            cluster_shift: boot.sectors_per_cluster_shift,
            limit: MAX_CLUSTER_SHIFT,
        });
    };
    let sector = u64::from(bytes_per_sector);

    let volume_length = boot.volume_length;
    if volume_length < MIN_VOLUME_SECTORS {
        return Err(BootDefect::VolumeLength {
            sectors: volume_length,
            why: "fewer sectors than two boot regions and a filesystem need",
        });
    }
    let Some(volume_bytes) = volume_length.checked_mul(sector) else {
        return Err(BootDefect::VolumeLength {
            sectors: volume_length,
            why: "the length in bytes does not fit in 64 bits",
        });
    };
    if volume_bytes > available {
        return Err(BootDefect::VolumeLength {
            sectors: volume_length,
            why: "the source does not hold that many",
        });
    }

    // Every region, in order, each held to beginning behind the one before it and ending
    // within the volume. Computed in bytes because the products are what overflow.
    let fat_at = u64::from(boot.fat_offset) * sector;
    let fat_bytes = u64::from(boot.fat_length) * sector;
    if fat_at < RESERVED_SECTORS * sector {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the allocation table",
            why: "it begins inside the boot regions",
        });
    }
    let heap_at = u64::from(boot.cluster_heap_offset) * sector;
    let Some(fat_end) = fat_at.checked_add(fat_bytes) else {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the allocation table",
            why: "its end does not fit in 64 bits",
        });
    };
    if fat_end > heap_at {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the allocation table",
            why: "it runs into the cluster heap",
        });
    }
    if heap_at >= volume_bytes {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the cluster heap",
            why: "it begins at or past the end of the volume",
        });
    }

    let cluster_count = boot.cluster_count;
    if cluster_count > MAX_CLUSTER_COUNT {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the cluster heap",
            why: "it claims more clusters than a cluster number addresses",
        });
    }
    let heap_bytes = u64::from(cluster_count) * u64::from(bytes_per_cluster);
    if heap_bytes > volume_bytes - heap_at {
        return Err(BootDefect::RegionOutsideVolume {
            region: "the cluster heap",
            why: "its clusters run past the end of the volume",
        });
    }
    // One entry per cluster plus the two reserved numbers ahead of them. A table shorter
    // than that has no entry for the volume's last clusters, so a chain reaching one would
    // be resolved out of whatever follows the table.
    if fat_bytes / 4 < u64::from(cluster_count) + u64::from(FIRST_CLUSTER) {
        return Err(BootDefect::TableTooShort {
            table_bytes: fat_bytes,
            cluster_count,
        });
    }

    let root = boot.first_cluster_of_root;
    if root < FIRST_CLUSTER || u64::from(root - FIRST_CLUSTER) >= u64::from(cluster_count) {
        return Err(BootDefect::RootOutsideHeap { cluster: root });
    }

    Ok(ExfatLayout {
        bytes_per_sector,
        bytes_per_cluster,
        volume_length,
        fat_offset: boot.fat_offset,
        fat_length: boot.fat_length,
        cluster_heap_offset: boot.cluster_heap_offset,
        cluster_count,
        first_cluster_of_root: root,
        bitmap_cluster: FIRST_CLUSTER,
        bitmap_bytes: u64::from(cluster_count).div_ceil(8),
        upcase_cluster: FIRST_CLUSTER,
        upcase_bytes: RECOMMENDED_UPCASE_BYTES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of the oracle tier's matrix and what the pinned baseline makes of it, so the
    /// arithmetic here is held to a foreign implementation's answer without a foreign
    /// implementation having to be installed.
    ///
    /// The oracle tier reads these off `mkfs.exfat` itself; what is written down here is the
    /// *recorded* answer, and the two are held together by that tier failing when the
    /// baseline stops producing them. That is what makes this a unit test of the arithmetic
    /// rather than a second recording.
    struct Row {
        /// Why the matrix has this row, in the tier's own words.
        what: &'static str,
        volume_bytes: u64,
        bytes_per_sector: u32,
        cluster_size: ClusterSize,
        fat_offset: u32,
        fat_length: u32,
        cluster_heap_offset: u32,
        cluster_count: u32,
        first_cluster_of_root: u32,
        bitmap_bytes: u64,
        upcase_cluster: u32,
    }

    impl Row {
        /// What this crate is told, to reach the volume the baseline was told to build.
        fn request(&self) -> PlanRequest {
            PlanRequest::new(self.volume_bytes)
                .bytes_per_sector(self.bytes_per_sector)
                .cluster_size(self.cluster_size)
        }
    }

    const BASELINE: &[Row] = &[
        Row {
            what: "the lowest cluster band, where the up-case table spans twelve clusters",
            volume_bytes: 4 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Auto,
            fat_offset: 2048,
            fat_length: 48,
            cluster_heap_offset: 4096,
            cluster_count: 4096,
            first_cluster_of_root: 15,
            bitmap_bytes: 512,
            upcase_cluster: 3,
        },
        Row {
            what: "the lowest band again, where the bitmap needs a second cluster",
            volume_bytes: 6 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Auto,
            fat_offset: 2048,
            fat_length: 80,
            cluster_heap_offset: 4096,
            cluster_count: 8192,
            first_cluster_of_root: 16,
            bitmap_bytes: 1024,
            upcase_cluster: 4,
        },
        Row {
            what: "the smallest volume, at whatever cluster the baseline picks",
            volume_bytes: 32 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Auto,
            fat_offset: 2048,
            fat_length: 62,
            cluster_heap_offset: 4096,
            cluster_count: 7680,
            first_cluster_of_root: 5,
            bitmap_bytes: 960,
            upcase_cluster: 3,
        },
        Row {
            what: "four-kilobyte clusters, where the up-case table spans two of them",
            volume_bytes: 64 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Bytes(4 << 10),
            fat_offset: 2048,
            fat_length: 126,
            cluster_heap_offset: 4096,
            cluster_count: 15872,
            first_cluster_of_root: 5,
            bitmap_bytes: 1984,
            upcase_cluster: 3,
        },
        Row {
            what: "thirty-two-kilobyte clusters, where it fits in one",
            volume_bytes: 512 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Bytes(32 << 10),
            fat_offset: 2048,
            fat_length: 128,
            cluster_heap_offset: 4096,
            cluster_count: 16320,
            first_cluster_of_root: 4,
            bitmap_bytes: 2040,
            upcase_cluster: 3,
        },
        Row {
            what: "a sector size that is not five hundred and twelve",
            volume_bytes: 64 << 20,
            bytes_per_sector: 4096,
            cluster_size: ClusterSize::Auto,
            fat_offset: 256,
            fat_length: 16,
            cluster_heap_offset: 512,
            cluster_count: 15872,
            first_cluster_of_root: 5,
            bitmap_bytes: 1984,
            upcase_cluster: 3,
        },
        Row {
            what: "a million clusters, so the allocation bitmap spans many of them",
            volume_bytes: 512 << 20,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Bytes(512),
            fat_offset: 2048,
            fat_length: 8113,
            cluster_heap_offset: 10240,
            cluster_count: 1_038_336,
            first_cluster_of_root: 268,
            bitmap_bytes: 129_792,
            upcase_cluster: 256,
        },
        Row {
            what: "a volume whose byte offsets pass four gigabytes",
            volume_bytes: 8 << 30,
            bytes_per_sector: 512,
            cluster_size: ClusterSize::Bytes(128 << 10),
            fat_offset: 2048,
            fat_length: 512,
            cluster_heap_offset: 4096,
            cluster_count: 65520,
            first_cluster_of_root: 4,
            bitmap_bytes: 8190,
            upcase_cluster: 3,
        },
    ];

    #[test]
    fn the_planner_derives_the_geometry_the_baseline_derives() {
        for row in BASELINE {
            let what = row.what;
            let layout = plan_layout(&row.request()).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(layout.fat_offset, row.fat_offset, "{what}: FatOffset");
            assert_eq!(layout.fat_length, row.fat_length, "{what}: FatLength");
            assert_eq!(
                layout.cluster_heap_offset, row.cluster_heap_offset,
                "{what}: ClusterHeapOffset"
            );
            assert_eq!(
                layout.cluster_count, row.cluster_count,
                "{what}: ClusterCount"
            );
            assert_eq!(
                layout.first_cluster_of_root, row.first_cluster_of_root,
                "{what}: root cluster"
            );
            assert_eq!(
                layout.bitmap_bytes, row.bitmap_bytes,
                "{what}: bitmap bytes"
            );
            assert_eq!(
                layout.upcase_cluster, row.upcase_cluster,
                "{what}: up-case cluster"
            );
            assert_eq!(
                layout.volume_length * u64::from(row.bytes_per_sector),
                row.volume_bytes,
                "{what}: length"
            );
        }
    }

    #[test]
    fn every_planned_layout_agrees_with_itself() {
        // The relations a materializer and a driver both depend on, over a wide sweep rather
        // than over the baseline's six rows: no region overlaps the next, the table has an
        // entry for every cluster, the heap's clusters fit inside the volume, and the three
        // residents fit inside the heap.
        for bytes in [
            8u64 << 20,
            32 << 20,
            100 << 20,
            512 << 20,
            3 << 30,
            64 << 30,
        ] {
            for sector in [512u32, 1024, 2048, 4096] {
                for cluster in [
                    ClusterSize::Auto,
                    ClusterSize::Bytes(4 << 10),
                    ClusterSize::Bytes(64 << 10),
                    ClusterSize::Bytes(1 << 20),
                ] {
                    let request = PlanRequest::new(bytes)
                        .bytes_per_sector(sector)
                        .cluster_size(cluster);
                    let Ok(layout) = plan_layout(&request) else {
                        continue;
                    };
                    let what = format!("{bytes} bytes, {sector}-byte sectors, {cluster:?}");
                    let sector = u64::from(sector);

                    let fat_at = u64::from(layout.fat_offset) * sector;
                    let fat_end = fat_at + u64::from(layout.fat_length) * sector;
                    let heap_at = u64::from(layout.cluster_heap_offset) * sector;
                    assert!(
                        fat_at >= RESERVED_SECTORS * sector,
                        "{what}: table over boot"
                    );
                    assert!(fat_end <= heap_at, "{what}: table over heap");

                    let heap_end = heap_at
                        + u64::from(layout.cluster_count) * u64::from(layout.bytes_per_cluster);
                    assert!(heap_end <= layout.total_bytes(), "{what}: heap over volume");

                    assert!(
                        u64::from(layout.fat_length) * sector / 4
                            >= u64::from(layout.cluster_count) + u64::from(FIRST_CLUSTER),
                        "{what}: table too short for its clusters"
                    );
                    assert_eq!(
                        layout.bitmap_bytes,
                        u64::from(layout.cluster_count).div_ceil(8),
                        "{what}: bitmap is one bit per cluster"
                    );

                    // The residents, in the order they are written, each behind the one
                    // before it and all inside the heap.
                    assert_eq!(layout.bitmap_cluster, FIRST_CLUSTER, "{what}");
                    assert_eq!(
                        layout.upcase_cluster,
                        layout.bitmap_cluster + layout.clusters_for(layout.bitmap_bytes) as u32,
                        "{what}: up-case table behind the bitmap"
                    );
                    assert_eq!(
                        layout.first_cluster_of_root,
                        layout.upcase_cluster + layout.clusters_for(layout.upcase_bytes) as u32,
                        "{what}: root behind the up-case table"
                    );
                    assert!(
                        layout
                            .cluster_start_sector(layout.first_cluster_of_root)
                            .is_some(),
                        "{what}: root inside the heap"
                    );
                }
            }
        }
    }

    #[test]
    fn a_planned_layout_is_one_a_boot_sector_round_trips() {
        // The two derivations held against each other, which is what makes them one: a
        // layout written into a boot sector and recovered from it is the layout that was
        // planned. A classifier that disagreed with the planner would claim volumes this
        // crate writes and cannot read, or the reverse.
        for row in BASELINE {
            let what = row.what;
            let planned = plan_layout(&row.request()).expect("plan");
            let boot = boot_for(&planned);
            let recovered =
                layout_from_boot(&boot, row.volume_bytes).unwrap_or_else(|e| panic!("{what}: {e}"));

            // Every field the boot sector records. The residents are not among them — the
            // root directory is what says where those are — so they are compared where the
            // format puts them and not where the planner did.
            assert_eq!(
                recovered.bytes_per_sector, planned.bytes_per_sector,
                "{what}"
            );
            assert_eq!(
                recovered.bytes_per_cluster, planned.bytes_per_cluster,
                "{what}"
            );
            assert_eq!(recovered.volume_length, planned.volume_length, "{what}");
            assert_eq!(recovered.fat_offset, planned.fat_offset, "{what}");
            assert_eq!(recovered.fat_length, planned.fat_length, "{what}");
            assert_eq!(
                recovered.cluster_heap_offset, planned.cluster_heap_offset,
                "{what}"
            );
            assert_eq!(recovered.cluster_count, planned.cluster_count, "{what}");
            assert_eq!(
                recovered.first_cluster_of_root, planned.first_cluster_of_root,
                "{what}"
            );
            assert_eq!(recovered.bitmap_bytes, planned.bitmap_bytes, "{what}");
        }
    }

    /// A boot sector carrying `layout`, which is what a materializer writes and the only way
    /// to get one whose fields agree with each other.
    fn boot_for(layout: &ExfatLayout) -> MainBootSector {
        MainBootSector {
            jump_boot: MainBootSector::JUMP_BOOT,
            file_system_name: super::super::ondisk::FILE_SYSTEM_NAME,
            partition_offset: 0,
            volume_length: layout.volume_length,
            fat_offset: layout.fat_offset,
            fat_length: layout.fat_length,
            cluster_heap_offset: layout.cluster_heap_offset,
            cluster_count: layout.cluster_count,
            first_cluster_of_root: layout.first_cluster_of_root,
            volume_serial: 0x1234_5678,
            file_system_revision: super::super::ondisk::FILE_SYSTEM_REVISION,
            volume_flags: 0,
            bytes_per_sector_shift: layout.bytes_per_sector_shift(),
            sectors_per_cluster_shift: layout.sectors_per_cluster_shift(),
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 0,
            boot_code: [0; 390],
        }
    }

    #[test]
    fn the_conventional_cluster_size_is_keyed_on_the_volume_alone() {
        // Each band and both sides of each boundary, since an off-by-one here is a different
        // geometry rather than a slower one.
        for (bytes, want) in [
            (1u64 << 20, 512u32),
            ((7 << 20) - 1, 512),
            (7 << 20, 4 << 10),
            (256 << 20, 4 << 10),
            ((256 << 20) + 1, 32 << 10),
            (32 << 30, 32 << 10),
            ((32 << 30) + 1, 128 << 10),
            (1 << 40, 128 << 10),
        ] {
            assert_eq!(conventional_cluster_size(bytes), want, "{bytes} bytes");
        }
    }

    #[test]
    fn an_input_the_format_does_not_define_is_refused_by_name() {
        let ok = PlanRequest::new(64 << 20);
        assert!(plan_layout(&ok).is_ok());

        assert!(matches!(
            plan_layout(&ok.bytes_per_sector(768)),
            Err(GeometryError::SectorSizeUnsupported {
                bytes_per_sector: 768
            })
        ));
        // A cluster smaller than a sector, and one that is not a power of two.
        assert!(matches!(
            plan_layout(
                &ok.bytes_per_sector(4096)
                    .cluster_size(ClusterSize::Bytes(512))
            ),
            Err(GeometryError::ClusterSizeUnsupported { .. })
        ));
        assert!(matches!(
            plan_layout(&ok.cluster_size(ClusterSize::Bytes(3072))),
            Err(GeometryError::ClusterSizeUnsupported { .. })
        ));
        assert!(matches!(
            plan_layout(&ok.cluster_size(ClusterSize::Bytes(64 << 20))),
            Err(GeometryError::ClusterTooLarge {
                limit: MAX_BYTES_PER_CLUSTER,
                ..
            })
        ));
        assert!(matches!(
            plan_layout(&ok.boundary_align(BoundaryAlign::Bytes(3 << 20))),
            Err(GeometryError::BoundaryAlignUnsupported { .. })
        ));
    }

    #[test]
    fn a_volume_that_cannot_hold_a_filesystem_is_refused_rather_than_planned() {
        // Below the minimum a volume has no room for two boot regions and a filesystem.
        assert!(matches!(
            plan_layout(&PlanRequest::new(512 * (MIN_VOLUME_SECTORS - 1))),
            Err(GeometryError::VolumeTooSmall { .. })
        ));

        // Above it, an alignment large enough to push the heap past the end is what runs out
        // of volume. Refusing is the whole point: a planner that returned a zero-cluster
        // heap would hand a materializer a volume to write nothing into.
        assert!(matches!(
            plan_layout(&PlanRequest::new(4 << 20).boundary_align(BoundaryAlign::Bytes(8 << 20))),
            Err(GeometryError::NoClusterHeap { .. })
        ));

        // And a heap with room for clusters but not for the three residents that have to go
        // in it. A four-mebibyte volume at a one-mebibyte cluster loses one cluster to the
        // alignment ahead of the heap and one to the two boot regions, leaving two clusters
        // for a bitmap, an up-case table, and a root directory that need three.
        let cramped =
            plan_layout(&PlanRequest::new(4 << 20).cluster_size(ClusterSize::Bytes(1 << 20)));
        assert!(
            matches!(
                cramped,
                Err(GeometryError::HeapTooSmall {
                    clusters: 2,
                    needed: 3
                })
            ),
            "expected a heap too small for its residents, got {cramped:?}"
        );

        // One cluster more is enough, which is what says the refusal above is about the
        // residents rather than about the volume being small.
        assert!(
            plan_layout(&PlanRequest::new(5 << 20).cluster_size(ClusterSize::Bytes(1 << 20)))
                .is_ok()
        );
    }

    #[test]
    fn the_alignment_is_a_byte_quantity_and_not_a_sector_count() {
        // The same boundary at two sector sizes is the same *place*, which is why the two
        // rows of the baseline that differ only in sector size have offsets that differ by
        // the ratio between them.
        let at_512 = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        let at_4096 =
            plan_layout(&PlanRequest::new(64 << 20).bytes_per_sector(4096)).expect("plan");
        assert_eq!(
            u64::from(at_512.fat_offset) * 512,
            u64::from(at_4096.fat_offset) * 4096
        );
        assert_eq!(
            u64::from(at_512.fat_offset) * 512,
            u64::from(DEFAULT_BOUNDARY_ALIGN)
        );

        // And naming a different one moves both regions to it.
        let packed =
            plan_layout(&PlanRequest::new(64 << 20).boundary_align(BoundaryAlign::Bytes(64 << 10)))
                .expect("plan");
        assert_eq!(u64::from(packed.fat_offset) * 512, 64 << 10);
        assert_eq!(u64::from(packed.cluster_heap_offset) * 512 % (64 << 10), 0);
        assert!(
            packed.cluster_count > at_512.cluster_count,
            "a tighter alignment leaves more room for clusters"
        );
    }

    #[test]
    fn a_volume_size_that_is_not_whole_sectors_is_planned_as_the_sectors_it_has() {
        // A partial sector is not addressable, so it is not part of the volume — and the
        // recorded length has to say so, or a driver reads a sector that is not there.
        let whole = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        let ragged = plan_layout(&PlanRequest::new((64 << 20) + 511)).expect("plan");
        assert_eq!(ragged.volume_length, whole.volume_length);
        assert_eq!(ragged.total_bytes(), 64 << 20);
    }

    #[test]
    fn a_boot_sector_that_does_not_agree_with_itself_is_refused_by_name() {
        let planned = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        let good = boot_for(&planned);
        let available = planned.total_bytes();
        assert!(layout_from_boot(&good, available).is_ok());

        // Each field damaged on its own, so a refusal names the field that was damaged
        // rather than the first check that happened to notice.
        let mut sector_shift = good;
        sector_shift.bytes_per_sector_shift = 13;
        assert!(matches!(
            layout_from_boot(&sector_shift, available),
            Err(BootDefect::SectorShift { shift: 13 })
        ));

        let mut cluster_shift = good;
        cluster_shift.sectors_per_cluster_shift = 20;
        assert!(matches!(
            layout_from_boot(&cluster_shift, available),
            Err(BootDefect::ClusterShift { .. })
        ));

        let mut long = good;
        long.volume_length = good.volume_length * 2;
        assert!(matches!(
            layout_from_boot(&long, available),
            Err(BootDefect::VolumeLength { .. })
        ));

        let mut short = good;
        short.volume_length = 4;
        assert!(matches!(
            layout_from_boot(&short, available),
            Err(BootDefect::VolumeLength { .. })
        ));

        let mut table_in_boot = good;
        table_in_boot.fat_offset = 4;
        assert!(matches!(
            layout_from_boot(&table_in_boot, available),
            Err(BootDefect::RegionOutsideVolume { .. })
        ));

        let mut table_over_heap = good;
        table_over_heap.fat_length = good.cluster_heap_offset;
        assert!(matches!(
            layout_from_boot(&table_over_heap, available),
            Err(BootDefect::RegionOutsideVolume { .. })
        ));

        let mut heap_past_end = good;
        heap_past_end.cluster_heap_offset = u32::try_from(good.volume_length).expect("fits");
        assert!(matches!(
            layout_from_boot(&heap_past_end, available),
            Err(BootDefect::RegionOutsideVolume { .. })
        ));

        let mut too_many = good;
        too_many.cluster_count = good.cluster_count * 4;
        assert!(matches!(
            layout_from_boot(&too_many, available),
            Err(BootDefect::RegionOutsideVolume { .. })
        ));

        // A table one entry short of the clusters the volume claims. It is the defect a
        // chain reaching the last cluster resolves out of whatever follows the table, so it
        // is refused rather than read.
        let mut short_table = good;
        short_table.fat_length = u32::try_from(
            (u64::from(good.cluster_count) + u64::from(FIRST_CLUSTER) - 1) * 4
                / u64::from(planned.bytes_per_sector),
        )
        .expect("fits");
        assert!(matches!(
            layout_from_boot(&short_table, available),
            Err(BootDefect::TableTooShort { .. })
        ));

        for cluster in [0, 1, good.cluster_count + FIRST_CLUSTER] {
            let mut root = good;
            root.first_cluster_of_root = cluster;
            assert!(
                matches!(
                    layout_from_boot(&root, available),
                    Err(BootDefect::RootOutsideHeap { .. })
                ),
                "a root at cluster {cluster} is outside the heap"
            );
        }
    }

    #[test]
    fn the_addressing_helpers_refuse_a_cluster_the_volume_does_not_have() {
        let layout = plan_layout(&PlanRequest::new(64 << 20)).expect("plan");
        let last = FIRST_CLUSTER + layout.cluster_count - 1;

        assert_eq!(
            layout.cluster_start_byte(FIRST_CLUSTER),
            Some(u64::from(layout.cluster_heap_offset) * u64::from(layout.bytes_per_sector))
        );
        assert!(layout.cluster_start_sector(last).is_some());
        assert_eq!(layout.cluster_start_sector(last + 1), None);
        assert_eq!(layout.cluster_start_sector(1), None);
        assert_eq!(layout.cluster_start_sector(0), None);

        // The table has an entry for the two reserved numbers as well as for every cluster,
        // and none past the last one.
        assert_eq!(
            layout.fat_entry_byte(0),
            Some(u64::from(layout.fat_offset) * u64::from(layout.bytes_per_sector))
        );
        assert!(layout.fat_entry_byte(last).is_some());
        assert_eq!(layout.fat_entry_byte(last + 1), None);

        assert_eq!(layout.boot_region_sector(0), Some(0));
        assert_eq!(layout.boot_region_sector(1), Some(BOOT_REGION_SECTORS));
        assert_eq!(layout.boot_region_sector(2), None);
    }
}
