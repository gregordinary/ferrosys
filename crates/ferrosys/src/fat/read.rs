//! The reader: parse a FAT volume back into a geometry, a directory tree, and file
//! contents.
//!
//! It reads volumes other tools wrote, not only the ones this crate writes. All three types
//! are followed through one implementation, because the only differences are the width of a
//! table entry and where the root directory sits; long names are reassembled from the
//! entries that carry them and tied to their short entry by checksum; and the type is
//! derived from the volume's own geometry rather than read out of the type string, which is
//! documentation that no conformant driver looks at.
//!
//! One shape the format permits is outside what this reads: a volume with more than two
//! allocation tables. The count is refused in the geometry, below the policy threshold, so
//! it is refused under [`ReadPolicy::Lenient`] as well as under `Strict` — see
//! [`GeometryError::FatCountUnsupported`](crate::fat::GeometryError::FatCountUnsupported).
//! `fsck.fat` refuses the same volume, so this is where the ecosystem sits rather than a
//! narrowness of this crate's own.
//!
//! # Robustness and strictness
//!
//! Two properties are kept apart. *Robustness* is always on: every on-disk field is
//! bounds-checked and every fallible step returns a [`ReadError`] rather than panicking or
//! reading out of range, on any input — including one built to break it.
//!
//! *Conformance strictness* is a policy: a threshold over the [`Severity`] of the
//! [`Anomaly`] a deviation carries. [`ReadPolicy::Strict`], the default, is fatal at any
//! deviation a FAT volume this crate writes would not carry, so a strict read either yields
//! the filesystem the image describes or names the deviation that stopped it.
//!
//! **A strict read accepts every volume this crate's own writer produces.** That is the line
//! the severities are drawn against, and it is what makes the two halves of the family one
//! thing rather than two: a format followed by a strict open is a round trip at every input
//! the writer accepts — every geometry a
//! [`PlanRequest`](crate::fat::PlanRequest) reaches and every value a
//! [`FormatOptions`](crate::fat::FormatOptions) carries alike, since a field the writer
//! accepts and this refuses breaks the round trip as surely as a misplaced cluster would.
//! It holds for the deliberately non-conformant geometries too: an undersized FAT32 is
//! something this crate emits on request, and so is remarked on rather than refused.
//!
//! The line runs both ways. Where a value has a set the format defines and this reader
//! enforces it — the media descriptor is the one such field — the writer refuses what falls
//! outside it, rather than emitting a volume neither end would read back.
//!
//! [`ReadPolicy::Lenient`] moves that threshold above every severity, so nothing is fatal. A
//! whole-volume [`scan`](Reader::scan) checks the parameter block, every copy of the file
//! allocation table against the first, the information sector, every directory entry, and
//! every cluster chain — including the clusters that are allocated and reached by nothing —
//! collecting each deviation as an [`Anomaly`] into a [`ScanReport`] instead of stopping at
//! the first. The report projects to JSON, SARIF, or a human table, and
//! [`ScanReport::has_fatal`] applies a policy's threshold back to what the scan found.
//!
//! # What a FAT volume does not tell you
//!
//! There is no owner, no permission bits, no second name for a file, and no field for the
//! code page an eleven-byte short name is written in. The first three are filled from the
//! caller's [`Synthesis`] on the extraction surface and named there; the fourth is
//! [`ShortNameCharset`], which defaults to interpreting nothing.
//!
//! The handle opens over any [`Read`] + [`Seek`] source at an arbitrary byte offset, so it
//! reads a volume inside a partitioned disk image as readily as a bare one.

use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::ControlFlow;

use crate::bytes::get_u16;
use crate::fidelity::Synthesis;
use crate::finding::{Family, Finding, Findings, Severity};
use crate::io::{offset_of, read_exact_at};
use crate::path::is_hostile_component;
use crate::policy::MAX_PATH;
use crate::policy::{Limits, ReadPolicy};
use crate::time::{DosTimestamp, Timestamp};
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};

use super::charset::ShortNameCharset;
use super::geometry::{
    FatLayout, FatType, MAX_CLUSTERS_FAT12, MIN_CLUSTERS_FAT16, layout_from_boot,
};
use super::ondisk::{
    Attributes as DirAttributes, BootSector, BootSectorTail, DIR_ENTRY_SIZE, DirEntry, FsInfo,
    LFN_CHARS_PER_ENTRY, LFN_LAST_ENTRY, LFN_MAX_ENTRIES, LfnEntry, NAME_DELETED, NAME_END,
    NAME_LEADING_E5, ParseError,
};
use super::table;

/// The subsystem a deviation was found in.
///
/// A FAT volume has four, and they are not ext's: there is no superblock, no group
/// descriptor, and no extent tree, and a family's own words for its own parts are the whole
/// reason a category stays with its family rather than hoisting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Category {
    /// The boot sector and its BIOS parameter block, or the backup copy of it.
    BootSector,
    /// The FAT32 information sector, or its backup.
    InfoSector,
    /// A copy of the file allocation table, or the allocation it records.
    AllocationTable,
    /// A directory, its entries, or the long names they carry.
    Directory,
}

impl Category {
    /// The lowercase name of this subsystem, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::BootSector => "boot sector",
            Category::InfoSector => "information sector",
            Category::AllocationTable => "allocation table",
            Category::Directory => "directory",
        }
    }
}

crate::naming::serialize_as_name!(Category);

/// Where in the volume a deviation sits. Every field is optional: a deviation carries only
/// the coordinates that locate it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Location {
    /// Sector number within the volume, when the deviation is sector-addressed. This is
    /// what becomes the byte offset a [`Finding`] carries.
    pub sector: Option<u32>,
    /// Cluster number, when the deviation is cluster-addressed.
    pub cluster: Option<u32>,
    /// Index of a directory entry within its directory, counting 32-byte slots from zero.
    pub entry: Option<u32>,
}

impl Location {
    /// This location with any coordinate `other` carries that this one does not.
    ///
    /// A deviation knows where it is in its own terms — a table entry knows its cluster —
    /// and the walk that met it knows the rest. Merging rather than replacing is what keeps
    /// the more specific of the two.
    fn or(self, other: Self) -> Self {
        Self {
            sector: self.sector.or(other.sector),
            cluster: self.cluster.or(other.cluster),
            entry: self.entry.or(other.entry),
        }
    }
}

/// A typed deviation from what this crate would emit, carrying its severity, the subsystem
/// it was found in, where it sits, and a human description.
///
/// This is FAT's structured value, and it stays FAT's: the subsystem is a [`Category`]
/// rather than a word, and the place is a cluster and a sector rather than a byte offset,
/// because those are what a consumer reasoning about a FAT volume acts on.
///
/// Rendering goes through [`to_finding`](Self::to_finding), which projects into the crate's
/// [`Finding`] — the frame every family shares and every renderer consumes.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    /// How serious the deviation is.
    pub severity: Severity,
    /// The subsystem it was found in.
    pub category: Category,
    /// Where it sits in the volume.
    pub location: Location,
    /// A human-readable description.
    pub detail: String,
}

impl crate::Deviation for Anomaly {
    fn severity(&self) -> Severity {
        self.severity
    }

    /// The sector size is the addressing unit a FAT location is stated in.
    fn to_finding(&self, unit: u32) -> Finding {
        Anomaly::to_finding(self, unit)
    }
}

impl Anomaly {
    /// Project this anomaly into the crate's family-agnostic [`Finding`], resolving a
    /// sector-addressed location to the byte offset that sector sits at under
    /// `bytes_per_sector`.
    ///
    /// The coordinates carry FAT's own words, outermost first — `cluster`, then `sector`,
    /// then `entry` — which is the order a person reads a location in. A cluster number is
    /// not converted to an offset, because where it sits depends on the layout rather than
    /// on the number alone, so an anomaly located only by one carries no offset.
    #[must_use]
    pub fn to_finding(&self, bytes_per_sector: u32) -> Finding {
        // Destructured exhaustively on purpose: a field added to `Anomaly` is a compile
        // error here, which forces a decision about what the projection carries rather than
        // letting a new fact about a finding go silently unreported.
        let Self {
            severity,
            category,
            location,
            detail,
        } = self;
        let Location {
            sector,
            cluster,
            entry,
        } = *location;

        crate::finding::project(
            *severity,
            Family::Fat,
            category.as_str(),
            &[
                ("cluster", cluster.map(u64::from)),
                ("sector", sector.map(u64::from)),
                ("entry", entry.map(u64::from)),
            ],
            // The sector is what addresses bytes. A cluster number does not: where it sits
            // depends on the layout rather than on the number alone.
            sector.map(u64::from),
            bytes_per_sector,
            detail,
        )
    }
}

/// A failure reading a FAT volume.
///
/// The variants divide into three kinds. A few are the source's rather than the image's
/// ([`Io`](Self::Io)) or a caller's bound being reached
/// ([`FileTooLarge`](Self::FileTooLarge), [`WalkTooLarge`](Self::WalkTooLarge)). Most are
/// deviations from what a FAT volume this crate writes carries, each of which projects to a
/// typed [`Anomaly`] through [`anomaly`](Self::anomaly) — so the same fault is an error
/// under [`ReadPolicy::Strict`] and a collected finding under a scan, described the same way
/// either time. The rest are a caller asking for something that is not there.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The underlying source could not be read or sought.
    /// Carried as [`TreeError::Io`] describes, which is where the rule
    /// this crate records an i/o failure by is written out: the kind beside the message, so a
    /// caller tells a truncated image from an environment failure without matching on text.
    #[error("i/o error: {message}")]
    #[non_exhaustive]
    Io {
        /// How the underlying [`std::io::Error`] classified itself.
        kind: std::io::ErrorKind,
        /// The error rendered as text, for a message a person reads.
        message: String,
    },
    /// An on-disk structure could not be recovered from its bytes.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The BIOS parameter block does not describe a FAT volume: a field holds a value no
    /// FAT volume carries, or the fields do not agree with each other.
    ///
    /// This is what detection answers "not ours" to. The reader names the field instead,
    /// because a caller who reached the reader has already been told the image is a FAT
    /// volume and needs to know why it is not readable as one.
    #[error("{field} = {value} is not a value a FAT volume's parameter block carries")]
    #[non_exhaustive]
    BadBootSector {
        /// The parameter block field, in the format's own spelling.
        field: &'static str,
        /// That field's value, or the number derived from it that failed.
        value: u64,
    },
    /// The volume's cluster count falls in the band the specification and Windows read as
    /// different types, so the two would follow its chains through tables of different entry
    /// widths.
    ///
    /// The reader agrees with the specification and with Linux, which is what the count
    /// derivation says; the deviation is that the volume is one no formatter should have
    /// written. This crate's planner steps down out of the band rather than emitting one.
    #[error(
        "a count of {clusters} clusters is FAT16 to the specification and to Linux and FAT12 \
         to Windows; the two follow its chains through tables of different entry widths"
    )]
    #[non_exhaustive]
    AmbiguousClusterCount {
        /// The volume's cluster count.
        clusters: u32,
    },
    /// A structure names a cluster the volume does not have.
    #[error("cluster {cluster} is not a cluster this volume has")]
    #[non_exhaustive]
    ClusterOutOfRange {
        /// The cluster named.
        cluster: u32,
    },
    /// A structure names a sector past the volume's own sector count.
    #[error("sector {sector} is past the volume's {total_sectors} sectors")]
    #[non_exhaustive]
    SectorOutOfRange {
        /// The first sector the read would have needed.
        sector: u32,
        /// The sectors the volume describes.
        total_sectors: u32,
    },
    /// A long name holds more UTF-16 units than the format defines for one.
    ///
    /// Twenty entries of thirteen units can carry 260, and the format caps a name at 255 —
    /// this crate's own writer refuses a longer one. The name is still read, so the tree
    /// stays enumerable under a lenient read; what could not happen is writing the name
    /// back to a volume of this family.
    #[error(
        "the long name ending at entry {index} holds {units} UTF-16 units, past the format's 255"
    )]
    #[non_exhaustive]
    LongNameTooLong {
        /// The entry the run ended at.
        index: u32,
        /// The units the run holds.
        units: usize,
    },
    /// A chain's table entry holds a value no chain may contain: free, reserved, or the
    /// bad-cluster mark.
    #[error("the table entry for cluster {cluster} is {entry:#x}, which no chain may contain")]
    #[non_exhaustive]
    BadChainEntry {
        /// The cluster whose entry was read.
        cluster: u32,
        /// The value found there.
        entry: u32,
    },
    /// A chain did not end within the clusters the volume has, so it repeats one.
    #[error("the chain from cluster {start} does not end within the volume's {clusters} clusters")]
    #[non_exhaustive]
    ChainTooLong {
        /// The chain's first cluster.
        start: u32,
        /// Clusters the volume has, which bounds any chain in it.
        clusters: u32,
    },
    /// A chain ended before the length the entry that owns it records.
    ///
    /// FAT has no sparse files: a length is a claim about clusters, and a chain that stops
    /// short means the length and the allocation disagree. Handing back a short buffer would
    /// report success for a file that is not all there.
    #[error("a chain from cluster {start} ends before byte {read} of the {size} its entry records")]
    #[non_exhaustive]
    ChainTooShort {
        /// The chain's first cluster.
        start: u32,
        /// The length the directory entry records.
        size: u64,
        /// The file byte offset the read required and the chain ends before. A read from
        /// an offset reports the offset it needed, not a walk of the whole chain — the
        /// chain may end earlier still.
        read: u64,
    },
    /// A copy of the file allocation table differs from the first.
    ///
    /// FAT carries no checksums, and the mirror is what stands in for one: two copies of an
    /// allocation record that disagree mean at least one of them is wrong and nothing in the
    /// volume says which.
    #[error(
        "file allocation table {copy} holds {other:#x} for cluster {cluster} where table 0 \
         holds {first:#x}"
    )]
    #[non_exhaustive]
    TableMismatch {
        /// Which copy differs, counting from zero.
        copy: u32,
        /// The cluster whose entry differs.
        cluster: u32,
        /// What the first table holds.
        first: u32,
        /// What this copy holds.
        other: u32,
    },
    /// A copy of the file allocation table differs from the first beyond its last entry.
    ///
    /// The bytes past the entry for the last cluster address nothing, so a difference there
    /// misallocates nothing — it is a formatter's padding rather than an allocation record.
    #[error("file allocation table {copy} differs from table 0 in the padding past its last entry")]
    #[non_exhaustive]
    TablePaddingMismatch {
        /// Which copy differs, counting from zero.
        copy: u32,
    },
    /// A reserved entry of the file allocation table does not hold the value the format
    /// defines for it.
    #[error("table entry {index} is {found:#x} where the format defines {expected:#x}")]
    #[non_exhaustive]
    BadReservedEntry {
        /// The entry's index: 0 carries the media descriptor, 1 the status bits.
        index: u32,
        /// The value found.
        found: u32,
        /// The value the format defines.
        expected: u32,
    },
    /// The backup boot sector is not a copy of sector 0.
    ///
    /// It exists to be used when sector 0 cannot be read, so a copy that has drifted is
    /// worse than none: it would restore a geometry the volume does not have.
    #[error("the backup boot sector at sector {sector} is not a copy of sector 0")]
    #[non_exhaustive]
    BackupBootSectorDiffers {
        /// Where the backup sits.
        sector: u32,
    },
    /// The sector the parameter block points at as the information sector is not one.
    #[error("sector {sector} is named as the information sector and does not hold one")]
    #[non_exhaustive]
    BadInfoSector {
        /// Where the parameter block said to look.
        sector: u32,
    },
    /// A run of long-name entries does not belong to the entry that follows it: the
    /// checksum over the short name does not match.
    ///
    /// This is what stops a driver without long-name support from orphaning a name onto the
    /// wrong file, so a mismatch means the long name describes some file that is no longer
    /// there. The short name is what the entry is then read under.
    #[error(
        "the long name before entry {index} checksums to {found:#04x} and its short name to \
         {expected:#04x}"
    )]
    #[non_exhaustive]
    LongNameChecksum {
        /// The short entry's index within its directory.
        index: u32,
        /// The checksum the long-name entries carry.
        found: u8,
        /// The checksum of the short name they precede.
        expected: u8,
    },
    /// A run of long-name entries is not followed by the short entry it belongs to, or its
    /// ordinals do not run down to one without a gap.
    #[error("the long-name entries ending at entry {index} do not form a complete run")]
    #[non_exhaustive]
    OrphanedLongName {
        /// Where the run ended.
        index: u32,
    },
    /// A long name's code units are not well-formed UTF-16: it carries a surrogate with no
    /// partner, which stands for no character.
    ///
    /// The name is still read, with each such unit replaced by U+FFFD, so a tree carrying
    /// one is still enumerable under a lenient read.
    #[error("the long name at entry {index} is not well-formed UTF-16")]
    #[non_exhaustive]
    IllFormedLongName {
        /// The short entry's index within its directory.
        index: u32,
    },
    /// One of an entry's three times holds a value the encoding does not define.
    ///
    /// A month of zero, a day of 31 in February, a twenty-fifth hour, or a hundredths byte
    /// past 199. A read reports the instant the arithmetic reaches, which is what every driver
    /// does; this is the judgment that says the field was never an instant.
    ///
    /// The creation and access times are the format's optional ones, and a wholly zero field
    /// is how it records that they were not kept — so a zero field is not reported. Nothing
    /// short of the whole field is that record: a date of zero beside a time that is not is a
    /// field that was written and not a field that was skipped.
    #[error("the {field} at entry {index} holds a value the encoding does not define")]
    #[non_exhaustive]
    MalformedTimestamp {
        /// The entry's index within its directory.
        index: u32,
        /// Which of the three times, in the format's own words.
        field: &'static str,
    },
    /// A short name carries a byte above ASCII and no code page was named, so what
    /// character it stands for is not something the volume records.
    ///
    /// Name a [`ShortNameCharset`] to interpret it. The name is still read under a lenient
    /// policy, with its bytes exactly as they sit on disk.
    #[error(
        "the short name at entry {index} carries byte {byte:#04x}, above ASCII, and this \
         volume records no code page; name one to interpret it"
    )]
    #[non_exhaustive]
    UninterpretedShortName {
        /// The entry's index within its directory.
        index: u32,
        /// The first byte above ASCII in the name.
        byte: u8,
    },
    /// An entry's name is one no directory can hold: `.` or `..`, or a name carrying a path
    /// separator or a NUL.
    ///
    /// The first two name a directory rather than something inside it, a separator would
    /// traverse out of the tree, and a NUL would truncate the path a consumer forms from the
    /// name. Neither field a name arrives in rules one out: a long name is UTF-16 and may
    /// spell anything, and a short name is eleven bytes an image chooses — the character set
    /// a short name is restricted to is a formatter's rule, not something a reader can assume
    /// of an image it did not write.
    ///
    /// The name itself is not repeated in the message. It is the image's, an image is
    /// untrusted input, and a name built to be one a directory cannot hold is equally free to
    /// carry the control bytes that would rewrite the line it is printed on.
    #[error("the name at entry {index} is one no directory can hold")]
    #[non_exhaustive]
    HostileName {
        /// The entry's index within its directory, counting 32-byte slots from zero.
        index: u32,
    },
    /// An entry records a length and no first cluster.
    ///
    /// FAT has no holes — a file's bytes are its chain — so a length is a claim about clusters
    /// and a first cluster of zero says there are none. An entry making both claims describes
    /// contents no read can reach, and the incoherence surfaces halfway through an extraction
    /// rather than at the entry that carries it.
    #[error("the entry at {index} records {size} bytes and no first cluster")]
    #[non_exhaustive]
    SizeWithoutAllocation {
        /// The entry's index within its directory.
        index: u32,
        /// The length the directory entry records.
        size: u32,
    },
    /// A subdirectory's `.` or `..` entry is missing, out of place, or does not point where
    /// the format requires.
    #[error("{detail}")]
    #[non_exhaustive]
    BadDotEntry {
        /// What is wrong with it.
        detail: String,
    },
    /// A directory holds entries after the one that marks its end, which no reader will
    /// reach.
    #[error("directory entry {index} follows the end marker and no reader reaches it")]
    #[non_exhaustive]
    EntriesAfterEnd {
        /// The index of the first entry past the marker.
        index: u32,
    },
    /// A volume label entry sits somewhere other than the root directory, where it is the
    /// one place the format defines for it.
    #[error("a volume label entry sits at entry {index} of a directory that is not the root")]
    #[non_exhaustive]
    MisplacedVolumeLabel {
        /// The entry's index within its directory.
        index: u32,
    },
    /// Clusters are marked allocated in the file allocation table and no chain reaches
    /// them, so the space is spent and holds nothing a reader can find.
    #[error("{count} clusters are allocated and reached by no chain, the first at {first}")]
    #[non_exhaustive]
    LostClusters {
        /// How many.
        count: u32,
        /// The lowest-numbered one.
        first: u32,
    },
    /// A path names nothing in the volume.
    #[error("no such path: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotFound {
        /// The path as given.
        path: Vec<u8>,
    },
    /// A path traverses through something that is not a directory.
    #[error("not a directory: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotADirectory {
        /// The path as given.
        path: Vec<u8>,
    },
    /// A whole-file read would exceed [`Limits::max_file_bytes`].
    #[error("a file of {size} bytes exceeds the {limit}-byte read limit")]
    #[non_exhaustive]
    FileTooLarge {
        /// The length the entry records.
        size: u64,
        /// The limit in force.
        limit: u64,
    },
    /// A walked path is longer than any consumer of one could use.
    ///
    /// Nothing in either format bounds how deep a tree nests, and a walk's entry cap counts
    /// *names* rather than the bytes their paths occupy — so a caterpillar tree of sixty-five
    /// thousand directories, each holding one entry naming the next, stays under every count
    /// while its paths grow by one component each and cost the walk their sum. A 32 MiB
    /// volume reaches tens of gigabytes of path bytes that way.
    ///
    /// The bound is `PATH_MAX`, which is the ceiling on what a path can be *used* for: a
    /// consumer resolving one against a host gets `ENAMETOOLONG` past it, so a longer path
    /// is not a path anything could act on.
    #[error("a walked path is longer than the {limit} bytes a path may be")]
    #[non_exhaustive]
    PathTooLong {
        /// The longest path a walk builds.
        limit: usize,
    },
    /// A whole-tree walk would gather more names than the bounds allow.
    #[error("the tree holds more than {limit} names")]
    #[non_exhaustive]
    WalkTooLarge {
        /// The bound that applied.
        limit: usize,
    },
}

crate::io::io_error!(ReadError);

impl ReadError {
    /// How this failure classifies as a deviation from what this crate emits.
    ///
    /// Every variant answers, so a scan describes a fault exactly as a strict read would
    /// have. The two that are not the image's — a source that could not be read, and a
    /// caller's own bound — classify as [`Severity::Structural`] all the same: from a
    /// scan's point of view the volume could not be followed past that point, whatever the
    /// reason.
    #[must_use]
    pub fn anomaly(&self) -> Anomaly {
        let at = |sector: Option<u32>, cluster: Option<u32>, entry: Option<u32>| Location {
            sector,
            cluster,
            entry,
        };
        let (severity, category, location) = match self {
            ReadError::Io { .. } => (
                Severity::Structural,
                Category::BootSector,
                Location::default(),
            ),
            ReadError::Parse(_) | ReadError::BadBootSector { .. } => (
                Severity::Structural,
                Category::BootSector,
                at(Some(0), None, None),
            ),
            // Valid, and read the way the specification and Linux read it — but a volume no
            // formatter should write, because the other mainstream driver reads it
            // differently.
            ReadError::AmbiguousClusterCount { .. } => (
                Severity::Conformance,
                Category::BootSector,
                at(Some(0), None, None),
            ),
            ReadError::ClusterOutOfRange { cluster } => (
                Severity::Structural,
                Category::AllocationTable,
                at(None, Some(*cluster), None),
            ),
            ReadError::SectorOutOfRange { sector, .. } => (
                Severity::Structural,
                Category::BootSector,
                at(Some(*sector), None, None),
            ),
            ReadError::BadChainEntry { cluster, .. } => (
                Severity::Structural,
                Category::AllocationTable,
                at(None, Some(*cluster), None),
            ),
            ReadError::ChainTooLong { start, .. } | ReadError::ChainTooShort { start, .. } => (
                Severity::Structural,
                Category::AllocationTable,
                at(None, Some(*start), None),
            ),
            // The mirror is what a FAT volume has instead of a checksum, so two copies that
            // disagree are self-inconsistent bytes rather than a matter of form.
            ReadError::TableMismatch { cluster, .. } => (
                Severity::Integrity,
                Category::AllocationTable,
                at(None, Some(*cluster), None),
            ),
            ReadError::TablePaddingMismatch { .. } => (
                Severity::Cosmetic,
                Category::AllocationTable,
                Location::default(),
            ),
            ReadError::BadReservedEntry { index, .. } => (
                Severity::Conformance,
                Category::AllocationTable,
                at(None, Some(*index), None),
            ),
            ReadError::BackupBootSectorDiffers { sector } => (
                Severity::Conformance,
                Category::BootSector,
                at(Some(*sector), None, None),
            ),
            ReadError::BadInfoSector { sector } => (
                Severity::Conformance,
                Category::InfoSector,
                at(Some(*sector), None, None),
            ),
            ReadError::LongNameChecksum { index, .. } | ReadError::OrphanedLongName { index } => (
                Severity::Integrity,
                Category::Directory,
                at(None, None, Some(*index)),
            ),
            // The name reads back whole and unambiguously; what it violates is the
            // format's own cap, which is a matter of conformance rather than of damage.
            ReadError::LongNameTooLong { index, .. } => (
                Severity::Conformance,
                Category::Directory,
                at(None, None, Some(*index)),
            ),
            // A name a directory cannot hold is not a matter of form: no driver creates one
            // and this crate's writer refuses one, so an entry carrying it describes a tree
            // that does not exist rather than one written to a different convention.
            //
            // A length with no clusters behind it is the same kind of fault one field along:
            // an entry describing bytes that are not there.
            ReadError::HostileName { index } | ReadError::SizeWithoutAllocation { index, .. } => (
                Severity::Structural,
                Category::Directory,
                at(None, None, Some(*index)),
            ),
            ReadError::IllFormedLongName { index }
            | ReadError::UninterpretedShortName { index, .. }
            | ReadError::EntriesAfterEnd { index }
            // A recovered field outside the range the format states for it. The entry reads
            // back whole and one field of it means nothing.
            | ReadError::MalformedTimestamp { index, .. }
            | ReadError::MisplacedVolumeLabel { index } => (
                Severity::Conformance,
                Category::Directory,
                at(None, None, Some(*index)),
            ),
            ReadError::BadDotEntry { .. } => (
                Severity::Conformance,
                Category::Directory,
                Location::default(),
            ),
            ReadError::LostClusters { first, .. } => (
                Severity::Conformance,
                Category::AllocationTable,
                at(None, Some(*first), None),
            ),
            ReadError::NotFound { .. } | ReadError::NotADirectory { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            ReadError::FileTooLarge { .. }
            | ReadError::PathTooLong { .. }
            | ReadError::WalkTooLarge { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
        };
        Anomaly {
            severity,
            category,
            location,
            detail: self.to_string(),
        }
    }
}

/// The FAT family's half of the shared path resolution: a directory listing to find a name in,
/// matched the way a driver matches one.
///
/// The link half of the trait is defaulted, because the format has none: an entry is a file, a
/// directory, or the volume label, and a path through this volume goes exactly where its
/// components say.
impl<R: Read + Seek> crate::resolve::Resolve for Reader<R> {
    /// The node itself. There is nothing to re-read on the way back up: a FAT [`Node`] is four
    /// fixed-size fields, so a locator would cost as much as the node — the same reason the
    /// walk's frontier holds one.
    type Ancestor = Node;
    type Node = Node;
    type Error = ReadError;

    fn root_node(&mut self) -> Result<Node, ReadError> {
        Ok(self.root())
    }

    fn ancestor_of(&self, node: &Node) -> Node {
        *node
    }

    fn node_at(&mut self, ancestor: Node) -> Result<Node, ReadError> {
        Ok(ancestor)
    }

    fn is_directory(&self, node: &Node) -> bool {
        node.is_dir()
    }

    fn find_name(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Node>, ReadError> {
        // One pass answers both questions: an exact match wins outright, and the first
        // case-folded match is remembered in case none is exact. Two passes would read
        // the whole listing twice for every component that resolves case-insensitively.
        let entries = self.read_dir(dir)?;
        let mut folded = None;
        for e in &entries {
            if e.name == name {
                return Ok(Some(e.node));
            }
            if folded.is_none() && e.name.eq_ignore_ascii_case(name) {
                folded = Some(e.node);
            }
        }
        Ok(folded)
    }

    fn not_found(&self, path: &[u8]) -> ReadError {
        ReadError::NotFound {
            path: path.to_vec(),
        }
    }

    fn not_a_directory(&self, _node: &Node, path: &[u8]) -> ReadError {
        ReadError::NotADirectory {
            path: path.to_vec(),
        }
    }
}

/// The FAT family's half of the shared walk: a resolved entry on the frontier, a first
/// cluster as the cycle key, and a directory listing as the children.
impl<R: Read + Seek> crate::walk::Walk for Reader<R> {
    /// A whole entry. Unlike the ext family, there is nothing to re-read at the pop: a FAT
    /// [`Node`] is four fixed-size fields, so a locator would cost as much as the node.
    type Pending = WalkEntry;
    type Entry = WalkEntry;
    /// The directory's first cluster. The root region has none and is entered once by
    /// construction, so it needs no key.
    type Key = u32;
    type Error = ReadError;

    fn cap(&mut self) -> usize {
        self.limits.max_walk_entries.min(self.max_names())
    }

    fn seed(&mut self) -> Result<crate::walk::Seed<Self>, ReadError> {
        let root = self.root();
        let occupied = match root.storage {
            Storage::Chain(start) => vec![start],
            Storage::None | Storage::RootRegion => Vec::new(),
        };
        Ok((self.walk_children(&root, &[])?, occupied))
    }

    fn resolve(&mut self, pending: WalkEntry) -> Result<WalkEntry, ReadError> {
        Ok(pending)
    }

    fn descend_key(&self, entry: &WalkEntry) -> Option<u32> {
        if !entry.node.is_dir() {
            return None;
        }
        match entry.node.storage {
            Storage::Chain(start) => Some(start),
            // A directory entry naming no cluster has no storage to descend into.
            Storage::None | Storage::RootRegion => None,
        }
    }

    fn children(&mut self, entry: &WalkEntry) -> Result<Vec<WalkEntry>, ReadError> {
        self.walk_children(&entry.node, &entry.path)
    }

    fn too_large(limit: usize) -> ReadError {
        ReadError::WalkTooLarge { limit }
    }
}

/// How a read failure classifies in the crate's family-agnostic frame.
impl From<ReadError> for TreeError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::Io { kind, message } => TreeError::Io { kind, message },
            ReadError::FileTooLarge { .. }
            | ReadError::PathTooLong { .. }
            | ReadError::WalkTooLarge { .. } => TreeError::LimitExceeded {
                family: Family::Fat,
                detail: err.to_string(),
            },
            other => TreeError::Malformed {
                family: Family::Fat,
                detail: other.to_string(),
            },
        }
    }
}

/// What a whole-volume [`scan`](Reader::scan) found, in FAT's own taxonomy.
///
/// This is the crate's [`ScanReport`](crate::ScanReport) over FAT's [`Anomaly`]: an anomaly
/// names the subsystem as a [`Category`] value and its place as a [`Location`] of cluster,
/// sector, and entry, which is what a consumer reasoning about a FAT volume wants. The
/// addressing unit is the volume's sector size, so a sector-addressed anomaly projects to the
/// byte offset that sector sits at.
pub type ScanReport = crate::ScanReport<Anomaly>;

/// Where a node's bytes are.
///
/// The domain is closed and the type is exhaustive: a FAT node's storage is a chain, or the
/// one fixed region a FAT12 or FAT16 volume reserves for its root, or nothing at all. There
/// is no fourth, and a fifth arriving *should* break a caller that switches on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    /// The node owns no cluster: an empty file, whose entry records a first cluster of zero.
    None,
    /// A cluster chain beginning at this cluster.
    Chain(u32),
    /// The fixed-capacity root directory region of a FAT12 or FAT16 volume, which is not a
    /// chain and has no entry in the file allocation table.
    RootRegion,
}

/// The three times a directory entry records.
///
/// The root directory has none — the format stores no entry for it on any type — which is
/// why [`Node::times`] is an [`Option`] rather than three fields that would have to hold
/// something invented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Times {
    /// When the entry was created, to ten milliseconds.
    pub create: Timestamp,
    /// When it was last accessed. The format stores a date and no time of day, so this is
    /// always midnight UTC.
    pub access: Timestamp,
    /// When it was last written, to two seconds.
    pub modify: Timestamp,
}

/// A handle to one node: where its bytes are, what it is, how long it is, and when.
///
/// This is what a walk hands back and what every by-node operation takes. There is no
/// number in it, and deliberately: FAT has no inodes, so there is nothing that distinguishes
/// a file from a second name for it — the format has no second names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Node {
    /// Where the node's bytes are.
    pub storage: Storage,
    /// The entry's attribute byte.
    pub attributes: DirAttributes,
    /// The length the entry records, in bytes. Zero for a directory, whose length is
    /// however many clusters its chain holds.
    pub size: u32,
    /// The times the entry records, or `None` for the root directory, which has no entry.
    pub times: Option<Times>,
}

impl Node {
    /// Whether the node is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.attributes.contains(DirAttributes::DIRECTORY)
            || matches!(self.storage, Storage::RootRegion)
    }

    /// Whether the node is the volume label rather than a file or a directory.
    #[must_use]
    pub const fn is_volume_label(&self) -> bool {
        !self.attributes.contains(DirAttributes::DIRECTORY)
            && self.attributes.contains(DirAttributes::VOLUME_ID)
    }
}

/// One resolved directory entry: the name it is found under, the short name it always has,
/// and a handle to what it points at.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Entry {
    /// The name the entry is found under: the long name where it has one, and otherwise the
    /// short name rendered with its dot.
    ///
    /// Always a name a directory can hold. An entry whose name resolves to `.` or `..`, or
    /// carries a path separator or a NUL, is [`HostileName`](ReadError::HostileName) rather
    /// than an [`Entry`], so a path built by joining this onto its directory's stays inside
    /// the tree.
    pub name: Vec<u8>,
    /// The short name, always, rendered with its dot and with the padding trimmed.
    ///
    /// Kept beside the name because the two differing is an observable fact about the volume
    /// rather than an implementation detail: a foreign tool listing the tree shows both
    /// columns, and a name that is already its own short name shows one of them empty.
    ///
    /// **The safety promise above belongs to [`name`](Self::name) alone.** This field shows
    /// the stored bytes, and where a long name is what the entry is found under, these
    /// eleven bytes go unchecked: a crafted volume can put a path separator, a NUL, or a
    /// dot-name here beside a clean long name. Build paths from `name`; treat this as a
    /// display column.
    ///
    /// A byte above ASCII here is not itself a deviation. What
    /// [`UninterpretedShortName`](ReadError::UninterpretedShortName) is about is a name the
    /// reader cannot say the meaning of and is handing back as the name anyway — so it
    /// applies where these eleven bytes *are* [`name`](Self::name), and not where a long
    /// name, which is UTF-16 and unambiguous, is what the entry is found under. A short name
    /// beside a long one is a legacy second record of it.
    pub short_name: Vec<u8>,
    /// Whether the name came from long-name entries rather than from the short name field.
    pub has_long_name: bool,
    /// A handle to what the entry points at.
    pub node: Node,
}

/// One name a [`walk`](Reader::walk) reached: its path, and a handle to what is there.
///
/// There is no number beside the path, unlike the ext family's walk: FAT has no second name
/// for a node, so a path and a node are the same thing and nothing has to distinguish them.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Absolute path from the volume root, `/`-joined, always beginning with `/`.
    pub path: Vec<u8>,
    /// A handle to what is at the path.
    pub node: Node,
}

/// How a FAT volume is opened: where it begins, how strictly it is read, what it may
/// allocate, and how the bytes of a short name above ASCII are interpreted.
///
/// Every input to [`Reader::open_with`] is a field here rather than a parameter, so a knob
/// the reader grows arrives as a field a caller may ignore.
///
/// The first three are the crate's family-agnostic [`OpenOptions`](crate::OpenOptions) and
/// mean exactly what they mean there. The fourth is why this type exists: a FAT volume
/// records no code page for its short names, and no other family has that question.
///
/// ```
/// # use ferrosys::fat::{OpenOptions, ShortNameCharset};
/// # use ferrosys::ReadPolicy;
/// // A volume inside a partition, read leniently so a scan can describe what is wrong with
/// // it rather than the open refusing it, with its short names read as code page 437.
/// let options = OpenOptions::new()
///     .base(1 << 20)
///     .policy(ReadPolicy::Lenient)
///     .charset(ShortNameCharset::Cp437);
/// # let _ = options;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Where the volume begins, how strictly it is read, and what one read may allocate —
    /// the crate's [`OpenOptions`](crate::OpenOptions), which mean exactly what they mean
    /// there.
    ///
    /// Held rather than flattened, so an input every family takes is added in one place and
    /// reaches every family at once. The three builders below set through it, so a caller
    /// writes `OpenOptions::new().base(..)` either way.
    pub common: crate::OpenOptions,
    /// How the bytes of a short name above ASCII are interpreted. Defaults to
    /// [`ShortNameCharset::Verbatim`], which interprets nothing.
    ///
    /// Naming a page is a claim the caller is making: the volume does not record one, and
    /// there is no field or heuristic that recovers it. What naming one *does* change is the
    /// severity of meeting such a byte — unrecognized bytes are a conformance deviation and
    /// a strict read stops at them, while bytes the caller has said how to read are a
    /// cosmetic remark and a strict read carries on.
    pub charset: ShortNameCharset,
}

impl OpenOptions {
    /// Open at the start of the source, strictly, with the default limits, interpreting no
    /// byte of a short name.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            common: crate::OpenOptions::new(),
            charset: ShortNameCharset::Verbatim,
        }
    }

    /// Open a volume that begins `base` bytes into the source.
    #[must_use]
    pub const fn base(mut self, base: u64) -> Self {
        self.common = self.common.base(base);
        self
    }

    /// Read under `policy`.
    #[must_use]
    pub const fn policy(mut self, policy: ReadPolicy) -> Self {
        self.common = self.common.policy(policy);
        self
    }

    /// Cap what one read may allocate.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.common = self.common.limits(limits);
        self
    }

    /// Take the three shared inputs from `common`, leaving this family's own alone.
    #[must_use]
    pub const fn common(mut self, common: crate::OpenOptions) -> Self {
        self.common = common;
        self
    }

    /// Interpret the bytes of a short name above ASCII as `charset` gives them.
    #[must_use]
    pub const fn charset(mut self, charset: ShortNameCharset) -> Self {
        self.charset = charset;
        self
    }
}

/// A read-only handle over a FAT volume on any [`Read`] + [`Seek`] source.
///
/// The volume may sit at an arbitrary byte offset within the source — a partition inside a
/// whole-disk image — fixed at open time. Reads seek relative to that offset and return
/// owned buffers, so nothing is borrowed from the source between calls.
pub struct Reader<R> {
    src: R,
    base: u64,
    boot: BootSector,
    layout: FatLayout,
    policy: ReadPolicy,
    limits: Limits,
    charset: ShortNameCharset,
    /// The deviations found while validating the parameter block, kept so a scan reports
    /// them without re-deriving the geometry and a lenient caller can see them without one.
    open_anomalies: Vec<Anomaly>,
    /// A two-sector window on the first file allocation table.
    ///
    /// Following a chain reads one entry at a time and the entries of a chain are usually
    /// near each other, so a window turns a walk of a large file from one seek per cluster
    /// into one per sector. Two sectors rather than one because a FAT12 entry may straddle
    /// the boundary between them. The image is read-only, so a cached window can never go
    /// stale.
    fat_window: Option<(u32, Vec<u8>)>,
    /// Where a chain walk left off: the chain's first cluster, the index within it, and the
    /// cluster at that index.
    ///
    /// A read at an offset has to skip to the cluster holding it, and skipping from the
    /// start every time makes a sequential read of one file quadratic in its length. Kept
    /// here so a read that continues where the last one stopped resumes rather than
    /// restarts.
    chain_cursor: Option<(u32, u64, u32)>,
}

/// What a directory parse does with a deviation it meets.
///
/// One parser serves both dispositions, which is what makes a scan describe a fault exactly
/// as the read that stops at it would have.
enum OnDeviation<'a> {
    /// An ordinary read: fatal under the policy, and otherwise passed over.
    Policy(ReadPolicy),
    /// A scan: every deviation collected, none fatal.
    Collect(&'a mut Findings<Anomaly>),
}

impl OnDeviation<'_> {
    /// Record `err`, having happened at `at`. Returns it as an error where the policy in
    /// force makes it fatal.
    fn record(&mut self, at: Location, err: ReadError) -> Result<(), ReadError> {
        match self {
            OnDeviation::Policy(policy) => {
                if policy.is_fatal(err.anomaly().severity) {
                    Err(err)
                } else {
                    Ok(())
                }
            }
            OnDeviation::Collect(findings) => {
                let mut anomaly = err.anomaly();
                anomaly.location = anomaly.location.or(at);
                findings.push(anomaly);
                Ok(())
            }
        }
    }
}

impl<R: Read + Seek> Reader<R> {
    /// Open the FAT volume at the start of `src` under the default options.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadBootSector`] when the parameter block does not describe a FAT volume,
    /// [`ReadError::Io`] when the source cannot be read, and — under
    /// [`ReadPolicy::Strict`] — whichever deviation the parameter block carries.
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open the FAT volume `src` holds, under `options`.
    ///
    /// The parameter block is validated through the same function detection classifies
    /// with, so a volume detection claims is one this opens and a volume it does not claim
    /// is one this refuses. What the reader adds is a reason.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_with(mut src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let end = src.seek(SeekFrom::End(0))?;
        let available = end.saturating_sub(options.common.base);
        let sector = read_exact_at(&mut src, options.common.base, BootSector::SIZE)?;
        let boot = BootSector::read_from(&sector)?;
        let layout = layout_from_boot(&boot, available).map_err(|d| ReadError::BadBootSector {
            field: d.field,
            value: d.value,
        })?;

        // The one deviation the geometry itself carries. A count in the disputed band is
        // read the way the specification and Linux read it, and said to be one no formatter
        // should have written — which under a strict policy is where the open stops.
        let mut open_anomalies = Vec::new();
        if layout.fat_type == FatType::Fat16
            && layout.clusters > MAX_CLUSTERS_FAT12
            && layout.clusters < MIN_CLUSTERS_FAT16
        {
            let err = ReadError::AmbiguousClusterCount {
                clusters: layout.clusters,
            };
            if options.common.policy.is_fatal(err.anomaly().severity) {
                return Err(err);
            }
            open_anomalies.push(err.anomaly());
        }

        Ok(Self {
            src,
            base: options.common.base,
            boot,
            layout,
            policy: options.common.policy,
            limits: options.common.limits,
            charset: options.charset,
            open_anomalies,
            fat_window: None,
            chain_cursor: None,
        })
    }

    /// The volume's geometry, as its parameter block describes it.
    ///
    /// This is the same type the planner produces, recovered rather than computed — so a
    /// layout planned and a layout read back from the image it produced compare equal, which
    /// is what makes a format-then-read a round trip rather than two descriptions that
    /// happen to agree.
    #[must_use]
    pub const fn layout(&self) -> &FatLayout {
        &self.layout
    }

    /// The boot sector exactly as it was parsed.
    #[must_use]
    pub const fn boot_sector(&self) -> &BootSector {
        &self.boot
    }

    /// Which of the three types the volume's geometry derives to.
    #[must_use]
    pub const fn fat_type(&self) -> FatType {
        self.layout.fat_type
    }

    /// The strictness this reader was opened under.
    #[must_use]
    pub const fn policy(&self) -> ReadPolicy {
        self.policy
    }

    /// How this reader interprets the bytes of a short name above ASCII.
    #[must_use]
    pub const fn charset(&self) -> ShortNameCharset {
        self.charset
    }

    /// The root directory.
    ///
    /// Its storage is the fixed region on FAT12 and FAT16 and the chain the parameter block
    /// names on FAT32, and it carries no times, because the format records no entry for it
    /// on any type.
    #[must_use]
    pub fn root(&self) -> Node {
        let storage = match self.layout.fat32 {
            Some(f) => Storage::Chain(f.root_cluster),
            None => Storage::RootRegion,
        };
        Node {
            storage,
            attributes: DirAttributes::DIRECTORY,
            size: 0,
            times: None,
        }
    }

    /// The FAT32 information sector, or `None` on a volume that has no such sector.
    ///
    /// Both of its counts are hints. A driver may update them, ignore them, or leave them
    /// stale, so a reader that trusted one over the file allocation table would be trusting
    /// a cache nothing is obliged to invalidate.
    ///
    /// # Errors
    ///
    /// [`ReadError::Io`] when the sector cannot be read, and [`ReadError::BadInfoSector`]
    /// when the sector the parameter block names does not hold one.
    pub fn info_sector(&mut self) -> Result<Option<FsInfo>, ReadError> {
        let Some(fat32) = self.layout.fat32 else {
            return Ok(None);
        };
        let sector = u32::from(fat32.fs_info_sector);
        let bytes = self.read_sectors(sector, 1)?;
        match FsInfo::read_from(&bytes) {
            Ok(info) => Ok(Some(info)),
            Err(_) => Err(ReadError::BadInfoSector { sector }),
        }
    }

    /// The volume label, or `None` for a volume that carries none.
    ///
    /// The authority is the entry in the root directory carrying
    /// [`Attributes::VOLUME_ID`](DirAttributes::VOLUME_ID), which is what a driver and
    /// `fatlabel` both read and what a rename updates. The copy in the boot sector is a
    /// second record of the same thing that nothing keeps in step, so it is used only where
    /// the root holds no such entry.
    ///
    /// The bytes are the eleven-byte field with its trailing padding trimmed, read under
    /// this reader's [`charset`](Self::charset) like any other short name.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the root directory cannot be read.
    pub fn volume_label(&mut self) -> Result<Option<Vec<u8>>, ReadError> {
        let root = self.root();
        let mut found = None;
        // `for_each_slot` hands back *every* slot, live or not, because that is what the
        // scan needs. A label is a live entry like any other, so the free and deleted markers
        // and the end of the directory are applied here — `fatlabel` and every driver read
        // the live label, and a deleted slot or one past the end holds a name the volume no
        // longer answers to.
        self.for_each_slot::<ReadError>(&root, |_, slot| {
            let first = slot.entry.name[0];
            if first == NAME_END {
                return Ok(ControlFlow::Break(()));
            }
            if first == NAME_DELETED {
                return Ok(ControlFlow::Continue(()));
            }
            if slot.entry.attributes.contains(DirAttributes::VOLUME_ID)
                && !slot.entry.attributes.is_long_name()
                && !slot.entry.attributes.contains(DirAttributes::DIRECTORY)
            {
                found = Some(slot.entry.name);
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        })?;
        if let Some(name) = found {
            return Ok(Some(self.charset.decode(&volume_label(&name))));
        }
        let stored = match self.boot.tail {
            BootSectorTail::Fat1216 { volume } | BootSectorTail::Fat32 { volume, .. } => {
                volume.label
            }
        };
        if stored == super::ondisk::VolumeInfo::NO_NAME {
            return Ok(None);
        }
        let trimmed = volume_label(&stored);
        if trimmed.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.charset.decode(&trimmed)))
    }

    // -- byte-level access ------------------------------------------------------------

    /// The byte offset of `sector` within the source, or [`None`] where it leaves the 64-bit
    /// range.
    ///
    /// Checked, for the reason every address in this crate is: `base` is the caller's and a
    /// sector number is the volume's, so a sum near the top of the range wraps into a small
    /// offset — which is not a read that fails but a successful read of the wrong bytes.
    ///
    /// What makes it unreachable today is `layout_from_boot`, which refuses a volume whose
    /// sectors do not fit the bytes the source holds from `base` onward: every sector this is
    /// asked for is therefore inside a source that already ends at or below `u64::MAX`. The
    /// check remains because that is a bound another function applies, held on the far side
    /// of the parameter block, and nothing here should depend on it — an overflow in a
    /// filesystem's addressing is silent, and the only cost of refusing one is a branch.
    fn sector_offset(&self, sector: u32) -> Option<u64> {
        offset_of(
            self.base,
            u64::from(sector),
            u64::from(self.layout.bytes_per_sector),
        )
    }

    /// `count` sectors from `first`, refusing a range the volume does not describe.
    ///
    /// The bound is the volume's own sector count, so a structure naming a sector past the
    /// filesystem is answered rather than read out of whatever follows it in the source.
    fn read_sectors(&mut self, first: u32, count: u32) -> Result<Vec<u8>, ReadError> {
        // The refusal names the sector asked for and the volume's own bound: which
        // structure named the sector varies by caller, so pinning the message to one
        // parameter-block field would blame a field whose value may be fine.
        let out_of_range = || ReadError::SectorOutOfRange {
            sector: first,
            total_sectors: self.layout.total_sectors,
        };
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.layout.total_sectors)
            .ok_or_else(out_of_range)?;
        debug_assert!(end <= self.layout.total_sectors);
        let offset = self.sector_offset(first).ok_or_else(out_of_range)?;
        let len = count as usize * self.layout.bytes_per_sector as usize;
        Ok(read_exact_at(&mut self.src, offset, len)?)
    }

    /// How many sectors a read must cover to hold the whole entry at `sector_in_table`,
    /// counted from the start of whichever copy of the table is being read.
    ///
    /// Two, because a FAT12 entry may begin in the last byte of one sector and end in the
    /// first of the next. One where the copy has no next sector — which is an entry the
    /// caller's own bound already refused, or one wholly inside the last sector.
    ///
    /// The end is the copy's own, not the first copy's. The copies are laid end to end, so
    /// reading one sector past the live table would splice the *next* copy's first entry
    /// onto a FAT12 entry that straddles the boundary, and the value read would belong to
    /// neither. Refusing there is what makes the two ways of reading an entry — the windowed
    /// walk and the copy-by-copy comparison — agree on every entry they both reach.
    const fn table_window_sectors(&self, sector_in_table: u32) -> u32 {
        if sector_in_table.saturating_add(1) < self.layout.fat_sectors {
            2
        } else {
            1
        }
    }

    /// The file allocation table's entry for `cluster`, from the copy the volume says is
    /// live.
    ///
    /// Read through the two-sector window, so a chain walk pays one read per table sector
    /// rather than one per cluster.
    fn table_entry(&mut self, cluster: u32) -> Result<u32, ReadError> {
        let fat_type = self.layout.fat_type;
        if cluster >= self.layout.max_table_entries() {
            return Err(ReadError::ClusterOutOfRange { cluster });
        }
        let copy = self.active_fat();
        let offset = table::entry_offset(fat_type, cluster);
        let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
        let sector_in_table = u32::try_from(offset / bytes_per_sector)
            .map_err(|_| ReadError::ClusterOutOfRange { cluster })?;
        let within = (offset % bytes_per_sector) as usize;
        let start = self
            .layout
            .fat_start_sector(copy)
            .ok_or(ReadError::ClusterOutOfRange { cluster })?;
        let sector = start
            .checked_add(sector_in_table)
            .ok_or(ReadError::ClusterOutOfRange { cluster })?;

        let window_sectors = self.table_window_sectors(sector_in_table);
        let need_reload = match &self.fat_window {
            Some((at, buf)) => {
                *at != sector || buf.len() < window_sectors as usize * bytes_per_sector as usize
            }
            None => true,
        };
        if need_reload {
            let buf = self.read_sectors(sector, window_sectors)?;
            self.fat_window = Some((sector, buf));
        }
        let (_, buf) = self.fat_window.as_ref().expect("just loaded");
        table::read_entry(fat_type, &buf[within..], 0).map_or(
            Err(ReadError::ClusterOutOfRange { cluster }),
            |raw| {
                // `read_entry` at index 0 of a slice beginning mid-table reads the low
                // twelve bits of the pair there, which is the even-cluster packing. An odd
                // FAT12 cluster owns the high twelve of the same pair.
                if fat_type == FatType::Fat12 && cluster & 1 == 1 {
                    let pair = u32::from(get_u16(buf, within));
                    Ok(pair >> 4)
                } else {
                    Ok(raw)
                }
            },
        )
    }

    /// The cluster that follows `cluster` in its chain, or `None` where the chain ends.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadChainEntry`] for a value no chain may contain, and
    /// [`ReadError::ClusterOutOfRange`] for one naming a cluster the volume does not have.
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, ReadError> {
        let fat_type = self.layout.fat_type;
        let entry = self.table_entry(cluster)?;
        if table::is_end_of_chain(fat_type, entry) {
            return Ok(None);
        }
        if !table::is_cluster(fat_type, entry) {
            return Err(ReadError::BadChainEntry { cluster, entry });
        }
        if entry - 2 >= self.layout.clusters {
            return Err(ReadError::ClusterOutOfRange { cluster: entry });
        }
        Ok(Some(entry))
    }

    /// The cluster at `index` in the chain beginning at `start`, or `None` where the chain
    /// is shorter than that.
    ///
    /// Resumes from [`chain_cursor`](Self::chain_cursor) where it can, so reading one file
    /// in order costs one pass over its chain rather than one per call.
    fn cluster_at(&mut self, start: u32, index: u64) -> Result<Option<u32>, ReadError> {
        let (mut at, mut current) = match self.chain_cursor {
            Some((cursor_start, cursor_index, cursor_cluster))
                if cursor_start == start && cursor_index <= index =>
            {
                (cursor_index, cursor_cluster)
            }
            _ => (0, start),
        };
        if start < 2 || start - 2 >= self.layout.clusters {
            return Err(ReadError::ClusterOutOfRange { cluster: start });
        }
        while at < index {
            match self.next_cluster(current)? {
                Some(next) => {
                    current = next;
                    at += 1;
                }
                None => return Ok(None),
            }
            // A chain longer than the volume has clusters must repeat one, so the bound is
            // the geometry's rather than a limit a caller sets.
            if at > u64::from(self.layout.clusters) {
                return Err(ReadError::ChainTooLong {
                    start,
                    clusters: self.layout.clusters,
                });
            }
        }
        self.chain_cursor = Some((start, at, current));
        Ok(Some(current))
    }

    /// The whole chain beginning at `start`, in order.
    ///
    /// Two bounds apply, and the tighter one wins. The structural bound is the volume's
    /// cluster count, which is what a chain cannot exceed without repeating a cluster; the
    /// caller's is [`Limits::max_walk_entries`], since a chain is collected whole for the
    /// same reason a walk is and a maximal FAT32 chain is four bytes times a quarter of a
    /// billion clusters. Reaching either is an error rather than a shortened list: a caller
    /// handed part of a chain would follow it somewhere the file does not go.
    ///
    /// # Errors
    ///
    /// [`ReadError::ClusterOutOfRange`] or [`ReadError::BadChainEntry`] where the chain
    /// leaves the volume, [`ReadError::ChainTooLong`] where it does not end, and
    /// [`ReadError::WalkTooLarge`] where it is longer than the caller's cap.
    pub fn chain(&mut self, start: u32) -> Result<Vec<u32>, ReadError> {
        if start < 2 || start - 2 >= self.layout.clusters {
            return Err(ReadError::ClusterOutOfRange { cluster: start });
        }
        let cap = self.limits.max_walk_entries;
        let mut out = vec![start];
        let mut current = start;
        while let Some(next) = self.next_cluster(current)? {
            if out.len() as u64 > u64::from(self.layout.clusters) {
                return Err(ReadError::ChainTooLong {
                    start,
                    clusters: self.layout.clusters,
                });
            }
            if out.len() >= cap {
                return Err(ReadError::WalkTooLarge { limit: cap });
            }
            out.push(next);
            current = next;
        }
        Ok(out)
    }

    /// The bytes of cluster `n`.
    fn read_cluster(&mut self, n: u32) -> Result<Vec<u8>, ReadError> {
        let first = self
            .layout
            .cluster_start_sector(n)
            .ok_or(ReadError::ClusterOutOfRange { cluster: n })?;
        self.read_sectors(first, self.layout.sectors_per_cluster)
    }

    // -- directories ------------------------------------------------------------------

    /// Hand every 32-byte slot of a directory's storage to `visit`, in order.
    ///
    /// One region is held at a time — the fixed root region, or a single cluster — so what
    /// this allocates is the largest region the geometry defines and not the directory's own
    /// size. That is the difference between a bound the *structure* implies and one a caller
    /// can rely on: a crafted directory whose chain spans the volume is the volume's size,
    /// and reading it whole would be an allocation the size of the image however tight a
    /// [`Limits`] the caller set. Streaming it costs one cluster whatever the chain does.
    ///
    /// `visit` says whether to keep going, so a caller that has found what it came for stops
    /// rather than reading the rest of the chain.
    fn for_each_slot<E: From<ReadError>>(
        &mut self,
        node: &Node,
        mut visit: impl FnMut(&mut Self, Slot) -> Result<ControlFlow<()>, E>,
    ) -> Result<(), E> {
        let entries_per_sector = (self.layout.bytes_per_sector as usize / DIR_ENTRY_SIZE).max(1);
        // Where the next slot sits, carried across regions: the index counts the whole
        // directory, and the sector is recomputed within each region from the index.
        let mut index = 0u32;

        // What is left to read. The fixed root region is one region and a chain is one per
        // cluster, which is the only difference between the two shapes.
        let mut next = match node.storage {
            Storage::None => None,
            Storage::RootRegion => self
                .layout
                .root_dir_start_sector()
                .map(|first| (first, self.layout.root_dir_sectors, None)),
            Storage::Chain(start) => Some((0, 0, Some(start))),
        };
        // Clusters this walk has already read. `steps` alone bounds the walk at the
        // volume's cluster count, which for a cycling chain means re-reading the same
        // cluster that many times before the refusal — and a scan absorbs that error and
        // moves on, so the cost is paid afresh for every directory. A 32 MiB volume can
        // spend gigabytes that way. A repeat is a cycle whatever it costs, so it ends the
        // chain the moment it is seen.
        //
        // The set is the volume's own domain, one bit per cluster, which is the answer this
        // file gives that question everywhere it is asked.
        let mut visited = ClusterSet::new(self.layout.clusters);
        if let Storage::Chain(start) = node.storage {
            visited.insert(start);
        }
        let mut steps = 0u64;

        while let Some((mut first, mut count, cluster)) = next {
            if let Some(current) = cluster {
                first = self
                    .layout
                    .cluster_start_sector(current)
                    .ok_or(ReadError::ClusterOutOfRange { cluster: current })?;
                count = self.layout.sectors_per_cluster;
            }
            let bytes = self.read_sectors(first, count).map_err(E::from)?;
            for (i, chunk) in bytes.chunks_exact(DIR_ENTRY_SIZE).enumerate() {
                // `chunks_exact` yields exactly `DIR_ENTRY_SIZE` bytes, so the parse cannot
                // be short; the error path stands because the parser is fallible in general.
                let Ok(entry) = DirEntry::read_from(chunk) else {
                    continue;
                };
                let slot = Slot {
                    entry,
                    index,
                    sector: first + (i / entries_per_sector) as u32,
                };
                index = index.saturating_add(1);
                if visit(self, slot)?.is_break() {
                    return Ok(());
                }
            }

            next = match cluster {
                None => None,
                Some(current) => match self.next_cluster(current).map_err(E::from)? {
                    None => None,
                    Some(following) => {
                        steps += 1;
                        let repeat = !visited.insert(following);
                        if repeat || steps > u64::from(self.layout.clusters) {
                            let Storage::Chain(start) = node.storage else {
                                unreachable!("only a chain steps between clusters")
                            };
                            return Err(E::from(ReadError::ChainTooLong {
                                start,
                                clusters: self.layout.clusters,
                            }));
                        }
                        Some((0, 0, Some(following)))
                    }
                },
            };
        }
        Ok(())
    }

    /// The entries of a directory, with long names reassembled.
    ///
    /// The volume label entry and the dot entries are not among them: the first is
    /// [`volume_label`](Self::volume_label)'s and the other two are the walk's own business,
    /// and none of the three is a name a consumer of a tree wants handed to it. The dot
    /// entries are recognized by their eleven-byte name field, which is where the format
    /// defines them, so a long-name run attached to one does not make it a name in the tree.
    ///
    /// Every name that *is* handed back is one a directory can hold. A name resolving to `.`
    /// or `..`, or carrying a path separator or a NUL, is
    /// [`HostileName`](ReadError::HostileName) — an error under [`ReadPolicy::Strict`] and a
    /// finding a [`scan`](Self::scan) collects, never an entry in the returned list.
    ///
    /// The directory's storage is read a region at a time and never held whole, so what one
    /// call allocates is the entries it produces plus a single cluster — the volume's size
    /// does not enter into it, however many clusters a directory chains together. The
    /// entries themselves are bounded by [`Limits::max_walk_entries`] and by the volume's
    /// whole directory capacity, whichever is smaller.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants when the directory's storage cannot be read,
    /// [`ReadError::WalkTooLarge`] when it holds more entries than that bound, and — under
    /// [`ReadPolicy::Strict`] — whichever deviation its entries carry, including
    /// [`ReadError::HostileName`].
    pub fn read_dir(&mut self, node: &Node) -> Result<Vec<Entry>, ReadError> {
        let policy = self.policy;
        self.parse_dir(node, &mut OnDeviation::Policy(policy))
    }

    /// The shared directory parser, which is the one place an entry's bytes become a name.
    fn parse_dir(
        &mut self,
        node: &Node,
        deviations: &mut OnDeviation<'_>,
    ) -> Result<Vec<Entry>, ReadError> {
        if !node.is_dir() {
            return Err(ReadError::NotADirectory { path: Vec::new() });
        }
        let is_root = matches!(node.storage, Storage::RootRegion)
            || self
                .layout
                .fat32
                .is_some_and(|f| node.storage == Storage::Chain(f.root_cluster));
        // The directory's own entries are held, and its storage is not: a crafted directory
        // is bounded by what a caller allowed rather than by how many clusters it chained
        // together. The structural half of the cap is the volume's whole directory capacity,
        // which a well-formed directory can never reach.
        let cap = self.limits.max_walk_entries.min(self.max_names());
        let charset = self.charset;
        let mut out: Vec<Entry> = Vec::new();
        let mut pending = LongName::default();
        let mut ended = false;
        let mut reported_after_end = false;
        let mut last_slot = None;

        self.for_each_slot::<ReadError>(node, |reader, slot| {
            let index = slot.index;
            let at = Location {
                sector: Some(slot.sector),
                cluster: None,
                entry: Some(index),
            };
            last_slot = Some((at, index));
            let entry = slot.entry;
            let first = entry.name[0];

            if ended {
                // Everything after the end marker should be free. A used slot there is
                // storage no reader reaches — including this one: every driver stops at the
                // marker, so yielding what is past it would show a caller names that nothing
                // else on the volume can see. It is reported once rather than once per slot,
                // and never handed back.
                if first != NAME_END && !reported_after_end {
                    deviations.record(at, ReadError::EntriesAfterEnd { index })?;
                    reported_after_end = true;
                }
                return Ok(ControlFlow::Continue(()));
            }
            if first == NAME_END {
                // A run still in flight at the end marker decorated nothing: the marker
                // says the names are over, so the run's slots are storage no driver reads
                // a name out of.
                if !matches!(pending.take(), LongRun::None) {
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                ended = true;
                return Ok(ControlFlow::Continue(()));
            }
            if first == NAME_DELETED {
                // The classic shape of this corruption: the short entry was deleted and
                // its long-name slots were not, so the run in flight belongs to nothing.
                if !matches!(pending.take(), LongRun::None) {
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                return Ok(ControlFlow::Continue(()));
            }
            if entry.attributes.is_long_name() {
                let lfn = LfnEntry::read_from(&raw_bytes(&entry))?;
                if pending.accept(&lfn) {
                    // A fresh sequence start wiped a run still being assembled, whose
                    // slots now belong to nothing.
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                return Ok(ControlFlow::Continue(()));
            }

            // A short entry ends whatever run preceded it.
            let run = pending.take();
            let short_name = render_short(&entry.name, entry.case_flags);

            if entry.attributes.contains(DirAttributes::VOLUME_ID) {
                if !is_root {
                    deviations.record(at, ReadError::MisplacedVolumeLabel { index })?;
                }
                // A run in front of the label belongs to nothing: the format hangs a long
                // name off an ordinary entry alone, and the label is not a name in the
                // tree under any circumstances.
                if !matches!(run, LongRun::None) {
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                return Ok(ControlFlow::Continue(()));
            }
            // The dot entries, recognized by the field the format defines them in. A run of
            // long-name entries in front of one decorates nothing: what the format says
            // sits in these two slots is a directory's link to itself and to its parent,
            // and a name hung off one of them is not an entry the directory holds. The
            // *name* is rightly dropped; the slots are the same debris they are in front
            // of the label one arm above, and are reported the same way.
            if crate::path::is_dot_entry(&short_name) {
                if !matches!(run, LongRun::None) {
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                return Ok(ControlFlow::Continue(()));
            }

            let mut has_long_name = false;
            let mut name = None;
            match run {
                LongRun::None => {}
                LongRun::Incomplete => {
                    deviations.record(at, ReadError::OrphanedLongName { index })?;
                }
                LongRun::Complete { units, checksum } => {
                    let expected = entry.lfn_checksum();
                    if checksum != expected {
                        deviations.record(
                            at,
                            ReadError::LongNameChecksum {
                                index,
                                found: checksum,
                                expected,
                            },
                        )?;
                    } else {
                        // Twenty entries carry up to 260 units and the format caps a name
                        // at 255, so a run can be whole and still hold a name no volume of
                        // this family should carry — one this crate's own writer refuses.
                        // The name is read anyway, so the tree stays enumerable.
                        if units.len() > super::name::MAX_NAME_UNITS {
                            deviations.record(
                                at,
                                ReadError::LongNameTooLong {
                                    index,
                                    units: units.len(),
                                },
                            )?;
                        }
                        let (decoded, ill_formed) = decode_utf16(&units);
                        if ill_formed {
                            deviations.record(at, ReadError::IllFormedLongName { index })?;
                        }
                        has_long_name = true;
                        name = Some(decoded);
                    }
                }
            }

            let name = match name {
                Some(name) => name,
                None => {
                    // Falling back to the short name is where its code page matters, so the
                    // deviation is raised for the name that is actually handed back.
                    if let Some(byte) = short_name.iter().copied().find(|b| *b >= 0x80) {
                        let err = ReadError::UninterpretedShortName { index, byte };
                        // Naming a charset is what makes the bytes recognized, so the same
                        // volume is a conformance deviation under `Verbatim` and a cosmetic
                        // remark once a caller has said how to read it.
                        if charset == ShortNameCharset::Verbatim {
                            deviations.record(at, err)?;
                        } else {
                            let mut anomaly = err.anomaly();
                            anomaly.severity = Severity::Cosmetic;
                            anomaly.detail = format!(
                                "the short name at entry {index} carries byte {byte:#04x}, \
                                 above ASCII, read as code page {}",
                                charset.as_str()
                            );
                            if let OnDeviation::Collect(findings) = deviations {
                                anomaly.location = anomaly.location.or(at);
                                findings.push(anomaly);
                            }
                        }
                    }
                    charset.decode(&short_name)
                }
            };

            // The resolved name is what a caller receives and what a path is built from, so
            // it is where a name no directory can hold is refused. Either field reaches it,
            // and a long-name run reaches it past every test above: the run is reassembled
            // after the dot entries are recognized by their name field, so one spelling `..`
            // belongs to an ordinary short entry and is well-formed in every other way.
            // Refusing it here keeps the four names out of every surface at once — the entry
            // list, a walk's paths, and an archive built from them.
            if is_hostile_component(&name) {
                deviations.record(at, ReadError::HostileName { index })?;
                return Ok(ControlFlow::Continue(()));
            }

            check_times(&entry, index, at, deviations)?;

            // The two fields an entry describes its contents with, held against each other
            // where they are read. FAT has no holes, so a length is a claim about clusters and
            // a first cluster below two says there are none — and the disagreement is invisible
            // to everything downstream: the storage the node carries is the same `None` a
            // legitimately empty file has, so the scan's size-against-chain comparison has no
            // chain to make it against and a read fails much later, at the cluster it cannot
            // follow.
            let node = node_of(&entry, reader.layout.fat_type);
            if node.size != 0 && matches!(node.storage, Storage::None) {
                deviations.record(
                    at,
                    ReadError::SizeWithoutAllocation {
                        index,
                        size: node.size,
                    },
                )?;
            }

            if out.len() >= cap {
                return Err(ReadError::WalkTooLarge { limit: cap });
            }
            out.push(Entry {
                name,
                short_name: charset.decode(&short_name),
                has_long_name,
                node,
            });
            Ok(ControlFlow::Continue(()))
        })?;
        // The fifth way a run can end: the storage itself runs out, on a directory whose
        // every slot is used and whose last slots are the run. The finding sits at the
        // run's last slot, which is the last slot there was.
        if !matches!(pending.take(), LongRun::None)
            && let Some((at, index)) = last_slot
        {
            deviations.record(at, ReadError::OrphanedLongName { index })?;
        }
        Ok(out)
    }

    /// Resolve `path` against the volume's own root.
    ///
    /// Components are matched exactly first and, failing that, without regard to the case of
    /// their ASCII letters — which is how every FAT driver finds a name, since the eleven-byte
    /// short name field is upper case by construction and a long name preserves a case no
    /// driver requires a caller to reproduce. Bytes above ASCII are compared as they stand,
    /// because folding them would need the code page the volume does not record.
    ///
    /// A `..` component ascends to the directory the resolution descended from, staying at the
    /// root where there is nothing to ascend to — so nothing outside the volume can be named.
    /// It is an ascent rather than a lookup of the entry of that name, which a FAT
    /// subdirectory carries and this reader refuses as a name.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotFound`] where no component matches, [`ReadError::NotADirectory`]
    /// where the path traverses through a file, and the read errors of the directories along
    /// the way.
    pub fn lookup(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        crate::resolve::drive(self, path, true)
    }

    // -- file contents ----------------------------------------------------------------

    /// Fill `buf` from `offset` in a regular file, returning how many bytes were placed.
    ///
    /// A short fill means the file ends there. A node that is not a regular file holds no
    /// bytes and yields none: a directory's storage is its entries, and handing those back
    /// as file contents would be a directory entry read as data.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants where the chain cannot be followed.
    pub fn read_into(
        &mut self,
        node: &Node,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        if node.is_dir() || node.is_volume_label() {
            return Ok(0);
        }
        let Storage::Chain(start) = node.storage else {
            return Ok(0);
        };
        let size = u64::from(node.size);
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster());
        let want = buf.len().min((size - offset) as usize);
        let mut done = 0usize;
        while done < want {
            let at = offset + done as u64;
            let index = at / bytes_per_cluster;
            let within = (at % bytes_per_cluster) as usize;
            let Some(cluster) = self.cluster_at(start, index)? else {
                // The chain ran out with bytes still to come, which is the length and the
                // allocation disagreeing. What is reported is the byte this read needed:
                // a read from an offset lands here without walking the earlier clusters,
                // so where exactly the chain ends is not known — only that it ends before
                // the byte that was asked for.
                return Err(ReadError::ChainTooShort {
                    start,
                    size,
                    read: at,
                });
            };
            let bytes = self.read_cluster(cluster)?;
            let take = (bytes.len() - within).min(want - done);
            buf[done..done + take].copy_from_slice(&bytes[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// A file's length as a whole-file read sees it: the length its directory entry records,
    /// held to [`Limits::max_file_bytes`].
    ///
    /// Every whole-file form goes through this, so the cap governs what a read hands back and
    /// what a stream into a caller's writer produces alike. Nothing accumulates in the second
    /// of those, which is exactly why it needs the cap named here: what it *writes* follows
    /// the length the image declares rather than the working memory it uses.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] if the length exceeds the cap.
    fn whole_file_len(&self, node: &Node) -> Result<u64, ReadError> {
        let size = u64::from(node.size);
        if size > self.limits.max_file_bytes {
            return Err(ReadError::FileTooLarge {
                size,
                limit: self.limits.max_file_bytes,
            });
        }
        Ok(size)
    }

    /// Stream a file's whole contents into `out`, returning how many bytes were written.
    ///
    /// Nothing accumulates, so a file of any size costs one cluster of working memory.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the length exceeds [`Limits::max_file_bytes`],
    /// [`ReadError`] variants where the chain cannot be followed,
    /// [`ReadError::ChainTooShort`] where it ends before the length the entry records, and
    /// whatever `out` returns.
    pub fn read_data_to(&mut self, node: &Node, mut out: impl Write) -> Result<u64, ReadError> {
        if node.is_dir() || node.is_volume_label() {
            return Ok(0);
        }
        let size = self.whole_file_len(node)?;
        let mut buf = vec![0u8; self.layout.bytes_per_cluster() as usize];
        let mut done = 0u64;
        while done < size {
            let want = buf.len().min((size - done) as usize);
            let got = self.read_into(node, done, &mut buf[..want])?;
            if got == 0 {
                return Err(ReadError::ChainTooShort {
                    start: match node.storage {
                        Storage::Chain(start) => start,
                        _ => 0,
                    },
                    size,
                    read: done,
                });
            }
            out.write_all(&buf[..got])?;
            done += got as u64;
        }
        Ok(done)
    }

    /// A file's whole contents.
    ///
    /// The buffer grows as bytes arrive rather than being sized from the length field up
    /// front, so a crafted length costs nothing beyond the bytes the volume actually holds.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the length exceeds
    /// [`Limits::max_file_bytes`], and the errors of
    /// [`read_data_to`](Self::read_data_to).
    pub fn read_data(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        let mut out = Vec::new();
        self.read_data_to(node, &mut out)?;
        Ok(out)
    }

    // -- walking ----------------------------------------------------------------------

    /// Every name in the tree, depth-first, a parent before its children.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if any directory along the walk cannot be read, and
    /// [`ReadError::WalkTooLarge`] if the tree holds more names than the bounds allow.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, ReadError> {
        let mut out = Vec::new();
        self.walk_with::<ReadError>(|_, entry| {
            out.push(entry);
            Ok(())
        })?;
        Ok(out)
    }

    /// Walk the whole tree, handing each [`WalkEntry`] to `visit` as it is reached rather
    /// than gathering them all first.
    ///
    /// `visit` receives the reader itself, so it may read each entry's contents as it goes.
    /// The error type is the consumer's, and the walk's own [`ReadError`]s convert into it,
    /// so a consumer's failure and the volume's each reach the caller as themselves.
    ///
    /// What the walk holds is the frontier — the names reached and not yet visited — rather
    /// than the tree, so a tree far larger than memory is walked without accumulating it.
    /// The frontier answers to the same bound the walk does: the names it holds count
    /// against [`Limits::max_walk_entries`](crate::Limits::max_walk_entries) and the volume's
    /// own directory capacity as the names already visited do.
    ///
    /// # Errors
    ///
    /// Whatever `visit` returns, or the [`walk`](Self::walk) errors converted into it.
    pub fn walk_with<E: From<ReadError>>(
        &mut self,
        mut visit: impl FnMut(&mut Self, WalkEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        crate::walk::drive(self, |reader, entry| visit(reader, entry))
    }

    /// The child entries of `node` in reverse name order, so a stack pops them in order.
    ///
    /// Every name here is one a directory can hold: [`parse_dir`](Self::parse_dir) is the one
    /// place an entry's bytes become a name, and it refuses the four that are not rather than
    /// handing one back for a path to be built from.
    fn walk_children(&mut self, node: &Node, prefix: &[u8]) -> Result<Vec<WalkEntry>, ReadError> {
        let mut entries = self.read_dir(node)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut children = Vec::new();
        for e in entries.iter().rev() {
            let path = crate::walk::child_path(prefix, &e.name)
                .ok_or(ReadError::PathTooLong { limit: MAX_PATH })?;
            children.push(WalkEntry { path, node: e.node });
        }
        Ok(children)
    }

    /// The most names the volume's own storage could hold, which bounds a walk regardless
    /// of what a caller asked for.
    ///
    /// Every name spends at least one 32-byte slot, and every slot is in the root region or
    /// in a cluster, so the volume's directory capacity is a hard ceiling that a well-formed
    /// tree can never reach.
    fn max_names(&self) -> usize {
        let root = u64::from(self.layout.root_entries);
        let data = u64::from(self.layout.clusters) * u64::from(self.layout.bytes_per_cluster())
            / DIR_ENTRY_SIZE as u64;
        usize::try_from(root.saturating_add(data)).unwrap_or(usize::MAX)
    }

    // -- verification -----------------------------------------------------------------

    /// Check every copy of the file allocation table against the first.
    ///
    /// This is what a FAT volume has instead of a checksum. Two copies of one allocation
    /// record that disagree mean at least one of them is wrong, and nothing in the volume
    /// says which — so the disagreement is the finding.
    ///
    /// A volume whose mirroring is switched off in `BPB_ExtFlags` keeps only one table live
    /// and the others are not obliged to agree, so nothing is compared and the fact is
    /// reported instead.
    ///
    /// # Errors
    ///
    /// [`ReadError::TableMismatch`] at the first entry two copies disagree about,
    /// [`ReadError::TablePaddingMismatch`] where they differ only past the last entry, and
    /// [`ReadError::Io`] where a table cannot be read.
    pub fn verify_tables(&mut self) -> Result<(), ReadError> {
        match self.table_faults()?.into_iter().next() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Every way the copies of the table disagree, in the order found.
    fn table_faults(&mut self) -> Result<Vec<ReadError>, ReadError> {
        let mut out = Vec::new();
        if self.mirroring_disabled() || self.layout.fats < 2 {
            return Ok(out);
        }
        let fat_type = self.layout.fat_type;
        let sectors = self.layout.fat_sectors;
        let bytes_per_sector = self.layout.bytes_per_sector;
        // Where the entries stop and the formatter's padding begins: one past the last byte
        // the highest cluster's entry touches. The highest cluster *number* is one past the
        // count, and on FAT12 its entry may end in the low nibble of a byte it shares — so
        // the bound is the entry's span rather than the next entry's offset, which on that
        // width is a byte short whenever the highest cluster is even.
        let highest = self.layout.clusters + 1;
        let live_bytes = table::entry_offset(fat_type, highest) + table::entry_span(fat_type);

        for copy in 1..self.layout.fats {
            let mut padding_only = false;
            let mut found = false;
            // Both tables exist: `copy` is below the count and zero always is, so the
            // placement is the layout's rather than something to fall back from.
            let (Some(first_start), Some(copy_start)) = (
                self.layout.fat_start_sector(0),
                self.layout.fat_start_sector(copy),
            ) else {
                continue;
            };
            // Compared a batch of sectors at a time rather than one: the copies of a
            // maximal FAT32 table span megabytes, and a seek and an allocation per
            // 512-byte sector on each side turns one comparison into millions of round
            // trips. A mebibyte per side bounds the memory whatever the table's size.
            let batch = (1u32 << 20) / bytes_per_sector.max(1);
            let mut s = 0u32;
            while s < sectors {
                let count = batch.clamp(1, sectors - s);
                let a = self.read_sectors(first_start + s, count)?;
                let b = self.read_sectors(copy_start + s, count)?;
                if a == b {
                    s += count;
                    continue;
                }
                let base = u64::from(s) * u64::from(bytes_per_sector);
                let at = a
                    .iter()
                    .zip(b.iter())
                    .position(|(x, y)| x != y)
                    .expect("the batches differ") as u64
                    + base;
                if at >= live_bytes {
                    padding_only = true;
                    s += count;
                    continue;
                }
                // The cluster whose entry that byte belongs to. Every width divides the
                // offset the same way its own packing does — except the middle byte of a
                // FAT12 pair, which two entries share: its low nibble is the even one's top
                // four bits and its high nibble is the odd one's bottom four. Both are
                // candidates there, and the finding names whichever actually differs, so a
                // consumer repairing by cluster number repairs the entry that is wrong.
                let (candidate, shared) = match fat_type {
                    FatType::Fat12 => {
                        let even = (at * 2 / 3) as u32;
                        let odd = (at % 3 == 1 && even < highest).then_some(even + 1);
                        (even, odd)
                    }
                    FatType::Fat16 => ((at / 2) as u32, None),
                    FatType::Fat32 => ((at / 4) as u32, None),
                };
                let mut mismatch = None;
                for cluster in [Some(candidate), shared].into_iter().flatten() {
                    let first = self.table_entry_in(0, cluster)?;
                    let other = self.table_entry_in(copy, cluster)?;
                    if first != other {
                        mismatch = Some((cluster, first, other));
                        break;
                    }
                }
                // Every bit of a differing byte belongs to one of the candidates, so one of
                // them differs. The fallback keeps the report total rather than describing a
                // case that can arise.
                let (cluster, first, other) = match mismatch {
                    Some(found) => found,
                    None => (
                        candidate,
                        self.table_entry_in(0, candidate)?,
                        self.table_entry_in(copy, candidate)?,
                    ),
                };
                out.push(ReadError::TableMismatch {
                    copy,
                    cluster,
                    first,
                    other,
                });
                found = true;
                break;
            }
            if !found && padding_only {
                out.push(ReadError::TablePaddingMismatch { copy });
            }
        }
        Ok(out)
    }

    /// The entry for `cluster` in copy `index` of the table, read without the window.
    ///
    /// The window is [`table_entry`](Self::table_entry)'s optimization for a chain walk,
    /// which reads one copy repeatedly; this reads each copy once per differing byte, so it
    /// keeps nothing. What it does keep is that function's bounds — the same ceiling on the
    /// entry, and the same refusal to read past this copy's own end — because the two are
    /// compared against each other and a value only one of them would splice together is not
    /// a disagreement between the copies.
    fn table_entry_in(&mut self, index: u32, cluster: u32) -> Result<u32, ReadError> {
        let fat_type = self.layout.fat_type;
        if cluster >= self.layout.max_table_entries() {
            return Err(ReadError::ClusterOutOfRange { cluster });
        }
        let offset = table::entry_offset(fat_type, cluster);
        let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
        let sector_in_table = u32::try_from(offset / bytes_per_sector)
            .map_err(|_| ReadError::ClusterOutOfRange { cluster })?;
        let within = (offset % bytes_per_sector) as usize;
        let first = self
            .layout
            .fat_start_sector(index)
            .ok_or(ReadError::ClusterOutOfRange { cluster })?;
        let sector = first
            .checked_add(sector_in_table)
            .ok_or(ReadError::ClusterOutOfRange { cluster })?;
        let count = self.table_window_sectors(sector_in_table);
        let bytes = self.read_sectors(sector, count)?;
        let raw = table::read_entry(fat_type, &bytes[within..], 0)
            .ok_or(ReadError::ClusterOutOfRange { cluster })?;
        if fat_type == FatType::Fat12 && cluster & 1 == 1 {
            Ok(u32::from(get_u16(&bytes, within)) >> 4)
        } else {
            Ok(raw)
        }
    }

    /// Whether the parameter block says only one table is live.
    const fn mirroring_disabled(&self) -> bool {
        match self.boot.tail {
            BootSectorTail::Fat32 { params, .. } => params.ext_flags & 0x0080 != 0,
            BootSectorTail::Fat1216 { .. } => false,
        }
    }

    /// The copy of the file allocation table every chain is resolved through.
    ///
    /// `BPB_ExtFlags` bit 7 switches mirroring off; when it is set, bits 0-3 name the one
    /// copy the driver maintains and the rest are stale by design. Following a stale copy
    /// yields a different tree and different file bytes from the ones a conformant driver
    /// returns — and silently, because the mirror check is suppressed on exactly these
    /// volumes, so the disagreement that would otherwise be reported is not there to see.
    ///
    /// With mirroring on, every copy is held identical and copy 0 is as good as any. FAT12
    /// and FAT16 have no such field and always mirror.
    ///
    /// A named copy the volume does not have is incoherent, and there is nothing to resolve
    /// through a table that is not there — so copy 0 is read and [`scan`](Self::scan)
    /// reports the field. Refusing the volume outright would make a one-nibble fault
    /// unreadable where a driver still reads it.
    const fn active_fat(&self) -> u32 {
        match self.boot.tail {
            BootSectorTail::Fat32 { params, .. } if params.ext_flags & 0x0080 != 0 => {
                let index = (params.ext_flags & 0x000F) as u32;
                if index < self.layout.fats { index } else { 0 }
            }
            _ => 0,
        }
    }

    // -- the scan ---------------------------------------------------------------------

    /// Walk the whole volume, collecting every deviation from what this crate's writer
    /// emits rather than stopping at the first.
    ///
    /// The parameter block, the backup boot sector, the information sector, every copy of
    /// the file allocation table, every directory entry, every cluster chain, and the
    /// clusters that are allocated and reached by nothing. Nothing here fails: a scan
    /// describes a volume rather than accepting or refusing it, and
    /// [`ScanReport::has_fatal`] applies a policy's threshold afterwards.
    ///
    /// **Memory.** Reaching the lost-cluster question needs one bit per cluster, which is a
    /// thirty-second of one copy of the table on any volume — so a scan's working set is
    /// bounded by the volume's own geometry and is small beside the structure it is reading.
    /// The count itself is held at open to what the type addresses, so the ceiling is
    /// [`MAX_CLUSTERS_FAT32`](crate::fat::MAX_CLUSTERS_FAT32) bits — 32 MiB, against the
    /// gibibyte of table a volume that large has to carry. Everything else a scan holds is a
    /// sector, a cluster, or one directory's entries.
    #[must_use]
    pub fn scan(&mut self) -> ScanReport {
        let mut findings = Findings::new(self.limits.max_findings);
        for anomaly in self.open_anomalies.clone() {
            findings.push(anomaly);
        }
        self.scan_reserved(&mut findings);
        self.scan_tables(&mut findings);
        let reached = self.scan_tree(&mut findings);
        if let Some(reached) = reached {
            self.scan_lost(&mut findings, &reached);
        }
        findings.into_report(self.layout.bytes_per_sector)
    }

    /// The backup boot sector and the information sector, on the type that has them.
    fn scan_reserved(&mut self, findings: &mut Findings<Anomaly>) {
        let Some(fat32) = self.layout.fat32 else {
            return;
        };
        // `BPB_FSVer` is the field a driver reads to decide whether it understands the
        // volume at all: zero is the only version ever defined, and neither Windows nor
        // Linux mounts anything else. A volume carrying another value is one no driver will
        // touch, so a read that said nothing about it would open and scan clean an image
        // that in practice does not exist — against the promise to name the deviation.
        if let BootSectorTail::Fat32 { params, .. } = self.boot.tail
            && params.version != 0
        {
            findings.push(Anomaly {
                severity: Severity::Conformance,
                category: Category::BootSector,
                location: Location::default(),
                detail: format!(
                    "BPB_FSVer is {:#06x}: zero is the only FAT32 version defined, and a \
                     driver refuses a volume whose version it does not know",
                    params.version
                ),
            });
        }
        if let Some(backup) = fat32.backup_boot_sector {
            let backup = u32::from(backup);
            match (self.read_sectors(0, 1), self.read_sectors(backup, 1)) {
                (Ok(primary), Ok(copy)) => {
                    if primary != copy {
                        findings
                            .push(ReadError::BackupBootSectorDiffers { sector: backup }.anomaly());
                    }
                }
                (Err(e), _) | (_, Err(e)) => findings.push(e.anomaly()),
            }
        }
        // The bottom half of the trailing signature, which is two zero bytes. The parser does
        // not require the signature because its top half duplicates the boot signature and a
        // foreign tool may have written that for reasons of its own — an argument that
        // reaches exactly those two bytes and not these. Nothing accounts for a value here,
        // so it is remarked on; the field is inert, so it is a remark and not a fault.
        let info_sector = u32::from(fat32.fs_info_sector);
        if let Ok(bytes) = self.read_sectors(info_sector, 1)
            && let Some(low) = bytes
                .get(FsInfo::TRAIL_OFFSET..FsInfo::TRAIL_OFFSET + 2)
                .map(|b| get_u16(b, 0))
            && low != 0
        {
            findings.push(Anomaly {
                severity: Severity::Cosmetic,
                category: Category::InfoSector,
                location: Location {
                    sector: Some(info_sector),
                    ..Location::default()
                },
                detail: format!(
                    "the information sector's trailing signature carries {low:#06x} where the \
                     format defines two zero bytes"
                ),
            });
        }
        match self.info_sector() {
            Ok(Some(info)) => {
                // Both counts are hints a driver may leave stale, so a stale one is a
                // remark rather than a fault — but it is worth remarking on, because this
                // crate's writer leaves both accurate.
                if let Some(next) = info.next_free_cluster
                    && next >= self.layout.clusters + 2
                {
                    findings.push(Anomaly {
                        severity: Severity::Cosmetic,
                        category: Category::InfoSector,
                        location: Location {
                            sector: Some(u32::from(fat32.fs_info_sector)),
                            cluster: Some(next),
                            entry: None,
                        },
                        detail: format!(
                            "the next-free hint names cluster {next}, which this volume does \
                             not have"
                        ),
                    });
                }
                if let Some(free) = info.free_clusters
                    && free > self.layout.clusters
                {
                    findings.push(Anomaly {
                        severity: Severity::Cosmetic,
                        category: Category::InfoSector,
                        location: Location {
                            sector: Some(u32::from(fat32.fs_info_sector)),
                            ..Location::default()
                        },
                        detail: format!(
                            "the free-cluster hint is {free}, more clusters than this volume's \
                             {}",
                            self.layout.clusters
                        ),
                    });
                }
            }
            Ok(None) => {}
            Err(e) => findings.push(e.anomaly()),
        }
    }

    /// The reserved entries of the table, and every copy against the first.
    fn scan_tables(&mut self, findings: &mut Findings<Anomaly>) {
        let fat_type = self.layout.fat_type;
        let expected_media = table::media_entry(fat_type, self.boot.media);
        let expected_tail = table::tail_entry(fat_type);
        for (index, expected) in [(0u32, expected_media), (1, expected_tail)] {
            match self.table_entry(index) {
                Ok(found) if found != expected => findings.push(
                    ReadError::BadReservedEntry {
                        index,
                        found,
                        expected,
                    }
                    .anomaly(),
                ),
                Ok(_) => {}
                Err(e) => findings.push(e.anomaly()),
            }
        }
        if self.mirroring_disabled() {
            let named = match self.boot.tail {
                BootSectorTail::Fat32 { params, .. } => u32::from(params.ext_flags & 0x000F),
                BootSectorTail::Fat1216 { .. } => 0,
            };
            findings.push(Anomaly {
                severity: Severity::Conformance,
                category: Category::AllocationTable,
                location: Location::default(),
                detail: format!(
                    "BPB_ExtFlags switches mirroring off, so only table {named} is live and \
                     the copies are not obliged to agree"
                ),
            });
            // A live copy the volume does not have leaves nothing to resolve chains
            // through. Reads fall back to copy 0, which is a different table from the one
            // the volume names, so the fault is reported at the weight of a wrong read
            // rather than as a cosmetic field.
            if named >= self.layout.fats {
                findings.push(Anomaly {
                    severity: Severity::Integrity,
                    category: Category::AllocationTable,
                    location: Location::default(),
                    detail: format!(
                        "BPB_ExtFlags names table {named} as the live one, but the volume \
                         has {} — chains are resolved through table 0 instead",
                        self.layout.fats
                    ),
                });
            }
            return;
        }
        match self.table_faults() {
            Ok(faults) => {
                for fault in faults {
                    findings.push(fault.anomaly());
                }
            }
            Err(e) => findings.push(e.anomaly()),
        }
    }

    /// Every directory and every chain, returning the clusters the tree reaches.
    ///
    /// `None` where the walk did not finish — because the findings cap was reached or a
    /// walk bound was — in which case the lost-cluster question has no answer, since every
    /// cluster the walk never got to would look unreachable. A count derived from a partial
    /// traversal reads as a fact and is not one, so it is not produced at all.
    fn scan_tree(&mut self, findings: &mut Findings<Anomaly>) -> Option<ClusterSet> {
        let mut reached = ClusterSet::new(self.layout.clusters);
        // The directories this walk has descended into, in the same set the clusters it has
        // claimed are held in: both questions are "which clusters has this been to", over the
        // volume's own cluster numbers, and a second structure over them would be a second
        // answer to keep in step.
        let mut visited = ClusterSet::new(self.layout.clusters);
        let mut queue = vec![(Vec::new(), self.root())];
        if let Storage::Chain(start) = self.root().storage {
            visited.insert(start);
        }
        let mut names = 0usize;
        let cap = self.limits.max_walk_entries.min(self.max_names());

        while let Some((path, node)) = queue.pop() {
            if findings.is_full() {
                // The tree is not fully walked, so the clusters it did not reach are not
                // evidence of anything. Saying so is the only honest answer: the
                // alternative is a lost-cluster count computed from a partial traversal,
                // which is a number that reads as a fact and is not one.
                return None;
            }
            // The node's own chain, claimed cluster by cluster so a second claim is a
            // cross-link rather than a second traversal.
            let claimed = self.claim_chain(&node, &path, &mut reached, findings);
            if node.is_dir() {
                let mut deviations = OnDeviation::Collect(findings);
                let entries = match self.parse_dir(&node, &mut deviations) {
                    Ok(entries) => entries,
                    // A directory that alone holds more names than the bound allows stops
                    // the traversal for the same reason the running count below does: what
                    // was not reached is not evidence, and a lost-cluster count taken from a
                    // partial walk reads as a fact and is not one.
                    Err(e @ ReadError::WalkTooLarge { .. }) => {
                        findings.push(e.anomaly());
                        return None;
                    }
                    Err(e) => {
                        findings.push(e.anomaly());
                        continue;
                    }
                };
                self.check_dots(&node, &path, findings);
                for entry in entries {
                    names += 1;
                    if names > cap {
                        findings.push(ReadError::WalkTooLarge { limit: cap }.anomaly());
                        // Likewise: a walk that stopped short reached fewer clusters than
                        // the tree owns, and every one it did not reach would be reported
                        // as allocated and unreferenced.
                        return None;
                    }
                    let mut child = path.clone();
                    child.push(b'/');
                    child.extend_from_slice(&entry.name);
                    let descend = match entry.node.storage {
                        Storage::Chain(start) if entry.node.is_dir() => visited.insert(start),
                        _ => false,
                    };
                    if descend || !entry.node.is_dir() {
                        queue.push((child, entry.node));
                    }
                }
            } else if let Some(chain_bytes) = claimed {
                // A file's length is a claim about its clusters, and FAT has no holes, so
                // the two disagreeing is worth saying even where every cluster reads. This
                // compares a length against a chain and so needs one: the shape with no chain
                // at all is `SizeWithoutAllocation`, raised where the entry is parsed.
                let size = u64::from(node.size);
                let bpc = u64::from(self.layout.bytes_per_cluster());
                let need = size.div_ceil(bpc.max(1)) * bpc;
                if chain_bytes != need {
                    findings.push(Anomaly {
                        severity: Severity::Conformance,
                        category: Category::AllocationTable,
                        location: Location::default(),
                        detail: format!(
                            "{}: a length of {size} bytes needs {need} bytes of clusters and \
                             its chain holds {chain_bytes}",
                            crate::escape::printable(&path)
                        ),
                    });
                }
            }
        }
        Some(reached)
    }

    /// Follow one node's chain, marking each cluster reached and reporting a cluster two
    /// chains both claim. Returns the bytes the chain holds, where it could be followed.
    fn claim_chain(
        &mut self,
        node: &Node,
        path: &[u8],
        reached: &mut ClusterSet,
        findings: &mut Findings<Anomaly>,
    ) -> Option<u64> {
        let Storage::Chain(start) = node.storage else {
            return None;
        };
        let mut current = start;
        let mut count = 0u64;
        let mut own = std::collections::HashSet::new();
        loop {
            if !reached.insert(current) {
                // Whose claim is repeated decides what the finding says: a cluster this
                // walk already stepped through is the chain looping onto itself, and one
                // another walk claimed is two chains sharing storage. Blaming "another
                // chain" for a loop would send a reader hunting for a second file that
                // does not exist.
                let detail = if own.contains(&current) {
                    format!(
                        "{}: the chain from cluster {start} returns to cluster {current}, \
                         and a chain that loops never ends",
                        crate::escape::printable(path)
                    )
                } else {
                    format!(
                        "{}: cluster {current} is already part of another chain",
                        crate::escape::printable(path)
                    )
                };
                findings.push(Anomaly {
                    severity: Severity::Structural,
                    category: Category::AllocationTable,
                    location: Location {
                        cluster: Some(current),
                        ..Location::default()
                    },
                    detail,
                });
                return None;
            }
            own.insert(current);
            count += 1;
            if count > u64::from(self.layout.clusters) {
                findings.push(
                    ReadError::ChainTooLong {
                        start,
                        clusters: self.layout.clusters,
                    }
                    .anomaly(),
                );
                return None;
            }
            match self.next_cluster(current) {
                Ok(Some(next)) => current = next,
                Ok(None) => break,
                Err(e) => {
                    findings.push(e.anomaly());
                    return None;
                }
            }
        }
        Some(count * u64::from(self.layout.bytes_per_cluster()))
    }

    /// A subdirectory's `.` and `..`, which the format requires as its first two entries.
    fn check_dots(&mut self, node: &Node, path: &[u8], findings: &mut Findings<Anomaly>) {
        if path.is_empty() {
            return; // the root has neither, on any type
        }
        // Only the first two slots decide this, so the read stops there rather than walking
        // the whole directory to look at its beginning.
        let mut first_two: [Option<[u8; 11]>; 2] = [None, None];
        let read = self.for_each_slot::<ReadError>(node, |_, slot| {
            let Some(cell) = first_two.get_mut(slot.index as usize) else {
                return Ok(ControlFlow::Break(()));
            };
            *cell = Some(slot.entry.name);
            Ok(if slot.index == 1 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        });
        if let Err(e) = read {
            findings.push(e.anomaly());
            return;
        }
        for (index, expected) in [(0usize, &b".          "[..]), (1, &b"..         "[..])] {
            let found = first_two[index].as_ref().map(|n| &n[..]);
            if found != Some(expected) {
                findings.push(
                    ReadError::BadDotEntry {
                        detail: format!(
                            "{}: entry {index} is {} where the format requires {}",
                            crate::escape::printable(path),
                            // Quoted rather than passed through `Debug`, which would escape
                            // the escaping's own backslashes a second time.
                            found.map_or("absent".to_string(), |n| {
                                format!("\"{}\"", crate::escape::printable(n))
                            }),
                            crate::escape::printable(expected).trim_end(),
                        ),
                    }
                    .anomaly(),
                );
            }
        }
    }

    /// Clusters the table marks allocated that no chain reached.
    fn scan_lost(&mut self, findings: &mut Findings<Anomaly>, reached: &ClusterSet) {
        let fat_type = self.layout.fat_type;
        let bad = table::bad_cluster(fat_type);
        let mut count = 0u32;
        let mut first = None;
        for cluster in 2..self.layout.clusters + 2 {
            let entry = match self.table_entry(cluster) {
                Ok(entry) => entry,
                // A table that cannot be read past here has already been reported by
                // whatever tried to follow a chain through it.
                Err(_) => break,
            };
            if entry == table::FREE || entry == bad || reached.contains(cluster) {
                continue;
            }
            count += 1;
            first.get_or_insert(cluster);
        }
        if let Some(first) = first {
            findings.push(ReadError::LostClusters { count, first }.anomaly());
        }
    }
}

/// One 32-byte slot of a directory, with where it sits: its index within the directory, and
/// the sector holding it.
struct Slot {
    entry: DirEntry,
    index: u32,
    sector: u32,
}

/// A dense set over the volume's clusters, one bit each.
///
/// Sized from the count the parameter block reaches, which is a bound rather than a claim:
/// the geometry refuses a count above what the type addresses and one whose sectors do not
/// fit in the source, so the widest set this reaches is
/// [`MAX_CLUSTERS_FAT32`](super::geometry::MAX_CLUSTERS_FAT32) bits — a thirty-second of the
/// one copy of the table such a volume must carry to describe those clusters at all.
///
/// This is the one answer to "which clusters has this been to", and every question of that
/// shape asks it: the chain a directory follows, the directories a scan has descended into,
/// and the clusters a scan has claimed. The domain is the same in all three — a cluster number
/// of this volume — and a second structure over it would be a second answer to keep in step.
struct ClusterSet {
    bits: Vec<u64>,
    clusters: u32,
}

impl ClusterSet {
    fn new(clusters: u32) -> Self {
        // Clusters number from 2, so the set is sized for the highest number rather than
        // for the count.
        let highest = clusters as usize + 2;
        Self {
            bits: vec![0u64; highest.div_ceil(64)],
            clusters,
        }
    }

    /// Add `cluster`, answering whether it was not already there.
    fn insert(&mut self, cluster: u32) -> bool {
        if cluster < 2 || cluster - 2 >= self.clusters {
            return true;
        }
        let (word, bit) = (cluster as usize / 64, cluster as usize % 64);
        let was = self.bits[word] & (1 << bit) != 0;
        self.bits[word] |= 1 << bit;
        !was
    }

    fn contains(&self, cluster: u32) -> bool {
        if cluster < 2 || cluster - 2 >= self.clusters {
            return false;
        }
        self.bits[cluster as usize / 64] & (1 << (cluster as usize % 64)) != 0
    }
}

/// What a run of long-name entries came to.
enum LongRun {
    /// There was none.
    None,
    /// There was one and it is not a whole name.
    Incomplete,
    /// A whole name, and the checksum its entries claim to be for.
    Complete { units: Vec<u16>, checksum: u8 },
}

/// A run of long-name entries being assembled.
///
/// The entries sit immediately before their short entry and in reverse order, so the first
/// one a forward reader meets carries the name's last characters and is flagged as the last
/// in the sequence. Chunks are placed by their ordinal rather than appended, so a run whose
/// ordinals skip or repeat comes out incomplete rather than silently reordered.
#[derive(Default)]
struct LongName {
    chunks: Vec<Option<[u16; LFN_CHARS_PER_ENTRY]>>,
    checksum: Option<u8>,
    broken: bool,
}

impl LongName {
    fn clear(&mut self) {
        self.chunks.clear();
        self.checksum = None;
        self.broken = false;
    }

    /// Fold one entry into the run, answering whether a run still being assembled was
    /// discarded to start over.
    ///
    /// The last-in-sequence flag opens a new run whatever preceded it, so one arriving
    /// mid-run wipes what was in flight — slots that then belong to nothing, which is the
    /// caller's to report since only it knows where they sit.
    fn accept(&mut self, entry: &LfnEntry) -> bool {
        let ordinal = usize::from(entry.order & !LFN_LAST_ENTRY);
        let mut discarded = false;
        if entry.order & LFN_LAST_ENTRY != 0 {
            // The last in the sequence starts a new run, whatever preceded it.
            discarded = self.is_live();
            self.clear();
            if ordinal == 0 || ordinal > LFN_MAX_ENTRIES {
                self.broken = true;
                return discarded;
            }
            self.chunks = vec![None; ordinal];
            self.checksum = Some(entry.checksum);
        }
        if ordinal == 0 || ordinal > self.chunks.len() || self.checksum != Some(entry.checksum) {
            self.broken = true;
            return discarded;
        }
        if self.chunks[ordinal - 1].is_some() {
            self.broken = true;
            return discarded;
        }
        self.chunks[ordinal - 1] = Some(entry.name);
        discarded
    }

    /// Whether a run is being assembled: entries accepted and not yet taken.
    fn is_live(&self) -> bool {
        !self.chunks.is_empty() || self.broken
    }

    fn take(&mut self) -> LongRun {
        let run = if self.chunks.is_empty() && !self.broken {
            LongRun::None
        } else if self.broken || self.chunks.iter().any(Option::is_none) {
            LongRun::Incomplete
        } else {
            let mut units = Vec::with_capacity(self.chunks.len() * LFN_CHARS_PER_ENTRY);
            for chunk in self.chunks.iter().flatten() {
                units.extend_from_slice(chunk);
            }
            // A name shorter than the entries holding it is terminated by one zero and
            // padded after it; one that fills them exactly has neither.
            if let Some(end) = units.iter().position(|u| *u == 0) {
                units.truncate(end);
            }
            match self.checksum {
                Some(checksum) => LongRun::Complete { units, checksum },
                None => LongRun::Incomplete,
            }
        };
        self.clear();
        run
    }
}

/// A directory entry's bytes, for handing to the long-name parser.
///
/// A long-name entry and a short one occupy the same 32 bytes and differ only in how they
/// are read, so the short parse is undone and the bytes re-laid rather than the region being
/// read twice from the source.
fn raw_bytes(entry: &DirEntry) -> [u8; DIR_ENTRY_SIZE] {
    let mut buf = [0u8; DIR_ENTRY_SIZE];
    // The write cannot be short: the buffer is exactly the structure's size.
    let _ = entry.write_to(&mut buf);
    buf
}

/// Bit of a directory entry's byte 12 meaning the eight-character base is lower case.
const NT_LOWER_BASE: u8 = 0x08;

/// Bit of a directory entry's byte 12 meaning the three-character extension is lower case.
const NT_LOWER_EXT: u8 = 0x10;

/// The eleven-byte name field as a name: padding trimmed, the dot restored, the substituted
/// leading byte put back, and the case flags at byte 12 applied.
///
/// **The case flags are honoured here and never written.** Byte 12 is reserved by the
/// format's own specification, which says an implementation must never look at it, and
/// implementations take it at its word — Linux honours it under two of its four
/// `shortname=` settings and ignores it under the other two, and a minimal firmware driver
/// skips it entirely. So a name carried only there is `readme.txt` on one mount and
/// `README.TXT` on another, which is why this crate's writer gives every such name a
/// long-name run instead. Reading is the opposite call for the opposite reason: understanding
/// what somebody else wrote costs nothing, and a volume that used the flags meant the name
/// the flags describe.
///
/// The folding is over ASCII alone. A byte above ASCII has no case without the code page the
/// volume does not record, and inventing one would be a name the entry does not carry.
fn render_short(name: &[u8; 11], case_flags: u8) -> Vec<u8> {
    let fold = |bytes: &mut Vec<u8>, lower: bool| {
        if lower {
            bytes.make_ascii_lowercase();
        }
    };
    let mut base = name[..8].to_vec();
    while base.last() == Some(&b' ') {
        base.pop();
    }
    if base.first() == Some(&NAME_LEADING_E5) {
        base[0] = NAME_DELETED;
    }
    fold(&mut base, case_flags & NT_LOWER_BASE != 0);
    let mut ext = name[8..].to_vec();
    while ext.last() == Some(&b' ') {
        ext.pop();
    }
    fold(&mut ext, case_flags & NT_LOWER_EXT != 0);
    if ext.is_empty() {
        base
    } else {
        base.push(b'.');
        base.extend_from_slice(&ext);
        base
    }
}

/// The volume label an eleven-byte name field holds.
///
/// Three things separate this from the field's plain padding rule
/// ([`unpadded`](crate::fat::ondisk::unpadded)), which is why it is its own function rather
/// than a call to that one. A label has no dot and no extension, so the eleven bytes are one
/// field rather than a base and a three-byte tail. A NUL is trimmed here as well as a space,
/// because a formatter that filled the field with either wrote the same label. And the
/// leading-byte substitution is undone.
fn volume_label(name: &[u8; 11]) -> Vec<u8> {
    let mut end = name.len();
    while end > 0 && (name[end - 1] == b' ' || name[end - 1] == 0) {
        end -= 1;
    }
    let mut out = name[..end].to_vec();
    // The substitution a leading `0xE5` takes on disk, undone. `0xE5` in the first byte is
    // the deleted marker, so a name really beginning with it is stored as `0x05` — and a
    // label read back without undoing that is one byte different from the label that was
    // set. The short-name renderer does this; a label bypasses it, since a label is one
    // eleven-byte field rather than a base and an extension.
    if out.first() == Some(&NAME_LEADING_E5) {
        out[0] = 0xE5;
    }
    out
}

/// UTF-16 code units as UTF-8 bytes, and whether any unit stood for no character.
///
/// A unit with no partner is replaced rather than refused, so a tree carrying one is still
/// enumerable; the caller raises the deviation.
fn decode_utf16(units: &[u16]) -> (Vec<u8>, bool) {
    let mut ill_formed = false;
    let text: String = char::decode_utf16(units.iter().copied())
        .map(|r| {
            r.unwrap_or_else(|_| {
                ill_formed = true;
                char::REPLACEMENT_CHARACTER
            })
        })
        .collect();
    (text.into_bytes(), ill_formed)
}

/// Judge the three times a directory entry records, each against the range the encoding
/// defines for its fields.
///
/// A read hands back the instant the arithmetic reaches, which is what every driver does and
/// what [`DosTimestamp::decode`] documents deferring. This is the site it defers to: month
/// zero, day 31 of February, a twenty-fifth hour and a hundredths byte past 199 are each a
/// field no encoder produces and an image may carry.
///
/// The write time is the one the format requires. The creation and access times are optional,
/// and a wholly zero field is how the format records that an implementation did not keep them
/// — so a zero field is passed over rather than reported as the month-zero date it spells.
/// Nothing short of the whole field counts: a zero date beside a time that is not zero is a
/// field that was written, and written wrongly.
///
/// The access field is a date and no time, and the write field has no hundredths byte, so each
/// is judged with zero in place of what the format does not give it.
fn check_times(
    entry: &DirEntry,
    index: u32,
    at: Location,
    deviations: &mut OnDeviation<'_>,
) -> Result<(), ReadError> {
    let optional = [
        (
            "creation time",
            DosTimestamp {
                date: entry.create_date,
                time: entry.create_time,
                tenth: entry.create_time_tenth,
            },
        ),
        (
            "access time",
            DosTimestamp {
                date: entry.access_date,
                time: 0,
                tenth: 0,
            },
        ),
    ];
    for (field, stamp) in optional {
        if stamp != DosTimestamp::default() && !stamp.is_well_formed() {
            deviations.record(at, ReadError::MalformedTimestamp { index, field })?;
        }
    }
    let write = DosTimestamp {
        date: entry.write_date,
        time: entry.write_time,
        tenth: 0,
    };
    if !write.is_well_formed() {
        deviations.record(
            at,
            ReadError::MalformedTimestamp {
                index,
                field: "modification time",
            },
        )?;
    }
    Ok(())
}

/// The node a directory entry describes.
fn node_of(entry: &DirEntry, fat_type: FatType) -> Node {
    // The high half of the first cluster number is not part of it on FAT12 and FAT16, where
    // a driver of that era left whatever it liked in those two bytes. Joining them there
    // would read that as an address.
    let first = match fat_type {
        FatType::Fat32 => {
            (u32::from(entry.first_cluster_hi) << 16) | u32::from(entry.first_cluster_lo)
        }
        FatType::Fat12 | FatType::Fat16 => u32::from(entry.first_cluster_lo),
    };
    Node {
        storage: if first < 2 {
            Storage::None
        } else {
            Storage::Chain(first)
        },
        attributes: entry.attributes,
        size: entry.size,
        times: Some(Times {
            create: DosTimestamp {
                date: entry.create_date,
                time: entry.create_time,
                tenth: entry.create_time_tenth,
            }
            .decode(),
            access: DosTimestamp {
                date: entry.access_date,
                time: 0,
                tenth: 0,
            }
            .decode(),
            modify: DosTimestamp {
                date: entry.write_date,
                time: entry.write_time,
                tenth: 0,
            }
            .decode(),
        }),
    }
}

/// The FAT family's implementation of the crate's extraction surface.
///
/// The node handle is [`Node`], which the walk already read, so a sink that stats and then
/// reads a file costs no second lookup of it.
impl<R: Read + Seek> FsTree for Reader<R> {
    type Node = Node;

    fn family(&self) -> Family {
        Family::Fat
    }

    fn max_file_bytes(&self) -> u64 {
        self.limits.max_file_bytes
    }

    fn walk_tree<E, F>(&mut self, mut visit: F) -> Result<(), E>
    where
        E: From<TreeError>,
        F: FnMut(&mut Self, TreeEntry<Node>) -> Result<(), E>,
    {
        // The root has no name, so the walk does not reach it. Yielding it first under the
        // empty path is what lets a sink apply the root's own metadata without a second way
        // of asking for it — even though on this family there is none to apply, which the
        // stat says by naming everything it filled in.
        let root = self.root();
        visit(self, TreeEntry::new(Vec::new(), NodeKind::Directory, root))?;

        let outcome = self.walk_with::<WalkFail<E>>(|reader, entry| {
            let kind = if entry.node.is_dir() {
                NodeKind::Directory
            } else {
                NodeKind::File {
                    size: u64::from(entry.node.size),
                }
            };
            // No `shared`: the format has no second name for a node, so two paths are
            // always two nodes.
            visit(reader, TreeEntry::new(entry.path, kind, entry.node)).map_err(WalkFail::Visitor)
        });
        match outcome {
            Ok(()) => Ok(()),
            Err(WalkFail::Read(e)) => Err(E::from(TreeError::from(e))),
            // Nothing above produces one: a FAT node is a directory or a file, and both are
            // kinds the shared frame has. The arm is here because the failure is the shared
            // surface's rather than this family's, so a later kind that cannot be described
            // reports through it.
            Err(WalkFail::Tree(e)) => Err(E::from(e)),
            Err(WalkFail::Visitor(e)) => Err(e),
        }
    }

    fn stat(&mut self, node: &Node, synthesis: &Synthesis) -> Result<Attributes, TreeError> {
        // A FAT volume's whole record of a node is a read-only bit and two times, which is
        // exFAT's too — so what a read of one invents has a single home, beside the one that
        // says what a write of one loses.
        Ok(Attributes::from_read_only_bit(
            synthesis,
            node.is_dir(),
            node.attributes.contains(DirAttributes::READ_ONLY),
            node.times.map(|t| (t.access, t.modify)),
        ))
    }

    fn read_bytes(&mut self, node: &Node, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError> {
        Ok(Reader::read_into(self, node, offset, buf)?)
    }

    fn link_target(&mut self, _node: &Node) -> Result<Vec<u8>, TreeError> {
        // The format has no symbolic links, so no node a walk yields is one and this is
        // reached only by a caller that did not look at the kind it was handed.
        Err(TreeError::Malformed {
            family: Family::Fat,
            detail: "a FAT volume holds no symbolic links".to_string(),
        })
    }
}

/// The shared walk failure over this family's read error.
type WalkFail<E> = crate::tree::WalkFail<ReadError, E>;

/// What makes `?` on a [`ReadError`] work inside a walk through the shared surface. Written
/// per family because a blanket implementation would collide with the reflexive one.
impl<E> From<ReadError> for WalkFail<E> {
    fn from(err: ReadError) -> Self {
        WalkFail::Read(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::{
        BootCode, ClusterSize, FatTypeRequest, FormatOptions, Image, MEDIA_REMOVABLE, PlanRequest,
        ReservedSectors, VolumeLabel, format,
    };
    use crate::path::canonical_parts;
    use crate::source::{Metadata, TreeBuilder};
    use std::io::Cursor;

    /// The instant every fixture stamps with: 2015-03-14T09:26:52Z, on a two-second boundary
    /// so that nothing under test is also exercising the hundredths field.
    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn options() -> FormatOptions {
        FormatOptions::new(0x1234_abcd, TIME)
    }

    /// A tree holding every naming shape the writer distinguishes.
    fn tree() -> TreeBuilder {
        let m = |mode| Metadata::new(mode, TIME);
        TreeBuilder::new()
            .directory(b"/EFI".to_vec(), m(0o755))
            .directory(b"/EFI/BOOT".to_vec(), m(0o755))
            // Already its own short name: the writer gives it no long-name run.
            .file(
                b"/EFI/BOOT/BOOTX64.EFI".to_vec(),
                b"MZ\x90\x00".to_vec(),
                m(0o644),
            )
            // Lower case, so it needs one.
            .file(b"/readme.txt".to_vec(), b"hello\n".to_vec(), m(0o644))
            // Long enough to be shortened, and a second that shortens alike so the tail
            // numbering is exercised.
            .file(
                b"/a-long-file-name.text".to_vec(),
                vec![b'x'; 5000],
                m(0o644),
            )
            .file(
                b"/a-long-file-name-two.text".to_vec(),
                b"two".to_vec(),
                m(0o644),
            )
            // Owning no cluster at all.
            .file(b"/empty".to_vec(), Vec::new(), m(0o444))
    }

    /// A populated volume of `mib` mebibytes at the given type.
    fn image(mib: u64, request: FatTypeRequest) -> Image {
        let opts = options()
            .label(VolumeLabel::new("FERROSYS").expect("label"))
            .plan(PlanRequest::new(0).fat_type(request));
        format(tree(), mib << 20, opts).expect("format")
    }

    /// The three types, each on a volume large enough to reach it.
    fn each_type() -> [(FatType, Image); 3] {
        [
            (
                FatType::Fat12,
                image(2, FatTypeRequest::Exactly(FatType::Fat12)),
            ),
            (
                FatType::Fat16,
                image(64, FatTypeRequest::Exactly(FatType::Fat16)),
            ),
            (
                FatType::Fat32,
                image(512, FatTypeRequest::Exactly(FatType::Fat32)),
            ),
        ]
    }

    fn reader(image: &Image) -> Reader<Cursor<&[u8]>> {
        Reader::open(Cursor::new(image.as_bytes())).expect("open")
    }

    /// The byte offset of sector `n`.
    fn at(layout: &FatLayout, sector: u32) -> usize {
        sector as usize * layout.bytes_per_sector as usize
    }

    #[test]
    fn a_table_read_never_reaches_past_the_copy_it_is_in() {
        // The copies are laid end to end, so one sector past the live table is the *next*
        // copy's first entry. Reading it would splice that byte onto a FAT12 entry that
        // straddles the boundary, and the value would belong to neither copy. Both ways of
        // reading an entry — the chain walk's window and the mirror comparison — take the
        // rule from here, which is what makes them agree on every entry they both reach.
        for (_, image) in each_type() {
            let r = reader(&image);
            let last = r.layout.fat_sectors - 1;
            assert_eq!(
                r.table_window_sectors(last),
                1,
                "the copy's last sector has no next sector of its own"
            );
            assert_eq!(r.table_window_sectors(last.saturating_sub(1)), 2);
            // A sector index past the table entirely — which no bounded caller produces —
            // still asks for no second sector.
            assert_eq!(r.table_window_sectors(u32::MAX), 1);
        }
    }

    #[test]
    fn the_layout_read_back_is_the_layout_planned() {
        // The planner's output and the reader's recovery are two derivations of one thing
        // from disjoint inputs — a request on one side and the bytes on the other — so their
        // agreeing is what says the boot sector records the whole geometry.
        for (what, image) in each_type() {
            let r = reader(&image);
            assert_eq!(r.layout(), image.layout(), "{what}");
            assert_eq!(r.fat_type(), what);
        }
    }

    #[test]
    fn every_name_the_writer_placed_reads_back() {
        for (what, image) in each_type() {
            let mut r = reader(&image);
            let mut paths: Vec<Vec<u8>> = r
                .walk()
                .expect("walk")
                .into_iter()
                .map(|e| e.path)
                .collect();
            paths.sort();
            let expected: Vec<&[u8]> = vec![
                b"/EFI",
                b"/EFI/BOOT",
                b"/EFI/BOOT/BOOTX64.EFI",
                b"/a-long-file-name-two.text",
                b"/a-long-file-name.text",
                b"/empty",
                b"/readme.txt",
            ];
            let got: Vec<&[u8]> = paths.iter().map(Vec::as_slice).collect();
            assert_eq!(got, expected, "{what}");
        }
    }

    #[test]
    fn every_file_reads_back_byte_for_byte() {
        for (what, image) in each_type() {
            let mut r = reader(&image);
            for (path, expected) in [
                (&b"/EFI/BOOT/BOOTX64.EFI"[..], b"MZ\x90\x00".to_vec()),
                (b"/readme.txt", b"hello\n".to_vec()),
                (b"/a-long-file-name.text", vec![b'x'; 5000]),
                (b"/a-long-file-name-two.text", b"two".to_vec()),
                (b"/empty", Vec::new()),
            ] {
                let node = r.lookup(path).unwrap_or_else(|e| {
                    panic!("{what}: {} not found: {e}", String::from_utf8_lossy(path))
                });
                assert_eq!(u64::from(node.size), expected.len() as u64, "{what}");
                assert_eq!(
                    r.read_data(&node).expect("read"),
                    expected,
                    "{what}: {}",
                    String::from_utf8_lossy(path)
                );
            }
        }
    }

    #[test]
    fn a_multi_cluster_file_reads_the_same_whole_as_it_does_in_pieces() {
        // The chain cursor is what makes a sequential read one pass rather than one per
        // call, and a cursor that resumed at the wrong index would show up here and nowhere
        // else: the whole-file path and the piecewise path would disagree.
        for (what, image) in each_type() {
            let mut r = reader(&image);
            let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
            let whole = r.read_data(&node).expect("whole");
            for chunk in [1usize, 7, 512, 4096] {
                let mut pieces = Vec::new();
                let mut buf = vec![0u8; chunk];
                let mut offset = 0u64;
                loop {
                    let got = r.read_into(&node, offset, &mut buf).expect("piece");
                    if got == 0 {
                        break;
                    }
                    pieces.extend_from_slice(&buf[..got]);
                    offset += got as u64;
                }
                assert_eq!(pieces, whole, "{what}: in {chunk}-byte pieces");
            }
            // And backwards, which the cursor cannot resume from and must restart for.
            let mut buf = [0u8; 16];
            for start in (0..whole.len()).step_by(997).rev() {
                let got = r
                    .read_into(&node, start as u64, &mut buf)
                    .expect("backwards");
                assert_eq!(&buf[..got], &whole[start..start + got], "{what}");
            }
        }
    }

    #[test]
    fn a_short_name_is_kept_beside_the_name_and_says_whether_a_long_one_was_used() {
        // The case-byte decision observed from the reading side: a name that is already its
        // own short name has no long-name run, and one that is not does. A writer that used
        // the reserved case byte instead would show `has_long_name` false for `readme.txt`.
        for (what, image) in each_type() {
            let mut r = reader(&image);
            let root = r.root();
            let entries = r.read_dir(&root).expect("read the root");
            let by_name = |n: &[u8]| {
                entries
                    .iter()
                    .find(|e| e.name == n)
                    .unwrap_or_else(|| panic!("{what}: {} absent", String::from_utf8_lossy(n)))
            };
            let readme = by_name(b"readme.txt");
            assert!(readme.has_long_name, "{what}");
            assert_eq!(readme.short_name, b"README.TXT", "{what}");

            // The two that shorten alike take different short names, and the reader sees
            // both of them.
            let one = by_name(b"a-long-file-name.text");
            let two = by_name(b"a-long-file-name-two.text");
            assert_ne!(one.short_name, two.short_name, "{what}");

            let efi = r.lookup(b"/EFI/BOOT").expect("lookup");
            let boot = r.read_dir(&efi).expect("read");
            let payload = boot
                .iter()
                .find(|e| e.name == b"BOOTX64.EFI")
                .expect("entry");
            assert!(
                !payload.has_long_name,
                "{what}: a name that is its own short name took a long-name run"
            );
            assert_eq!(payload.short_name, b"BOOTX64.EFI");
        }
    }

    #[test]
    fn the_case_flags_are_honoured_on_reading_and_never_written() {
        // The writer leaves byte 12 zero on every entry, so nothing in an image this crate
        // wrote depends on it.
        for (what, image) in each_type() {
            let mut r = reader(&image);
            let root = r.root();
            r.for_each_slot::<ReadError>(&root, |_, slot| {
                assert_eq!(
                    slot.entry.case_flags, 0,
                    "{what}: the writer set a reserved case flag"
                );
                Ok(ControlFlow::Continue(()))
            })
            .expect("raw");
        }
        // And read back, the flags mean what Windows means by them.
        assert_eq!(render_short(b"README  TXT", 0), b"README.TXT");
        assert_eq!(render_short(b"README  TXT", NT_LOWER_BASE), b"readme.TXT");
        assert_eq!(render_short(b"README  TXT", NT_LOWER_EXT), b"README.txt");
        assert_eq!(
            render_short(b"README  TXT", NT_LOWER_BASE | NT_LOWER_EXT),
            b"readme.txt"
        );
        // A byte above ASCII has no case without the code page the volume does not record,
        // so folding leaves it alone.
        assert_eq!(
            render_short(b"CAF\xE9    TXT", NT_LOWER_BASE),
            b"caf\xE9.TXT".to_vec(),
            "the flag names the base alone, and the byte above ASCII has no case"
        );
    }

    #[test]
    fn a_name_with_no_extension_keeps_no_dot() {
        assert_eq!(render_short(b"EMPTY      ", 0), b"EMPTY");
        assert_eq!(render_short(b"A       B  ", 0), b"A.B");
        // The substituted leading byte is put back: a name that genuinely begins 0xE5 is
        // stored as 0x05 so it is not read as a deleted slot.
        assert_eq!(render_short(b"\x05BC        ", 0), b"\xE5BC".to_vec());
    }

    #[test]
    fn the_volume_label_comes_from_the_root_entry() {
        for (what, image) in each_type() {
            let mut r = reader(&image);
            assert_eq!(
                r.volume_label().expect("label"),
                Some(b"FERROSYS".to_vec()),
                "{what}"
            );
            // And it is not among the names the tree yields: it is not a file.
            let root = r.root();
            let names: Vec<Vec<u8>> = r
                .read_dir(&root)
                .expect("read")
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert!(!names.contains(&b"FERROSYS".to_vec()), "{what}");
        }
    }

    #[test]
    fn a_strict_scan_of_a_volume_this_crate_wrote_is_clean() {
        // The line the severities are drawn against: a strict read accepts everything the
        // writer emits, so a scan of one finds nothing at all.
        for (what, image) in each_type() {
            let mut r = reader(&image);
            let report = r.scan();
            assert!(report.is_clean(), "{what}: {:#?}", report.anomalies());
            assert!(!report.has_fatal(ReadPolicy::Strict), "{what}");
            r.verify_tables()
                .unwrap_or_else(|e| panic!("{what}: the tables disagree: {e}"));
        }
    }

    #[test]
    fn a_strict_read_accepts_every_volume_the_writer_produces_at_every_option() {
        // The same line, over the half of the writer's input the geometry sweeps do not
        // reach. `PlanRequest` decides where the bytes go; `FormatOptions` decides what a
        // dozen of them say — and a field the writer accepts but the reader's parameter-block
        // gate refuses breaks the round trip exactly as surely as a misplaced cluster would.
        // So every field is varied here, one at a time, across all three types.
        /// One departure from the default options, and what to call it in a failure.
        type Variant = (&'static str, Box<dyn Fn(FormatOptions) -> FormatOptions>);

        let long_code = vec![0x90u8; BootCode::MAX_BYTES_FAT32];
        let mut variants: Vec<Variant> = vec![
            ("default", Box::new(|o: FormatOptions| o)),
            (
                "unlabelled",
                Box::new(|mut o: FormatOptions| {
                    o.label = None;
                    o
                }),
            ),
            (
                "oem name",
                Box::new(|mut o: FormatOptions| {
                    o.oem_name = *b"MSWIN4.1";
                    o
                }),
            ),
            (
                "hidden sectors",
                Box::new(|mut o: FormatOptions| {
                    o.hidden_sectors = 2048;
                    o
                }),
            ),
            (
                "volume id",
                Box::new(|mut o: FormatOptions| {
                    o.volume_id = 0;
                    o
                }),
            ),
            (
                "earliest time",
                Box::new(|mut o: FormatOptions| {
                    o.time = Timestamp::from_secs(DosTimestamp::SECS_MIN);
                    o
                }),
            ),
            (
                "latest time",
                Box::new(|mut o: FormatOptions| {
                    o.time = Timestamp::from_secs(DosTimestamp::SECS_MAX);
                    o
                }),
            ),
            (
                "boot code",
                Box::new(move |o: FormatOptions| {
                    o.boot_code(BootCode::new(&long_code).expect("boot code"))
                }),
            ),
        ];
        // The sweep's own completeness check, and the reason this test can claim "every
        // field" rather than "the fields someone listed". `FormatOptions` is destructured
        // field by field, so a field added to it stops this test compiling until someone
        // decides what varies it. Without that, a matrix is exhaustive only over the axes
        // it was written with — which is how a sweep over the sector size, the table count,
        // the type, the cluster size and the label certified a round trip it did not test,
        // because `media` was the one field nobody had thought to move.
        //
        // Bindings are discarded: it is the exhaustiveness the compiler checks, not the
        // values.
        let FormatOptions {
            // Each varied above, by the variant named for it.
            label: _,
            oem_name: _,
            hidden_sectors: _,
            volume_id: _,
            time: _,
            media: _,
            boot_code: _,
            // Varied by the type loop below, and exhaustively by the geometry sweeps in
            // tests/fat_oracle.rs, which compare against the pinned oracle rather than
            // against this crate's own reader.
            plan: _,
            // Neither reaches a byte this reader gates on. `accepted_loss` decides whether
            // a format *fails* over a property FAT cannot hold, so a volume that exists at
            // all was written with a setting that permitted it; `synthesis` names what an
            // owner and a mode read back as, which the format does not record and no parse
            // consults. A tree carrying something lossy is the subject of the fidelity
            // tests, not of the parameter block's round trip.
            accepted_loss: _,
            synthesis: _,
        } = options();

        // Every media descriptor the format defines: the writer refuses the rest, and the
        // reader accepts exactly these.
        for media in (0xF8u8..=0xFF).chain([MEDIA_REMOVABLE]) {
            variants.push((
                "media",
                Box::new(move |mut o: FormatOptions| {
                    o.media = media;
                    o
                }),
            ));
        }

        for (what, mib) in [
            (FatType::Fat12, 2u64),
            (FatType::Fat16, 64),
            (FatType::Fat32, 512),
        ] {
            for (name, vary) in &variants {
                let base = options()
                    .label(VolumeLabel::new("FERROSYS").expect("label"))
                    .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(what)));
                let image = format(tree(), mib << 20, vary(base))
                    .unwrap_or_else(|e| panic!("{what} / {name}: format: {e}"));
                let mut r = Reader::open(Cursor::new(image.as_bytes()))
                    .unwrap_or_else(|e| panic!("{what} / {name}: a strict open: {e}"));
                assert_eq!(r.layout(), image.layout(), "{what} / {name}");
                let report = r.scan();
                assert!(
                    report.is_clean(),
                    "{what} / {name}: {:#?}",
                    report.anomalies()
                );
            }
        }
    }

    #[test]
    fn an_undersized_fat32_is_remarked_on_and_not_refused() {
        // The opt-in small FAT32 volume: below the format's own cluster minimum, written on
        // request, and read as FAT32 by every mainstream driver. This crate emits it, so a
        // strict read must accept it.
        let opts = options().plan(
            PlanRequest::new(0)
                .cluster_size(ClusterSize::Sectors(1))
                .reserved_sectors(ReservedSectors::Count(32))
                .fat_type(FatTypeRequest::UndersizedFat32),
        );
        let image = format(TreeBuilder::new(), 8 << 20, opts).expect("format");
        let mut r = Reader::open(Cursor::new(image.as_bytes())).expect("a strict open");
        assert_eq!(r.fat_type(), FatType::Fat32);
        assert!(r.layout().clusters < crate::fat::MIN_CLUSTERS_FAT32);
        let report = r.scan();
        assert!(report.is_clean(), "{:#?}", report.anomalies());
    }

    #[test]
    fn the_reader_opens_exactly_what_detection_claims() {
        // Both go through one derivation, so there is no image detection names and the
        // reader refuses, and none it calls unrecognized that the reader opens.
        for (_, image) in each_type() {
            let bytes = image.as_bytes();
            assert!(matches!(
                crate::detect(Cursor::new(bytes)),
                Ok(crate::Filesystem::Fat(_))
            ));
            assert!(Reader::open(Cursor::new(bytes)).is_ok());
        }
        // And a master boot record, which ends in the same two bytes a FAT volume does.
        let mut mbr = vec![0u8; 1 << 20];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        mbr[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        assert!(crate::detect(Cursor::new(&mbr)).is_err());
        assert!(matches!(
            Reader::open(Cursor::new(&mbr)),
            Err(ReadError::BadBootSector { .. })
        ));
    }

    #[test]
    fn a_volume_inside_a_larger_image_reads_at_its_own_offset() {
        const BASE: u64 = 1 << 20;
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut disk = vec![0u8; BASE as usize];
        disk.extend_from_slice(image.as_bytes());
        // Nothing at the start of the disk, and the volume where it was put.
        assert!(Reader::open(Cursor::new(&disk)).is_err());
        let mut r = Reader::open_with(Cursor::new(&disk), &OpenOptions::new().base(BASE))
            .expect("open at the partition's start");
        assert_eq!(r.layout(), image.layout());
        assert_eq!(r.walk().expect("walk").len(), 7);
    }

    #[test]
    fn a_lookup_finds_a_name_however_its_letters_are_cased() {
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = reader(&image);
        // Two rules meet in these spellings, and they are separate. The separators and `.`
        // elements carry no meaning to *any* path in this crate, so a volume drops them
        // because it splits through the one shared rule rather than because this reader
        // reimplemented it — asserted here against `canonical_key`, so a splitter that
        // drifted would make a model key an entry at a path this reader could no longer
        // reach. The case of the letters is FAT's own business, which is why the shared key
        // does not fold it and this assertion uppercases before comparing.
        for path in [
            &b"/EFI/BOOT/BOOTX64.EFI"[..],
            b"/efi/boot/bootx64.efi",
            b"/EFI/boot/BootX64.efi",
            b"//EFI//BOOT//BOOTX64.EFI",
            b"/./EFI/BOOT/BOOTX64.EFI",
            b"/EFI/BOOT/BOOTX64.EFI/",
            b"EFI/BOOT/BOOTX64.EFI",
        ] {
            let node = r
                .lookup(path)
                .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(path)));
            assert_eq!(node.size, 4);
            assert_eq!(
                crate::path::canonical_key(path).to_ascii_uppercase(),
                b"EFI/BOOT/BOOTX64.EFI",
                "{}: one path to a model as well as to a lookup",
                String::from_utf8_lossy(path)
            );
        }
        assert!(matches!(
            r.lookup(b"/EFI/BOOT/NOPE"),
            Err(ReadError::NotFound { .. })
        ));
        assert!(matches!(
            r.lookup(b"/readme.txt/deeper"),
            Err(ReadError::NotADirectory { .. })
        ));
    }

    #[test]
    fn a_parent_component_ascends_though_no_entry_of_that_name_is_ever_handed_back() {
        // This family is where the two questions the one spelling asks came apart. A FAT
        // subdirectory genuinely stores `.` and `..` entries, and none of them reaches a
        // caller: the format's own are identified by their short-name field and filtered
        // there, and a long name spelling either is refused as a name. So there is no entry
        // an ascent could be a lookup of, and it has to be the descent walked back.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = reader(&image);
        let boot = r.lookup(b"/EFI/BOOT").expect("lookup");
        let listed = r.read_dir(&boot).expect("read the subdirectory");
        // Asked through the shared rule rather than by spelling the two names again, so a
        // clause added to what no path component may carry reaches this assertion too.
        assert!(
            !listed
                .iter()
                .any(|e| is_hostile_component(&e.name) || is_hostile_component(&e.short_name)),
            "a name no path component may carry reached a caller: {:?}",
            listed.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        // The volume stores them all the same, which is what makes the filtering the claim
        // rather than an accident of this fixture.
        assert_eq!(listed.len(), 1);

        // And the component resolves, through a directory whose listing has nothing of that
        // name in it.
        let want = r.lookup(b"/EFI/BOOT/BOOTX64.EFI").expect("lookup");
        assert_eq!(
            r.lookup(b"/EFI/BOOT/../BOOT/BOOTX64.EFI")
                .map(|node| node.storage),
            Ok(want.storage)
        );
        assert_eq!(
            r.lookup(b"/EFI/..").map(|n| n.storage),
            Ok(r.root().storage)
        );
    }

    #[test]
    fn a_directory_holds_no_bytes_and_yields_none() {
        // A directory's storage is its entries, and handing those back as file contents
        // would be a directory entry read as data.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = reader(&image);
        let dir = r.lookup(b"/EFI").expect("lookup");
        assert!(dir.is_dir());
        assert_eq!(r.read_data(&dir).expect("read"), Vec::<u8>::new());
        let mut buf = [0u8; 32];
        assert_eq!(r.read_into(&dir, 0, &mut buf).expect("read"), 0);
    }

    #[test]
    fn the_read_limit_refuses_rather_than_shortening() {
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = Reader::open_with(
            Cursor::new(image.as_bytes()),
            &OpenOptions::new().limits(Limits::new().max_file_bytes(1024)),
        )
        .expect("open");
        let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
        assert!(matches!(
            r.read_data(&node),
            Err(ReadError::FileTooLarge {
                size: 5000,
                limit: 1024
            })
        ));
        // A stream into a caller's own writer answers to it too, and it has to: nothing
        // accumulates there, so the memory it costs says nothing about the bytes it
        // produces — and an extraction's `--cat` is exactly that stream.
        assert!(matches!(
            r.read_data_to(&node, std::io::sink()),
            Err(ReadError::FileTooLarge {
                size: 5000,
                limit: 1024
            })
        ));
        // A read into a caller's own buffer is bounded by the buffer and says how much of
        // it was filled, so a partial read stays representable.
        let mut buf = [0u8; 64];
        assert_eq!(r.read_into(&node, 0, &mut buf).expect("read"), 64);
    }

    #[test]
    fn a_time_the_encoding_does_not_define_is_named_where_the_entry_is_read() {
        // `DosTimestamp::decode` reports the instant the arithmetic reaches and says a scan
        // is what judges it. This is that scan, and it is the write time that is judged
        // unconditionally: the format requires it, where the creation and access times are
        // optional and a wholly zero field is how it records that they were not kept.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let entry = entry_of(&image, b"EMPTY      ");

        // Day 31 of February, which is a date the calendar does not have and the arithmetic
        // reads as the third of March.
        let mut bytes = image.as_bytes().to_vec();
        let odd = ((2035u16 - 1980) << 9) | (2 << 5) | 31;
        bytes[entry + 24..entry + 26].copy_from_slice(&odd.to_le_bytes());
        let err = Reader::open(Cursor::new(bytes.as_slice()))
            .expect("open")
            .walk()
            .expect_err("a strict read refuses it");
        assert!(
            matches!(
                err,
                ReadError::MalformedTimestamp {
                    field: "modification time",
                    ..
                }
            ),
            "{err}"
        );

        // The creation time zeroed whole, which is the format recording that nothing kept
        // it — so it is passed over rather than reported as the month-zero date it spells.
        let mut bytes = image.as_bytes().to_vec();
        bytes[entry + 13] = 0;
        bytes[entry + 14..entry + 18].copy_from_slice(&0u32.to_le_bytes());
        Reader::open(Cursor::new(bytes.as_slice()))
            .expect("open")
            .walk()
            .expect("a field the format calls optional and absent stops no read");

        // Nothing short of the whole field is that record: a zero date beside a time that is
        // not zero is a field that was written, and written wrongly.
        let mut bytes = image.as_bytes().to_vec();
        bytes[entry + 16..entry + 18].copy_from_slice(&0u16.to_le_bytes());
        let err = Reader::open(Cursor::new(bytes.as_slice()))
            .expect("open")
            .walk()
            .expect_err("a strict read refuses it");
        assert!(
            matches!(
                err,
                ReadError::MalformedTimestamp {
                    field: "creation time",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Where the directory entry whose short name is `name` begins, as a byte offset into
    /// `image`.
    ///
    /// Found by scanning the root region for the eleven-byte field rather than computed, so a
    /// case that patches an entry stays correct when the order a directory is written in
    /// changes.
    fn entry_of(image: &Image, name: &[u8; 11]) -> usize {
        let bytes = image.as_bytes();
        bytes
            .chunks_exact(DIR_ENTRY_SIZE)
            .position(|slot| &slot[..11] == name)
            .map(|n| n * DIR_ENTRY_SIZE)
            .unwrap_or_else(|| panic!("no entry is named {}", String::from_utf8_lossy(name)))
    }

    #[test]
    fn a_walk_bound_is_reported_rather_than_silently_shortening_the_tree() {
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = Reader::open_with(
            Cursor::new(image.as_bytes()),
            &OpenOptions::new().limits(Limits::new().max_walk_entries(3)),
        )
        .expect("open");
        assert!(matches!(
            r.walk(),
            Err(ReadError::WalkTooLarge { limit: 3 })
        ));
    }

    /// A volume whose root directory is chained through every cluster it has, with every
    /// 32-byte slot of the data region a well-formed short-name entry.
    ///
    /// This is the shape a caller's cap has to survive: nothing here is larger than the
    /// image, so no structural bound refuses it, and a read that materialized the directory
    /// before consulting a limit would allocate the volume's size whatever the caller asked
    /// for.
    fn root_chained_through_the_whole_volume() -> (Vec<u8>, FatLayout) {
        let opts = options().plan(
            PlanRequest::new(0)
                .cluster_size(ClusterSize::Sectors(1))
                .reserved_sectors(ReservedSectors::Count(32))
                .fat_type(FatTypeRequest::UndersizedFat32),
        );
        let image = format(TreeBuilder::new(), 8 << 20, opts).expect("format");
        let layout = *image.layout();
        let mut bytes = image.into_bytes();

        // Every cluster points at the next, so the chain that begins at the root runs to the
        // end of the volume.
        let last = layout.clusters + 1;
        let table_bytes = layout.fat_sectors as usize * layout.bytes_per_sector as usize;
        for copy in 0..layout.fats {
            let start = at(&layout, layout.fat_start_sector(copy).expect("a table"));
            let table = &mut bytes[start..start + table_bytes];
            for cluster in 2..=last {
                let value = if cluster == last {
                    table::end_of_chain(layout.fat_type)
                } else {
                    cluster + 1
                };
                assert!(table::write_entry(layout.fat_type, table, cluster, value));
            }
        }

        // And every slot in the data region is an entry, so nothing stops the parse early.
        // Each carries a real write time, because the bound under test is the entry cap and
        // an entry whose date the calendar does not have is a deviation that would stop the
        // parse first — on a fixture where the times were never the point.
        let mut slot = [0u8; DIR_ENTRY_SIZE];
        slot[..11].copy_from_slice(b"FILLER  TXT");
        slot[11] = 0x20; // archive, which is what an ordinary file carries
        let stamp = DosTimestamp::encode(Timestamp::from_secs(1_426_325_212)).expect("in range");
        slot[22..24].copy_from_slice(&stamp.time.to_le_bytes());
        slot[24..26].copy_from_slice(&stamp.date.to_le_bytes());
        let data = at(&layout, layout.first_data_sector);
        for chunk in bytes[data..].chunks_exact_mut(DIR_ENTRY_SIZE) {
            chunk.copy_from_slice(&slot);
        }
        (bytes, layout)
    }

    #[test]
    fn a_directory_larger_than_the_cap_is_refused_before_it_is_gathered() {
        // A directory is read a region at a time and its entries are counted against the
        // caller's bound as they are produced, so a crafted one costs a cluster rather than
        // the volume. Reading it whole first and consulting the bound afterwards would make
        // `Limits` unable to do the one thing it exists for.
        let (bytes, layout) = root_chained_through_the_whole_volume();
        assert!(
            layout.clusters > 4096,
            "the fixture is too small to be evidence: {} clusters",
            layout.clusters
        );

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().limits(Limits::new().max_walk_entries(16)),
        )
        .expect("open");
        let root = r.root();
        assert!(matches!(
            r.read_dir(&root),
            Err(ReadError::WalkTooLarge { limit: 16 })
        ));
        assert!(matches!(
            r.walk(),
            Err(ReadError::WalkTooLarge { limit: 16 })
        ));

        // A chain collected whole answers to the same bound, for the same reason.
        assert!(matches!(
            r.chain(2),
            Err(ReadError::WalkTooLarge { limit: 16 })
        ));
    }

    #[test]
    fn a_scan_that_hit_the_cap_inside_one_directory_reports_nothing_lost() {
        // The same rule the running name count follows: a traversal that stopped reached
        // fewer clusters than the volume owns, so what it did not reach is not evidence.
        let (bytes, _) = root_chained_through_the_whole_volume();
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new()
                .policy(ReadPolicy::Lenient)
                .limits(Limits::new().max_walk_entries(16)),
        )
        .expect("open");
        let report = r.scan();
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("more than 16 names")),
            "{:#?}",
            report.anomalies()
        );
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("reached by no chain")),
            "{:#?}",
            report.anomalies()
        );
    }

    /// Format a volume, hand its bytes to `damage`, and report what a lenient scan finds.
    fn damaged(what: FatTypeRequest, damage: impl FnOnce(&mut [u8], &FatLayout)) -> ScanReport {
        let image = image(64, what);
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        damage(&mut bytes, &layout);
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        r.scan()
    }

    /// Switch a FAT32 volume's mirroring off and name `live` as the one maintained copy, in
    /// the boot sector and in its backup.
    fn set_ext_flags(bytes: &mut [u8], layout: &FatLayout, flags: u16) {
        let mut sectors = vec![0u32];
        if let Some(backup) = layout.fat32.and_then(|f| f.backup_boot_sector) {
            sectors.push(u32::from(backup));
        }
        for sector in sectors {
            let off = at(layout, sector) + 40;
            bytes[off..off + 2].copy_from_slice(&flags.to_le_bytes());
        }
    }

    #[test]
    fn a_chain_is_followed_through_the_table_the_volume_says_is_live() {
        // `BPB_ExtFlags` bit 7 says only one copy of the table is maintained and bits 0-3 say
        // which. A reader that takes the bit and drops the number follows the copy the volume
        // abandoned, and returns the tree and the file bytes *that* table describes — while a
        // conformant driver returns different ones.
        //
        // What makes it silent rather than merely wrong is that this is exactly the shape
        // where the mirror check is suppressed: with mirroring off the copies are not obliged
        // to agree, so the disagreement that would otherwise be an integrity finding is not
        // reported. A strict open followed by an extraction succeeds and is wrong.
        let pristine = image(512, FatTypeRequest::Exactly(FatType::Fat32));
        let layout = *pristine.layout();
        let want = {
            let mut r = reader(&pristine);
            let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
            r.read_data(&node).expect("read")
        };
        assert_eq!(want.len(), 5000, "the fixture file spans several clusters");
        let names = reader(&pristine).walk().expect("walk").len();
        let mut bytes = pristine.into_bytes();

        // Copy 0 is emptied outright, so nothing can be resolved through it: every chain
        // ends at a free cluster on the first step. Copy 1 is left as the writer laid it
        // down, and the volume is told that copy 1 is the live one.
        let start = at(&layout, layout.fat_start_sector(0).expect("a first table"));
        let len = at(&layout, layout.fat_sectors);
        bytes[start..start + len].fill(0);
        set_ext_flags(&mut bytes, &layout, 0x0081);

        let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("a strict open");
        let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
        assert_eq!(
            r.read_data(&node).expect("read through the live table"),
            want,
            "the bytes are the live table's, not the abandoned copy's"
        );
        assert_eq!(
            r.walk().expect("walk").len(),
            names,
            "the tree is the live table's too"
        );

        // And the same volume with mirroring on is a volume whose table 0 is destroyed: the
        // control that shows the damage was real rather than unreached.
        let mut mirrored = bytes;
        set_ext_flags(&mut mirrored, &layout, 0x0000);
        let mut r = Reader::open(Cursor::new(mirrored.as_slice())).expect("open");
        assert!(
            r.lookup(b"/a-long-file-name.text").is_err(),
            "with mirroring on the read goes through the emptied copy 0, which \
             resolves nothing at all"
        );
    }

    #[test]
    fn the_label_is_the_live_one_and_survives_the_leading_byte_substitution() {
        // `volume_label` walks `for_each_slot`, which hands back *every* slot because that is
        // what the scan needs. All the free, deleted, and end-of-directory handling lives in
        // `parse_dir`, which this bypasses — so a deleted label entry, or one sitting past
        // the end marker, was returned where `fatlabel` and every driver read the live one.
        // And because `parse_dir` was bypassed, neither the entries-after-end nor the
        // misplaced-label finding fired: a strict read reported nothing.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let live = reader(&image)
            .volume_label()
            .expect("read")
            .expect("a label");
        assert_eq!(live, b"FERROSYS");
        let mut bytes = image.into_bytes();

        // The volume records the label twice: in the root directory, which is what a rename
        // updates and what every driver reads, and in the boot sector, which nothing keeps in
        // step. Made to differ, so which one answered is visible.
        let boot = bytes
            .windows(11)
            .position(|w| w == b"FERROSYS   ")
            .expect("the boot sector's copy");
        let root = bytes
            .windows(11)
            .rposition(|w| w == b"FERROSYS   ")
            .expect("the root entry");
        assert_ne!(boot, root, "the two copies are two places");
        bytes[boot..boot + 11].copy_from_slice(b"STALECOPY  ");

        // The root's entry, struck out. The live label is then the boot sector's, which is
        // what the reader falls back to — and *not* the deleted entry, which is a name the
        // volume no longer answers to.
        bytes[root] = NAME_DELETED;
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        assert_eq!(
            r.volume_label().expect("read").as_deref(),
            Some(&b"STALECOPY"[..]),
            "a deleted entry is not the volume's label"
        );

        // And a label whose first byte really is `0xE5` is stored as `0x05`, the deleted
        // marker's substitution — so reading it back without undoing that gives a label one
        // byte different from the one that was set.
        let mut restored = bytes.clone();
        restored[root] = NAME_LEADING_E5;
        restored[root + 1..root + 11].copy_from_slice(b"ABEL      ");
        let mut r = Reader::open_with(
            Cursor::new(restored.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        assert_eq!(
            r.volume_label().expect("read").expect("a label")[0],
            0xE5,
            "the substituted leading byte is put back"
        );
    }

    #[test]
    fn an_unknown_filesystem_version_is_reported_rather_than_scanned_clean() {
        // `BPB_FSVer` is the field a driver reads to decide whether it understands the
        // volume at all. Zero is the only version ever defined, and neither Windows nor
        // Linux mounts anything else — so a volume carrying another value is one nothing
        // will touch, and a read that opened and scanned it clean would be describing an
        // image that in practice does not exist.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat32), |bytes, layout| {
            // `BPB_FSVer` sits at offset 42 of the boot sector, and of its backup.
            let mut sectors = vec![0u32];
            if let Some(backup) = layout.fat32.and_then(|f| f.backup_boot_sector) {
                sectors.push(u32::from(backup));
            }
            for sector in sectors {
                let off = at(layout, sector) + 42;
                bytes[off..off + 2].copy_from_slice(&1u16.to_le_bytes());
            }
        });
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("BPB_FSVer is 0x0001")),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn a_live_table_the_volume_does_not_have_is_reported_rather_than_followed_blindly() {
        // `BPB_ExtFlags` naming copy 5 of two is incoherent. Nothing can be resolved through
        // a table that is not there, so reads fall back to copy 0 — and because that is a
        // different table from the one the volume names, the scan says so at the weight of a
        // wrong read rather than as a cosmetic field.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat32), |bytes, layout| {
            set_ext_flags(bytes, layout, 0x0085);
        });
        assert!(
            report.anomalies().iter().any(|a| {
                a.severity == Severity::Integrity && a.detail.contains("names table 5")
            }),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn a_name_carrying_terminal_control_bytes_is_escaped_where_it_enters_a_finding() {
        // FAT refuses only `.`, `..`, `/`, and NUL in a name, so ESC, CR, and a
        // right-to-left override are all legal in a short name and in a long one. A finding
        // that interpolated such a name raw would hand those bytes to whatever printed it —
        // and a name of `\x1b[2J\x1b[1;1Hno findings\x1b[0m` puts a forged clean report on
        // the screen of whoever inspects the image, from a command that exited zero.
        //
        // So the name is escaped where it enters the text. Nothing downstream can do it:
        // by then the detail is one string and no part of it is marked as the image's.
        let hostile = b"\x1b[2Jred\r";
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat16), |bytes, _| {
            let at = bytes
                .windows(11)
                .position(|w| w == b"BOOTX64 EFI")
                .expect("the fixture's short name is on disk");
            // The name, and a length its chain cannot hold — which is what makes a finding
            // that names the entry fire at all.
            bytes[at..at + 8].copy_from_slice(hostile);
            bytes[at + 28..at + 32].copy_from_slice(&999_999u32.to_le_bytes());
        });

        let named: Vec<&str> = report
            .anomalies()
            .iter()
            .map(|a| a.detail.as_str())
            .filter(|d| d.contains("\\x1b"))
            .collect();
        assert!(
            !named.is_empty(),
            "a finding names the entry: {:#?}",
            report.anomalies()
        );
        for detail in report.anomalies().iter().map(|a| &a.detail) {
            assert!(
                !detail.chars().any(char::is_control),
                "a finding carries a raw control byte: {detail:?}"
            );
        }
        // And the projections a caller renders carry the same guarantee, because the detail
        // they interpolate already does.
        let findings = report.to_report();
        for rendered in [findings.to_table(), findings.to_json()] {
            assert!(
                !rendered.chars().any(|c| c.is_control() && c != '\n'),
                "a rendered report carries a raw control byte: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_table_that_disagrees_with_its_mirror_is_an_integrity_finding() {
        // FAT carries no checksums, and the mirror is what stands in for one.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat16), |bytes, layout| {
            let second = layout.fat_start_sector(1).expect("two tables");
            bytes[at(layout, second) + 8] ^= 0xFF;
        });
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.severity == Severity::Integrity
                    && a.category == Category::AllocationTable),
            "{:#?}",
            report.anomalies()
        );
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    /// A FAT12 volume whose highest cluster number is even, with a reader over it and the
    /// byte offset of the second table's first byte.
    ///
    /// Both packing-boundary cases live at that parity: an even highest cluster is the one
    /// whose entry ends in a shared nibble rather than on a byte boundary.
    fn fat12_with_an_even_highest_cluster() -> (Vec<u8>, FatLayout) {
        for mib in 1u64..8 {
            let image = image(mib, FatTypeRequest::Exactly(FatType::Fat12));
            let layout = *image.layout();
            if (layout.clusters + 1).is_multiple_of(2) && layout.fats >= 2 {
                return (image.into_bytes(), layout);
            }
        }
        panic!("no FAT12 fixture in range has an even highest cluster");
    }

    #[test]
    fn a_divergence_in_the_last_fat12_entry_is_a_mismatch_and_not_padding() {
        // On FAT12 the highest cluster's entry can end in the *low* nibble of a byte, so a
        // difference at that byte is a difference in a live allocation entry. Classifying it
        // as padding would make it cosmetic, and a strict read would accept a volume whose
        // two tables disagree about where a chain goes.
        let (mut bytes, layout) = fat12_with_an_even_highest_cluster();
        let highest = layout.clusters + 1;
        let shared = table::entry_offset(FatType::Fat12, highest) + 1;
        let second = at(&layout, layout.fat_start_sector(1).expect("two tables"));

        // The low nibble of that byte is the highest entry's top four bits; the high nibble
        // belongs to no cluster the volume has.
        bytes[second + shared as usize] ^= 0x01;

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        match r.verify_tables() {
            Err(ReadError::TableMismatch { copy, cluster, .. }) => {
                assert_eq!(copy, 1);
                assert_eq!(cluster, highest);
            }
            other => panic!("expected a mismatch at the last entry, got {other:?}"),
        }
        // And it is fatal under a strict policy, which is what a padding classification —
        // `Severity::Cosmetic` — would not have been.
        let report = r.scan();
        assert!(
            report.has_fatal(ReadPolicy::Strict),
            "a table that disagrees about a live entry is not a remark: {:#?}",
            report.anomalies()
        );

        // The control: the byte one past the entry's last belongs to nothing, and a
        // difference there is padding and stays cosmetic.
        let (mut bytes, layout) = fat12_with_an_even_highest_cluster();
        let past = table::entry_offset(FatType::Fat12, layout.clusters + 1) + 2;
        bytes[second + past as usize] ^= 0xFF;
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        assert!(matches!(
            r.verify_tables(),
            Err(ReadError::TablePaddingMismatch { copy: 1 })
        ));
    }

    #[test]
    fn a_divergence_in_a_shared_fat12_byte_names_the_entry_that_differs() {
        // The middle byte of a FAT12 pair belongs to two entries. A difference in its high
        // nibble is the *odd* entry's, and naming the even one would print a mismatch whose
        // two values are equal and send a repair at the wrong cluster.
        let (mut bytes, layout) = fat12_with_an_even_highest_cluster();
        let second = at(&layout, layout.fat_start_sector(1).expect("two tables"));
        // The pair (100, 101) shares the byte at offset 150 + 1.
        let odd = 101u32;
        let shared = table::entry_offset(FatType::Fat12, odd) as usize;
        assert!(odd < layout.clusters + 1, "the fixture is too small");

        let before = {
            let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
            (
                r.table_entry_in(0, odd - 1).expect("even entry"),
                r.table_entry_in(0, odd).expect("odd entry"),
            )
        };
        // The high nibble, which is the odd entry's low four bits.
        bytes[second + shared] ^= 0x10;

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        match r.verify_tables() {
            Err(ReadError::TableMismatch {
                copy,
                cluster,
                first,
                other,
            }) => {
                assert_eq!(copy, 1);
                assert_eq!(
                    cluster, odd,
                    "the shared byte was attributed to its neighbour"
                );
                assert_ne!(first, other, "a mismatch printed two identical values");
                assert_eq!(first, before.1);
            }
            other => panic!("expected a mismatch at the odd entry, got {other:?}"),
        }

        // And the other nibble of the same byte is the even entry's, reported as that one.
        let (mut bytes, _) = fat12_with_an_even_highest_cluster();
        bytes[second + shared] ^= 0x01;
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        match r.verify_tables() {
            Err(ReadError::TableMismatch {
                cluster,
                first,
                other,
                ..
            }) => {
                assert_eq!(cluster, odd - 1);
                assert_ne!(first, other);
                assert_eq!(first, before.0);
            }
            other => panic!("expected a mismatch at the even entry, got {other:?}"),
        }
    }

    #[test]
    fn a_long_name_whose_checksum_does_not_match_is_an_integrity_finding() {
        // The checksum is what stops a driver without long-name support from orphaning a
        // name onto the wrong file, so a mismatch means the long name describes a file that
        // is not there.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat16), |bytes, layout| {
            let root = at(
                layout,
                layout.root_dir_start_sector().expect("a root region"),
            );
            // Rename the short entry a run belongs to, which is exactly what breaks the tie
            // in practice: a driver without long-name support renames the file and the
            // stale run stops matching. Corrupting one entry *of* the run would make it
            // incomplete instead, which is the neighbouring finding.
            for slot in 1..layout.root_entries as usize {
                let off = root + slot * DIR_ENTRY_SIZE;
                let previous = root + (slot - 1) * DIR_ENTRY_SIZE;
                if bytes[off + 11] != DirAttributes::LFN.bits()
                    && bytes[previous + 11] == DirAttributes::LFN.bits()
                {
                    bytes[off] = b'Z';
                    return;
                }
            }
            panic!("the fixture holds no long-name run");
        });
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("checksums to")),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn a_first_cluster_outside_the_volume_is_a_structural_finding() {
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat16), |bytes, layout| {
            let root = at(
                layout,
                layout.root_dir_start_sector().expect("a root region"),
            );
            for slot in 0..layout.root_entries as usize {
                let off = root + slot * DIR_ENTRY_SIZE;
                let attrs = bytes[off + 11];
                let size = u32::from_le_bytes(bytes[off + 28..off + 32].try_into().unwrap());
                if attrs != DirAttributes::LFN.bits() && size > 0 {
                    bytes[off + 26..off + 28].copy_from_slice(&0xFFFEu16.to_le_bytes());
                    return;
                }
            }
            panic!("the fixture holds no file entry in the root");
        });
        assert!(
            report.worst_severity() >= Some(Severity::Structural),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn clusters_allocated_and_reached_by_nothing_are_reported() {
        // What `fsck.fat` calls lost clusters: space spent holding something no reader can
        // find. It is the one finding that needs the whole allocation rather than any single
        // structure, which is why the scan carries a set over the clusters.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat16), |bytes, layout| {
            // The last cluster number a volume of `clusters` clusters has is `clusters + 1`;
            // this one is inside the volume and no entry points at it.
            let orphan = layout.clusters;
            for copy in 0..layout.fats {
                let start = at(layout, layout.fat_start_sector(copy).expect("a table"));
                let off = start + table::entry_offset(FatType::Fat16, orphan) as usize;
                bytes[off..off + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            }
        });
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("reached by no chain")),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn an_entry_recording_a_length_and_no_first_cluster_is_named_where_it_is_read() {
        // FAT has no holes, so a length is a claim about clusters and a first cluster of zero
        // says there are none. Nothing downstream can see the two disagree: the storage such
        // an entry yields is the same `None` a legitimately empty file has, so the scan's
        // size-against-chain comparison has no chain to make it against — a volume `fsck.fat`
        // truncates the file on scanned clean, and the read refused halfway through an
        // extraction.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let entry = entry_of(&image, b"EMPTY      ");
        let mut bytes = image.into_bytes();
        bytes[entry + 28..entry + 32].copy_from_slice(&10u32.to_le_bytes());

        let err = Reader::open(Cursor::new(bytes.as_slice()))
            .expect("open")
            .walk()
            .expect_err("a strict read refuses it");
        assert!(
            matches!(err, ReadError::SizeWithoutAllocation { size: 10, .. }),
            "{err}"
        );

        // And the scan says it, at the severity that stops an `inspect`: this is the one
        // finding the volume carries, so nothing else could be standing in for it.
        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient open");
        let report = r.scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .filter(|a| a.detail.contains("no first cluster"))
            .collect();
        assert_eq!(found.len(), 1, "{:#?}", report.anomalies());
        assert_eq!(found[0].severity, Severity::Structural);
        assert!(!report.is_clean());

        // And the read objects too: the scan says so first and the read says so again, so a
        // caller reaching this entry either way is told.
        let node = r.lookup(b"/empty").expect("lookup");
        assert!(matches!(
            r.read_data(&node),
            Err(ReadError::ChainTooShort {
                start: 0,
                size: 10,
                read: 0
            })
        ));
    }

    #[test]
    fn a_backup_boot_sector_that_has_drifted_is_reported() {
        // It exists to be used when sector 0 cannot be read, so a copy that no longer
        // matches would restore a geometry the volume does not have.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat32), |bytes, layout| {
            let backup = layout
                .fat32
                .and_then(|f| f.backup_boot_sector)
                .expect("a backup");
            bytes[at(layout, u32::from(backup)) + 20] ^= 0xFF;
        });
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::BootSector),
            "{:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn the_half_of_the_information_sector_signature_nothing_explains_is_checked() {
        // The trailing signature's top half is the `55 AA` a stray boot signature accounts
        // for, so the parser does not require it. Its bottom half is two zero bytes that
        // nothing accounts for, and a value there is a false clean if the scan is silent
        // about it — which is the one thing a conformance surface must not be.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat32), |bytes, layout| {
            let info = at(
                layout,
                u32::from(layout.fat32.expect("a FAT32 layout").fs_info_sector),
            );
            bytes[info + FsInfo::TRAIL_OFFSET] ^= 0x01;
        });
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::InfoSector)
            .collect();
        assert_eq!(found.len(), 1, "{:#?}", report.anomalies());
        assert_eq!(found[0].severity, Severity::Cosmetic);
        assert!(found[0].detail.contains("trailing signature"));
        // Inert, so it is a remark: a strict read still opens the volume.
        assert!(!report.has_fatal(ReadPolicy::Strict));

        // And the half the parser's reasoning does cover stays unchecked, which is the
        // leniency that reasoning argues for rather than an oversight.
        let report = damaged(FatTypeRequest::Exactly(FatType::Fat32), |bytes, layout| {
            let info = at(
                layout,
                u32::from(layout.fat32.expect("a FAT32 layout").fs_info_sector),
            );
            bytes[info + FsInfo::TRAIL_OFFSET + 3] ^= 0xFF;
        });
        assert!(report.is_clean(), "{:#?}", report.anomalies());
    }

    #[test]
    fn a_short_name_above_ascii_is_a_conformance_deviation_until_a_page_is_named() {
        // The severity tracks whether the reader recognized what it saw, which is the whole
        // of what naming a code page changes: the bytes are the same either way.
        //
        // The deviation is about the name the entry is *found under*. An entry with a long
        // name is found under that, which is UTF-16 and unambiguous, so its short name is a
        // legacy second record and not something the reader has to interpret. This fixture
        // therefore holds one name that is already its own short name, which is the case
        // where the eleven bytes are the whole of what the volume says.
        let opts =
            options().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16)));
        let m = Metadata::new(0o644, TIME);
        let src = TreeBuilder::new().file(b"/README.TXT".to_vec(), b"hi\n".to_vec(), m);
        let built = format(src, 64 << 20, opts).expect("format");
        let layout = *built.layout();
        let mut bytes = built.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );
        let mut placed = false;
        for slot in 0..layout.root_entries as usize {
            let off = root + slot * DIR_ENTRY_SIZE;
            if &bytes[off..off + 11] == b"README  TXT" {
                bytes[off + 5] = 0x82;
                placed = true;
                break;
            }
        }
        assert!(placed, "the fixture holds no README entry");

        // Verbatim: a conformance deviation, so a strict read stops at it.
        let mut strict = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
        let root_node = strict.root();
        assert!(matches!(
            strict.read_dir(&root_node),
            Err(ReadError::UninterpretedShortName { byte: 0x82, .. })
        ));

        let mut lenient = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let root_node = lenient.root();
        let names: Vec<Vec<u8>> = lenient
            .read_dir(&root_node)
            .expect("read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&b"READM\x82.TXT".to_vec()), "{names:?}");
        let report = lenient.scan();
        assert_eq!(
            report.worst_severity(),
            Some(Severity::Conformance),
            "{:#?}",
            report.anomalies()
        );

        // Naming the page: the byte is interpreted, the read succeeds under a strict policy,
        // and the remark drops to cosmetic.
        let mut named = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().charset(ShortNameCharset::Cp437),
        )
        .expect("open");
        let root_node = named.root();
        let names: Vec<Vec<u8>> = named
            .read_dir(&root_node)
            .expect("a strict read, with the page named")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            names.contains(&"READMé.TXT".as_bytes().to_vec()),
            "{names:?}"
        );
        let report = named.scan();
        assert_eq!(report.worst_severity(), Some(Severity::Cosmetic));
        assert!(!report.has_fatal(ReadPolicy::Strict));
    }

    #[test]
    fn a_long_name_that_is_not_well_formed_utf16_is_read_with_a_replacement() {
        // An unpaired surrogate stands for no character. The name is still handed back, so a
        // tree carrying one stays enumerable, and the deviation is what says so.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );
        let mut placed = false;
        for slot in 0..layout.root_entries as usize {
            let off = root + slot * DIR_ENTRY_SIZE;
            // The entry holding a name's *first* characters is the one with ordinal 1, which
            // is the last of the run on disk and so the one immediately before its short
            // entry.
            if bytes[off + 11] == DirAttributes::LFN.bits() && bytes[off] & !LFN_LAST_ENTRY == 1 {
                bytes[off + 1..off + 3].copy_from_slice(&0xD800u16.to_le_bytes());
                placed = true;
                break;
            }
        }
        assert!(placed, "the fixture holds no long-name entry");

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let root_node = r.root();
        let names: Vec<Vec<u8>> = r
            .read_dir(&root_node)
            .expect("read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            names.iter().any(|n| n.starts_with("\u{FFFD}".as_bytes())),
            "{names:?}"
        );
        assert!(
            r.scan()
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("well-formed UTF-16"))
        );
    }

    #[test]
    fn an_orphaned_long_name_run_is_reported_however_the_run_ends() {
        // A long-name run belongs to the ordinary short entry that follows it, and that
        // entry is only one of the ways a run can end. The others leave the run belonging
        // to nothing — an end marker, a deleted entry, a volume label, a fresh sequence
        // start — and each must be a finding: the classic corruption here is a short
        // entry deleted with its long-name slots left behind, and a scan that reported
        // the orphan at one terminal state and not the others would go quiet on exactly
        // that shape.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let bytes = image.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );

        // The slot of the short entry a single-entry run belongs to.
        let short_off = (0..layout.root_entries as usize)
            .map(|slot| root + slot * DIR_ENTRY_SIZE)
            .find(|&off| {
                bytes[off + 11] == DirAttributes::LFN.bits() && bytes[off] == LFN_LAST_ENTRY | 1
            })
            .map(|off| off + DIR_ENTRY_SIZE)
            .expect("the fixture holds a single-entry long-name run");

        let orphans_of = |edit: &dyn Fn(&mut [u8])| -> usize {
            let mut edited = bytes.clone();
            edit(&mut edited[short_off..short_off + DIR_ENTRY_SIZE]);
            let mut r = Reader::open_with(
                Cursor::new(edited.as_slice()),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .expect("open");
            r.scan()
                .anomalies()
                .iter()
                .filter(|a| a.detail.contains("do not form a complete run"))
                .count()
        };

        // The untouched fixture holds no orphan, so each count below is the edit's.
        assert_eq!(orphans_of(&|_| {}), 0, "the fixture is clean");
        // The run ends at the directory's end marker.
        assert_eq!(
            orphans_of(&|slot| slot[0] = NAME_END),
            1,
            "at the end marker"
        );
        // The short entry was deleted and the run's slots were not.
        assert_eq!(
            orphans_of(&|slot| slot[0] = NAME_DELETED),
            1,
            "at a deleted entry"
        );
        // The run ends at the volume label, which is not a name in the tree.
        assert_eq!(
            orphans_of(&|slot| slot[11] = DirAttributes::VOLUME_ID.bits()),
            1,
            "at the volume label"
        );
        // A fresh last-in-sequence entry starts over, wiping the run in flight; whatever
        // ends the second run may be an orphan of its own, so the bound here is at least.
        assert!(
            orphans_of(&|slot| {
                slot[0] = LFN_LAST_ENTRY | 1;
                slot[11] = DirAttributes::LFN.bits();
            }) >= 1,
            "at a second sequence start"
        );
        // The run ends at a dot entry, whose two slots hold a directory's link to itself
        // and to its parent and never carry a long name. The name is dropped there like
        // the label's is, and the debris is a finding there like the label's is.
        assert_eq!(
            orphans_of(&|slot| {
                slot[..11].copy_from_slice(b".          ");
                slot[11] = DirAttributes::DIRECTORY.bits();
            }),
            1,
            "at a dot entry"
        );
    }

    /// Format a volume and rewrite the first single-entry long-name run in its root region to
    /// spell `name`.
    ///
    /// The ordinal, the last-in-sequence flag, and the checksum are left where they are, so
    /// the run is still well-formed and still belongs to the short entry that follows it.
    /// What changes is the name and nothing else about how the run is formed — which is what
    /// makes the resolved name the only thing under test.
    fn root_long_name_spelling(name: &str) -> Vec<u8> {
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );
        let units: Vec<u16> = name.encode_utf16().collect();
        assert!(
            units.len() < LFN_CHARS_PER_ENTRY,
            "the name and its terminator must fit one entry"
        );
        for slot in 0..layout.root_entries as usize {
            let off = root + slot * DIR_ENTRY_SIZE;
            // A run of exactly one entry: the last-in-sequence flag over ordinal 1.
            if bytes[off + 11] != DirAttributes::LFN.bits() || bytes[off] != LFN_LAST_ENTRY | 1 {
                continue;
            }
            for i in 0..LFN_CHARS_PER_ENTRY {
                // The thirteen units of one entry sit in three ranges the attribute byte and
                // the cluster field divide: five, then six, then two.
                let within = match i {
                    0..=4 => 1 + i * 2,
                    5..=10 => 14 + (i - 5) * 2,
                    _ => 28 + (i - 11) * 2,
                };
                // A name shorter than the entry holding it is terminated by one zero and
                // padded with `FFFF` after it, which is what the writer emits.
                let unit = match i.cmp(&units.len()) {
                    std::cmp::Ordering::Less => units[i],
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 0xFFFF,
                };
                bytes[off + within..off + within + 2].copy_from_slice(&unit.to_le_bytes());
            }
            return bytes;
        }
        panic!("the fixture holds no single-entry long-name run");
    }

    /// Format a volume and put `name` into the eleven-byte name field of its `EFI` directory
    /// entry — the one name in the fixture the writer stores without a long-name run, so the
    /// eleven bytes are the whole of what the reader has to go on.
    fn root_short_name_of_efi(name: &[u8; 11]) -> Vec<u8> {
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );
        for slot in 0..layout.root_entries as usize {
            let off = root + slot * DIR_ENTRY_SIZE;
            if &bytes[off..off + 11] == b"EFI        " {
                bytes[off..off + 11].copy_from_slice(name);
                return bytes;
            }
        }
        panic!("the fixture holds no EFI entry");
    }

    /// What a name no directory can hold must produce, whichever field it arrived in: a
    /// strict read that stops at it, a lenient read that hands it to nobody, and a scan that
    /// says the volume is not clean.
    fn assert_hostile_name_is_refused(bytes: &[u8], what: &str) {
        let mut strict = Reader::open(Cursor::new(bytes)).expect("open");
        let root_node = strict.root();
        assert!(
            matches!(
                strict.read_dir(&root_node),
                Err(ReadError::HostileName { .. })
            ),
            "{what}: a strict read did not stop at it"
        );

        let mut lenient = Reader::open_with(
            Cursor::new(bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let root_node = lenient.root();
        for entry in lenient.read_dir(&root_node).expect("a lenient read") {
            assert!(
                !is_hostile_component(&entry.name),
                "{what}: read_dir handed back {:?}",
                String::from_utf8_lossy(&entry.name)
            );
        }
        for entry in lenient.walk().expect("a lenient walk") {
            for component in canonical_parts(&entry.path) {
                assert!(
                    !is_hostile_component(component),
                    "{what}: the walk built {:?}",
                    String::from_utf8_lossy(&entry.path)
                );
            }
        }

        // And the volume is not called clean, which is what a consumer gating on
        // `is_clean()` before it extracts is relying on.
        let report = lenient.scan();
        assert!(!report.is_clean(), "{what}: the scan found nothing");
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.severity == Severity::Structural
                    && a.category == Category::Directory
                    && a.detail.contains("no directory can hold")),
            "{what}: {:#?}",
            report.anomalies()
        );
        assert!(report.has_fatal(ReadPolicy::Strict), "{what}");
    }

    #[test]
    fn a_long_name_a_directory_could_not_hold_is_refused_where_it_is_resolved() {
        // A run of long-name entries is reassembled after the dot entries are recognized by
        // their name field, so a run spelling `..` belongs to an ordinary short entry and
        // reaches the name a caller receives. The four names below are the ones a directory
        // cannot hold, and a crafted volume controls every byte of the run — the ordinal, the
        // checksum, and the units — so being well-formed says nothing about what it spells.
        for name in ["..", ".", "a/b", "../etc"] {
            assert_hostile_name_is_refused(&root_long_name_spelling(name), name);
        }
    }

    #[test]
    fn a_short_name_a_directory_could_not_hold_is_refused_where_it_is_resolved() {
        // The other field a name arrives in. An entry with no long-name run is found under
        // its eleven bytes, and nothing in the format stops those bytes being a separator or
        // a NUL — the character set a short name is restricted to is a formatter's rule, not
        // something a reader can assume of an image it did not write.
        for (name, what) in [(b"E/I        ", "a separator"), (b"E\0I        ", "a NUL")] {
            assert_hostile_name_is_refused(&root_short_name_of_efi(name), what);
        }
        // Eleven spaces render to nothing at all. An empty name is not a name: the path
        // built from one is the *directory's own* path with a trailing separator, which is
        // not an entry in that directory — and an archive writer renders it as a member
        // ending in `/`, which every tar reader takes for a directory and merges with the
        // real entry of that name.
        assert_hostile_name_is_refused(&root_short_name_of_efi(b"           "), "an empty name");
    }

    #[cfg(feature = "tar")]
    #[test]
    fn an_archive_of_a_volume_holding_a_traversal_name_carries_no_traversal_member() {
        // The consequence the refusal is there to prevent: this crate turning an untrusted
        // image into an archive whose members climb out of the directory they are unpacked
        // into. A great many tar readers unpack a `..` member where it points.
        let bytes = root_long_name_spelling("..");
        let mut reader = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let mut archive = Vec::new();
        crate::ArchiveSink::new(&mut archive)
            .write_tree(&mut reader)
            .expect("write the archive");

        let mut members = 0usize;
        for entry in tar::Archive::new(archive.as_slice())
            .entries()
            .expect("the archive lists its members")
        {
            let path = entry.expect("a member").path_bytes().to_vec();
            for component in canonical_parts(&path) {
                assert_ne!(
                    component,
                    b"..",
                    "the archive holds {:?}",
                    String::from_utf8_lossy(&path)
                );
            }
            assert!(!path.contains(&0), "a member name carries a NUL");
            members += 1;
        }
        // The rest of the tree is still there, so what the refusal cost is the one entry.
        assert!(members > 1, "the archive holds only {members} members");
    }

    #[test]
    fn a_used_slot_past_the_end_marker_is_reported_and_never_handed_back() {
        // Every driver stops at the marker, so an entry past it is storage nothing else on
        // the volume can see. Handing it back would show a caller a file no other tool
        // agrees exists, which is worse than not showing it — so it is reported and skipped.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let root = at(
            &layout,
            layout.root_dir_start_sector().expect("a root region"),
        );

        // The first free slot, which is where the writer put the end marker, gets an entry.
        let mut placed = None;
        for slot in 0..layout.root_entries as usize {
            let off = root + slot * DIR_ENTRY_SIZE;
            if bytes[off] == NAME_END {
                let mut ghost = [0u8; DIR_ENTRY_SIZE];
                ghost[..11].copy_from_slice(b"GHOST   TXT");
                ghost[11] = DirAttributes::ARCHIVE.bits();
                // A slot after the marker rather than at it, so the marker still terminates
                // the directory and this is genuinely past it.
                let past = off + DIR_ENTRY_SIZE;
                bytes[past..past + DIR_ENTRY_SIZE].copy_from_slice(&ghost);
                placed = Some(slot + 1);
                break;
            }
        }
        assert!(placed.is_some(), "the fixture's root has no free slot");

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let root_node = r.root();
        let names: Vec<Vec<u8>> = r
            .read_dir(&root_node)
            .expect("read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            !names.contains(&b"GHOST.TXT".to_vec()),
            "an entry past the end marker was handed back: {names:?}"
        );
        assert!(
            r.scan()
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("follows the end marker")),
            "{:#?}",
            r.scan().anomalies()
        );
        // And a strict read stops at it rather than quietly returning the shorter listing.
        let mut strict = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
        let root_node = strict.root();
        assert!(matches!(
            strict.read_dir(&root_node),
            Err(ReadError::EntriesAfterEnd { .. })
        ));
    }

    #[test]
    fn a_scan_that_stopped_short_does_not_report_lost_clusters() {
        // The lost-cluster finding is the one that needs the *whole* allocation: a cluster
        // is lost when nothing reached it, and "nothing reached it" is only true once the
        // walk has been everywhere. A scan that stopped at a bound reached fewer clusters
        // than the tree owns, so reporting the rest as unreferenced would turn a partial
        // traversal into a fact about the volume.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        for limits in [
            Limits::new().max_walk_entries(2),
            Limits::new().max_findings(1),
        ] {
            let mut r = Reader::open_with(
                Cursor::new(image.as_bytes()),
                &OpenOptions::new()
                    .policy(ReadPolicy::Lenient)
                    .limits(limits),
            )
            .expect("open");
            let report = r.scan();
            assert!(
                !report
                    .anomalies()
                    .iter()
                    .any(|a| a.detail.contains("reached by no chain")),
                "a scan that stopped short reported lost clusters: {:#?}",
                report.anomalies()
            );
        }
        // And with no bound in the way, the same volume scans clean — so the case above is
        // the bound doing something rather than the fixture having nothing to find.
        let mut r = Reader::open(Cursor::new(image.as_bytes())).expect("open");
        assert!(r.scan().is_clean());
    }

    #[test]
    fn a_scan_that_never_looked_is_not_a_clean_verdict() {
        // A cap of zero stops the scan before it reads a sector. The report is empty, and it
        // is *not* clean: an absence of findings from a scan that never looked is an absence
        // of looking, and a caller acting on `is_clean` must not read it as a verdict. This
        // is the ext reader's rule too, and it is one rule — both scans collect through the
        // same bounded accumulator, which is what records that reaching the cap stopped it.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let mut r = Reader::open_with(
            Cursor::new(image.as_bytes()),
            &OpenOptions::new()
                .policy(ReadPolicy::Lenient)
                .limits(Limits::new().max_findings(0)),
        )
        .expect("open");
        let report = r.scan();
        assert!(report.anomalies().is_empty());
        assert!(report.is_truncated());
        assert!(!report.is_clean(), "a truncated report claimed a verdict");
        assert!(report.to_report().to_json().contains("\"clean\":false"));
    }

    #[test]
    fn a_chain_that_loops_is_bounded_rather_than_followed() {
        // Nothing in a table says a chain ends, so a chain that points back at itself would
        // be followed forever. The bound is the volume's own cluster count, which a chain
        // cannot exceed without repeating one.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let start = {
            let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
            let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
            match node.storage {
                Storage::Chain(start) => start,
                _ => panic!("the fixture's multi-cluster file owns no chain"),
            }
        };

        // Point the chain's second cluster back at its first.
        for copy in 0..layout.fats {
            let off = at(&layout, layout.fat_start_sector(copy).expect("a table"))
                + table::entry_offset(FatType::Fat16, start + 1) as usize;
            bytes[off..off + 2].copy_from_slice(&(start as u16).to_le_bytes());
        }

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        assert!(matches!(
            r.chain(start),
            Err(ReadError::ChainTooLong { .. })
        ));
        // A *directory* whose chain cycles is the other half, and the expensive one. The
        // chain walks above stop at a repeat in two steps; the slot walk a directory read
        // goes through had no such check and re-read the cycling cluster once per cluster
        // the volume owns before refusing — and a scan absorbs that error and carries on, so
        // the cost was paid afresh for every directory in the volume. A 32 MiB volume of
        // such directories runs to hundreds of gigabytes of reads.
        //
        // Both shapes refuse; only the work says which was done, so the reads are counted.
        let mut cycled = bytes.clone();
        let dir_start = {
            let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
            let node = r.lookup(b"/EFI").expect("lookup");
            match node.storage {
                Storage::Chain(start) => start,
                _ => panic!("a FAT16 subdirectory owns a chain"),
            }
        };
        for copy in 0..layout.fats {
            let off = at(&layout, layout.fat_start_sector(copy).expect("a table"))
                + table::entry_offset(FatType::Fat16, dir_start) as usize;
            cycled[off..off + 2].copy_from_slice(&(dir_start as u16).to_le_bytes());
        }

        let reads = std::rc::Rc::new(std::cell::Cell::new(0usize));
        struct Counting {
            inner: Cursor<Vec<u8>>,
            reads: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl std::io::Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                std::io::Read::read(&mut self.inner, buf)
            }
        }
        impl Seek for Counting {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                Seek::seek(&mut self.inner, pos)
            }
        }
        let mut counted = Reader::open_with(
            Counting {
                inner: Cursor::new(cycled),
                reads: std::rc::Rc::clone(&reads),
            },
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let dir = counted.lookup(b"/EFI").expect("lookup");
        let before = reads.get();
        assert!(
            matches!(counted.read_dir(&dir), Err(ReadError::ChainTooLong { .. })),
            "a directory whose chain cycles is refused"
        );
        assert!(
            reads.get() - before < 64,
            "a directory cycling on one cluster cost {} reads",
            reads.get() - before
        );

        // And the scan says what it is rather than running forever.
        assert!(!r.scan().is_clean());
    }

    #[test]
    fn a_chain_looping_onto_itself_is_told_apart_from_a_cluster_two_chains_share() {
        // Whose claim is repeated decides what the scan says: a cluster this walk already
        // stepped through is the chain looping onto itself, and blaming "another chain"
        // for it would send a reader hunting for a second file that does not exist. The
        // chain's second cluster is pointed back at its first, so the walk returns to
        // where it began.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let layout = *image.layout();
        let mut bytes = image.into_bytes();
        let start = {
            let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
            let node = r.lookup(b"/a-long-file-name.text").expect("lookup");
            match node.storage {
                Storage::Chain(start) => start,
                _ => panic!("the fixture's multi-cluster file owns no chain"),
            }
        };
        for copy in 0..layout.fats {
            let off = at(&layout, layout.fat_start_sector(copy).expect("a table"))
                + table::entry_offset(FatType::Fat16, start + 1) as usize;
            bytes[off..off + 2].copy_from_slice(&(start as u16).to_le_bytes());
        }

        let mut r = Reader::open_with(
            Cursor::new(bytes.as_slice()),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open");
        let report = r.scan();
        let said = report
            .anomalies()
            .iter()
            .find(|a| a.detail.contains("loops"))
            .unwrap_or_else(|| panic!("no loop finding: {}", report.to_report().to_table()))
            .detail
            .clone();
        assert!(
            said.contains(&format!(
                "the chain from cluster {start} returns to cluster {start}"
            )),
            "{said}"
        );
        assert!(
            said.contains("a-long-file-name.text"),
            "the owning path rides along: {said}"
        );
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("another chain")),
            "a loop is not a cross-link: {}",
            report.to_report().to_table()
        );
    }

    #[test]
    fn the_reader_never_panics_on_mangled_images() {
        // The never-panic contract: opening and every read path return errors on malformed
        // bytes, never crash. A deterministic sweep over degenerate geometry, truncations,
        // and bit-flips of a valid volume; the cargo-fuzz target in fuzz/ is the exhaustive
        // version.
        let image = image(2, FatTypeRequest::Exactly(FatType::Fat12)).into_bytes();

        fn drive(bytes: &[u8]) {
            for options in [
                OpenOptions::new(),
                OpenOptions::new().policy(ReadPolicy::Lenient),
                OpenOptions::new()
                    .policy(ReadPolicy::Lenient)
                    .charset(ShortNameCharset::Cp437),
                OpenOptions::new().base(512).policy(ReadPolicy::Lenient),
            ] {
                let Ok(mut r) = Reader::open_with(Cursor::new(bytes), &options) else {
                    continue;
                };
                let _ = r.verify_tables();
                let _ = r.info_sector();
                let _ = r.volume_label();
                let _ = r.scan();
                if let Ok(entries) = r.walk() {
                    for e in &entries {
                        let _ = r.read_data(&e.node);
                        if let Storage::Chain(start) = e.node.storage {
                            let _ = r.chain(start);
                        }
                    }
                    for e in &entries {
                        let _ = r.lookup(&e.path);
                    }
                }
                for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./"] {
                    let _ = r.lookup(path);
                }
            }
        }

        drive(&image);

        // Degenerate geometry that would divide by zero or underflow if unguarded. Offsets
        // are into the parameter block at the start of sector 0.
        for (off, len, fill) in [
            (11usize, 2usize, 0xffu8), // BPB_BytsPerSec
            (13, 1, 0x00),             // BPB_SecPerClus
            (14, 2, 0xff),             // BPB_RsvdSecCnt
            (16, 1, 0xff),             // BPB_NumFATs
            (17, 2, 0xff),             // BPB_RootEntCnt
            (19, 2, 0xff),             // BPB_TotSec16
            (22, 2, 0xff),             // BPB_FATSz16
            (32, 4, 0xff),             // BPB_TotSec32
        ] {
            let mut mangled = image.clone();
            mangled[off..off + len].fill(fill);
            drive(&mangled);
        }

        // Truncations at assorted lengths.
        for len in [0usize, 1, 511, 512, 513, 1024, 4096, 65_536] {
            drive(&image[..len.min(image.len())]);
        }

        // Deterministic single-byte flips across the metadata region, one image reused
        // (flip, drive, restore) so the sweep stays cheap.
        let mut flip = image.clone();
        let span = flip.len().min(96 * 1024);
        let mut i = 0usize;
        while i < span {
            let orig = flip[i];
            flip[i] ^= 0xff;
            drive(&flip);
            flip[i] = orig;
            i += 251; // a prime stride, so flips land on varied field offsets
        }

        // A few fixed non-image patterns.
        drive(&vec![0x00u8; 8192]);
        drive(&vec![0xffu8; 8192]);
        let ramp: Vec<u8> = (0..8192u32).map(|k| (k % 256) as u8).collect();
        drive(&ramp);
    }
}
