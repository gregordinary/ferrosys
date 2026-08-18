//! The reader: parse an exFAT volume back into a geometry, a directory tree, and file
//! contents.
//!
//! It reads volumes other implementations wrote, not only the ones this crate writes. Both
//! run shapes the format defines are followed through one implementation — a stream that
//! declares `NoFatChain` is read as consecutive clusters and the allocation table is not
//! consulted for it, and a stream that does not is followed through the table — and the two
//! coalesce into one answer, because which of them a file uses is a property of how it was
//! written rather than of what it holds.
//!
//! One shape the format permits is outside what this reads: a volume recording two allocation
//! tables, which is the transaction-safe variant. It is refused by name below the policy
//! threshold, so it is refused under [`ReadPolicy::Lenient`] as well as under `Strict` — see
//! [`ReadError::TexFat`]. Misreading one as an ordinary volume would follow the wrong table on
//! a volume whose whole point is that there are two.
//!
//! # Robustness and strictness
//!
//! Two properties are kept apart. *Robustness* is always on: every on-disk field is
//! bounds-checked and every fallible step returns a [`ReadError`] rather than panicking or
//! reading out of range, on any input — including one built to break it.
//!
//! *Conformance strictness* is a policy: a threshold over the [`Severity`] of the
//! [`Anomaly`] a deviation carries. [`ReadPolicy::Strict`], the default, is fatal at any
//! deviation an exFAT volume this crate writes would not carry, so a strict read either
//! yields the filesystem the image describes or names the deviation that stopped it.
//!
//! **A strict read accepts every volume this crate's own writer produces, and every state a
//! conformant driver can leave behind.** The first half is the line the severities are drawn
//! against, and it is what makes the two halves of the family one thing rather than two: a
//! format followed by a strict open is a round trip at every input the writer accepts. The
//! second half is what keeps that from refusing ordinary images — a volume a driver had open
//! and did not put down, and a stream whose written length trails its allocated length, are
//! both states this crate's writer never produces and every driver produces routinely. Each
//! is reported at [`Severity::Cosmetic`], so a strict read of a card someone pulled out of a
//! reader still succeeds and still says what it found.
//!
//! [`ReadPolicy::Lenient`] moves the threshold above every severity, so nothing is fatal. A
//! whole-volume [`scan`](Reader::scan) checks both boot regions, the allocation table's
//! reserved entries, the three residents of the cluster heap, every directory entry set, and
//! every cluster the tree reaches against the allocation bitmap — including the clusters the
//! bitmap says are in use and nothing reaches — collecting each deviation as an [`Anomaly`]
//! into a [`ScanReport`] instead of stopping at the first.
//!
//! # The volume's own case folding
//!
//! exFAT compares names case-insensitively, and what that means is a mapping the volume
//! carries in its cluster heap rather than a property of Unicode. So the table is read at
//! open, its checksum verified, its run compression decoded, and every lookup and every
//! `NameHash` check goes through it. A reader that folded through its own copy would resolve
//! names a driver does not and miss names a driver finds.
//!
//! # What an exFAT volume does not tell you
//!
//! There is no owner, no permission bits beyond a read-only flag, no symbolic link, no second
//! name for a file, and no extended attribute. Each is filled from the caller's [`Synthesis`]
//! on the extraction surface and named there.
//!
//! The handle opens over any [`Read`] + [`Seek`] source at an arbitrary byte offset, so it
//! reads a volume inside a partitioned disk image as readily as a bare one.

use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::ControlFlow;

use crate::bytes::{get_u16, get_u32};
use crate::fidelity::Synthesis;
use crate::finding::{Family, Finding, Findings, Severity};
use crate::io::{offset_of, read_exact_at};
use crate::path::is_hostile_component;
use crate::policy::{Limits, MAX_PATH, OpenOptions, ReadPolicy};
use crate::time::Timestamp;
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};

use super::geometry::{ExfatLayout, FIRST_CLUSTER, layout_from_boot};
use super::model::MAX_DIRECTORY_BYTES;
use super::ondisk::{
    AllocationBitmapEntry, BAD_CLUSTER, BOOT_REGION_SECTORS, CHECKSUM_SECTOR, DIR_ENTRY_SIZE,
    EXTENDED_BOOT_FIRST_SECTOR, EXTENDED_BOOT_SECTORS, EXTENDED_BOOT_SIGNATURE, EntryType,
    FAT_ENTRY_MEDIA, FAT_ENTRY_RESERVED, FILE_SYSTEM_MINOR_REVISION, FileAttributes, FileEntry,
    FileNameEntry, MAIN_BOOT_REGION_SECTOR, MAX_LABEL_UNITS, MainBootSector, NAME_UNITS_PER_ENTRY,
    PERCENT_IN_USE_MAX, PERCENT_IN_USE_UNKNOWN, ParseError, SECONDARY_ALLOCATION_POSSIBLE,
    StreamExtensionEntry, UpcaseTable, UpcaseTableEntry, VOLUME_FLAG_MEDIA_FAILURE,
    VOLUME_FLAG_VOLUME_DIRTY, VolumeLabelEntry, boot_checksum, checksum_sector_value,
    entry_set_checksum, extended_boot_signature, name_hash, percent_in_use, unpack_timestamp,
    upcase_checksum, utc_offset_minutes,
};

/// The most bytes of an up-case table this reader loads.
///
/// A table maps the Basic Multilingual Plane and nothing beyond it, so 65536 units — 131072
/// bytes — is every mapping one could state, and the run-compressed form every implementation
/// writes is a twentieth of that. A declared length past this is not a table length, and
/// loading it would be an allocation an image chose.
const MAX_UPCASE_BYTES: u64 = 2 * 0x1_0000;

/// The subsystem a deviation was found in.
///
/// exFAT has five, and they are neither ext's nor FAT's: there is no superblock and no group
/// descriptor, and the two things FAT keeps in one allocation table are two structures here —
/// the table says what chains where and the bitmap says what is in use, and a volume can be
/// wrong about either alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Category {
    /// A boot region — the Main Boot Sector, the sectors behind it, or its checksum.
    BootRegion,
    /// The allocation table, or a chain it records.
    AllocationTable,
    /// The allocation bitmap, or the allocation it records.
    AllocationBitmap,
    /// The up-case table, or the entry describing it.
    UpcaseTable,
    /// A directory, an entry set in it, or a name one carries.
    Directory,
}

impl Category {
    /// The lowercase name of this subsystem, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::BootRegion => "boot region",
            Category::AllocationTable => "allocation table",
            Category::AllocationBitmap => "allocation bitmap",
            Category::UpcaseTable => "up-case table",
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
    /// Sector number within the volume, when the deviation is sector-addressed. This is what
    /// becomes the byte offset a [`Finding`] carries.
    ///
    /// Sixty-four bits wide, unlike the cluster beside it: an exFAT volume's length is
    /// recorded in sectors as a 64-bit field, so a sector number is the one coordinate here
    /// that a 32-bit value would truncate on a large volume.
    pub sector: Option<u64>,
    /// Cluster number, when the deviation is cluster-addressed.
    pub cluster: Option<u32>,
    /// Index of a directory entry within its directory, counting 32-byte slots from zero.
    pub entry: Option<u32>,
}

impl Location {
    /// This location with any coordinate `other` carries that this one does not.
    ///
    /// A deviation knows where it is in its own terms — a table entry knows its cluster — and
    /// the walk that met it knows the rest. Merging rather than replacing is what keeps the
    /// more specific of the two.
    fn or(self, other: Self) -> Self {
        Self {
            sector: self.sector.or(other.sector),
            cluster: self.cluster.or(other.cluster),
            entry: self.entry.or(other.entry),
        }
    }

    /// A location naming the directory entry at `index`, and nothing else.
    const fn at_entry(index: u32) -> Self {
        Self {
            sector: None,
            cluster: None,
            entry: Some(index),
        }
    }

    /// A location naming `cluster`, and nothing else.
    const fn at_cluster(cluster: u32) -> Self {
        Self {
            sector: None,
            cluster: Some(cluster),
            entry: None,
        }
    }

    /// A location naming `sector`, and nothing else.
    const fn at_sector(sector: u64) -> Self {
        Self {
            sector: Some(sector),
            cluster: None,
            entry: None,
        }
    }
}

/// A typed deviation from what this crate would emit, carrying its severity, the subsystem it
/// was found in, where it sits, and a human description.
///
/// This is exFAT's structured value, and it stays exFAT's: the subsystem is a [`Category`]
/// rather than a word, and the place is a cluster, a sector, and an entry index, because
/// those are what a consumer reasoning about an exFAT volume acts on.
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

    /// The sector size is the addressing unit an exFAT location is stated in.
    fn to_finding(&self, unit: u32) -> Finding {
        Anomaly::to_finding(self, unit)
    }
}

impl Anomaly {
    /// Project this anomaly into the crate's family-agnostic [`Finding`], resolving a
    /// sector-addressed location to the byte offset that sector sits at under
    /// `bytes_per_sector`.
    ///
    /// The coordinates carry exFAT's own words, outermost first — `cluster`, then `sector`,
    /// then `entry` — which is the order a person reads a location in. A cluster number is
    /// not converted to an offset, because where it sits depends on the layout rather than on
    /// the number alone, so an anomaly located only by one carries no offset.
    #[must_use]
    pub fn to_finding(&self, bytes_per_sector: u32) -> Finding {
        // Destructured exhaustively on purpose: a field added to `Anomaly` is a compile error
        // here, which forces a decision about what the projection carries rather than letting
        // a new fact about a finding go silently unreported.
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
            Family::ExFat,
            category.as_str(),
            &[
                ("cluster", cluster.map(u64::from)),
                ("sector", sector),
                ("entry", entry.map(u64::from)),
            ],
            // The sector is what addresses bytes. A cluster number does not: where it sits
            // depends on the layout rather than on the number alone.
            sector,
            bytes_per_sector,
            detail,
        )
    }
}

/// A failure reading an exFAT volume.
///
/// The variants divide into three kinds. A few are the source's rather than the image's
/// ([`Io`](Self::Io)) or a caller's bound being reached ([`FileTooLarge`](Self::FileTooLarge),
/// [`WalkTooLarge`](Self::WalkTooLarge)). Most are deviations from what an exFAT volume this
/// crate writes carries, each of which projects to a typed [`Anomaly`] through
/// [`anomaly`](Self::anomaly) — so the same fault is an error under [`ReadPolicy::Strict`] and
/// a collected finding under a scan, described the same way either time. The rest are a
/// caller asking for something that is not there.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The underlying source could not be read or sought.
    ///
    /// Carried as [`TreeError::Io`] describes, which is where the rule this crate records an
    /// i/o failure by is written out: the kind beside the message, so a caller tells a
    /// truncated image from an environment failure without matching on text.
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
    /// The Main Boot Sector does not describe an exFAT volume: a field holds a value no such
    /// volume carries, or the fields do not agree with each other.
    ///
    /// This is what detection answers "not ours" to. The reader names what is wrong instead,
    /// because a caller who reached the reader has already been told the image is an exFAT
    /// volume and needs to know why it is not readable as one.
    #[error("the boot sector does not describe an exFAT volume: {detail}")]
    #[non_exhaustive]
    BadBootSector {
        /// Which of the sector's fields does not agree with the others.
        detail: String,
    },
    /// The volume records two allocation tables, which is the transaction-safe variant of the
    /// format.
    ///
    /// A second table is not a mirror. It is the other half of a transaction mechanism, and
    /// which of the two is live is `VolumeFlags` bit 0 — so a reader that treated the volume
    /// as an ordinary one would follow whichever table it picked and be right half the time.
    /// Refusing by name is the only answer that does not silently misread it.
    #[error("this volume records two allocation tables, which is the transaction-safe variant")]
    TexFat,
    /// The volume records a count of allocation tables the format does not define.
    #[error("a volume with {count} allocation tables is not one the format defines")]
    #[non_exhaustive]
    FatCount {
        /// The count found on disk.
        count: u8,
    },
    /// A boot region's stored checksum is not the checksum of the region's own bytes.
    ///
    /// The checksum covers the region's first eleven sectors, two fields of the first
    /// excepted, so a mismatch means those bytes have changed since a formatter wrote them —
    /// and every geometry field a reader depends on is among them.
    #[error(
        "the boot region at sector {sector} checksums to {computed:#010x} and records \
         {stored:#010x}"
    )]
    #[non_exhaustive]
    BootChecksumMismatch {
        /// The region's first sector: 0 for the main region, 12 for its backup.
        sector: u64,
        /// The checksum the region's bytes make.
        computed: u32,
        /// The value its checksum sector records.
        stored: u32,
    },
    /// A boot region's checksum sector does not hold one value repeated for its whole length.
    ///
    /// The repetition is the format's, and a sector whose words disagree is not a checksum
    /// with a stale tail — it is a sector this reader cannot say the intended value of.
    #[error("the checksum sector of the boot region at sector {sector} does not repeat one value")]
    #[non_exhaustive]
    BootChecksumSectorSplit {
        /// The region's first sector.
        sector: u64,
    },
    /// The backup boot region does not describe the same volume as the main one.
    ///
    /// It exists to be used when the main region cannot be read, so a copy that has drifted is
    /// worse than none: it would restore a geometry the volume does not have. The two fields
    /// outside the region's checksum are not compared — a mounted driver rewrites those in the
    /// main region alone, and a volume in ordinary use has them differing by design.
    #[error(
        "the backup boot region at sector {sector} does not describe the same volume: {detail}"
    )]
    #[non_exhaustive]
    BackupBootRegionDiffers {
        /// Where the backup region begins.
        sector: u64,
        /// Which field differs.
        detail: String,
    },
    /// The volume records a minor revision of the format this reader does not know.
    ///
    /// The format asks an implementation to honour a minor revision above zero rather than
    /// refuse it, so this is a remark: every structure is the one this reader knows, and
    /// something in the volume may mean more than it appears to. A *major* revision other
    /// than 1 is the refusal, and it is [`BadBootSector`](Self::BadBootSector), raised where
    /// the rest of the boot sector is judged.
    #[error(
        "this volume records minor revision {minor} of the format, which this reader does not know"
    )]
    #[non_exhaustive]
    UnknownMinorRevision {
        /// The minor revision found on disk.
        minor: u8,
    },
    /// An extended boot sector does not end with the signature the format requires.
    ///
    /// The region's checksum covers whatever is in the sector, so a region whose eight
    /// signatures are all missing and whose checksum agrees with its bytes is self-consistent
    /// and still not the region the format defines.
    #[error(
        "the extended boot sector at sector {sector} ends with {found:#010x} and the format \
         requires {expected:#010x}"
    )]
    #[non_exhaustive]
    BadExtendedBootSignature {
        /// The sector, counted from the volume's start.
        sector: u64,
        /// The value found in the sector's last four bytes.
        found: u32,
        /// [`EXTENDED_BOOT_SIGNATURE`].
        expected: u32,
    },
    /// A structure names a cluster the volume does not have.
    #[error("cluster {cluster} is not a cluster this volume has")]
    #[non_exhaustive]
    ClusterOutOfRange {
        /// The cluster named.
        cluster: u32,
    },
    /// A chain reaches a cluster the allocation table marks as one the medium could not be
    /// relied on for.
    ///
    /// A bad cluster is not part of any chain: it is a number the format sets aside so that
    /// nothing allocates it. A chain reaching one is a chain into storage a driver was told
    /// to leave alone, which is why it is named rather than followed.
    #[error("the chain reaches cluster {cluster}, which the allocation table marks bad")]
    #[non_exhaustive]
    BadClusterInChain {
        /// The cluster the table marks bad.
        cluster: u32,
    },
    /// A chain's table entry holds a value no chain may contain: free, reserved, or the
    /// bad-cluster mark.
    #[error("the table entry for cluster {cluster} is {entry:#010x}, which no chain may contain")]
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
    /// A stream's allocation ends before the length its entry records.
    ///
    /// A length is a claim about clusters, and one that stops short means the length and the
    /// allocation disagree. Handing back a short buffer would report success for a file that
    /// is not all there.
    #[error("a stream from cluster {start} holds {held} bytes and its entry records {declared}")]
    #[non_exhaustive]
    StreamTooShort {
        /// The stream's first cluster.
        start: u32,
        /// The length the stream extension records.
        declared: u64,
        /// Bytes the allocation actually holds.
        held: u64,
    },
    /// A reserved entry of the allocation table does not hold the value the format defines
    /// for it.
    #[error("table entry {index} is {found:#010x} where the format defines {expected:#010x}")]
    #[non_exhaustive]
    BadReservedEntry {
        /// The entry's index: 0 carries the media descriptor, 1 is reserved.
        index: u32,
        /// The value found.
        found: u32,
        /// The value the format defines.
        expected: u32,
    },
    /// The root directory does not describe one of the residents every volume must carry.
    ///
    /// The allocation bitmap and the up-case table are found by reading the root directory and
    /// nowhere else, so a volume missing one is a volume in which nothing can be allocated or
    /// nothing can be looked up — and a reader that answered with an empty tree would report a
    /// working filesystem.
    #[error("the root directory describes no {resident}, which every volume carries")]
    #[non_exhaustive]
    MissingResident {
        /// Which resident, in the format's own words.
        resident: &'static str,
    },
    /// The up-case table's bytes are not the mapping its entry advertises.
    ///
    /// The checksum is the only thing standing between "the table this volume folds through"
    /// and "whatever bytes are at that cluster", so a mismatch means every name comparison on
    /// the volume is being made through a mapping nobody wrote.
    #[error("the up-case table checksums to {computed:#010x} and its entry records {stored:#010x}")]
    #[non_exhaustive]
    UpcaseChecksumMismatch {
        /// The checksum the table's bytes make.
        computed: u32,
        /// The value the describing entry records.
        stored: u32,
    },
    /// The up-case table's entry records a length no mapping of the Basic Multilingual Plane
    /// reaches.
    #[error("an up-case table of {bytes} bytes is longer than the {limit} a mapping can need")]
    #[non_exhaustive]
    UpcaseTooLong {
        /// The length the describing entry records.
        bytes: u64,
        /// The most bytes a mapping of the plane occupies.
        limit: u64,
    },
    /// The allocation bitmap is not one bit per cluster.
    #[error(
        "an allocation bitmap of {bytes} bytes does not hold one bit for each of {clusters} clusters"
    )]
    #[non_exhaustive]
    BitmapWrongSize {
        /// The length the describing entry records.
        bytes: u64,
        /// Clusters the volume has.
        clusters: u32,
    },
    /// A directory entry set's stored checksum is not the checksum of the set's own bytes.
    ///
    /// The checksum covers every entry of the set, which is what makes a half-written one
    /// detectable: a set is a file's whole record, and half of one is not a file.
    #[error(
        "the entry set at entry {index} checksums to {computed:#06x} and records {stored:#06x}"
    )]
    #[non_exhaustive]
    SetChecksumMismatch {
        /// The set's first entry index within its directory.
        index: u32,
        /// The checksum the set's bytes make.
        computed: u16,
        /// The value the file entry records.
        stored: u16,
    },
    /// A file entry's set does not hold the entries it says it does, or is not followed by
    /// them.
    ///
    /// A set is one file entry, one stream extension, and the name entries behind them. A set
    /// that ends early, or one whose secondary entries are not marked as secondary, describes
    /// a file whose record is incomplete.
    #[error("the entry set at entry {index} is not complete: {detail}")]
    #[non_exhaustive]
    IncompleteEntrySet {
        /// The set's first entry index within its directory.
        index: u32,
        /// What is missing from it.
        detail: String,
    },
    /// An entry marked as continuing a set sits where no set is open.
    #[error("entry {index} continues a set that no entry opened")]
    #[non_exhaustive]
    StraySecondaryEntry {
        /// The entry's index within its directory.
        index: u32,
    },
    /// A directory holds an entry of a type this reader does not recognize and the format does
    /// not permit it to ignore.
    ///
    /// The type byte says whether an implementation that does not know an entry may carry on.
    /// A *benign* one it does not know is carried through untouched; a *critical* one means it
    /// cannot claim to understand the volume, which is what this reports.
    #[error("entry {index} is of critical type {entry_type:#04x}, which this reader does not know")]
    #[non_exhaustive]
    UnknownCriticalEntry {
        /// The entry's index within its directory.
        index: u32,
        /// The type byte found there.
        entry_type: u8,
    },
    /// A name's code units are not well-formed UTF-16: it carries a surrogate with no partner,
    /// which stands for no character.
    ///
    /// The name is still read, with each such unit replaced by U+FFFD, so a tree carrying one
    /// is still enumerable under a lenient read.
    #[error("the name at entry {index} is not well-formed UTF-16")]
    #[non_exhaustive]
    IllFormedName {
        /// The set's first entry index within its directory.
        index: u32,
    },
    /// A name's hash is not the hash of the name behind it.
    ///
    /// The hash is a lookup accelerator: a driver compares it to skip a set without
    /// reassembling the name in it. So a wrong one costs no data and makes the file invisible
    /// to every driver that trusts it — a failure a reader is uniquely placed to name and no
    /// checksum covers, since the set's own checksum is satisfied by a hash and a name that
    /// disagree.
    #[error(
        "the name at entry {index} hashes to {computed:#06x} and its entry records {stored:#06x}"
    )]
    #[non_exhaustive]
    NameHashMismatch {
        /// The set's first entry index within its directory.
        index: u32,
        /// The hash of the up-cased name the set carries.
        computed: u16,
        /// The hash the stream extension records.
        stored: u16,
    },
    /// An entry's name is one no directory can hold: `.` or `..`, empty, or a name carrying a
    /// path separator or a NUL.
    ///
    /// The first two name a directory rather than something inside it, an empty name names
    /// nothing, a separator would traverse out of the tree, and a NUL would truncate the path
    /// a consumer forms from the name. Nothing about the field a name arrives in rules any of
    /// them out: an exFAT name is UTF-16 and may spell anything.
    ///
    /// The name itself is not repeated in the message. It is the image's, an image is
    /// untrusted input, and a name built to be one a directory cannot hold is equally free to
    /// carry the control bytes that would rewrite the line it is printed on.
    #[error("the name at entry {index} is one no directory can hold")]
    #[non_exhaustive]
    HostileName {
        /// The set's first entry index within its directory.
        index: u32,
    },
    /// An entry set carries more name entries than its name needs.
    ///
    /// The secondary count is defined as one plus the entries the name occupies, so a set
    /// carrying one the name does not reach into is a set the format does not describe. The
    /// name is still the one `NameLength` states — no implementation reads past it — so this
    /// is a remark about bytes nothing reads rather than a name in doubt.
    #[error("the entry set at entry {index} carries {have} name entries and its name needs {want}")]
    #[non_exhaustive]
    ExcessNameEntries {
        /// Name entries the length the stream extension records occupies.
        want: usize,
        /// Name entries the set carries.
        have: usize,
        /// The set's first entry index within its directory.
        index: u32,
    },
    /// A volume label entry sits somewhere other than the root directory, where it is the one
    /// place the format defines for it.
    #[error("a {entry_type} entry sits at entry {index} of a directory that is not the root")]
    #[non_exhaustive]
    MisplacedRootEntry {
        /// The entry's index within its directory.
        index: u32,
        /// What kind of entry it is, in the format's own words.
        entry_type: &'static str,
    },
    /// The root directory carries a second entry of a kind the format defines one of.
    ///
    /// There is one allocation bitmap, one up-case table and one volume label on a volume
    /// outside the transaction-safe variant, which this reader refuses by name anyway. A
    /// reader takes the first of each and steps over the rest, so a second is storage nothing
    /// reads and a second answer to a question with one.
    #[error("a second {entry_type} entry sits at entry {index} of the root directory")]
    #[non_exhaustive]
    DuplicateRootEntry {
        /// The entry's index within the root directory.
        index: u32,
        /// What kind of entry it is, in the format's own words.
        entry_type: &'static str,
    },
    /// The volume label entry records more characters than the field holds.
    ///
    /// `CharacterCount` runs 0 to 11 and the field is eleven code units wide, so a larger
    /// count names units that are not there. Reading the field to its end is the only thing a
    /// reader can do with one, and what lies past the label is the field's zero padding.
    #[error("a volume label of {count} characters is longer than the {limit} the field holds")]
    #[non_exhaustive]
    LabelTooLong {
        /// The count found on disk.
        count: u8,
        /// [`MAX_LABEL_UNITS`].
        limit: usize,
    },
    /// The volume label carries `U+0000`, which is what the field's padding is.
    ///
    /// A label holding one is a label every implementation that reads the field as terminated
    /// rather than counted would read differently, so this crate's writer refuses to produce
    /// one and this answers [`volume_label`](Reader::volume_label) with `None` rather than
    /// handing back a name that is not one.
    #[error("the volume label carries a NUL, which is what the field's padding is")]
    LabelNulUnit,
    /// A directory holds entries after the one that marks its end, which no reader will reach.
    #[error("directory entry {index} follows the end marker and no reader reaches it")]
    #[non_exhaustive]
    EntriesAfterEnd {
        /// The index of the first entry past the marker.
        index: u32,
    },
    /// A directory's entry records no allocation, so it holds not even the byte that ends it.
    #[error("the directory at entry {index} records no clusters, so it holds no entries at all")]
    #[non_exhaustive]
    DirectoryWithoutAllocation {
        /// The set's first entry index within its parent.
        index: u32,
    },
    /// A stream records a length and no first cluster.
    ///
    /// The format states the constraint in both directions: a first cluster of zero means the
    /// stream owns nothing, and the only length a stream owning nothing has is zero. An entry
    /// claiming bytes it has nowhere to keep describes a file whose contents no read can
    /// reach, and the incoherence surfaces halfway through an extraction rather than at the
    /// entry that carries it.
    #[error("the stream at entry {index} records {declared} bytes and no first cluster")]
    #[non_exhaustive]
    StreamWithoutAllocation {
        /// The set's first entry index within its directory.
        index: u32,
        /// The length the stream extension records.
        declared: u64,
    },
    /// A stream records a first cluster and no length.
    ///
    /// The converse of [`StreamWithoutAllocation`](Self::StreamWithoutAllocation), and the
    /// other half of the same constraint: a stream owning nothing has a first cluster of zero,
    /// so a stream naming a cluster and claiming no bytes has an allocation nothing reaches.
    /// The clusters behind it are spent and hold nothing a read can find, which a scan
    /// otherwise meets only at the far end, as clusters in use and reached by no stream.
    #[error("the stream at entry {index} records no bytes and a first cluster of {first_cluster}")]
    #[non_exhaustive]
    AllocationWithoutLength {
        /// The set's first entry index within its directory.
        index: u32,
        /// The cluster the stream extension names.
        first_cluster: u32,
    },
    /// A stream records a length longer than the whole cluster heap.
    ///
    /// exFAT has no holes, so a stream's bytes are its allocation and the heap is what bounds
    /// it. The bound refuses no conformant volume — the whole heap is the most anything in it
    /// could occupy — and without it a 64-bit field turns any volume into an unbounded source
    /// of the zeros an unwritten tail reads as.
    #[error("a stream of {declared} bytes is longer than the {limit} bytes the cluster heap holds")]
    #[non_exhaustive]
    StreamPastHeap {
        /// The length the stream extension records.
        declared: u64,
        /// Bytes the cluster heap holds.
        limit: u64,
    },
    /// A directory records a length past the cap the format puts on one.
    ///
    /// It is the one capacity limit exFAT puts on a tree's shape, and it is what keeps the
    /// cost of reading a directory a property of the format rather than of the number the
    /// entry happens to carry: every slot the length covers is read, so an unbounded length
    /// is an unbounded read per directory.
    #[error(
        "the directory at entry {index} records {declared} bytes, more than the {limit} the \
         format allows one"
    )]
    #[non_exhaustive]
    DirectoryTooLong {
        /// The set's first entry index within its parent.
        index: u32,
        /// The length the stream extension records.
        declared: u64,
        /// [`MAX_DIRECTORY_BYTES`].
        limit: u64,
    },
    /// A directory's length is not a whole number of clusters.
    ///
    /// The format states a directory's `DataLength` as the entire size of its allocation, and
    /// an allocation is clusters — so every conformant volume's is a multiple of the cluster
    /// size. A directory is enumerated by the clusters its length covers, so a length that is
    /// not one is a number neither honoured nor meaningful.
    #[error(
        "the directory at entry {index} records {declared} bytes, which is not whole clusters \
         of {bytes_per_cluster}"
    )]
    #[non_exhaustive]
    DirectoryLengthNotClusters {
        /// The set's first entry index within its parent.
        index: u32,
        /// The length the stream extension records.
        declared: u64,
        /// The volume's cluster size.
        bytes_per_cluster: u32,
    },
    /// An entry sets attribute bits the format reserves.
    ///
    /// Eleven of the sixteen are reserved and zero on a conformant volume, bit 3 among them —
    /// which is FAT's volume-label attribute, and is reserved here because exFAT gives the
    /// label an entry type of its own.
    #[error(
        "the entry at entry {index} sets attribute bits {bits:#06x}, which the format reserves"
    )]
    #[non_exhaustive]
    ReservedAttributes {
        /// The set's first entry index within its directory.
        index: u32,
        /// The reserved bits that are set.
        bits: u16,
    },
    /// A stream extension records an allocation and does not declare one possible.
    ///
    /// The format requires the flag on every stream extension, whether or not the stream
    /// currently addresses a cluster — so a clear one is a secondary entry saying it addresses
    /// nothing, beside a first cluster and a length saying it does.
    #[error("the stream at entry {index} records an allocation and does not declare one possible")]
    #[non_exhaustive]
    AllocationNotPossible {
        /// The set's first entry index within its directory.
        index: u32,
    },
    /// One of an entry's three times holds a value the encoding does not define.
    ///
    /// A month of zero, a day of 31 in February, a twenty-fifth hour, or a hundredths byte
    /// past 199. A read reports the instant the arithmetic reaches, which is what every driver
    /// does; this is the judgment that says the field was never an instant.
    #[error("the {field} at entry {index} holds a value the encoding does not define")]
    #[non_exhaustive]
    MalformedTimestamp {
        /// The set's first entry index within its directory.
        index: u32,
        /// Which of the three times, in the format's own words.
        field: &'static str,
    },
    /// A stream records more written bytes than it has bytes.
    ///
    /// The two lengths are a claim about the same allocation, and the written one being the
    /// larger is not a state any sequence of writes reaches.
    #[error("a stream records {valid} bytes written of a length of {declared}")]
    #[non_exhaustive]
    ValidLengthPastEnd {
        /// The written length the stream extension records.
        valid: u64,
        /// The length the stream extension records.
        declared: u64,
    },
    /// A stream's written length trails its length, so the bytes between them were allocated
    /// and never written.
    ///
    /// This is a state a driver leaves behind and this crate's writer never produces, since a
    /// format writes every byte it allocates. The volume is conformant and the region is
    /// defined: a read yields zeros there, as every driver does, rather than whatever the
    /// medium last held.
    #[error("a stream of {declared} bytes has {valid} of them written; the rest reads as zeros")]
    #[non_exhaustive]
    ValidLengthTrails {
        /// The written length the stream extension records.
        valid: u64,
        /// The length the stream extension records.
        declared: u64,
    },
    /// A cluster a stream occupies is one the allocation bitmap says is free.
    ///
    /// The bitmap is the volume's record of what is in use, and a stream that occupies a
    /// cluster it calls free is a volume in which the next allocation overwrites a file.
    #[error("cluster {cluster} is occupied and the allocation bitmap says it is free")]
    #[non_exhaustive]
    ClusterNotAllocated {
        /// The cluster.
        cluster: u32,
    },
    /// Clusters are marked in use in the allocation bitmap and no stream reaches them, so the
    /// space is spent and holds nothing a reader can find.
    #[error("{count} clusters are marked in use and reached by nothing, the first at {first}")]
    #[non_exhaustive]
    LostClusters {
        /// How many.
        count: u64,
        /// The lowest-numbered one.
        first: u32,
    },
    /// Two streams both occupy one cluster.
    #[error("cluster {cluster} is occupied by more than one stream")]
    #[non_exhaustive]
    CrossLinkedCluster {
        /// The cluster.
        cluster: u32,
    },
    /// `PercentInUse` holds a value the field does not define.
    ///
    /// The field is a percentage, 0 through 100, or `0xFF` for "not known". A value between
    /// the two is not a stale percentage — it is a byte that was never one.
    #[error(
        "the volume records a PercentInUse of {stated}, and the field holds 0 to 100 or 255 \
         for not known"
    )]
    #[non_exhaustive]
    PercentInUseOutOfRange {
        /// The value found on disk.
        stated: u8,
    },
    /// `PercentInUse` does not say how full the volume actually is.
    ///
    /// The field sits outside the boot region's checksum precisely so a driver can keep it
    /// current, so a stale value is a remark about a number nobody is obliged to have updated
    /// rather than a fault in the volume.
    #[error(
        "the volume records that it is {stated}% in use and {in_use} of its {clusters} \
         clusters are, which is {actual}%"
    )]
    #[non_exhaustive]
    PercentInUseStale {
        /// The value the boot sector records.
        stated: u8,
        /// Clusters the allocation bitmap marks in use.
        in_use: u64,
        /// Clusters the volume has.
        clusters: u32,
        /// The percentage those clusters are.
        actual: u8,
    },
    /// The volume was not cleanly put down by the driver that last had it open.
    ///
    /// The format records this, and it is the format working rather than failing: every field
    /// is what a driver is supposed to have written. It is the one condition under which what
    /// the metadata says and what the volume contains are allowed to differ.
    #[error("this volume was not cleanly unmounted, so its metadata may not describe its contents")]
    VolumeDirty,
    /// The driver that last had the volume open recorded a failure of the underlying medium.
    #[error("a driver recorded a failure of the medium this volume is on")]
    MediaFailure,
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
    /// Nothing in the format bounds how deep a tree nests, and a walk's entry cap counts
    /// *names* rather than the bytes their paths occupy — so a caterpillar tree of directories
    /// each holding one entry naming the next stays under every count while its paths grow by
    /// one component each and cost the walk their sum.
    ///
    /// The bound is `PATH_MAX`, which is the ceiling on what a path can be *used* for: a
    /// consumer resolving one against a host gets `ENAMETOOLONG` past it, so a longer path is
    /// not a path anything could act on.
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
    /// Every variant answers, so a scan describes a fault exactly as a strict read would have.
    /// The two that are not the image's — a source that could not be read, and a caller's own
    /// bound — classify as [`Severity::Structural`] all the same: from a scan's point of view
    /// the volume could not be followed past that point, whatever the reason.
    #[must_use]
    pub fn anomaly(&self) -> Anomaly {
        let (severity, category, location) = match self {
            ReadError::Io { .. } => (
                Severity::Structural,
                Category::BootRegion,
                Location::default(),
            ),
            ReadError::Parse(_) | ReadError::BadBootSector { .. } => (
                Severity::Structural,
                Category::BootRegion,
                Location::at_sector(MAIN_BOOT_REGION_SECTOR),
            ),
            // Not a deviation from the format at all — a volume the format defines and this
            // reader does not follow. It is structural because nothing past it can be read.
            ReadError::TexFat | ReadError::FatCount { .. } => (
                Severity::Structural,
                Category::BootRegion,
                Location::at_sector(MAIN_BOOT_REGION_SECTOR),
            ),
            // The region's own bytes disagree with the answer stored beside them, which is
            // self-inconsistency rather than a matter of form.
            ReadError::BootChecksumMismatch { sector, .. }
            | ReadError::BootChecksumSectorSplit { sector } => (
                Severity::Integrity,
                Category::BootRegion,
                Location::at_sector(*sector),
            ),
            ReadError::BackupBootRegionDiffers { sector, .. }
            | ReadError::BadExtendedBootSignature { sector, .. } => (
                Severity::Conformance,
                Category::BootRegion,
                Location::at_sector(*sector),
            ),
            // The structures are the ones this reader knows — a minor revision says so — and
            // something in the volume may mean more than it appears to.
            ReadError::UnknownMinorRevision { .. } => (
                Severity::Conformance,
                Category::BootRegion,
                Location::at_sector(MAIN_BOOT_REGION_SECTOR),
            ),
            ReadError::ClusterOutOfRange { cluster }
            | ReadError::BadChainEntry { cluster, .. }
            | ReadError::BadClusterInChain { cluster }
            | ReadError::ChainTooLong { start: cluster, .. }
            | ReadError::StreamTooShort { start: cluster, .. } => (
                Severity::Structural,
                Category::AllocationTable,
                Location::at_cluster(*cluster),
            ),
            // No cluster coordinate: the index is a slot of the table, and the heap's
            // clusters begin at two — projecting a table slot through the cluster field
            // would name heap cluster 0 or 1, which no volume has. The message names the
            // slot itself.
            ReadError::BadReservedEntry { .. } => (
                Severity::Conformance,
                Category::AllocationTable,
                Location::default(),
            ),
            // A volume with no bitmap or no up-case table is one nothing can allocate in or
            // look a name up in, whatever else reads back.
            ReadError::MissingResident { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            ReadError::UpcaseChecksumMismatch { .. } => (
                Severity::Integrity,
                Category::UpcaseTable,
                Location::default(),
            ),
            ReadError::UpcaseTooLong { .. } => (
                Severity::Structural,
                Category::UpcaseTable,
                Location::default(),
            ),
            ReadError::BitmapWrongSize { .. } => (
                Severity::Structural,
                Category::AllocationBitmap,
                Location::default(),
            ),
            ReadError::SetChecksumMismatch { index, .. }
            | ReadError::NameHashMismatch { index, .. } => (
                Severity::Integrity,
                Category::Directory,
                Location::at_entry(*index),
            ),
            // A name no directory can hold is not a matter of form: no driver creates one and
            // this crate's writer refuses one, so an entry carrying it describes a tree that
            // does not exist rather than one written to a different convention.
            ReadError::HostileName { index }
            | ReadError::IncompleteEntrySet { index, .. }
            | ReadError::StraySecondaryEntry { index }
            | ReadError::DirectoryWithoutAllocation { index }
            // A length with no allocation behind it and a length no allocation could hold are
            // the same fault at two scales: an entry describing bytes that are not there.
            | ReadError::StreamWithoutAllocation { index, .. }
            | ReadError::DirectoryTooLong { index, .. } => (
                Severity::Structural,
                Category::Directory,
                Location::at_entry(*index),
            ),
            ReadError::UnknownCriticalEntry { index, .. }
            | ReadError::IllFormedName { index }
            | ReadError::MisplacedRootEntry { index, .. }
            | ReadError::DuplicateRootEntry { index, .. }
            | ReadError::ExcessNameEntries { index, .. }
            | ReadError::EntriesAfterEnd { index }
            // Each is a recovered field outside the range the format states for it. The
            // volume reads back whole and a field in it means nothing.
            | ReadError::DirectoryLengthNotClusters { index, .. }
            | ReadError::ReservedAttributes { index, .. }
            | ReadError::AllocationNotPossible { index }
            // The clusters are there and the entry does not claim them, so the volume reads
            // back whole and the space is spent — a conformance fault rather than a structural
            // one, which is the call FAT makes for the same shape.
            | ReadError::AllocationWithoutLength { index, .. }
            | ReadError::MalformedTimestamp { index, .. } => (
                Severity::Conformance,
                Category::Directory,
                Location::at_entry(*index),
            ),
            ReadError::ValidLengthPastEnd { .. } | ReadError::StreamPastHeap { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            // Both are the root directory's label entry, which is found once at open and has
            // no index a later report could carry.
            ReadError::LabelTooLong { .. } | ReadError::LabelNulUnit => (
                Severity::Conformance,
                Category::Directory,
                Location::default(),
            ),
            // A written length behind a declared one is what every driver leaves behind and
            // this crate's writer never produces. The volume is conformant, so the remark
            // says what the region holds and stops no read.
            ReadError::ValidLengthTrails { .. } => {
                (Severity::Cosmetic, Category::Directory, Location::default())
            }
            ReadError::ClusterNotAllocated { cluster }
            | ReadError::CrossLinkedCluster { cluster } => (
                Severity::Integrity,
                Category::AllocationBitmap,
                Location::at_cluster(*cluster),
            ),
            ReadError::LostClusters { first, .. } => (
                Severity::Conformance,
                Category::AllocationBitmap,
                Location::at_cluster(*first),
            ),
            // Both are the format correctly recording a state a driver put it in, so the
            // volume is well-formed and a strict read carries on. A stale fullness is the
            // same shape: the field is outside the region's checksum so a driver may keep it
            // current, and nothing obliges one to.
            ReadError::VolumeDirty
            | ReadError::MediaFailure
            | ReadError::PercentInUseStale { .. } => (
                Severity::Cosmetic,
                Category::BootRegion,
                Location::at_sector(MAIN_BOOT_REGION_SECTOR),
            ),
            // A value the field cannot hold is a different remark from one that is merely
            // stale: no driver wrote it, whatever it had been doing.
            ReadError::PercentInUseOutOfRange { .. } => (
                Severity::Conformance,
                Category::BootRegion,
                Location::at_sector(MAIN_BOOT_REGION_SECTOR),
            ),
            ReadError::NotFound { .. }
            | ReadError::NotADirectory { .. }
            | ReadError::FileTooLarge { .. }
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

/// How a read failure classifies in the crate's family-agnostic frame.
impl From<ReadError> for TreeError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::Io { kind, message } => TreeError::Io { kind, message },
            ReadError::FileTooLarge { .. }
            | ReadError::PathTooLong { .. }
            | ReadError::WalkTooLarge { .. } => TreeError::LimitExceeded {
                family: Family::ExFat,
                detail: err.to_string(),
            },
            // A shape the format defines and this reader does not follow, which is what the
            // shared frame calls unsupported rather than malformed.
            ReadError::TexFat | ReadError::FatCount { .. } => TreeError::Unsupported {
                family: Family::ExFat,
                detail: err.to_string(),
            },
            other => TreeError::Malformed {
                family: Family::ExFat,
                detail: other.to_string(),
            },
        }
    }
}

/// What a whole-volume [`scan`](Reader::scan) found, in exFAT's own taxonomy.
///
/// This is the crate's [`ScanReport`](crate::ScanReport) over exFAT's [`Anomaly`]: an anomaly
/// names the subsystem as a [`Category`] value and its place as a [`Location`] of cluster,
/// sector, and entry. The addressing unit is the volume's sector size, so a sector-addressed
/// anomaly projects to the byte offset that sector sits at.
pub type ScanReport = crate::ScanReport<Anomaly>;

/// Where a node's bytes are, and how to follow them.
///
/// The domain is closed and the type is exhaustive: an exFAT stream is a run of consecutive
/// clusters the allocation table says nothing about, or a chain through that table, or no
/// allocation at all. There is no fourth, and a fifth arriving *should* break a caller that
/// switches on it.
///
/// Which of the first two a stream uses is declared by its own entry rather than discovered,
/// and the declaration is binding: the format defines the table entries of a consecutive run
/// as meaningless, so a reader that consulted them would follow whatever happened to be there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    /// The stream owns no cluster: an empty file, whose entry records a first cluster of zero.
    None,
    /// A run of consecutive clusters beginning here, declared by `NoFatChain`. How many is the
    /// stream's length rounded up to whole clusters.
    Contiguous(u32),
    /// A chain through the allocation table beginning at this cluster.
    Chain(u32),
}

impl Storage {
    /// The first cluster, or `None` for a stream with no allocation.
    #[must_use]
    pub const fn first_cluster(self) -> Option<u32> {
        match self {
            Storage::None => None,
            Storage::Contiguous(first) | Storage::Chain(first) => Some(first),
        }
    }
}

/// The three times a directory entry records, and the zone each was recorded in.
///
/// The instants are absolute: exFAT stores a local time beside the offset it is local to, so
/// the offset has already been applied here and two volumes written in two zones compare
/// directly. The offsets are kept beside them because "no offset was recorded" is a fact about
/// the volume — a reader has no choice but to read such a time as UTC, and a caller that cares
/// which times were qualified can ask.
///
/// The root directory has none — the format stores no entry for it — which is why
/// [`Node::times`] is an [`Option`] rather than fields that would have to hold something
/// invented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Times {
    /// When the entry was created, to ten milliseconds.
    pub create: Timestamp,
    /// When it was last accessed. The format gives this field no hundredths, so it is granular
    /// to two seconds.
    pub access: Timestamp,
    /// When it was last written, to ten milliseconds.
    pub modify: Timestamp,
    /// The offset from UTC recorded beside the creation time, in minutes, or `None` where the
    /// entry recorded none.
    pub create_offset: Option<i32>,
    /// The offset from UTC recorded beside the access time, in minutes, or `None` where the
    /// entry recorded none.
    pub access_offset: Option<i32>,
    /// The offset from UTC recorded beside the modification time, in minutes, or `None` where
    /// the entry recorded none.
    pub modify_offset: Option<i32>,
}

/// A handle to one node: where its bytes are, what it is, how long it is, and when.
///
/// This is what a walk hands back and what every by-node operation takes. There is no number
/// in it, and deliberately: exFAT has no inodes, so there is nothing that distinguishes a file
/// from a second name for it — the format has no second names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Node {
    /// Where the node's bytes are.
    pub storage: Storage,
    /// The attribute word the file entry carries.
    pub attributes: FileAttributes,
    /// How long the stream is, in bytes.
    ///
    /// For the root directory this is the length of the chain the boot sector names, since the
    /// format records no entry for it and so no length: the root is as long as its allocation.
    pub data_length: u64,
    /// How many of those bytes have been written. Equal to
    /// [`data_length`](Self::data_length) on a volume this crate wrote, since a format writes
    /// every byte it allocates.
    pub valid_data_length: u64,
    /// The times the entry records, or `None` for the root directory, which has no entry.
    ///
    /// It is also how the root is told from anything else. Every other node here was built
    /// from a directory entry and carries that entry's times, so "no entry behind it" is a
    /// property the node carries rather than one recomputed from where its bytes are — and a
    /// subdirectory whose stream extension names the root's own first cluster is still a
    /// subdirectory.
    pub times: Option<Times>,
}

impl Node {
    /// Whether the node is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.attributes.contains(FileAttributes::DIRECTORY)
    }
}

/// One resolved directory entry: the name it is found under, and a handle to what it points
/// at.
///
/// There is one name and no second: exFAT stores the name whole, in UTF-16, with no shortened
/// legacy form beside it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Entry {
    /// The name the entry is found under, as UTF-8.
    ///
    /// Always a name a directory can hold. An entry whose name is `.` or `..`, is empty, or
    /// carries a path separator or a NUL, is [`HostileName`](ReadError::HostileName) rather
    /// than an [`Entry`], so a path built by joining this onto its directory's stays inside the
    /// tree.
    pub name: Vec<u8>,
    /// A handle to what the entry points at.
    pub node: Node,
}

/// One name a [`walk`](Reader::walk) reached: its path, and a handle to what is there.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Absolute path from the volume root, `/`-joined, always beginning with `/`.
    pub path: Vec<u8>,
    /// A handle to what is at the path.
    pub node: Node,
}

/// A read-only handle over an exFAT volume on any [`Read`] + [`Seek`] source.
///
/// The volume may sit at an arbitrary byte offset within the source — a partition inside a
/// whole-disk image — fixed at open time. Reads seek relative to that offset and return owned
/// buffers, so nothing is borrowed from the source between calls.
///
/// It is opened under the crate's own [`OpenOptions`] rather than options of its own: this
/// family takes where the volume begins, how strictly it is read, and what one read may
/// allocate, and nothing else. A knob it does not have would be a knob to keep in step for
/// nothing.
pub struct Reader<R> {
    src: R,
    base: u64,
    /// The Main Boot Sector as it was parsed.
    ///
    /// Boxed because 390 of its 512 bytes are boot code a reader never looks at, and the
    /// reader itself is a variant of the enum the crate's own `open` hands back — where an
    /// outsized variant is a cost every caller of every family pays.
    boot: Box<MainBootSector>,
    layout: ExfatLayout,
    policy: ReadPolicy,
    limits: Limits,
    /// The volume's own case folding, decoded from the table its root directory names.
    ///
    /// Read at open because every name comparison goes through it, and folding through
    /// anything else would resolve names a driver does not and miss names a driver finds.
    upcase: UpcaseTable,
    /// Where the allocation bitmap is, as the root directory's describing entry gives it.
    bitmap: Resident,
    /// The name in the root directory's volume label entry, or `None` where the volume carries
    /// none — which the format records as an entry with a character count of zero.
    label: Option<Vec<u8>>,
    /// How long the root directory's chain is, in bytes. The format records no entry for the
    /// root and so no length, so it is measured once at open rather than at every walk.
    root_bytes: u64,
    /// The deviations found while opening, kept so a scan reports them without re-deriving the
    /// geometry and a lenient caller can see them without one.
    open_anomalies: Vec<Anomaly>,
    /// A one-sector window on the allocation table.
    ///
    /// Following a chain reads one entry at a time and the entries of a chain are usually near
    /// each other, so a window turns a walk of a large file from one seek per cluster into one
    /// per sector. One sector rather than FAT's two, because an entry here is four bytes at a
    /// four-byte-aligned offset and cannot straddle a boundary. The image is read-only, so a
    /// cached window can never go stale.
    fat_window: Option<(u64, Vec<u8>)>,
    /// A one-sector window on the allocation bitmap, for the same reason.
    bitmap_window: Option<(u64, Vec<u8>)>,
    /// Where the bitmap's own chain walk left off: an index into its stream, and the cluster
    /// at that index.
    bitmap_at: Option<(u64, u32)>,
    /// Where a chain walk left off: the chain's first cluster, the index within it, and the
    /// cluster at that index.
    ///
    /// A read at an offset has to skip to the cluster holding it, and skipping from the start
    /// every time makes a sequential read of one file quadratic in its length.
    chain_cursor: Option<(u32, u64, u32)>,
}

/// One of the cluster heap's format-time residents, as the root directory describes it.
///
/// Both of the two a reader must find — the allocation bitmap and the up-case table — are
/// described by a primary entry carrying a first cluster and a length, and neither has a flags
/// field to declare a consecutive run with, so both are chains through the allocation table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Resident {
    first_cluster: u32,
    bytes: u64,
}

/// What a directory parse does with a deviation it meets.
///
/// One parser serves both dispositions, which is what makes a scan describe a fault exactly as
/// the read that stops at it would have.
enum OnDeviation<'a> {
    /// An ordinary read: fatal under the policy, and otherwise passed over.
    Policy(ReadPolicy),
    /// A scan: every deviation collected, none fatal.
    Collect(&'a mut Findings<Anomaly>),
}

impl OnDeviation<'_> {
    /// Record `err`, having happened at `at`. Returns it as an error where the policy in force
    /// makes it fatal.
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

/// One 32-byte slot of a directory, as it sits on disk.
///
/// The bytes are handed over raw rather than parsed, because a set's checksum is taken over
/// exactly these and a parsed entry has already lost the reserved runs the answer covers.
struct Slot {
    bytes: [u8; DIR_ENTRY_SIZE],
    /// Which slot of the directory this is, counting from zero.
    index: u32,
    /// The cluster it sits in.
    cluster: u32,
    /// The sector it sits in, counted from the volume's start.
    sector: u64,
}

impl Slot {
    /// The entry's type byte.
    const fn entry_type(&self) -> EntryType {
        EntryType(self.bytes[0])
    }

    /// Where this slot is, in the coordinates a deviation carries.
    const fn location(&self) -> Location {
        Location {
            sector: Some(self.sector),
            cluster: Some(self.cluster),
            entry: Some(self.index),
        }
    }
}

impl<R: Read + Seek> Reader<R> {
    /// Open the exFAT volume at the start of `src` under the default options.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadBootSector`] when the boot sector does not describe an exFAT volume,
    /// [`ReadError::TexFat`] for the transaction-safe variant, [`ReadError::Io`] when the
    /// source cannot be read, and — under [`ReadPolicy::Strict`] — whichever deviation the
    /// boot regions or the root directory's residents carry.
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open the exFAT volume `src` holds, under `options`.
    ///
    /// The boot sector is validated through the same function detection classifies with, so a
    /// volume detection claims is one this opens and a volume it does not claim is one this
    /// refuses. What the reader adds is a reason.
    ///
    /// Opening reads more than the boot sector, and it has to: the allocation bitmap and the
    /// up-case table are found by reading the root directory and nowhere else, and a name
    /// cannot be compared or hashed until the table a volume folds through is in hand.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_with(mut src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let end = src.seek(SeekFrom::End(0))?;
        let available = end.saturating_sub(options.base);
        let sector = read_exact_at(&mut src, options.base, MainBootSector::SIZE)?;
        let boot = MainBootSector::read_from(&sector)?;
        let layout = layout_from_boot(&boot, available).map_err(|d| ReadError::BadBootSector {
            detail: d.to_string(),
        })?;

        // Refused before anything else is read, and below the policy threshold: which of a
        // TexFAT volume's two tables is live is a flag rather than a convention, so there is no
        // lenient reading of one — only a coin toss dressed as an answer.
        match boot.number_of_fats {
            1 => {}
            2 => return Err(ReadError::TexFat),
            count => return Err(ReadError::FatCount { count }),
        }

        let mut reader = Self {
            src,
            base: options.base,
            boot: Box::new(boot),
            layout,
            policy: options.policy,
            limits: options.limits,
            // Replaced below by the volume's own, once the root directory has been read. The
            // placeholder folds nothing, so a name resolved before it is replaced is resolved
            // case-sensitively — which nothing does, the replacement happening inside `open`.
            upcase: UpcaseTable::new(&[]),
            bitmap: Resident {
                first_cluster: FIRST_CLUSTER,
                bytes: 0,
            },
            label: None,
            root_bytes: 0,
            open_anomalies: Vec::new(),
            fat_window: None,
            bitmap_window: None,
            bitmap_at: None,
            chain_cursor: None,
        };

        let mut deviations = Vec::new();
        reader.check_boot_regions(&mut deviations)?;
        reader.check_revision(&mut deviations);
        reader.check_volume_state(&mut deviations);
        reader.root_bytes = reader.measure_root()?;
        reader.load_residents(&mut deviations)?;

        // The policy is applied once, after everything an open reads has been read, so a
        // strict open reports the first deviation in the order the volume is laid out rather
        // than in the order this happens to check.
        for err in deviations {
            let anomaly = err.anomaly();
            if options.policy.is_fatal(anomaly.severity) {
                return Err(err);
            }
            reader.open_anomalies.push(anomaly);
        }
        Ok(reader)
    }

    /// The volume's geometry, as its boot sector describes it and its root directory completes
    /// it.
    ///
    /// This is the same type the planner produces, recovered rather than computed — so a
    /// layout planned and a layout read back from the image it produced compare equal, which
    /// is what makes a format-then-read a round trip rather than two descriptions that happen
    /// to agree. The four fields no boot sector records — where the allocation bitmap and the
    /// up-case table are, and how long each is — are what the root directory said rather than
    /// what a conformant volume would have.
    #[must_use]
    pub const fn layout(&self) -> &ExfatLayout {
        &self.layout
    }

    /// The Main Boot Sector exactly as it was parsed.
    #[must_use]
    pub fn boot_sector(&self) -> &MainBootSector {
        &self.boot
    }

    /// The strictness this reader was opened under.
    #[must_use]
    pub const fn policy(&self) -> ReadPolicy {
        self.policy
    }

    /// The case folding this volume compares and hashes names through, decoded from the table
    /// its root directory names.
    #[must_use]
    pub const fn upcase(&self) -> &UpcaseTable {
        &self.upcase
    }

    /// The volume label, or `None` for a volume that carries none.
    ///
    /// The authority is the root directory's `0x83` entry, which is what a driver and
    /// `exfatlabel` both read and what a rename updates. A volume with no name carries that
    /// entry with a character count of zero rather than no entry at all, and this answers
    /// `None` for it.
    #[must_use]
    pub fn volume_label(&self) -> Option<&[u8]> {
        self.label.as_deref()
    }

    /// Whether a driver had this volume open and did not put it down.
    ///
    /// The volume is well-formed either way — the bit is the format recording a state, not a
    /// departure from it — and it is the one condition under which what the metadata says and
    /// what the volume contains are allowed to differ.
    #[must_use]
    pub const fn volume_dirty(&self) -> bool {
        self.boot.volume_flags & VOLUME_FLAG_VOLUME_DIRTY != 0
    }

    /// Whether a driver recorded a failure of the medium this volume is on.
    #[must_use]
    pub const fn media_failure(&self) -> bool {
        self.boot.volume_flags & VOLUME_FLAG_MEDIA_FAILURE != 0
    }

    /// The root directory.
    ///
    /// Its storage is the chain the boot sector names, and it carries no times, because the
    /// format records no entry for it. Its length is its chain's, measured when the volume was
    /// opened.
    #[must_use]
    pub const fn root(&self) -> Node {
        Node {
            storage: Storage::Chain(self.layout.first_cluster_of_root),
            attributes: FileAttributes::DIRECTORY,
            data_length: self.root_bytes,
            valid_data_length: self.root_bytes,
            times: None,
        }
    }

    // -- opening ------------------------------------------------------------------------

    /// Verify both boot regions: each against its own checksum, and the backup against the
    /// main one.
    ///
    /// The main region is preferred whatever the backup says. A reader that fell back to the
    /// backup would open a volume under a geometry no driver uses, and every driver reads
    /// sector 0.
    fn check_boot_regions(&mut self, out: &mut Vec<ReadError>) -> Result<(), ReadError> {
        for region in [MAIN_BOOT_REGION_SECTOR, BOOT_REGION_SECTORS] {
            // The eleven sectors the checksum covers, then the sector holding it.
            let covered = self.read_sectors(region, CHECKSUM_SECTOR)?;
            let stored_sector = self.read_sectors(region + CHECKSUM_SECTOR, 1)?;
            let Some(stored) = checksum_sector_value(&stored_sector) else {
                out.push(ReadError::BootChecksumSectorSplit { sector: region });
                continue;
            };
            let computed = boot_checksum(&covered);
            if computed != stored {
                out.push(ReadError::BootChecksumMismatch {
                    sector: region,
                    computed,
                    stored,
                });
            }
            self.check_extended_boot_sectors(region, &covered, out);
        }

        let backup = self.read_sectors(BOOT_REGION_SECTORS, 1)?;
        match MainBootSector::read_from(&backup) {
            Ok(copy) => {
                if let Some(detail) = self.backup_differs(&copy) {
                    out.push(ReadError::BackupBootRegionDiffers {
                        sector: BOOT_REGION_SECTORS,
                        detail,
                    });
                }
            }
            Err(e) => out.push(ReadError::BackupBootRegionDiffers {
                sector: BOOT_REGION_SECTORS,
                detail: e.to_string(),
            }),
        }
        Ok(())
    }

    /// Check the eight extended boot sectors of the region beginning at `region`, whose bytes
    /// are already in `covered`.
    ///
    /// Each ends with [`EXTENDED_BOOT_SIGNATURE`] in its last four bytes, at the end of the
    /// sector rather than at a fixed offset — so where to look is a function of the sector
    /// size. The region's checksum covers whatever is there and says nothing about what it
    /// should be, which is what leaves a region with all eight signatures missing
    /// self-consistent and still not the region the format defines.
    ///
    /// One report per region rather than one per sector: eight sectors that were zeroed
    /// together are one fact about the region, and a scan that spent eight findings on it
    /// would have that much less room for the rest of the volume.
    fn check_extended_boot_sectors(&self, region: u64, covered: &[u8], out: &mut Vec<ReadError>) {
        let bytes_per_sector = self.layout.bytes_per_sector as usize;
        for n in 0..EXTENDED_BOOT_SECTORS {
            let at = (EXTENDED_BOOT_FIRST_SECTOR + n) as usize * bytes_per_sector;
            // A short slice is a region the read did not cover, which is the read's to
            // report rather than this function's.
            let Some(found) = covered
                .get(at..at + bytes_per_sector)
                .and_then(extended_boot_signature)
            else {
                return;
            };
            if found != EXTENDED_BOOT_SIGNATURE {
                out.push(ReadError::BadExtendedBootSignature {
                    sector: region + EXTENDED_BOOT_FIRST_SECTOR + n,
                    found,
                    expected: EXTENDED_BOOT_SIGNATURE,
                });
                return;
            }
        }
    }

    /// Which field of the backup boot sector describes a different volume from the main one,
    /// or `None` where the two agree.
    ///
    /// The two fields outside the region's checksum are excluded, and that exclusion is the
    /// whole reason this compares fields rather than bytes: a mounted driver marks the volume
    /// dirty and updates how full it is in the main region alone, so a byte comparison would
    /// report every volume that has ever been written to.
    fn backup_differs(&self, copy: &MainBootSector) -> Option<String> {
        let main = &self.boot;
        // Compared exhaustively through a destructure, so a field added to the boot sector is
        // a compile error here rather than a field the backup is silently allowed to differ in.
        let MainBootSector {
            jump_boot,
            file_system_name,
            partition_offset,
            volume_length,
            fat_offset,
            fat_length,
            cluster_heap_offset,
            cluster_count,
            first_cluster_of_root,
            volume_serial,
            file_system_revision,
            volume_flags: _,
            bytes_per_sector_shift,
            sectors_per_cluster_shift,
            number_of_fats,
            drive_select,
            percent_in_use: _,
            boot_code,
        } = copy;
        let fields: [(&'static str, bool); 15] = [
            ("JumpBoot", *jump_boot == main.jump_boot),
            ("FileSystemName", *file_system_name == main.file_system_name),
            (
                "PartitionOffset",
                *partition_offset == main.partition_offset,
            ),
            ("VolumeLength", *volume_length == main.volume_length),
            ("FatOffset", *fat_offset == main.fat_offset),
            ("FatLength", *fat_length == main.fat_length),
            (
                "ClusterHeapOffset",
                *cluster_heap_offset == main.cluster_heap_offset,
            ),
            ("ClusterCount", *cluster_count == main.cluster_count),
            (
                "FirstClusterOfRootDirectory",
                *first_cluster_of_root == main.first_cluster_of_root,
            ),
            ("VolumeSerialNumber", *volume_serial == main.volume_serial),
            (
                "FileSystemRevision",
                *file_system_revision == main.file_system_revision,
            ),
            (
                "BytesPerSectorShift",
                *bytes_per_sector_shift == main.bytes_per_sector_shift,
            ),
            (
                "SectorsPerClusterShift",
                *sectors_per_cluster_shift == main.sectors_per_cluster_shift,
            ),
            ("NumberOfFats", *number_of_fats == main.number_of_fats),
            ("DriveSelect", *drive_select == main.drive_select),
        ];
        if let Some((field, _)) = fields.iter().find(|(_, same)| !*same) {
            return Some(format!("{field} differs from the main region's"));
        }
        (*boot_code != main.boot_code)
            .then(|| "BootCode differs from the main region's".to_string())
    }

    /// Record the two states a driver leaves in `VolumeFlags`.
    ///
    /// Both are cosmetic. The bits are the format correctly recording something that happened
    /// to the volume, so the message says what each means rather than which field held it: a
    /// caller told "the volume was not cleanly unmounted" knows what to do, and one told that
    /// a flag word is `0x0002` does not.
    fn check_volume_state(&self, out: &mut Vec<ReadError>) {
        if self.volume_dirty() {
            out.push(ReadError::VolumeDirty);
        }
        if self.media_failure() {
            out.push(ReadError::MediaFailure);
        }
    }

    /// Record a minor revision of the format this reader does not know.
    ///
    /// The major half is the refusal, and it is applied where the rest of the boot sector is
    /// judged, so the classifier and the reader answer together. The minor half is the weaker
    /// case the format asks an implementation to honour: every structure is the one this
    /// reader knows, and something in the volume may mean more than it appears to.
    fn check_revision(&self, out: &mut Vec<ReadError>) {
        let minor = self.boot.minor_revision();
        if minor != FILE_SYSTEM_MINOR_REVISION {
            out.push(ReadError::UnknownMinorRevision { minor });
        }
    }

    /// How long the root directory's chain is, in bytes.
    ///
    /// The format records no entry for the root, so there is no length field to read: the root
    /// is exactly as long as the chain the boot sector's first cluster begins. Measured at open
    /// so every later question about the root has a length to answer with.
    fn measure_root(&mut self) -> Result<u64, ReadError> {
        let start = self.layout.first_cluster_of_root;
        let mut clusters = 0u64;
        let mut current = start;
        // A step counter bounds the walk, the idiom `chain_cluster` uses: a chain of
        // distinct clusters cannot be longer than the heap, so a walk still going past
        // that count has revisited one. A set answering the same question would cost a
        // bit per heap cluster — half a gigabyte of zeros on the largest volumes — at
        // every open, to detect a cycle the count detects for free.
        loop {
            if clusters >= u64::from(self.layout.cluster_count) {
                return Err(ReadError::ChainTooLong {
                    start,
                    clusters: self.layout.cluster_count,
                });
            }
            clusters += 1;
            match self.next_cluster(current)? {
                Some(next) => current = next,
                None => break,
            }
        }
        Ok(clusters * u64::from(self.layout.bytes_per_cluster))
    }

    /// Read the root directory's describing entries and load what they name.
    ///
    /// Three entries are found here and nowhere else: the allocation bitmap's, the up-case
    /// table's, and the volume label's. The first two are what a driver must have before it can
    /// allocate anything or compare any name, which is why a volume missing either is refused
    /// rather than reported as an empty tree.
    fn load_residents(&mut self, out: &mut Vec<ReadError>) -> Result<(), ReadError> {
        let root = self.root();
        let mut bitmap: Option<AllocationBitmapEntry> = None;
        let mut upcase: Option<UpcaseTableEntry> = None;
        let mut label: Option<VolumeLabelEntry> = None;

        // Only the critical primary entries are looked at. A set's secondary entries can never
        // be one of these — the type byte's secondary bit says so — so stepping over them by
        // that bit alone finds the residents without assembling a single name.
        //
        // The first of each kind is what a driver takes, so it is what this takes; a second
        // is storage nothing reads, and is reported rather than stepped over in silence.
        let mut duplicates: Vec<ReadError> = Vec::new();
        self.for_each_slot::<ReadError>(&root, |_, slot| {
            let entry_type = slot.entry_type();
            if entry_type.is_end_of_directory() {
                return Ok(ControlFlow::Break(()));
            }
            if !entry_type.in_use() || entry_type.is_secondary() {
                return Ok(ControlFlow::Continue(()));
            }
            let mut second = |named: &'static str| {
                duplicates.push(ReadError::DuplicateRootEntry {
                    index: slot.index,
                    entry_type: named,
                });
            };
            match entry_type {
                EntryType::ALLOCATION_BITMAP => match bitmap {
                    None => bitmap = Some(AllocationBitmapEntry::read_from(&slot.bytes)?),
                    Some(_) => second("allocation bitmap"),
                },
                EntryType::UPCASE_TABLE => match upcase {
                    None => upcase = Some(UpcaseTableEntry::read_from(&slot.bytes)?),
                    Some(_) => second("up-case table"),
                },
                EntryType::VOLUME_LABEL => match label {
                    None => label = Some(VolumeLabelEntry::read_from(&slot.bytes)?),
                    Some(_) => second("volume label"),
                },
                _ => {}
            }
            Ok(ControlFlow::Continue(()))
        })?;
        out.append(&mut duplicates);

        let bitmap = bitmap.ok_or(ReadError::MissingResident {
            resident: "allocation bitmap",
        })?;
        let upcase = upcase.ok_or(ReadError::MissingResident {
            resident: "up-case table",
        })?;

        // A bitmap is one bit per cluster. A shorter one addresses fewer clusters than the
        // volume has, and a longer one is a length that is not this bitmap's.
        let want = u64::from(self.layout.cluster_count).div_ceil(8);
        if bitmap.data_length != want {
            out.push(ReadError::BitmapWrongSize {
                bytes: bitmap.data_length,
                clusters: self.layout.cluster_count,
            });
        }
        self.bitmap = Resident {
            first_cluster: bitmap.first_cluster,
            bytes: bitmap.data_length,
        };
        self.layout.bitmap_cluster = bitmap.first_cluster;
        self.layout.bitmap_bytes = bitmap.data_length;

        self.layout.upcase_cluster = upcase.first_cluster;
        self.layout.upcase_bytes = upcase.data_length;
        self.upcase = self.load_upcase(&upcase, out)?;

        self.label = label.and_then(|entry| self.label_of(&entry, out));
        Ok(())
    }

    /// The name a volume label entry carries, or `None` where it carries none.
    ///
    /// Two fields are judged rather than taken. `CharacterCount` runs 0 to 11, and a larger
    /// one names units the field does not have — so it is reported and the field is read to
    /// its end, which is the only thing there is to read. And a label carrying `U+0000` is one
    /// every implementation that reads the field as terminated rather than counted would read
    /// differently, so it is reported and answered `None`: this crate's writer refuses to
    /// produce one, and the two ends of that rule now match.
    ///
    /// An over-long count on an unnamed volume is what makes the second check earn its place.
    /// The field of an unnamed volume is eleven zero units, so clamping alone would turn "no
    /// name" into a name of eleven NULs.
    fn label_of(&self, entry: &VolumeLabelEntry, out: &mut Vec<ReadError>) -> Option<Vec<u8>> {
        let mut count = usize::from(entry.character_count);
        if count > MAX_LABEL_UNITS {
            out.push(ReadError::LabelTooLong {
                count: entry.character_count,
                limit: MAX_LABEL_UNITS,
            });
            count = MAX_LABEL_UNITS;
        }
        if count == 0 {
            return None;
        }
        let units = &entry.label[..count];
        if units.contains(&0) {
            out.push(ReadError::LabelNulUnit);
            return None;
        }
        Some(decode_utf16(units).0)
    }

    /// The folding the volume's up-case table describes.
    ///
    /// The checksum is verified and a mismatch reported, and the table is decoded either way.
    /// That is the honest answer to a table whose checksum fails under a lenient read: the
    /// bytes are still the volume's own statement about how its names compare, and folding
    /// through a table this crate happens to carry would answer a question about *this* volume
    /// with a fact about another one. A table that cannot be read at all folds nothing, which
    /// is the conformant extreme rather than an invention.
    fn load_upcase(
        &mut self,
        entry: &UpcaseTableEntry,
        out: &mut Vec<ReadError>,
    ) -> Result<UpcaseTable, ReadError> {
        if entry.data_length > MAX_UPCASE_BYTES {
            out.push(ReadError::UpcaseTooLong {
                bytes: entry.data_length,
                limit: MAX_UPCASE_BYTES,
            });
            return Ok(UpcaseTable::new(&[]));
        }
        let bytes = self.read_chain(entry.first_cluster, entry.data_length)?;
        let computed = upcase_checksum(&bytes);
        if computed != entry.table_checksum {
            out.push(ReadError::UpcaseChecksumMismatch {
                computed,
                stored: entry.table_checksum,
            });
        }
        // A trailing odd byte is half a code unit and states nothing, so it is dropped rather
        // than paired with whatever follows the table.
        let units: Vec<u16> = (0..bytes.len() / 2)
            .map(|n| get_u16(&bytes, n * 2))
            .collect();
        Ok(UpcaseTable::new(&units))
    }

    // -- byte-level access --------------------------------------------------------------

    /// `count` sectors from `first`, refusing a range the volume does not describe.
    ///
    /// The bound is the volume's own length, so a structure naming a sector past the
    /// filesystem is answered rather than read out of whatever follows it in the source.
    fn read_sectors(&mut self, first: u64, count: u64) -> Result<Vec<u8>, ReadError> {
        let out_of_range = || ReadError::BadBootSector {
            detail: format!("sector {first} is past the volume's {} sectors", {
                self.layout.volume_length
            }),
        };
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.layout.volume_length)
            .ok_or_else(out_of_range)?;
        debug_assert!(end <= self.layout.volume_length);
        let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
        let offset = offset_of(self.base, first, bytes_per_sector).ok_or_else(out_of_range)?;
        let len = usize::try_from(count * bytes_per_sector).map_err(|_| out_of_range())?;
        Ok(read_exact_at(&mut self.src, offset, len)?)
    }

    /// Cluster `n`'s bytes.
    fn read_cluster(&mut self, n: u32) -> Result<Vec<u8>, ReadError> {
        let first = self
            .layout
            .cluster_start_sector(n)
            .ok_or(ReadError::ClusterOutOfRange { cluster: n })?;
        self.read_sectors(first, u64::from(self.layout.sectors_per_cluster()))
    }

    /// The allocation table's entry for `cluster`.
    ///
    /// Read through a one-sector window, so a chain walk pays one read per table sector rather
    /// than one per cluster.
    fn table_entry(&mut self, cluster: u32) -> Result<u32, ReadError> {
        // The table has an entry for every cluster and for the two reserved numbers ahead of
        // them, and `layout_from_boot` has already established it is long enough for that.
        if cluster < FIRST_CLUSTER || cluster - FIRST_CLUSTER >= self.layout.cluster_count {
            return Err(ReadError::ClusterOutOfRange { cluster });
        }
        let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
        let offset = u64::from(cluster) * 4;
        let sector = u64::from(self.layout.fat_offset) + offset / bytes_per_sector;
        // An entry is four bytes at a four-byte-aligned offset, so it lies wholly within one
        // sector however large the sector is.
        let within = (offset % bytes_per_sector) as usize;

        let stale = match &self.fat_window {
            Some((at, _)) => *at != sector,
            None => true,
        };
        if stale {
            let buf = self.read_sectors(sector, 1)?;
            self.fat_window = Some((sector, buf));
        }
        let (_, buf) = self.fat_window.as_ref().expect("just loaded");
        // Bounded before the accessor, which indexes: a sector shorter than the offset the
        // arithmetic reached is a volume whose sector size and table length disagree.
        if within + 4 > buf.len() {
            return Err(ReadError::ClusterOutOfRange { cluster });
        }
        Ok(get_u32(buf, within))
    }

    /// Whether the allocation bitmap says `cluster` is in use.
    ///
    /// A cluster the bitmap does not cover — one past its length — is answered `false`, which
    /// is the bitmap saying nothing rather than saying no. The length is checked at open, so a
    /// volume that reaches this is one already reported.
    fn is_allocated(&mut self, cluster: u32) -> Result<bool, ReadError> {
        if cluster < FIRST_CLUSTER || cluster - FIRST_CLUSTER >= self.layout.cluster_count {
            return Err(ReadError::ClusterOutOfRange { cluster });
        }
        let bit = u64::from(cluster - FIRST_CLUSTER);
        let at = bit / 8;
        if at >= self.bitmap.bytes {
            return Ok(false);
        }
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster);
        let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
        let index = at / bytes_per_cluster;
        // The bitmap's own place in its chain, remembered. The chain cursor beside it is the
        // one a *stream* walk uses, and a scan interleaves the two — claim a file's cluster,
        // ask the bitmap about it, claim the next — so sharing one cursor would restart the
        // bitmap's walk at every question and make a scan quadratic in the bitmap's length.
        // One entry is enough, because both callers ask about a run of adjacent clusters.
        let holding = match self.bitmap_at {
            Some((cached, cluster)) if cached == index => cluster,
            _ => {
                let Some(holding) = self.chain_cluster(self.bitmap.first_cluster, index)? else {
                    return Err(ReadError::StreamTooShort {
                        start: self.bitmap.first_cluster,
                        declared: self.bitmap.bytes,
                        held: index * bytes_per_cluster,
                    });
                };
                self.bitmap_at = Some((index, holding));
                holding
            }
        };
        let within_cluster = at % bytes_per_cluster;
        let Some(cluster_sector) = self.layout.cluster_start_sector(holding) else {
            return Err(ReadError::ClusterOutOfRange { cluster: holding });
        };
        let sector = cluster_sector + within_cluster / bytes_per_sector;
        let within = (within_cluster % bytes_per_sector) as usize;

        let stale = match &self.bitmap_window {
            Some((cached, _)) => *cached != sector,
            None => true,
        };
        if stale {
            let buf = self.read_sectors(sector, 1)?;
            self.bitmap_window = Some((sector, buf));
        }
        let (_, buf) = self.bitmap_window.as_ref().expect("just loaded");
        let byte = buf.get(within).copied().unwrap_or(0);
        Ok(byte & (1 << (bit % 8)) != 0)
    }

    /// The cluster that follows `cluster` in its chain, or `None` where the chain ends.
    ///
    /// The bad-cluster mark is named rather than left to the range test that would also
    /// refuse it: a chain reaching one is a chain into storage a driver was told to leave
    /// alone, and the number it holds is not a cluster that happens to be too high.
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, ReadError> {
        let entry = self.table_entry(cluster)?;
        if entry == super::ondisk::END_OF_CHAIN {
            return Ok(None);
        }
        if entry == BAD_CLUSTER {
            return Err(ReadError::BadClusterInChain { cluster: entry });
        }
        if entry < FIRST_CLUSTER || entry - FIRST_CLUSTER >= self.layout.cluster_count {
            return Err(ReadError::BadChainEntry { cluster, entry });
        }
        Ok(Some(entry))
    }

    /// The cluster at `index` in the chain beginning at `start`, or `None` where the chain is
    /// shorter than that.
    ///
    /// Resumes from [`chain_cursor`](Self::chain_cursor) where it can, so reading one file in
    /// order costs one pass over its chain rather than one per call.
    fn chain_cluster(&mut self, start: u32, index: u64) -> Result<Option<u32>, ReadError> {
        if start < FIRST_CLUSTER || start - FIRST_CLUSTER >= self.layout.cluster_count {
            return Err(ReadError::ClusterOutOfRange { cluster: start });
        }
        let (mut at, mut current) = match self.chain_cursor {
            Some((cursor_start, cursor_index, cursor_cluster))
                if cursor_start == start && cursor_index <= index =>
            {
                (cursor_index, cursor_cluster)
            }
            _ => (0, start),
        };
        while at < index {
            match self.next_cluster(current)? {
                Some(next) => {
                    current = next;
                    at += 1;
                }
                None => return Ok(None),
            }
            // A chain longer than the volume has clusters must repeat one, so the bound is the
            // geometry's rather than a limit a caller sets.
            if at > u64::from(self.layout.cluster_count) {
                return Err(ReadError::ChainTooLong {
                    start,
                    clusters: self.layout.cluster_count,
                });
            }
        }
        self.chain_cursor = Some((start, at, current));
        Ok(Some(current))
    }

    /// The cluster holding byte `index * bytes_per_cluster` of `storage`, or `None` where the
    /// stream is shorter than that.
    ///
    /// This is the one place the two run shapes become one answer: a declared consecutive run
    /// is arithmetic and a chain is a walk, and every read above here asks this rather than
    /// asking which shape it has.
    fn stream_cluster(&mut self, storage: Storage, index: u64) -> Result<Option<u32>, ReadError> {
        match storage {
            Storage::None => Ok(None),
            Storage::Contiguous(first) => {
                // A run that leaves the heap is refused rather than wrapped: the sum is
                // computed in 64 bits and the bound is the heap's own last cluster.
                let n = u64::from(first) + index;
                match u32::try_from(n) {
                    Ok(n)
                        if n >= FIRST_CLUSTER && n - FIRST_CLUSTER < self.layout.cluster_count =>
                    {
                        Ok(Some(n))
                    }
                    _ => Err(ReadError::ClusterOutOfRange {
                        cluster: u32::try_from(n).unwrap_or(u32::MAX),
                    }),
                }
            }
            Storage::Chain(start) => self.chain_cluster(start, index),
        }
    }

    /// `len` bytes from the chain beginning at `first`.
    ///
    /// For the two residents, whose lengths a caller has already bounded. Everything else
    /// streams.
    fn read_chain(&mut self, first: u32, len: u64) -> Result<Vec<u8>, ReadError> {
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster);
        let mut out = Vec::new();
        let mut index = 0u64;
        while (out.len() as u64) < len {
            let Some(cluster) = self.chain_cluster(first, index)? else {
                return Err(ReadError::StreamTooShort {
                    start: first,
                    declared: len,
                    held: index * bytes_per_cluster,
                });
            };
            let bytes = self.read_cluster(cluster)?;
            let take = bytes.len().min((len - out.len() as u64) as usize);
            out.extend_from_slice(&bytes[..take]);
            index += 1;
        }
        Ok(out)
    }

    // -- directories --------------------------------------------------------------------

    /// Hand every 32-byte slot of a directory's storage to `visit`, in order.
    ///
    /// One cluster is held at a time, so what this allocates is the volume's cluster size and
    /// not the directory's own length. That is the difference between a bound the *structure*
    /// implies and one a caller can rely on: a crafted directory whose chain spans the volume
    /// is the volume's size, and reading it whole would be an allocation the size of the image
    /// however tight a [`Limits`] the caller set.
    ///
    /// `visit` says whether to keep going, so a caller that has found what it came for stops
    /// rather than reading the rest of the chain.
    fn for_each_slot<E: From<ReadError>>(
        &mut self,
        node: &Node,
        mut visit: impl FnMut(&mut Self, Slot) -> Result<ControlFlow<()>, E>,
    ) -> Result<(), E> {
        let Some(start) = node.storage.first_cluster() else {
            return Ok(());
        };
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster);
        let slots_per_sector = u64::from(self.layout.bytes_per_sector) / DIR_ENTRY_SIZE as u64;
        // How many clusters the directory's length covers. The root's length was measured from
        // its chain at open, so every directory here has one.
        let clusters = node.data_length.div_ceil(bytes_per_cluster.max(1));

        let mut index = 0u32;
        // Clusters this walk has already read. The step count alone bounds it at the volume's
        // cluster count, which for a cycling chain means re-reading the same cluster that many
        // times before the refusal — and a scan absorbs that error and moves on, so the cost is
        // paid afresh for every directory. A repeat is a cycle whatever it costs, so it ends
        // the chain the moment it is seen.
        //
        // The set is the volume's own domain, one bit per cluster, which is the answer this
        // file gives that question everywhere it is asked.
        let mut visited = ClusterSet::new(self.layout.cluster_count);
        visited.insert(start);
        let mut current = Some(start);

        for at in 0..clusters {
            let Some(cluster) = current else {
                return Err(E::from(ReadError::StreamTooShort {
                    start,
                    declared: node.data_length,
                    held: at * bytes_per_cluster,
                }));
            };
            let first_sector = self
                .layout
                .cluster_start_sector(cluster)
                .ok_or(ReadError::ClusterOutOfRange { cluster })?;
            let bytes = self.read_cluster(cluster).map_err(E::from)?;
            for (i, chunk) in bytes.chunks_exact(DIR_ENTRY_SIZE).enumerate() {
                let mut raw = [0u8; DIR_ENTRY_SIZE];
                raw.copy_from_slice(chunk);
                let slot = Slot {
                    bytes: raw,
                    index,
                    cluster,
                    sector: first_sector + (i as u64) / slots_per_sector.max(1),
                };
                index = index.saturating_add(1);
                if visit(self, slot)?.is_break() {
                    return Ok(());
                }
            }

            // Only where there is another cluster to reach. Asking for the one past the last
            // is not free in either shape: a declared consecutive run's arithmetic refuses a
            // cluster outside the heap, so a directory ending on the heap's *last* cluster
            // would be refused for running past an end it never reached.
            if at + 1 == clusters {
                break;
            }
            current = match node.storage {
                // A declared consecutive run is arithmetic, and the next cluster is refused
                // where it would leave the heap rather than read from wherever it landed.
                Storage::Contiguous(_) | Storage::None => {
                    self.stream_cluster(node.storage, at + 1).map_err(E::from)?
                }
                Storage::Chain(_) => match self.next_cluster(cluster).map_err(E::from)? {
                    None => None,
                    Some(following) => {
                        if !visited.insert(following) {
                            return Err(E::from(ReadError::ChainTooLong {
                                start,
                                clusters: self.layout.cluster_count,
                            }));
                        }
                        Some(following)
                    }
                },
            };
        }
        Ok(())
    }

    /// The entries of a directory, with names reassembled and every set checked.
    ///
    /// The volume label and the two residents are not among them: none is a name a consumer of
    /// a tree wants handed to it, and each is answered by its own accessor.
    ///
    /// Every name that *is* handed back is one a directory can hold. A name resolving to `.` or
    /// `..`, empty, or carrying a path separator or a NUL, is
    /// [`HostileName`](ReadError::HostileName) — an error under [`ReadPolicy::Strict`] and a
    /// finding a [`scan`](Self::scan) collects, never an entry in the returned list.
    ///
    /// The directory's storage is read a cluster at a time and never held whole, so what one
    /// call allocates is the entries it produces plus a single cluster. The entries themselves
    /// are bounded by [`Limits::max_walk_entries`] and by the volume's whole directory
    /// capacity, whichever is smaller.
    ///
    /// What is *read* is bounded three times over, because a declared length is a number an
    /// image supplies: at the end-of-directory marker, which is where the directory ends and
    /// where every driver stops; at
    /// [`MAX_DIRECTORY_BYTES`], which is the cap the format
    /// puts on one; and at the cluster heap, which is what any stream's bytes could occupy.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants when the directory's storage cannot be read,
    /// [`ReadError::WalkTooLarge`] when it holds more entries than that bound, and — under
    /// [`ReadPolicy::Strict`] — whichever deviation its entries carry.
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
        // The root is the one directory the format records no entry for, which is what
        // [`Node::times`] being `None` carries — so the identity is read off the node rather
        // than recomputed from where its bytes are. A subdirectory whose stream extension
        // names the root's first cluster is `Storage::Chain(root)` and is not the root, and a
        // bitmap, up-case or label entry inside it is misplaced like any other.
        let is_root = node.times.is_none();
        // The directory's own entries are held, and its storage is not: a crafted directory is
        // bounded by what a caller allowed rather than by how many clusters it chained
        // together. The structural half of the cap is the volume's whole directory capacity,
        // which a well-formed directory can never reach.
        let cap = self.limits.max_walk_entries.min(self.max_names());
        let mut out: Vec<Entry> = Vec::new();
        let mut set: Option<PendingSet> = None;
        // The cluster the end-of-directory marker sat in, once one has been met.
        let mut ended: Option<u32> = None;
        let mut reported_after_end = false;
        let mut too_many = false;

        self.for_each_slot::<ReadError>(node, |reader, slot| {
            let at = slot.location();
            let entry_type = slot.entry_type();

            if let Some(marker) = ended {
                // The directory ends at the marker: every driver stops there, so what is
                // behind it is not the directory's content however far its declared length
                // runs. Reading on to that length is a courtesy a scan is owed and not a
                // traversal the format asks for, so it stops at the end of the cluster the
                // marker sat in — the one already in hand. That is what keeps the cost of
                // reading a directory the cost of what is in it: a length is a number an
                // image supplies, and a directory of two entries declaring the whole heap
                // would otherwise be read to the end of the heap.
                if slot.cluster != marker {
                    return Ok(ControlFlow::Break(()));
                }
                // A used slot past the marker is storage no reader reaches — including this
                // one, since yielding it would show a caller names that nothing else on the
                // volume can see. It is reported once rather than once per slot, and never
                // handed back.
                if !entry_type.is_end_of_directory() && !reported_after_end {
                    deviations.record(at, ReadError::EntriesAfterEnd { index: slot.index })?;
                    reported_after_end = true;
                }
                return Ok(ControlFlow::Continue(()));
            }

            // A set under assembly consumes the slots behind it. Anything that is not an
            // in-use secondary entry ends it short, and the slot is then read afresh below as
            // whatever it is — a set that stopped early must not swallow the entry after it.
            if let Some(pending) = set.as_mut() {
                if entry_type.in_use() && entry_type.is_secondary() {
                    pending.push(&slot.bytes);
                    if pending.is_complete() {
                        let finished = set.take().expect("just checked");
                        if let Some(entry) = reader.finish_set(finished, deviations)? {
                            out.push(entry);
                        }
                    }
                    return Ok(ControlFlow::Continue(()));
                }
                let broken = set.take().expect("just checked");
                deviations.record(
                    Location::at_entry(broken.index),
                    ReadError::IncompleteEntrySet {
                        index: broken.index,
                        detail: format!(
                            "it declares {} entries behind it and {} follow",
                            broken.want,
                            broken.have()
                        ),
                    },
                )?;
            }

            if entry_type.is_end_of_directory() {
                ended = Some(slot.cluster);
                return Ok(ControlFlow::Continue(()));
            }
            // A slot whose in-use bit is clear is skipped and enumeration continues. It is not
            // an edge case: the second slot of every formatted volume's root directory is
            // exactly that, with the bitmap and the up-case table behind it.
            if !entry_type.in_use() {
                return Ok(ControlFlow::Continue(()));
            }
            if entry_type.is_secondary() {
                deviations.record(at, ReadError::StraySecondaryEntry { index: slot.index })?;
                return Ok(ControlFlow::Continue(()));
            }

            match entry_type {
                EntryType::FILE => {
                    if out.len() >= cap {
                        too_many = true;
                        return Ok(ControlFlow::Break(()));
                    }
                    let file = FileEntry::read_from(&slot.bytes)?;
                    if file.secondary_count == 0 {
                        deviations.record(
                            at,
                            ReadError::IncompleteEntrySet {
                                index: slot.index,
                                detail: "it declares no entries behind it, and a file needs a \
                                         stream extension and a name"
                                    .to_string(),
                            },
                        )?;
                        return Ok(ControlFlow::Continue(()));
                    }
                    set = Some(PendingSet::new(
                        slot.index,
                        file.secondary_count,
                        &slot.bytes,
                    ));
                }
                // The three the root directory owns. Each is answered by its own accessor, so
                // none is a name in the tree — and one anywhere else is an entry the format
                // defines a single place for.
                EntryType::ALLOCATION_BITMAP
                | EntryType::UPCASE_TABLE
                | EntryType::VOLUME_LABEL => {
                    if !is_root {
                        let named = match entry_type {
                            EntryType::ALLOCATION_BITMAP => "allocation bitmap",
                            EntryType::UPCASE_TABLE => "up-case table",
                            _ => "volume label",
                        };
                        deviations.record(
                            at,
                            ReadError::MisplacedRootEntry {
                                index: slot.index,
                                entry_type: named,
                            },
                        )?;
                    }
                }
                other if other.is_benign() => {
                    // The format says an implementation that does not recognize a benign entry
                    // may carry on. Carrying on is exactly what this does.
                }
                other => {
                    deviations.record(
                        at,
                        ReadError::UnknownCriticalEntry {
                            index: slot.index,
                            entry_type: other.0,
                        },
                    )?;
                }
            }
            Ok(ControlFlow::Continue(()))
        })?;

        if too_many {
            return Err(ReadError::WalkTooLarge { limit: cap });
        }
        // A directory whose last set runs past its end is a set that was never completed.
        if let Some(unfinished) = set {
            deviations.record(
                Location::at_entry(unfinished.index),
                ReadError::IncompleteEntrySet {
                    index: unfinished.index,
                    detail: format!(
                        "it declares {} entries behind it and the directory ends after {}",
                        unfinished.want,
                        unfinished.have()
                    ),
                },
            )?;
        }
        Ok(out)
    }

    /// Turn a complete entry set into the one name it describes, or nothing where a deviation
    /// the policy tolerates leaves no name to hand back.
    fn finish_set(
        &mut self,
        set: PendingSet,
        deviations: &mut OnDeviation<'_>,
    ) -> Result<Option<Entry>, ReadError> {
        let at = Location::at_entry(set.index);
        let index = set.index;

        let computed = entry_set_checksum(&set.bytes);
        let file = FileEntry::read_from(&set.bytes)?;
        if computed != file.set_checksum {
            deviations.record(
                at,
                ReadError::SetChecksumMismatch {
                    index,
                    computed,
                    stored: file.set_checksum,
                },
            )?;
        }

        // The stream extension is the set's first secondary entry, and the format puts it
        // nowhere else: a set without one describes a file with no length and no allocation.
        let Some(stream_bytes) = set.bytes.get(DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE) else {
            deviations.record(
                at,
                ReadError::IncompleteEntrySet {
                    index,
                    detail: "it holds no stream extension".to_string(),
                },
            )?;
            return Ok(None);
        };
        let Ok(stream) = StreamExtensionEntry::read_from(stream_bytes) else {
            deviations.record(
                at,
                ReadError::IncompleteEntrySet {
                    index,
                    detail: "its first secondary entry is not a stream extension".to_string(),
                },
            )?;
            return Ok(None);
        };

        // Every name entry of the set, in order. A benign secondary entry a vendor placed among
        // them is stepped over rather than read as name units.
        let mut units: Vec<u16> = Vec::new();
        for slot in set.bytes[2 * DIR_ENTRY_SIZE..].chunks_exact(DIR_ENTRY_SIZE) {
            let entry_type = EntryType(slot[0]);
            if entry_type == EntryType::FILE_NAME {
                let name = FileNameEntry::read_from(slot)?;
                units.extend_from_slice(&name.units);
            } else if !entry_type.is_benign() {
                deviations.record(
                    at,
                    ReadError::UnknownCriticalEntry {
                        index,
                        entry_type: entry_type.0,
                    },
                )?;
            }
        }
        // Both directions of one comparison. The secondary count is defined as one plus the
        // name's entries, so a set is as long as its name and no longer: short of it there is
        // no name to hand back, and past it there are bytes the set's checksum covers and no
        // implementation reads.
        let want = usize::from(stream.name_length);
        if units.len() < want {
            deviations.record(
                at,
                ReadError::IncompleteEntrySet {
                    index,
                    detail: format!(
                        "its name is {want} code units and its entries carry {}",
                        units.len()
                    ),
                },
            )?;
            return Ok(None);
        }
        //
        // Counted in *entries* rather than in units, because the last entry of a name is
        // padded: a ten-unit name occupies one entry carrying fifteen units, and comparing
        // units would report every name whose length is not a multiple of fifteen.
        let carried = units.len() / NAME_UNITS_PER_ENTRY;
        let needed = want.div_ceil(NAME_UNITS_PER_ENTRY);
        if carried > needed {
            deviations.record(
                at,
                ReadError::ExcessNameEntries {
                    index,
                    want: needed,
                    have: carried,
                },
            )?;
        }
        units.truncate(want);

        // The hash is over the folded name, which is the form a lookup compares — so a hash
        // that disagrees is a file no driver trusting the field will find.
        let computed = name_hash(&self.upcase.fold(&units));
        if computed != stream.name_hash {
            deviations.record(
                at,
                ReadError::NameHashMismatch {
                    index,
                    computed,
                    stored: stream.name_hash,
                },
            )?;
        }

        let (name, well_formed) = decode_utf16(&units);
        if !well_formed {
            deviations.record(at, ReadError::IllFormedName { index })?;
        }
        if is_hostile_component(&name) {
            deviations.record(at, ReadError::HostileName { index })?;
            // Never handed back, whatever the policy: a path built by joining this onto its
            // directory's would leave the tree.
            return Ok(None);
        }

        let node = self.node_of(&file, &stream, index, deviations)?;
        Ok(Some(Entry { name, node }))
    }

    /// The node a file entry and its stream extension describe, with every field the format
    /// bounds held to its bound and what is incoherent about the pair reported.
    ///
    /// Each length a deviation is reported for is also *clamped* to what the volume could
    /// hold. That is what makes the bounds bounds rather than remarks: a lenient read passes
    /// over every deviation here, and a length nothing narrowed would still drive the read
    /// that follows it.
    fn node_of(
        &mut self,
        file: &FileEntry,
        stream: &StreamExtensionEntry,
        index: u32,
        deviations: &mut OnDeviation<'_>,
    ) -> Result<Node, ReadError> {
        let at = Location::at_entry(index);
        let is_dir = file.attributes.contains(FileAttributes::DIRECTORY);

        // Eleven of the sixteen attribute bits are reserved, and a conformant volume has all
        // eleven clear.
        let reserved = file.attributes.bits() & !FileAttributes::DEFINED.bits();
        if reserved != 0 {
            deviations.record(
                at,
                ReadError::ReservedAttributes {
                    index,
                    bits: reserved,
                },
            )?;
        }
        self.check_times(file, index, deviations)?;

        // The format states the constraint in both directions — a first cluster of zero means
        // the stream owns nothing, and the only length a stream owning nothing has is zero —
        // so both directions are held to it. Neither is visible downstream on its own: a
        // length with no cluster reads as a file whose bytes cannot be reached, and a cluster
        // with no length reads as an ordinary empty file whose allocation a scan meets much
        // later, as clusters in use and reached by nothing.
        let storage = if stream.first_cluster == 0 || stream.data_length == 0 {
            if stream.first_cluster == 0 && stream.data_length != 0 {
                deviations.record(
                    at,
                    ReadError::StreamWithoutAllocation {
                        index,
                        declared: stream.data_length,
                    },
                )?;
            }
            if stream.first_cluster != 0 && stream.data_length == 0 {
                deviations.record(
                    at,
                    ReadError::AllocationWithoutLength {
                        index,
                        first_cluster: stream.first_cluster,
                    },
                )?;
            }
            if is_dir {
                // A directory needs a cluster to hold even the byte that ends it, so one with
                // no allocation is a directory nothing can be in — including the entries a
                // walk would otherwise report as absent.
                deviations.record(at, ReadError::DirectoryWithoutAllocation { index })?;
            }
            Storage::None
        } else {
            // The format requires the flag on every stream extension, whether or not the
            // stream currently addresses a cluster — so a clear one beside an allocation is
            // the entry contradicting itself.
            if stream.flags & SECONDARY_ALLOCATION_POSSIBLE == 0 {
                deviations.record(at, ReadError::AllocationNotPossible { index })?;
            }
            if stream.no_fat_chain() {
                Storage::Contiguous(stream.first_cluster)
            } else {
                Storage::Chain(stream.first_cluster)
            }
        };

        let declared = self.bound_length(stream.data_length, is_dir, index, deviations)?;

        // The two lengths are one number on a volume this crate wrote and routinely differ on
        // one a driver wrote. Which way they differ is what decides whether the pair is a state
        // or a contradiction.
        let mut valid = stream.valid_data_length;
        if valid > declared {
            deviations.record(at, ReadError::ValidLengthPastEnd { valid, declared })?;
            valid = declared;
        } else if valid < declared {
            deviations.record(at, ReadError::ValidLengthTrails { valid, declared })?;
        }

        Ok(Node {
            storage,
            attributes: file.attributes,
            data_length: declared,
            valid_data_length: valid,
            times: Some(times_of(file)),
        })
    }

    /// `declared` held to every bound the format puts on a stream's length, with each one it
    /// passes reported and the length narrowed to it.
    ///
    /// Two bounds, and the second applies to directories alone.
    ///
    /// The heap is the first. exFAT has no holes — a stream's bytes are its allocation — so a
    /// length past the whole cluster heap is a length no volume could hold. Without it a
    /// 64-bit field is an unbounded source of the zeros an unwritten tail reads as: set
    /// `ValidDataLength` to zero and no cluster is ever touched, so the read is answered
    /// entirely out of the number.
    ///
    /// The format's directory cap is the second, and it is the bound that keeps reading a
    /// directory a cost the format decides. Every slot the length covers is read, and neither
    /// the entry cap nor the cycle check reaches it — a directory that produces no entries
    /// never reaches the first, and a declared consecutive run has no chain to repeat.
    ///
    /// Neither refuses a volume any conformant implementation writes: the whole heap is the
    /// most anything in it could occupy, and the writer here holds every directory to the same
    /// cap.
    fn bound_length(
        &self,
        declared: u64,
        is_dir: bool,
        index: u32,
        deviations: &mut OnDeviation<'_>,
    ) -> Result<u64, ReadError> {
        let at = Location::at_entry(index);
        let mut declared = declared;
        let heap = self.layout.heap_bytes();
        if declared > heap {
            deviations.record(
                at,
                ReadError::StreamPastHeap {
                    declared,
                    limit: heap,
                },
            )?;
            declared = heap;
        }
        if is_dir {
            if declared > MAX_DIRECTORY_BYTES {
                deviations.record(
                    at,
                    ReadError::DirectoryTooLong {
                        index,
                        declared,
                        limit: MAX_DIRECTORY_BYTES,
                    },
                )?;
                declared = MAX_DIRECTORY_BYTES;
            }
            // A directory's length is the entire size of its allocation, which makes it whole
            // clusters on every conformant volume. It is enumerated by the clusters it covers
            // either way, so a length that is not one is neither honoured nor meaningful.
            let bytes_per_cluster = self.layout.bytes_per_cluster;
            if !declared.is_multiple_of(u64::from(bytes_per_cluster)) {
                deviations.record(
                    at,
                    ReadError::DirectoryLengthNotClusters {
                        index,
                        declared,
                        bytes_per_cluster,
                    },
                )?;
            }
        }
        Ok(declared)
    }

    /// Judge the three times a file entry records, each against the range the encoding
    /// defines for its fields.
    ///
    /// A read hands back the instant the arithmetic reaches, which is what every driver does
    /// and what [`DosTimestamp::decode`](crate::DosTimestamp::decode) documents deferring.
    /// This is the site it defers to: month zero, day 31 of February, a twenty-fifth hour and
    /// a hundredths byte past 199 are each a field no encoder produces and an image may carry.
    ///
    /// The access time has no hundredths byte, which is the whole of what "granular to two
    /// seconds" means for it, so zero is what is judged beside it.
    fn check_times(
        &self,
        file: &FileEntry,
        index: u32,
        deviations: &mut OnDeviation<'_>,
    ) -> Result<(), ReadError> {
        let at = Location::at_entry(index);
        for (field, packed, tenth) in [
            ("creation time", file.create, file.create_tenth),
            ("modification time", file.modify, file.modify_tenth),
            ("access time", file.access, 0),
        ] {
            if !unpack_timestamp(packed, tenth).is_well_formed() {
                deviations.record(at, ReadError::MalformedTimestamp { index, field })?;
            }
        }
        Ok(())
    }

    /// The node at `path`, resolved from the root.
    ///
    /// Names are compared the way every driver reading this volume compares them: through the
    /// volume's own up-case table. So a lookup for `readme.txt` finds a `README.TXT` the volume
    /// holds, and finds it by the same rule that made the pair unwritable in one directory.
    ///
    /// A `..` component ascends to the directory the resolution descended from, staying at the
    /// root where there is nothing to ascend to — so nothing outside the volume can be named.
    /// It is an ascent and not a lookup, this format storing no entry of that name in any
    /// directory.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotFound`] where no such path exists, [`ReadError::NotADirectory`] where
    /// one traverses through something that is not a directory, and the errors of
    /// [`read_dir`](Self::read_dir).
    pub fn lookup(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        crate::resolve::drive(self, path, true)
    }

    /// `name` as the volume's own table folds it, which is the form two names are one name in.
    ///
    /// A name that is not UTF-8 has no UTF-16 form, and so folds to nothing rather than to a
    /// replacement character that would collide with every other such name.
    fn fold_name(&self, name: &[u8]) -> Vec<u16> {
        match core::str::from_utf8(name) {
            Ok(text) => self.upcase.fold(&text.encode_utf16().collect::<Vec<_>>()),
            Err(_) => Vec::new(),
        }
    }

    // -- file contents ------------------------------------------------------------------

    /// Fill `buf` from `offset` in a regular file, returning how many bytes were placed.
    ///
    /// A short fill means the file ends there. A node that is not a regular file holds no bytes
    /// and yields none: a directory's storage is its entries, and handing those back as file
    /// contents would be a directory entry read as data.
    ///
    /// Bytes past the stream's written length read as zeros. That region is allocated and was
    /// never written, so what is on the medium there is whatever it last held — and handing
    /// that back would leak it. Every driver answers the same way, and the discrepancy that
    /// creates the region is reported when the entry is read.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants where the stream cannot be followed.
    pub fn read_into(
        &mut self,
        node: &Node,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        if node.is_dir() {
            return Ok(0);
        }
        let size = node.data_length;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster);
        let want = buf.len().min((size - offset) as usize);
        let mut done = 0usize;
        while done < want {
            let at = offset + done as u64;
            if at >= node.valid_data_length {
                // The tail nothing wrote. Zeroed rather than read, and in one step rather than
                // cluster by cluster: what is there is not the file's.
                buf[done..want].fill(0);
                return Ok(want);
            }
            let take = (want - done).min((node.valid_data_length - at) as usize);
            let index = at / bytes_per_cluster;
            let within = (at % bytes_per_cluster) as usize;
            let Some(cluster) = self.stream_cluster(node.storage, index)? else {
                // The allocation ran out with bytes still to come, which is the length and the
                // allocation disagreeing.
                return Err(ReadError::StreamTooShort {
                    start: node.storage.first_cluster().unwrap_or(0),
                    declared: size,
                    held: index * bytes_per_cluster,
                });
            };
            let bytes = self.read_cluster(cluster)?;
            let take = take.min(bytes.len() - within);
            buf[done..done + take].copy_from_slice(&bytes[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// A file's length as a whole-file read sees it: the length its entry records, held to
    /// [`Limits::max_file_bytes`].
    ///
    /// Every whole-file form goes through this, so the cap governs what a read hands back and
    /// what a stream into a caller's writer produces alike. Nothing accumulates in the second
    /// of those, which is exactly why it needs the cap named here: what it *writes* follows
    /// the length the image declares, and an unwritten tail reads as zeros without a cluster
    /// being touched.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] if the length exceeds the cap.
    fn whole_file_len(&self, node: &Node) -> Result<u64, ReadError> {
        if node.data_length > self.limits.max_file_bytes {
            return Err(ReadError::FileTooLarge {
                size: node.data_length,
                limit: self.limits.max_file_bytes,
            });
        }
        Ok(node.data_length)
    }

    /// Stream a file's whole contents into `out`, returning how many bytes were written.
    ///
    /// Nothing accumulates, so a file of any size costs one cluster of working memory.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the length exceeds [`Limits::max_file_bytes`],
    /// [`ReadError`] variants where the stream cannot be followed,
    /// [`ReadError::StreamTooShort`] where it ends before the length the entry records, and
    /// whatever `out` returns.
    pub fn read_data_to(&mut self, node: &Node, mut out: impl Write) -> Result<u64, ReadError> {
        if node.is_dir() {
            return Ok(0);
        }
        let size = self.whole_file_len(node)?;
        let mut buf = vec![0u8; self.layout.bytes_per_cluster as usize];
        let mut done = 0u64;
        while done < size {
            let want = buf.len().min((size - done) as usize);
            let got = self.read_into(node, done, &mut buf[..want])?;
            if got == 0 {
                return Err(ReadError::StreamTooShort {
                    start: node.storage.first_cluster().unwrap_or(0),
                    declared: size,
                    held: done,
                });
            }
            out.write_all(&buf[..got])?;
            done += got as u64;
        }
        Ok(done)
    }

    /// A file's whole contents.
    ///
    /// The buffer grows as bytes arrive rather than being sized from the length field up front,
    /// so a crafted length costs nothing beyond the bytes the volume actually holds.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the length exceeds [`Limits::max_file_bytes`], and the
    /// errors of [`read_data_to`](Self::read_data_to).
    pub fn read_data(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        let mut out = Vec::new();
        self.read_data_to(node, &mut out)?;
        Ok(out)
    }

    // -- walking ------------------------------------------------------------------------

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

    /// Walk the whole tree, handing each [`WalkEntry`] to `visit` as it is reached rather than
    /// gathering them all first.
    ///
    /// `visit` receives the reader itself, so it may read each entry's contents as it goes. The
    /// error type is the consumer's, and the walk's own [`ReadError`]s convert into it, so a
    /// consumer's failure and the volume's each reach the caller as themselves.
    ///
    /// What the walk holds is the frontier — the names reached and not yet visited — rather
    /// than the tree, so a tree far larger than memory is walked without accumulating it.
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

    /// The most names the volume's own storage could hold, which bounds a walk regardless of
    /// what a caller asked for.
    ///
    /// Every name spends at least three 32-byte slots — a file entry, a stream extension, and a
    /// name entry — and every slot is in a cluster, so the heap's slot count over three is a
    /// hard ceiling that a well-formed tree can never reach.
    fn max_names(&self) -> usize {
        let slots = u64::from(self.layout.cluster_count) * u64::from(self.layout.bytes_per_cluster)
            / DIR_ENTRY_SIZE as u64;
        usize::try_from(slots / 3).unwrap_or(usize::MAX)
    }

    // -- scanning -----------------------------------------------------------------------

    /// Check the whole volume, collecting every deviation rather than stopping at the first.
    ///
    /// This is the lenient reading made explicit: both boot regions, the allocation table's
    /// reserved entries, every directory entry set, every name's hash, and every cluster the
    /// tree occupies held against the allocation bitmap in both directions — a cluster in use
    /// and reached by nothing, and a cluster reached and marked free.
    ///
    /// The report is capped by [`Limits::max_findings`], and reaching the cap is itself
    /// recorded: an absence of findings from a scan that stopped looking is not a verdict.
    #[must_use]
    pub fn scan(&mut self) -> ScanReport {
        let mut findings = Findings::new(self.limits.max_findings);
        for anomaly in self.open_anomalies.clone() {
            findings.push(anomaly);
        }
        self.scan_table_head(&mut findings);
        let reached = self.scan_tree(&mut findings);
        if let Some(reached) = reached {
            self.scan_allocation(&mut findings, &reached);
        }
        findings.into_report(self.layout.bytes_per_sector)
    }

    /// The allocation table's two reserved entries, which the format fixes.
    fn scan_table_head(&mut self, findings: &mut Findings<Anomaly>) {
        for (index, expected) in [(0u32, FAT_ENTRY_MEDIA), (1, FAT_ENTRY_RESERVED)] {
            let bytes_per_sector = u64::from(self.layout.bytes_per_sector);
            let offset = u64::from(index) * 4;
            let sector = u64::from(self.layout.fat_offset) + offset / bytes_per_sector;
            let within = (offset % bytes_per_sector) as usize;
            let found = match self.read_sectors(sector, 1) {
                Ok(buf) if within + 4 <= buf.len() => get_u32(&buf, within),
                Ok(_) => continue,
                Err(e) => {
                    findings.push(e.anomaly());
                    return;
                }
            };
            if found != expected {
                findings.push(
                    ReadError::BadReservedEntry {
                        index,
                        found,
                        expected,
                    }
                    .anomaly(),
                );
            }
        }
    }

    /// Walk the tree, collecting every deviation and the clusters it occupies.
    ///
    /// `None` where the walk did not finish. What it did not reach is not evidence of anything,
    /// and an allocation comparison over a partial traversal reads as a fact and is not one.
    fn scan_tree(&mut self, findings: &mut Findings<Anomaly>) -> Option<ClusterSet> {
        let mut reached = ClusterSet::new(self.layout.cluster_count);
        // The three the format itself allocates. They are not in the tree and they are in the
        // bitmap, so a comparison that did not claim them would call every one of their
        // clusters lost.
        let residents = [
            (self.bitmap.first_cluster, self.bitmap.bytes),
            (self.layout.upcase_cluster, self.layout.upcase_bytes),
            (self.layout.first_cluster_of_root, self.root_bytes),
        ];
        for (first, bytes) in residents {
            self.claim_stream(Storage::Chain(first), bytes, &[], &mut reached, findings);
        }

        let mut visited = ClusterSet::new(self.layout.cluster_count);
        visited.insert(self.layout.first_cluster_of_root);
        let mut queue = vec![(Vec::new(), self.root())];
        let mut names = 0usize;
        let cap = self.limits.max_walk_entries.min(self.max_names());

        while let Some((path, node)) = queue.pop() {
            if findings.is_full() {
                return None;
            }
            if node.is_dir() {
                // The root's clusters were claimed above with the other residents; every other
                // directory's are its own.
                if !path.is_empty() {
                    self.claim_stream(
                        node.storage,
                        node.data_length,
                        &path,
                        &mut reached,
                        findings,
                    );
                }
                let mut deviations = OnDeviation::Collect(findings);
                let entries = match self.parse_dir(&node, &mut deviations) {
                    Ok(entries) => entries,
                    Err(e @ ReadError::WalkTooLarge { .. }) => {
                        findings.push(e.anomaly());
                        return None;
                    }
                    Err(e) => {
                        findings.push(e.anomaly());
                        continue;
                    }
                };
                for entry in entries {
                    names += 1;
                    if names > cap {
                        findings.push(ReadError::WalkTooLarge { limit: cap }.anomaly());
                        return None;
                    }
                    let mut child = path.clone();
                    child.push(b'/');
                    child.extend_from_slice(&entry.name);
                    let descend = match entry.node.storage {
                        Storage::None => false,
                        Storage::Contiguous(first) | Storage::Chain(first) => {
                            !entry.node.is_dir() || visited.insert(first)
                        }
                    };
                    if descend {
                        queue.push((child, entry.node));
                    }
                }
            } else {
                self.claim_stream(
                    node.storage,
                    node.data_length,
                    &path,
                    &mut reached,
                    findings,
                );
            }
        }
        Some(reached)
    }

    /// Claim every cluster one stream occupies, reporting a cluster two streams both claim and
    /// one the bitmap says is free.
    fn claim_stream(
        &mut self,
        storage: Storage,
        bytes: u64,
        path: &[u8],
        reached: &mut ClusterSet,
        findings: &mut Findings<Anomaly>,
    ) {
        let Some(start) = storage.first_cluster() else {
            return;
        };
        let bytes_per_cluster = u64::from(self.layout.bytes_per_cluster);
        let clusters = bytes.div_ceil(bytes_per_cluster.max(1));
        let mut own = std::collections::HashSet::new();
        for index in 0..clusters {
            let cluster = match self.stream_cluster(storage, index) {
                Ok(Some(cluster)) => cluster,
                Ok(None) => {
                    findings.push(
                        ReadError::StreamTooShort {
                            start,
                            declared: bytes,
                            held: index * bytes_per_cluster,
                        }
                        .anomaly(),
                    );
                    return;
                }
                Err(e) => {
                    let mut anomaly = e.anomaly();
                    if !path.is_empty() {
                        anomaly.detail =
                            format!("{}: {}", crate::escape::printable(path), anomaly.detail);
                    }
                    findings.push(anomaly);
                    return;
                }
            };
            if !reached.insert(cluster) {
                // Whose claim is repeated decides what the finding says: a cluster this
                // stream already stepped through is its own chain looping onto itself, and
                // one another stream claimed is two streams sharing storage. Blaming
                // "another stream" for a loop would send a reader hunting for a second file
                // that does not exist.
                let mut anomaly = ReadError::CrossLinkedCluster { cluster }.anomaly();
                if own.contains(&cluster) {
                    anomaly.detail = format!(
                        "the chain from cluster {start} returns to cluster {cluster}, and a \
                         chain that loops never ends"
                    );
                }
                if !path.is_empty() {
                    anomaly.detail =
                        format!("{}: {}", crate::escape::printable(path), anomaly.detail);
                }
                findings.push(anomaly);
                return;
            }
            own.insert(cluster);
            match self.is_allocated(cluster) {
                Ok(true) => {}
                Ok(false) => findings.push(ReadError::ClusterNotAllocated { cluster }.anomaly()),
                Err(e) => {
                    findings.push(e.anomaly());
                    return;
                }
            }
            if findings.is_full() {
                return;
            }
        }
    }

    /// Hold the allocation bitmap against what the walk reached, and how full the volume says
    /// it is against how full it is.
    fn scan_allocation(&mut self, findings: &mut Findings<Anomaly>, reached: &ClusterSet) {
        let mut lost = 0u64;
        let mut first_lost = None;
        let mut in_use = 0u64;
        for n in 0..self.layout.cluster_count {
            let cluster = FIRST_CLUSTER + n;
            let allocated = match self.is_allocated(cluster) {
                Ok(allocated) => allocated,
                Err(e) => {
                    findings.push(e.anomaly());
                    return;
                }
            };
            if allocated {
                in_use += 1;
                if !reached.contains(cluster) {
                    lost += 1;
                    first_lost.get_or_insert(cluster);
                }
            }
        }
        if let Some(first) = first_lost {
            findings.push(ReadError::LostClusters { count: lost, first }.anomaly());
        }

        // How full the volume says it is, against how full it is. Two remarks rather than one,
        // because a value the field cannot hold and a value that is merely out of date are
        // different things to be told: the field is a percentage or `0xFF` for "not known",
        // and it sits outside the boot region's checksum precisely so a driver can keep it
        // current — so a stale value is a number nobody was obliged to update, and a value
        // between 100 and 255 is a byte that was never a percentage.
        let stated = self.boot.percent_in_use;
        let actual = percent_in_use(
            u32::try_from(in_use).unwrap_or(u32::MAX),
            self.layout.cluster_count,
        );
        if stated > PERCENT_IN_USE_MAX && stated != PERCENT_IN_USE_UNKNOWN {
            findings.push(ReadError::PercentInUseOutOfRange { stated }.anomaly());
        } else if stated != actual && stated != PERCENT_IN_USE_UNKNOWN {
            findings.push(
                ReadError::PercentInUseStale {
                    stated,
                    in_use,
                    clusters: self.layout.cluster_count,
                    actual,
                }
                .anomaly(),
            );
        }
    }
}

/// The exFAT family's half of the shared path resolution: a directory listing to find a name
/// in, folded through the volume's own up-case table.
///
/// The link half of the trait is defaulted, because the format has none.
impl<R: Read + Seek> crate::resolve::Resolve for Reader<R> {
    /// The node itself, for the reason the walk's frontier holds one: an exFAT [`Node`] is
    /// five fixed-size fields, so a locator would cost as much as the node.
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
        // up-case-folded match is remembered in case none is exact. The needle folds
        // once; each entry folds at most once, and only until a folded candidate is in
        // hand — where two passes folded every name of the directory per lookup.
        let entries = self.read_dir(dir)?;
        let folded = self.fold_name(name);
        let mut fallback = None;
        for e in &entries {
            if e.name == name {
                return Ok(Some(e.node));
            }
            if fallback.is_none() && self.fold_name(&e.name) == folded {
                fallback = Some(e.node);
            }
        }
        Ok(fallback)
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

/// The exFAT family's half of the shared walk: a resolved entry on the frontier, a first
/// cluster as the cycle key, and a directory listing as the children.
impl<R: Read + Seek> crate::walk::Walk for Reader<R> {
    /// A whole entry. Like FAT and unlike ext, there is nothing to re-read at the pop: an
    /// exFAT [`Node`] is five fixed-size fields, so a locator would cost as much as the node.
    type Pending = WalkEntry;
    type Entry = WalkEntry;
    /// The directory's first cluster.
    type Key = u32;
    type Error = ReadError;

    fn cap(&mut self) -> usize {
        self.limits.max_walk_entries.min(self.max_names())
    }

    fn seed(&mut self) -> Result<crate::walk::Seed<Self>, ReadError> {
        let root = self.root();
        let occupied = root.storage.first_cluster().into_iter().collect();
        Ok((self.walk_children(&root, &[])?, occupied))
    }

    fn resolve(&mut self, pending: WalkEntry) -> Result<WalkEntry, ReadError> {
        Ok(pending)
    }

    fn descend_key(&self, entry: &WalkEntry) -> Option<u32> {
        entry
            .node
            .is_dir()
            .then(|| entry.node.storage.first_cluster())?
    }

    fn children(&mut self, entry: &WalkEntry) -> Result<Vec<WalkEntry>, ReadError> {
        self.walk_children(&entry.node, &entry.path)
    }

    fn too_large(limit: usize) -> ReadError {
        ReadError::WalkTooLarge { limit }
    }
}

impl<R: Read + Seek> FsTree for Reader<R> {
    type Node = Node;

    fn family(&self) -> Family {
        Family::ExFat
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
        // empty path is what lets a sink apply the root's own metadata without a second way of
        // asking for it — even though on this family there is none to apply, which the stat
        // says by naming everything it filled in.
        let root = self.root();
        visit(self, TreeEntry::new(Vec::new(), NodeKind::Directory, root))?;

        let outcome = self.walk_with::<WalkFail<E>>(|reader, entry| {
            let kind = if entry.node.is_dir() {
                NodeKind::Directory
            } else {
                NodeKind::File {
                    size: entry.node.data_length,
                }
            };
            // No `shared`: the format has no second name for a node, so two paths are always
            // two nodes.
            visit(reader, TreeEntry::new(entry.path, kind, entry.node)).map_err(WalkFail::Visitor)
        });
        match outcome {
            Ok(()) => Ok(()),
            Err(WalkFail::Read(e)) => Err(E::from(TreeError::from(e))),
            // Nothing above produces one: an exFAT node is a directory or a file, and both are
            // kinds the shared frame has. The arm is here because the failure is the shared
            // surface's rather than this family's.
            Err(WalkFail::Tree(e)) => Err(E::from(e)),
            Err(WalkFail::Visitor(e)) => Err(e),
        }
    }

    fn stat(&mut self, node: &Node, synthesis: &Synthesis) -> Result<Attributes, TreeError> {
        // An exFAT volume's whole record of a node is a read-only bit and two times, which is
        // FAT's too — so what a read of one invents has a single home, beside the one that
        // says what a write of one loses.
        Ok(Attributes::from_read_only_bit(
            synthesis,
            node.is_dir(),
            node.attributes.contains(FileAttributes::READ_ONLY),
            node.times.map(|t| (t.access, t.modify)),
        ))
    }

    fn read_bytes(&mut self, node: &Node, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError> {
        Ok(Reader::read_into(self, node, offset, buf)?)
    }

    fn link_target(&mut self, _node: &Node) -> Result<Vec<u8>, TreeError> {
        // The format has no symbolic links, so no node a walk yields is one and this is reached
        // only by a caller that did not look at the kind it was handed.
        Err(TreeError::Malformed {
            family: Family::ExFat,
            detail: "an exFAT volume holds no symbolic links".to_string(),
        })
    }
}

/// The shared walk failure over this family's read error.
type WalkFail<E> = crate::tree::WalkFail<ReadError, E>;

/// What makes `?` on a [`ReadError`] work inside a walk through the shared surface. Written per
/// family because a blanket implementation would collide with the reflexive one.
impl<E> From<ReadError> for WalkFail<E> {
    fn from(err: ReadError) -> Self {
        WalkFail::Read(err)
    }
}

/// A directory entry set being assembled, slot by slot.
///
/// The raw bytes are kept because the set's checksum is over exactly them, and because a set
/// spans as many clusters as it needs — so the assembler is what carries a set across a cluster
/// boundary rather than the reader holding two clusters at once.
struct PendingSet {
    /// The file entry's index within its directory.
    index: u32,
    /// Entries the file entry says follow it.
    want: usize,
    /// The set's bytes so far, the file entry included.
    bytes: Vec<u8>,
}

impl PendingSet {
    /// A set opened by the file entry `file`, expecting `secondary` entries behind it.
    fn new(index: u32, secondary: u8, file: &[u8; DIR_ENTRY_SIZE]) -> Self {
        let want = usize::from(secondary);
        let mut bytes = Vec::with_capacity((want + 1) * DIR_ENTRY_SIZE);
        bytes.extend_from_slice(file);
        Self { index, want, bytes }
    }

    /// Take one more entry.
    fn push(&mut self, entry: &[u8; DIR_ENTRY_SIZE]) {
        self.bytes.extend_from_slice(entry);
    }

    /// Entries taken so far, the file entry excepted.
    fn have(&self) -> usize {
        self.bytes.len() / DIR_ENTRY_SIZE - 1
    }

    /// Whether every entry the file entry declared has arrived.
    fn is_complete(&self) -> bool {
        self.have() >= self.want
    }
}

/// A dense set over the volume's clusters, one bit each.
///
/// Sized from the count the boot sector records, which the geometry has already held to the
/// heap fitting inside the source — so the widest set this reaches is one bit per cluster of a
/// volume that exists, which is exactly the size of the allocation bitmap that volume already
/// carries.
///
/// This is the one answer to "which clusters has this been to", and every question of that
/// shape asks it: the chain a directory follows, the chain the root's length is measured from,
/// the directories a scan has descended into, and the clusters a scan has claimed. The domain
/// is the same in all four — a cluster number of this volume — and a second structure over it
/// would be a second answer to keep in step.
struct ClusterSet {
    bits: Vec<u64>,
    clusters: u32,
}

impl ClusterSet {
    fn new(clusters: u32) -> Self {
        // Clusters number from two, so the set is sized for the highest number rather than for
        // the count.
        let highest = clusters as usize + FIRST_CLUSTER as usize;
        Self {
            bits: vec![0u64; highest.div_ceil(64)],
            clusters,
        }
    }

    /// Whether `cluster` is one this set covers.
    fn holds(&self, cluster: u32) -> bool {
        cluster >= FIRST_CLUSTER && cluster - FIRST_CLUSTER < self.clusters
    }

    /// Add `cluster`, answering whether it was not already there.
    fn insert(&mut self, cluster: u32) -> bool {
        if !self.holds(cluster) {
            return true;
        }
        let (word, bit) = (cluster as usize / 64, cluster as usize % 64);
        let was = self.bits[word] & (1 << bit) != 0;
        self.bits[word] |= 1 << bit;
        !was
    }

    fn contains(&self, cluster: u32) -> bool {
        self.holds(cluster)
            && self.bits[cluster as usize / 64] & (1 << (cluster as usize % 64)) != 0
    }
}

/// The three instants a file entry records, with each one's recorded zone applied.
///
/// The packed words are a *local* time and the byte beside them says which locality, so the
/// instant is the decoded time less the offset. An entry recording no offset is read as UTC,
/// which is the only thing a reader can do with a time whose zone the volume did not write
/// down, and [`Times`] says which of the three that happened to.
fn times_of(file: &FileEntry) -> Times {
    let at = |field: u32, tenth: u8, offset: u8| {
        let minutes = utc_offset_minutes(offset);
        let local = unpack_timestamp(field, tenth).decode();
        let secs = local
            .secs
            .saturating_sub(i64::from(minutes.unwrap_or(0)) * 60);
        (
            Timestamp {
                secs,
                nanos: local.nanos,
            },
            minutes,
        )
    };
    let (create, create_offset) = at(file.create, file.create_tenth, file.create_utc_offset);
    let (modify, modify_offset) = at(file.modify, file.modify_tenth, file.modify_utc_offset);
    // The access field has no hundredths byte, which is the whole of what "granular to two
    // seconds" means for it.
    let (access, access_offset) = at(file.access, 0, file.access_utc_offset);
    Times {
        create,
        access,
        modify,
        create_offset,
        access_offset,
        modify_offset,
    }
}

/// `units` as UTF-8, and whether they were well-formed UTF-16.
///
/// A unit standing for no character becomes U+FFFD rather than stopping the decode: a name that
/// cannot be spelled is still a name a lenient read must be able to enumerate, and the caller
/// reports the fact separately.
fn decode_utf16(units: &[u16]) -> (Vec<u8>, bool) {
    let mut out = String::with_capacity(units.len());
    let mut well_formed = true;
    for ch in char::decode_utf16(units.iter().copied()) {
        match ch {
            Ok(ch) => out.push(ch),
            Err(_) => {
                well_formed = false;
                out.push(char::REPLACEMENT_CHARACTER);
            }
        }
    }
    (out.into_bytes(), well_formed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exfat::ondisk::{
        BOOT_CHECKSUM_SKIPS, RECOMMENDED_UPCASE_TABLE, SECONDARY_NO_FAT_CHAIN, UTC_OFFSET,
        UTC_OFFSET_VALID, write_checksum_sector, write_upcase_table,
    };
    use crate::exfat::{FormatOptions, VolumeLabel, format};
    use crate::fidelity::Property;
    use crate::finding::Finding;
    use crate::source::{Metadata, TreeBuilder};
    use crate::time::DosTimestamp;
    use std::io::Cursor;

    /// An instant every field of an entry holds exactly, so nothing under test is also
    /// exercising a rounding.
    const TIME: Timestamp = Timestamp {
        secs: 1_426_325_212,
        nanos: 0,
    };

    /// The volume every case below is built on: 64 MiB, which convention formats at
    /// four-kilobyte clusters and whose up-case table therefore spans two of them.
    const VOLUME: u64 = 64 << 20;

    fn meta(mode: u16) -> Metadata {
        Metadata::new(mode, TIME)
    }

    /// A tree with a subdirectory, a file in it, an empty file, a file spanning more than one
    /// cluster, and a name that needs more than one name entry.
    fn tree() -> TreeBuilder {
        TreeBuilder::new()
            .directory(b"/DCIM".to_vec(), meta(0o755))
            .file(b"/DCIM/READY.TXT".to_vec(), b"hello\n", meta(0o644))
            .file(b"/DCIM/EMPTY.BIN".to_vec(), b"", meta(0o644))
            .file(
                b"/DCIM/A name long enough to need two entries.txt".to_vec(),
                b"two",
                meta(0o444),
            )
            .file(b"/BIG.BIN".to_vec(), vec![0x5a; 9_000], meta(0o644))
    }

    /// `source` formatted onto a volume of the usual size, as bytes.
    fn image_of(source: TreeBuilder) -> Vec<u8> {
        format(source, VOLUME, FormatOptions::new(0x1234_5678))
            .expect("format")
            .into_bytes()
    }

    /// The tree above, formatted.
    fn image() -> Vec<u8> {
        image_of(tree())
    }

    /// A reader over `bytes`, opened strictly.
    fn reader(bytes: &[u8]) -> Reader<Cursor<&[u8]>> {
        Reader::open(Cursor::new(bytes)).expect("open")
    }

    /// A reader over `bytes`, opened leniently, so a case can scan an image a strict read
    /// would refuse.
    fn lenient(bytes: &[u8]) -> Reader<Cursor<&[u8]>> {
        Reader::open_with(
            Cursor::new(bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open leniently")
    }

    /// The failure opening `bytes` under `policy`.
    ///
    /// A helper rather than `expect_err`, since a [`Reader`] holds a source and is not a
    /// value to render — so the `Err` side is unwrapped by matching rather than by requiring
    /// the `Ok` side to be printable.
    fn open_err(bytes: &[u8], policy: ReadPolicy) -> ReadError {
        match Reader::open_with(Cursor::new(bytes), &OpenOptions::new().policy(policy)) {
            Err(e) => e,
            Ok(_) => panic!("the image was expected to be refused and was not"),
        }
    }

    /// The root directory's entries, read strictly.
    fn root_entries(bytes: &[u8]) -> Result<Vec<Entry>, ReadError> {
        let mut r = reader(bytes);
        let root = r.root();
        r.read_dir(&root)
    }

    /// The root directory's entries, read leniently, so a deviation is collected rather than
    /// fatal.
    fn root_entries_lenient(bytes: &[u8]) -> Vec<Entry> {
        let mut r = lenient(bytes);
        let root = r.root();
        r.read_dir(&root).expect("a lenient read carries on")
    }

    /// Every path a walk reaches, in the order it yields them.
    fn paths(bytes: &[u8]) -> Vec<Vec<u8>> {
        reader(bytes)
            .walk()
            .expect("walk")
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    /// The byte offset of cluster `n`, for a case that patches an image.
    fn cluster_at(bytes: &[u8], n: u32) -> usize {
        reader(bytes)
            .layout()
            .cluster_start_byte(n)
            .expect("a cluster the volume has") as usize
    }

    /// Where the entry set naming `name` begins, as a byte offset into `bytes`.
    ///
    /// Found by walking the directory's slots rather than computed, so a case that patches a
    /// set stays correct when the order a directory is written in changes.
    fn set_at(bytes: &[u8], dir_cluster: u32, name: &str) -> usize {
        let want: Vec<u16> = name.encode_utf16().collect();
        let at = cluster_at(bytes, dir_cluster);
        let cluster = reader(bytes).layout().bytes_per_cluster as usize;
        let mut slot = 0;
        while (slot + 1) * DIR_ENTRY_SIZE <= cluster {
            let start = at + slot * DIR_ENTRY_SIZE;
            let entry = &bytes[start..start + DIR_ENTRY_SIZE];
            if EntryType(entry[0]) == EntryType::FILE {
                let secondary = usize::from(entry[1]);
                let stream = &bytes[start + DIR_ENTRY_SIZE..start + 2 * DIR_ENTRY_SIZE];
                let length = usize::from(stream[3]);
                let mut units = Vec::new();
                for n in 2..=secondary {
                    let e = &bytes[start + n * DIR_ENTRY_SIZE..start + (n + 1) * DIR_ENTRY_SIZE];
                    if EntryType(e[0]) != EntryType::FILE_NAME {
                        continue;
                    }
                    for pair in e[2..].chunks_exact(2) {
                        units.push(u16::from_le_bytes([pair[0], pair[1]]));
                    }
                }
                units.truncate(length);
                if units == want {
                    return start;
                }
                slot += secondary + 1;
                continue;
            }
            slot += 1;
        }
        panic!("no entry set names {name} in cluster {dir_cluster}");
    }

    /// Recompute and patch the set checksum of the set at `at`, so a case that changes one
    /// field of a set is testing that field rather than the checksum.
    fn refresh_set_checksum(bytes: &mut [u8], at: usize) {
        let slots = usize::from(bytes[at + 1]) + 1;
        let checksum = entry_set_checksum(&bytes[at..at + slots * DIR_ENTRY_SIZE]);
        bytes[at + 2..at + 4].copy_from_slice(&checksum.to_le_bytes());
    }

    /// Recompute and patch the checksum of the boot region beginning at `sector`, so a case
    /// that changes a boot field is testing that field rather than the checksum.
    ///
    /// The sector size comes from the main boot sector's own shift, which is where a reader
    /// gets it and the one field this cannot be told.
    fn refresh_boot_checksum(bytes: &mut [u8], sector: u64) {
        let size = 1usize << bytes[108];
        let at = sector as usize * size;
        let covered = boot_checksum(&bytes[at..at + 11 * size]);
        write_checksum_sector(&mut bytes[at + 11 * size..at + 12 * size], covered);
    }

    /// Every finding a lenient scan of `bytes` reports.
    fn scan_of(bytes: &[u8]) -> Vec<Finding> {
        lenient(bytes).scan().to_report().findings().to_vec()
    }

    // -- the round trip -----------------------------------------------------------------

    #[test]
    fn a_tree_written_by_this_crate_reads_back_whole() {
        // The claim the whole family rests on: a format followed by a strict open is a round
        // trip. Every path, in order, and every byte of every file.
        let bytes = image();
        assert_eq!(
            paths(&bytes),
            vec![
                b"/BIG.BIN".to_vec(),
                b"/DCIM".to_vec(),
                b"/DCIM/A name long enough to need two entries.txt".to_vec(),
                b"/DCIM/EMPTY.BIN".to_vec(),
                b"/DCIM/READY.TXT".to_vec(),
            ]
        );

        let mut r = reader(&bytes);
        for (path, contents) in [
            (&b"/DCIM/READY.TXT"[..], &b"hello\n"[..]),
            (b"/DCIM/EMPTY.BIN", b""),
            (b"/DCIM/A name long enough to need two entries.txt", b"two"),
        ] {
            let node = r.lookup(path).expect("look the path up");
            assert_eq!(r.read_data(&node).expect("read"), contents, "{path:?}");
        }
        let big = r.lookup(b"/BIG.BIN").expect("look /BIG.BIN up");
        assert_eq!(r.read_data(&big).expect("read"), vec![0x5a; 9_000]);
        assert!(r.scan().is_clean(), "{}", r.scan().to_report().to_table());
    }

    #[test]
    fn a_layout_read_back_is_the_layout_that_was_planned() {
        // Recovered rather than recomputed, which is what makes the two halves of the family
        // one thing: the four fields no boot sector records are what the root directory said,
        // and they agree with what the planner placed.
        let image = format(tree(), VOLUME, FormatOptions::new(0x1234_5678)).expect("format");
        let planned = *image.layout();
        let bytes = image.into_bytes();
        assert_eq!(reader(&bytes).layout(), &planned);
    }

    #[test]
    fn the_times_an_entry_records_come_back_as_the_instants_that_went_in() {
        let bytes = image();
        let mut r = reader(&bytes);
        let node = r.lookup(b"/DCIM/READY.TXT").expect("look up");
        let times = node.times.expect("a file has times");
        assert_eq!(times.modify, TIME);
        assert_eq!(times.access, TIME);
        // A volume this crate writes records that its times are UTC rather than leaving a
        // reader to guess, which is a zero offset *recorded* and not an absent one.
        assert_eq!(times.modify_offset, Some(0));
        assert_eq!(times.access_offset, Some(0));
        assert_eq!(times.create_offset, Some(0));
        // The root has no entry, so it has no times at all rather than invented ones.
        assert_eq!(r.root().times, None);
    }

    #[test]
    fn a_zone_offset_moves_the_instant_and_an_absent_one_reads_as_utc() {
        // The field FAT does not have. The packed words are a local time, so the same words
        // beside two offsets are two instants — and a reader that ignored the byte would
        // report a photograph taken in Auckland as having been taken thirteen hours earlier.
        let mut file = FileEntry::read_from(&{
            let mut buf = [0u8; DIR_ENTRY_SIZE];
            buf[0] = EntryType::FILE.0;
            buf
        })
        .expect("a file entry");
        let stamp = DosTimestamp::encode(TIME).expect("in range");
        file.create = super::super::ondisk::pack_timestamp(stamp);
        file.modify = file.create;
        file.access = file.create;
        file.create_tenth = stamp.tenth;
        file.modify_tenth = stamp.tenth;

        // UTC recorded.
        file.create_utc_offset = UTC_OFFSET;
        file.modify_utc_offset = UTC_OFFSET;
        file.access_utc_offset = UTC_OFFSET;
        assert_eq!(times_of(&file).modify, TIME);

        // One hour east: the local words say the same thing and the instant is an hour
        // earlier.
        file.modify_utc_offset = UTC_OFFSET_VALID | 0x04;
        let east = times_of(&file);
        assert_eq!(east.modify.secs, TIME.secs - 3600);
        assert_eq!(east.modify_offset, Some(60));

        // Nothing recorded: read as UTC, and said to have been unqualified.
        file.modify_utc_offset = 0;
        let bare = times_of(&file);
        assert_eq!(bare.modify, TIME);
        assert_eq!(bare.modify_offset, None);
    }

    #[test]
    fn a_volume_answers_to_the_name_its_root_directory_records() {
        let labelled = format(
            TreeBuilder::new(),
            VOLUME,
            FormatOptions::new(1).label(VolumeLabel::new("CARD").expect("a label")),
        )
        .expect("format")
        .into_bytes();
        assert_eq!(reader(&labelled).volume_label(), Some(&b"CARD"[..]));

        // A volume with no name carries the entry all the same, with a character count of
        // zero — which is the volume having no name rather than an entry to report.
        let unnamed = image_of(TreeBuilder::new());
        assert_eq!(reader(&unnamed).volume_label(), None);
    }

    #[test]
    fn a_label_field_the_reader_cannot_read_as_a_name_is_named_rather_than_invented() {
        // `CharacterCount` runs 0 to 11 and the field is eleven units wide, so a larger count
        // names units that are not there. `libexfat` writes one and `fsck.exfat` calls the
        // volume clean, so this is a volume a reader meets.
        let mut bytes = image_of(TreeBuilder::new());
        let root = cluster_at(&bytes, reader(&bytes).layout().first_cluster_of_root);
        assert_eq!(bytes[root], EntryType::VOLUME_LABEL.0, "the first slot");
        bytes[root + 1] = 200;

        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(
            matches!(
                err,
                ReadError::LabelTooLong {
                    count: 200,
                    limit: MAX_LABEL_UNITS
                }
            ),
            "{err}"
        );

        // And the half that makes the clamp worth reporting rather than merely doing. The
        // field of an unnamed volume is eleven zero units, so a reader that clamped in
        // silence would turn "no name" into a name of eleven NULs — a name this crate's
        // writer refuses to produce, because a label holding one is a label every
        // implementation that reads the field as terminated would read differently.
        let mut r = lenient(&bytes);
        assert_eq!(r.volume_label(), None);
        let details: Vec<_> = r
            .scan()
            .to_report()
            .findings()
            .iter()
            .map(|f| f.detail.clone())
            .collect();
        assert!(
            details.iter().any(|d| d.contains("carries a NUL")),
            "{details:#?}"
        );
    }

    #[test]
    fn a_second_entry_of_a_kind_the_root_owns_one_of_is_named() {
        // A reader takes the first of each and steps over the rest, so a second is storage
        // nothing reads and a second answer to a question with one. The misplaced case — one
        // of these outside the root — was reported and the duplicate inside it was not.
        let bytes = image_of(TreeBuilder::new());
        let root_cluster = reader(&bytes).layout().first_cluster_of_root;
        let root = cluster_at(&bytes, root_cluster);
        for (entry_type, named) in [
            (EntryType::VOLUME_LABEL, "volume label"),
            (EntryType::ALLOCATION_BITMAP, "allocation bitmap"),
            (EntryType::UPCASE_TABLE, "up-case table"),
        ] {
            let mut bytes = bytes.clone();
            let slots = reader(&bytes).layout().bytes_per_cluster as usize / DIR_ENTRY_SIZE;
            let source = (0..slots)
                .map(|n| root + n * DIR_ENTRY_SIZE)
                .find(|at| bytes[*at] == entry_type.0)
                .expect("the entry the format writes");
            let free = (0..slots)
                .map(|n| root + n * DIR_ENTRY_SIZE)
                .find(|at| bytes[*at] == 0)
                .expect("a slot past the end marker");
            let copy: Vec<u8> = bytes[source..source + DIR_ENTRY_SIZE].to_vec();
            bytes[free..free + DIR_ENTRY_SIZE].copy_from_slice(&copy);

            let err = open_err(&bytes, ReadPolicy::Strict);
            assert!(
                matches!(err, ReadError::DuplicateRootEntry { entry_type: e, .. } if e == named),
                "{named}: {err}"
            );
        }
    }

    #[test]
    fn a_subdirectory_naming_the_roots_first_cluster_is_not_the_root() {
        // Which directory is the root is carried on the node — it is the one the format
        // records no entry for, which is what `times: None` says — rather than recomputed
        // from where its bytes are. A subdirectory whose stream extension names the root's
        // own first cluster is `Storage::Chain(root)` and is still a subdirectory, so an
        // entry the format defines one place for is misplaced inside it like any other.
        let mut bytes = image();
        let root_cluster = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root_cluster, "DCIM");
        let stream = stream_at(set);
        bytes[stream + 1] &= !SECONDARY_NO_FAT_CHAIN;
        bytes[stream + 20..stream + 24].copy_from_slice(&root_cluster.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let mut r = lenient(&bytes);
        let node = r.lookup(b"/DCIM").expect("look up");
        assert_eq!(node.storage, Storage::Chain(root_cluster));
        let err = {
            let mut strict = reader(&bytes);
            let node = strict.lookup(b"/DCIM").expect("look up");
            strict
                .read_dir(&node)
                .expect_err("the root's own entries are misplaced in it")
        };
        assert!(matches!(err, ReadError::MisplacedRootEntry { .. }), "{err}");
    }

    #[test]
    fn a_lookup_finds_a_name_through_the_folding_the_volume_carries() {
        // exFAT lookups are case-insensitive, and what "case" means is the volume's own
        // table. So the reader finds the entry by the same rule that made `README` and
        // `readme` a pair no directory could hold.
        let bytes = image();
        let mut r = reader(&bytes);
        assert!(r.lookup(b"/dcim/ready.txt").is_ok());
        assert!(r.lookup(b"/DCIM/Ready.Txt").is_ok());
        // And a name the folding keeps apart is a name the volume does not hold.
        assert!(matches!(
            r.lookup(b"/DCIM/READY_TXT"),
            Err(ReadError::NotFound { .. })
        ));
        // A path through something that is not a directory says so rather than reporting the
        // path absent.
        assert!(matches!(
            r.lookup(b"/DCIM/READY.TXT/nothing"),
            Err(ReadError::NotADirectory { .. })
        ));
    }

    #[test]
    fn an_ascent_lands_where_the_volumes_own_folding_resolves_from() {
        // This format stores no dot entry in any directory, so an ascent never had anything
        // it could be a lookup of. What it has to get right instead is the directory it
        // hands back: every component after one is found through the up-case table the
        // *volume* carries, so an ascent that landed somewhere else would resolve names
        // against the wrong directory and still fold them correctly.
        let bytes = image();
        let mut r = reader(&bytes);
        let want = r.lookup(b"/dcim/ready.txt").expect("lookup");
        // Down under one spelling, up, and back down under another.
        assert_eq!(
            r.lookup(b"/DCIM/../dcim/Ready.TXT")
                .map(|node| node.storage),
            Ok(want.storage)
        );
        assert_eq!(
            r.lookup(b"/dcim/..").map(|n| n.storage),
            Ok(r.root().storage)
        );
        // And a name the folding keeps apart is still absent after an ascent, so what the
        // ascent produced is a directory being searched rather than a lookup being skipped.
        assert!(matches!(
            r.lookup(b"/dcim/../DCIM/READY_TXT"),
            Err(ReadError::NotFound { .. })
        ));
    }

    #[test]
    fn the_folding_is_the_volumes_own_and_not_this_crates_copy_of_one() {
        // The claim a reader can only make by reading the table: fold through a volume that
        // carries a *different* mapping and the lookup follows that mapping instead. Here the
        // volume's table folds nothing, so its lookups are case-sensitive — conformant, and
        // not what any ordinary volume does.
        let mut bytes = image_of(TreeBuilder::new().file(b"/README".to_vec(), b"x", meta(0o644)));
        // Every offset this case needs, taken before a byte of the volume is changed: past
        // this point the volume's table is not the one its entry advertises, so opening a
        // reader over it is exactly what must not be done to find one's way around it.
        let (table_at, table_bytes, entry_at) = {
            let r = reader(&bytes);
            let layout = r.layout();
            let table_at = layout
                .cluster_start_byte(layout.upcase_cluster)
                .expect("a cluster") as usize;
            let root_at = layout
                .cluster_start_byte(layout.first_cluster_of_root)
                .expect("a cluster") as usize;
            let entry_at = (0..16)
                .map(|n| root_at + n * DIR_ENTRY_SIZE)
                .find(|at| bytes[*at] == EntryType::UPCASE_TABLE.0)
                .expect("the up-case table's entry");
            (table_at, layout.upcase_bytes as usize, entry_at)
        };

        // An identity table: one run marker and a count covering the whole plane, which is
        // four bytes and folds nothing.
        let identity = [super::super::ondisk::UPCASE_IDENTITY_RUN, 0u16];
        let mut table = vec![0u8; 4];
        write_upcase_table(&identity, &mut table).expect("write the table");
        bytes[table_at..table_at + table_bytes].fill(0);
        bytes[table_at..table_at + table.len()].copy_from_slice(&table);

        // The describing entry has to say what is now there, or the checksum is what the read
        // objects to rather than the folding.
        let checksum = upcase_checksum(&bytes[table_at..table_at + table.len()]);
        bytes[entry_at + 4..entry_at + 8].copy_from_slice(&checksum.to_le_bytes());
        bytes[entry_at + 24..entry_at + 32].copy_from_slice(&(table.len() as u64).to_le_bytes());

        let mut r = reader(&bytes);
        assert_eq!(r.upcase().folded_units(), 0, "the volume folds nothing");
        assert!(r.lookup(b"/README").is_ok());
        assert!(
            matches!(r.lookup(b"/readme"), Err(ReadError::NotFound { .. })),
            "a volume folding nothing resolves names case-sensitively",
        );
        // And the same image read through the mapping every implementation writes would have
        // found it, which is what makes this a measurement rather than a tautology.
        assert_eq!(
            UpcaseTable::recommended().fold(&"readme".encode_utf16().collect::<Vec<_>>()),
            UpcaseTable::recommended().fold(&"README".encode_utf16().collect::<Vec<_>>()),
        );
    }

    // -- the two run shapes -------------------------------------------------------------

    #[test]
    fn a_stream_chained_through_the_table_reads_the_same_as_a_consecutive_one() {
        // This writer always declares `NoFatChain`, so the chained shape is one only a
        // foreign volume produces — and the reader must follow both. The volume is rewritten
        // here into the shape this crate never emits: the flag cleared, and the chain the
        // format then requires written into the allocation table.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/BIG.BIN".to_vec(), vec![0x5a; 9_000], meta(0o644)));
        let (root, bytes_per_cluster, fat_at) = {
            let r = reader(&bytes);
            (
                r.layout().first_cluster_of_root,
                r.layout().bytes_per_cluster,
                r.layout().fat_offset as usize * r.layout().bytes_per_sector as usize,
            )
        };
        let set = set_at(&bytes, root, "BIG.BIN");
        let stream = set + DIR_ENTRY_SIZE;
        let first = u32::from_le_bytes(bytes[stream + 20..stream + 24].try_into().unwrap());
        let clusters = 9_000u32.div_ceil(bytes_per_cluster);
        assert!(clusters > 1, "the file must span more than one cluster");

        // Clear the flag and write the chain the format then requires.
        bytes[stream + 1] &= !SECONDARY_NO_FAT_CHAIN;
        refresh_set_checksum(&mut bytes, set);
        for n in 0..clusters {
            let entry = fat_at + (first + n) as usize * 4;
            let next = if n + 1 == clusters {
                super::super::ondisk::END_OF_CHAIN
            } else {
                first + n + 1
            };
            bytes[entry..entry + 4].copy_from_slice(&next.to_le_bytes());
        }

        let mut r = reader(&bytes);
        let node = r.lookup(b"/BIG.BIN").expect("look up");
        assert_eq!(node.storage, Storage::Chain(first));
        assert_eq!(r.read_data(&node).expect("read"), vec![0x5a; 9_000]);
        assert!(r.scan().is_clean(), "{}", r.scan().to_report().to_table());
    }

    #[test]
    fn a_chain_looping_onto_itself_is_told_apart_from_a_cluster_two_streams_share() {
        // Whose claim is repeated decides what the scan says: a cluster this stream already
        // stepped through is its own chain cycling, and blaming "another stream" for it
        // would send a reader hunting for a second file that does not exist. The chain here
        // is two clusters pointing at each other under a three-cluster declared length, so
        // the third step returns to the first.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/BIG.BIN".to_vec(), vec![0x5a; 9_000], meta(0o644)));
        let (root, bytes_per_cluster, fat_at) = {
            let r = reader(&bytes);
            (
                r.layout().first_cluster_of_root,
                r.layout().bytes_per_cluster,
                r.layout().fat_offset as usize * r.layout().bytes_per_sector as usize,
            )
        };
        let set = set_at(&bytes, root, "BIG.BIN");
        let stream = set + DIR_ENTRY_SIZE;
        let first = u32::from_le_bytes(bytes[stream + 20..stream + 24].try_into().unwrap());
        assert_eq!(9_000u32.div_ceil(bytes_per_cluster), 3);

        bytes[stream + 1] &= !SECONDARY_NO_FAT_CHAIN;
        refresh_set_checksum(&mut bytes, set);
        for (cluster, next) in [(first, first + 1), (first + 1, first)] {
            let entry = fat_at + cluster as usize * 4;
            bytes[entry..entry + 4].copy_from_slice(&next.to_le_bytes());
        }

        let mut r = reader(&bytes);
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
                "the chain from cluster {first} returns to cluster {first}"
            )),
            "{said}"
        );
        assert!(
            said.contains("BIG.BIN"),
            "the owning path rides along: {said}"
        );
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("more than one stream")),
            "a loop is not a cross-link: {}",
            report.to_report().to_table()
        );
    }

    #[test]
    fn a_consecutive_run_is_read_without_consulting_the_table() {
        // What the flag *means*: the table's entries for the run are undefined, so a reader
        // that consulted them would follow whatever is there. This writes nonsense into them
        // and the read is unaffected.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/BIG.BIN".to_vec(), vec![0x5a; 9_000], meta(0o644)));
        let (root, fat_at, count) = {
            let r = reader(&bytes);
            (
                r.layout().first_cluster_of_root,
                r.layout().fat_offset as usize * r.layout().bytes_per_sector as usize,
                r.layout().cluster_count,
            )
        };
        let stream = set_at(&bytes, root, "BIG.BIN") + DIR_ENTRY_SIZE;
        let first = u32::from_le_bytes(bytes[stream + 20..stream + 24].try_into().unwrap());
        assert_ne!(bytes[stream + 1] & SECONDARY_NO_FAT_CHAIN, 0);

        for n in 0..4u32 {
            let entry = fat_at + (first + n) as usize * 4;
            bytes[entry..entry + 4].copy_from_slice(&(count - 1).to_le_bytes());
        }
        let mut r = reader(&bytes);
        let node = r.lookup(b"/BIG.BIN").expect("look up");
        assert_eq!(node.storage, Storage::Contiguous(first));
        assert_eq!(r.read_data(&node).expect("read"), vec![0x5a; 9_000]);
    }

    // -- the two lengths ----------------------------------------------------------------

    #[test]
    fn a_written_length_behind_a_declared_one_reads_as_zeros_and_stops_no_strict_read() {
        // The state every driver leaves behind and this writer never produces. It is the
        // format recording something true, so a strict read carries on and says so — and the
        // region past it reads as zeros rather than as whatever the medium last held.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 300], meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "F.BIN");
        let stream = set + DIR_ENTRY_SIZE;
        bytes[stream + 8..stream + 16].copy_from_slice(&100u64.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let mut r = reader(&bytes);
        let node = r.lookup(b"/F.BIN").expect("a strict read accepts it");
        assert_eq!(node.data_length, 300);
        assert_eq!(node.valid_data_length, 100);
        let read = r.read_data(&node).expect("read");
        assert_eq!(read.len(), 300);
        assert_eq!(&read[..100], &[0x5a; 100]);
        assert!(
            read[100..].iter().all(|b| *b == 0),
            "the tail reads as zeros"
        );

        // Said out loud, at the severity that lets a strict read carry on.
        let found = scan_of(&bytes)
            .into_iter()
            .find(|f| f.detail.contains("of them written"))
            .expect("the discrepancy is reported");
        assert_eq!(found.severity, Severity::Cosmetic);
    }

    #[test]
    fn a_written_length_past_a_declared_one_is_a_contradiction_and_is_refused() {
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 300], meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "F.BIN");
        let stream = set + DIR_ENTRY_SIZE;
        bytes[stream + 8..stream + 16].copy_from_slice(&4000u64.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(matches!(err, ReadError::ValidLengthPastEnd { .. }), "{err}");
        // And a lenient read bounds the read by the length rather than by the claim.
        let mut r = lenient(&bytes);
        let node = r.lookup(b"/F.BIN").expect("look up");
        assert_eq!(node.valid_data_length, 300);
        assert_eq!(r.read_data(&node).expect("read").len(), 300);
    }

    // -- the ranges the format states ---------------------------------------------------

    /// The stream extension of the set at `set`, as a byte offset.
    fn stream_at(set: usize) -> usize {
        set + DIR_ENTRY_SIZE
    }

    /// Rewrite the 64-bit field at `at` and repair the set checksum at `set`, so a case that
    /// changes one field of a set is testing that field.
    fn patch_u64(bytes: &mut [u8], set: usize, at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        refresh_set_checksum(bytes, set);
    }

    #[test]
    fn a_stream_longer_than_the_whole_heap_is_refused_and_its_length_is_held_to_it() {
        // exFAT has no holes, so a stream's bytes are its allocation and the heap is what
        // bounds it. Without the bound a 64-bit field is an unbounded source of the zeros an
        // unwritten tail reads as: nothing past `ValidDataLength` touches a cluster, so the
        // read is answered entirely out of the number.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 300], meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "F.BIN");
        let stream = stream_at(set);
        patch_u64(&mut bytes, set, stream + 8, 0);
        patch_u64(&mut bytes, set, stream + 24, 8 << 30);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(matches!(err, ReadError::StreamPastHeap { .. }), "{err}");

        // And a lenient read is *bounded*, not merely informed: the length it answers with
        // is the heap's, and a stream of it is that many bytes rather than eight gibibytes.
        let heap = reader(&bytes).layout().heap_bytes();
        assert!(heap < 8 << 30, "the fixture is not evidence otherwise");
        let mut r = lenient(&bytes);
        let node = r.lookup(b"/F.BIN").expect("look up");
        assert_eq!(node.data_length, heap);
        assert_eq!(
            r.read_data_to(&node, std::io::sink()).expect("stream"),
            heap
        );
    }

    #[test]
    fn a_streamed_read_stops_at_the_cap_a_caller_set() {
        // The cap governs what an extraction *writes*, and a stream into a caller's writer
        // is what an extraction's `--cat` is. Nothing accumulates there, so the memory a
        // stream costs says nothing about the bytes it produces.
        let bytes = image();
        let mut r = Reader::open_with(
            Cursor::new(&bytes[..]),
            &OpenOptions::new().limits(Limits::new().max_file_bytes(1024)),
        )
        .expect("open");
        let node = r.lookup(b"/BIG.BIN").expect("look up");
        assert!(matches!(
            r.read_data_to(&node, std::io::sink()),
            Err(ReadError::FileTooLarge { size: 9_000, .. })
        ));
    }

    #[test]
    fn a_directory_is_read_to_its_end_marker_and_not_to_its_declared_length() {
        // The marker is where a directory ends and where every driver stops, so what is
        // behind it is not the directory's content however far the length runs. Without that
        // bound a directory of two entries declaring the rest of the heap costs a full-heap
        // read — once per directory, and the count of them is bounded by the cluster count.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        let stream = stream_at(set);
        let heap = reader(&bytes).layout().heap_bytes();
        let dcim = reader(&bytes).lookup(b"/DCIM").expect("look up").storage;
        let first = dcim.first_cluster().expect("a directory has an allocation");
        let bytes_per_cluster = u64::from(reader(&bytes).layout().bytes_per_cluster);
        // Every cluster from the directory's first to the end of the heap, declared as a
        // consecutive run so there is no chain to repeat and no cycle to catch it.
        let rest = heap - u64::from(first - FIRST_CLUSTER) * bytes_per_cluster;
        bytes[stream + 1] |= SECONDARY_NO_FAT_CHAIN;
        patch_u64(&mut bytes, set, stream + 8, rest);
        patch_u64(&mut bytes, set, stream + 24, rest);

        // The declared length is inside every bound the format states, so nothing refuses it
        // and the traversal itself is what has to be bounded.
        assert!(rest <= heap && rest <= MAX_DIRECTORY_BYTES);
        assert!(
            rest / bytes_per_cluster > 1000,
            "the fixture declares {} clusters, which is not evidence of anything",
            rest / bytes_per_cluster
        );
        assert_eq!(
            reader(&bytes)
                .lookup(b"/DCIM")
                .expect("look up")
                .data_length,
            rest
        );

        // Which clusters were read, said by what the reader would object to. An entry of a
        // critical type nothing recognizes refuses a strict read wherever it is met, so it
        // is a probe that answers "this cluster was read" — placed in the last cluster the
        // declared length covers, and in the marker's own cluster as the control that says
        // the probe works.
        let unknown = |bytes: &mut Vec<u8>, at: usize| bytes[at] = 0x9F;
        let last = FIRST_CLUSTER + reader(&bytes).layout().cluster_count - 1;
        let dcim_at = cluster_at(&bytes, first);
        let slots = usize::try_from(bytes_per_cluster).expect("a cluster") / DIR_ENTRY_SIZE;
        let marker = dcim_at
            + (0..slots)
                .find(|n| bytes[dcim_at + n * DIR_ENTRY_SIZE] == 0)
                .expect("the end marker")
                * DIR_ENTRY_SIZE;

        let mut control = bytes.clone();
        unknown(&mut control, marker + DIR_ENTRY_SIZE);
        let err = root_entries(&control)
            .map(|_| ())
            .and_then(|()| {
                let mut r = reader(&control);
                let node = r.lookup(b"/DCIM")?;
                r.read_dir(&node).map(|_| ())
            })
            .expect_err("the probe is met in the cluster the marker sits in");
        assert!(matches!(err, ReadError::EntriesAfterEnd { .. }), "{err}");

        let last_at = cluster_at(&bytes, last);
        unknown(&mut bytes, last_at);
        let mut r = reader(&bytes);
        let node = r.lookup(b"/DCIM").expect("look up");
        let entries = r
            .read_dir(&node)
            .expect("the read stopped at the marker, so the probe was never met");
        assert_eq!(entries.len(), 3, "and it is still the directory it was");
    }

    #[test]
    fn a_directory_longer_than_the_format_allows_one_is_refused() {
        // The cap is the format's own and the writer is held to it, so the two ends match.
        // It binds only above the 256 mebibytes it states, and a volume with a heap that
        // large is larger than a case here holds in memory — so the heap the bound is asked
        // about is set on the layout rather than formatted, and every other field is the
        // volume's own.
        let bytes = image();
        let mut r = reader(&bytes);
        r.layout.cluster_count = 100_000;
        assert!(r.layout.heap_bytes() > MAX_DIRECTORY_BYTES);

        let mut strict = OnDeviation::Policy(ReadPolicy::Strict);
        let err = r
            .bound_length(MAX_DIRECTORY_BYTES + 1, true, 7, &mut strict)
            .expect_err("a strict read refuses it");
        assert!(
            matches!(err, ReadError::DirectoryTooLong { index: 7, .. }),
            "{err}"
        );

        // A lenient read is bounded rather than merely informed, and a file of the same
        // length is not a directory and is not held to a directory's cap.
        let mut lenient = OnDeviation::Policy(ReadPolicy::Lenient);
        assert_eq!(
            r.bound_length(MAX_DIRECTORY_BYTES + 1, true, 7, &mut lenient)
                .expect("a lenient read carries on"),
            MAX_DIRECTORY_BYTES
        );
        assert_eq!(
            r.bound_length(MAX_DIRECTORY_BYTES + 1, false, 7, &mut lenient)
                .expect("a lenient read carries on"),
            MAX_DIRECTORY_BYTES + 1
        );
    }

    /// A volume holding one 300-byte file, with the byte offsets of that file's entry set and
    /// of the stream extension inside it.
    ///
    /// The two fields that describe where a stream's bytes are — `FirstCluster` and
    /// `DataLength` — both live in that entry, and the constraint between them runs in two
    /// directions, so the fixture is shared and the patch is what each case says.
    fn a_volume_with_one_file() -> (Vec<u8>, usize, usize) {
        let bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 300], meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "F.BIN");
        let stream = stream_at(set);
        (bytes, set, stream)
    }

    #[test]
    fn a_stream_recording_a_length_and_no_first_cluster_is_named_where_it_is_read() {
        // The format states the constraint in both directions, and the directory half was
        // the only one reported: a file claiming nine thousand bytes it has nowhere to keep
        // is inside every bound, and the incoherence surfaced halfway through an extraction
        // rather than at the entry that carries it.
        let (mut bytes, set, stream) = a_volume_with_one_file();
        bytes[stream + 20..stream + 24].copy_from_slice(&0u32.to_le_bytes());
        patch_u64(&mut bytes, set, stream + 8, 9_000);
        patch_u64(&mut bytes, set, stream + 24, 9_000);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(
                err,
                ReadError::StreamWithoutAllocation {
                    declared: 9_000,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(err.anomaly().severity, Severity::Structural);
    }

    #[test]
    fn a_stream_recording_a_first_cluster_and_no_length_is_named_where_it_is_read() {
        // The other half of the same constraint, and the half that hides better: the entry
        // reads back as an ordinary empty file, every bound it passes is one it would pass
        // anyway, and the clusters it holds surface only at the far end of a scan as space in
        // use and reached by nothing — a symptom, three structures away from its cause. The
        // volume still reads, which is what puts this one a severity below its converse.
        let (mut bytes, set, stream) = a_volume_with_one_file();
        patch_u64(&mut bytes, set, stream + 8, 0);
        patch_u64(&mut bytes, set, stream + 24, 0);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(err, ReadError::AllocationWithoutLength { .. }),
            "{err}"
        );
        assert_eq!(err.anomaly().severity, Severity::Conformance);
    }

    #[test]
    fn a_directory_whose_length_is_not_whole_clusters_is_named() {
        // The format states a directory's length as the entire size of its allocation, which
        // makes it a multiple of the cluster size on every conformant volume. It is
        // enumerated by the clusters it covers either way, so a length that is not one is
        // neither honoured nor meaningful.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        patch_u64(&mut bytes, set, stream_at(set) + 24, 1);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(
                err,
                ReadError::DirectoryLengthNotClusters { declared: 1, .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn attribute_bits_the_format_reserves_are_named() {
        // Eleven of the sixteen are reserved and zero on a conformant volume, bit 3 among
        // them — which is FAT's volume-label attribute, and is reserved here because exFAT
        // gives the label an entry type of its own.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        let attributes = u16::from_le_bytes([bytes[set + 4], bytes[set + 5]]) | 0xF008;
        bytes[set + 4..set + 6].copy_from_slice(&attributes.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(err, ReadError::ReservedAttributes { bits: 0xF008, .. }),
            "{err}"
        );
        // And the five the format defines are not swept up with them.
        assert_eq!(FileAttributes::DEFINED.bits(), 0x0037);
    }

    #[test]
    fn a_stream_with_an_allocation_and_no_allocation_declared_possible_is_named() {
        // The format requires the flag on every stream extension, whether or not the stream
        // currently addresses a cluster — so a clear one beside a first cluster and a length
        // is the entry contradicting itself.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        let stream = stream_at(set);
        assert_ne!(
            bytes[stream + 1] & SECONDARY_ALLOCATION_POSSIBLE,
            0,
            "the writer sets it, which is what makes clearing it the case under test"
        );
        bytes[stream + 1] &= !SECONDARY_ALLOCATION_POSSIBLE;
        refresh_set_checksum(&mut bytes, set);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(err, ReadError::AllocationNotPossible { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_time_the_encoding_does_not_define_is_named_where_the_entry_is_read() {
        // `DosTimestamp::decode` reports the instant the arithmetic reaches and says a scan
        // is what judges it. This is that scan: a creation time of zero spells month 0 and
        // day 0, which reads back as a date in 1979 and was never an instant.
        for (offset, field) in [(8usize, "creation time"), (16, "access time")] {
            let mut bytes = image();
            let root = reader(&bytes).layout().first_cluster_of_root;
            let set = set_at(&bytes, root, "DCIM");
            bytes[set + offset..set + offset + 4].copy_from_slice(&0u32.to_le_bytes());
            refresh_set_checksum(&mut bytes, set);
            let err = root_entries(&bytes).expect_err("a strict read refuses it");
            assert!(
                matches!(err, ReadError::MalformedTimestamp { field: f, .. } if f == field),
                "{field}: {err}"
            );
        }

        // And the hundredths byte, whose range the format states as 0 to 199 — a value of
        // 255 would move the instant 2.55 seconds by a field that cannot hold that value.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        bytes[set + 20] = 255;
        refresh_set_checksum(&mut bytes, set);
        let err = root_entries(&bytes).expect_err("a strict read refuses it");
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

    #[test]
    fn a_set_carrying_a_name_entry_its_name_does_not_reach_is_named() {
        // The secondary count is defined as one plus the entries the name occupies. The
        // mirror case — a set that ends before its name does — was reported and this one was
        // not, which is one direction of one comparison.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "DCIM");
        assert_eq!(bytes[set + 1], 2, "a file entry, a stream and one name");
        // A second name entry behind the first, with the count raised to match so the set is
        // complete and only its length is wrong.
        bytes[set + 1] = 3;
        let third = set + 3 * DIR_ENTRY_SIZE;
        let mut extra = [0u8; DIR_ENTRY_SIZE];
        FileNameEntry::new(&[0x0041])
            .write_to(&mut extra)
            .expect("write");
        bytes[third..third + DIR_ENTRY_SIZE].copy_from_slice(&extra);
        refresh_set_checksum(&mut bytes, set);

        let err = root_entries(&bytes).expect_err("a strict read refuses it");
        assert!(
            matches!(
                err,
                ReadError::ExcessNameEntries {
                    want: 1,
                    have: 2,
                    ..
                }
            ),
            "{err}"
        );
        // The name is still the one `NameLength` states, since no implementation reads past
        // it — so a lenient read enumerates the directory unchanged.
        assert!(
            root_entries_lenient(&bytes)
                .iter()
                .any(|e| e.name == b"DCIM")
        );
    }

    // -- what a volume must carry -------------------------------------------------------

    #[test]
    fn a_volume_recording_two_allocation_tables_is_refused_by_name_under_either_policy() {
        // The transaction-safe variant. Which of the two tables is live is a flag rather than
        // a convention, so there is no lenient reading of one — only a coin toss dressed as
        // an answer.
        let mut bytes = image();
        bytes[110] = 2;
        refresh_boot_checksum(&mut bytes, 0);
        for policy in [ReadPolicy::Strict, ReadPolicy::Lenient] {
            let err = open_err(&bytes, policy);
            assert!(matches!(err, ReadError::TexFat), "{policy:?}: {err}");
        }

        // A count the format does not define at all is refused as that rather than as TexFAT.
        for count in [0u8, 3, 255] {
            let mut bytes = image();
            bytes[110] = count;
            refresh_boot_checksum(&mut bytes, 0);
            let err = open_err(&bytes, ReadPolicy::Strict);
            assert!(matches!(err, ReadError::FatCount { .. }), "{count}: {err}");
        }
    }

    #[test]
    fn a_volume_whose_root_names_no_bitmap_or_no_table_is_refused_rather_than_read_empty() {
        // A reader that answered with an empty tree would report a working filesystem: both
        // are found by reading the root directory and nowhere else, and a volume without them
        // is one nothing can allocate in or look a name up in.
        for entry_type in [EntryType::ALLOCATION_BITMAP, EntryType::UPCASE_TABLE] {
            let mut bytes = image();
            let root = reader(&bytes).layout().first_cluster_of_root;
            let at = cluster_at(&bytes, root);
            let slot = (0..8)
                .map(|n| at + n * DIR_ENTRY_SIZE)
                .find(|at| bytes[*at] == entry_type.0)
                .expect("the describing entry");
            // Its in-use bit cleared, which is a slot a reader steps over.
            bytes[slot] = entry_type.cleared().0;
            for policy in [ReadPolicy::Strict, ReadPolicy::Lenient] {
                let err = open_err(&bytes, policy);
                assert!(
                    matches!(err, ReadError::MissingResident { .. }),
                    "{entry_type:?} under {policy:?}: {err}"
                );
            }
        }
    }

    #[test]
    fn a_slot_whose_in_use_bit_is_clear_is_stepped_over_rather_than_read_as_the_end() {
        // Not an edge case: the second slot of every formatted volume's root directory is a
        // volume GUID entry reserved by clearing its in-use bit, with the bitmap and the
        // up-case table behind it. A reader that stopped there would find neither, on a
        // conformant volume, silently — which is why the case above passes at all.
        let bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let at = cluster_at(&bytes, root);
        let guid = at + DIR_ENTRY_SIZE;
        assert_eq!(bytes[guid], EntryType::VOLUME_GUID.cleared().0);
        assert!(!EntryType(bytes[guid]).is_end_of_directory());
        assert!(!paths(&bytes).is_empty());
    }

    // -- negative controls, each watched failing ----------------------------------------

    #[test]
    fn a_damaged_boot_region_checksum_is_named_and_the_main_region_is_still_preferred() {
        // Every geometry field a reader depends on is inside the checksum, so a mismatch says
        // those bytes have changed since a formatter wrote them.
        let mut bytes = image();
        bytes[64] ^= 0x01; // PartitionOffset, inside the checksum and read by nothing
        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(
            matches!(err, ReadError::BootChecksumMismatch { sector: 0, .. }),
            "{err}"
        );
        let anomaly = err.anomaly();
        assert_eq!(anomaly.severity, Severity::Integrity);
        assert_eq!(anomaly.category, Category::BootRegion);

        // Leniently the volume still opens, through the main region rather than the backup —
        // which is what every driver does, so a reader that fell back would open a volume
        // under a geometry nothing else uses.
        let r = lenient(&bytes);
        assert_eq!(r.boot_sector().partition_offset, bytes_u64(&bytes, 64));
    }

    #[test]
    fn a_backup_region_describing_a_different_volume_is_named() {
        let mut bytes = image();
        let sector = reader(&bytes).layout().bytes_per_sector as usize;
        let backup = 12 * sector;
        bytes[backup + 100..backup + 104].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        refresh_boot_checksum(&mut bytes, 12);

        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(
            matches!(err, ReadError::BackupBootRegionDiffers { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("VolumeSerialNumber"), "{err}");
        assert_eq!(err.anomaly().severity, Severity::Conformance);
    }

    #[test]
    fn the_two_fields_a_driver_rewrites_are_not_held_against_the_backup() {
        // The trap a byte comparison walks into. A mounted driver marks the volume dirty and
        // updates how full it is in the *main* region alone, so comparing the regions byte for
        // byte would report every volume that has ever been written to.
        let mut bytes = image();
        bytes[106] = 0x02; // VolumeDirty, outside the checksum
        bytes[112] = 99; // PercentInUse, likewise
        let r = lenient(&bytes);
        assert!(r.volume_dirty());
        let report = r.boot_sector().volume_flags;
        assert_eq!(report & 0x0002, 0x0002);
        assert!(
            !scan_of(&bytes)
                .iter()
                .any(|a| a.detail.contains("does not describe the same volume")),
            "a driver's own two fields are not a backup that has drifted",
        );
    }

    #[test]
    fn a_volume_a_driver_left_open_is_a_remark_and_not_a_refusal() {
        // The carve-out the strict line needs. This crate's writer never produces a dirty
        // volume because it never mounts one, so the literal rule would refuse a card someone
        // pulled out of a reader — the most common image a consumer has.
        let mut bytes = image();
        bytes[106] = 0x02;
        let mut r = Reader::open(Cursor::new(&bytes)).expect("a strict read accepts it");
        assert!(r.volume_dirty());
        assert!(!r.media_failure());
        assert!(!r.scan().has_fatal(ReadPolicy::Strict));
        let found = scan_of(&bytes)
            .into_iter()
            .find(|f| f.detail.contains("not cleanly unmounted"))
            .expect("the state is reported");
        assert_eq!(found.severity, Severity::Cosmetic);
        // The message says what the bit means rather than which field held it: the two
        // readings send a caller to different places.
        assert!(!found.detail.contains("VolumeFlags"), "{}", found.detail);

        let mut bytes = image();
        bytes[106] = 0x04;
        let r = Reader::open(Cursor::new(&bytes)).expect("a strict read accepts it");
        assert!(r.media_failure());
    }

    #[test]
    fn a_major_revision_this_reader_does_not_implement_is_refused_and_a_minor_one_is_a_remark() {
        // The format states the major half as a `shall`: an implementation mounts revision 1
        // and no other, because a major revision is how it says the structures behind the
        // boot sector are not the ones a reader knows. Comparing the two boot regions against
        // each other reads as coverage and is not — both copies agreeing on a revision
        // nothing here implements is the case that matters, so both are written.
        for revision in [0x0200u16, 0xFFFF] {
            let mut bytes = image();
            for region in [0u64, BOOT_REGION_SECTORS] {
                let at = region as usize * 512;
                bytes[at + 104..at + 106].copy_from_slice(&revision.to_le_bytes());
                refresh_boot_checksum(&mut bytes, region);
            }
            for policy in [ReadPolicy::Strict, ReadPolicy::Lenient] {
                let err = open_err(&bytes, policy);
                assert!(
                    matches!(err, ReadError::BadBootSector { .. }),
                    "{revision:#06x} under {policy:?}: {err}"
                );
                assert!(err.to_string().contains("revision"), "{err}");
            }
            // The classifier answers with the reader, since both judge the boot sector
            // through one function.
            assert!(
                crate::detect(Cursor::new(&bytes)).is_err(),
                "{revision:#06x}"
            );
        }

        // A minor revision is the weaker case: the format asks an implementation to honour
        // one, so every structure is still the one this reader knows and the volume opens.
        let mut bytes = image();
        for region in [0u64, BOOT_REGION_SECTORS] {
            let at = region as usize * 512;
            bytes[at + 104..at + 106].copy_from_slice(&0x0103u16.to_le_bytes());
            refresh_boot_checksum(&mut bytes, region);
        }
        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(
            matches!(err, ReadError::UnknownMinorRevision { minor: 3 }),
            "{err}"
        );
        let found = scan_of(&bytes)
            .into_iter()
            .find(|f| f.detail.contains("minor revision"))
            .expect("the revision is reported");
        assert_eq!(found.severity, Severity::Conformance);
    }

    #[test]
    fn an_extended_boot_sector_missing_its_signature_is_named() {
        // The region's checksum covers whatever is in the sector and says nothing about what
        // it should be, so a region with its eight signatures wiped and a checksum that
        // agrees with its bytes is self-consistent and still not the region the format
        // defines. The accessor for the check existed and the check did not.
        for region in [0u64, BOOT_REGION_SECTORS] {
            let mut bytes = image();
            let at = (region as usize + 1) * 512;
            bytes[at + 508..at + 512].copy_from_slice(&0u32.to_le_bytes());
            refresh_boot_checksum(&mut bytes, region);
            let err = open_err(&bytes, ReadPolicy::Strict);
            assert!(
                matches!(
                    err,
                    ReadError::BadExtendedBootSignature {
                        sector,
                        found: 0,
                        expected: EXTENDED_BOOT_SIGNATURE,
                    } if sector == region + 1
                ),
                "region {region}: {err}"
            );
        }

        // One report per region, however many of its eight sectors are wiped: eight sectors
        // zeroed together are one fact about the region, and a scan that spent eight findings
        // on it would have that much less room for the rest of the volume.
        let mut bytes = image();
        for sector in 1..=EXTENDED_BOOT_SECTORS as usize {
            let at = sector * 512;
            bytes[at + 508..at + 512].copy_from_slice(&0u32.to_le_bytes());
        }
        refresh_boot_checksum(&mut bytes, 0);
        let named: Vec<_> = scan_of(&bytes)
            .into_iter()
            .filter(|f| f.detail.contains("extended boot sector"))
            .collect();
        assert_eq!(named.len(), 1, "{named:#?}");
        assert_eq!(named[0].severity, Severity::Conformance);
    }

    #[test]
    fn a_chain_reaching_a_cluster_the_table_marks_bad_is_named_as_that() {
        // A bad cluster is a number the format sets aside so that nothing allocates it, so a
        // chain reaching one is a chain into storage a driver was told to leave alone rather
        // than a cluster number that happens to be too high. The range test would refuse it
        // either way; what the constant buys is a reader that says which.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 9_000], meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "F.BIN");
        let stream = stream_at(set);
        // Chained rather than consecutive, so the table is consulted at all.
        bytes[stream + 1] &= !SECONDARY_NO_FAT_CHAIN;
        refresh_set_checksum(&mut bytes, set);
        let first = u32::from_le_bytes([
            bytes[stream + 20],
            bytes[stream + 21],
            bytes[stream + 22],
            bytes[stream + 23],
        ]);
        let entry = reader(&bytes)
            .layout()
            .fat_entry_byte(first)
            .expect("an entry for the first cluster") as usize;
        bytes[entry..entry + 4].copy_from_slice(&BAD_CLUSTER.to_le_bytes());

        let mut r = lenient(&bytes);
        let node = r.lookup(b"/F.BIN").expect("look up");
        let err = r
            .read_data(&node)
            .expect_err("the chain runs into the mark");
        assert!(
            matches!(err, ReadError::BadClusterInChain { cluster } if cluster == BAD_CLUSTER),
            "{err}"
        );
    }

    #[test]
    fn a_percentage_the_field_cannot_hold_is_a_different_remark_from_a_stale_one() {
        // The field is a percentage, 0 through 100, or 255 for "not known", and it sits
        // outside the boot region's checksum precisely so a driver can keep it current. So a
        // stale value is a number nobody was obliged to update, and a value between the two
        // is a byte that was never a percentage — which is a different thing to be told.
        let mut bytes = image();
        bytes[112] = 200;
        let found = scan_of(&bytes)
            .into_iter()
            .find(|f| f.detail.contains("PercentInUse"))
            .expect("the value is reported");
        assert_eq!(found.severity, Severity::Conformance);
        assert!(!found.detail.contains("200%"), "{}", found.detail);

        // A percentage that is merely out of date says how full the volume is instead.
        let mut bytes = image();
        bytes[112] = 99;
        let found = scan_of(&bytes)
            .into_iter()
            .find(|f| f.detail.contains("99% in use"))
            .expect("the staleness is reported");
        assert_eq!(found.severity, Severity::Cosmetic);

        // And "not known" is neither.
        let mut bytes = image();
        bytes[112] = PERCENT_IN_USE_UNKNOWN;
        assert!(
            !scan_of(&bytes)
                .iter()
                .any(|f| f.detail.contains("PercentInUse") || f.detail.contains("in use and")),
            "the format's own value for an unmeasured volume is not a deviation"
        );
    }

    #[test]
    fn an_up_case_table_that_is_not_the_mapping_its_entry_advertises_is_named() {
        let mut bytes = image();
        let table = cluster_at(&bytes, reader(&bytes).layout().upcase_cluster);
        bytes[table + 200] ^= 0xff;
        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(
            matches!(err, ReadError::UpcaseChecksumMismatch { .. }),
            "{err}"
        );
        assert_eq!(err.anomaly().severity, Severity::Integrity);
        assert_eq!(err.anomaly().category, Category::UpcaseTable);
        // Leniently the volume opens and folds through the table as it stands, because those
        // bytes are still the volume's own statement about how its names compare.
        assert!(lenient(&bytes).upcase().folded_units() > 0);
    }

    #[test]
    fn a_damaged_entry_set_checksum_is_named() {
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "BIG.BIN");
        // The attribute word, which is inside the set and outside the two bytes the checksum
        // steps over.
        bytes[set + 4] ^= 0x01;
        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(
            matches!(err, ReadError::SetChecksumMismatch { .. }),
            "{err}"
        );
        assert_eq!(err.anomaly().severity, Severity::Integrity);
    }

    #[test]
    fn a_name_hash_no_name_produces_is_named_where_no_checksum_covers_it() {
        // The failure a reader is uniquely placed to name: the set's own checksum is
        // satisfied by a hash and a name that disagree, so nothing but recomputing the hash
        // finds it — and a driver that trusts the field never sees the file.
        let mut bytes = image();
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "BIG.BIN");
        let stream = set + DIR_ENTRY_SIZE;
        let was = u16::from_le_bytes(bytes[stream + 4..stream + 6].try_into().unwrap());
        bytes[stream + 4..stream + 6].copy_from_slice(&(was ^ 0x0001).to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(matches!(err, ReadError::NameHashMismatch { .. }), "{err}");
        assert_eq!(err.anomaly().severity, Severity::Integrity);
    }

    #[test]
    fn a_name_no_directory_can_hold_is_refused_where_the_reader_resolves_it() {
        // Nothing about the field a name arrives in rules these out: an exFAT name is UTF-16
        // and may spell anything, so the refusal is the reader's.
        for name in ["..", ".", "a/b", "a\u{0}b"] {
            let mut bytes = image_of(TreeBuilder::new().file(b"/XX".to_vec(), b"x", meta(0o644)));
            let root = reader(&bytes).layout().first_cluster_of_root;
            let set = set_at(&bytes, root, "XX");
            let stream = set + DIR_ENTRY_SIZE;
            let units: Vec<u16> = name.encode_utf16().collect();
            bytes[stream + 3] = units.len() as u8;
            let hash = name_hash(&UpcaseTable::recommended().fold(&units));
            bytes[stream + 4..stream + 6].copy_from_slice(&hash.to_le_bytes());
            let name_entry = set + 2 * DIR_ENTRY_SIZE;
            bytes[name_entry + 2..name_entry + DIR_ENTRY_SIZE].fill(0);
            for (n, unit) in units.iter().enumerate() {
                let at = name_entry + 2 + n * 2;
                bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            }
            refresh_set_checksum(&mut bytes, set);

            let err = root_entries(&bytes).expect_err("a strict read refuses");
            assert!(
                matches!(err, ReadError::HostileName { .. }),
                "{name:?}: {err}"
            );
            assert_eq!(err.anomaly().severity, Severity::Structural);
            // And it is never handed back, whatever the policy: a path built by joining it
            // onto its directory's would leave the tree.
            let names = root_entries_lenient(&bytes);
            assert!(names.is_empty(), "{name:?}: the name was handed back");
        }
    }

    #[test]
    fn an_entry_set_that_ends_before_it_said_it_would_is_named() {
        let mut bytes = image_of(TreeBuilder::new().file(b"/XX".to_vec(), b"x", meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let set = set_at(&bytes, root, "XX");
        // One more entry than the set has, so the terminator behind it ends the set short.
        bytes[set + 1] += 1;
        refresh_set_checksum(&mut bytes, set);
        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(matches!(err, ReadError::IncompleteEntrySet { .. }), "{err}");
        assert_eq!(err.anomaly().severity, Severity::Structural);
    }

    #[test]
    fn an_entry_continuing_a_set_no_entry_opened_is_named() {
        let mut bytes = image_of(TreeBuilder::new());
        let root = reader(&bytes).layout().first_cluster_of_root;
        let at = cluster_at(&bytes, root);
        // The first free slot behind the four a format writes.
        let slot = at + 4 * DIR_ENTRY_SIZE;
        bytes[slot] = EntryType::FILE_NAME.0;
        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(
            matches!(err, ReadError::StraySecondaryEntry { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_entry_of_a_critical_type_this_reader_does_not_know_is_named_and_a_benign_one_is_not() {
        // The type byte says whether an implementation that does not know an entry may carry
        // on, and this reader takes the format at its word in both directions.
        let root = {
            let bytes = image_of(TreeBuilder::new());
            reader(&bytes).layout().first_cluster_of_root
        };
        let mut bytes = image_of(TreeBuilder::new());
        let at = cluster_at(&bytes, root);
        bytes[at + 4 * DIR_ENTRY_SIZE] = 0x9F; // in use, primary, critical, code 31
        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(
            matches!(err, ReadError::UnknownCriticalEntry { .. }),
            "{err}"
        );
        assert_eq!(err.anomaly().severity, Severity::Conformance);

        let mut bytes = image_of(TreeBuilder::new());
        bytes[at + 4 * DIR_ENTRY_SIZE] = 0xBF; // in use, primary, benign, code 31
        assert!(
            root_entries(&bytes).is_ok(),
            "a benign entry is carried through rather than refused",
        );
    }

    #[test]
    fn an_entry_after_the_end_marker_is_named_once_and_never_handed_back() {
        let mut bytes = image_of(TreeBuilder::new().file(b"/XX".to_vec(), b"x", meta(0o644)));
        let root = reader(&bytes).layout().first_cluster_of_root;
        let at = cluster_at(&bytes, root);
        let set = set_at(&bytes, root, "XX");
        // The terminator moved ahead of the set, so the set is past the end of the directory.
        assert!(set > at);
        bytes[set] = 0;
        // ...and a used slot behind it, which every driver stops before reaching.
        let orphan = set + 4 * DIR_ENTRY_SIZE;
        bytes[orphan] = EntryType::VOLUME_GUID.0;

        let err = root_entries(&bytes).expect_err("a strict read refuses");
        assert!(matches!(err, ReadError::EntriesAfterEnd { .. }), "{err}");
        let entries = root_entries_lenient(&bytes);
        assert!(entries.is_empty(), "nothing past the marker is a name");
    }

    // -- the allocation record ----------------------------------------------------------

    #[test]
    fn a_cluster_a_stream_occupies_and_the_bitmap_calls_free_is_named() {
        // The bitmap is the volume's record of what is in use, so a stream occupying a
        // cluster it calls free is a volume in which the next allocation overwrites a file.
        // It is also the disagreement the checker misses: `fsck.exfat` objects only when a
        // cluster a file *chains through* is marked free, and every stream this writer emits
        // chains through nothing.
        let mut bytes =
            image_of(TreeBuilder::new().file(b"/F.BIN".to_vec(), vec![0x5a; 300], meta(0o644)));
        let (root, bitmap_cluster) = {
            let r = reader(&bytes);
            (r.layout().first_cluster_of_root, r.layout().bitmap_cluster)
        };
        let stream = set_at(&bytes, root, "F.BIN") + DIR_ENTRY_SIZE;
        let first = u32::from_le_bytes(bytes[stream + 20..stream + 24].try_into().unwrap());
        let bit = (first - FIRST_CLUSTER) as usize;
        let at = cluster_at(&bytes, bitmap_cluster) + bit / 8;
        assert_ne!(bytes[at] & (1 << (bit % 8)), 0, "the bit was set");
        bytes[at] &= !(1 << (bit % 8));

        let found = scan_of(&bytes);
        assert!(
            found
                .iter()
                .any(|a| a.detail.contains("the allocation bitmap says it is free")),
            "{found:#?}"
        );
        // The volume still reads: the disagreement is about the record, not about the bytes.
        let mut r = lenient(&bytes);
        let node = r.lookup(b"/F.BIN").expect("look up");
        assert_eq!(r.read_data(&node).expect("read").len(), 300);
    }

    #[test]
    fn clusters_the_bitmap_holds_and_nothing_reaches_are_named() {
        let mut bytes = image();
        let bitmap = cluster_at(&bytes, reader(&bytes).layout().bitmap_cluster);
        // Two bits high in the bitmap, for clusters nothing on the volume owns.
        bytes[bitmap + 40] |= 0b1001;

        let found = scan_of(&bytes);
        let lost = found
            .iter()
            .find(|a| a.detail.contains("reached by nothing"))
            .expect("the clusters are named");
        assert!(lost.detail.contains('2'), "{}", lost.detail);
        assert_eq!(lost.severity, Severity::Conformance);
    }

    #[test]
    fn a_reserved_table_entry_the_format_fixes_is_held_to_it() {
        let mut bytes = image();
        let fat = reader(&bytes).layout().fat_offset as usize
            * reader(&bytes).layout().bytes_per_sector as usize;
        bytes[fat + 4..fat + 8].copy_from_slice(&0u32.to_le_bytes());
        let found = scan_of(&bytes);
        assert!(
            found.iter().any(|a| a.detail.contains("table entry 1")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_clean_volume_scans_clean_at_every_cluster_size_the_writer_reaches() {
        // The scan's own negative control: it has to be silent on a volume with nothing wrong
        // with it, or nothing above means anything. Three geometries, so the bitmap spans one
        // cluster on one of them and several on another.
        use crate::exfat::{ClusterSize, PlanRequest};
        for (bytes_total, cluster) in [
            (32u64 << 20, ClusterSize::Bytes(512)),
            (64 << 20, ClusterSize::Auto),
            (256 << 20, ClusterSize::Bytes(128 << 10)),
        ] {
            let options = FormatOptions::new(7).plan(PlanRequest::new(0).cluster_size(cluster));
            let image = format(tree(), bytes_total, options).expect("format");
            let bytes = image.into_bytes();
            let mut r = reader(&bytes);
            let report = r.scan();
            assert!(
                report.is_clean(),
                "{bytes_total} at {cluster:?}:\n{}",
                report.to_report().to_table()
            );
            assert_eq!(paths(&bytes).len(), 5);
        }
    }

    // -- the bounds ----------------------------------------------------------------------

    #[test]
    fn a_walk_stops_at_the_cap_a_caller_set() {
        let bytes = image();
        let mut r = Reader::open_with(
            Cursor::new(&bytes[..]),
            &OpenOptions::new().limits(Limits::new().max_walk_entries(2)),
        )
        .expect("open");
        assert!(matches!(
            r.walk(),
            Err(ReadError::WalkTooLarge { limit: 2 })
        ));
    }

    #[test]
    fn a_whole_file_read_stops_at_the_cap_a_caller_set() {
        let bytes = image();
        let mut r = Reader::open_with(
            Cursor::new(&bytes[..]),
            &OpenOptions::new().limits(Limits::new().max_file_bytes(1024)),
        )
        .expect("open");
        let node = r.lookup(b"/BIG.BIN").expect("look up");
        assert!(matches!(
            r.read_data(&node),
            Err(ReadError::FileTooLarge { size: 9_000, .. })
        ));
        // And a read into a caller's own buffer is bounded by the buffer instead, so a
        // partial read stays representable rather than becoming a refusal.
        let mut buf = [0u8; 16];
        assert_eq!(r.read_into(&node, 0, &mut buf).expect("read"), 16);
    }

    #[test]
    fn a_directory_that_points_at_itself_terminates_a_walk() {
        // Nothing in a directory entry says it does not point back up the tree. Descending
        // into a directory only the first time its first cluster is reached is what bounds
        // the walk, and the set checksum is refreshed so the cycle is what stops it.
        let mut bytes = image_of(
            TreeBuilder::new()
                .directory(b"/a".to_vec(), meta(0o755))
                .directory(b"/a/b".to_vec(), meta(0o755)),
        );
        let root = reader(&bytes).layout().first_cluster_of_root;
        let a_cluster = {
            let mut r = reader(&bytes);
            let node = r.lookup(b"/a").expect("look up");
            node.storage.first_cluster().expect("a directory has one")
        };
        let set = set_at(&bytes, a_cluster, "b");
        let stream = set + DIR_ENTRY_SIZE;
        bytes[stream + 20..stream + 24].copy_from_slice(&a_cluster.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);
        assert_ne!(a_cluster, root);

        let names = paths(&bytes);
        assert_eq!(names, vec![b"/a".to_vec(), b"/a/b".to_vec()]);
    }

    #[test]
    fn a_directory_ending_on_the_heaps_last_cluster_is_read_rather_than_refused() {
        // The fencepost a consecutive run invites: the cluster after a run is arithmetic, and
        // asking for the one past the last would refuse a directory that ends exactly where
        // the heap does — for running past an end it never reached. Nothing this writer
        // places lands there, which is why it is built rather than found.
        let mut bytes = image_of(TreeBuilder::new().directory(b"/d".to_vec(), meta(0o755)));
        let (root, last) = {
            let r = reader(&bytes);
            let layout = r.layout();
            (
                layout.first_cluster_of_root,
                FIRST_CLUSTER + layout.cluster_count - 1,
            )
        };
        let set = set_at(&bytes, root, "d");
        let stream = set + DIR_ENTRY_SIZE;
        bytes[stream + 20..stream + 24].copy_from_slice(&last.to_le_bytes());
        refresh_set_checksum(&mut bytes, set);

        let mut r = lenient(&bytes);
        let node = r.lookup(b"/d").expect("look the directory up");
        assert_eq!(node.storage, Storage::Contiguous(last));
        // The cluster holds zeros, which is an empty directory: the first slot ends it.
        assert!(r.read_dir(&node).expect("read the last cluster").is_empty());
    }

    #[test]
    fn a_directory_whose_chain_repeats_a_cluster_is_refused_rather_than_followed() {
        let mut bytes = image();
        let (root, fat) = {
            let r = reader(&bytes);
            (
                r.layout().first_cluster_of_root,
                r.layout().fat_offset as usize * r.layout().bytes_per_sector as usize,
            )
        };
        // The root's own chain, pointed back at itself.
        let entry = fat + root as usize * 4;
        bytes[entry..entry + 4].copy_from_slice(&root.to_le_bytes());
        let err = open_err(&bytes, ReadPolicy::Strict);
        assert!(matches!(err, ReadError::ChainTooLong { .. }), "{err}");
    }

    #[test]
    fn a_reader_never_panics_on_mangled_images() {
        // The never-panic contract: opening and every read path return errors on malformed
        // bytes, never crash. A deterministic smoke test over degenerate geometry,
        // truncations, and bit-flips of a valid image; the cargo-fuzz target in fuzz/ is the
        // exhaustive version.
        let image = image();

        fn drive(bytes: &[u8]) {
            if let Ok(mut r) = Reader::open(Cursor::new(bytes)) {
                let _ = r.volume_label();
                if let Ok(entries) = r.walk() {
                    for e in &entries {
                        let _ = r.read_data(&e.node);
                    }
                    for e in &entries {
                        let _ = r.lookup(&e.path);
                    }
                }
            }
            if let Ok(mut r) = Reader::open_with(
                Cursor::new(bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            ) {
                let report = r.scan();
                let _ = report.to_report().to_json();
                let _ = report.to_report().to_table();
                let _ = r.walk();
            }
            // At a nonzero base, which drives the base-relative addressing a volume inside a
            // larger image is read through.
            if let Ok(mut r) = Reader::open_with(
                Cursor::new(bytes),
                &OpenOptions::new().base(512).policy(ReadPolicy::Lenient),
            ) {
                let _ = r.scan();
            }
        }

        drive(&image);

        // Degenerate geometry that would divide by zero, overflow, or address outside the
        // volume if unguarded. Every one is a field of the Main Boot Sector at sector 0.
        for (off, len, fill) in [
            (72usize, 8usize, 0xffu8), // VolumeLength enormous
            (80, 4, 0xff),             // FatOffset past the volume
            (84, 4, 0xff),             // FatLength enormous
            (88, 4, 0xff),             // ClusterHeapOffset past the volume
            (92, 4, 0xff),             // ClusterCount enormous
            (96, 4, 0xff),             // FirstClusterOfRootDirectory outside the heap
            (108, 1, 0x00),            // BytesPerSectorShift zero
            (108, 1, 0xff),            // BytesPerSectorShift enormous
            (109, 1, 0xff),            // SectorsPerClusterShift enormous
            (110, 1, 0x00),            // NumberOfFats zero
        ] {
            let mut mangled = image.clone();
            mangled[off..off + len].fill(fill);
            drive(&mangled);
        }

        // Truncations at assorted lengths.
        for len in [0usize, 1, 511, 512, 513, 4096, 6144, 65_536, 1 << 20] {
            drive(&image[..len.min(image.len())]);
        }

        // Deterministic single-byte flips across the metadata region, one image reused
        // (flip, drive, restore) so the sweep stays cheap.
        let mut flip = image.clone();
        let span = flip.len().min(1 << 20);
        let mut i = 0usize;
        while i < span {
            let orig = flip[i];
            flip[i] ^= 0xff;
            drive(&flip);
            flip[i] = orig;
            i += 4093; // a prime stride so flips land on varied field offsets
        }

        // A few fixed non-image patterns.
        drive(&vec![0x00u8; 1 << 16]);
        drive(&vec![0xffu8; 1 << 16]);
        let ramp: Vec<u8> = (0..1u32 << 16).map(|k| (k % 256) as u8).collect();
        drive(&ramp);
    }

    // -- the shared surface --------------------------------------------------------------

    #[test]
    fn the_extraction_surface_answers_for_every_node_a_walk_reaches() {
        // What a sink sees, and the one thing that must be complete however little the format
        // records: an owner and a mode, both invented, both said to be.
        let bytes = image();
        let mut r = reader(&bytes);
        let synthesis = Synthesis::new();
        let mut seen = Vec::new();
        r.walk_tree::<TreeError, _>(|reader, entry| {
            let attrs = reader.stat(&entry.node, &synthesis)?;
            assert!(attrs.synthesized.contains(&Property::Ownership));
            assert!(attrs.synthesized.contains(&Property::Permissions));
            assert!(attrs.xattrs.is_empty());
            // No second name for a node: the format has none, so two paths are two nodes.
            assert_eq!(entry.shared, None);
            seen.push((entry.path.clone(), entry.kind));
            Ok(())
        })
        .expect("walk");
        assert_eq!(seen[0].0, Vec::<u8>::new(), "the root comes first");
        assert_eq!(seen.len(), 6);
        assert!(matches!(seen[1].1, NodeKind::File { size: 9_000 }));

        // A link target is an error rather than a value, this family having no links at all.
        let root = r.root();
        assert!(matches!(
            r.link_target(&root),
            Err(TreeError::Malformed { .. })
        ));
    }

    #[test]
    fn a_read_only_file_comes_back_with_its_write_bits_cleared() {
        // The one permission bit the format holds. The other eight came from the caller and
        // nothing in the volume speaks to them, which is why both are named as invented.
        let bytes = image();
        let mut r = reader(&bytes);
        let node = r
            .lookup(b"/DCIM/A name long enough to need two entries.txt")
            .expect("look up");
        let attrs = r.stat(&node, &Synthesis::new()).expect("stat");
        assert_eq!(attrs.meta.mode & 0o222, 0);
    }

    #[test]
    fn every_read_error_answers_with_an_anomaly_that_says_where_it_was() {
        // Exhaustive by construction: a variant added without a case here is a variant whose
        // severity nobody chose. The list is the enum's, and the assertion is only that each
        // answers rather than what it answers, which the cases above pin one at a time.
        let all = [
            ReadError::Io {
                kind: std::io::ErrorKind::UnexpectedEof,
                message: "x".to_string(),
            },
            ReadError::Parse(ParseError::TooShort {
                structure: "x",
                need: 1,
                got: 0,
            }),
            ReadError::BadBootSector {
                detail: "x".to_string(),
            },
            ReadError::TexFat,
            ReadError::FatCount { count: 3 },
            ReadError::BootChecksumMismatch {
                sector: 0,
                computed: 1,
                stored: 2,
            },
            ReadError::BootChecksumSectorSplit { sector: 12 },
            ReadError::BackupBootRegionDiffers {
                sector: 12,
                detail: "x".to_string(),
            },
            ReadError::UnknownMinorRevision { minor: 3 },
            ReadError::BadExtendedBootSignature {
                sector: 1,
                found: 0,
                expected: EXTENDED_BOOT_SIGNATURE,
            },
            ReadError::ClusterOutOfRange { cluster: 9 },
            ReadError::BadChainEntry {
                cluster: 9,
                entry: 0,
            },
            ReadError::BadClusterInChain {
                cluster: BAD_CLUSTER,
            },
            ReadError::ChainTooLong {
                start: 2,
                clusters: 4,
            },
            ReadError::StreamTooShort {
                start: 2,
                declared: 8,
                held: 4,
            },
            ReadError::BadReservedEntry {
                index: 1,
                found: 0,
                expected: 1,
            },
            ReadError::MissingResident { resident: "x" },
            ReadError::UpcaseChecksumMismatch {
                computed: 1,
                stored: 2,
            },
            ReadError::UpcaseTooLong {
                bytes: 1 << 40,
                limit: MAX_UPCASE_BYTES,
            },
            ReadError::BitmapWrongSize {
                bytes: 1,
                clusters: 2,
            },
            ReadError::SetChecksumMismatch {
                index: 0,
                computed: 1,
                stored: 2,
            },
            ReadError::IncompleteEntrySet {
                index: 0,
                detail: "x".to_string(),
            },
            ReadError::StraySecondaryEntry { index: 0 },
            ReadError::UnknownCriticalEntry {
                index: 0,
                entry_type: 0x9F,
            },
            ReadError::IllFormedName { index: 0 },
            ReadError::NameHashMismatch {
                index: 0,
                computed: 1,
                stored: 2,
            },
            ReadError::HostileName { index: 0 },
            ReadError::ExcessNameEntries {
                want: 1,
                have: 2,
                index: 0,
            },
            ReadError::MisplacedRootEntry {
                index: 0,
                entry_type: "x",
            },
            ReadError::DuplicateRootEntry {
                index: 0,
                entry_type: "x",
            },
            ReadError::LabelTooLong {
                count: 200,
                limit: MAX_LABEL_UNITS,
            },
            ReadError::LabelNulUnit,
            ReadError::EntriesAfterEnd { index: 0 },
            ReadError::DirectoryWithoutAllocation { index: 0 },
            ReadError::StreamWithoutAllocation {
                index: 0,
                declared: 9_000,
            },
            ReadError::AllocationWithoutLength {
                index: 0,
                first_cluster: 5,
            },
            ReadError::StreamPastHeap {
                declared: 1 << 40,
                limit: 1 << 20,
            },
            ReadError::DirectoryTooLong {
                index: 0,
                declared: 1 << 30,
                limit: MAX_DIRECTORY_BYTES,
            },
            ReadError::DirectoryLengthNotClusters {
                index: 0,
                declared: 1,
                bytes_per_cluster: 4096,
            },
            ReadError::ReservedAttributes {
                index: 0,
                bits: 0xF008,
            },
            ReadError::AllocationNotPossible { index: 0 },
            ReadError::MalformedTimestamp {
                index: 0,
                field: "creation time",
            },
            ReadError::ValidLengthPastEnd {
                valid: 2,
                declared: 1,
            },
            ReadError::ValidLengthTrails {
                valid: 1,
                declared: 2,
            },
            ReadError::ClusterNotAllocated { cluster: 2 },
            ReadError::LostClusters { count: 1, first: 2 },
            ReadError::CrossLinkedCluster { cluster: 2 },
            ReadError::PercentInUseOutOfRange { stated: 200 },
            ReadError::PercentInUseStale {
                stated: 4,
                in_use: 10,
                clusters: 15_872,
                actual: 0,
            },
            ReadError::VolumeDirty,
            ReadError::MediaFailure,
            ReadError::NotFound {
                path: b"/x".to_vec(),
            },
            ReadError::NotADirectory {
                path: b"/x".to_vec(),
            },
            ReadError::FileTooLarge { size: 2, limit: 1 },
            ReadError::PathTooLong { limit: MAX_PATH },
            ReadError::WalkTooLarge { limit: 1 },
        ];
        for err in all {
            let anomaly = err.anomaly();
            assert!(!anomaly.detail.is_empty(), "{err:?}");
            // The projection too: a coordinate and a byte offset are arithmetic over numbers
            // an image supplied, and the family and category ride along.
            let finding = anomaly.to_finding(512);
            assert_eq!(finding.family, Family::ExFat);
            assert_eq!(finding.category, anomaly.category.as_str());
        }
    }

    #[test]
    fn every_category_names_itself() {
        for category in [
            Category::BootRegion,
            Category::AllocationTable,
            Category::AllocationBitmap,
            Category::UpcaseTable,
            Category::Directory,
        ] {
            assert!(!category.as_str().is_empty());
        }
    }

    /// A little-endian 64-bit field of `bytes` at `at`, for a case that reads one back raw.
    fn bytes_u64(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
    }

    #[test]
    fn the_recommended_table_is_what_a_volume_this_crate_wrote_folds_through() {
        // The writer lays down the mapping every implementation writes, and the reader reads
        // whatever is there — so on this crate's own volumes the two are the same table, and
        // that is a fact worth asserting rather than assuming.
        let bytes = image();
        let r = reader(&bytes);
        let recommended = UpcaseTable::recommended();
        assert_eq!(r.upcase().folded_units(), recommended.folded_units());
        for unit in [b'a' as u16, 0x00E9, 0x03B1, 0x0430, 0x00DF] {
            assert_eq!(r.upcase().fold_unit(unit), recommended.fold_unit(unit));
        }
        assert_eq!(RECOMMENDED_UPCASE_TABLE.len(), 2918);
        assert_eq!(BOOT_CHECKSUM_SKIPS.len(), 3);
    }
}
