//! The FAT12/FAT16/FAT32 family: the formatter, the geometry planner, and the byte-exact
//! on-disk structures.
//!
//! The three FATs are one lineage. They share a boot sector, a directory format, and a
//! cluster heap, and differ in the width of a file allocation table entry and in where the
//! root directory sits — so they are one implementation parameterized by [`FatType`], not
//! three siblings, and one Cargo feature rather than three.
//!
//! # The type is derived, never chosen
//!
//! Nothing in a FAT image records which of the three it is. Every driver counts the clusters
//! and compares against two thresholds, so the type follows from the geometry and from
//! nothing else — not from the media byte, not from the type string in the boot sector, and
//! not from what a caller asked for. [`plan_layout`] therefore takes what the derivation
//! must *arrive at* ([`FatTypeRequest`]) rather than what to write down, and reports the
//! result on the layout it returns.
//!
//! Two consequences are worth knowing before reading anything else here:
//!
//! - A count of 4085 or 4086 clusters is FAT16 to the specification and to Linux, and FAT12
//!   to Windows. This crate never writes one — the planner shortens the filesystem by a
//!   cluster or two and produces the largest count neither disputes — and
//!   [`FatType::of_cluster_count`] answers `Fat16` for one it is shown, agreeing with the
//!   specification.
//! - A FAT32 volume below [`MIN_CLUSTERS_FAT32`] clusters is non-conformant and is read as
//!   FAT32 by every mainstream driver all the same, since they recognize the type by a zero
//!   16-bit table size before counting anything. It is refused by default and produced on
//!   request through [`FatTypeRequest::UndersizedFat32`].
//!
//! # What a FAT volume cannot carry
//!
//! A directory entry holds a name, one attribute byte, three coarse timestamps, a first
//! cluster, and a length. There is no field for an owner, a group, permission bits, a
//! symbolic link, a second name for a file, a device number, or an extended attribute — so a
//! tree carrying any of those loses something on the way in, and a build that would lose
//! something fails until the caller has named it in an [`AcceptedLoss`](crate::AcceptedLoss).
//!
//! A property counts as lost when the value a read gets back is not the value that was
//! stated, which is narrower than "the format has no field for it". A tree owned by root with
//! `0644` files and `0755` directories goes in and comes back out unchanged, because those
//! are what [`Synthesis`](crate::Synthesis) hands back for a filesystem recording none — so
//! nothing was lost and [`FidelityReport::is_faithful`](crate::FidelityReport::is_faithful)
//! says so. A file at `0755` did lose something, and the build says which entry and what.
//!
//! Two shapes of entry are worth knowing about before pointing a root filesystem at this:
//!
//! - **A hard link is written as a second copy of its file.** Its target is named inside the
//!   [`Source`](crate::Source), so resolving it reads nothing this crate was not given.
//!   [`FormatPlan`] is where the size that costs is a number to read rather than discover.
//! - **A symbolic link is never followed.** Its target is an arbitrary path, so resolving one
//!   would copy whatever it happens to point at into the image. It leaves no entry behind,
//!   and neither do device nodes, named pipes, and sockets.
//!
//! # Reproducible output
//!
//! Two formats of the same tree produce the same bytes. Every value a formatter would
//! conventionally draw from the clock or from a random source is a [`FormatOptions`] input —
//! the volume serial number and the times the volume label entry carries — the date
//! conversion is UTC, so nothing about the machine that wrote an image reaches it, and
//! entries are sorted by path before anything is placed, so the order of a directory, the
//! short name each entry takes, and the cluster every file lands on are functions of the tree
//! rather than of the order a source yielded it in.
//!
//! # Example
//!
//! ```
//! use ferrosys::fat::{
//!     ClusterSize, FatType, FormatOptions, PlanRequest, Timestamp, VolumeLabel, format,
//!     plan_layout,
//! };
//! use ferrosys::{Metadata, TreeBuilder};
//!
//! // A 512 MiB volume, formatted the way convention formats one.
//! let layout = plan_layout(&PlanRequest::new(512 << 20))?;
//! assert_eq!(layout.fat_type, FatType::Fat32);
//!
//! // Every field is a decision a materializer obeys, and they agree with each other: the
//! // cluster count is exactly what a driver derives from the rest.
//! let derived =
//!     (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster;
//! assert_eq!(derived, layout.clusters);
//!
//! // Pinning the allocation unit is a planning input, and the type follows from it.
//! let small =
//!     plan_layout(&PlanRequest::new(32 << 20).cluster_size(ClusterSize::Sectors(1)))?;
//! assert_eq!(small.fat_type, FatType::Fat16);
//!
//! // Writing one takes a tree, the size, and the identity the image records.
//! let time = Timestamp::from_secs(1_700_000_000);
//! let source = TreeBuilder::new()
//!     .directory(b"/EFI/".to_vec(), Metadata::new(0o755, time))
//!     .file(b"/EFI/BOOTX64.EFI".to_vec(), b"MZ", Metadata::new(0o644, time));
//! let options = FormatOptions::new(0x1234_abcd, time).label(VolumeLabel::new("ESP")?);
//! let image = format(source, 512 << 20, options)?;
//! assert_eq!(image.layout(), &layout);
//!
//! // Root-owned, conventionally moded, no links: nothing was lost putting it here.
//! assert!(image.fidelity().is_faithful());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod charset;
mod detect;
mod fit;
mod geometry;
mod materialize;
mod model;
mod name;
mod read;

pub mod ondisk;
pub mod table;

pub(crate) use detect::claim;

pub use charset::ShortNameCharset;
pub use model::{MAX_FILE_BYTES, ModelError, TimeField};
pub use name::{MAX_NAME_UNITS, NameError};
pub use read::{
    Anomaly, Category, Entry, Location, Node, OpenOptions, ReadError, Reader, ScanReport, Storage,
    Times, WalkEntry,
};

pub use geometry::{
    ClusterSize, Fat32Layout, FatLayout, FatType, FatTypeRequest, GeometryError,
    MAX_BYTES_PER_CLUSTER, MAX_CLUSTERS_FAT12, MAX_CLUSTERS_FAT16, MAX_CLUSTERS_FAT32,
    MIN_CLUSTERS_FAT16, MIN_CLUSTERS_FAT32, PlanRequest, ReservedSectors, RootEntries, plan_layout,
};
pub use materialize::{
    BootCode, DEFAULT_OEM_NAME, FormatError, FormatOptions, FormatPlan, Image, LabelError,
    MEDIA_FIXED, MEDIA_REMOVABLE, VolumeLabel, format, format_to,
};

// The crate root's family-agnostic vocabulary, reached from here as well, so a caller
// formatting a FAT image names one namespace rather than two. This mirrors what `ext` does
// and is the one place a public item has two paths.
pub use crate::time::Timestamp;
