//! The exFAT family: the formatter, the geometry planner, the byte-exact on-disk structures,
//! and the classifier [`detect`](fn@crate::detect) answers
//! [`Filesystem::ExFat`](crate::Filesystem) with.
//!
//! exFAT is the interchange filesystem for large removable media. SDXC cards specify it, and
//! it is read and written by Windows, macOS, Linux, and Android as they ship.
//!
//! # A family of its own
//!
//! It shares a name with FAT and no bytes. A different boot region, a different directory
//! entry format, a different name encoding, a different allocation model, and an allocation
//! bitmap FAT has no concept of — so this is its own module behind its own feature, and the
//! only thing the two formats have in common is the word "cluster".
//!
//! # Everything is checked, and a wrong byte is a hard failure
//!
//! Three structures carry a checksum and a fourth carries a hash, and every one of them is
//! recomputed rather than copied: the boot region's over its own first eleven sectors, the
//! up-case table's over the table it describes, a directory entry set's over the whole set,
//! and a file name's hash over the up-cased name. [`ondisk`] holds all four, as pure
//! functions.
//!
//! Two bytes of the boot sector sit deliberately outside its checksum — the volume's state
//! flags and how full it is — because a mounted driver rewrites them in place. They are
//! stepped over rather than summed as zero, which is a different answer on every volume.
//!
//! # The geometry
//!
//! [`plan_layout`] derives every field the format records from a volume size, a sector size,
//! and an allocation unit: where the allocation table begins and how long it is, where the
//! cluster heap begins and how many clusters it holds, and which of those the allocation
//! bitmap, the up-case table, and the root directory occupy. It is pure, so a caller can ask
//! what a volume would look like without writing one.
//!
//! ```
//! use ferrosys::exfat::{ClusterSize, PlanRequest, plan_layout};
//!
//! // A 512 MiB volume, formatted the way convention formats one.
//! let layout = plan_layout(&PlanRequest::new(512 << 20))?;
//! assert_eq!(layout.bytes_per_cluster, 32 << 10);
//!
//! // Every field agrees with the others: the heap's clusters end within the volume, and
//! // the allocation table has an entry for each of them and for the two reserved numbers.
//! let heap = u64::from(layout.cluster_heap_offset) * u64::from(layout.bytes_per_sector);
//! let used = heap + u64::from(layout.cluster_count) * u64::from(layout.bytes_per_cluster);
//! assert!(used <= layout.total_bytes());
//! let entries = u64::from(layout.fat_length) * u64::from(layout.bytes_per_sector) / 4;
//! assert!(entries >= u64::from(layout.cluster_count) + 2);
//!
//! // Pinning the allocation unit moves everything behind it, the residents included.
//! let dense = plan_layout(&PlanRequest::new(512 << 20).cluster_size(ClusterSize::Bytes(512)))?;
//! assert_eq!(dense.cluster_count, 1_038_336);
//! assert_eq!(dense.upcase_cluster, 256);
//! # Ok::<(), ferrosys::exfat::GeometryError>(())
//! ```
//!
//! # Writing one
//!
//! [`format()`] lays down a volume of that geometry, fills it from a [`Source`](crate::Source),
//! and hands back the bytes; [`format_to`] writes the same bytes to any seekable destination
//! without ever holding them all, so a volume far larger than memory can be created into a file
//! that stays sparse. An empty volume is [`TreeBuilder::new`](crate::TreeBuilder), which places
//! nothing.
//!
//! Two formats of the same tree and the same parameters produce the same bytes, and one input
//! is the whole of what that costs: [`FormatOptions::volume_serial`], the only value a
//! formatter would conventionally draw from the clock. The times an entry records come from the
//! source that named it, and its creation time is derived from its modification time.
//!
//! ```
//! use ferrosys::exfat::{FormatOptions, VolumeLabel, format};
//! use ferrosys::{Metadata, Timestamp, TreeBuilder};
//!
//! let time = Timestamp::from_secs(1_426_325_212);
//! let source = TreeBuilder::new()
//!     .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
//!     .file(b"/DCIM/READY.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));
//!
//! let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
//! let image = format(source.clone(), 64 << 20, options)?;
//! assert_eq!(image.as_bytes().len(), 64 << 20);
//!
//! // Two formats of the same tree are the same bytes.
//! assert_eq!(image.as_bytes(), format(source, 64 << 20, options)?.as_bytes());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # What a volume cannot hold
//!
//! exFAT records a name, five attribute bits, three times, and a length. It has no field for an
//! owner, a mode, a symbolic link, a second name for a file, a device node, or an extended
//! attribute, so a tree carrying one of those loses something on the way in — and a build that
//! would lose anything is **refused** until the caller has said which losses it accepts
//! ([`FormatOptions::accepted_loss`]). What each then cost comes back as a
//! [`FidelityReport`](crate::FidelityReport), entry by entry.
//!
//! A property counts as lost when the value a read hands back is not the value that was stated,
//! which is narrower than "the format has no field for it": a root-owned tree with `0644` files
//! and `0755` directories goes in and comes back out unchanged, so it loses nothing and the
//! report says so.
//!
//! [`FormatPlan`] is where that account is available *before* the destination is touched, which
//! is what a caller wants when the answer might change what it builds — a hard link is written
//! as a second copy of its file, and the plan is where the size that costs is a number to read
//! rather than to discover.
//!
//! # Reading one
//!
//! [`Reader`] opens any exFAT volume on any seekable source — one this crate wrote, one a
//! camera wrote — and walks it, resolves a path through the volume's own case folding, and
//! streams a file's bytes. [`Reader::scan`] reports every deviation the volume carries instead
//! of stopping at the first, and [`FsTree`](crate::FsTree) is what an extraction drains it
//! through without naming the family at all.
//!
//! ```
//! use ferrosys::exfat::{FormatOptions, Reader, format};
//! use ferrosys::{Metadata, Timestamp, TreeBuilder};
//!
//! let time = Timestamp::from_secs(1_426_325_212);
//! let source = TreeBuilder::new()
//!     .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
//!     .file(b"/DCIM/READY.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));
//! let image = format(source, 64 << 20, FormatOptions::new(0x1234_abcd))?;
//!
//! let mut reader = Reader::open(std::io::Cursor::new(image.into_bytes()))?;
//! // Names are compared through the table the volume carries, so a lookup finds the entry
//! // the way every driver reading the volume would.
//! let node = reader.lookup(b"/dcim/ready.txt")?;
//! assert_eq!(reader.read_data(&node)?, b"hello\n");
//!
//! // And nothing is wrong with what was written.
//! assert!(reader.scan().is_clean());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod detect;
mod geometry;
mod materialize;
mod model;
mod name;
mod read;

pub mod ondisk;

pub(crate) use detect::claim;

pub use geometry::{
    BootDefect, BoundaryAlign, ClusterSize, DEFAULT_BOUNDARY_ALIGN, ExfatLayout, FIRST_CLUSTER,
    GeometryError, MAX_BYTES_PER_CLUSTER, MAX_CLUSTER_COUNT, MIN_VOLUME_SECTORS, PlanRequest,
    conventional_cluster_size, plan_layout,
};
pub use materialize::{
    FormatError, FormatOptions, FormatPlan, Image, LabelError, VolumeLabel, format, format_to,
};
pub use model::{MAX_DIRECTORY_BYTES, MAX_DIRECTORY_ENTRIES, ModelError, TimeField};
pub use name::{MAX_NAME_UNITS, NameError};
pub use read::{
    Anomaly, Category, Entry, Location, Node, ReadError, Reader, ScanReport, Storage, Times,
    WalkEntry,
};

// The crate root's family-agnostic vocabulary, reached from here as well, so a caller
// formatting an exFAT image names one namespace rather than two. This mirrors what `ext` and
// `fat` do and is the one place a public item has two paths.
pub use crate::time::Timestamp;
