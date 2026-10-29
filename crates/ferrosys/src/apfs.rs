//! The APFS family: containers, the volumes in them, and the byte-exact on-disk structures
//! both are made of.
//!
//! APFS is the filesystem of every Mac, iPhone and iPad, of the disk images macOS makes, and
//! of the external drives a Mac formats. This module reads one over any seekable source — a
//! file, a partition within a disk image, anything that is `Read + Seek` — and writes one from a
//! source tree into any seekable destination, in userspace and rootless, as ordinary reads and
//! writes of ordinary bytes.
//!
//! # A container of volumes
//!
//! An APFS partition holds one **container**: a pool of blocks, a checkpoint saying which
//! state of it is current, and an object map finding each of its objects. The container lists
//! up to a hundred **volumes**, each a whole filesystem of its own — its own tree of files,
//! its own inode numbers, its own name — sharing the container's free space. None is inside
//! another, so a read is a read of one volume.
//!
//! [`Container`] is the pool and the volumes it lists. [`Reader`] is one volume, read as files:
//!
//! ```no_run
//! use ferrosys::apfs::{Container, OpenOptions, Reader, VolumeSelector};
//!
//! let container = Container::open(std::fs::File::open("disk.img")?)?;
//! for volume in container.volumes() {
//!     println!("{}: {}", volume.slot, String::from_utf8_lossy(volume.name()));
//! }
//!
//! let options = OpenOptions::new().volume(VolumeSelector::Name(b"Data".to_vec()));
//! let mut reader = Reader::open_with(std::fs::File::open("disk.img")?, &options)?;
//! for entry in reader.walk()? {
//!     println!("{}", String::from_utf8_lossy(&entry.path));
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Everything is checked
//!
//! Every object carries a checksum over its block, and this crate recomputes each one from the
//! bytes that came off the source. A checksum is not the whole of it: an object also records
//! its own identifier, its type, and the transaction that wrote it, and each is held against
//! what led to it — so an object read from the wrong place, or one left from an earlier
//! transaction at an address since written again, is refused by a check no checksum can make.
//! A tree node's keys are held to the entry its parent has for it.
//!
//! # What a container may carry that this refuses
//!
//! An incompatible feature bit is the format telling a reader in advance that it will not
//! understand what follows, so a bit outside [`SUPPORTED_CONTAINER_INCOMPAT`] or
//! [`SUPPORTED_VOLUME_INCOMPAT`] is a refusal naming the feature. So is an encrypted volume, a
//! sealed one, and a Fusion container: each is entirely well-formed, and the refusal says what
//! it would take to read it.
//!
//! A file whose content is compressed is read through its compression header. A compression
//! type this build does not decode is an error naming the type, never the file's empty data
//! stream handed back as its content.
//!
//! # Planning a container
//!
//! [`plan_layout`] takes a container's size, its block size and how many volumes it begins
//! with, and places every object a newly formatted container holds: the checkpoint areas, the
//! space manager and its internal pool, and for each of the two checkpoints a container is
//! formatted with, its ephemeral objects, its object map, its volumes' objects and the blocks
//! of the space manager it writes. For one volume, each is at the block `newfs_apfs` puts it
//! when it formats a file of that size at that block size.
//!
//! # Formatting a container
//!
//! [`format()`] writes the container a plan places, its first volume populated from a
//! [`Source`](crate::Source) and every other volume from the
//! [`contents`](VolumeRequest::contents) its request gives it, or empty but for its root
//! directory and its private directory, and [`format_to`] streams it into a seekable destination, touching only the
//! blocks it occupies:
//!
//! ```no_run
//! use ferrosys::apfs::{FormatOptions, NameKind, VolumeName, VolumeRequest, format_to};
//! use ferrosys::{Metadata, Timestamp, TreeBuilder};
//!
//! let time = Timestamp::from_secs(1_700_000_000);
//! let volume = VolumeRequest::new(VolumeName::new("Data")?, [0x22; 16])
//!     .names(NameKind::CaseKeeping);
//! let options = FormatOptions::new([0x11; 16], time, volume);
//! let source = TreeBuilder::new()
//!     .directory("/etc", Metadata::new(0o755, time))
//!     .file("/etc/hostname", "ferrosys\n", Metadata::new(0o644, time));
//! format_to(std::fs::File::create("container.img")?, source, 1 << 30, options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A volume holds every property a source states: owners, modes, four times to the
//! nanosecond, hard links, device nodes, pipes, sockets and extended attributes. A name is held
//! to what macOS creates under the release profile's Unicode version, and two names a directory
//! compares as one are refused. Identifiers are taken in a depth-first walk of the tree, each
//! directory in the order its records sort, as `hdiutil create -srcfolder` takes them on a
//! volume of the same kind.
//!
//! A volume may be formatted with a [`RootSnapshot`]: a snapshot of the whole tree as it is
//! written, laid out as macOS lays out one it takes, which the volume records as the one it
//! roots from.
//!
//! Two volumes may be joined as a [`VolumeGroup`], a System volume and a Data volume, written
//! as macOS writes a group it makes, and the System volume given [`Firmlinks`]: directories
//! macOS joins to a path in the Data volume, each marked as macOS 27 marks its own.
//!
//! A container with nothing in it is, for one volume, the one `newfs_apfs` writes into a file
//! of that size, block for block, at that block size, on the macOS release the
//! [`ReleaseProfile`] names. The identifiers and the one instant the container records are
//! [`FormatOptions`] inputs, so two formats of the same source and options are the same bytes.

mod btree;
mod bulk;
mod container;
mod decmpfs;
mod detect;
mod firmlink;
mod fit;
mod fs;
mod geometry;
mod materialize;
mod model;
mod names;
mod records;
mod scan;
mod space;
mod unicode_tables;

// A container assembled byte by byte, so the guards over a malformed one are exercised in a
// build with no corpus, and so the faults no image macOS wrote carries have a gate at all.
// Reachable from the crate's own family-agnostic gates as well, which take its container as
// this family's image, built without the writer they may be checking.
#[cfg(test)]
pub(crate) mod forge;

pub mod ondisk;

pub(crate) use detect::claim;

pub use container::{
    BlockZero, Container, PassedOver, ReadError, SUPPORTED_CONTAINER_INCOMPAT,
    SUPPORTED_VOLUME_INCOMPAT, UnreadableVolume, VolumeEntry,
};
pub use firmlink::{FIRMLINK_FLAG, FIRMLINK_XATTR, Firmlinks, FirmlinksError, MAX_FIRMLINK_TARGET};
pub use fs::{Compression, Entry, Node, OpenOptions, Reader, Snapshot, VolumeSelector, WalkEntry};
pub use geometry::{
    ApfsLayout, BlockSize, Checkpoint, ChunkBitmap, ChunkGeometry, GeometryError,
    LAST_CONTIGUOUS_BLOCK_COUNT, MAX_CONTAINER_BYTES, MIN_BLOCK_COUNT, MapPlace, PlanRequest,
    QueueNodeLimits, QueueRoots, SpaceManagerShape, VolumePlace, plan_layout,
};
pub use materialize::{
    FormatError, FormatOptions, FormatPlan, Identifier, Image, NameError, NameKind, ProgramName,
    ReleaseProfile, RootSnapshot, VolumeGroup, VolumeName, VolumeRequest, format, format_to,
};
pub use model::{
    CompressedFault, MAX_EMBEDDED_XATTR, MAX_SYMLINK_TARGET, MAX_XATTR_NAME, MAX_XATTR_VALUE,
    ModelError,
};
pub use scan::{Anomaly, Category, ScanReport};

// The crate root's family-agnostic vocabulary, reached from here as well, so a caller reading
// an APFS image names one namespace rather than two. This mirrors what every other family does
// and is the one place a public item has two paths.
pub use crate::time::Timestamp;
pub use crate::{Limits, ReadPolicy};
