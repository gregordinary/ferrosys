//! The btrfs family: the logical address space, the B-trees over it, and the byte-exact
//! on-disk structures both are made of.
//!
//! btrfs is the default root filesystem on Fedora and openSUSE, the storage layer under a
//! large share of network storage appliances, and the format image-based Linux tooling
//! increasingly assumes. This module reads one over any seekable source — a file, a partition
//! within a disk image, anything that is `Read + Seek` — and writes a whole one from a source
//! tree, both in userspace and rootless, as ordinary reads and writes of ordinary bytes.
//!
//! # A format built differently from the others here
//!
//! The three other families in this crate address storage directly: a block number or a
//! cluster number is arithmetic away from a byte offset. btrfs does not. **Every address in a
//! btrfs is logical**, and a *chunk tree* maps that space onto the device — so a tree root, a
//! child pointer, and a file's extents are all addresses in a space that exists only because
//! something translates it.
//!
//! That leaves the format with a bootstrap problem it solves in the superblock: the chunk
//! items covering the chunk tree's own address are copied into it, so a reader loads those,
//! translates the chunk root, reads the chunk tree, and has the whole map.
//! [`ChunkMap`] is that map, and there is exactly one of it — a shortcut that assumed the
//! mapping were near enough the identity would work on every image a formatter writes fresh
//! and be wrong on every image that has been balanced.
//!
//! # Opening one
//!
//! [`Volume`] is the address space and the trees on it. Opening one reads every superblock
//! copy the device holds, chooses the newest that verifies, and builds the chunk map:
//!
//! ```no_run
//! use ferrosys::btrfs::{Volume, ondisk::objectid};
//!
//! let mut volume = Volume::open(std::fs::File::open("root.img")?)?;
//! let sb = volume.superblock();
//! println!("{} bytes, {} KiB nodes", sb.total_bytes, sb.nodesize / 1024);
//!
//! // Every tree the filesystem has, and how many records each holds. Reaching them verifies
//! // the checksum of every block on the way.
//! for root in volume.tree_roots()? {
//!     let name = objectid::name(root.objectid).unwrap_or("subvolume");
//!     println!("{name}: {} items", volume.tree(root).count_items()?);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Building one
//!
//! [`format()`] writes a whole filesystem from a [`Source`](crate::Source) — a directory of the
//! host, an archive, or a tree stated in code — in one transaction, in userspace and under an
//! ordinary user account:
//!
//! ```no_run
//! use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
//! use ferrosys::{DirectorySource, Metadata, Timestamp};
//!
//! let time = Timestamp::from_secs(1_700_000_000);
//! let options = FormatOptions::new([0x11; 16], time)
//!     .chunk_tree_uuid([0x22; 16])
//!     .device_uuid([0x33; 16])
//!     .subvolume_uuid([0x44; 16])
//!     // The layout a distribution that defaults to btrfs expects, stated by path.
//!     .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x55; 16]))
//!     .default_subvolume(b"/@home".to_vec());
//!
//! let source = DirectorySource::from_path("staged-root")?;
//! let image = std::fs::File::create("root.img")?;
//! format_to(image, source, 8 << 30, options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Every value a formatter would conventionally take from the clock or from a random source is
//! an option, so two formats of one tree at one parameter set are the same bytes. Everything the
//! tree cannot hold is refused before the destination is touched, and what btrfs *can* hold is
//! everything a source states — so [`Image::fidelity`] is empty on every build, which is a fact
//! about the format worth being able to check rather than to take on trust.
//!
//! # Everything is checked, and the checks are not the same check
//!
//! Every metadata block carries a checksum over itself, and this crate recomputes each one
//! from the bytes that came off the device — never from a value re-serialized through its own
//! types, which would report as damaged every filesystem it did not write.
//!
//! A checksum is not the whole of it. A block also records its own logical address and the
//! filesystem it belongs to, and both are held against what the reader believed when it went
//! to fetch it — so a block read from the wrong place, or an image carved out of a disk at the
//! wrong offset, is caught by a check no checksum can make. The same is true one level up: a
//! superblock records where it lives, so a copy of one written somewhere else verifies
//! perfectly and says the wrong thing about itself, and [`Volume::mirrors`] is where that is
//! reported.
//!
//! # What a filesystem may carry that this refuses
//!
//! The `incompat` feature word is the format telling a reader in advance that it will not
//! understand what follows, so a bit outside [`SUPPORTED_INCOMPAT`] is a refusal naming the
//! feature rather than a read that guesses. So is a checksum algorithm this crate does not
//! compute, a filesystem spanning more than one device, and a chunk whose copies are pieces
//! rather than whole — each of those is a filesystem that is entirely well-formed, and the
//! refusal says what it would take to read it.
//!
//! An unrecognized *item type* is the opposite contract and takes the opposite answer: it is a
//! record this reader has no opinion about sitting beside records it does, so it keeps its
//! byte and [`ItemType::name`](ondisk::ItemType::name) answers [`None`] for it. A reader that
//! refused what it could not name would refuse every filesystem that has been used.

mod btree;
mod chunk;
mod decode;
mod detect;
mod fs;
mod geometry;
mod materialize;
mod model;
mod scan;
mod volume;

// A filesystem assembled byte by byte, so the guards over a malformed tree are exercised in a
// build with no host tools — and so the faults no tool has a switch for have a gate at all.
// Reachable from the crate's own family-agnostic gates as well, which need a real image of
// this family and have no formatter to build one with.
#[cfg(test)]
pub(crate) mod forge;

pub mod ondisk;

pub(crate) use detect::claim;

pub use btree::{Located, Tree};
pub use chunk::{ChunkMap, MappedChunk};
pub use fs::{Entry, Node, Reader, Subvolume, WalkEntry};
pub use materialize::{
    DEVICE_ID, FormatError, FormatOptions, FormatPlan, GENERATION, Image, LabelError, VolumeLabel,
    format, format_to,
};
pub use model::{MAX_EXTENT_BYTES, MAX_NAME_LEN, ModelError, SubvolumeRequest};

pub use geometry::{
    BOOTSTRAP_SYSTEM_CHUNK, BtrfsLayout, Content, DEFAULT_COMPAT_RO, DEFAULT_DATA_PROFILE,
    DEFAULT_INCOMPAT, DEFAULT_METADATA_PROFILE, DEFAULT_NODE_SIZE, DEFAULT_SECTOR_SIZE,
    GeometryError, LARGE_VOLUME, NodeSize, PlanRequest, Pool, Profile, RESERVED_HEAD, Reservation,
    ReservationExceeded, STRIPE_LEN, SectorSize, Slack, VOLUME_SHARE, WRITABLE_COMPAT_RO,
    WRITABLE_INCOMPAT, block_sizes, chunk_length, minimum_volume_bytes, plan_layout,
};
pub use scan::{Anomaly, Category, ScanReport, tree_name};
pub use volume::{Mirror, ReadError, SUPPORTED_INCOMPAT, TreeBlock, TreeRoot, Volume};

// The crate root's family-agnostic vocabulary, reached from here as well, so a caller reading
// a btrfs image names one namespace rather than two. This mirrors what `ext`, `fat`, and
// `exfat` do and is the one place a public item has two paths. The symlink-hop budget is
// not among them: it is a constant of the shared resolver with one path,
// `crate::MAX_SYMLINK_HOPS`.
pub use crate::time::Timestamp;
pub use crate::{Limits, OpenOptions, ReadPolicy};
