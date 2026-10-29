//! The materializer: turn a planned [`ApfsLayout`] into the bytes of a container.
//!
//! [`plan_layout`](super::plan_layout) decided where every object a container of its size has
//! goes. This module models what each volume holds, places it, decides what each object
//! holds, checksums it, and writes it, and reads nothing back from the destination.
//!
//! # What a container is written as
//!
//! A container is written as `newfs_apfs` writes one, in two transactions whose checkpoints
//! both stay in the checkpoint areas. The first commits the container alone: a space manager
//! accounting for the checkpoint areas and the internal pool, an idle reaper, and an object map
//! with nothing in it. The second adds the volumes. Each has an object map, an extent-reference
//! tree, a snapshot tree with nothing in it, a file-system tree holding the root directory, the
//! private directory and what the source states, and a superblock. The second also writes a
//! new space manager, a new object map for the container listing the volumes, and a new
//! chunk-info block and bitmap for every chunk it allocated from, and a new address block for
//! every one listing a chunk-info block it rewrote. What it supersedes it frees: the first
//! object map to the main free queue, the first chunk-info, address and bitmap blocks to the
//! internal pool's. Block zero holds the second checkpoint's superblock.
//!
//! For one volume with nothing in it, every block is the one `newfs_apfs` writes into a file of
//! the same size, at the same block size, on the release [`ReleaseProfile`] names, except in
//! these fields:
//!
//! - the container's and the volume's identifiers, and every time the container records,
//!   which are [`FormatOptions`] inputs;
//! - the name of the program that formatted the volume, which is this crate's own unless a
//!   caller names another;
//! - the container superblock's 32 counters, which are zero;
//! - the newest version to have mounted the container, which is zero.
//!
//! Each of those values was observed accepted on macOS 15, 26 and 27, set in a container
//! `newfs_apfs` formatted: `fsck_apfs` passes one whose counters and newest mounted version are
//! zero, whose program name is another program's and whose times are zero, and the kernel
//! mounts it read-write.
//!
//! # What a volume holds
//!
//! The source's entries become inodes, directory entries, attributes, sibling records and
//! extents as [`build_model`](super::model) numbers them. Everything the second transaction
//! allocates past the objects a container of its size has is taken first-fit from the end of
//! the internal pool, a volume at a time in slot order: each file's data in inode order, then
//! each attribute stream, then the file-system tree's nodes past its root and the
//! extent-reference tree's, then what a root snapshot adds. Every volume's object map comes
//! after every volume's contents, again in slot order, since it maps what they hold.
//! Each tree is built whole, every node filled in key order. A file-system tree of one node
//! keeps the layout `newfs_apfs` gives its four records, the rest after them; every other node
//! of every tree is laid out in key order.
//!
//! # A root snapshot
//!
//! A volume asked for a [`RootSnapshot`] holds it in its snapshot tree, recorded in the second
//! transaction beside everything else, and its root-to transaction names that transaction.
//! Each object a snapshot adds is laid out as macOS lays out the one it writes when it takes a
//! snapshot, and its numbers move as they move then. The volume counts three blocks more and
//! takes one object identifier more, and the extension object takes the container's next
//! identifier once every volume's nodes have theirs. What the snapshot adds is taken from the
//! end of the internal pool after the volume's trees, in the order macOS 15, 26 and 27 write
//! it (observed): the copy of the superblock, the volume's new extent-reference tree, the
//! object map's tree of snapshots and the extension object.
//!
//! # Two volumes or more
//!
//! `newfs_apfs` formats a container with one volume, so a second and more are this crate's own
//! placement. Each takes the places [`plan_layout`](super::plan_layout) gives it, and its
//! superblock and file-system tree take the next two object identifiers after the ones the
//! first volume and the two free queues take. The nodes of each volume's file-system tree past
//! its root take the identifiers after every volume's, volume by volume in slot order. The
//! first volume holds the format's source, and each other one the
//! [`contents`](VolumeRequest::contents) its request gives it.
//!
//! # A volume group
//!
//! A [`VolumeGroup`] joins a System volume and a Data volume as macOS joins the two it makes
//! with `diskutil`. Each records its role, both record the Data volume's identifier as the
//! group's and a compatible feature bit beside the one every volume records, and the System
//! volume numbers the objects of its tree from a range of its own and records 0 where every
//! other volume records 16 past the superblock's laid-out fields. Nothing moves: every object
//! is where it is in the same container without the group. A System volume's root
//! snapshot carries all of it in its copy of the superblock, as one taken after the volume
//! joined its group would.
//!
//! The System volume's [`Firmlinks`] mark the directories they name with the flag and the
//! attribute macOS 27 keeps on its own: what the Data volume holds of each is the caller's.
//!
//! # Reproducibility
//!
//! Two formats of the same source and options are the same bytes. Every value a formatter
//! would conventionally take from the clock or from a random source is an input: an identifier
//! for the container and one for each volume, and one instant.

use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Seek, Write};

use crate::Timestamp;
use crate::bytes::{get_u16, put_u16, put_u32, put_u64};
use crate::fidelity::FidelityReport;
use crate::io::ByteSink;
use crate::sizing::Slack;
use crate::source::{Metadata, Source, SourceEntry};

use super::btree::compare_records;
use super::bulk::{self, Entries, Placed, Record, Shape, TreeKind};
use super::firmlink::{self, Firmlinks};
use super::geometry::{
    ApfsLayout, BlockSize, Checkpoint, ContentPlanner, FIRST_XID, GeometryError, MapPlace,
    POOL_BITMAP_SLOTS, PlanRequest, SECOND_XID, SPACE_MANAGER_STRUCT_SIZE, VolumePlace, chunk_span,
    narrow, to_index,
};
use super::model::{ApfsModel, ModelError, StreamBytes, build_model, nanos_of};
use super::names::UnicodeVersion;
use super::ondisk::{
    BlockRange, CheckpointAreas, CheckpointMap, CheckpointMapping, ChunkInfo, ChunkList,
    ContainerSuperblock, FreeQueue, FreeQueueKey, MAX_VOLUMES, MODIFIED_BY_ENTRIES, MapKey,
    MapValue, ModifiedBy, NO_VALUE, NODE_DATA_START, NodeHeader, ObjectHeader, ObjectMap, Reaper,
    SnapshotExtension, SnapshotMeta, SpaceDevice, SpaceManager, Storage, TREE_INFO_SIZE, TreeInfo,
    VOLUME_NAME_LEN, VolumeSuperblock, container_incompat, inode_number, kind, node_flags, seal,
    snapshot_name_record, volume_flags, volume_incompat,
};
use super::records::{VolumeRecords, volume_records};

// ---------------------------------------------------------------------------
// What a caller states

/// How a volume compares the names in it.
///
/// Both kinds store a name as the bytes it was given and look it up by a hash of a normalized
/// form, so two names that differ only in how a character is composed are one name on either.
/// They differ in case.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum NameKind {
    /// Names compare with case folded: `Read Me` and `read me` are one name. What macOS
    /// formats a volume with unless told otherwise.
    #[default]
    CaseFolding,
    /// Names keep their case: `Read Me` and `read me` are two names. What `newfs_apfs -e`
    /// formats, and what a volume that roots a Unix tree with names differing only in case
    /// needs.
    CaseKeeping,
}

crate::naming::named_choice!(NameKind {
    NameKind::CaseFolding => "case-insensitive",
    NameKind::CaseKeeping => "case-sensitive",
});

impl NameKind {
    /// The kind a volume's superblock records, or `None` where it records neither: a volume
    /// whose names compare with their composition kept too, which this crate reads and does
    /// not write.
    #[must_use]
    pub const fn of_volume(superblock: &VolumeSuperblock) -> Option<Self> {
        if superblock.is_case_insensitive() {
            Some(Self::CaseFolding)
        } else if superblock.incompatible_features & volume_incompat::NORMALIZATION_INSENSITIVE != 0
        {
            Some(Self::CaseKeeping)
        } else {
            None
        }
    }

    /// The volume's incompatible feature bit that records this kind.
    const fn feature(self) -> u64 {
        match self {
            Self::CaseFolding => volume_incompat::CASE_INSENSITIVE,
            Self::CaseKeeping => volume_incompat::NORMALIZATION_INSENSITIVE,
        }
    }

    /// Whether a name's case is folded before it is hashed.
    const fn folds(self) -> bool {
        matches!(self, Self::CaseFolding)
    }
}

/// The macOS release whose shape a container is written in.
///
/// Releases agree on every field this crate writes but two words of a volume superblock past
/// the fields every release shares: macOS 14 and 15 leave both zero, and macOS 26 and 27 record
/// the transaction that wrote the superblock in the first and 12 in the second. macOS 26's
/// kernel mounts a volume of either shape. A release also holds names to a Unicode version of
/// its own: 15.1 on macOS 14, 16.0 on 15, and 17.0 on 26 and 27.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ReleaseProfile {
    /// macOS 14.
    Macos14,
    /// macOS 15.
    Macos15,
    /// macOS 26, the default.
    #[default]
    Macos26,
    /// macOS 27.
    Macos27,
}

crate::naming::named_choice!(ReleaseProfile {
    ReleaseProfile::Macos14 => "macos14",
    ReleaseProfile::Macos15 => "macos15",
    ReleaseProfile::Macos26 => "macos26",
    ReleaseProfile::Macos27 => "macos27",
});

impl ReleaseProfile {
    /// Whether a volume superblock records its own transaction and the 12 beside it.
    const fn records_superblock_xid(self) -> bool {
        matches!(self, Self::Macos26 | Self::Macos27)
    }

    /// The Unicode version the release holds a name to: 15.1 on macOS 14, 16.0 on 15, and 17.0
    /// on 26 and 27.
    const fn unicode(self) -> UnicodeVersion {
        match self {
            Self::Macos14 => (15, 1),
            Self::Macos15 => (16, 0),
            Self::Macos26 | Self::Macos27 => (17, 0),
        }
    }
}

/// A name that does not fit the field it is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty.
    #[error("the name is empty")]
    Empty,
    /// The name is longer than the field holds.
    #[error("the name is {bytes} bytes and the field holds {max}")]
    #[non_exhaustive]
    TooLong {
        /// The name's length.
        bytes: usize,
        /// The most the field holds.
        max: usize,
    },
    /// The name holds a NUL byte, where a reader of the field stops.
    #[error("the name holds a NUL byte at {at}")]
    #[non_exhaustive]
    Nul {
        /// Where the NUL is.
        at: usize,
    },
}

/// A name of `bytes`, checked against a field of `max` bytes before its terminator.
fn checked_name(bytes: &[u8], max: usize) -> Result<(), NameError> {
    if bytes.is_empty() {
        return Err(NameError::Empty);
    }
    if bytes.len() > max {
        return Err(NameError::TooLong {
            bytes: bytes.len(),
            max,
        });
    }
    if let Some(at) = bytes.iter().position(|b| *b == 0) {
        return Err(NameError::Nul { at });
    }
    Ok(())
}

/// A volume's name, as its superblock records it and as macOS shows it.
///
/// UTF-8, stored as given without normalization, from one byte to
/// [`MAX_BYTES`](Self::MAX_BYTES), with no NUL in it: the field is 256 bytes and ends in its
/// terminator.
///
/// ```
/// # use ferrosys::apfs::VolumeName;
/// assert_eq!(VolumeName::new("Data")?.as_str(), "Data");
/// assert!(VolumeName::new("").is_err());
/// assert!(VolumeName::new(&"n".repeat(VolumeName::MAX_BYTES + 1)).is_err());
/// # Ok::<(), ferrosys::apfs::NameError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VolumeName(String);

impl VolumeName {
    /// The most bytes a volume's name may have.
    pub const MAX_BYTES: usize = VOLUME_NAME_LEN - 1;

    /// A volume name of `name`.
    ///
    /// # Errors
    ///
    /// [`NameError`] for an empty name, one longer than [`MAX_BYTES`](Self::MAX_BYTES), or one
    /// holding a NUL.
    pub fn new(name: &str) -> Result<Self, NameError> {
        checked_name(name.as_bytes(), Self::MAX_BYTES)?;
        Ok(Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A snapshot of a volume taken as it is formatted, which the volume records as the one it roots
/// from.
///
/// The snapshot keeps the volume's whole tree as the format writes it. It is recorded in the
/// transaction that writes the volume, stamped with the format's instant, under this name and
/// identifier, with the records, the superblock copy, the identifier's object and the object
/// map's snapshot tree that macOS writes when it takes a snapshot. The volume's
/// extent-reference tree goes with it, as it does when macOS takes one, and the volume starts an
/// empty tree of its own. The volume superblock's root-to transaction, at 968, names the
/// snapshot's transaction.
///
/// The name is UTF-8, stored as given without normalization, from one byte to
/// [`MAX_BYTES`](Self::MAX_BYTES), with no NUL in it.
///
/// ```
/// # use ferrosys::apfs::RootSnapshot;
/// let snapshot = RootSnapshot::new("root", [0x33; 16])?;
/// assert_eq!((snapshot.name(), snapshot.uuid()), ("root", [0x33; 16]));
/// assert!(RootSnapshot::new("", [0x33; 16]).is_err());
/// # Ok::<(), ferrosys::apfs::NameError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RootSnapshot {
    name: String,
    uuid: [u8; 16],
}

impl RootSnapshot {
    /// The most bytes a snapshot's name may have: the bound macOS holds a snapshot's name to.
    /// macOS 14, 15, 26 and 27 list and mount a snapshot named by 255 bytes, and `fsck_apfs`
    /// there finds the snapshot metadata tree invalid for a name of 256 bytes or more, ASCII or
    /// not; 255 two-byte characters, 510 bytes, are refused as well, so the bound is bytes
    /// rather than characters (observed).
    pub const MAX_BYTES: usize = 255;

    /// A snapshot named `name` and identified by `uuid`.
    ///
    /// # Errors
    ///
    /// [`NameError`] for an empty name, one longer than [`MAX_BYTES`](Self::MAX_BYTES), or one
    /// holding a NUL.
    pub fn new(name: &str, uuid: [u8; 16]) -> Result<Self, NameError> {
        checked_name(name.as_bytes(), Self::MAX_BYTES)?;
        Ok(Self {
            name: name.to_owned(),
            uuid,
        })
    }

    /// The name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The identifier: nonzero, and apart from the container's, every volume's and every other
    /// snapshot's.
    #[must_use]
    pub const fn uuid(&self) -> [u8; 16] {
        self.uuid
    }
}

/// The name a volume records for the program that formatted it.
///
/// Bytes, from one to [`MAX_BYTES`](Self::MAX_BYTES), with no NUL in them: the field is 32
/// bytes and a reader stops at the first NUL. [`THIS_CRATE`](Self::THIS_CRATE), the default,
/// names this crate and its version.
///
/// ```
/// # use ferrosys::apfs::ProgramName;
/// assert!(ProgramName::THIS_CRATE.as_bytes().starts_with(b"ferrosys ("));
/// assert_eq!(ProgramName::new(b"mkimage (1.0)")?.as_bytes(), b"mkimage (1.0)");
/// assert!(ProgramName::new(&[b'p'; ProgramName::MAX_BYTES + 1]).is_err());
/// # Ok::<(), ferrosys::apfs::NameError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProgramName([u8; PROGRAM_NAME_FIELD]);

/// The bytes the field naming a volume's formatter takes.
const PROGRAM_NAME_FIELD: usize = 32;

impl ProgramName {
    /// The most bytes the name may have.
    pub const MAX_BYTES: usize = PROGRAM_NAME_FIELD - 1;

    /// This crate's name and version, as `ferrosys (0.7.0)`.
    pub const THIS_CRATE: Self = {
        let text = concat!("ferrosys (", env!("CARGO_PKG_VERSION"), ")").as_bytes();
        assert!(
            text.len() <= Self::MAX_BYTES,
            "the crate's name fits the field"
        );
        let mut field = [0u8; PROGRAM_NAME_FIELD];
        let mut i = 0;
        while i < text.len() {
            field[i] = text[i];
            i += 1;
        }
        Self(field)
    };

    /// A program name of `name`.
    ///
    /// # Errors
    ///
    /// [`NameError`] for an empty name, one longer than [`MAX_BYTES`](Self::MAX_BYTES), or one
    /// holding a NUL.
    pub fn new(name: &[u8]) -> Result<Self, NameError> {
        checked_name(name, Self::MAX_BYTES)?;
        let mut field = [0u8; PROGRAM_NAME_FIELD];
        field[..name.len()].copy_from_slice(name);
        Ok(Self(field))
    }

    /// The name, without the padding after it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let end = self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len());
        &self.0[..end]
    }
}

impl Default for ProgramName {
    fn default() -> Self {
        Self::THIS_CRATE
    }
}

/// One volume of a container to be formatted.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct VolumeRequest {
    /// The volume's name.
    pub name: VolumeName,
    /// The volume's identifier: nonzero, and apart from the container's and every other
    /// volume's.
    pub uuid: [u8; 16],
    /// How the volume compares names.
    pub names: NameKind,
    /// The owner the root directory records, where the volume's contents give no entry for `/`;
    /// one they give carries its own.
    pub root_owner: u32,
    /// The group the root directory records, where the volume's contents give no entry for `/`;
    /// one they give carries its own.
    pub root_group: u32,
    /// The snapshot the volume is formatted with and roots from, where it has one.
    pub root_snapshot: Option<RootSnapshot>,
    /// What the volume holds, where it is not the first: [`None`] for a volume holding nothing
    /// but its root and private directories. The first volume holds the format's source.
    pub contents: Option<Vec<SourceEntry>>,
    /// The firmlinks of a volume group's System volume, where it has them.
    pub firmlinks: Option<Firmlinks>,
}

impl VolumeRequest {
    /// A volume named `name` and identified by `uuid`, comparing names with case folded, its
    /// root directory owned by user and group 0, with no snapshot.
    #[must_use]
    pub const fn new(name: VolumeName, uuid: [u8; 16]) -> Self {
        Self {
            name,
            uuid,
            names: NameKind::CaseFolding,
            root_owner: 0,
            root_group: 0,
            root_snapshot: None,
            contents: None,
            firmlinks: None,
        }
    }

    /// The volume with `snapshot` taken as it is formatted, and recorded as the one it roots
    /// from.
    #[must_use]
    pub fn root_snapshot(mut self, snapshot: RootSnapshot) -> Self {
        self.root_snapshot = Some(snapshot);
        self
    }

    /// The volume holding what `source` states, as the first volume holds the format's source.
    /// Given to the first volume, the format refuses it.
    #[must_use]
    pub fn contents(mut self, source: impl Source) -> Self {
        self.contents = Some(source.into_entries());
        self
    }

    /// The volume with `links` marked among its directories: each directory a line names gets
    /// [`FIRMLINK_FLAG`](super::FIRMLINK_FLAG) beside its own flags and the attribute
    /// [`FIRMLINK_XATTR`](super::FIRMLINK_XATTR) holding the line's target and a NUL. A line
    /// names a directory as the volume compares names, so `/users` names `/Users` on a volume
    /// that folds case; a line naming nothing the volume holds marks nothing. Only a volume
    /// group's System volume may be given them.
    #[must_use]
    pub fn firmlinks(mut self, links: Firmlinks) -> Self {
        self.firmlinks = Some(links);
        self
    }

    /// The volume with names compared as `names` says.
    #[must_use]
    pub const fn names(mut self, names: NameKind) -> Self {
        self.names = names;
        self
    }

    /// The volume with its root directory owned by `owner` and `group`, where its contents give
    /// no entry for `/`, whose own ownership is what the root records.
    #[must_use]
    pub const fn root_owned_by(mut self, owner: u32, group: u32) -> Self {
        self.root_owner = owner;
        self.root_group = group;
        self
    }
}

/// A System volume and a Data volume of one container, joined as a volume group.
///
/// macOS boots from a group: the System volume holds the operating system and is mounted
/// read-only, and the Data volume holds what changes. Each records its role, the System
/// volume 0x1 and the Data volume 0x40, and both record the Data volume's identifier as the
/// group's, and a compatible feature bit, 0x10, beside the one every volume records. The System
/// volume numbers the objects of its tree from 0x0FFF_FFFF_0000_0010, so that no inode of it
/// shares a number with one of the Data volume's; its root and private directories keep 2 and
/// 3. The container itself records nothing of the group.
///
/// The slots are any two. `diskutil` makes a group with the Data volume first, and a Mac's own
/// boot disk has the System volume first.
///
/// ```
/// # use ferrosys::apfs::{FormatOptions, VolumeGroup, VolumeName, VolumeRequest};
/// # use ferrosys::Timestamp;
/// let system = VolumeRequest::new(VolumeName::new("System")?, [0x22; 16]);
/// let data = VolumeRequest::new(VolumeName::new("Data")?, [0x33; 16]);
/// let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(0), system)
///     .volume(data)
///     .volume_group(VolumeGroup::new(0, 1));
/// assert_eq!(options.volume_group, Some(VolumeGroup::new(0, 1)));
/// # Ok::<(), ferrosys::apfs::NameError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct VolumeGroup {
    /// The System volume's slot.
    pub system: u32,
    /// The Data volume's slot.
    pub data: u32,
}

impl VolumeGroup {
    /// A group of the System volume in slot `system` and the Data volume in slot `data`.
    #[must_use]
    pub const fn new(system: u32, data: u32) -> Self {
        Self { system, data }
    }
}

/// What a container is formatted with, besides its size.
///
/// Build one with [`new`](Self::new), which takes the container's identifier, the instant every
/// time in it records, and its first volume, then set what departs from the defaults.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The container's identifier: nonzero, and apart from every volume's.
    pub uuid: [u8; 16],
    /// The instant every time the container records is: when each volume was formatted and
    /// last changed, and when each directory was created, changed, read and added.
    ///
    /// At or after 1970, and before the year 2262, the last instant a time in nanoseconds
    /// since 1970 holds. `fsck_apfs -W` holds a volume superblock's two times to the clock of
    /// the machine checking it: a time later than that clock draws a warning for when the
    /// volume was formatted, and for when it was last changed until a mount changes it. Every
    /// other check of macOS 15, 26 and 27 passes such a container.
    pub time: Timestamp,
    /// The size of every block. 4 KiB by default.
    pub block_size: BlockSize,
    /// The release whose shape the container is written in.
    pub profile: ReleaseProfile,
    /// The program every volume records as having formatted it.
    pub formatted_by: ProgramName,
    /// The volumes, in slot order: at least one, and no more than the container has slots for.
    pub volumes: Vec<VolumeRequest>,
    /// The volume group two of the volumes form, where they form one.
    pub volume_group: Option<VolumeGroup>,
}

impl FormatOptions {
    /// Options for a container identified by `uuid`, stamped `time`, holding `volume`, at
    /// every default.
    #[must_use]
    pub fn new(uuid: [u8; 16], time: Timestamp, volume: VolumeRequest) -> Self {
        Self {
            uuid,
            time,
            block_size: BlockSize::K4,
            profile: ReleaseProfile::Macos26,
            formatted_by: ProgramName::THIS_CRATE,
            volumes: vec![volume],
            volume_group: None,
        }
    }

    /// These options with the block size replaced.
    #[must_use]
    pub const fn block_size(mut self, size: BlockSize) -> Self {
        self.block_size = size;
        self
    }

    /// These options with the release profile replaced.
    #[must_use]
    pub const fn profile(mut self, profile: ReleaseProfile) -> Self {
        self.profile = profile;
        self
    }

    /// These options with the program the volumes record replaced.
    #[must_use]
    pub const fn formatted_by(mut self, name: ProgramName) -> Self {
        self.formatted_by = name;
        self
    }

    /// These options with one more volume, in the next slot.
    #[must_use]
    pub fn volume(mut self, volume: VolumeRequest) -> Self {
        self.volumes.push(volume);
        self
    }

    /// These options with two of the volumes joined as `group`.
    #[must_use]
    pub const fn volume_group(mut self, group: VolumeGroup) -> Self {
        self.volume_group = Some(group);
        self
    }
}

/// Which identifier a [`FormatError`] is about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Identifier {
    /// The container's.
    Container,
    /// The volume's in this slot.
    Volume(u32),
    /// The root snapshot's of the volume in this slot.
    Snapshot(u32),
}

/// What the identifier belongs to, as a message names it: `the container`, `the volume in slot
/// 1`, or `the root snapshot of the volume in slot 1`.
impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Container => f.write_str("the container"),
            Self::Volume(slot) => write!(f, "the volume in slot {slot}"),
            Self::Snapshot(slot) => write!(f, "the root snapshot of the volume in slot {slot}"),
        }
    }
}

/// A failure formatting a container.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// Writing to the destination failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The geometry cannot be realized.
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    /// The source states something a volume cannot hold.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// An identifier is zero, which `fsck_apfs` refuses.
    #[error("the identifier of {which} is zero")]
    #[non_exhaustive]
    ZeroIdentifier {
        /// Which one.
        which: Identifier,
    },
    /// Two identifiers are the same.
    #[error("{first} and {second} have the same identifier")]
    #[non_exhaustive]
    RepeatedIdentifier {
        /// The first that carries it.
        first: Identifier,
        /// The one after it that carries it too.
        second: Identifier,
    },
    /// A volume group names a slot that holds no volume.
    #[error("the volume group names slot {slot}, which holds no volume")]
    #[non_exhaustive]
    GroupSlot {
        /// The slot.
        slot: u32,
    },
    /// A volume group names one slot for both its volumes.
    #[error("the volume group names slot {slot} for both its System and its Data volume")]
    #[non_exhaustive]
    GroupOneSlot {
        /// The slot.
        slot: u32,
    },
    /// The first volume's request gives it contents, where the format's source is its contents.
    #[error("the first volume holds the format's source, and its request gives it contents too")]
    ContentsOnFirstVolume,
    /// A volume that is not a volume group's System volume is given firmlinks.
    #[error(
        "the volume in slot {slot} is given firmlinks and is not a volume group's System volume"
    )]
    #[non_exhaustive]
    FirmlinksOutsideGroup {
        /// The volume's slot.
        slot: u32,
    },
    /// A firmlink names an entry that is not a directory.
    #[error(
        "the firmlink {} names an entry that is not a directory",
        String::from_utf8_lossy(path)
    )]
    #[non_exhaustive]
    FirmlinkNotDirectory {
        /// The directory as the list gives it.
        path: Vec<u8>,
    },
    /// A firmlink names a directory whose source gives the firmlink attribute another value.
    #[error(
        "the firmlink {} names a directory already holding the firmlink attribute with another value",
        String::from_utf8_lossy(path)
    )]
    #[non_exhaustive]
    FirmlinkAttributeHeld {
        /// The directory as the list gives it.
        path: Vec<u8>,
    },
    /// The time is before 1970, past what a time in nanoseconds since 1970 holds, or has a
    /// fraction of a second of a second or more.
    #[error(
        "{} seconds and {} nanoseconds since 1970 is outside the times a container records",
        time.secs,
        time.nanos
    )]
    #[non_exhaustive]
    TimeOutOfRange {
        /// The time given.
        time: Timestamp,
    },
    /// The share of the container [`FormatPlan::fit`] was asked to leave free is past the
    /// largest it searches for.
    #[error("slack of {hundredths} hundredths of a percent is past the limit of {limit}")]
    #[non_exhaustive]
    SlackShareTooLarge {
        /// The share asked for, in hundredths of one percent.
        hundredths: u16,
        /// The largest share a search will look for.
        limit: u16,
    },
    /// No container up to [`MAX_CONTAINER_BYTES`](super::MAX_CONTAINER_BYTES) holds the source
    /// with the room [`FormatPlan::fit`] was asked to leave.
    #[error("no container up to {ceiling} bytes holds the source with the room asked for")]
    #[non_exhaustive]
    DoesNotFit {
        /// The largest container the search could have tried, in bytes.
        ceiling: u64,
    },
    /// The image is larger than this machine can hold in memory.
    ///
    /// Reached only by [`format()`], which collects the whole image. [`format_to`] writes only
    /// the blocks the container occupies and has no such limit.
    #[error("an image of {bytes} bytes cannot be held in memory on this machine")]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// The size asked for, in bytes.
        bytes: u64,
    },
}

// ---------------------------------------------------------------------------
// The entry points

/// A finished container image: the bytes, and the layout they realize.
pub struct Image {
    bytes: Vec<u8>,
    layout: ApfsLayout,
    fidelity: FidelityReport,
}

impl Image {
    /// The image bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the image, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The layout the image was written against.
    #[must_use]
    pub const fn layout(&self) -> &ApfsLayout {
        &self.layout
    }

    /// What the source offered that the volume does not hold: nothing, since a volume holds
    /// every property a source states.
    #[must_use]
    pub const fn fidelity(&self) -> &FidelityReport {
        &self.fidelity
    }

    /// Write the image to `w`.
    ///
    /// # Errors
    ///
    /// Any I/O error from `w`.
    pub fn write_to(&self, mut w: impl Write) -> std::io::Result<()> {
        w.write_all(&self.bytes)
    }
}

/// A format decided but not yet performed: the options checked, the source modelled and the
/// layout planned.
///
/// Everything a format can fail on but I/O has happened by the time one of these exists, so a
/// caller can find out what a container will be before opening a destination.
/// [`write_to`](Self::write_to) is the half that can only fail on I/O.
///
/// ```no_run
/// use ferrosys::apfs::{FormatOptions, FormatPlan, VolumeName, VolumeRequest};
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// let volume = VolumeRequest::new(VolumeName::new("Data")?, [0x22; 16]);
/// let options = FormatOptions::new([0x11; 16], time, volume);
/// let source = TreeBuilder::new().file("/hello", "hello\n", Metadata::new(0o644, time));
/// let plan = FormatPlan::new(source, 1 << 30, options)?;
///
/// // Where everything will be, before the destination is touched.
/// println!("volume superblock at block {}", plan.layout().newest().volumes[0].superblock);
///
/// plan.write_to(std::fs::File::create("container.img")?)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct FormatPlan {
    layout: ApfsLayout,
    container_bytes: u64,
    options: FormatOptions,
    models: Vec<ApfsModel>,
    volumes: Vec<PreparedVolume>,
    firmlinked: usize,
}

impl FormatPlan {
    /// Plan a container of `container_bytes` formatted with `options`, its first volume holding
    /// what `source` states and every other volume what its request's
    /// [`contents`](VolumeRequest::contents) state, or nothing.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the geometry cannot be realized or the container is too small for
    /// what the source holds, the source states something a volume cannot hold, an identifier
    /// is zero or repeated, the time is outside the ones a container records, a volume group
    /// names a slot that holds no volume or one slot twice, the first volume's request gives it
    /// contents, or a volume's firmlinks are given to anything but a group's System volume or
    /// name an entry that cannot be one.
    pub fn new(
        source: impl Source,
        container_bytes: u64,
        options: FormatOptions,
    ) -> Result<Self, FormatError> {
        Self::planned(source, container_bytes, options, |_| {})
    }

    /// A smallest container that holds `source` with the room `slack` asks for, formatted with
    /// `options` and planned ready to write: one block smaller does not hold it, and where a
    /// larger container keeps another volume slot, a smaller size past that step may.
    ///
    /// The size is searched for rather than computed. A container's checkpoint areas, its
    /// space manager and its internal pool all follow from its size, so a candidate is planned
    /// and the volumes' content placed into it, and what the space manager would then record
    /// free judges the candidate. The answer is a size that planned and placed, with the block
    /// below it proven not to.
    ///
    /// [`Slack`] is room macOS lets a process of any user write, in what
    /// [`ApfsLayout::writable_blocks`](super::ApfsLayout::writable_blocks) counts: a container
    /// fitted with a slack of 8 MiB takes 8 MiB written a mebibyte or less at a time, however
    /// its files grow, and each file's records take room beside its data, about a block for
    /// every sixteen files. [`Slack::None`] asks for no room, and gives a smallest container,
    /// one macOS mounts and may refuse every change to: the shape of an image that is only read.
    ///
    /// The source is modelled once and each candidate places that model, so no file is read
    /// during the search. [`container_bytes`](Self::container_bytes) is a whole number of
    /// blocks.
    ///
    /// # Errors
    ///
    /// [`FormatError::SlackShareTooLarge`] for a share past the limit,
    /// [`FormatError::DoesNotFit`] when the container of
    /// [`MAX_CONTAINER_BYTES`](super::MAX_CONTAINER_BYTES) holds the source and leaves less
    /// than the room asked for, [`FormatError::Geometry`] with what that container met where
    /// it does not hold the source at all ([`GeometryError::ContainerFull`]), and otherwise what
    /// [`new`](Self::new) refuses that no size changes.
    pub fn fit(
        source: impl Source,
        options: FormatOptions,
        slack: Slack,
    ) -> Result<Self, FormatError> {
        let time = checked_time(&options)?;
        let (models, firmlinked) = model_volumes(source, &options)?;
        let fitted = super::fit::search(&models, &options, time, slack)?;
        Ok(Self {
            layout: fitted.layout,
            container_bytes: fitted.container_bytes,
            options,
            models,
            volumes: fitted.volumes,
            firmlinked,
        })
    }

    /// As [`new`](Self::new), with `shape` given the planner before anything is placed.
    fn planned(
        source: impl Source,
        container_bytes: u64,
        options: FormatOptions,
        shape: impl FnOnce(&mut ContentPlanner),
    ) -> Result<Self, FormatError> {
        let time = checked_time(&options)?;
        let mut planner = ContentPlanner::new(&plan_request(&options, container_bytes))?;
        shape(&mut planner);
        let (models, firmlinked) = model_volumes(source, &options)?;
        let volumes = place_volumes(&models, &options, time, &mut planner)?;
        Ok(Self {
            layout: planner.finish(),
            container_bytes,
            options,
            models,
            volumes,
            firmlinked,
        })
    }

    /// The layout the bytes will realize: the same value the write uses.
    #[must_use]
    pub const fn layout(&self) -> &ApfsLayout {
        &self.layout
    }

    /// Bytes the destination will hold: the size the format was asked for. The container
    /// occupies the whole blocks of it.
    #[must_use]
    pub const fn container_bytes(&self) -> u64 {
        self.container_bytes
    }

    /// How many directories the volume group's System volume holds as firmlinks: those its
    /// [`Firmlinks`] name that its contents hold. Zero where no volume is given any.
    #[must_use]
    pub const fn firmlinked(&self) -> usize {
        self.firmlinked
    }

    /// What the source offered that the volume does not hold: nothing, since a volume holds
    /// every property a source states. It answers rather than being absent so that a caller
    /// writing one build step against several families asks each the same question.
    #[must_use]
    pub fn fidelity(&self) -> &FidelityReport {
        &self.models[0].fidelity
    }

    /// Write the planned container to `sink`.
    ///
    /// Only the blocks the container occupies are written and nothing is read back, so a file
    /// destination stays sparse. The sink is extended to
    /// [`container_bytes`](Self::container_bytes), and every byte of it that is not written
    /// must read back as zero: a freshly created file, or one truncated to zero length, does.
    /// Two writes of one plan are the same bytes, unless a file a
    /// [`FileRange`](crate::FileRange) names changed in between.
    ///
    /// # Errors
    ///
    /// [`FormatError::Io`] if writing to `sink` fails, or if a file the source named by range
    /// cannot be read.
    pub fn write_to(&self, sink: impl Write + Seek) -> Result<(), FormatError> {
        let blocks = assemble(&self.layout, &self.options, &self.models, &self.volumes);
        let block_size = u64::from(self.layout.block_size);
        let mut sink = ByteSink::new(sink);
        for (block, bytes) in &blocks {
            sink.write_at(block * block_size, bytes)?;
        }
        for (model, volume) in self.models.iter().zip(&self.volumes) {
            write_streams(&mut sink, model, volume, block_size)?;
        }
        sink.extend_to(self.container_bytes)?;
        Ok(())
    }
}

/// Format an APFS container of `container_bytes`, its first volume populated from `source` and
/// every other one from its request's [`contents`](VolumeRequest::contents), collecting it into
/// memory.
///
/// ```
/// use ferrosys::apfs::{
///     Container, FormatOptions, NameKind, Reader, VolumeName, VolumeRequest, format,
/// };
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// let volume = VolumeRequest::new(VolumeName::new("ramdisk")?, [0x22; 16])
///     .names(NameKind::CaseKeeping);
/// let options = FormatOptions::new([0x11; 16], time, volume);
/// let source = TreeBuilder::new()
///     .directory("/etc", Metadata::new(0o755, time))
///     .file("/etc/hostname", "ferrosys\n", Metadata::new(0o644, time));
/// let image = format(source.clone(), 64 << 20, options.clone())?;
///
/// // Read back with this crate's own reader: the volume, by its name, and the file in it.
/// let container = Container::open(std::io::Cursor::new(image.as_bytes()))?;
/// assert_eq!(container.volumes()[0].name(), b"ramdisk");
/// let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
/// let node = reader.lookup(b"/etc/hostname")?;
/// assert_eq!(reader.read_data(&node)?, b"ferrosys\n");
/// assert!(reader.scan().anomalies().is_empty());
///
/// // Two formats of the same source and options are the same bytes.
/// assert_eq!(image.as_bytes(), format(source, 64 << 20, options)?.as_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized or holds too little, the source states
/// something a volume cannot hold, an identifier is zero or repeated, the time is outside the
/// ones a container records, the volume group, contents or firmlinks are given as
/// [`FormatPlan::new`] refuses, a file the source named by range cannot be read, or the image will
/// not fit in memory.
pub fn format(
    source: impl Source,
    container_bytes: u64,
    options: FormatOptions,
) -> Result<Image, FormatError> {
    // Planned before the buffer is allocated, so a container that cannot be formatted fails
    // without first asking for its size in memory.
    let plan = FormatPlan::new(source, container_bytes, options)?;
    let size =
        usize::try_from(container_bytes).map_err(|_| FormatError::ImageTooLargeInMemory {
            bytes: container_bytes,
        })?;
    let mut image = Cursor::new(vec![0u8; size]);
    plan.write_to(&mut image)?;
    let fidelity = plan.fidelity().clone();
    Ok(Image {
        bytes: image.into_inner(),
        layout: plan.layout,
        fidelity,
    })
}

/// Format an APFS container of `container_bytes` into `sink`, its first volume populated from
/// `source` and every other one from its request's [`contents`](VolumeRequest::contents),
/// returning the layout it realizes.
///
/// Only the blocks the container occupies are written and nothing is read back, so a file
/// destination stays sparse and the image never exists in memory: what this costs in memory is
/// the source's entry records, the records of every tree built from them, and one window of a
/// file's bytes. The sink is extended to `container_bytes`, and every byte of it that is not
/// written must read back as zero, as a freshly created file's do.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized or holds too little, the source states
/// something a volume cannot hold, an identifier is zero or repeated, the time is outside the
/// ones a container records, the volume group, contents or firmlinks are given as
/// [`FormatPlan::new`] refuses, a file the source named by range cannot be read, or writing to
/// `sink` fails.
pub fn format_to<W: Write + Seek>(
    sink: W,
    source: impl Source,
    container_bytes: u64,
    options: FormatOptions,
) -> Result<ApfsLayout, FormatError> {
    let plan = FormatPlan::new(source, container_bytes, options)?;
    plan.write_to(sink)?;
    Ok(plan.layout)
}

/// Where one volume's content goes in a container of one size, decided when the plan is made:
/// the blocks of each of its streams, its records, and the place of every node of its three
/// trees that has content.
pub(super) struct PreparedVolume {
    runs: HashMap<u64, Vec<BlockRange>>,
    records: VolumeRecords,
    fs: Built,
    extents: Built,
    map: Built,
    snapshot: Option<SnapshotPlace>,
}

/// A tree's records, how they divide among its nodes, and where each node goes: the leaves
/// first, then each level above, the root last.
struct Built {
    records: Vec<Record>,
    shape: Shape,
    places: Vec<Placed>,
}

impl Built {
    /// The tree's nodes past its root.
    fn extra_nodes(&self) -> u64 {
        self.places.len() as u64 - 1
    }
}

/// The file-system tree's flags, entries inserted in order and keys and values unaligned, on
/// every file-system tree's root macOS wrote.
const FS_TREE: TreeKind = TreeKind {
    subtype: kind::FS_TREE,
    storage: Storage::Virtual,
    tree_flags: ROOT_TREE_FLAGS,
    entries: Entries::Variable,
};

/// The extent-reference tree's.
const EXTENT_REF_TREE: TreeKind = TreeKind {
    subtype: kind::EXTENT_REF_TREE,
    storage: Storage::Physical,
    tree_flags: PHYSICAL_TREE_FLAGS,
    entries: Entries::Variable,
};

/// A volume's snapshot tree's.
const SNAPSHOT_TREE: TreeKind = TreeKind {
    subtype: kind::SNAPSHOT_TREE,
    storage: Storage::Physical,
    tree_flags: PHYSICAL_TREE_FLAGS,
    entries: Entries::Variable,
};

/// An object map's tree of the snapshots it keeps versions for: each snapshot's transaction,
/// and a value of zero.
const MAP_SNAPSHOT_TREE: TreeKind = TreeKind {
    subtype: kind::OBJECT_MAP_SNAPSHOT,
    storage: Storage::Physical,
    tree_flags: MAP_SNAPSHOT_TREE_FLAGS,
    entries: Entries::Fixed {
        key: MAP_SNAPSHOT_KEY,
        value: MAP_SNAPSHOT_VALUE,
    },
};

/// The bytes of a key of an object map's tree of snapshots: the transaction.
const MAP_SNAPSHOT_KEY: usize = 8;
/// The bytes of a value of it.
const MAP_SNAPSHOT_VALUE: usize = 16;

/// An object map's tree, given its flags.
const fn map_tree(tree_flags: u32) -> TreeKind {
    TreeKind {
        subtype: kind::OBJECT_MAP,
        storage: Storage::Physical,
        tree_flags,
        entries: Entries::Fixed {
            key: MapKey::SIZE,
            value: MapValue::SIZE,
        },
    }
}

/// The blocks a plan gives, as runs: what [`ContentPlanner::take`] answers.
type Take<'a> = dyn FnMut(u64) -> Result<Vec<BlockRange>, GeometryError> + 'a;

/// The identifiers checked, and the instant every time the container records is, in
/// nanoseconds since 1970.
pub(super) fn checked_time(options: &FormatOptions) -> Result<i64, FormatError> {
    check_identifiers(options)?;
    check_volumes(options)?;
    Ok(i64::try_from(nanos_since_epoch(options.time)?)
        .expect("a time since 1970 in nanoseconds fits 63 bits"))
}

/// The plan of a container of `container_bytes` formatted with `options`.
pub(super) fn plan_request(options: &FormatOptions, container_bytes: u64) -> PlanRequest {
    PlanRequest::new(container_bytes)
        .block_size(options.block_size)
        .volumes(u32::try_from(options.volumes.len()).unwrap_or(u32::MAX))
}

/// Model every volume `options` asks for: the first holding what `source` states, every other
/// one what its request's contents state, or nothing, each with its firmlinks marked; and how
/// many directories those mark. Nothing here depends on the container's size.
pub(super) fn model_volumes(
    source: impl Source,
    options: &FormatOptions,
) -> Result<(Vec<ApfsModel>, usize), FormatError> {
    let mut source = Some(source.into_entries());
    let mut firmlinked = 0;
    let models = (0u32..)
        .zip(&options.volumes)
        .map(|(slot, request)| {
            let root =
                Metadata::new(0o755, options.time).owned_by(request.root_owner, request.root_group);
            let mut entries = source
                .take()
                .or_else(|| request.contents.clone())
                .unwrap_or_default();
            if let Some(links) = &request.firmlinks {
                firmlinked += firmlink::mark(&mut entries, links, request.names.folds())?;
            }
            Ok(build_model(
                entries,
                request.names.folds(),
                options.profile.unicode(),
                root,
                member(options, slot).map_or(inode_number::FIRST_USER, Member::first_id),
            )?)
        })
        .collect::<Result<_, FormatError>>()?;
    Ok((models, firmlinked))
}

/// Place every volume `models` holds in the container `planner` plans, in slot order.
pub(super) fn place_volumes(
    models: &[ApfsModel],
    options: &FormatOptions,
    time: i64,
    planner: &mut ContentPlanner,
) -> Result<Vec<PreparedVolume>, FormatError> {
    let mut next_oid = next_oid(models.len() as u64);
    let block_size = planner.block_size();
    let mut contents = Vec::with_capacity(models.len());
    for (slot, (model, request)) in (0u64..).zip(models.iter().zip(&options.volumes)) {
        let place = planner.volume_place(slot);
        contents.push(place_content(
            model,
            request,
            (slot, place),
            block_size,
            time,
            &mut |blocks| planner.take(blocks),
            &mut next_oid,
        )?);
    }
    // A root snapshot's extension object takes the container's next identifier once every
    // volume's nodes have theirs, as macOS gives one when it takes a snapshot of a volume
    // already written. Each object map is placed after, since it maps that object.
    for snapshot in contents.iter_mut().filter_map(|c| c.snapshot.as_mut()) {
        snapshot.extension.oid = next_oid;
        next_oid += 1;
    }
    (0u64..)
        .zip(contents)
        .map(|(slot, content)| {
            place_map(
                content,
                planner.volume_place(slot),
                block_size,
                &mut |blocks| planner.take(blocks),
            )
        })
        .collect()
}

/// What a volume holds placed, its object map aside: what [`place_content`] gives and
/// [`place_map`] completes.
struct Content {
    runs: HashMap<u64, Vec<BlockRange>>,
    records: VolumeRecords,
    fs: Built,
    extents: Built,
    snapshot: Option<SnapshotPlace>,
}

/// Where a volume's root snapshot puts what it adds to the volume.
struct SnapshotPlace {
    /// The volume's own extent-reference tree from the snapshot on, empty: the tree the volume
    /// was written with is the snapshot's.
    references: Built,
    /// The block of the snapshot's copy of the volume superblock.
    copy: u64,
    /// The object map's tree of the snapshots it keeps versions for.
    map_snapshots: Built,
    /// The snapshot extension object: its identifier, given once every volume is placed, and
    /// its block.
    extension: Placed,
}

/// Place the content of the volume in `slot`, at `place`, holding `model`: give each of its
/// streams blocks from `take`, build its records, give every node of its trees past the roots a
/// block from `take` and each node of its file-system tree past the root the next of
/// `next_oid`, and give what its root snapshot adds a block each from `take`.
fn place_content(
    model: &ApfsModel,
    request: &VolumeRequest,
    (slot, place): (u64, VolumePlace),
    block_size: u32,
    time: i64,
    take: &mut Take<'_>,
    next_oid: &mut u64,
) -> Result<Content, FormatError> {
    let fold = request.names.folds();
    let bs = u64::from(block_size);
    let size = to_index(bs);

    let mut runs = HashMap::new();
    for stream in &model.streams {
        runs.insert(stream.id, take(stream.len.div_ceil(bs))?);
    }
    let records = volume_records(model, &runs, block_size, fold, time);

    // The file-system tree: the root where the plan puts it, under the volume's identifier for
    // it, and every other node at the next block and the next identifier.
    let fs_records = records.sorted();
    let shape = bulk::shape(&fs_records, size, Entries::Variable);
    let mut places: Vec<Placed> = blocks_of(&take(shape.node_count() as u64 - 1)?)
        .map(|block| {
            let oid = *next_oid;
            *next_oid += 1;
            Placed { oid, block }
        })
        .collect();
    places.push(Placed {
        oid: volume_oids(slot).1,
        block: place.root_tree,
    });
    let fs = Built {
        records: fs_records,
        shape,
        places,
    };

    let extents = physical_tree(
        records.extents.clone(),
        Entries::Variable,
        place.extent_ref_tree,
        size,
        take,
    )?;

    // What a root snapshot adds, in the order macOS writes it when it takes one: the copy of
    // the superblock, the volume's new extent-reference tree, the object map's tree of
    // snapshots, and the extension object. In the snapshot's transaction macOS 15, 26 and 27
    // write, in rising block order, the copy, the snapshot metadata tree, the new
    // extent-reference tree, the object map, the map's tree of snapshots and the extension
    // object, then the map's tree and the volume superblock (observed); the snapshot metadata
    // tree, the object map, its tree and the superblock are the volume's own here, placed with
    // the rest of it.
    let snapshot = match request.root_snapshot {
        Some(_) => {
            let mut block = || -> Result<u64, FormatError> {
                Ok(blocks_of(&take(1)?)
                    .next()
                    .expect("a block taken is a block"))
            };
            let copy = block()?;
            let references = block()?;
            let map_snapshots = block()?;
            let extension = block()?;
            Some(SnapshotPlace {
                references: physical_tree(Vec::new(), Entries::Variable, references, size, take)?,
                copy,
                map_snapshots: physical_tree(
                    vec![(
                        SECOND_XID.to_le_bytes().to_vec(),
                        vec![0; MAP_SNAPSHOT_VALUE],
                    )],
                    Entries::Fixed {
                        key: MAP_SNAPSHOT_KEY,
                        value: MAP_SNAPSHOT_VALUE,
                    },
                    map_snapshots,
                    size,
                    take,
                )?,
                extension: Placed {
                    oid: 0,
                    block: extension,
                },
            })
        }
        None => None,
    };
    Ok(Content {
        runs,
        records,
        fs,
        extents,
        snapshot,
    })
}

/// Complete a volume at `place` whose content is placed: its object map, mapping each
/// file-system node and the snapshot extension object by identifier at the second transaction,
/// every node past the root at the next block `take` gives.
fn place_map(
    content: Content,
    place: VolumePlace,
    block_size: u32,
    take: &mut Take<'_>,
) -> Result<PreparedVolume, FormatError> {
    let mut mappings: Vec<(u64, u64)> = content
        .fs
        .places
        .iter()
        .chain(content.snapshot.iter().map(|s| &s.extension))
        .map(|p| (p.oid, p.block))
        .collect();
    mappings.sort_unstable();
    let map = physical_tree(
        map_records(&mappings, SECOND_XID, block_size),
        Entries::Fixed {
            key: MapKey::SIZE,
            value: MapValue::SIZE,
        },
        place.object_map.root,
        to_index(u64::from(block_size)),
        take,
    )?;
    Ok(PreparedVolume {
        runs: content.runs,
        records: content.records,
        fs: content.fs,
        extents: content.extents,
        map,
        snapshot: content.snapshot,
    })
}

/// A physical tree of `records`, its root at block `root` and every other node at the next
/// block `take` gives.
fn physical_tree(
    records: Vec<Record>,
    entries: Entries,
    root: u64,
    size: usize,
    take: &mut Take<'_>,
) -> Result<Built, FormatError> {
    let shape = bulk::shape(&records, size, entries);
    let mut places: Vec<Placed> = blocks_of(&take(shape.node_count() as u64 - 1)?)
        .map(|block| Placed { oid: block, block })
        .collect();
    places.push(Placed {
        oid: root,
        block: root,
    });
    Ok(Built {
        records,
        shape,
        places,
    })
}

/// Every block of `runs`, in order.
fn blocks_of(runs: &[BlockRange]) -> impl Iterator<Item = u64> + '_ {
    runs.iter().flat_map(|run| run.start..run.start + run.count)
}

/// An object map's records, mapping each `(oid, block)` at transaction `xid`.
fn map_records(entries: &[(u64, u64)], xid: u64, block_size: u32) -> Vec<Record> {
    let mut records: Vec<(MapKey, MapValue)> = entries
        .iter()
        .map(|&(oid, block)| {
            (
                MapKey { oid, xid },
                MapValue {
                    flags: 0,
                    size: block_size,
                    address: block,
                },
            )
        })
        .collect();
    records.sort_by_key(|(key, _)| *key);
    records
        .into_iter()
        .map(|(key, value)| {
            let (mut k, mut v) = (vec![0u8; MapKey::SIZE], vec![0u8; MapValue::SIZE]);
            key.write_to(&mut k);
            value.write_to(&mut v);
            (k, v)
        })
        .collect()
}

/// Write each stream `model` holds into the blocks `volume` gives it: a file's bytes a window
/// at a time, an attribute's at once. The rest of a stream's last block is left as the sink holds it, zero.
fn write_streams<W: Write + Seek>(
    sink: &mut ByteSink<W>,
    model: &ApfsModel,
    volume: &PreparedVolume,
    block_size: u64,
) -> Result<(), FormatError> {
    for stream in &model.streams {
        let runs = &volume.runs[&stream.id];
        // Where in the container each byte of the stream goes: run by run, each run's bytes
        // following the last's.
        let mut put = |at: u64, bytes: &[u8]| -> Result<(), FormatError> {
            let mut at = at;
            let mut rest = bytes;
            let mut logical = 0;
            for run in runs {
                let len = run.count * block_size;
                if !rest.is_empty() && at < logical + len {
                    let within = at - logical;
                    let take = usize::try_from((len - within).min(rest.len() as u64))
                        .expect("a window fits memory");
                    sink.write_at(run.start * block_size + within, &rest[..take])?;
                    rest = &rest[take..];
                    at += take as u64;
                }
                logical += len;
            }
            Ok(())
        };
        match &stream.bytes {
            StreamBytes::File(content) => content.for_each_window(|at, bytes| put(at, bytes))?,
            StreamBytes::Held(bytes) => put(0, bytes)?,
        }
    }
    Ok(())
}

/// Every identifier nonzero and none repeated.
fn check_identifiers(options: &FormatOptions) -> Result<(), FormatError> {
    let mut seen: Vec<(Identifier, [u8; 16])> = vec![(Identifier::Container, options.uuid)];
    seen.extend(
        (0u32..)
            .zip(&options.volumes)
            .map(|(slot, volume)| (Identifier::Volume(slot), volume.uuid)),
    );
    seen.extend((0u32..).zip(&options.volumes).filter_map(|(slot, volume)| {
        let snapshot = volume.root_snapshot.as_ref()?;
        Some((Identifier::Snapshot(slot), snapshot.uuid))
    }));
    for (i, (which, uuid)) in seen.iter().enumerate() {
        if *uuid == [0; 16] {
            return Err(FormatError::ZeroIdentifier { which: *which });
        }
        if let Some((first, _)) = seen[..i].iter().find(|(_, earlier)| earlier == uuid) {
            return Err(FormatError::RepeatedIdentifier {
                first: *first,
                second: *which,
            });
        }
    }
    Ok(())
}

/// The volume group in range and of two slots, contents given to no first volume, and
/// firmlinks given to a group's System volume alone.
fn check_volumes(options: &FormatOptions) -> Result<(), FormatError> {
    if let Some(group) = options.volume_group {
        for slot in [group.system, group.data] {
            if slot as usize >= options.volumes.len() {
                return Err(FormatError::GroupSlot { slot });
            }
        }
        if group.system == group.data {
            return Err(FormatError::GroupOneSlot { slot: group.system });
        }
    }
    if options
        .volumes
        .first()
        .is_some_and(|first| first.contents.is_some())
    {
        return Err(FormatError::ContentsOnFirstVolume);
    }
    for (slot, request) in (0u32..).zip(&options.volumes) {
        if request.firmlinks.is_some() && member(options, slot) != Some(Member::System) {
            return Err(FormatError::FirmlinksOutsideGroup { slot });
        }
    }
    Ok(())
}

/// The part the volume in `slot` plays in the container's volume group, where it is in one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Member {
    System,
    Data,
}

impl Member {
    /// The role its superblock records.
    const fn role(self) -> u16 {
        match self {
            Self::System => 0x1,
            Self::Data => 0x40,
        }
    }

    /// The first identifier an object of its tree takes past the root and private
    /// directories: a System volume's are numbered from where none of the Data volume's are.
    const fn first_id(self) -> u64 {
        match self {
            Self::System => SYSTEM_FIRST_ID,
            Self::Data => inode_number::FIRST_USER,
        }
    }
}

/// The part the volume in `slot` plays in `options`'s volume group, if any.
fn member(options: &FormatOptions, slot: u32) -> Option<Member> {
    let group = options.volume_group?;
    if slot == group.system {
        Some(Member::System)
    } else if slot == group.data {
        Some(Member::Data)
    } else {
        None
    }
}

/// `time` in nanoseconds since 1970, as every time a container records holds it: held as an
/// inode's times are, and no earlier than 1970.
fn nanos_since_epoch(time: Timestamp) -> Result<u64, FormatError> {
    nanos_of(time)
        .and_then(|nanos| u64::try_from(nanos).ok())
        .ok_or(FormatError::TimeOutOfRange { time })
}

// ---------------------------------------------------------------------------
// The identifiers and values every container carries

/// The space manager's ephemeral identifier.
const SPACE_MANAGER_OID: u64 = 1024;
/// The reaper's.
const REAPER_OID: u64 = 1025;
/// The first volume's superblock's virtual identifier: the first the second transaction takes.
const FIRST_VOLUME_OID: u64 = 1026;
/// The internal pool's free queue's ephemeral identifier: taken after the first volume's.
const POOL_QUEUE_OID: u64 = 1027;
/// The first volume's file-system tree's virtual identifier.
const FIRST_ROOT_TREE_OID: u64 = 1028;
/// The main free queue's ephemeral identifier: the last the first volume's transaction takes.
const MAIN_QUEUE_OID: u64 = 1029;

/// The virtual identifiers of the superblock and the file-system tree of the volume in `slot`:
/// the first volume's are the ones `newfs_apfs` gives it, and each further volume takes the
/// next two after the main queue's.
const fn volume_oids(slot: u64) -> (u64, u64) {
    if slot == 0 {
        (FIRST_VOLUME_OID, FIRST_ROOT_TREE_OID)
    } else {
        let superblock = MAIN_QUEUE_OID + 1 + 2 * (slot - 1);
        (superblock, superblock + 1)
    }
}

/// The identifier a container's next virtual or ephemeral object would take, once it holds
/// `volumes` volumes: past the space manager and the reaper, then past the two free queues and
/// two identifiers per volume.
const fn next_oid(volumes: u64) -> u64 {
    if volumes == 0 {
        FIRST_VOLUME_OID
    } else {
        MAIN_QUEUE_OID + 1 + 2 * (volumes - 1)
    }
}

/// The container's incompatible features: the format's second version, the one bit every
/// container macOS writes carries.
const CONTAINER_INCOMPAT: u64 = container_incompat::VERSION2;

/// The low 32 bits of the container superblock's first ephemeral-information word, which every
/// container records as these two half-words; the high 32 bits are the ephemeral minimum.
const EPHEMERAL_INFO_LOW: u64 = (4 << 16) | 1;

/// The space manager's flags, as every container records them.
const SPACE_MANAGER_FLAGS: u32 = 1;

/// The reaper's flags, as every container records them on a reaper with nothing to reap.
const REAPER_FLAGS: u32 = 1;

/// The checkpoint-mapping block's flags, as every checkpoint records them on its one block of
/// mappings.
const MAPPING_BLOCK_FLAGS: u32 = 1;

/// The space manager structure's version, as every container records it, and `fsck_apfs`
/// requires.
const SPACE_MANAGER_VERSION: u32 = 1;

/// The flags a container's object map carries. A volume's carries none.
const CONTAINER_MAP_FLAGS: u32 = 1;

/// A volume's compatible features, as every volume records them.
const VOLUME_FEATURES: u64 = 2;

/// The compatible feature both volumes of a volume group record beside [`VOLUME_FEATURES`], on
/// every group macOS 15, 26 and 27 made.
const GROUP_FEATURE: u64 = 0x10;

/// The first identifier a volume group's System volume gives an object of its tree, on every
/// one macOS 15, 26 and 27 made, and the one it numbers each inode it makes there from.
const SYSTEM_FIRST_ID: u64 = 0x0FFF_FFFF_0000_0010;

/// The next document identifier a volume records, in every volume observed, written to or not.
const NEXT_DOCUMENT_ID: u32 = 3;

/// The flags of a file-system tree, as every one macOS writes records them.
const ROOT_TREE_FLAGS: u32 = 0x42;
/// The flags of an extent-reference tree and a snapshot tree.
const PHYSICAL_TREE_FLAGS: u32 = 0x52;
/// The flags of an object map's tree.
const MAP_TREE_FLAGS: u32 = 0x12;
/// The flags of an object map's tree of snapshots, on every one macOS 15, 26 and 27 wrote.
const MAP_SNAPSHOT_TREE_FLAGS: u32 = 0x10;
/// The flags of a free queue's tree.
const QUEUE_TREE_FLAGS: u32 = 0x0E;

/// A volume superblock's words past the fields [`VolumeSuperblock`] lays out, each as every
/// volume `newfs_apfs` and `hdiutil` wrote records it: at 1056 the superblock's own
/// transaction, which `fsck_apfs` holds below the container's next; at 1064 16, and 2 at 1068
/// and at 1104; and, in [`ReleaseProfile`]s that record them, the superblock's own transaction
/// at 1120 and 12 at 1128. No other byte past 1056 is set in any volume observed. A volume
/// group's System volume records 0 at 1064, as every one macOS made does.
fn write_volume_tail(block: &mut [u8], xid: u64, profile: ReleaseProfile, member: Option<Member>) {
    put_u64(block, 1056, xid);
    put_u32(
        block,
        1064,
        if member == Some(Member::System) {
            0
        } else {
            16
        },
    );
    put_u32(block, 1068, 2);
    put_u64(block, 1104, 2);
    if profile.records_superblock_xid() {
        put_u64(block, 1120, xid);
        put_u64(block, 1128, 12);
    }
}

// ---------------------------------------------------------------------------
// Assembling the blocks

/// Every block the container holds, by address, each one block long.
struct Blocks {
    size: usize,
    map: BTreeMap<u64, Vec<u8>>,
}

impl Blocks {
    fn new(size: usize) -> Self {
        Self {
            size,
            map: BTreeMap::new(),
        }
    }

    /// Place `bytes`, a whole number of blocks, from `at`.
    fn put(&mut self, at: u64, bytes: Vec<u8>) {
        assert!(
            !bytes.is_empty() && bytes.len().is_multiple_of(self.size),
            "an object takes whole blocks"
        );
        for (i, block) in (at..).zip(bytes.chunks(self.size)) {
            let previous = self.map.insert(i, block.to_vec());
            assert!(previous.is_none(), "block {i} is written once");
        }
    }

    /// Place an object of `bytes`, checksummed.
    fn put_object(&mut self, at: u64, mut bytes: Vec<u8>) {
        seal(&mut bytes);
        self.put(at, bytes);
    }
}

impl<'a> IntoIterator for &'a Blocks {
    type Item = (&'a u64, &'a Vec<u8>);
    type IntoIter = std::collections::btree_map::Iter<'a, u64, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

/// An object header for an object of `kind` and `subtype`, found as `storage` says, written in
/// transaction `xid`.
fn header(oid: u64, xid: u64, storage: Storage, kind: u16, subtype: u16) -> ObjectHeader {
    ObjectHeader {
        checksum: 0,
        oid,
        xid,
        type_word: storage.type_bits() | u32::from(kind),
        subtype: u32::from(subtype),
    }
}

/// What is in use at one checkpoint: the main device's blocks and the internal pool's.
struct Usage {
    /// Main-device blocks in use, as runs.
    main: Vec<BlockRange>,
    /// Internal-pool blocks in use.
    pool: Vec<u64>,
}

impl Usage {
    /// Blocks of the main device in use.
    fn main_blocks(&self) -> u64 {
        self.main.iter().map(|run| run.count).sum()
    }

    /// Blocks in use in the chunk `[first, first + count)`.
    fn used_in(&self, first: u64, count: u64) -> u64 {
        self.main
            .iter()
            .map(|run| {
                let start = run.start.max(first);
                let end = (run.start + run.count).min(first + count);
                end.saturating_sub(start)
            })
            .sum()
    }

    /// The bitmap of the chunk `[first, first + count)`, one bit per block from the least
    /// significant bit of the first byte, set where the block is in use.
    fn bitmap(&self, first: u64, count: u64, size: usize) -> Vec<u8> {
        let mut bits = vec![0u8; size];
        for run in &self.main {
            let start = run.start.max(first);
            let end = (run.start + run.count).min(first + count);
            for block in start..end {
                let bit = usize::try_from(block - first).expect("a chunk's bit fits memory");
                bits[bit / 8] |= 1 << (bit % 8);
            }
        }
        bits
    }
}

/// Lay out every block of the container `layout` plans, formatted with `options`, its volumes
/// holding what `models` hold where `volumes` places it, file data aside.
fn assemble(
    layout: &ApfsLayout,
    options: &FormatOptions,
    models: &[ApfsModel],
    volumes: &[PreparedVolume],
) -> Blocks {
    let size = usize::try_from(layout.block_size).expect("a block fits memory");
    let time = nanos_since_epoch(options.time).expect("checked when the plan was made");
    let [first, second] = &layout.checkpoints;
    let mut blocks = Blocks::new(size);

    // What each checkpoint holds in use. The second still holds what it freed: a free queue's
    // blocks are not free until a later transaction takes them out of it.
    let [first_main, second_main] = layout.in_use();
    let first_pool: Vec<u64> = pool_blocks_written(first, None);
    let mut second_pool = first_pool.clone();
    second_pool.extend(pool_blocks_written(second, Some(first)));
    let usage = [
        Usage {
            main: first_main,
            pool: first_pool,
        },
        Usage {
            main: second_main,
            pool: second_pool,
        },
    ];

    // The internal pool's chunk-info, address and bitmap blocks, each checkpoint writing the
    // ones it changed.
    for (cp, (use_, earlier)) in layout
        .checkpoints
        .iter()
        .zip(usage.iter().zip([None, Some(first)]))
    {
        write_chunk_blocks(&mut blocks, layout, cp, use_, earlier);
        write_pool_bitmaps(&mut blocks, layout, cp, use_, earlier);
    }

    // The free queues the second checkpoint fills with what it freed.
    let pool_queue = queue_node(layout, &second.freed_pool, POOL_QUEUE_OID, second.xid);
    let main_queue = queue_node(layout, &second.freed_main, MAIN_QUEUE_OID, second.xid);

    // Each checkpoint's ephemeral objects, mapping block and superblock.
    for (cp, use_) in layout.checkpoints.iter().zip(&usage) {
        let queues = cp.queues.map(|roots| {
            [
                (roots.pool, POOL_QUEUE_OID, &pool_queue),
                (roots.main, MAIN_QUEUE_OID, &main_queue),
            ]
        });
        blocks.put_object(
            cp.space_manager,
            space_manager(layout, cp, use_, queues.is_some().then_some(second)),
        );
        blocks.put_object(cp.reaper, reaper(layout, cp.xid));
        let mut mappings = vec![
            mapping(
                kind::SPACE_MANAGER,
                0,
                layout.block_size * layout.space_manager.blocks,
                SPACE_MANAGER_OID,
                cp.space_manager,
            ),
            mapping(kind::REAPER, 0, layout.block_size, REAPER_OID, cp.reaper),
        ];
        for (at, oid, node) in queues.iter().flatten() {
            blocks.put(*at, (*node).clone());
            mappings.push(mapping(
                kind::BTREE_ROOT,
                kind::SPACE_MANAGER_FREE_QUEUE,
                layout.block_size,
                *oid,
                *at,
            ));
        }
        // Every node past a file-system tree's root takes an identifier of the container's, and
        // so does every root snapshot's extension object.
        let extra_oids = if cp.volumes.is_empty() {
            0
        } else {
            volumes
                .iter()
                .map(|v| v.fs.extra_nodes() + u64::from(v.snapshot.is_some()))
                .sum()
        };
        blocks.put_object(cp.map, checkpoint_map(layout, cp, &mappings));
        blocks.put_object(
            cp.superblock,
            container_superblock(layout, options, cp, extra_oids),
        );

        // The container's object map, listing every volume this checkpoint holds, in one leaf:
        // a container holds at most 100 volumes, and a leaf at 4 KiB holds 111 mappings.
        let entries: Vec<(u64, u64)> = (0u64..)
            .zip(&cp.volumes)
            .map(|(slot, volume)| (volume_oids(slot).0, volume.superblock))
            .collect();
        let records = map_records(&entries, cp.xid, layout.block_size);
        let size = blocks.size;
        let shape = bulk::shape(&records, size, map_tree(CONTAINER_MAP_FLAGS).entries);
        assert!(shape.is_one_leaf(), "a container's volumes fit one leaf");
        let root = Placed {
            oid: cp.object_map.root,
            block: cp.object_map.root,
        };
        write_object_map(
            &mut blocks,
            cp.object_map,
            cp.xid,
            CONTAINER_MAP_FLAGS,
            &Built {
                records,
                shape,
                places: vec![root],
            },
            None,
        );
    }

    // Each volume, written in the second transaction.
    for (slot, ((place, request), (model, prepared))) in (0u64..).zip(
        second
            .volumes
            .iter()
            .zip(&options.volumes)
            .zip(models.iter().zip(volumes)),
    ) {
        write_volume(
            &mut blocks,
            options,
            slot,
            place,
            request,
            (model, prepared),
            second.xid,
            time,
        );
    }

    // Block zero: the newest checkpoint's superblock.
    let newest = blocks.map[&second.superblock].clone();
    blocks.put(0, newest);
    blocks
}

/// The pool blocks checkpoint `cp` wrote: every address, chunk-info and bitmap block it lists
/// that `earlier`, the checkpoint before it, did not.
fn pool_blocks_written(cp: &Checkpoint, earlier: Option<&Checkpoint>) -> Vec<u64> {
    let listed = cp
        .cab_blocks
        .iter()
        .chain(&cp.cib_blocks)
        .copied()
        .chain(cp.bitmaps.iter().map(|bitmap| bitmap.block));
    listed
        .filter(|block| {
            earlier.is_none_or(|e| {
                !e.cab_blocks.contains(block)
                    && !e.cib_blocks.contains(block)
                    && !e.bitmaps.iter().any(|bitmap| bitmap.block == *block)
            })
        })
        .collect()
}

/// The chunk-info and address blocks checkpoint `cp` wrote, and its chunks' bitmaps.
///
/// The first checkpoint writes every chunk-info and address block and every chunk's bitmap; a
/// later one writes the ones whose block it changed. A chunk's entry records the transaction
/// that wrote the bitmap it names, and 1 for a chunk nothing has been allocated from, which
/// names none.
fn write_chunk_blocks(
    blocks: &mut Blocks,
    layout: &ApfsLayout,
    cp: &Checkpoint,
    usage: &Usage,
    earlier: Option<&Checkpoint>,
) {
    let chunks = &layout.chunks;
    let size = blocks.size;
    // Whether this checkpoint wrote the block it lists where `before` lists `block`'s place.
    let wrote = |block: u64, before: Option<u64>| earlier.is_none() || before != Some(block);
    let earlier_bitmap = |chunk: u64| {
        earlier.and_then(|e| e.bitmaps.iter().find(|b| b.chunk == chunk).map(|b| b.block))
    };

    for bitmap in &cp.bitmaps {
        if wrote(bitmap.block, earlier_bitmap(bitmap.chunk)) {
            let (first, count) = span_of(layout, bitmap.chunk);
            blocks.put(bitmap.block, usage.bitmap(first, count, size));
        }
    }
    for (index, &block) in (0u64..).zip(&cp.cib_blocks) {
        if !wrote(block, earlier.map(|e| e.cib_blocks[to_index(index)])) {
            continue;
        }
        let lo = index * chunks.chunks_per_cib;
        let hi = (lo + chunks.chunks_per_cib).min(chunks.chunk_count);
        let mut bytes = vec![0u8; size];
        ChunkList {
            header: header(block, cp.xid, Storage::Physical, kind::SPACE_MANAGER_CIB, 0),
            index: narrow(index),
            count: narrow(hi - lo),
        }
        .write_to(&mut bytes);
        for (at, chunk) in (ChunkList::ENTRIES_AT..)
            .step_by(ChunkInfo::SIZE)
            .zip(lo..hi)
        {
            let (first, count) = span_of(layout, chunk);
            let bitmap = cp
                .bitmaps
                .iter()
                .find(|b| b.chunk == chunk)
                .map(|b| b.block);
            let xid = match (bitmap, earlier) {
                (Some(block), Some(e)) if earlier_bitmap(chunk) == Some(block) => e.xid,
                (Some(_), _) => cp.xid,
                (None, _) => FIRST_XID,
            };
            ChunkInfo {
                xid,
                address: first,
                block_count: narrow(count),
                free_count: narrow(count - usage.used_in(first, count)),
                bitmap: bitmap.unwrap_or(0),
            }
            .write_to(&mut bytes[at..]);
        }
        blocks.put_object(block, bytes);
    }
    for (index, &block) in (0u64..).zip(&cp.cab_blocks) {
        if !wrote(block, earlier.map(|e| e.cab_blocks[to_index(index)])) {
            continue;
        }
        let lo = index * chunks.cibs_per_cab;
        let hi = (lo + chunks.cibs_per_cab).min(chunks.cib_count);
        let mut bytes = vec![0u8; size];
        ChunkList {
            header: header(block, cp.xid, Storage::Physical, kind::SPACE_MANAGER_CAB, 0),
            index: narrow(index),
            count: narrow(hi - lo),
        }
        .write_to(&mut bytes);
        for (at, cib) in (ChunkList::ENTRIES_AT..).step_by(8).zip(lo..hi) {
            put_u64(&mut bytes, at, cp.cib_blocks[to_index(cib)]);
        }
        blocks.put_object(block, bytes);
    }
}

/// The first block of `chunk` of the planned container and how many blocks it has.
fn span_of(layout: &ApfsLayout, chunk: u64) -> (u64, u64) {
    chunk_span(layout.chunks.blocks_per_chunk, layout.block_count, chunk)
}

/// The internal pool's bitmap blocks checkpoint `cp` wrote, each into its slot.
///
/// The first checkpoint writes every one; a later one writes those it moved to a new slot,
/// which are the ones it allocated from. A pool bitmap has one bit per pool block, set where
/// the block is in use.
fn write_pool_bitmaps(
    blocks: &mut Blocks,
    layout: &ApfsLayout,
    cp: &Checkpoint,
    usage: &Usage,
    earlier: Option<&Checkpoint>,
) {
    let per_bitmap = layout.chunks.blocks_per_chunk;
    for (index, &slot) in (0u64..).zip(&cp.pool_bitmap_slots) {
        if earlier.is_some_and(|e| e.pool_bitmap_slots[to_index(index)] == slot) {
            continue;
        }
        let mut bits = vec![0u8; blocks.size];
        for &block in &usage.pool {
            let bit = block - layout.pool.start;
            if bit / per_bitmap == index {
                let bit = to_index(bit % per_bitmap);
                bits[bit / 8] |= 1 << (bit % 8);
            }
        }
        blocks.put(layout.pool_bitmap_area.start + u64::from(slot), bits);
    }
}

/// The free list of the pool-bitmap slots at checkpoint `cp`, as the next slot after each,
/// with its head and tail.
///
/// The slots no pool bitmap occupies, as a queue: the first checkpoint's in ascending order,
/// and each later one's those its predecessor's left, less the ones it moved a bitmap into,
/// then the ones it moved a bitmap out of. A slot in use, and the last free one, are followed
/// by none.
fn slot_free_list(layout: &ApfsLayout, cp: &Checkpoint) -> (Vec<u16>, u16, u16) {
    let slots = to_index(layout.pool_bitmap_area.count);
    let [first, _] = &layout.checkpoints;
    let mut order: Vec<u32> = (0..narrow::<u32>(layout.pool_bitmap_area.count))
        .filter(|slot| !first.pool_bitmap_slots.contains(slot))
        .collect();
    if cp.xid != first.xid {
        let moved: Vec<(u32, u32)> = first
            .pool_bitmap_slots
            .iter()
            .zip(&cp.pool_bitmap_slots)
            .filter(|(before, after)| before != after)
            .map(|(before, after)| (*before, *after))
            .collect();
        order.retain(|slot| !moved.iter().any(|(_, into)| into == slot));
        order.extend(moved.iter().map(|(out_of, _)| *out_of));
    }
    let mut next = vec![NO_VALUE; slots];
    for pair in order.windows(2) {
        next[to_index(u64::from(pair[0]))] = narrow(u64::from(pair[1]));
    }
    let head = order
        .first()
        .map_or(NO_VALUE, |slot| narrow(u64::from(*slot)));
    let tail = order
        .last()
        .map_or(NO_VALUE, |slot| narrow(u64::from(*slot)));
    (next, head, tail)
}

/// The space manager of checkpoint `cp`, over all of its blocks; `queues` is the checkpoint
/// whose frees its queues hold, where it has any.
fn space_manager(
    layout: &ApfsLayout,
    cp: &Checkpoint,
    usage: &Usage,
    queues: Option<&Checkpoint>,
) -> Vec<u8> {
    let size = blocks_bytes(layout, u64::from(layout.space_manager.blocks));
    let shape = &layout.space_manager;
    let chunks = &layout.chunks;
    let limits = layout.queue_node_limits;
    let queue = |oid: u64, frees: Option<&Vec<BlockRange>>, limit: u16| FreeQueue {
        count: frees.map_or(0, |runs| runs.iter().map(|run| run.count).sum()),
        tree_oid: frees.map_or(0, |_| oid),
        oldest_xid: frees.map_or(0, |_| queues.map_or(0, |q| q.xid)),
        tree_node_limit: limit,
        ..FreeQueue::default()
    };
    let (next, head, tail) = slot_free_list(layout, cp);
    let mut bytes = vec![0u8; size];
    SpaceManager {
        header: header(
            SPACE_MANAGER_OID,
            cp.xid,
            Storage::Ephemeral,
            kind::SPACE_MANAGER,
            0,
        ),
        block_size: layout.block_size,
        blocks_per_chunk: narrow(chunks.blocks_per_chunk),
        chunks_per_cib: narrow(chunks.chunks_per_cib),
        cibs_per_cab: narrow(chunks.cibs_per_cab),
        devices: [
            SpaceDevice {
                block_count: layout.block_count,
                chunk_count: chunks.chunk_count,
                cib_count: narrow(chunks.cib_count),
                cab_count: narrow(chunks.cab_count),
                free_count: layout.block_count - usage.main_blocks(),
                addr_offset: shape.address_offset,
                ..SpaceDevice::default()
            },
            SpaceDevice {
                addr_offset: shape.second_address_offset,
                ..SpaceDevice::default()
            },
        ],
        flags: SPACE_MANAGER_FLAGS,
        ip_bm_tx_multiplier: POOL_BITMAP_SLOTS,
        ip_block_count: layout.pool.count,
        ip_bm_size_in_blocks: layout.pool_bitmaps,
        ip_bm_block_count: narrow(layout.pool_bitmap_area.count),
        ip_bm_base: layout.pool_bitmap_area.start,
        ip_base: layout.pool.start,
        fs_reserve_block_count: 0,
        fs_reserve_alloc_count: 0,
        free_queues: [
            queue(POOL_QUEUE_OID, queues.map(|q| &q.freed_pool), limits.pool),
            queue(MAIN_QUEUE_OID, queues.map(|q| &q.freed_main), limits.main),
            FreeQueue::default(),
        ],
        ip_bm_free_head: head,
        ip_bm_free_tail: tail,
        ip_bm_xid_offset: shape.bitmap_xid_offset,
        ip_bitmap_offset: shape.bitmap_slot_offset,
        ip_bm_free_next_offset: shape.bitmap_free_list_offset,
        version: SPACE_MANAGER_VERSION,
        struct_size: SPACE_MANAGER_STRUCT_SIZE,
    }
    .write_to(&mut bytes);

    // The arrays past the structure: each pool bitmap's transaction and slot, the slots' free
    // list, and the main device's address list. The transaction of a bitmap is the one that
    // last moved it.
    let [first, _] = &layout.checkpoints;
    for (index, &slot) in cp.pool_bitmap_slots.iter().enumerate() {
        let xid = if slot == first.pool_bitmap_slots[index] {
            first.xid
        } else {
            cp.xid
        };
        put_u64(&mut bytes, offset(shape.bitmap_xid_offset) + 8 * index, xid);
        put_u16(
            &mut bytes,
            offset(shape.bitmap_slot_offset) + 2 * index,
            narrow(u64::from(slot)),
        );
    }
    for (i, next) in next.iter().enumerate() {
        put_u16(
            &mut bytes,
            offset(shape.bitmap_free_list_offset) + 2 * i,
            *next,
        );
    }
    let listed = if chunks.cab_count > 0 {
        &cp.cab_blocks
    } else {
        &cp.cib_blocks
    };
    for (i, block) in listed.iter().enumerate() {
        put_u64(&mut bytes, offset(shape.address_offset) + 8 * i, *block);
    }
    bytes
}

/// The reaper of a checkpoint written in transaction `xid`: idle, with nothing to reap.
fn reaper(layout: &ApfsLayout, xid: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; blocks_bytes(layout, 1)];
    Reaper {
        header: header(REAPER_OID, xid, Storage::Ephemeral, kind::REAPER, 0),
        next_reap_id: 1,
        completed_id: 0,
        head: 0,
        tail: 0,
        flags: REAPER_FLAGS,
        list_count: 0,
        kind: 0,
        size: 0,
        volume_oid: 0,
        oid: 0,
        xid: 0,
        entry_flags: 0,
        state_buffer_size: layout.block_size - narrow::<u32>(Reaper::SIZE as u64),
    }
    .write_to(&mut bytes);
    bytes
}

/// A checkpoint's mapping of one ephemeral object.
fn mapping(kind: u16, subtype: u16, size: u32, oid: u64, address: u64) -> CheckpointMapping {
    CheckpointMapping {
        type_word: Storage::Ephemeral.type_bits() | u32::from(kind),
        subtype: u32::from(subtype),
        size,
        pad: 0,
        volume_oid: 0,
        oid,
        address,
    }
}

/// Checkpoint `cp`'s mapping block, the one block of its descriptor area besides its
/// superblock, mapping each of its ephemeral objects.
fn checkpoint_map(layout: &ApfsLayout, cp: &Checkpoint, mappings: &[CheckpointMapping]) -> Vec<u8> {
    let mut bytes = vec![0u8; blocks_bytes(layout, 1)];
    CheckpointMap {
        header: header(cp.map, cp.xid, Storage::Physical, kind::CHECKPOINT_MAP, 0),
        flags: MAPPING_BLOCK_FLAGS,
        count: narrow(mappings.len() as u64),
    }
    .write_to(mappings, &mut bytes);
    bytes
}

/// Checkpoint `cp`'s copy of the container superblock, whose volumes' trees have `extra_oids`
/// nodes past their roots.
fn container_superblock(
    layout: &ApfsLayout,
    options: &FormatOptions,
    cp: &Checkpoint,
    extra_oids: u64,
) -> Vec<u8> {
    let desc = layout.descriptor_area;
    let data = layout.data_area;
    // The descriptor blocks this checkpoint uses are its mapping block and its superblock; the
    // data blocks are its ephemeral objects, from its space manager to the last of them.
    let last_ephemeral = cp.queues.map_or(cp.reaper, |queues| queues.main);
    let desc_index = cp.map - desc.start;
    let data_index = cp.space_manager - data.start;
    let data_len = last_ephemeral + 1 - cp.space_manager;
    let mut volume_oids_field = [0u64; MAX_VOLUMES];
    for (slot, field) in (0u64..).zip(volume_oids_field.iter_mut().take(cp.volumes.len())) {
        *field = volume_oids(slot).0;
    }
    let mut bytes = vec![0u8; blocks_bytes(layout, 1)];
    ContainerSuperblock {
        header: header(1, cp.xid, Storage::Ephemeral, kind::CONTAINER_SUPERBLOCK, 0),
        block_size: layout.block_size,
        block_count: layout.block_count,
        features: 0,
        readonly_compatible_features: 0,
        incompatible_features: CONTAINER_INCOMPAT,
        uuid: options.uuid,
        next_oid: next_oid(cp.volumes.len() as u64) + extra_oids,
        next_xid: cp.xid + 1,
        checkpoint: CheckpointAreas {
            desc_blocks: narrow(desc.count),
            data_blocks: narrow(data.count),
            desc_base: desc.start,
            data_base: data.start,
            desc_next: narrow(desc_index + 2),
            data_next: narrow(data_index + data_len),
            desc_index: narrow(desc_index),
            desc_len: 2,
            data_index: narrow(data_index),
            data_len: narrow(data_len),
        },
        space_manager_oid: SPACE_MANAGER_OID,
        object_map_oid: cp.object_map.object,
        reaper_oid: REAPER_OID,
        test_type: 0,
        max_volumes: layout.max_volumes,
        volume_oids: volume_oids_field,
        counters: [0; super::ondisk::COUNTERS],
        blocked_out: BlockRange::default(),
        evict_mapping_tree_oid: 0,
        flags: 0,
        efi_jumpstart: 0,
        fusion_uuid: [0; 16],
        keylocker: BlockRange::default(),
        ephemeral_info: [
            (u64::from(layout.ephemeral_min_blocks) << 32) | EPHEMERAL_INFO_LOW,
            0,
            0,
            0,
        ],
        test_oid: 0,
        fusion_middle_tree_oid: 0,
        fusion_cache_oid: 0,
        fusion_cache: BlockRange::default(),
        newest_mounted_version: 0,
        media_keybag: BlockRange::default(),
    }
    .write_to(&mut bytes);
    bytes
}

/// An object map at `place`, written in `xid`, with object-map flags `flags`, its tree as
/// `tree` builds it, and the tree of the one snapshot it keeps versions for, at that
/// transaction, where `snapshots` gives one.
fn write_object_map(
    blocks: &mut Blocks,
    place: MapPlace,
    xid: u64,
    flags: u32,
    tree: &Built,
    snapshots: Option<&Built>,
) {
    let mut bytes = vec![0u8; blocks.size];
    let physical_root = Storage::Physical.type_bits() | u32::from(kind::BTREE_ROOT);
    let snapshot_tree_oid = snapshots.map_or(0, |tree| {
        tree.places.last().expect("a tree has its root").block
    });
    ObjectMap {
        header: header(place.object, xid, Storage::Physical, kind::OBJECT_MAP, 0),
        flags,
        snapshot_count: u32::from(snapshots.is_some()),
        tree_type: physical_root,
        snapshot_tree_type: physical_root,
        tree_oid: place.root,
        snapshot_tree_oid,
        most_recent_snapshot: if snapshots.is_some() { xid } else { 0 },
        pending_revert_min: 0,
        pending_revert_max: 0,
    }
    .write_to(&mut bytes);
    blocks.put_object(place.object, bytes);
    write_tree(blocks, tree, map_tree(MAP_TREE_FLAGS), xid);
    if let Some(snapshots) = snapshots {
        write_tree(blocks, snapshots, MAP_SNAPSHOT_TREE, xid);
    }
}

/// Every node of `tree`, a tree of `kind`, written in `xid`.
fn write_tree(blocks: &mut Blocks, tree: &Built, kind: TreeKind, xid: u64) {
    let size = blocks.size;
    for (block, bytes) in bulk::render(&tree.records, &tree.shape, kind, size, xid, &tree.places) {
        blocks.put_object(block, bytes);
    }
}

/// The volume in `slot`, at `place`, holding what `model` holds where `prepared` places it,
/// written in transaction `xid`.
#[allow(clippy::too_many_arguments)]
fn write_volume(
    blocks: &mut Blocks,
    options: &FormatOptions,
    slot: u64,
    place: &VolumePlace,
    request: &VolumeRequest,
    (model, prepared): (&ApfsModel, &PreparedVolume),
    xid: u64,
    time: u64,
) {
    let (volume_oid, root_oid) = volume_oids(slot);
    let physical_root = Storage::Physical.type_bits() | u32::from(kind::BTREE_ROOT);
    let snapshot = prepared
        .snapshot
        .as_ref()
        .zip(request.root_snapshot.as_ref());
    write_object_map(
        blocks,
        place.object_map,
        xid,
        0,
        &prepared.map,
        snapshot.map(|(placed, _)| &placed.map_snapshots),
    );
    write_tree(blocks, &prepared.extents, EXTENT_REF_TREE, xid);
    // The snapshot tree: empty, or the root snapshot's two records, its metadata and then its
    // name, in the order macOS inserts them. The metadata names the extent-reference tree the
    // volume was written with, which the snapshot keeps.
    let snapshot_records: Vec<Record> = snapshot.map_or_else(Vec::new, |(placed, root)| {
        let meta = SnapshotMeta {
            xid,
            extent_ref_tree_oid: place.extent_ref_tree,
            superblock: placed.copy,
            create_time: time as i64,
            change_time: time as i64,
            next_object_id: model.next_object_id,
            extent_ref_tree_type: physical_root,
            flags: 0,
            name: root.name().as_bytes().to_vec(),
        };
        vec![
            meta.to_record(),
            snapshot_name_record(root.name().as_bytes(), xid),
        ]
    });
    blocks.put_object(
        place.snapshot_tree,
        inserted_root_leaf(
            blocks.size,
            header(
                place.snapshot_tree,
                xid,
                Storage::Physical,
                kind::BTREE_ROOT,
                kind::SNAPSHOT_TREE,
            ),
            SNAPSHOT_TREE,
            &snapshot_records,
        ),
    );
    if prepared.fs.shape.is_one_leaf() {
        // One leaf: laid out as a tree grown from the four records a volume is made with, in
        // the order `newfs_apfs` inserts them, by inserting the rest in key order.
        let records: Vec<Record> = prepared
            .records
            .made
            .iter()
            .chain(&prepared.records.rest)
            .cloned()
            .collect();
        blocks.put_object(
            place.root_tree,
            inserted_root_leaf(
                blocks.size,
                header(
                    root_oid,
                    xid,
                    Storage::Virtual,
                    kind::BTREE_ROOT,
                    kind::FS_TREE,
                ),
                FS_TREE,
                &records,
            ),
        );
    } else {
        write_tree(blocks, &prepared.fs, FS_TREE, xid);
    }

    // What the volume holds in blocks: its object map, every node of its trees, and its
    // streams; its superblock is not counted.
    let allocated = 1
        + prepared.map.places.len() as u64
        + prepared.extents.places.len() as u64
        + 1
        + prepared.fs.places.len() as u64
        + prepared.records.stream_blocks;
    let mut name = [0u8; VOLUME_NAME_LEN];
    name[..request.name.0.len()].copy_from_slice(request.name.0.as_bytes());
    // A member of a volume group records its role, the group's identifier, which is the Data
    // volume's own, and the feature bit both members carry.
    let member = member(options, narrow(slot));
    let group = options
        .volume_group
        .filter(|_| member.is_some())
        .map_or([0; 16], |g| options.volumes[g.data as usize].uuid);
    let formatted_by = ModifiedBy {
        id: options.formatted_by.0,
        timestamp: time,
        last_xid: xid,
    };
    let unwritten = ModifiedBy {
        id: [0; PROGRAM_NAME_FIELD],
        timestamp: 0,
        last_xid: 0,
    };
    let mut volume = VolumeSuperblock {
        header: header(
            volume_oid,
            xid,
            Storage::Virtual,
            kind::VOLUME_SUPERBLOCK,
            0,
        ),
        index: narrow(slot),
        features: VOLUME_FEATURES | member.map_or(0, |_| GROUP_FEATURE),
        readonly_compatible_features: 0,
        incompatible_features: request.names.feature(),
        unmount_time: 0,
        reserve_blocks: 0,
        quota_blocks: 0,
        allocated_blocks: allocated,
        meta_crypto: [0; 20],
        root_tree_type: Storage::Virtual.type_bits() | u32::from(kind::BTREE_ROOT),
        extent_ref_tree_type: physical_root,
        snapshot_tree_type: physical_root,
        object_map_oid: place.object_map.object,
        root_tree_oid: root_oid,
        extent_ref_tree_oid: place.extent_ref_tree,
        snapshot_tree_oid: place.snapshot_tree,
        revert_to_xid: 0,
        revert_to_superblock: 0,
        next_object_id: model.next_object_id,
        file_count: model.counts.files,
        directory_count: model.counts.directories,
        symlink_count: model.counts.symlinks,
        other_count: model.counts.other,
        snapshot_count: 0,
        total_blocks_allocated: prepared.records.stream_blocks,
        total_blocks_freed: 0,
        uuid: request.uuid,
        last_modified: time,
        flags: volume_flags::UNENCRYPTED,
        formatted_by,
        modified_by: [unwritten; MODIFIED_BY_ENTRIES],
        name,
        next_document_id: NEXT_DOCUMENT_ID,
        role: member.map_or(0, Member::role),
        reserved: 0,
        root_to_xid: 0,
        encryption_rolling_oid: 0,
        clone_info_epoch: 0,
        clone_info_xid: 0,
        snapshot_extension_oid: 0,
        volume_group: group,
        integrity_meta_oid: 0,
        file_extent_tree_oid: 0,
        file_extent_tree_type: physical_root,
        reserved_type: physical_root,
        reserved_oid: 0,
    };
    if let Some((placed, root)) = snapshot {
        write_snapshot(blocks, options, member, placed, root, &mut volume);
    }
    let mut bytes = vec![0u8; blocks.size];
    volume.write_to(&mut bytes);
    write_volume_tail(&mut bytes, xid, options.profile, member);
    blocks.put_object(place.superblock, bytes);
}

/// Write what the root snapshot `root`, placed as `placed`, adds to `volume`, a superblock
/// that holds none yet, and record it there.
///
/// As macOS writes a snapshot it takes: the copy keeps the superblock as it was before the
/// snapshot, physical at its own block, with no object map, extent-reference tree or snapshot
/// tree named. The extension object holds the snapshot's identifier, version 1 and no flags.
/// The volume then counts the extension object, the object map's tree of snapshots and its own
/// new extent-reference tree among its blocks, names that tree, holds one snapshot, and takes
/// one more object identifier. Its root-to transaction is the snapshot's.
fn write_snapshot(
    blocks: &mut Blocks,
    options: &FormatOptions,
    member: Option<Member>,
    placed: &SnapshotPlace,
    root: &RootSnapshot,
    volume: &mut VolumeSuperblock,
) {
    let xid = volume.header.xid;
    let mut copy = volume.clone();
    copy.header = header(
        placed.copy,
        xid,
        Storage::Physical,
        kind::VOLUME_SUPERBLOCK,
        0,
    );
    copy.object_map_oid = 0;
    copy.extent_ref_tree_oid = 0;
    copy.snapshot_tree_oid = 0;
    let mut bytes = vec![0u8; blocks.size];
    copy.write_to(&mut bytes);
    write_volume_tail(&mut bytes, xid, options.profile, member);
    blocks.put_object(placed.copy, bytes);

    let mut bytes = vec![0u8; blocks.size];
    header(
        placed.extension.oid,
        xid,
        Storage::Virtual,
        kind::SNAPSHOT_EXTENSION,
        0,
    )
    .write_to(&mut bytes);
    SnapshotExtension {
        version: 1,
        flags: 0,
        xid,
        uuid: root.uuid(),
        token: 0,
    }
    .write_to(&mut bytes);
    blocks.put_object(placed.extension.block, bytes);

    write_tree(blocks, &placed.references, EXTENT_REF_TREE, xid);
    volume.allocated_blocks +=
        placed.references.places.len() as u64 + placed.map_snapshots.places.len() as u64 + 1;
    volume.extent_ref_tree_oid = placed
        .references
        .places
        .last()
        .expect("a tree has its root")
        .block;
    volume.snapshot_count = 1;
    volume.snapshot_extension_oid = placed.extension.oid;
    volume.next_object_id += 1;
    volume.root_to_xid = xid;
}

// ---------------------------------------------------------------------------
// Tree nodes

/// A root leaf of a tree of `kind` holding `records`: the layout a tree has when its records
/// were inserted in the order `records` gives, its table listing them in key order.
fn inserted_root_leaf(
    size: usize,
    object: ObjectHeader,
    kind: TreeKind,
    records: &[(Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let mut key_order: Vec<usize> = (0..records.len()).collect();
    key_order.sort_by(|&a, &b| {
        compare_records(&records[a].0, &records[b].0)
            .expect("a record this writer made parses")
            .expect("two records this writer made are ordered")
    });
    bulk::inserted_root_leaf(records, &key_order, kind, size, object)
}

/// A root leaf of a tree whose keys and values have fixed sizes, built by the edits the tree
/// makes: an insertion lays its key after every key the node has held and its value before
/// every value, and slides the table entries after it along; a deletion puts its key and value
/// on the free lists, slides the table entries after it back, and leaves the bytes it vacated
/// as they were.
struct FixedNode {
    size: usize,
    key_size: usize,
    value_size: usize,
    bytes: Vec<u8>,
    table: usize,
    entries: usize,
    /// Bytes of the key area ever taken.
    keys: usize,
    /// Bytes of the value area ever taken.
    values: usize,
    key_free: (u16, u16),
    value_free: (u16, u16),
    longest_key: usize,
    longest_value: usize,
}

impl FixedNode {
    fn new(size: usize, key_size: usize, value_size: usize) -> Self {
        Self {
            size,
            key_size,
            value_size,
            bytes: vec![0u8; size],
            table: bulk::fixed_table_bytes(size, key_size, value_size),
            entries: 0,
            keys: 0,
            values: 0,
            key_free: (NO_VALUE, 0),
            value_free: (NO_VALUE, 0),
            longest_key: 0,
            longest_value: 0,
        }
    }

    const fn key_area(&self) -> usize {
        NODE_DATA_START + self.table
    }

    const fn value_end(&self) -> usize {
        self.size - TREE_INFO_SIZE
    }

    /// Entry `i`'s key and value offsets.
    fn slot(&self, i: usize) -> (u16, u16) {
        let at = NODE_DATA_START + 4 * i;
        (get_u16(&self.bytes, at), get_u16(&self.bytes, at + 2))
    }

    fn set_slot(&mut self, i: usize, (key, value): (u16, u16)) {
        let at = NODE_DATA_START + 4 * i;
        put_u16(&mut self.bytes, at, key);
        put_u16(&mut self.bytes, at + 2, value);
    }

    /// Entry `i`'s key bytes.
    fn key(&self, i: usize) -> &[u8] {
        let at = self.key_area() + usize::from(self.slot(i).0);
        &self.bytes[at..at + self.key_size]
    }

    /// Entry `i`'s value bytes, where it has one.
    fn value(&self, i: usize) -> Option<&[u8]> {
        let (_, value) = self.slot(i);
        (value != NO_VALUE).then(|| {
            let at = self.value_end() - usize::from(value);
            &self.bytes[at..at + self.value_size]
        })
    }

    /// Give entry `i` the value `value`, taking value space for it where it had none.
    fn set_value(&mut self, i: usize, value: &[u8]) {
        let (key, mut at) = self.slot(i);
        if at == NO_VALUE {
            self.values += self.value_size;
            at = narrow(self.values as u64);
            self.set_slot(i, (key, at));
        }
        let start = self.value_end() - usize::from(at);
        self.bytes[start..start + self.value_size].copy_from_slice(value);
        self.longest_value = self.value_size;
    }

    /// Insert `key`, with `value` where it has one, at table position `i`.
    fn insert(&mut self, i: usize, key: &[u8], value: Option<&[u8]>) {
        let key_at = self.keys;
        let start = self.key_area() + key_at;
        self.bytes[start..start + self.key_size].copy_from_slice(key);
        self.keys += self.key_size;
        self.longest_key = self.key_size;
        let at = NODE_DATA_START + 4 * i;
        self.bytes
            .copy_within(at..NODE_DATA_START + 4 * self.entries, at + 4);
        self.entries += 1;
        self.set_slot(i, (narrow(key_at as u64), NO_VALUE));
        if let Some(value) = value {
            self.set_value(i, value);
        }
    }

    /// Delete entry `i`.
    fn delete(&mut self, i: usize) {
        let (key, value) = self.slot(i);
        let start = self.key_area() + usize::from(key);
        put_u16(&mut self.bytes, start, self.key_free.0);
        put_u16(&mut self.bytes, start + 2, narrow(self.key_size as u64));
        self.key_free = (key, self.key_free.1 + narrow::<u16>(self.key_size as u64));
        if value != NO_VALUE {
            let start = self.value_end() - usize::from(value);
            put_u16(&mut self.bytes, start, self.value_free.0);
            put_u16(&mut self.bytes, start + 2, narrow(self.value_size as u64));
            self.value_free = (
                value,
                self.value_free.1 + narrow::<u16>(self.value_size as u64),
            );
        }
        let at = NODE_DATA_START + 4 * i;
        self.bytes
            .copy_within(at + 4..NODE_DATA_START + 4 * self.entries, at);
        self.entries -= 1;
    }

    /// The node, with its header and its tree's information.
    fn finish(mut self, object: ObjectHeader, tree_flags: u32) -> Vec<u8> {
        let key_area = self.key_area();
        let value_end = self.value_end();
        NodeHeader {
            header: object,
            flags: node_flags::ROOT | node_flags::LEAF | node_flags::FIXED_SIZE,
            level: 0,
            key_count: narrow(self.entries as u64),
            table: (0, narrow(self.table as u64)),
            free_space: (
                narrow(self.keys as u64),
                narrow((value_end - key_area - self.keys - self.values) as u64),
            ),
            key_free_list: self.key_free,
            value_free_list: self.value_free,
        }
        .write_to(&mut self.bytes);
        TreeInfo {
            flags: tree_flags,
            node_size: narrow(self.size as u64),
            key_size: narrow(self.key_size as u64),
            value_size: narrow(self.value_size as u64),
            longest_key: narrow(self.longest_key as u64),
            longest_value: narrow(self.longest_value as u64),
            key_count: self.entries as u64,
            node_count: 1,
        }
        .write_to(&mut self.bytes[value_end..]);
        self.bytes
    }
}

/// A free queue's one node, holding `frees` freed in transaction `xid` in the order given.
///
/// A queue keys a run of blocks by the transaction that freed it and its first block, and
/// gives it a value of its length only where it is longer than one block. A block freed right
/// after a run the queue holds extends that run; any other is inserted as a run of its own.
/// Either way, a run the queue holds that begins where the freed one now ends is then deleted
/// and the freed one extended over it, which is what leaves a deleted key on the node's free
/// list. `newfs_apfs` frees one pool block just before another it has already freed in every
/// container of about 2.4 TiB and more at 4 KiB, and one between two it has already freed in
/// containers just past the contiguous limit at 16, 32 and 64 KiB.
fn queue_node(layout: &ApfsLayout, frees: &[BlockRange], oid: u64, xid: u64) -> Vec<u8> {
    let size = usize::try_from(layout.block_size).expect("a block fits memory");
    let mut node = FixedNode::new(size, FreeQueueKey::SIZE, 8);
    let key_of = |node: &FixedNode, i: usize| {
        FreeQueueKey::read_from(node.key(i)).expect("a queue's key is whole")
    };
    let count_of = |node: &FixedNode, i: usize| {
        node.value(i).map_or(1, |value| {
            u64::from_le_bytes(value.try_into().expect("eight bytes"))
        })
    };
    let find = |node: &FixedNode, pred: &dyn Fn(FreeQueueKey, u64) -> bool| {
        (0..node.entries).find(|&i| pred(key_of(node, i), count_of(node, i)))
    };
    for run in frees {
        // A run ending where this one begins takes it in; otherwise it is a run of its own.
        let key = if let Some(i) = find(&node, &|key, count| {
            key.xid == xid && key.address + count == run.start
        }) {
            let total = count_of(&node, i) + run.count;
            node.set_value(i, &total.to_le_bytes());
            key_of(&node, i)
        } else {
            let key = FreeQueueKey {
                xid,
                address: run.start,
            };
            let i = find(&node, &|k, _| k > key).unwrap_or(node.entries);
            let mut bytes = [0u8; FreeQueueKey::SIZE];
            key.write_to(&mut bytes);
            let value = run.count.to_le_bytes();
            node.insert(i, &bytes, (run.count > 1).then_some(&value[..]));
            key
        };
        // A run beginning where that one now ends is taken into it.
        let i = find(&node, &|k, _| k == key).expect("the run just freed");
        let end = key.address + count_of(&node, i);
        if let Some(j) = find(&node, &|k, _| k.xid == xid && k.address == end) {
            let total = count_of(&node, i) + count_of(&node, j);
            node.delete(j);
            let i = find(&node, &|k, _| k == key).expect("the run just freed");
            node.set_value(i, &total.to_le_bytes());
        }
    }
    let mut bytes = node.finish(
        header(
            oid,
            xid,
            Storage::Ephemeral,
            kind::BTREE_ROOT,
            kind::SPACE_MANAGER_FREE_QUEUE,
        ),
        QUEUE_TREE_FLAGS,
    );
    seal(&mut bytes);
    bytes
}

// ---------------------------------------------------------------------------
// Small conversions

/// Bytes in `blocks` blocks of the container.
fn blocks_bytes(layout: &ApfsLayout, blocks: u64) -> usize {
    usize::try_from(blocks * u64::from(layout.block_size)).expect("an object fits memory")
}

/// A space manager array's offset, as an index into its bytes.
fn offset(at: u32) -> usize {
    usize::try_from(at).expect("an offset fits memory")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    use std::io::{Read, Seek, SeekFrom, Write};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::SourceEntry;
    use crate::apfs::ondisk::{inode_field, record_kind, verify};
    use crate::apfs::{BlockZero, Container, Reader};

    /// A source holding nothing: the empty container `newfs_apfs` formats.
    fn nothing() -> Vec<SourceEntry> {
        Vec::new()
    }

    /// Every volume of `layout`, formatted with `options`, empty: what a plan models and places
    /// for a container below the floor, which only the rules' gates assemble.
    fn empty_volumes(
        layout: &ApfsLayout,
        options: &FormatOptions,
    ) -> (Vec<ApfsModel>, Vec<PreparedVolume>) {
        let time = checked_time(options).expect("a time");
        let (models, _) = model_volumes(nothing(), options).expect("empty volumes");
        let mut next = next_oid(layout.newest().volumes.len() as u64);
        let volumes = (0u64..)
            .zip(&layout.newest().volumes)
            .zip(models.iter().zip(&options.volumes))
            .map(|((slot, place), (model, request))| {
                let mut take = |blocks| {
                    assert_eq!(blocks, 0, "an empty volume takes no block");
                    Ok(Vec::new())
                };
                let content = place_content(
                    model,
                    request,
                    (slot, *place),
                    layout.block_size,
                    time,
                    &mut take,
                    &mut next,
                )
                .expect("an empty volume");
                place_map(content, *place, layout.block_size, &mut take).expect("an empty volume")
            })
            .collect();
        (models, volumes)
    }

    /// Every empty container `newfs_apfs` formatted that the writer is held to, one line per
    /// shape: the inputs that formatted it, and the digest of its blocks with the fields
    /// [`normalize`] names cleared, once for macOS 14 and 15 and once for 26 and 27.
    const NEWFS: &str = include_str!("fixtures/newfs-images.txt");

    /// The shapes the fixture holds, and the containers they stand for: a fixture that lost a
    /// line is a gate that compares less.
    const SHAPES: usize = 1827;
    const CONTAINERS: usize = 7390;

    /// A destination that keeps what is written to it and nothing else.
    #[derive(Default)]
    struct Sparse {
        pos: u64,
        writes: BTreeMap<u64, Vec<u8>>,
    }

    impl Write for Sparse {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.insert(self.pos, buf.to_vec());
            self.pos += buf.len() as u64;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for Sparse {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            let SeekFrom::Start(at) = to else {
                unreachable!("the writer seeks from the start")
            };
            self.pos = at;
            Ok(at)
        }
    }

    impl Sparse {
        /// What was written, as whole blocks of `size`. The one-byte write that extends the
        /// destination to its size is a zero and is no block.
        fn blocks(&self, size: usize) -> BTreeMap<u64, Vec<u8>> {
            let mut out = BTreeMap::new();
            for (&at, bytes) in &self.writes {
                if bytes.len() % size != 0 {
                    assert!(
                        bytes.iter().all(|b| *b == 0),
                        "a short write extends with zeros"
                    );
                    continue;
                }
                assert_eq!(at % size as u64, 0, "a block write starts at a block");
                for (i, block) in (at / size as u64..).zip(bytes.chunks(size)) {
                    out.insert(i, block.to_vec());
                }
            }
            out
        }
    }

    /// A container held as its nonzero blocks, read as a seekable source of `len` bytes, and
    /// written to as a destination that keeps each block written whole or in part and reads
    /// every other byte as zero.
    pub(super) struct Held {
        size: usize,
        len: u64,
        blocks: BTreeMap<u64, Vec<u8>>,
        pos: u64,
    }

    impl Held {
        /// A destination of blocks of `size` bytes with nothing written to it.
        pub(super) fn empty(size: usize) -> Self {
            Self {
                size,
                len: 0,
                blocks: BTreeMap::new(),
                pos: 0,
            }
        }

        /// The blocks `blocks`, of `size` bytes, read as an image of `len` bytes.
        pub(super) fn with(size: usize, len: u64, blocks: BTreeMap<u64, Vec<u8>>) -> Self {
            Self {
                size,
                len,
                blocks,
                pos: 0,
            }
        }

        /// What was written, read again from its first byte.
        pub(super) fn rewound(mut self) -> Self {
            self.pos = 0;
            self
        }
    }

    impl Write for Held {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let size = self.size as u64;
            let within = usize::try_from(self.pos % size).expect("a block offset");
            let n = buf.len().min(self.size - within);
            let block = self
                .blocks
                .entry(self.pos / size)
                .or_insert_with(|| vec![0; self.size]);
            block[within..within + n].copy_from_slice(&buf[..n]);
            self.pos += n as u64;
            self.len = self.len.max(self.pos);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for Held {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.len || buf.is_empty() {
                return Ok(0);
            }
            let size = self.size as u64;
            let block = self.pos / size;
            let within = usize::try_from(self.pos % size).expect("a block offset");
            let n = buf
                .len()
                .min(self.size - within)
                .min(usize::try_from(self.len - self.pos).unwrap_or(usize::MAX));
            match self.blocks.get(&block) {
                Some(bytes) => buf[..n].copy_from_slice(&bytes[within..within + n]),
                None => buf[..n].fill(0),
            }
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for Held {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.pos = match to {
                SeekFrom::Start(at) => at,
                SeekFrom::End(back) => self.len.saturating_add_signed(back),
                SeekFrom::Current(by) => self.pos.saturating_add_signed(by),
            };
            Ok(self.pos)
        }
    }

    /// A block dump: an 8-byte magic, the image's size as a `u64` and the dump's block size as a
    /// `u32`, then runs of a first block (`u64`) and a count (`u32`) followed by that many
    /// blocks, ended by a run of none. Its blocks are cut again into blocks of `size`.
    pub(super) fn read_dump(bytes: &[u8]) -> (u64, BTreeMap<u64, Vec<u8>>) {
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8"));
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4"));
        assert_eq!(&bytes[..8], b"BLKDUMP1", "a block dump");
        let len = u64_at(8);
        let dump_size = usize::try_from(u32_at(16)).expect("a block size");
        let mut at = 20;
        let mut runs = BTreeMap::new();
        loop {
            let first = u64_at(at);
            let count = usize::try_from(u32_at(at + 8)).expect("a count");
            at += 12;
            if count == 0 {
                break;
            }
            for (i, block) in (first..).zip(bytes[at..at + count * dump_size].chunks(dump_size)) {
                runs.insert(i * dump_size as u64, block.to_vec());
            }
            at += count * dump_size;
        }
        // The container's block size, from its superblock in block zero.
        let size = usize::try_from(u32::from_le_bytes(
            runs[&0][36..40].try_into().expect("a block size"),
        ))
        .expect("a block size");
        let mut blocks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for (offset, piece) in runs {
            let block = offset / size as u64;
            let within = usize::try_from(offset % size as u64).expect("within a block");
            let whole = blocks.entry(block).or_insert_with(|| vec![0u8; size]);
            whole[within..within + piece.len()].copy_from_slice(&piece);
        }
        (len, blocks)
    }

    /// Clear, in every block that is a whole object, the fields `newfs_apfs` and this writer
    /// fill from different inputs, and checksum the object again:
    ///
    /// - the container superblock's identifier, its counters and the newest version to have
    ///   mounted it;
    /// - a volume superblock's identifier, when it was last changed, and who formatted it and
    ///   when;
    /// - in a file-system tree's node, each inode's four times and each directory entry's
    ///   time;
    /// - where `crypto` says, a volume's 20 metadata-crypto bytes, which `newfs_apfs` fills on
    ///   an attached disk and leaves zero in a file.
    ///
    /// Blocks of zeros are dropped, so a container is the set of blocks it holds. Every other
    /// byte, checksums of objects with no field cleared among them, is left as it is.
    fn normalize(blocks: &mut BTreeMap<u64, Vec<u8>>, crypto: bool) {
        let clear = |block: &mut [u8], range: std::ops::Range<usize>| block[range].fill(0);
        for block in blocks.values_mut() {
            let head = ObjectHeader::read_from(block).expect("a header");
            let cleared = matches!(
                (head.kind(), u16::try_from(head.subtype).ok()),
                (kind::CONTAINER_SUPERBLOCK | kind::VOLUME_SUPERBLOCK, _)
                    | (kind::BTREE_ROOT | kind::BTREE_NODE, Some(kind::FS_TREE))
            );
            if !cleared || !verify(block) {
                continue;
            }
            match (head.kind(), u16::try_from(head.subtype).ok()) {
                (kind::CONTAINER_SUPERBLOCK, _) => {
                    clear(block, 72..88);
                    clear(block, 984..1240);
                    clear(block, 1384..1392);
                }
                (kind::VOLUME_SUPERBLOCK, _) => {
                    clear(block, 240..264);
                    clear(block, 272..312);
                    if crypto {
                        clear(block, 96..116);
                    }
                }
                (kind::BTREE_ROOT | kind::BTREE_NODE, Some(kind::FS_TREE)) => {
                    clear_record_times(block);
                }
                _ => continue,
            }
            seal(block);
        }
        blocks.retain(|_, block| block.iter().any(|b| *b != 0));
    }

    /// Clear each inode's four times and each directory entry's time in one file-system node.
    fn clear_record_times(block: &mut [u8]) {
        let u16_at = |b: &[u8], at: usize| usize::from(u16::from_le_bytes([b[at], b[at + 1]]));
        let flags = u16_at(block, 32);
        let count = u32::from_le_bytes(block[36..40].try_into().expect("4"));
        let table = u16_at(block, 42);
        let key_area = NODE_DATA_START + table;
        let value_end = if flags & usize::from(node_flags::ROOT) != 0 {
            block.len() - TREE_INFO_SIZE
        } else {
            block.len()
        };
        for i in 0..usize::try_from(count).expect("a count") {
            let entry = NODE_DATA_START + 8 * i;
            let key = key_area + u16_at(block, entry);
            let value = value_end - u16_at(block, entry + 4);
            let kind = (u64::from_le_bytes(block[key..key + 8].try_into().expect("8")) >> 60) as u8;
            match kind {
                record_kind::INODE => block[value + 16..value + 48].fill(0),
                record_kind::DIR_ENTRY => block[value + 8..value + 16].fill(0),
                _ => {}
            }
        }
    }

    /// The first 64 bits of the SHA-256 of a normalized container: each block's address and
    /// bytes, in order.
    fn digest(blocks: &BTreeMap<u64, Vec<u8>>) -> String {
        let mut sha = Sha256::new();
        for (block, bytes) in blocks {
            sha.update(block.to_le_bytes());
            sha.update(bytes);
        }
        sha.finalize()[..8]
            .iter()
            .fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
    }

    /// What formatted a container besides its size: the set it was measured in, how its volume
    /// compares names, the root directory's owner and group, whether its metadata-crypto bytes
    /// are cleared, and its volume's name.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Inputs {
        set: String,
        names: NameKind,
        owner: u32,
        group: u32,
        crypto: bool,
        volume: String,
    }

    impl Inputs {
        /// The fixture's line naming these inputs, which the shapes under it share.
        fn line(&self) -> String {
            let hex: String = self.volume.bytes().fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            });
            format!(
                "@ {} {} {} {} {} {hex}",
                self.set,
                match self.names {
                    NameKind::CaseFolding => "fold",
                    NameKind::CaseKeeping => "keep",
                },
                self.owner,
                self.group,
                if self.crypto { "crypto" } else { "-" },
            )
        }

        fn parse(line: &str) -> Self {
            let w: Vec<&str> = line.split(' ').collect();
            assert_eq!((w.len(), w[0]), (7, "@"), "{line}");
            let volume: Vec<u8> = (0..w[6].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&w[6][i..i + 2], 16).expect("hex"))
                .collect();
            Self {
                set: w[1].to_string(),
                names: match w[2] {
                    "fold" => NameKind::CaseFolding,
                    "keep" => NameKind::CaseKeeping,
                    other => panic!("name kind {other}"),
                },
                owner: w[3].parse().expect("an owner"),
                group: w[4].parse().expect("a group"),
                crypto: w[5] == "crypto",
                volume: String::from_utf8(volume).expect("a UTF-8 name"),
            }
        }
    }

    /// One shape of the fixture: a container's inputs, size and block size, how many
    /// containers of it were measured, and its digest under macOS 14 and 15 and under 26 and
    /// 27.
    #[derive(Clone, Debug)]
    struct Shape {
        inputs: Inputs,
        name: String,
        block_size: u32,
        bytes: u64,
        measured: usize,
        digests: [String; 2],
    }

    /// The two pairs of releases that write the same bytes, each with the profile the gate
    /// writes it under.
    const PAIRS: [(&str, &str, ReleaseProfile); 2] = [
        ("14", "15", ReleaseProfile::Macos14),
        ("26", "27", ReleaseProfile::Macos26),
    ];

    impl Shape {
        fn line(&self) -> String {
            format!(
                "{} {} {} {} {} {}",
                self.name,
                self.block_size,
                self.bytes,
                self.measured,
                self.digests[0],
                self.digests[1]
            )
        }

        fn parse(inputs: &Inputs, line: &str) -> Self {
            let w: Vec<&str> = line.split(' ').collect();
            assert_eq!(w.len(), 6, "{line}");
            Self {
                inputs: inputs.clone(),
                name: w[0].to_string(),
                block_size: w[1].parse().expect("a block size"),
                bytes: w[2].parse().expect("a size"),
                measured: w[3].parse().expect("a count"),
                digests: [w[4].to_string(), w[5].to_string()],
            }
        }

        /// What the writer is given to format this container under `profile`: its inputs, and
        /// identifiers and a time of the gate's own, which the comparison clears.
        fn options(&self, profile: ReleaseProfile) -> FormatOptions {
            let volume = VolumeRequest::new(
                VolumeName::new(&self.inputs.volume).expect("a volume name"),
                [0x22; 16],
            )
            .names(self.inputs.names)
            .root_owned_by(self.inputs.owner, self.inputs.group);
            FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), volume)
                .block_size(block_size(self.block_size))
                .profile(profile)
        }

        /// The writer's container under `profile`, normalized.
        ///
        /// A container below the floor the writer refuses is laid out by the planner's rules
        /// all the same, and its blocks assembled as the writer assembles any other's: the
        /// rules hold there, and `newfs_apfs` formats it.
        fn written(&self, profile: ReleaseProfile) -> BTreeMap<u64, Vec<u8>> {
            let options = self.options(profile);
            let mut sink = Sparse::default();
            let mut blocks = match format_to(&mut sink, nothing(), self.bytes, options.clone()) {
                Ok(_) => sink.blocks(self.block_size as usize),
                Err(FormatError::Geometry(GeometryError::ContainerTooSmall {
                    block_count,
                    ..
                })) => {
                    let layout = super::super::geometry::layout_of(block_count, self.block_size, 1);
                    let (models, volumes) = empty_volumes(&layout, &options);
                    assemble(&layout, &options, &models, &volumes).map
                }
                Err(e) => panic!("{} {}: {e}", self.inputs.set, self.name),
            };
            normalize(&mut blocks, self.inputs.crypto);
            blocks
        }
    }

    fn block_size(bytes: u32) -> BlockSize {
        match bytes {
            4096 => BlockSize::K4,
            8192 => BlockSize::K8,
            16384 => BlockSize::K16,
            32768 => BlockSize::K32,
            65536 => BlockSize::K64,
            other => panic!("block size {other}"),
        }
    }

    fn shapes() -> Vec<Shape> {
        let mut inputs = None;
        let mut out = Vec::new();
        for line in NEWFS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            if line.starts_with("@ ") {
                inputs = Some(Inputs::parse(line));
            } else {
                out.push(Shape::parse(
                    inputs.as_ref().expect("a shape follows its inputs"),
                    line,
                ));
            }
        }
        out
    }

    /// `f` of every item, over as many threads as the machine has.
    fn in_parallel<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
        let threads = std::thread::available_parallelism().map_or(1, usize::from);
        let per = items.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            let f = &f;
            let handles: Vec<_> = items
                .chunks(per)
                .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<R>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a thread of the gate"))
                .collect()
        })
    }

    #[test]
    fn every_container_newfs_apfs_formatted_is_written_as_it_wrote_it() {
        let shapes = shapes();
        assert_eq!(shapes.len(), SHAPES, "the fixture's shapes");
        assert_eq!(
            shapes.iter().map(|s| s.measured).sum::<usize>(),
            CONTAINERS,
            "the containers they stand for"
        );
        let differ: Vec<String> = in_parallel(&shapes, |shape| {
            PAIRS
                .iter()
                .zip(&shape.digests)
                .filter(|((_, _, profile), digest)| {
                    self::digest(&shape.written(*profile)) != **digest
                })
                .map(|((first, second, _), _)| {
                    format!(
                        "{} {} on {first} and {second}",
                        shape.inputs.set, shape.name
                    )
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        assert!(differ.is_empty(), "{} differ: {differ:#?}", differ.len());
    }

    #[test]
    fn macos_15_is_written_as_14_and_27_as_26() {
        // The profile's one effect: the two words of the volume superblock. Every shape the
        // fixture holds has one digest for each pair, so the pair must write one container.
        for bytes in [64 << 20, 1 << 40] {
            let shape = shapes()
                .into_iter()
                .find(|s| s.bytes == bytes && s.block_size == 4096)
                .expect("a shape of that size");
            let image = |profile| {
                let mut sink = Sparse::default();
                format_to(&mut sink, nothing(), bytes, shape.options(profile)).expect("formats");
                sink.blocks(4096)
            };
            assert_eq!(
                image(ReleaseProfile::Macos14),
                image(ReleaseProfile::Macos15)
            );
            assert_eq!(
                image(ReleaseProfile::Macos26),
                image(ReleaseProfile::Macos27)
            );
            assert_ne!(
                image(ReleaseProfile::Macos14),
                image(ReleaseProfile::Macos26)
            );
        }
    }

    /// The release a runner's label names: macOS 15 and 26 on Intel are 15 and 26.
    fn release_of(runner: &str) -> &str {
        runner.strip_suffix("-intel").unwrap_or(runner)
    }

    /// The block-by-block comparison behind the fixture, over the block dumps `newfs_apfs`
    /// made, named by a manifest at `FERROSYS_APFS_NEWFS`: a line per container of its release,
    /// set, name, dump path and mask (`crypto` or `-`), tab-separated. With
    /// `FERROSYS_BLESS_APFS_NEWFS` set as well it writes the fixture from the dumps, never from
    /// the writer, once each release pair is seen to agree. Without the manifest there is
    /// nothing to compare and it passes.
    #[test]
    fn every_newfs_dump_on_hand_is_written_block_for_block() {
        let Some(manifest) = std::env::var_os("FERROSYS_APFS_NEWFS") else {
            return;
        };
        let manifest = std::fs::read_to_string(manifest).expect("the manifest");
        let rows: Vec<Vec<String>> = manifest
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect();
        // Each container: its release, shape and digest, and how it differs from the writer's.
        let measured = in_parallel(&rows, |w| {
            let (len, mut apple) = read_dump(&std::fs::read(&w[3]).expect("a dump"));
            let size = apple[&0].len();
            let held = |blocks: &BTreeMap<u64, Vec<u8>>| Held {
                size,
                len,
                blocks: blocks.clone(),
                pos: 0,
            };
            let mut reader = Reader::open(held(&apple)).unwrap_or_else(|e| panic!("{w:?}: {e}"));
            let superblock = reader.superblock().clone();
            let root = reader.root().expect("the root directory");
            let block_size = Container::open(held(&apple))
                .expect("the container")
                .block_size();
            let inputs = Inputs {
                set: w[1].clone(),
                names: if superblock.is_case_insensitive() {
                    NameKind::CaseFolding
                } else {
                    NameKind::CaseKeeping
                },
                owner: root.value.owner,
                group: root.value.group,
                crypto: w[4] == "crypto",
                volume: String::from_utf8(superblock.name_bytes().to_vec()).expect("UTF-8"),
            };
            normalize(&mut apple, inputs.crypto);
            let shape = Shape {
                inputs,
                name: w[2].clone(),
                block_size,
                bytes: len,
                measured: 1,
                digests: [String::new(), String::new()],
            };
            let profile = PAIRS
                .iter()
                .find(|(a, b, _)| release_of(&w[0]) == *a || release_of(&w[0]) == *b)
                .map(|(_, _, profile)| *profile)
                .expect("a release the fixture names");
            let written = shape.written(profile);
            let mut faults = Vec::new();
            for block in apple
                .keys()
                .chain(written.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                match (apple.get(block), written.get(block)) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(a), Some(b)) => {
                        let at: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
                        let (first, last) = (at[0], at[at.len() - 1]);
                        faults.push(format!(
                            "block {block}: {} bytes differ, {first}..={last}; newfs {:02x?} writer {:02x?}",
                            at.len(),
                            &a[first..(first + 16).min(a.len())],
                            &b[first..(first + 16).min(b.len())]
                        ));
                    }
                    (Some(_), None) => {
                        faults.push(format!("block {block}: only newfs_apfs wrote it"))
                    }
                    (None, Some(_)) => {
                        faults.push(format!("block {block}: only the writer wrote it"))
                    }
                    (None, None) => unreachable!(),
                }
            }
            let fault = (!faults.is_empty())
                .then(|| format!("{} {} {}:\n  {}", w[0], w[1], w[2], faults.join("\n  ")));
            (w[0].clone(), shape, digest(&apple), fault)
        });
        let report: Vec<&String> = measured.iter().filter_map(|m| m.3.as_ref()).collect();

        if std::env::var_os("FERROSYS_BLESS_APFS_NEWFS").is_some() {
            // One line per shape, in the order the manifest first names it: the same inputs on
            // every release, and one digest for each pair of releases.
            let mut order: Vec<(String, String)> = Vec::new();
            // By set and name: each release's shape and digest.
            type Seen = Vec<(String, Shape, String)>;
            let mut by: BTreeMap<(String, String), Seen> = BTreeMap::new();
            for (release, shape, digest, _) in &measured {
                let key = (shape.inputs.set.clone(), shape.name.clone());
                if !by.contains_key(&key) {
                    order.push(key.clone());
                }
                by.entry(key)
                    .or_default()
                    .push((release.clone(), shape.clone(), digest.clone()));
            }
            let mut lines = vec![
                "# Every empty container newfs_apfs formatted that the APFS writer is held to."
                    .to_string(),
                "# `@ set name-kind owner group mask volume-name-in-hex` names the inputs of the"
                    .to_string(),
                "# shapes under it; each shape is its name, block size, bytes, how many containers"
                    .to_string(),
                "# of it were measured, and the first 64 bits of the SHA-256 of its blocks with"
                    .to_string(),
                "# the fields the gate clears cleared, on macOS 14 and 15, then on 26 and 27."
                    .to_string(),
            ];
            let mut header = String::new();
            for key in &order {
                let seen = &by[key];
                let first = &seen[0].1;
                let mut digests = [String::new(), String::new()];
                for (pair, (a, b, _)) in PAIRS.iter().enumerate() {
                    let found: std::collections::BTreeSet<&String> = seen
                        .iter()
                        .filter(|(release, _, _)| {
                            release_of(release) == *a || release_of(release) == *b
                        })
                        .map(|(_, _, digest)| digest)
                        .collect();
                    assert_eq!(found.len(), 1, "{key:?}: one digest on {a} and {b}");
                    digests[pair] = (*found.first().expect("a digest")).clone();
                }
                for (release, shape, _) in seen {
                    assert!(
                        shape.inputs == first.inputs
                            && shape.bytes == first.bytes
                            && shape.block_size == first.block_size,
                        "{key:?}: the inputs on {release} are the first release's"
                    );
                }
                let releases: std::collections::BTreeSet<&str> = seen
                    .iter()
                    .map(|(release, _, _)| release_of(release))
                    .collect();
                assert_eq!(releases.len(), 4, "{key:?}: measured on every release");
                if first.inputs.line() != header {
                    header = first.inputs.line();
                    lines.push(header.clone());
                }
                lines.push(
                    Shape {
                        measured: seen.len(),
                        digests,
                        ..first.clone()
                    }
                    .line(),
                );
            }
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/apfs/fixtures/newfs-images.txt"
            );
            std::fs::write(path, lines.join("\n") + "\n").expect("the fixture");
        }
        assert!(
            report.is_empty(),
            "{} containers differ:\n{}",
            report.len(),
            report
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// A written container, opened as a seekable source.
    fn held(sink: &Sparse, size: usize, len: u64) -> Held {
        Held {
            size,
            len,
            blocks: sink.blocks(size),
            pos: 0,
        }
    }

    /// Open every volume of a written container strictly, scan it, and hold what it reads back
    /// to what the options asked for.
    fn read_back(options: &FormatOptions, bytes: u64) {
        let size = options.block_size.bytes() as usize;
        let mut sink = Sparse::default();
        let layout =
            format_to(&mut sink, nothing(), bytes, options.clone()).expect("the container formats");
        let container = Container::open(held(&sink, size, bytes)).expect("the container opens");
        assert_eq!(container.superblock().uuid, options.uuid);
        assert_eq!(container.superblock().block_count, layout.block_count);
        assert_eq!(container.volumes().len(), options.volumes.len());
        assert!(container.unreadable_volumes().is_empty());
        let time = i64::try_from(nanos_since_epoch(options.time).expect("a time")).expect("a time");
        for (entry, request) in container.volumes().iter().zip(&options.volumes) {
            let mut reader = Reader::over(
                Container::open(held(&sink, size, bytes)).expect("opens"),
                entry.clone(),
            )
            .expect("the volume opens");
            let found = reader.scan();
            assert!(
                found.anomalies().is_empty(),
                "{bytes} bytes, {} volumes, slot {}: {found:?}",
                options.volumes.len(),
                entry.slot
            );
            let superblock = reader.superblock().clone();
            assert_eq!(superblock.name_bytes(), request.name.as_str().as_bytes());
            assert_eq!(superblock.uuid, request.uuid);
            assert_eq!(
                superblock.is_case_insensitive(),
                request.names == NameKind::CaseFolding
            );
            assert_eq!(
                superblock.formatted_by.name(),
                options.formatted_by.as_bytes()
            );
            let root = reader.root().expect("the root directory");
            assert!(root.is_dir());
            assert_eq!(
                (root.value.owner, root.value.group),
                (request.root_owner, request.root_group)
            );
            assert_eq!(root.value.mode, 0o040_755);
            assert_eq!(root.value.create_time, time);
            assert!(reader.read_dir(&root).expect("the root lists").is_empty());
            assert_eq!(reader.walk().expect("the volume walks").len(), 1);
        }
    }

    #[test]
    fn every_container_written_opens_strictly_and_scans_clean() {
        // Every shape the fixture holds that the writer formats, as newfs_apfs's options had
        // it, under each pair's profile.
        let shapes: Vec<Shape> = shapes()
            .into_iter()
            .filter(|s| {
                s.bytes / u64::from(s.block_size) >= super::super::geometry::MIN_BLOCK_COUNT
            })
            .collect();
        in_parallel(&shapes, |shape| {
            for (_, _, profile) in PAIRS {
                read_back(&shape.options(profile), shape.bytes);
            }
        });
    }

    #[test]
    fn a_container_of_several_volumes_opens_strictly_and_scans_clean() {
        let volume = |slot: u8, names: NameKind| {
            VolumeRequest::new(
                VolumeName::new(&format!("Volume {slot}")).expect("a name"),
                [slot + 1; 16],
            )
            .names(names)
            .root_owned_by(u32::from(slot), 20)
        };
        // Each block size, each name kind, each profile, below and past the contiguous limit,
        // and the most volumes a container of each size has room for.
        let shapes: [(BlockSize, u64, u32); 6] = [
            (BlockSize::K4, 4 << 30, 8),
            (BlockSize::K4, 64 << 30, 100),
            (BlockSize::K8, 16 << 30, 32),
            (BlockSize::K16, 1 << 40, 3),
            (BlockSize::K32, 6 << 30, 12),
            (BlockSize::K64, 128 << 30, 2),
        ];
        let profiles = [
            ReleaseProfile::Macos14,
            ReleaseProfile::Macos15,
            ReleaseProfile::Macos26,
            ReleaseProfile::Macos27,
        ];
        for (i, (block_size, bytes, volumes)) in shapes.into_iter().enumerate() {
            let kind = |slot: u32| {
                if (slot + i as u32).is_multiple_of(2) {
                    NameKind::CaseFolding
                } else {
                    NameKind::CaseKeeping
                }
            };
            let mut options = FormatOptions::new(
                [0xF0; 16],
                Timestamp {
                    secs: 1_700_000_000,
                    nanos: 123_456_789,
                },
                volume(0, kind(0)),
            )
            .block_size(block_size)
            .profile(profiles[i % profiles.len()])
            .formatted_by(ProgramName::new(b"gate (1)").expect("a name"));
            for slot in 1..volumes {
                options = options.volume(volume(u8::try_from(slot).expect("a slot"), kind(slot)));
            }
            read_back(&options, bytes);
        }
    }

    #[test]
    fn two_formats_of_one_options_are_the_same_bytes() {
        let options = FormatOptions::new(
            [0x11; 16],
            Timestamp::from_secs(1_700_000_000),
            VolumeRequest::new(VolumeName::new("Data").expect("a name"), [0x22; 16]),
        );
        let first = format(nothing(), 64 << 20, options.clone()).expect("formats");
        let second = format(nothing(), 64 << 20, options).expect("formats");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.as_bytes().len(), 64 << 20);
    }

    #[test]
    fn an_identifier_zero_or_repeated_and_a_time_out_of_range_are_refused() {
        let volume =
            |uuid: [u8; 16]| VolumeRequest::new(VolumeName::new("Data").expect("a name"), uuid);
        let time = Timestamp::from_secs(0);
        let plan = |options: FormatOptions| FormatPlan::new(nothing(), 64 << 20, options).err();
        assert!(matches!(
            plan(FormatOptions::new([0; 16], time, volume([2; 16]))),
            Some(FormatError::ZeroIdentifier {
                which: Identifier::Container
            })
        ));
        assert!(matches!(
            plan(FormatOptions::new([1; 16], time, volume([2; 16])).volume(volume([0; 16]))),
            Some(FormatError::ZeroIdentifier {
                which: Identifier::Volume(1)
            })
        ));
        assert!(matches!(
            plan(FormatOptions::new([1; 16], time, volume([1; 16]))),
            Some(FormatError::RepeatedIdentifier {
                first: Identifier::Container,
                second: Identifier::Volume(0)
            })
        ));
        assert!(matches!(
            plan(FormatOptions::new([1; 16], time, volume([2; 16])).volume(volume([2; 16]))),
            Some(FormatError::RepeatedIdentifier {
                first: Identifier::Volume(0),
                second: Identifier::Volume(1)
            })
        ));
        let snapshot = |uuid: [u8; 16]| RootSnapshot::new("root", uuid).expect("a snapshot");
        assert!(matches!(
            plan(FormatOptions::new(
                [1; 16],
                time,
                volume([2; 16]).root_snapshot(snapshot([0; 16]))
            )),
            Some(FormatError::ZeroIdentifier {
                which: Identifier::Snapshot(0)
            })
        ));
        assert!(matches!(
            plan(
                FormatOptions::new([1; 16], time, volume([2; 16]))
                    .volume(volume([3; 16]).root_snapshot(snapshot([2; 16])))
            ),
            Some(FormatError::RepeatedIdentifier {
                first: Identifier::Volume(0),
                second: Identifier::Snapshot(1)
            })
        ));
        assert!(matches!(
            plan(
                FormatOptions::new(
                    [1; 16],
                    time,
                    volume([2; 16]).root_snapshot(snapshot([4; 16]))
                )
                .volume(volume([3; 16]).root_snapshot(snapshot([4; 16])))
            ),
            Some(FormatError::RepeatedIdentifier {
                first: Identifier::Snapshot(0),
                second: Identifier::Snapshot(1)
            })
        ));
        for secs in [-1, i64::MAX / 1_000_000_000 + 1] {
            let time = Timestamp::from_secs(secs);
            assert!(matches!(
                plan(FormatOptions::new([1; 16], time, volume([2; 16]))),
                Some(FormatError::TimeOutOfRange { .. })
            ));
        }
        // Zero is the earliest time, and the format's own tools accept it.
        assert!(plan(FormatOptions::new([1; 16], time, volume([2; 16]))).is_none());
        // A fraction of a second of a second or more is no time, whether the root takes the
        // format's instant or the source states the root's own times.
        let stated_root = || {
            crate::TreeBuilder::new().directory("/", Metadata::new(0o755, Timestamp::from_secs(9)))
        };
        for nanos in [999_999_999, 1_000_000_000, 1_500_000_000] {
            let time = Timestamp {
                secs: 1_700_000_000,
                nanos,
            };
            let options = FormatOptions::new([1; 16], time, volume([2; 16]));
            let refused = nanos >= Timestamp::NANOS_PER_SEC;
            for result in [
                FormatPlan::new(nothing(), 4 << 20, options.clone()),
                FormatPlan::new(stated_root(), 4 << 20, options),
            ] {
                match result {
                    Err(FormatError::TimeOutOfRange { time: t }) => {
                        assert!(refused, "{nanos}");
                        assert_eq!(t, time);
                    }
                    Ok(_) => assert!(!refused, "{nanos}"),
                    Err(e) => panic!("{nanos}: {e}"),
                }
            }
        }
        let mut none = FormatOptions::new([1; 16], time, volume([2; 16]));
        none.volumes.clear();
        assert!(matches!(
            plan(none),
            Some(FormatError::Geometry(GeometryError::NoVolumes))
        ));
    }

    #[test]
    fn a_name_empty_too_long_or_holding_a_nul_is_refused() {
        assert_eq!(VolumeName::new(""), Err(NameError::Empty));
        assert_eq!(
            VolumeName::new(&"n".repeat(256)),
            Err(NameError::TooLong {
                bytes: 256,
                max: 255
            })
        );
        assert_eq!(VolumeName::new("a\0b"), Err(NameError::Nul { at: 1 }));
        assert!(VolumeName::new(&"n".repeat(255)).is_ok());
        assert_eq!(ProgramName::new(b""), Err(NameError::Empty));
        assert!(ProgramName::new(&[b'p'; 31]).is_ok());
        assert!(matches!(
            ProgramName::new(&[b'p'; 32]),
            Err(NameError::TooLong { bytes: 32, max: 31 })
        ));
    }

    // -----------------------------------------------------------------------
    // The images macOS is asked to accept

    /// The empty containers macOS is asked to judge, each with the change made to it after it is
    /// written, the digest of what is sent, what macOS is expected to make of it and the
    /// releases whose batch found that.
    const ACCEPT: &str = include_str!("fixtures/accept-images.txt");

    /// The images the fixture holds: a fixture that lost a line sends less.
    const SENT: usize = 70;

    /// The offset in a volume superblock of the name's first byte, which `neg-checksum`
    /// changes.
    const VOLUME_NAME_AT: usize = 704;

    /// What an image's first volume holds: nothing, a tree [`super::populated::tree_up_to`]
    /// generates, as `tree:N:DIRS:SEED:MAX`, or a corpus volume taken through the steps
    /// [`super::from_corpus::built`] names, as `corpus:RELEASE:ROW:VOLUME:SHA256`.
    #[derive(Clone, PartialEq, Eq, Debug)]
    enum Filled {
        Nothing,
        Tree {
            n: usize,
            dirs: usize,
            seed: u64,
            max: u64,
        },
        Corpus(CorpusVolume),
    }

    /// A volume of the corpus [`apfs_corpus`] finds: the release's directory without its
    /// `corpus-`, the container's row, the volume's name, and the SHA-256 of the row's block
    /// dump, which the volume is read from only where it matches.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub(super) struct CorpusVolume {
        pub(super) release: String,
        pub(super) row: String,
        pub(super) volume: String,
        pub(super) sha256: String,
    }

    impl Filled {
        fn parse(token: &str) -> Self {
            if token == "-" {
                return Self::Nothing;
            }
            if let Some(corpus) = token.strip_prefix("corpus:") {
                let w: Vec<&str> = corpus.split(':').collect();
                assert_eq!(w.len(), 4, "{token}");
                assert_eq!(w[3].len(), 64, "{token}: a whole SHA-256");
                return Self::Corpus(CorpusVolume {
                    release: w[0].to_string(),
                    row: w[1].to_string(),
                    volume: w[2].to_string(),
                    sha256: w[3].to_string(),
                });
            }
            let w: Vec<&str> = token
                .strip_prefix("tree:")
                .expect("tree:N:DIRS:SEED:MAX")
                .split(':')
                .collect();
            assert_eq!(w.len(), 4, "{token}");
            Self::Tree {
                n: w[0].parse().expect("entries"),
                dirs: w[1].parse().expect("directories"),
                seed: w[2].parse().expect("a seed"),
                max: w[3].parse().expect("a largest file"),
            }
        }

        fn token(&self) -> String {
            match self {
                Self::Nothing => "-".to_string(),
                Self::Tree { n, dirs, seed, max } => format!("tree:{n}:{dirs}:{seed}:{max}"),
                Self::Corpus(v) => {
                    format!("corpus:{}:{}:{}:{}", v.release, v.row, v.volume, v.sha256)
                }
            }
        }
    }

    /// What macOS is expected to make of an image.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Expect {
        /// `fsck_apfs` passes it, macOS lists and mounts it as the reader reads it, and a file
        /// written to it read-write leaves a container `fsck_apfs` passes.
        Accept,
        /// Some check of [`Accept`](Self::Accept) fails.
        Refuse,
        /// As [`Accept`](Self::Accept), but that the time is later than the clock of the runner
        /// checking it, and `fsck_apfs -W` warns of that and of nothing else.
        WarnFutureTime,
        /// As [`Accept`](Self::Accept), but that macOS finds too little room in the container to
        /// take the file: every volume mounts read-write and refuses it for want of room,
        /// `fsck_apfs` passes the container after, and every volume mounts again holding no file
        /// or a part of the one written, from its start. A container with no block free is one,
        /// and so is one with fewer free blocks than macOS sets aside before it writes.
        Full,
        /// As [`Accept`](Self::Accept), and before the probe's file the runner's own user writes
        /// this many bytes into the first volume, a mebibyte a write, and every write is taken:
        /// the room [`FormatPlan::fit`] was asked to leave.
        Room(u64),
    }

    impl Expect {
        fn token(self) -> String {
            match self {
                Self::Accept => "accept".to_string(),
                Self::Refuse => "refuse".to_string(),
                Self::WarnFutureTime => "warn-future-time".to_string(),
                Self::Full => "full".to_string(),
                Self::Room(bytes) => format!("room:{bytes}"),
            }
        }

        fn parse(token: &str) -> Self {
            if let Some(bytes) = token.strip_prefix("room:") {
                return Self::Room(bytes.parse().expect("a count of bytes"));
            }
            [Self::Accept, Self::Refuse, Self::WarnFutureTime, Self::Full]
                .into_iter()
                .find(|e| e.token() == token)
                .unwrap_or_else(|| panic!("expectation {token}"))
        }
    }

    /// What is changed in an image after the writer writes it, in the newest checkpoint.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Change {
        /// Nothing.
        None,
        /// One byte of the first volume's superblock, its checksum left as it was.
        Checksum,
        /// Free queue `queue`'s node limit, set to `limit` in a space manager checksummed again.
        Limit { queue: usize, limit: u16 },
    }

    impl Change {
        fn token(self) -> String {
            match self {
                Self::None => "-".to_string(),
                Self::Checksum => "checksum".to_string(),
                Self::Limit { queue, limit } => format!("{}-limit:{limit}", queue_token(queue)),
            }
        }

        fn parse(token: &str) -> Self {
            match token {
                "-" => Self::None,
                "checksum" => Self::Checksum,
                _ => {
                    let (queue, limit) = token
                        .split_once("-limit:")
                        .unwrap_or_else(|| panic!("change {token}"));
                    let queue = match queue {
                        "pool" => SpaceManager::INTERNAL_POOL,
                        "main" => SpaceManager::MAIN_QUEUE,
                        other => panic!("queue {other}"),
                    };
                    Self::Limit {
                        queue,
                        limit: limit.parse().expect("a node limit"),
                    }
                }
            }
        }
    }

    const fn queue_token(queue: usize) -> &'static str {
        match queue {
            SpaceManager::INTERNAL_POOL => "pool",
            _ => "main",
        }
    }

    pub(super) fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// An identifier as `diskutil` prints one.
    fn uuid_text(id: &[u8; 16]) -> String {
        let hex = to_hex(id).to_uppercase();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    const fn kind_token(kind: NameKind) -> &'static str {
        match kind {
            NameKind::CaseFolding => "fold",
            NameKind::CaseKeeping => "keep",
        }
    }

    fn profile_of(token: &str) -> ReleaseProfile {
        match token {
            "14" => ReleaseProfile::Macos14,
            "15" => ReleaseProfile::Macos15,
            "26" => ReleaseProfile::Macos26,
            "27" => ReleaseProfile::Macos27,
            other => panic!("profile {other}"),
        }
    }

    /// How many keys a free queue's node absorbs, taking `frees` in the order the writer does:
    /// a run that ends where a later free begins is extended, and a run that begins where the
    /// extended one now ends is taken into it, its key deleted.
    fn absorbed(frees: &[BlockRange]) -> usize {
        let mut runs: BTreeMap<u64, u64> = BTreeMap::new();
        let mut absorbed = 0;
        for run in frees {
            let before = runs
                .iter()
                .find(|(start, count)| **start + **count == run.start)
                .map(|(start, _)| *start);
            let start = before.unwrap_or(run.start);
            *runs.entry(start).or_insert(0) += run.count;
            let end = start + runs[&start];
            if let Some(count) = runs.remove(&end) {
                *runs.get_mut(&start).expect("the run just freed") += count;
                absorbed += 1;
            }
        }
        absorbed
    }

    /// One image of the set, as its line has it.
    #[derive(Clone, Debug)]
    struct Sent {
        name: String,
        block_size: u32,
        bytes: u64,
        profile: String,
        time: Timestamp,
        owner: u32,
        group: u32,
        program: Vec<u8>,
        /// Each volume's kind and name, and the name of its root snapshot where it has one.
        volumes: Vec<(NameKind, String, Option<String>)>,
        /// What the first volume holds.
        source: Filled,
        /// What each volume after the first holds, in slot order; a volume past the list holds
        /// nothing.
        others: Vec<Filled>,
        /// The System and Data volumes of the volume group, where two form one.
        volume_group: Option<VolumeGroup>,
        /// How many firmlinks the group's System volume is given: `/dK` to `dK` for each K
        /// below it, of which those of the root's directories mark one.
        firmlinks: usize,
        change: Change,
        digest: String,
        expect: Expect,
        releases: String,
    }

    impl Sent {
        fn parse(line: &str) -> Self {
            let w: Vec<&str> = line.split(' ').collect();
            assert_eq!(w.len(), 13, "{line}");
            let (secs, nanos) = w[4].split_once('.').expect("seconds.nanoseconds");
            let (owner, group) = w[5].split_once(':').expect("owner:group");
            let mut system = None;
            let mut data = None;
            let volumes = (0u32..)
                .zip(w[7].split(','))
                .map(|(slot, volume)| {
                    let volume = if let Some(rest) = volume.strip_prefix("system/") {
                        system = Some(slot);
                        rest
                    } else if let Some(rest) = volume.strip_prefix("data/") {
                        data = Some(slot);
                        rest
                    } else {
                        volume
                    };
                    let w: Vec<&str> = volume.split(':').collect();
                    assert!(matches!(w.len(), 2 | 3), "kind:name[:snapshot] in {volume}");
                    let kind = match w[0] {
                        "fold" => NameKind::CaseFolding,
                        "keep" => NameKind::CaseKeeping,
                        other => panic!("name kind {other}"),
                    };
                    let text = |hex: &str| String::from_utf8(from_hex(hex)).expect("UTF-8");
                    (kind, text(w[1]), w.get(2).map(|hex| text(hex)))
                })
                .collect();
            let volume_group = match (system, data) {
                (Some(system), Some(data)) => Some(VolumeGroup::new(system, data)),
                (None, None) => None,
                _ => panic!("a group of one System and one Data volume in {line}"),
            };
            let mut firmlinks = 0;
            let mut held = w[8]
                .split(',')
                .map(|token| match token.split_once("+firmlinks:") {
                    Some((token, count)) => {
                        firmlinks = count.parse().expect("a count of firmlinks");
                        Filled::parse(token)
                    }
                    None => Filled::parse(token),
                });
            let source = held.next().expect("the first volume's contents");
            let others = held.collect();
            Self {
                name: w[0].to_string(),
                block_size: w[1].parse().expect("a block size"),
                bytes: w[2].parse().expect("a size"),
                profile: w[3].to_string(),
                time: Timestamp {
                    secs: secs.parse().expect("seconds"),
                    nanos: nanos.parse().expect("nanoseconds"),
                },
                owner: owner.parse().expect("an owner"),
                group: group.parse().expect("a group"),
                program: from_hex(w[6]),
                volumes,
                source,
                others,
                volume_group,
                firmlinks,
                change: Change::parse(w[9]),
                digest: w[10].to_string(),
                expect: Expect::parse(w[11]),
                releases: w[12].to_string(),
            }
        }

        fn line(&self) -> String {
            let volumes: Vec<String> = (0u32..)
                .zip(&self.volumes)
                .map(|(slot, (kind, name, snapshot))| {
                    let role = match self.volume_group {
                        Some(group) if group.system == slot => "system/",
                        Some(group) if group.data == slot => "data/",
                        _ => "",
                    };
                    let mut token =
                        format!("{role}{}:{}", kind_token(*kind), to_hex(name.as_bytes()));
                    if let Some(snapshot) = snapshot {
                        token += &format!(":{}", to_hex(snapshot.as_bytes()));
                    }
                    token
                })
                .collect();
            format!(
                "{} {} {} {} {}.{:09} {}:{} {} {} {} {} {} {} {}",
                self.name,
                self.block_size,
                self.bytes,
                self.profile,
                self.time.secs,
                self.time.nanos,
                self.owner,
                self.group,
                to_hex(&self.program),
                volumes.join(","),
                self.contents_token(),
                self.change.token(),
                self.digest,
                self.expect.token(),
                self.releases
            )
        }

        /// An identifier from `label`: the first 16 bytes of its SHA-256, with the version and
        /// variant bits of a random identifier.
        fn identifier(label: &str) -> [u8; 16] {
            let sha = Sha256::digest(label.as_bytes());
            let mut id: [u8; 16] = sha[..16].try_into().expect("16 bytes");
            id[6] = (id[6] & 0x0f) | 0x40;
            id[8] = (id[8] & 0x3f) | 0x80;
            id
        }

        fn options(&self) -> FormatOptions {
            let volume = |slot: usize| {
                let (kind, name, snapshot) = &self.volumes[slot];
                let request = VolumeRequest::new(
                    VolumeName::new(name).expect("a volume name"),
                    Self::identifier(&format!("volume {slot} {}", self.name)),
                )
                .names(*kind)
                .root_owned_by(self.owner, self.group);
                let request = match self.others.get(slot.wrapping_sub(1)) {
                    Some(filled) if slot > 0 && *filled != Filled::Nothing => {
                        request.contents(Self::entries_of(filled))
                    }
                    _ => request,
                };
                let request = match self.volume_group {
                    Some(group) if group.system as usize == slot && self.firmlinks > 0 => {
                        request.firmlinks(self.firmlink_list())
                    }
                    _ => request,
                };
                match snapshot {
                    Some(snapshot) => request.root_snapshot(
                        RootSnapshot::new(
                            snapshot,
                            Self::identifier(&format!("snapshot {slot} {}", self.name)),
                        )
                        .expect("a snapshot name"),
                    ),
                    None => request,
                }
            };
            let mut options = FormatOptions::new(
                Self::identifier(&format!("container {}", self.name)),
                self.time,
                volume(0),
            )
            .block_size(block_size(self.block_size))
            .profile(profile_of(&self.profile))
            .formatted_by(ProgramName::new(&self.program).expect("a program name"));
            for slot in 1..self.volumes.len() {
                options = options.volume(volume(slot));
            }
            match self.volume_group {
                Some(group) => options.volume_group(group),
                None => options,
            }
        }

        /// The firmlink list the group's System volume is given: `/dK`, a tab and `dK` for
        /// each K below [`firmlinks`](Self::firmlinks).
        fn firmlink_list(&self) -> Firmlinks {
            let text: String = (0..self.firmlinks)
                .map(|k| format!("/d{k}\td{k}\n"))
                .collect();
            Firmlinks::parse(text.as_bytes()).expect("a firmlink list")
        }

        /// The contents field: each volume's, in slot order, the System volume's followed by
        /// its firmlink count where it is given any.
        fn contents_token(&self) -> String {
            let firmlinked = self
                .volume_group
                .filter(|_| self.firmlinks > 0)
                .map(|group| group.system as usize);
            std::iter::once(&self.source)
                .chain(&self.others)
                .enumerate()
                .map(|(slot, filled)| match firmlinked {
                    Some(system) if system == slot => {
                        format!("{}+firmlinks:{}", filled.token(), self.firmlinks)
                    }
                    _ => filled.token(),
                })
                .collect::<Vec<_>>()
                .join(",")
        }

        /// What the first volume holds.
        fn entries(&self) -> Vec<SourceEntry> {
            Self::entries_of(&self.source)
        }

        /// What `filled` holds.
        fn entries_of(filled: &Filled) -> Vec<SourceEntry> {
            match filled {
                Filled::Nothing => nothing(),
                Filled::Tree { n, dirs, seed, max } => {
                    super::populated::tree_up_to(*n, *dirs, *seed, *max)
                }
                Filled::Corpus(volume) => super::from_corpus::built(volume).entries.clone(),
            }
        }

        /// Whether the volume in `slot` holds anything past its root and private directories.
        fn filled(&self, slot: usize) -> bool {
            let filled = if slot == 0 {
                Some(&self.source)
            } else {
                self.others.get(slot - 1)
            };
            filled.is_some_and(|filled| *filled != Filled::Nothing)
        }

        /// The plan the writer makes for this image.
        fn planned(&self) -> FormatPlan {
            FormatPlan::new(self.entries(), self.bytes, self.options())
                .unwrap_or_else(|e| panic!("{}: {e}", self.name))
        }

        /// The layout the writer formats this image to, and its nonzero blocks by index.
        fn written(&self) -> (ApfsLayout, BTreeMap<u64, Vec<u8>>) {
            let plan = self.planned();
            let mut sink = Held::empty(self.block_size as usize);
            plan.write_to(&mut sink)
                .unwrap_or_else(|e| panic!("{}: {e}", self.name));
            let mut blocks = sink.blocks;
            blocks.retain(|_, block| block.iter().any(|b| *b != 0));
            (plan.layout, blocks)
        }

        /// The blocks sent: the writer's, with the change the row names made to them.
        fn sent(
            &self,
            layout: &ApfsLayout,
            written: &BTreeMap<u64, Vec<u8>>,
        ) -> BTreeMap<u64, Vec<u8>> {
            let mut blocks = written.clone();
            let newest = layout.newest();
            match self.change {
                Change::None => {}
                Change::Checksum => {
                    let block = blocks
                        .get_mut(&newest.volumes[0].superblock)
                        .expect("the first volume's superblock");
                    block[VOLUME_NAME_AT] ^= 0xFF;
                    assert!(
                        !verify(block),
                        "{}: the checksum no longer holds",
                        self.name
                    );
                }
                Change::Limit { queue, limit } => {
                    let block = blocks
                        .get_mut(&newest.space_manager)
                        .expect("the space manager");
                    let mut manager = SpaceManager::read_from(block).expect("a space manager");
                    let queue = &mut manager.free_queues[queue];
                    assert_ne!(
                        queue.tree_node_limit, limit,
                        "{}: a limit to change",
                        self.name
                    );
                    queue.tree_node_limit = limit;
                    manager.write_to(block);
                    seal(block);
                    assert!(verify(block), "{}: checksummed again", self.name);
                }
            }
            blocks
        }

        /// What the reader reads of the container as the writer wrote it, held to this line's
        /// inputs: what macOS is to list, mount and stat.
        fn prediction(
            &self,
            layout: &ApfsLayout,
            written: &BTreeMap<u64, Vec<u8>>,
        ) -> serde_json::Value {
            let held = || Held {
                size: self.block_size as usize,
                len: self.bytes,
                blocks: written.clone(),
                pos: 0,
            };
            let options = self.options();
            let container = Container::open(held()).expect("the container opens");
            assert_eq!(container.superblock().uuid, options.uuid);
            assert_eq!(container.superblock().block_count, layout.block_count);
            assert!(container.unreadable_volumes().is_empty());
            let manager = SpaceManager::read_from(&written[&layout.newest().space_manager])
                .expect("a space manager");
            let mut volumes = Vec::new();
            for (entry, request) in container.volumes().iter().zip(&options.volumes) {
                let mut reader =
                    Reader::over(Container::open(held()).expect("opens"), entry.clone())
                        .expect("the volume opens");
                let found = reader.scan();
                assert!(found.anomalies().is_empty(), "{}: {found:?}", self.name);
                let superblock = reader.superblock().clone();
                assert_eq!(superblock.uuid, request.uuid);
                assert_eq!(superblock.name_bytes(), request.name.as_str().as_bytes());
                assert_eq!(
                    superblock.is_case_insensitive(),
                    request.names == NameKind::CaseFolding
                );
                let root = reader.root().expect("the root directory");
                let filled = self.filled(entry.slot);
                let children = names_in(&mut reader, &root);
                assert_eq!(children.is_empty(), !filled, "{}", self.name);
                let value = &root.value;
                let mut volume = serde_json::json!({
                    "slot": entry.slot,
                    "role": superblock.role,
                    "volume_group": uuid_text(&superblock.volume_group),
                    "name": request.name.as_str(),
                    "name_hex": to_hex(superblock.name_bytes()),
                    "uuid": uuid_text(&superblock.uuid),
                    "case_sensitive": !superblock.is_case_insensitive(),
                    "formatted_by": String::from_utf8_lossy(superblock.formatted_by.name()),
                    "allocated_blocks": superblock.allocated_blocks,
                    "root": {
                        "uid": value.owner,
                        "gid": value.group,
                        "mode": value.mode,
                        "flags": value.bsd_flags,
                        "birthtime_ns": value.create_time,
                        "mtime_ns": value.modify_time,
                        "ctime_ns": value.change_time,
                        "atime_ns": value.access_time,
                        "children": children,
                    },
                });
                let live = filled.then(|| manifest(&mut reader));
                if let Some(root) = &request.root_snapshot {
                    // The root snapshot, as `diskutil` lists one, and its tree, which is the
                    // volume's as written: what macOS is to mount through it, before and after
                    // the volume is changed.
                    let listed = reader.snapshots().expect("the snapshots list");
                    assert_eq!(listed.len(), 1, "{}", self.name);
                    assert_eq!(superblock.root_to_xid, listed[0].xid, "{}", self.name);
                    volume["snapshot"] = serde_json::json!({
                        "name": root.name(),
                        "name_hex": to_hex(root.name().as_bytes()),
                        "uuid": uuid_text(&root.uuid()),
                        "xid": listed[0].xid,
                    });
                    let mut view =
                        Reader::over(Container::open(held()).expect("opens"), entry.clone())
                            .expect("the volume opens")
                            .at_snapshot(root.name().as_bytes())
                            .expect("the snapshot opens");
                    let found = view.scan();
                    assert!(found.anomalies().is_empty(), "{}: {found:?}", self.name);
                    let kept = view.root().expect("the root directory");
                    assert_eq!(names_in(&mut view, &kept), children, "{}", self.name);
                    if let Some(live) = &live {
                        assert_eq!(&manifest(&mut view), live, "{}", self.name);
                    }
                }
                if let Some(live) = live {
                    volume["entries"] = live.into();
                    volume["checkseal"] =
                        checkseal(&mut reader, &self.planned(), entry.slot).into();
                }
                volumes.push(volume);
            }
            assert_eq!(volumes.len(), self.volumes.len(), "{}", self.name);
            serde_json::json!({
                "name": self.name,
                "change": self.change.token(),
                "expect": self.expect.token(),
                "profile": self.profile,
                "block_size": self.block_size,
                "bytes": self.bytes,
                "block_count": layout.block_count,
                "container_uuid": uuid_text(&container.superblock().uuid),
                "free_blocks": manager.devices[SpaceManager::MAIN].free_count,
                "volumes": volumes,
            })
        }
    }

    /// The names of the directory `dir` holds, in hex, in byte order.
    fn names_in<R: Read + Seek>(reader: &mut Reader<R>, dir: &crate::apfs::Node) -> Vec<String> {
        let mut names: Vec<String> = reader
            .read_dir(dir)
            .expect("the directory lists")
            .iter()
            .map(|entry| to_hex(&entry.name))
            .collect();
        names.sort();
        names
    }

    /// Every entry of the volume `reader` reads, as the probe's manifest describes an entry of
    /// a mounted volume: what macOS is to report of each through `lstat`, `getattrlist`,
    /// `listxattr` and `getxattr`, `readlink` and a read. `listxattr` lists a resource fork on a
    /// regular file alone: macOS 15, 26 and 27 leave it out on a link, a pipe and a socket that
    /// holds one.
    fn manifest<R: Read + Seek>(reader: &mut Reader<R>) -> Vec<serde_json::Value> {
        let sha = |bytes: &[u8]| to_hex(&Sha256::digest(bytes));
        let mut out = Vec::new();
        for walked in reader.walk().expect("the volume walks") {
            let node = walked.node;
            let v = &node.value;
            let rel = walked.path.strip_prefix(b"/").unwrap_or(&walked.path);
            let regular = v.mode & 0o170_000 == 0o100_000;
            let mut xattrs: Vec<serde_json::Value> = reader
                .xattrs(&node)
                .expect("attributes read")
                .iter()
                .filter(|x| regular || x.name != crate::apfs::ondisk::RESOURCE_FORK_XATTR)
                .map(|x| {
                    serde_json::json!({
                        "name_hex": to_hex(&x.name),
                        "len": x.value.len(),
                        "sha256": sha(&x.value),
                    })
                })
                .collect();
            xattrs.sort_by(|a, b| a["name_hex"].as_str().cmp(&b["name_hex"].as_str()));
            let mut entry = serde_json::json!({
                "path_hex": to_hex(rel),
                "ino": node.inode,
                "mode": v.mode,
                "uid": v.owner,
                "gid": v.group,
                "flags": v.bsd_flags,
                "atime_ns": v.access_time,
                "mtime_ns": v.modify_time,
                "ctime_ns": v.change_time,
                "birthtime_ns": v.create_time,
                "xattrs": xattrs,
            });
            if node.is_dir() {
                entry["children_hex"] = names_in(reader, &node).into();
            } else if node.is_symlink() {
                let target = reader.link_target(&node).expect("a target");
                entry["size"] = target.len().into();
                entry["target_hex"] = to_hex(&target).into();
                entry["nlink"] = v.links_or_children.into();
            } else {
                entry["nlink"] = v.links_or_children.into();
                if let Some(device) = node.device {
                    entry["rdev"] = device.into();
                }
                if v.mode & 0o170_000 == 0o100_000 {
                    let data = reader.read_data(&node).expect("the file reads");
                    entry["size"] = data.len().into();
                    entry["sha256"] = sha(&data).into();
                    entry["read_len"] = data.len().into();
                }
            }
            out.push(entry);
        }
        out
    }

    /// What the seal checker macOS ships beside `fsck_apfs` lists, run with `-q -v`, of the volume
    /// `plan` writes in `slot`:
    /// each entry but the root by path, with its owner, group, mode, flags and, where it holds
    /// data, its size and allocation as the writer recorded them; and each attribute by path and
    /// name, with its flags and, held in its record, its length. Each carries its inode, since
    /// macOS 15, 26 and 27 list the attributes of an inode of several names once, under one of
    /// them, and the attributes are held to the inode rather than to a name.
    fn checkseal<R: Read + Seek>(
        reader: &mut Reader<R>,
        plan: &FormatPlan,
        slot: usize,
    ) -> Vec<serde_json::Value> {
        use crate::apfs::ondisk::{
            DataStream, InodeValue, KeyHeader, XattrValue, extended_fields, field,
        };
        let mut inodes: BTreeMap<u64, serde_json::Value> = BTreeMap::new();
        let mut xattrs: BTreeMap<u64, Vec<serde_json::Value>> = BTreeMap::new();
        for (key, value) in plan.volumes[slot].records.sorted() {
            let header = KeyHeader::read_from(&key).expect("a key");
            match header.kind {
                record_kind::INODE => {
                    let inode = InodeValue::read_from(&value).expect("an inode");
                    let mut held = serde_json::json!({
                        "uid": inode.owner,
                        "gid": inode.group,
                        "mode": inode.mode,
                        "bsd_flags": inode.bsd_flags,
                        "internal_flags": inode.internal_flags,
                    });
                    let fields = extended_fields(&value[InodeValue::SIZE..]).expect("fields");
                    if let Some(stream) = field(&fields, inode_field::DATA_STREAM) {
                        let stream = DataStream::read_from(stream).expect("a stream");
                        held["file_size"] = stream.size.into();
                        held["alloced_size"] = stream.allocated.into();
                    }
                    inodes.insert(header.id, held);
                }
                record_kind::XATTR => {
                    let name = crate::apfs::ondisk::xattr_name(&key).expect("a name");
                    let xattr = XattrValue::read_from(&value).expect("an attribute");
                    let mut held = serde_json::json!({
                        "name_hex": to_hex(name),
                        "flags": xattr.flags,
                    });
                    if xattr.flags & crate::apfs::ondisk::xattr_flags::EMBEDDED != 0 {
                        held["data_len"] = xattr.data.len().into();
                    }
                    xattrs.entry(header.id).or_default().push(held);
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for walked in reader.walk().expect("the volume walks") {
            if walked.path.is_empty() {
                continue;
            }
            let id = walked.node.inode;
            let mut entry = inodes[&id].clone();
            entry["path_hex"] = to_hex(&walked.path).into();
            entry["ino"] = id.into();
            entry["xattrs"] = xattrs.get(&id).cloned().unwrap_or_default().into();
            out.push(entry);
        }
        out
    }

    fn sent_images() -> Vec<Sent> {
        ACCEPT
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(Sent::parse)
            .collect()
    }

    /// The APFS corpus `ci/fetch-apfs-corpus.sh` unpacks, where the script finds it whole: a
    /// cache unpacked from another release is not this corpus, and reads as absent. An absent
    /// corpus is said so loudly, and under `FERROSYS_REQUIRE_HOST_TOOLS` it fails the run.
    pub(super) fn apfs_corpus() -> Option<std::path::PathBuf> {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/fetch-apfs-corpus.sh");
        let ask = |flag: &str| {
            let out = std::process::Command::new("bash")
                .arg(&script)
                .arg(flag)
                .output()
                .ok()
                .filter(|out| out.status.success())?;
            Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
        };
        let (dir, pin) = ask("--print-prefix")
            .zip(ask("--print-sha256"))
            .expect("ci/fetch-apfs-corpus.sh answers");
        let dir = std::path::PathBuf::from(dir);
        let marker = std::fs::read_to_string(dir.join(".complete")).unwrap_or_default();
        if marker.trim() == pin {
            return Some(dir);
        }
        assert!(
            std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
            "the APFS corpus is required at {}, which ci/fetch-apfs-corpus.sh unpacks",
            dir.display()
        );
        eprintln!(
            "\n!!! SKIPPING what reads the APFS corpus: none at {} — run ci/fetch-apfs-corpus.sh !!!\n",
            dir.display()
        );
        None
    }

    /// The images this build writes: every one, but the rows a corpus volume fills where the
    /// corpus is absent or the build lacks a decoder its compressed files need, which are said
    /// to be left out.
    fn written_here(sent: Vec<Sent>) -> Vec<Sent> {
        let from_corpus = |image: &Sent| matches!(image.source, Filled::Corpus(_));
        if !sent.iter().any(from_corpus) {
            return sent;
        }
        let decoders = cfg!(all(
            feature = "zlib",
            feature = "lzvn",
            feature = "lzfse",
            feature = "lzbitmap"
        ));
        if !decoders {
            eprintln!(
                "\n!!! SKIPPING the images a corpus volume fills: this build lacks a decoder !!!\n"
            );
        } else if apfs_corpus().is_some() {
            return sent;
        }
        sent.into_iter()
            .filter(|image| !from_corpus(image))
            .collect()
    }

    /// `blocks` as a block dump of an image of `len` bytes in blocks of `size`, the form
    /// [`read_dump`] reads: runs of consecutive blocks, at most 4,096 to a run.
    fn dump_of(len: u64, size: u32, blocks: &BTreeMap<u64, Vec<u8>>) -> Vec<u8> {
        let mut runs: Vec<(u64, Vec<&[u8]>)> = Vec::new();
        for (&index, block) in blocks {
            match runs.last_mut() {
                Some((first, run)) if *first + run.len() as u64 == index && run.len() < 4096 => {
                    run.push(block);
                }
                _ => runs.push((index, vec![block])),
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"BLKDUMP1");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        for (first, run) in runs {
            out.extend_from_slice(&first.to_le_bytes());
            out.extend_from_slice(&u32::try_from(run.len()).expect("a run").to_le_bytes());
            for block in run {
                out.extend_from_slice(block);
            }
        }
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    /// Every image macOS is asked to judge is the one the writer writes now, so a verdict
    /// recorded for it is a verdict on this writer.
    ///
    /// With `FERROSYS_APFS_ACCEPT_OUT=DIR`, each image is also written to `DIR` as a block
    /// dump, `NAME.bd`, beside `NAME.json`, what the reader reads of it. With
    /// `FERROSYS_BLESS_APFS_ACCEPT=1`, the fixture's digests are rewritten from the writer's.
    #[test]
    fn every_image_sent_to_macos_is_written_as_it_was_sent() {
        let out = std::env::var_os("FERROSYS_APFS_ACCEPT_OUT").map(std::path::PathBuf::from);
        let bless = std::env::var_os("FERROSYS_BLESS_APFS_ACCEPT").is_some();
        let sent = sent_images();
        assert_eq!(sent.len(), SENT);
        let sent = written_here(sent);
        assert!(
            !bless || sent.len() == SENT,
            "the fixture is blessed from every image written"
        );
        let found = in_parallel(&sent, |image| {
            let (layout, written) = image.written();
            let blocks = image.sent(&layout, &written);
            let digest = digest(&blocks);
            let prediction = image.prediction(&layout, &written);
            if let Some(dir) = &out {
                let dump = dump_of(image.bytes, image.block_size, &blocks);
                let (len, back) = read_dump(&dump);
                assert_eq!((len, &back), (image.bytes, &blocks), "{}", image.name);
                std::fs::write(dir.join(format!("{}.bd", image.name)), dump).expect("the dump");
                let mut prediction = prediction;
                prediction["digest"] = digest.clone().into();
                let text = serde_json::to_string_pretty(&prediction).expect("JSON") + "\n";
                std::fs::write(dir.join(format!("{}.json", image.name)), text)
                    .expect("the prediction");
            }
            digest
        });
        if bless {
            let mut found = found.iter();
            let lines: Vec<String> = ACCEPT
                .lines()
                .map(|line| {
                    if line.starts_with('#') || line.is_empty() {
                        line.to_string()
                    } else {
                        // A verdict is on the image it was recorded for: one written otherwise
                        // has been judged by no release.
                        let sent = Sent::parse(line);
                        let digest = found.next().expect("a digest per line").clone();
                        let releases = if digest == sent.digest {
                            sent.releases.clone()
                        } else {
                            "-".to_string()
                        };
                        Sent {
                            digest,
                            releases,
                            ..sent
                        }
                        .line()
                    }
                })
                .collect();
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/apfs/fixtures/accept-images.txt"
            );
            std::fs::write(path, lines.join("\n") + "\n").expect("the fixture");
            return;
        }
        let differ: Vec<String> = sent
            .iter()
            .zip(&found)
            .filter(|(image, digest)| image.digest != **digest)
            .map(|(image, digest)| {
                format!("{}: sent {}, written {digest}", image.name, image.digest)
            })
            .collect();
        assert!(differ.is_empty(), "{}", differ.join("\n"));
    }

    /// The reader opens each image sent at the checkpoint macOS mounted it at: the newest, but
    /// where a free queue's node limit was changed, which macOS mounts at the checkpoint before,
    /// holding no volume, as the reader does.
    #[test]
    fn every_image_sent_to_macos_opens_at_the_checkpoint_macos_mounts() {
        let sent = written_here(sent_images());
        in_parallel(&sent, |image| {
            let (layout, written) = image.written();
            let blocks = image.sent(&layout, &written);
            let container = Container::open(Held {
                size: image.block_size as usize,
                len: image.bytes,
                blocks,
                pos: 0,
            })
            .unwrap_or_else(|e| panic!("{}: {e}", image.name));
            let [first, newest] = &layout.checkpoints;
            let passed: Vec<_> = container.passed_over().iter().map(|p| p.reason).collect();
            if let Change::Limit { .. } = image.change {
                assert_eq!(image.expect, Expect::Refuse, "{}", image.name);
                assert_eq!(container.xid(), first.xid, "{}", image.name);
                assert!(container.volumes().is_empty(), "{}", image.name);
                assert_eq!(
                    passed,
                    [super::super::container::QUEUE_LIMITS],
                    "{}",
                    image.name
                );
                assert_eq!(
                    container.block_zero(),
                    BlockZero::NotLoaded { xid: newest.xid },
                    "{}",
                    image.name
                );
            } else {
                assert_eq!(container.xid(), newest.xid, "{}", image.name);
                assert!(passed.is_empty(), "{}", image.name);
            }
        });
    }

    /// What decides the size of a container fitted to its contents.
    #[derive(Clone, Copy, Debug)]
    enum Decides {
        /// What the volumes hold: the block below has too little room for it.
        Contents,
        /// How many volumes there are: the block below has too few slots for them.
        Slots,
        /// The room left: the same contents fit a smaller container with none.
        Slack,
    }

    /// The images named `fit-`, in fixture order, each with the slack [`FormatPlan::fit`] sized
    /// it with and what decides that size.
    const FITTED: [(&str, Slack, Decides); 5] = [
        ("fit-ramdisk", Slack::None, Decides::Contents),
        ("fit-v2", Slack::None, Decides::Slots),
        ("fit-slack", Slack::Share(2000), Decides::Slack),
        ("fit-room-b4k", Slack::Bytes(64 << 20), Decides::Slack),
        ("fit-room-b64k", Slack::Bytes(256 << 20), Decides::Slack),
    ];

    /// Every image named `fit-` is the size [`FormatPlan::fit`] gives its contents with the
    /// slack [`FITTED`] names, for the reason it names. One that records no block free is one
    /// macOS finds full, and one fitted with room is expected to take that room: the bytes a
    /// slack of bytes names, or the blocks a share asks for.
    #[test]
    fn every_fitted_image_is_the_size_the_fit_gives_it() {
        let rows: Vec<Sent> = sent_images()
            .into_iter()
            .filter(|image| image.name.starts_with("fit-"))
            .collect();
        let names: Vec<&str> = rows.iter().map(|image| image.name.as_str()).collect();
        assert_eq!(names, FITTED.map(|(name, ..)| name));
        in_parallel(&rows, |image| {
            let (_, slack, decides) = FITTED
                .into_iter()
                .find(|(name, ..)| *name == image.name)
                .expect("a row FITTED names");
            let plan = FormatPlan::fit(image.entries(), image.options(), slack)
                .unwrap_or_else(|e| panic!("{}: {e}", image.name));
            assert_eq!(plan.container_bytes(), image.bytes, "{}", image.name);
            let block_size = u64::from(image.block_size);
            let blocks = image.bytes / block_size;
            let room = match slack {
                Slack::None => None,
                Slack::Bytes(bytes) => Some(bytes),
                Slack::Share(_) => Some(slack.required_free(blocks, block_size) * block_size),
            };
            if let Some(room) = room {
                assert_eq!(image.expect, Expect::Room(room), "{}", image.name);
                assert!(
                    plan.layout().writable_blocks() * block_size >= room,
                    "{}: {} blocks writable",
                    image.name,
                    plan.layout().writable_blocks()
                );
            }
            let free = plan.layout().free_blocks();
            assert!(
                free > 0 || image.expect == Expect::Full,
                "{}: no block free, expected {}",
                image.name,
                image.expect.token()
            );
            let below = FormatPlan::new(
                image.entries(),
                image.bytes - u64::from(image.block_size),
                image.options(),
            )
            .err();
            let decided = match decides {
                Decides::Contents => matches!(
                    below,
                    Some(FormatError::Geometry(GeometryError::ContainerFull { .. }))
                ),
                Decides::Slots => matches!(
                    below,
                    Some(FormatError::Geometry(GeometryError::TooManyVolumes { .. }))
                ),
                Decides::Slack => {
                    let bare = FormatPlan::fit(image.entries(), image.options(), Slack::None)
                        .unwrap_or_else(|e| panic!("{}: {e}", image.name));
                    bare.container_bytes() < image.bytes
                }
            };
            assert!(
                decided,
                "{}: not decided by {decides:?}; one block below: {below:?}",
                image.name
            );
        });
    }

    /// Every image a corpus volume fills sends only what the corpus probe wrote and what the
    /// steps make, and sends it whole: each regular file's content is one the probe recorded
    /// writing or one a step made, and reads back from the container written as it was given, a
    /// compressed file's through the form passed through.
    #[test]
    fn every_file_an_image_takes_from_the_corpus_is_one_its_probe_or_a_step_wrote() {
        let rows: Vec<Sent> = written_here(sent_images())
            .into_iter()
            .filter(|image| matches!(image.source, Filled::Corpus(_)))
            .collect();
        in_parallel(&rows, |image| {
            let Filled::Corpus(volume) = &image.source else {
                unreachable!("a corpus row")
            };
            let built = super::from_corpus::built(volume);
            let plan = FormatPlan::new(built.entries.clone(), image.bytes, image.options())
                .unwrap_or_else(|e| panic!("{}: {e}", image.name));
            let mut sink = Held::empty(image.block_size as usize);
            plan.write_to(&mut sink)
                .unwrap_or_else(|e| panic!("{}: {e}", image.name));
            let mut reader = Reader::open(sink.rewound()).expect("the volume opens strictly");
            // The paths written are the paths given, each reached once.
            let walked: BTreeMap<Vec<u8>, crate::apfs::Node> = reader
                .walk()
                .expect("the volume walks")
                .into_iter()
                .map(|w| (crate::path::canonical_key(&w.path), w.node))
                .collect();
            let given: BTreeMap<Vec<u8>, &SourceEntry> = built
                .entries
                .iter()
                .map(|e| (crate::path::canonical_key(&e.path), e))
                .collect();
            let printable = |paths: Vec<&Vec<u8>>| -> Vec<String> {
                paths
                    .into_iter()
                    .take(3)
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect()
            };
            let unwritten = printable(given.keys().filter(|p| !walked.contains_key(*p)).collect());
            let ungiven = printable(walked.keys().filter(|p| !given.contains_key(*p)).collect());
            assert!(
                unwritten.is_empty() && ungiven.is_empty(),
                "{}: given and not written {unwritten:?}, written and not given {ungiven:?}",
                image.name
            );
            let mut passed_through = 0;
            for (path, entry) in &given {
                let what = format!("{}: {}", image.name, String::from_utf8_lossy(path));
                let node = &walked[path];
                let crate::source::EntryKind::File(content) = &entry.kind else {
                    continue;
                };
                let given = super::from_corpus::digest_of(content);
                assert!(
                    built.contents.contains(&given),
                    "{what}: content neither the corpus probe nor a step wrote"
                );
                let read = reader.read_data(node).expect("the file reads back");
                assert_eq!(to_hex(&Sha256::digest(read)), given, "{what}: read back");
                if entry
                    .darwin
                    .as_ref()
                    .is_some_and(|d| d.compressed.is_some())
                {
                    assert!(node.compression.is_some(), "{what}: written compressed");
                    passed_through += 1;
                }
            }
            assert!(
                passed_through > 0,
                "{}: a compressed file passed through",
                image.name
            );
        });
    }

    /// The releases every image is judged on: a line whose image the writer wrote otherwise
    /// has its verdicts cleared when it is blessed, and fails here until the batch has run
    /// over it again.
    const JUDGED_ON: &str = "15,26,27";

    #[test]
    fn macos_15_26_and_27_each_found_every_image_sent_as_expected() {
        let unjudged: Vec<String> = sent_images()
            .into_iter()
            .filter(|image| image.releases != JUDGED_ON)
            .map(|image| format!("{}: {}", image.name, image.releases))
            .collect();
        assert!(
            unjudged.is_empty(),
            "judged on fewer releases: {unjudged:?}"
        );
    }

    #[test]
    fn the_images_sent_to_macos_pair_every_two_of_their_inputs() {
        let min = super::super::geometry::MIN_BLOCK_COUNT;
        let limit = super::super::geometry::LAST_CONTIGUOUS_BLOCK_COUNT;
        let measured: Vec<(u32, u64)> = shapes().iter().map(|s| (s.block_size, s.bytes)).collect();
        let mut rows: Vec<[String; 5]> = Vec::new();
        for image in sent_images() {
            if [
                "edge-", "neg-", "limit-", "tree-", "corpus-", "fit-", "root-", "group-",
            ]
            .iter()
            .any(|prefix| image.name.starts_with(prefix))
            {
                continue;
            }
            let blocks = image.bytes / u64::from(image.block_size);
            let size = if blocks == min {
                "floor"
            } else if blocks > limit {
                // Past the contiguous limit, where newfs_apfs formatted a container of the same
                // size, and where a free queue absorbs a key.
                assert!(
                    measured.contains(&(image.block_size, image.bytes)),
                    "{}",
                    image.name
                );
                let (layout, _) = image.written();
                let newest = layout.newest();
                assert!(
                    absorbed(&newest.freed_pool) + absorbed(&newest.freed_main) > 0,
                    "{}",
                    image.name
                );
                "far"
            } else {
                assert_eq!(image.bytes, 4 << 30, "{}", image.name);
                "mid"
            };
            let row = [
                (image.block_size / 1024).to_string(),
                image.profile.clone(),
                size.to_string(),
                image.volumes.len().to_string(),
                kind_token(image.volumes[0].0).to_string(),
            ];
            assert_eq!(
                image.name,
                format!("b{}k-p{}-{}-v{}-{}", row[0], row[1], row[2], row[3], row[4])
            );
            for (slot, pair) in image.volumes.windows(2).enumerate() {
                assert_ne!(
                    pair[0].0, pair[1].0,
                    "{}: slots {slot} and the next alternate",
                    image.name
                );
            }
            rows.push(row);
        }
        let levels: [&[&str]; 5] = [
            &["4", "8", "16", "32", "64"],
            &["14", "15", "26", "27"],
            &["floor", "mid", "far"],
            &["1", "2", "5"],
            &["fold", "keep"],
        ];
        let mut missing = Vec::new();
        for i in 0..levels.len() {
            for j in i + 1..levels.len() {
                for a in levels[i] {
                    for b in levels[j] {
                        let present = rows.iter().any(|r| r[i] == *a && r[j] == *b);
                        if (i, j, *a) == (2, 3, "floor") && *b != "1" {
                            assert!(!present, "floor and {b} volumes");
                        } else if !present {
                            missing.push(format!("{a} with {b}"));
                        }
                    }
                }
            }
        }
        assert!(missing.is_empty(), "pairs no row holds: {missing:?}");
        // The two pairs left out are out of reach: a container of 1,024 blocks has one slot.
        for size in [4096u32, 8192, 16384, 32768, 65536] {
            let volume =
                |id: u8| VolumeRequest::new(VolumeName::new("v").expect("a name"), [id; 16]);
            let options = FormatOptions::new([1; 16], Timestamp::from_secs(0), volume(2))
                .block_size(block_size(size))
                .volume(volume(3));
            assert!(matches!(
                FormatPlan::new(nothing(), min * u64::from(size), options),
                Err(FormatError::Geometry(GeometryError::TooManyVolumes {
                    max_volumes: 1,
                    ..
                }))
            ));
        }
    }
}

#[cfg(test)]
mod populated {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};

    use super::tests::Held;
    use super::*;
    use crate::SourceEntry;
    use crate::apfs::Reader;
    use crate::source::EntryKind;
    use crate::xattr::Xattr;

    /// A generator of numbers, seeded, so a tree is one tree on every run.
    struct Seeded(u64);

    impl Seeded {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn time(seed: &mut Seeded) -> Timestamp {
        // Before and after 1970, to the nanosecond.
        Timestamp {
            secs: seed.below(4_000_000_000) as i64 - 1_000_000_000,
            nanos: seed.below(1_000_000_000) as u32,
        }
    }

    fn meta(seed: &mut Seeded, mode: u16) -> Metadata {
        Metadata::new(mode, time(seed))
            .owned_by(seed.below(70_000) as u32, seed.below(70_000) as u32)
            .with_times(time(seed), time(seed), time(seed))
    }

    /// A tree of `n` entries under `dirs` directories: files from empty to past a mebibyte,
    /// symbolic links, hard links, device nodes, pipes and sockets, attributes either side of
    /// what a record holds and resource forks, and names past ASCII.
    fn tree(n: usize, dirs: usize, seed: u64) -> Vec<SourceEntry> {
        tree_up_to(n, dirs, seed, u64::MAX)
    }

    /// [`tree`], no file of it larger than `max` bytes. A device node carries no attribute,
    /// since macOS refuses to list one's.
    pub(super) fn tree_up_to(n: usize, dirs: usize, seed: u64, max: u64) -> Vec<SourceEntry> {
        let mut seed = Seeded(seed | 1);
        let names = [
            "file",
            "Datei",
            "\u{E9}t\u{E9}",
            "\u{6587}\u{4EF6}",
            "x",
            "n\u{303}o",
        ];
        let mut entries = vec![SourceEntry::new(
            "/",
            EntryKind::Directory,
            meta(&mut seed, 0o755),
        )];
        let mut directories = vec![String::new()];
        for d in 0..dirs {
            let parent = directories[seed.below(directories.len() as u64) as usize].clone();
            let path = format!("{parent}/d{d}");
            entries.push(SourceEntry::new(
                path.clone(),
                EntryKind::Directory,
                meta(&mut seed, 0o750),
            ));
            directories.push(path);
        }
        let mut files = Vec::new();
        for i in 0..n {
            let dir = &directories[seed.below(directories.len() as u64) as usize];
            let base = names[seed.below(names.len() as u64) as usize];
            let path = format!("{dir}/{base}{i}");
            let kind = match seed.below(20) {
                0..=10 => {
                    let size = match seed.below(10) {
                        0 => 0,
                        1 => (1 << 20) + seed.below(300_000),
                        _ => seed.below(70_000),
                    }
                    .min(max);
                    let byte = seed.below(256) as u8;
                    files.push(path.clone());
                    EntryKind::File(
                        (0..size)
                            .map(|j| byte ^ (j as u8))
                            .collect::<Vec<u8>>()
                            .into(),
                    )
                }
                11 | 12 => EntryKind::Symlink(
                    format!("../t{}", "x".repeat(seed.below(900) as usize)).into_bytes(),
                ),
                13 if !files.is_empty() => EntryKind::HardLink {
                    target: files[seed.below(files.len() as u64) as usize]
                        .clone()
                        .into_bytes(),
                },
                14 => EntryKind::CharDevice {
                    major: seed.below(256) as u32,
                    minor: seed.below(1 << 24) as u32,
                },
                15 => EntryKind::BlockDevice {
                    major: seed.below(256) as u32,
                    minor: seed.below(1 << 24) as u32,
                },
                16 => EntryKind::Fifo,
                17 => EntryKind::Socket,
                _ => EntryKind::File(Vec::new().into()),
            };
            let bare = matches!(
                kind,
                EntryKind::HardLink { .. }
                    | EntryKind::CharDevice { .. }
                    | EntryKind::BlockDevice { .. }
            );
            let mut entry = SourceEntry::new(
                path,
                kind,
                meta(&mut seed, 0o640 | (0o4000 * (i % 2) as u16)),
            );
            if !bare && seed.below(3) == 0 {
                let mut xattrs = vec![Xattr {
                    name: b"user.small".to_vec(),
                    value: vec![seed.below(256) as u8; seed.below(200) as usize],
                }];
                if seed.below(2) == 0 {
                    let size = [3800, 3801, 9000, 70_000][seed.below(4) as usize];
                    xattrs.push(Xattr {
                        name: b"user.large".to_vec(),
                        value: (0..size).map(|j| (j % 251) as u8).collect(),
                    });
                }
                if seed.below(4) == 0 {
                    xattrs.push(Xattr {
                        name: crate::apfs::ondisk::RESOURCE_FORK_XATTR.to_vec(),
                        value: vec![7; seed.below(5000) as usize],
                    });
                }
                entry = entry.with_xattrs(xattrs);
            }
            entries.push(entry);
        }
        entries
    }

    /// The instant every populated gate formats at, in nanoseconds since 1970.
    const FORMATTED: i64 = 1_700_000_000_000_000_000;

    fn options(block_size: BlockSize, names: NameKind) -> FormatOptions {
        FormatOptions::new(
            [0x11; 16],
            Timestamp::from_secs(FORMATTED / 1_000_000_000),
            VolumeRequest::new(VolumeName::new("Rep").expect("a name"), [0x22; 16]).names(names),
        )
        .block_size(block_size)
    }

    /// The container `plan` writes, held sparsely.
    fn written(plan: &FormatPlan, block_size: BlockSize) -> Held {
        let mut image = Held::empty(to_index(u64::from(block_size.bytes())));
        plan.write_to(&mut image).expect("writes");
        image.rewound()
    }

    /// Hold every entry of `entries` to what the first volume of `image` holds reads back as,
    /// field by field, and the volume to a strict scan with no finding.
    fn hold(image: impl Read + Seek, entries: &[SourceEntry]) {
        hold_view(
            Reader::open(image).expect("the volume opens strictly"),
            entries,
        );
    }

    /// [`hold`], of the view `reader` reads: the volume as it is, or one of its snapshots.
    fn hold_view<R: Read + Seek>(mut reader: Reader<R>, entries: &[SourceEntry]) {
        let report = reader.scan();
        assert!(
            report.anomalies().is_empty(),
            "the scan found:\n{}",
            report
                .anomalies()
                .iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let by_path: BTreeMap<Vec<u8>, &SourceEntry> = entries
            .iter()
            .map(|e| (crate::path::canonical_key(&e.path), e))
            .collect();
        let mut names: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        for entry in entries {
            if let EntryKind::HardLink { target } = &entry.kind {
                *names.entry(crate::path::canonical_key(target)).or_insert(1) += 1;
            }
        }
        for entry in entries {
            let key = crate::path::canonical_key(&entry.path);
            let node = reader
                .lookup_no_follow(&entry.path)
                .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(&entry.path)));
            let object = match &entry.kind {
                EntryKind::HardLink { target } => by_path[&crate::path::canonical_key(target)],
                _ => entry,
            };
            let what = String::from_utf8_lossy(&entry.path).into_owned();
            let meta = object.meta;
            let v = &node.value;
            assert_eq!(v.mode & 0o7777, meta.mode, "{what}: mode");
            assert_eq!((v.owner, v.group), (meta.uid, meta.gid), "{what}: owner");
            assert_eq!(node.modify_time(), meta.mtime, "{what}: modified");
            assert_eq!(node.change_time(), meta.ctime, "{what}: changed");
            assert_eq!(node.access_time(), meta.atime, "{what}: read");
            let born = crate::apfs::model::nanos_of(meta.mtime)
                .map(|m| super::super::records::birth_time(m, FORMATTED))
                .expect("a time");
            assert_eq!(node.value.create_time, born, "{what}: born");
            match &object.kind {
                EntryKind::Directory => {
                    assert!(node.is_dir(), "{what}: a directory");
                    let held = reader.read_dir(&node).expect("a listing").len();
                    let stated = entries
                        .iter()
                        .filter(|e| {
                            let k = crate::path::canonical_key(&e.path);
                            !k.is_empty() && k.rsplit_once_byte() == Some(key.as_slice())
                        })
                        .count();
                    assert_eq!(held, stated, "{what}: entries");
                    assert_eq!(v.links_or_children as usize, stated, "{what}: children");
                }
                EntryKind::File(content) => {
                    let bytes = reader.read_data(&node).expect("the file reads");
                    let mut stated = vec![0u8; to_index(content.len())];
                    content.read_at(0, &mut stated).expect("held");
                    assert_eq!(bytes, stated, "{what}: data");
                    let links = names
                        .get(&crate::path::canonical_key(&object.path))
                        .copied();
                    assert_eq!(
                        v.links_or_children as u32,
                        links.unwrap_or(1),
                        "{what}: links"
                    );
                }
                EntryKind::Symlink(target) => {
                    assert_eq!(
                        &reader.link_target(&node).expect("a target"),
                        target,
                        "{what}"
                    );
                }
                EntryKind::CharDevice { major, minor }
                | EntryKind::BlockDevice { major, minor } => {
                    assert_eq!(node.device, Some((major << 24) | minor), "{what}: device");
                }
                _ => {}
            }
            let mut stated = object.xattrs.clone();
            stated.sort_by(|a, b| a.name.cmp(&b.name));
            let mut held = reader.xattrs(&node).expect("attributes read");
            held.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(held, stated, "{what}: attributes");
        }
    }

    trait SplitParent {
        fn rsplit_once_byte(&self) -> Option<&[u8]>;
    }

    impl SplitParent for Vec<u8> {
        /// The parent of a canonical key: everything before its last separator, or the root.
        fn rsplit_once_byte(&self) -> Option<&[u8]> {
            Some(
                self.iter()
                    .rposition(|&b| b == b'/')
                    .map_or(&[][..], |at| &self[..at]),
            )
        }
    }

    /// The nodes of each level of the first volume's file-system tree, its extent-reference
    /// tree's nodes and its object map's.
    fn depths(plan: &FormatPlan) -> (Vec<usize>, usize, usize) {
        let volume = &plan.volumes[0];
        (
            volume.fs.shape.level_sizes().collect(),
            volume.extents.places.len(),
            volume.map.places.len(),
        )
    }

    #[test]
    fn a_populated_volume_reads_back_entry_for_entry_and_scans_clean() {
        // Each case reaches what the one before does not: a tree of one level of leaves; three
        // levels, with an extent-reference tree and an object map of more than one node; and
        // the larger block sizes, one with a tree of one leaf.
        for (block_size, names, n, dirs, bytes, reached) in [
            (
                BlockSize::K4,
                NameKind::CaseFolding,
                30,
                3,
                64u64 << 20,
                (vec![3, 1], 1, 1),
            ),
            (
                BlockSize::K4,
                NameKind::CaseKeeping,
                2_000,
                40,
                512 << 20,
                (vec![271, 3, 1], 13, 4),
            ),
            (
                BlockSize::K16,
                NameKind::CaseFolding,
                600,
                20,
                512 << 20,
                (vec![21, 1], 1, 1),
            ),
            (
                BlockSize::K64,
                NameKind::CaseKeeping,
                300,
                10,
                1 << 30,
                (vec![3, 1], 1, 1),
            ),
            (
                BlockSize::K64,
                NameKind::CaseFolding,
                20,
                2,
                1 << 30,
                (vec![1], 1, 1),
            ),
        ] {
            let entries = tree(n, dirs, n as u64 * 7919);
            let options = options(block_size, names);
            let plan = FormatPlan::new(entries.clone(), bytes, options.clone())
                .unwrap_or_else(|e| panic!("{n} entries: {e}"));
            assert_eq!(depths(&plan), reached, "{n} entries at {block_size:?}");
            let image = format(entries.clone(), bytes, options).expect("formats");
            hold(Cursor::new(image.as_bytes()), &entries);
        }
    }

    /// The root snapshot the gates below format a volume with.
    fn root_snapshot() -> RootSnapshot {
        RootSnapshot::new("root", [0x33; 16]).expect("a snapshot")
    }

    /// `options` with a root snapshot on its first volume.
    fn rooted(mut options: FormatOptions) -> FormatOptions {
        options.volumes[0] = options.volumes[0].clone().root_snapshot(root_snapshot());
        options
    }

    /// The records of the root leaf of `size` bytes in `block`, in table order: each key and
    /// value, from a table of offsets and lengths, or of offsets alone where `fixed` gives the
    /// sizes.
    fn leaf(block: &[u8], fixed: Option<(usize, usize)>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let header = NodeHeader::read_from(block).expect("a node");
        let keys = NODE_DATA_START + usize::from(header.table.1);
        let values = block.len() - TREE_INFO_SIZE;
        (0..to_index(u64::from(header.key_count)))
            .map(|i| {
                let (k, kl, v, vl) = match fixed {
                    Some((kl, vl)) => {
                        let at = NODE_DATA_START + 4 * i;
                        let word = |o| usize::from(crate::bytes::get_u16(block, at + o));
                        (word(0), kl, word(2), vl)
                    }
                    None => {
                        let at = NODE_DATA_START + 8 * i;
                        let word = |o| usize::from(crate::bytes::get_u16(block, at + o));
                        (word(0), word(2), word(4), word(6))
                    }
                };
                (
                    block[keys + k..keys + k + kl].to_vec(),
                    block[values - v..values - v + vl].to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn a_root_snapshot_keeps_the_volume_as_written_and_both_read_back_and_scan_clean() {
        // A tree of one leaf, one of three levels with an object map of more than one node,
        // and the largest block size.
        for (block_size, n, dirs, bytes) in [
            (BlockSize::K4, 30, 3, 64u64 << 20),
            (BlockSize::K4, 2_000, 40, 512 << 20),
            (BlockSize::K64, 300, 10, 1 << 30),
        ] {
            let entries = tree(n, dirs, n as u64 * 7919);
            let options = rooted(options(block_size, NameKind::CaseFolding));
            let image = format(entries.clone(), bytes, options.clone()).expect("formats");
            assert_eq!(
                image.as_bytes(),
                format(entries.clone(), bytes, options.clone())
                    .expect("formats")
                    .as_bytes(),
                "two formats are the same bytes"
            );
            hold(Cursor::new(image.as_bytes()), &entries);
            let mut reader = Reader::open(Cursor::new(image.as_bytes())).expect("opens");
            assert_eq!(reader.superblock().root_to_xid, SECOND_XID);
            let listed = reader.snapshots().expect("the snapshots list");
            assert_eq!(listed.len(), 1, "{n} entries");
            let held = &listed[0];
            assert_eq!(held.name, b"root");
            assert_eq!(held.xid, SECOND_XID);
            assert_eq!(held.uuid, Some([0x33; 16]));
            assert_eq!(held.created, options.time);
            assert_eq!(held.flags, 0);
            let view = reader.at_snapshot(b"root").expect("the snapshot opens");
            hold_view(view, &entries);
        }
    }

    #[test]
    fn what_a_root_snapshot_adds_is_what_macos_adds_when_it_takes_one() {
        let entries = tree(2_000, 40, 2_000 * 7919);
        let bytes = 512u64 << 20;
        let size = 4096;
        for profile in [ReleaseProfile::Macos15, ReleaseProfile::Macos26] {
            let plain = plain_of(profile);
            let without = format(entries.clone(), bytes, plain.clone()).expect("formats");
            let with = format(entries.clone(), bytes, rooted(plain)).expect("formats");
            let block = |image: &Image, at: u64| {
                let at = to_index(at) * size;
                image.as_bytes()[at..at + size].to_vec()
            };
            let container = |image: &Image| {
                ContainerSuperblock::read_from(&block(image, 0)).expect("a container")
            };
            let place = with.layout().newest().volumes[0];
            assert_eq!(place, without.layout().newest().volumes[0]);
            let before =
                VolumeSuperblock::read_from(&block(&without, place.superblock)).expect("a volume");
            let after =
                VolumeSuperblock::read_from(&block(&with, place.superblock)).expect("a volume");

            // The extension object takes the container's next identifier.
            let extension = container(&without).next_oid;
            assert_eq!(container(&with).next_oid, extension + 1);
            assert_eq!(after.snapshot_extension_oid, extension);
            // The volume counts three blocks more, takes one identifier more, holds one
            // snapshot and roots from it, and has a new extent-reference tree, empty.
            assert_eq!(after.allocated_blocks, before.allocated_blocks + 3);
            assert_eq!(after.next_object_id, before.next_object_id + 1);
            assert_eq!(after.total_blocks_allocated, before.total_blocks_allocated);
            assert_eq!((after.snapshot_count, after.root_to_xid), (1, SECOND_XID));
            assert_ne!(after.extent_ref_tree_oid, before.extent_ref_tree_oid);
            assert!(leaf(&block(&with, after.extent_ref_tree_oid), None).is_empty());
            // Four blocks more are in use: the copy, that tree, the object map's tree of
            // snapshots and the extension object.
            assert_eq!(
                with.layout().free_blocks() + 4,
                without.layout().free_blocks()
            );

            // The snapshot tree: the metadata, then the name, as macOS lays them out.
            let snapshots = block(&with, place.snapshot_tree);
            let records = leaf(&snapshots, None);
            assert_eq!(records.len(), 2);
            let meta = SnapshotMeta::read_from(&records[0].0, &records[0].1).expect("metadata");
            assert_eq!(meta.xid, SECOND_XID);
            assert_eq!(meta.extent_ref_tree_oid, before.extent_ref_tree_oid);
            assert_eq!(meta.extent_ref_tree_type, 0x4000_0002);
            assert_eq!(meta.next_object_id, before.next_object_id);
            assert_eq!((meta.create_time, meta.change_time), (FORMATTED, FORMATTED));
            assert_eq!((meta.flags, meta.name.as_slice()), (0, &b"root"[..]));
            assert_eq!(
                records[1],
                snapshot_name_record(b"root", SECOND_XID),
                "the name record"
            );
            let table: Vec<u16> = (0..8)
                .map(|i| crate::bytes::get_u16(&snapshots, NODE_DATA_START + 2 * i))
                .collect();
            let value = records[0].1.len() as u16;
            let name = records[1].0.len() as u16;
            assert_eq!(table, [0, 8, value, value, 8, name, value + 8, 8]);

            // The copy is the volume as it was before the snapshot, physical at its own block,
            // naming no object map, extent-reference tree or snapshot tree.
            let copy = block(&with, meta.superblock);
            let object = ObjectHeader::read_from(&copy).expect("a header");
            assert_eq!(
                (object.oid, object.xid, object.type_word),
                (meta.superblock, SECOND_XID, 0x4000_000D)
            );
            let unchanged = block(&without, place.superblock);
            let differ: Vec<usize> = (32..size)
                .step_by(8)
                .filter(|&at| copy[at..at + 8] != unchanged[at..at + 8])
                .collect();
            assert_eq!(differ, [128, 144, 152], "{profile:?}");
            for at in differ {
                assert_eq!(crate::bytes::get_u64(&copy, at), 0);
            }

            // The object map keeps versions for the snapshot, and maps the extension object.
            let map = ObjectMap::read_from(&block(&with, place.object_map.object)).expect("a map");
            assert_eq!(
                (map.flags, map.snapshot_count, map.most_recent_snapshot),
                (0, 1, SECOND_XID)
            );
            let kept = block(&with, map.snapshot_tree_oid);
            assert_eq!(
                leaf(&kept, Some((8, 16))),
                [(SECOND_XID.to_le_bytes().to_vec(), vec![0; 16])]
            );
            let info = TreeInfo::read_from(&kept[size - TREE_INFO_SIZE..]).expect("a root");
            assert_eq!((info.flags, info.key_size, info.value_size), (0x10, 8, 16));
            // The extension object, at the block the plan gave it: the reader found the
            // snapshot's identifier in it through the object map, by its identifier.
            let plan =
                FormatPlan::new(entries.clone(), bytes, rooted(plain_of(profile))).expect("plans");
            let at = plan.volumes[0]
                .snapshot
                .as_ref()
                .expect("a root snapshot")
                .extension
                .block;
            let object = block(&with, at);
            let header = ObjectHeader::read_from(&object).expect("a header");
            assert_eq!(
                (header.oid, header.xid, header.type_word),
                (extension, SECOND_XID, u32::from(kind::SNAPSHOT_EXTENSION))
            );
            let ext = SnapshotExtension::read_from(&object).expect("an extension");
            assert_eq!(
                (ext.version, ext.flags, ext.xid, ext.uuid, ext.token),
                (1, 0, SECOND_XID, [0x33; 16], 0)
            );
            assert!(object[SnapshotExtension::SIZE..].iter().all(|b| *b == 0));
        }
    }

    /// The options of the gate above, under `profile`.
    fn plain_of(profile: ReleaseProfile) -> FormatOptions {
        options(BlockSize::K4, NameKind::CaseFolding).profile(profile)
    }

    #[test]
    fn a_root_snapshot_on_any_volume_takes_an_identifier_after_every_node() {
        use crate::apfs::{OpenOptions, VolumeSelector};
        let volume = |slot: u8| {
            VolumeRequest::new(
                VolumeName::new(&format!("Volume {slot}")).expect("a name"),
                [slot + 1; 16],
            )
        };
        let snapshot = |slot: u8| {
            RootSnapshot::new(&format!("root {slot}"), [slot + 0x40; 16]).expect("a snapshot")
        };
        let options = FormatOptions::new(
            [0xF0; 16],
            Timestamp::from_secs(FORMATTED / 1_000_000_000),
            volume(0).root_snapshot(snapshot(0)),
        )
        .volume(volume(1))
        .volume(volume(2).root_snapshot(snapshot(2)));
        let entries = tree(2_000, 40, 2_000 * 7919);
        let bytes = 2u64 << 30;
        let plan = FormatPlan::new(entries.clone(), bytes, options.clone()).expect("plans");
        let nodes: u64 = plan.volumes.iter().map(|v| v.fs.extra_nodes()).sum();
        assert!(nodes > 0, "the tree has nodes past its root");
        let first = next_oid(3) + nodes;
        let image = format(entries.clone(), bytes, options).expect("formats");
        hold(Cursor::new(image.as_bytes()), &entries);
        for (slot, extension) in [(0usize, Some(first)), (1, None), (2, Some(first + 1))] {
            let open = OpenOptions::new().volume(VolumeSelector::Slot(slot));
            let mut reader =
                Reader::open_with(Cursor::new(image.as_bytes()), &open).expect("opens");
            assert!(reader.scan().anomalies().is_empty(), "slot {slot}");
            let sb = reader.superblock().clone();
            assert_eq!(
                (sb.snapshot_extension_oid, sb.root_to_xid),
                extension.map_or((0, 0), |oid| (oid, SECOND_XID)),
                "slot {slot}"
            );
            let listed = reader.snapshots().expect("the snapshots list");
            assert_eq!(
                listed.len(),
                usize::from(extension.is_some()),
                "slot {slot}"
            );
        }
    }

    #[test]
    fn a_fitted_container_holds_its_root_snapshot() {
        let entries = tree(300, 10, 300 * 7919);
        let plain = options(BlockSize::K4, NameKind::CaseKeeping);
        let without = FormatPlan::fit(entries.clone(), plain.clone(), Slack::None).expect("fits");
        let with = FormatPlan::fit(entries.clone(), rooted(plain), Slack::None).expect("fits");
        assert!(with.container_bytes() >= without.container_bytes());
        let image = written(&with, BlockSize::K4);
        hold(image, &entries);
    }

    /// A container of two volumes, the first holding the format's source and the second
    /// `second`, with the System volume in `system` and the Data volume in the other slot
    /// where `grouped`.
    fn two_volumes(system: u32, grouped: bool, second: &[SourceEntry]) -> FormatOptions {
        let options = FormatOptions::new(
            [0x11; 16],
            Timestamp::from_secs(FORMATTED / 1_000_000_000),
            VolumeRequest::new(VolumeName::new("First").expect("a name"), [0x22; 16]),
        )
        .volume(
            VolumeRequest::new(VolumeName::new("Second").expect("a name"), [0x44; 16])
                .contents(second.to_vec()),
        );
        if grouped {
            options.volume_group(VolumeGroup::new(system, 1 - system))
        } else {
            options
        }
    }

    /// The container `plan` writes, in memory.
    fn image_of(plan: &FormatPlan) -> Image {
        let mut bytes = Cursor::new(vec![0u8; to_index(plan.container_bytes())]);
        plan.write_to(&mut bytes).expect("writes");
        Image {
            bytes: bytes.into_inner(),
            layout: plan.layout.clone(),
            fidelity: plan.fidelity().clone(),
        }
    }

    /// A reader of the volume in `slot` of `image`.
    fn reader_of(image: &Image, slot: usize) -> Reader<Cursor<&[u8]>> {
        use crate::apfs::{OpenOptions, VolumeSelector};
        let open = OpenOptions::new().volume(VolumeSelector::Slot(slot));
        Reader::open_with(Cursor::new(image.as_bytes()), &open).expect("opens")
    }

    #[test]
    fn what_a_volume_group_writes_is_what_macos_writes_for_one() {
        let first = tree(300, 10, 300 * 7919);
        let second = tree(200, 8, 200 * 7919);
        let bytes = 1u64 << 30;
        let size = 4096;
        for profile in [ReleaseProfile::Macos15, ReleaseProfile::Macos26] {
            // The System volume first, as a Mac's boot disk has it, and second, as `diskutil`
            // makes a group.
            for system in [0u32, 1] {
                let plain = two_volumes(system, false, &second).profile(profile);
                let grouped = two_volumes(system, true, &second).profile(profile);
                let without = format(first.clone(), bytes, plain).expect("formats");
                let with = format(first.clone(), bytes, grouped).expect("formats");
                assert_eq!(with.layout(), without.layout(), "the group moves nothing");
                let data_uuid = [[0x22; 16], [0x44; 16]][1 - system as usize];
                for (slot, place) in (0u32..).zip(&with.layout().newest().volumes) {
                    let at = to_index(place.superblock) * size;
                    let before = &without.as_bytes()[at..at + size];
                    let after = &with.as_bytes()[at..at + size];
                    let is_system = slot == system;
                    // Every word that differs, and only those: as between a group's volumes
                    // and one `diskutil` adds with no role.
                    let differ: Vec<usize> = (32..size)
                        .step_by(8)
                        .filter(|&at| before[at..at + 8] != after[at..at + 8])
                        .collect();
                    let expected: &[usize] = if is_system {
                        &[40, 176, 960, 1008, 1016, 1064]
                    } else {
                        &[40, 960, 1008, 1016]
                    };
                    assert_eq!(differ, expected, "{profile:?}, slot {slot}");
                    let sb = VolumeSuperblock::read_from(after).expect("a volume");
                    assert_eq!(sb.features, 0x12);
                    assert_eq!(sb.role, if is_system { 0x1 } else { 0x40 });
                    assert_eq!(sb.volume_group, data_uuid);
                    let low = crate::bytes::get_u32(after, 1064);
                    assert_eq!(low, if is_system { 0 } else { 16 });
                    assert_eq!(crate::bytes::get_u32(after, 1068), 2);
                    let plain = VolumeSuperblock::read_from(before).expect("a volume");
                    if is_system {
                        assert_eq!(
                            sb.next_object_id - SYSTEM_FIRST_ID,
                            plain.next_object_id - inode_number::FIRST_USER
                        );
                    }
                }
                // The container records nothing of the group.
                let container = |image: &Image| image.as_bytes()[..size].to_vec();
                assert_eq!(container(&with), container(&without));
            }
        }
    }

    #[test]
    fn a_groups_system_volume_numbers_its_tree_from_its_range_and_both_read_back() {
        let system = tree(500, 12, 500 * 7919);
        let data = tree(300, 10, 300 * 7919);
        let bytes = 1u64 << 30;
        let options = two_volumes(0, true, &data);
        let image = format(system.clone(), bytes, options.clone()).expect("formats");
        assert_eq!(
            image.as_bytes(),
            format(system.clone(), bytes, options.clone())
                .expect("formats")
                .as_bytes(),
            "two formats are the same bytes"
        );
        for (slot, entries, range) in [
            (0, &system, SYSTEM_FIRST_ID..u64::MAX),
            (1, &data, inode_number::FIRST_USER..SYSTEM_FIRST_ID),
        ] {
            hold_view(reader_of(&image, slot), entries);
            let mut reader = reader_of(&image, slot);
            let root = reader.lookup(b"/").expect("the root");
            assert_eq!(root.inode, 2, "slot {slot}");
            for entry in entries
                .iter()
                .filter(|e| !crate::path::canonical_key(&e.path).is_empty())
            {
                let node = reader.lookup_no_follow(&entry.path).expect("held");
                assert!(range.contains(&node.inode), "slot {slot}: {}", node.inode);
            }
        }
        // A fitted container holds both volumes' contents.
        let fitted = FormatPlan::fit(system.clone(), options, Slack::None).expect("fits");
        let image = image_of(&fitted);
        hold_view(reader_of(&image, 0), &system);
        hold_view(reader_of(&image, 1), &data);
    }

    #[test]
    fn a_groups_system_volume_keeps_its_group_in_its_root_snapshot() {
        let entries = tree(300, 10, 300 * 7919);
        let options = rooted(two_volumes(0, true, &[]));
        let image = format(entries.clone(), 1 << 30, options).expect("formats");
        let mut reader = reader_of(&image, 0);
        let live = reader.superblock().clone();
        let listed = reader.snapshots().expect("the snapshots list");
        assert_eq!(listed.len(), 1);
        let size = 4096;
        let place = image.layout().newest().volumes[0];
        let at = to_index(place.snapshot_tree) * size;
        let records = leaf(&image.as_bytes()[at..at + size], None);
        let meta = SnapshotMeta::read_from(&records[0].0, &records[0].1).expect("metadata");
        let at = to_index(meta.superblock) * size;
        let copy = &image.as_bytes()[at..at + size];
        let sb = VolumeSuperblock::read_from(copy).expect("the copy");
        assert_eq!(
            (sb.role, sb.features, sb.volume_group),
            (0x1, 0x12, [0x44; 16])
        );
        // The identifier before the snapshot took one, in the System volume's range.
        assert_eq!(sb.next_object_id, live.next_object_id - 1);
        assert!(sb.next_object_id > SYSTEM_FIRST_ID);
        assert_eq!(crate::bytes::get_u32(copy, 1064), 0);
        hold_view(
            reader.at_snapshot(b"root").expect("the snapshot opens"),
            &entries,
        );
    }

    #[test]
    fn a_firmlinked_directory_carries_the_flag_beside_its_own_and_the_attribute() {
        use crate::source::Darwin;
        let meta = Metadata::new(0o755, Timestamp::from_secs(1_650_000_000));
        let mut system = tree(200, 8, 200 * 7919);
        system.extend(
            crate::TreeBuilder::new()
                .directory("/fl-a", meta)
                .directory("/fl-b", meta)
                .directory("/nest", meta)
                .directory("/nest/fl-c", meta)
                .into_entries(),
        );
        let at = system.len() - 4;
        system[at].darwin = Some(Darwin::new(0x8000));
        let data = tree(100, 4, 100 * 7919);
        let links = Firmlinks::parse(b"/fl-a\tfl-a\n/nest/fl-c\tx/fl-c\n/absent\tabsent\n")
            .expect("a list");
        // The Data volume first, as `diskutil` makes a group, so the System volume's tree is
        // its request's contents.
        let mut options = two_volumes(1, true, &system);
        options.volumes[1] = options.volumes[1].clone().firmlinks(links.clone());
        let plan = FormatPlan::new(data.clone(), 1 << 30, options).expect("plans");
        assert_eq!(plan.firmlinked(), 2, "the absent directory marks nothing");
        let image = image_of(&plan);
        let mut expected = system.clone();
        firmlink::mark(&mut expected, &links, true).expect("marked");
        hold_view(reader_of(&image, 1), &expected);
        hold_view(reader_of(&image, 0), &data);
        let mut reader = reader_of(&image, 1);
        for (path, flags, target) in [
            (
                &b"/fl-a"[..],
                0x8000 | super::super::FIRMLINK_FLAG,
                Some(&b"fl-a\0"[..]),
            ),
            (b"/fl-b", 0, None),
            (
                b"/nest/fl-c",
                super::super::FIRMLINK_FLAG,
                Some(b"x/fl-c\0"),
            ),
        ] {
            let node = reader.lookup(path).expect("held");
            assert_eq!(node.value.bsd_flags, flags, "{path:?}");
            let attributes = reader.xattrs(&node).expect("attributes read");
            let value = attributes
                .iter()
                .find(|x| x.name == super::super::FIRMLINK_XATTR)
                .map(|x| x.value.as_slice());
            assert_eq!(value, target, "{path:?}");
        }
    }

    #[test]
    fn a_group_out_of_range_contents_on_the_first_volume_and_misplaced_firmlinks_are_refused() {
        let bytes = 1u64 << 30;
        let links = Firmlinks::parse(b"/a\ta\n").expect("a list");
        let refused = |options: FormatOptions, entries: Vec<SourceEntry>| {
            FormatPlan::new(entries, bytes, options)
                .err()
                .expect("refused")
        };
        let grouped = two_volumes(0, true, &[]);
        let mut out_of_range = grouped.clone();
        out_of_range.volume_group = Some(VolumeGroup::new(0, 2));
        assert!(matches!(
            refused(out_of_range, Vec::new()),
            FormatError::GroupSlot { slot: 2 }
        ));
        let mut one_slot = grouped.clone();
        one_slot.volume_group = Some(VolumeGroup::new(1, 1));
        assert!(matches!(
            refused(one_slot, Vec::new()),
            FormatError::GroupOneSlot { slot: 1 }
        ));
        let mut first = grouped.clone();
        first.volumes[0] = first.volumes[0].clone().contents(Vec::new());
        assert!(matches!(
            refused(first, Vec::new()),
            FormatError::ContentsOnFirstVolume
        ));
        // Firmlinks on the Data volume, and on a volume of no group.
        let mut on_data = grouped.clone();
        on_data.volumes[1] = on_data.volumes[1].clone().firmlinks(links.clone());
        assert!(matches!(
            refused(on_data, Vec::new()),
            FormatError::FirmlinksOutsideGroup { slot: 1 }
        ));
        let mut ungrouped = two_volumes(0, false, &[]);
        ungrouped.volumes[0] = ungrouped.volumes[0].clone().firmlinks(links.clone());
        assert!(matches!(
            refused(ungrouped, Vec::new()),
            FormatError::FirmlinksOutsideGroup { slot: 0 }
        ));
        // A firmlink naming a file.
        let mut on_file = grouped;
        on_file.volumes[0] = on_file.volumes[0].clone().firmlinks(links);
        let file = crate::TreeBuilder::new()
            .file("/a", "a", Metadata::new(0o644, Timestamp::from_secs(0)))
            .into_entries();
        assert!(matches!(
            refused(on_file, file),
            FormatError::FirmlinkNotDirectory { path } if path == b"/a"
        ));
    }

    #[test]
    fn the_compressed_flag_is_the_stored_forms_whatever_the_source_states() {
        use crate::source::{CompressedFile, Darwin};
        // A form of type 9, which keeps `hello` after its header behind one byte.
        let mut header = b"fpmc".to_vec();
        header.extend_from_slice(&9u32.to_le_bytes());
        header.extend_from_slice(&5u64.to_le_bytes());
        header.push(0xCC);
        header.extend_from_slice(b"hello");
        let form = CompressedFile::new(header, None);
        // The form with the flag cleared, with it set, and beside another flag; and the flag
        // with no form, alone and beside another.
        for (flags, form, written) in [
            (0, Some(form.clone()), 0x20),
            (0x20, Some(form.clone()), 0x20),
            (0x8000, Some(form), 0x8020),
            (0x20, None, 0),
            (0x8020, None, 0x8000),
        ] {
            let mut darwin = Darwin::new(flags);
            darwin.compressed = form;
            let entries = vec![
                SourceEntry::new(
                    "/f",
                    EntryKind::File(b"hello".to_vec().into()),
                    Metadata::new(0o644, Timestamp::from_secs(1_600_000_000)),
                )
                .with_darwin(darwin),
            ];
            let image = format(
                entries,
                4 << 20,
                options(BlockSize::K4, NameKind::CaseFolding),
            )
            .expect("formats");
            let mut reader = Reader::open(Cursor::new(image.as_bytes())).expect("opens");
            assert_eq!(reader.scan().anomalies(), [], "{flags:#x}");
            let node = reader.lookup(b"/f").expect("the file");
            assert_eq!(node.value.bsd_flags, written, "{flags:#x}");
            assert_eq!(reader.read_data(&node).expect("reads"), b"hello");
        }
    }

    #[test]
    fn every_attribute_name_macos_sets_is_written_and_every_longer_one_refused_at_every_block_size()
    {
        use super::super::model::{MAX_EMBEDDED_XATTR, MAX_XATTR_NAME, ModelXattr};
        // setxattr on macOS 15, 26 and 27 sets 127 bytes and refuses 128.
        assert_eq!(MAX_XATTR_NAME, 127);
        // An attribute name `len` bytes long, distinct by `tag`.
        let named = |len: usize, tag: usize| {
            let mut name = format!("user.{tag:04}.").into_bytes();
            name.resize(len, b'n');
            name
        };
        let xattr = |name: Vec<u8>, len: usize| Xattr {
            name,
            value: vec![0x5A; len],
        };
        let file = |path: &str, xattrs: Vec<Xattr>| {
            SourceEntry::new(
                path,
                EntryKind::File(b"x".to_vec().into()),
                Metadata::new(0o644, Timestamp::from_secs(1_600_000_000)),
            )
            .with_xattrs(xattrs)
        };
        for block_size in [
            BlockSize::K4,
            BlockSize::K8,
            BlockSize::K16,
            BlockSize::K32,
            BlockSize::K64,
        ] {
            let node = to_index(u64::from(block_size.bytes()));
            // Enough attributes of the longest name that their keys fill index nodes of their
            // own; and beside the longest name, the largest value held in its record and one a
            // byte larger, held in a stream.
            let keys = 3 * node / (MAX_XATTR_NAME + 32);
            let entries = vec![
                file(
                    "/keys",
                    (0..keys)
                        .map(|i| xattr(named(MAX_XATTR_NAME, i), 1))
                        .collect(),
                ),
                file(
                    "/beside",
                    vec![
                        xattr(named(MAX_XATTR_NAME, 0), MAX_EMBEDDED_XATTR),
                        xattr(named(MAX_XATTR_NAME, 1), MAX_EMBEDDED_XATTR + 1),
                        xattr(named(16, 2), MAX_EMBEDDED_XATTR),
                    ],
                ),
            ];
            let options = options(block_size, NameKind::CaseFolding);
            let bytes = 512 << 20;
            let plan = FormatPlan::new(entries.clone(), bytes, options.clone())
                .unwrap_or_else(|e| panic!("{block_size:?}: {e}"));
            let in_record: BTreeMap<(usize, usize), bool> = plan.models[0]
                .inodes
                .iter()
                .flat_map(|inode| &inode.xattrs)
                .filter_map(|x| match x {
                    ModelXattr::Embedded { name, value, .. } if value.len() > 1 => {
                        Some(((name.len(), value.len()), true))
                    }
                    ModelXattr::Embedded { .. } => None,
                    ModelXattr::Stream { name, .. } => {
                        Some(((name.len(), MAX_EMBEDDED_XATTR + 1), false))
                    }
                })
                .collect();
            assert_eq!(
                in_record,
                BTreeMap::from([
                    ((16, MAX_EMBEDDED_XATTR), true),
                    ((MAX_XATTR_NAME, MAX_EMBEDDED_XATTR), true),
                    ((MAX_XATTR_NAME, MAX_EMBEDDED_XATTR + 1), false),
                ]),
                "{block_size:?}"
            );
            assert!(
                depths(&plan).0.len() > 1,
                "{block_size:?}: {:?}",
                depths(&plan)
            );
            hold(written(&plan, block_size), &entries);

            // A name a byte past the longest is refused while the plan is made, as are the
            // lengths macOS lists and does not read, and those past which fsck_apfs finds the
            // tree invalid.
            for len in [MAX_XATTR_NAME + 1, 255, 1969, 4096, u16::MAX as usize - 1] {
                let entries = vec![file("/f", vec![xattr(named(len, 0), 1)])];
                match FormatPlan::new(entries, bytes, options.clone()) {
                    Err(FormatError::Model(ModelError::XattrNameTooLong { name, .. })) => {
                        assert_eq!(name.len(), len, "{block_size:?}");
                    }
                    Err(e) => panic!("{block_size:?} {len}: {e}"),
                    Ok(_) => panic!("{block_size:?} {len}: planned"),
                }
            }
        }
    }

    #[test]
    fn a_volume_whose_every_run_is_broken_reads_back_and_scans_clean() {
        // Every fifth block past the pool kept from the content, so every stream and every
        // tree's nodes span several runs, which a container's own objects do only to content
        // past 256 MiB in a container of six gibibytes and more.
        let entries = tree(800, 12, 4242);
        let options = options(BlockSize::K4, NameKind::CaseFolding);
        let plan = FormatPlan::planned(entries.clone(), 512 << 20, options, |planner| {
            planner.keep_every(5);
        })
        .expect("plans");
        let runs = &plan.layout.newest().content;
        assert!(runs.iter().all(|run| run.count <= 4), "every run is broken");
        hold(written(&plan, BlockSize::K4), &entries);
    }

    #[test]
    fn a_populated_volume_whose_objects_are_far_in_reads_back_and_scans_clean() {
        // 6 GiB at 4 KiB is the first size whose volume objects are past the pool's end: at
        // block 65,536, past every block the content takes.
        let entries = tree(400, 8, 31337);
        let bytes = (crate::apfs::geometry::LAST_CONTIGUOUS_BLOCK_COUNT + 1) * 4096;
        let plan = FormatPlan::new(
            entries.clone(),
            bytes,
            options(BlockSize::K4, NameKind::CaseFolding),
        )
        .expect("plans");
        let place = plan.layout.newest().volumes[0];
        assert!(place.superblock >= 65_536);
        assert!(
            plan.layout
                .newest()
                .content
                .iter()
                .all(|run| run.start < 65_536)
        );
        hold(written(&plan, BlockSize::K4), &entries);
    }

    #[test]
    fn a_populated_volume_beside_empty_ones_reads_back_and_each_scans_clean() {
        let entries = tree(300, 6, 99);
        let options = options(BlockSize::K4, NameKind::CaseFolding)
            .volume(VolumeRequest::new(
                VolumeName::new("Two").expect("a name"),
                [0x33; 16],
            ))
            .volume(
                VolumeRequest::new(VolumeName::new("Three").expect("a name"), [0x44; 16])
                    .names(NameKind::CaseKeeping),
            );
        let image = format(entries.clone(), 2 << 30, options).expect("formats");
        hold(Cursor::new(image.as_bytes()), &entries);
        for slot in 1..3 {
            let mut reader = Reader::open_with(
                Cursor::new(image.as_bytes()),
                &crate::apfs::OpenOptions::default()
                    .volume(crate::apfs::VolumeSelector::Slot(slot)),
            )
            .expect("opens");
            assert!(reader.scan().anomalies().is_empty(), "volume {slot}");
            let root = reader.root().expect("a root");
            assert!(reader.read_dir(&root).expect("lists").is_empty());
        }
    }
}

/// The first volume of an image the acceptance set fills from the corpus: a volume of a container
/// macOS made, read back as a source and taken through the steps a root image is made with.
///
/// What is sent holds only what the corpus probe wrote and what those steps make. The container
/// is found only through the corpus `ci/fetch-apfs-corpus.sh` pins, and read only where its dump
/// has the digest the row names. What macOS wrote on its own is removed: the search index's
/// directory, the event log's, and the attribute it sets on the root. Every regular file left is
/// one the probe's record of what it wrote names, with the content that record gives, and every
/// attribute is one the probe sets. Anything else stops the build.
#[cfg(test)]
mod from_corpus {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex, OnceLock};

    use sha2::{Digest, Sha256};

    use super::tests::{CorpusVolume, Held, apfs_corpus, read_dump, to_hex};
    use super::*;
    use crate::apfs::{OpenOptions, Reader, VolumeSelector};
    use crate::source::{EntryKind, FileContent, LayeredSource};
    use crate::{Darwin, ImageSource, SourceEntry, Synthesis};

    /// What macOS writes at a volume's root on its own while the corpus probe fills it: the
    /// search index's directory, and the event log's, which holds the probe's marker beside it.
    const MACOS_MADE: [&str; 2] = ["/.Spotlight-V100", "/.fseventsd"];

    /// The attribute macOS sets on a volume's root directory.
    const MACOS_ROOT_ATTRIBUTE: &[u8] = b"purgeable-drecs-fixed";

    /// What every attribute name the corpus probe sets begins with.
    const PROBE_ATTRIBUTE: &[u8] = b"corpus.";

    /// The directories at the root a step hides, as a root image hides some of its own.
    const HIDDEN: [&[u8]; 3] = [b"/bigdir", b"/names", b"/special"];

    /// `UF_HIDDEN`.
    const UF_HIDDEN: u32 = 0x8000;

    /// The directory a step replaces with a file.
    const REPLACED_DIRECTORY: &[u8] = b"/deep";

    /// The directory a step adds a generated tree beneath.
    const ADDED: &[u8] = b"/added";

    /// A corpus volume taken through the steps.
    pub(super) struct Built {
        /// What the first volume is written from.
        pub(super) entries: Vec<SourceEntry>,
        /// The digest of every content a regular file may hold: each the probe recorded writing,
        /// and each a step makes.
        pub(super) contents: BTreeSet<String>,
    }

    fn sha(bytes: &[u8]) -> String {
        to_hex(&Sha256::digest(bytes))
    }

    /// The SHA-256 of a file's content, read a window at a time.
    pub(super) fn digest_of(content: &FileContent) -> String {
        let mut sha = Sha256::new();
        content
            .for_each_window(|_, window| {
                sha.update(window);
                Ok::<(), std::io::Error>(())
            })
            .expect("the file reads");
        to_hex(&sha.finalize())
    }

    fn json(path: &std::path::Path) -> serde_json::Value {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        serde_json::from_slice(&bytes).expect("JSON")
    }

    /// [`build`], once a run for each volume: every caller after the first shares it, its files
    /// read through the one reader.
    pub(super) fn built(volume: &CorpusVolume) -> Arc<Built> {
        type Cell = Arc<OnceLock<Arc<Built>>>;
        static BUILT: Mutex<BTreeMap<String, Cell>> = Mutex::new(BTreeMap::new());
        let cell = Arc::clone(
            BUILT
                .lock()
                .expect("a lock")
                .entry(volume.sha256.clone() + &volume.volume)
                .or_default(),
        );
        Arc::clone(cell.get_or_init(|| Arc::new(build(volume))))
    }

    /// The volume `volume` names, read back as a source and taken through the steps: a file whose
    /// other names are hard links removed, so the first of them takes it; a compressed file
    /// replaced by one held plain, and a directory by a file; three directories at the root
    /// hidden; and a generated tree added beneath a directory of its own.
    fn build(volume: &CorpusVolume) -> Built {
        let corpus = apfs_corpus().expect("the corpus ci/fetch-apfs-corpus.sh unpacks");
        let what = format!("{}/{}/{}", volume.release, volume.row, volume.volume);
        let dir = corpus.join(format!("corpus-{}", volume.release));
        let index = json(&dir.join("corpus.json"));
        let row = index["rows"]
            .as_array()
            .expect("the index lists its rows")
            .iter()
            .find(|r| r["name"] == volume.row.as_str())
            .unwrap_or_else(|| panic!("{what}: no such row"));
        let listed = row["volume_list"]
            .as_array()
            .expect("the row lists its volumes")
            .iter()
            .find(|v| v["name"] == volume.volume.as_str())
            .unwrap_or_else(|| panic!("{what}: no such volume"));
        // The probe's record describes the live tree of a volume that keeps no snapshots.
        assert!(
            listed["snapshots"].as_array().is_none_or(Vec::is_empty),
            "{what}: a volume with snapshots"
        );
        let slot = usize::try_from(listed["slot"].as_u64().expect("a slot")).expect("a slot");
        let dump =
            std::fs::read(dir.join(row["image"].as_str().expect("an image"))).expect("the dump");
        assert_eq!(
            sha(&dump),
            volume.sha256,
            "{what}: not the container the row pins"
        );
        let record: BTreeMap<String, String> = json(
            &dir.join("manifests")
                .join(&volume.row)
                .join(&volume.volume)
                .join("expect-0.json"),
        )["files"]
            .as_object()
            .expect("the probe records the files it wrote")
            .iter()
            .map(|(path, digest)| {
                let digest = digest.as_str().expect("a digest").to_string();
                (path.clone(), digest)
            })
            .collect();

        let (len, blocks) = read_dump(&dump);
        let size = blocks[&0].len();
        let reader = Reader::open_with(
            Held::with(size, len, blocks),
            &OpenOptions::new().volume(VolumeSelector::Slot(slot)),
        )
        .expect("the volume opens strictly");
        let source = ImageSource::read(reader, &Synthesis::default()).expect("reads as a source");
        assert!(
            source.fidelity().is_faithful(),
            "{what}: nothing synthesized"
        );
        let mut entries = source.into_entries();
        for entry in entries.iter_mut().filter(|e| e.path == b"/") {
            entry.xattrs.retain(|x| x.name != MACOS_ROOT_ATTRIBUTE);
        }
        let mut layered = LayeredSource::new().layer(entries);
        for path in MACOS_MADE {
            layered = layered
                .remove(path)
                .unwrap_or_else(|e| panic!("{what}: {e}"));
        }
        let entries = layered.into_entries();

        // A file the probe did not record writing, or holding other content than it recorded,
        // or an attribute it does not set, stops the build.
        for entry in &entries {
            let path = String::from_utf8_lossy(&entry.path);
            for x in &entry.xattrs {
                assert!(
                    x.name.starts_with(PROBE_ATTRIBUTE),
                    "{what}: {path} holds the attribute {}, which the corpus probe does not set",
                    String::from_utf8_lossy(&x.name)
                );
            }
            if let EntryKind::File(content) = &entry.kind {
                let key = to_hex(entry.path.strip_prefix(b"/").unwrap_or(&entry.path));
                let digest = digest_of(content);
                assert_eq!(
                    record.get(&key),
                    Some(&digest),
                    "{what}: {path} is not a file the corpus probe recorded writing"
                );
            }
        }

        let mut contents: BTreeSet<String> = record.into_values().collect();
        let at = Timestamp::from_secs(1_700_000_000);
        let linked = entries
            .iter()
            .find_map(|e| match &e.kind {
                EntryKind::HardLink { target } => Some(target.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{what}: a hard link"));
        let compressed = entries
            .iter()
            .filter(|e| e.darwin.as_ref().is_some_and(|d| d.compressed.is_some()))
            .map(|e| e.path.clone())
            .min()
            .unwrap_or_else(|| panic!("{what}: a compressed file"));
        let plain: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let note = b"a file in place of a directory\n".to_vec();
        contents.insert(sha(&plain));
        contents.insert(sha(&note));
        let replaced = vec![
            SourceEntry::new(
                compressed,
                EntryKind::File(plain.into()),
                Metadata::new(0o644, at),
            ),
            SourceEntry::new(
                REPLACED_DIRECTORY,
                EntryKind::File(note.into()),
                Metadata::new(0o600, at),
            ),
        ];
        let hidden: Vec<SourceEntry> = entries
            .iter()
            .filter(|e| HIDDEN.contains(&e.path.as_slice()))
            .map(|e| {
                let flags = e.darwin.as_ref().map_or(0, |d| d.bsd_flags);
                e.clone().with_darwin(Darwin::new(flags | UF_HIDDEN))
            })
            .collect();
        assert_eq!(
            hidden.len(),
            HIDDEN.len(),
            "{what}: the directories to hide"
        );
        let added = added_tree();
        for entry in &added {
            if let EntryKind::File(content) = &entry.kind {
                contents.insert(digest_of(content));
            }
        }

        let entries = LayeredSource::new()
            .layer(entries)
            .remove(&linked)
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .layer(replaced)
            .layer(hidden)
            .layer(added)
            .into_entries();
        Built { entries, contents }
    }

    /// A tree as the acceptance set's populated rows hold one, beneath [`ADDED`].
    fn added_tree() -> Vec<SourceEntry> {
        let beneath = |path: &[u8]| {
            if path == b"/" {
                ADDED.to_vec()
            } else {
                [ADDED, path].concat()
            }
        };
        super::populated::tree_up_to(60, 4, 109, 70_000)
            .into_iter()
            .map(|mut entry| {
                entry.path = beneath(&entry.path);
                if let EntryKind::HardLink { target } = &mut entry.kind {
                    *target = beneath(target);
                }
                entry
            })
            .collect()
    }
}

#[cfg(test)]
mod differential {
    use std::collections::BTreeMap;
    use std::io::{Seek, SeekFrom};

    use super::tests::{Held, read_dump};
    use super::*;
    use crate::apfs::ondisk::{
        EntryValue, InodeValue, KeyHeader, extended_fields, inode_field, inode_number, record_kind,
    };
    use crate::apfs::{Container, Reader};

    /// A record's key and value with every field a named divergence covers cleared.
    fn normalized(key: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let header = KeyHeader::read_from(key).expect("a key");
        let mut value = value.to_vec();
        match header.kind {
            record_kind::INODE => {
                // The write counter, which a record written once leaves at 1.
                value[64..68].fill(0);
                if header.id == inode_number::PRIVATE {
                    // The private directory's times are the format's own instant.
                    value[16..48].fill(0);
                }
            }
            record_kind::DIR_ENTRY => {
                // When each entry was added: the copy's clock, and the format's instant here.
                value[8..16].fill(0);
            }
            record_kind::FILE_EXTENT => {
                // Where a stream's blocks are is each writer's choice.
                value[8..16].fill(0);
            }
            _ => {}
        }
        (key.to_vec(), value)
    }

    /// The volume `open` chooses of the container `held` gives, read back as a source and
    /// written again as the writer writes it on `release`, at the container's block size and the
    /// volume's name kind: Apple's volume, and the writer's, each opened, the writer's scanned
    /// clean. `path` names the dump in a failure.
    fn written_again(
        release: &str,
        held: &dyn Fn() -> Held,
        open: &crate::apfs::OpenOptions,
        path: &str,
    ) -> (Reader<Held>, Reader<Held>) {
        let container = Container::open(held()).expect("the container");
        let block_size = container.block_size();
        let reader = Reader::open_with(held(), open).expect("the volume");
        let superblock = reader.superblock().clone();
        let source = crate::ImageSource::read(
            Reader::open_with(held(), open).expect("the volume"),
            &crate::Synthesis::default(),
        )
        .expect("the volume reads as a source");
        assert!(
            source.fidelity().is_faithful(),
            "{path}: nothing synthesized"
        );

        let names = if superblock.is_case_insensitive() {
            NameKind::CaseFolding
        } else {
            NameKind::CaseKeeping
        };
        let profile = match release {
            "14" => ReleaseProfile::Macos14,
            "15" => ReleaseProfile::Macos15,
            "26" => ReleaseProfile::Macos26,
            _ => ReleaseProfile::Macos27,
        };
        let block = match block_size {
            4096 => BlockSize::K4,
            8192 => BlockSize::K8,
            16384 => BlockSize::K16,
            32768 => BlockSize::K32,
            _ => BlockSize::K64,
        };
        let options = FormatOptions::new(
            container.superblock().uuid,
            Timestamp::from_secs(1_700_000_000),
            VolumeRequest::new(
                VolumeName::new(std::str::from_utf8(superblock.name_bytes()).expect("a name"))
                    .expect("a volume name"),
                superblock.uuid,
            )
            .names(names),
        )
        .block_size(block)
        .profile(profile);
        let len = held().seek(SeekFrom::End(0)).expect("a length");
        let plan = FormatPlan::new(source, len, options).expect("the writer plans it");
        let mut written = Held::empty(usize::try_from(block_size).expect("a block size"));
        plan.write_to(&mut written).expect("writes");
        let mut ours = Reader::open(written.rewound()).expect("ours opens");
        let scan = ours.scan();
        assert!(
            scan.anomalies().is_empty(),
            "{path}: ours scans clean: {:?}",
            &scan.anomalies()[..scan.anomalies().len().min(4)]
        );
        (reader, ours)
    }

    /// How the volume `apple` holds differs from the one the writer writes from it, record by
    /// record, once the named divergences are cleared.
    fn compare(release: &str, path: &str) -> Vec<String> {
        let (len, blocks) = read_dump(&std::fs::read(path).expect("a dump"));
        let size = blocks[&0].len();
        let held = || Held::with(size, len, blocks.clone());
        let (mut reader, mut ours) =
            written_again(release, &held, &crate::apfs::OpenOptions::new(), path);
        let apple = reader.every_record().expect("records");
        let mine = ours.every_record().expect("records");

        let them: BTreeMap<Vec<u8>, Vec<u8>> =
            apple.iter().map(|(k, v)| normalized(k, v)).collect();
        let us: BTreeMap<Vec<u8>, Vec<u8>> = mine.iter().map(|(k, v)| normalized(k, v)).collect();
        let mut found = Vec::new();
        for (key, value) in &them {
            match us.get(key) {
                None => found.push(format!("only hdiutil's: {}", describe(key, value))),
                Some(ours) if ours != value => found.push(format!(
                    "differs: {}\n      hdiutil {}\n      ours    {}",
                    describe(key, value),
                    to_hex_short(value),
                    to_hex_short(ours)
                )),
                Some(_) => {}
            }
        }
        for (key, value) in &us {
            if !them.contains_key(key) {
                found.push(format!("only ours: {}", describe(key, value)));
            }
        }
        found
    }

    fn to_hex_short(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn describe(key: &[u8], value: &[u8]) -> String {
        let header = KeyHeader::read_from(key).expect("a key");
        let extra = match header.kind {
            record_kind::INODE => {
                let inode = InodeValue::read_from(value).expect("an inode");
                let fields = extended_fields(&value[InodeValue::SIZE..]).expect("fields");
                let name = crate::apfs::ondisk::field(&fields, inode_field::NAME)
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .unwrap_or_default();
                format!("inode {name:?} mode {:o}", inode.mode)
            }
            record_kind::DIR_ENTRY => {
                let entry = EntryValue::read_from(value).expect("an entry");
                format!("entry of {} naming {}", header.id, entry.file_id)
            }
            _ => String::new(),
        };
        format!("id {} kind {} {extra}", header.id, header.kind)
    }

    /// The `srcfolder` volumes `hdiutil create -srcfolder` wrote, read back as sources and
    /// written again, hold the records `hdiutil` wrote but for the named divergences.
    ///
    /// With `FERROSYS_APFS_SRCFOLDER=FILE`, each line of FILE a release and a dump's path, every
    /// dump is compared; without it there is nothing to compare and it passes.
    #[test]
    fn every_srcfolder_volume_is_written_again_record_for_record() {
        let Some(list) = std::env::var_os("FERROSYS_APFS_SRCFOLDER") else {
            return;
        };
        let list = std::fs::read_to_string(list).expect("the list");
        let mut report = Vec::new();
        for line in list.lines().filter(|l| !l.is_empty()) {
            let (release, path) = line.split_once(' ').expect("RELEASE PATH");
            let found = compare(release, path);
            if !found.is_empty() {
                report.push(format!("{path} ({} differences)", found.len()));
                report.extend(found.into_iter().take(12).map(|f| format!("  {f}")));
            }
        }
        assert!(report.is_empty(), "\n{}", report.join("\n"));
    }

    /// The corpus read back and written again: its compressed files are read as the decoders
    /// read them, so it is built with every one.
    #[cfg(all(
        feature = "zlib",
        feature = "lzvn",
        feature = "lzfse",
        feature = "lzbitmap"
    ))]
    mod corpus {
        use super::super::tests::apfs_corpus;
        use super::*;
        use crate::apfs::ondisk::{
            DataStream, ExtendedField, FileExtent, SiblingLink, XattrValue, extended_field_blob,
            xattr_flags,
        };

        /// One view of a corpus volume: the live volume, or one of its snapshots.
        struct View {
            release: String,
            image: std::path::PathBuf,
            slot: usize,
            snapshot: Option<Vec<u8>>,
        }

        /// Every view the corpus's listings name, each release's in its rows' order.
        fn views(corpus: &std::path::Path) -> Vec<View> {
            let mut releases: Vec<std::path::PathBuf> = std::fs::read_dir(corpus)
                .expect("the corpus")
                .map(|e| e.expect("an entry").path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("corpus-"))
                })
                .collect();
            releases.sort();
            let mut out = Vec::new();
            for dir in releases {
                let name = dir
                    .file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned();
                let release = name.rsplit('-').next().expect("a release").to_string();
                let index: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(dir.join("corpus.json")).expect("an index"),
                )
                .expect("JSON");
                for row in index["rows"].as_array().expect("rows") {
                    let image = dir.join(row["image"].as_str().expect("an image"));
                    for volume in row["volume_list"].as_array().expect("volumes") {
                        let slot = usize::try_from(volume["slot"].as_u64().expect("a slot"))
                            .expect("a slot");
                        let snapshots = volume["snapshots"].as_array().cloned().unwrap_or_default();
                        let names = snapshots
                            .iter()
                            .map(|s| Some(s["name"].as_str().expect("a name").as_bytes().to_vec()));
                        for snapshot in std::iter::once(None).chain(names) {
                            out.push(View {
                                release: release.clone(),
                                image: image.clone(),
                                slot,
                                snapshot,
                            });
                        }
                    }
                }
            }
            out
        }

        /// What the corpus differential set aside, by the divergence that set it aside, each
        /// counted only where the two volumes differ in it.
        #[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
        struct SetAside {
            /// A file of several names records one of them as its own, its directory as its parent:
            /// macOS the name it was made or last renamed under, the writer the first it meets.
            primary_name: usize,
            /// Bytes ever written to and read from a stream: what a file's history did, where the
            /// writer's file was written once.
            counters: usize,
            /// A clone: macOS's two files share a stream and say they were cloned, and the writer
            /// writes each with its own.
            clones: usize,
            /// A sparse file: macOS keeps its holes, and the source states none, so the writer
            /// writes them as zeros.
            sparse: usize,
            /// A file compressed after it was written keeps the empty stream it had, which a file
            /// written compressed never had.
            compressed_in_place: usize,
            /// A stream's run cut into extents differently, which is each writer's allocation.
            extents_cut: usize,
            /// An inode's write counter.
            write_count: usize,
            /// When each directory entry was added.
            date_added: usize,
        }

        impl std::ops::AddAssign for SetAside {
            fn add_assign(&mut self, o: Self) {
                self.primary_name += o.primary_name;
                self.counters += o.counters;
                self.clones += o.clones;
                self.sparse += o.sparse;
                self.compressed_in_place += o.compressed_in_place;
                self.extents_cut += o.extents_cut;
                self.write_count += o.write_count;
                self.date_added += o.date_added;
            }
        }

        /// `key` with its identifier `id`, its kind kept.
        fn rekeyed(key: &[u8], id: u64) -> Vec<u8> {
            let mut key = key.to_vec();
            let kind = crate::bytes::get_u64(&key, 0) & !crate::apfs::ondisk::ID_MASK;
            crate::bytes::put_u64(&mut key, 0, kind | id);
            key
        }

        /// An inode's value taken apart: its fixed fields, and its extended fields in order.
        struct Parts {
            base: Vec<u8>,
            fields: Vec<(u8, u8, Vec<u8>)>,
        }

        impl Parts {
            fn of(value: &[u8]) -> Self {
                let fields = extended_fields(&value[InodeValue::SIZE..])
                    .expect("fields")
                    .into_iter()
                    .map(|f| (f.kind, f.flags, f.data.to_vec()))
                    .collect();
                Self {
                    base: value[..InodeValue::SIZE].to_vec(),
                    fields,
                }
            }

            fn field(&self, kind: u8) -> Option<&Vec<u8>> {
                self.fields.iter().find(|f| f.0 == kind).map(|f| &f.2)
            }

            fn field_mut(&mut self, kind: u8) -> Option<&mut Vec<u8>> {
                self.fields
                    .iter_mut()
                    .find(|f| f.0 == kind)
                    .map(|f| &mut f.2)
            }

            fn drop_field(&mut self, kind: u8) {
                self.fields.retain(|f| f.0 != kind);
            }

            fn value(&self) -> Vec<u8> {
                let fields: Vec<ExtendedField<'_>> = self
                    .fields
                    .iter()
                    .map(|(kind, flags, data)| ExtendedField {
                        kind: *kind,
                        flags: *flags,
                        data,
                    })
                    .collect();
                let mut out = self.base.clone();
                out.extend(extended_field_blob(&fields));
                out
            }
        }

        /// Every path a walk reaches, with its inode's identifier.
        fn inodes_by_path(reader: &mut Reader<Held>) -> BTreeMap<Vec<u8>, u64> {
            reader
                .walk()
                .expect("the volume walks")
                .into_iter()
                .map(|entry| (entry.path, entry.node.inode))
                .collect()
        }

        /// Each file extent of `records`, merged into the runs of its stream: a run the next begins
        /// where it ends, with the same flags and encryption, is one run. Where each run's blocks
        /// are is each writer's choice, and is left out.
        fn runs(records: &BTreeMap<Vec<u8>, Vec<u8>>) -> BTreeMap<u64, Vec<(u64, u64, u8, u64)>> {
            let mut out: BTreeMap<u64, Vec<(u64, u64, u8, u64)>> = BTreeMap::new();
            for (key, value) in records {
                let header = KeyHeader::read_from(key).expect("a key");
                if header.kind != record_kind::FILE_EXTENT {
                    continue;
                }
                let extent = FileExtent::read_from(key, value).expect("an extent");
                let stream = out.entry(header.id).or_default();
                match stream.last_mut() {
                    Some(last)
                        if last.0 + last.1 == extent.logical
                            && last.2 == extent.flags
                            && last.3 == extent.crypto_id =>
                    {
                        last.1 += extent.length;
                    }
                    _ => stream.push((
                        extent.logical,
                        extent.length,
                        extent.flags,
                        extent.crypto_id,
                    )),
                }
            }
            out
        }

        /// How the corpus volume `view` names differs from the one the writer writes from it,
        /// record by record, once Apple's identifiers are the writer's and the named divergences are
        /// set aside; with what was set aside and how many records were compared.
        fn compare_view(view: &View) -> (Vec<String>, SetAside, usize) {
            let path = format!(
                "{} slot {}{}",
                view.image.display(),
                view.slot,
                view.snapshot
                    .as_ref()
                    .map(|s| format!(" at {}", String::from_utf8_lossy(s)))
                    .unwrap_or_default()
            );
            let (len, blocks) = read_dump(&std::fs::read(&view.image).expect("a dump"));
            let size = blocks[&0].len();
            let held = || Held::with(size, len, blocks.clone());
            let mut open = crate::apfs::OpenOptions::new()
                .volume(crate::apfs::VolumeSelector::Slot(view.slot));
            if let Some(snapshot) = &view.snapshot {
                open = open.snapshot(snapshot.clone());
            }
            compare_volume(&view.release, &held, &open, &path)
        }

        /// How the volume `open` chooses of the container `held` gives differs from the one the
        /// writer writes from it on `release`, as [`compare_view`] has it. `path` names it in a
        /// failure.
        fn compare_volume(
            release: &str,
            held: &dyn Fn() -> Held,
            open: &crate::apfs::OpenOptions,
            path: &str,
        ) -> (Vec<String>, SetAside, usize) {
            let path = path.to_string();
            let (mut apple_reader, mut ours) = written_again(release, held, open, &path);
            let apple: BTreeMap<Vec<u8>, Vec<u8>> = apple_reader
                .every_record()
                .expect("records")
                .into_iter()
                .collect();
            let mine: BTreeMap<Vec<u8>, Vec<u8>> =
                ours.every_record().expect("records").into_iter().collect();
            let block = u64::from(apple_reader.container().block_size());
            let mut set_aside = SetAside::default();
            let mut found = Vec::new();

            // Apple's identifiers, as the writer's: an inode's by the path that reaches it, and an
            // attribute's stream and a name's sibling by what they belong to. A stream is keyed by
            // its inode's own identifier, but for a clone's, which is the file it was cloned from.
            let apple_paths = inodes_by_path(&mut apple_reader);
            let our_paths = inodes_by_path(&mut ours);
            let mut inodes: BTreeMap<u64, u64> = [
                (inode_number::ROOT_PARENT, inode_number::ROOT_PARENT),
                (inode_number::PRIVATE, inode_number::PRIVATE),
            ]
            .into();
            for (p, apple_id) in &apple_paths {
                let ours = our_paths
                    .get(p)
                    .unwrap_or_else(|| panic!("{path}: {p:?} written"));
                assert_eq!(
                    *inodes.entry(*apple_id).or_insert(*ours),
                    *ours,
                    "{path}: {p:?}"
                );
            }
            assert_eq!(
                apple_paths.len(),
                our_paths.len(),
                "{path}: the paths written"
            );
            let mut streams = inodes.clone();
            let mut siblings: BTreeMap<u64, u64> = BTreeMap::new();
            let mut our_names: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
            for (key, value) in &mine {
                let header = KeyHeader::read_from(key).expect("a key");
                if header.kind == record_kind::SIBLING_LINK {
                    let link = SiblingLink::read_from(key, value).expect("a sibling");
                    our_names
                        .entry(header.id)
                        .or_default()
                        .push((link.parent_id, link.name.to_vec()));
                }
            }
            for (key, value) in &apple {
                let header = KeyHeader::read_from(key).expect("a key");
                let ours = |key: Vec<u8>| mine.get(&key).cloned();
                if header.kind == record_kind::XATTR
                    && XattrValue::read_from(value).expect("an attribute").flags
                        & xattr_flags::STREAM
                        != 0
                {
                    let mine =
                        ours(rekeyed(key, inodes[&header.id])).expect("the attribute written");
                    streams.insert(
                        crate::bytes::get_u64(value, 4),
                        crate::bytes::get_u64(&mine, 4),
                    );
                }
                if header.kind == record_kind::SIBLING_LINK {
                    let link = SiblingLink::read_from(key, value).expect("a sibling");
                    let inode = inodes[&header.id];
                    let parent = inodes[&link.parent_id];
                    let sibling = mine
                        .iter()
                        .filter(|(k, _)| KeyHeader::read_from(k).expect("a key").id == inode)
                        .filter_map(|(k, v)| SiblingLink::read_from(k, v).ok())
                        .find(|l| l.parent_id == parent && l.name == link.name)
                        .unwrap_or_else(|| panic!("{path}: a name of {inode} written"));
                    siblings.insert(link.sibling_id, sibling.sibling_id);
                }
            }

            // A clone shares its source's stream: the stream's records go to each of the files
            // sharing it, as the writer writes each file with its own.
            let mut sharers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            for (key, value) in &apple {
                let header = KeyHeader::read_from(key).expect("a key");
                if header.kind == record_kind::INODE {
                    let stream = InodeValue::read_from(value).expect("an inode").private_id;
                    sharers.entry(stream).or_default().push(header.id);
                }
            }

            let mut them: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for (key, value) in &apple {
                let header = KeyHeader::read_from(key).expect("a key");
                let mut value = value.clone();
                let translated: Vec<(Vec<u8>, Vec<u8>)> = match header.kind {
                    record_kind::INODE => {
                        let inode = InodeValue::read_from(&value).expect("an inode");
                        crate::bytes::put_u64(&mut value, 0, inodes[&inode.parent_id]);
                        // Its own stream, the writer's, where macOS's is a clone's shared one.
                        crate::bytes::put_u64(&mut value, 8, inodes[&header.id]);
                        vec![(rekeyed(key, inodes[&header.id]), value)]
                    }
                    record_kind::DIR_ENTRY => {
                        let entry = EntryValue::read_from(&value).expect("an entry");
                        crate::bytes::put_u64(&mut value, 0, inodes[&entry.file_id]);
                        let fields = extended_fields(&value[EntryValue::SIZE..]).expect("fields");
                        if let Some(sibling) = crate::apfs::ondisk::field(
                            &fields,
                            crate::apfs::ondisk::SIBLING_ID_FIELD,
                        ) {
                            let old = crate::bytes::get_u64(sibling, 0);
                            let at = value.len()
                                - value
                                    .windows(8)
                                    .rev()
                                    .position(|w| w == old.to_le_bytes())
                                    .expect("the sibling")
                                - 8;
                            crate::bytes::put_u64(&mut value, at, siblings[&old]);
                        }
                        vec![(rekeyed(key, inodes[&header.id]), value)]
                    }
                    record_kind::XATTR => {
                        if XattrValue::read_from(&value).expect("an attribute").flags
                            & xattr_flags::STREAM
                            != 0
                        {
                            let stream = streams[&crate::bytes::get_u64(&value, 4)];
                            crate::bytes::put_u64(&mut value, 4, stream);
                        }
                        vec![(rekeyed(key, inodes[&header.id]), value)]
                    }
                    record_kind::SIBLING_LINK => {
                        let mut k = rekeyed(key, inodes[&header.id]);
                        let w = siblings[&crate::bytes::get_u64(key, 8)];
                        crate::bytes::put_u64(&mut k, 8, w);
                        let w = inodes[&crate::bytes::get_u64(&value, 0)];
                        crate::bytes::put_u64(&mut value, 0, w);
                        vec![(k, value)]
                    }
                    record_kind::SIBLING_MAP => {
                        let w = inodes[&crate::bytes::get_u64(&value, 0)];
                        crate::bytes::put_u64(&mut value, 0, w);
                        vec![(rekeyed(key, siblings[&header.id]), value)]
                    }
                    record_kind::DATA_STREAM_ID | record_kind::FILE_EXTENT => {
                        // A stream several files share is each one's.
                        let owners = sharers.get(&header.id).cloned().unwrap_or_default();
                        if owners.len() > 1 {
                            if header.kind == record_kind::DATA_STREAM_ID {
                                crate::bytes::put_u32(&mut value, 0, 1);
                                set_aside.clones += 1;
                            }
                            owners
                                .iter()
                                .map(|o| (rekeyed(key, inodes[o]), value.clone()))
                                .collect()
                        } else if let [owner] = owners[..] {
                            // The one file using it, whose own the writer's stream is, whichever
                            // identifier macOS's stream kept from a file cloned and since removed.
                            vec![(rekeyed(key, inodes[&owner]), value)]
                        } else {
                            let stream = streams.get(&header.id).unwrap_or_else(|| {
                                panic!("{path}: stream {} belongs to nothing", header.id)
                            });
                            vec![(rekeyed(key, *stream), value)]
                        }
                    }
                    other => panic!("{path}: a record of kind {other} in a volume's tree"),
                };
                them.extend(translated);
            }

            // The divergences, record by record, each set aside only where the writer's differs.
            let mut dropped_streams = Vec::new();
            let mut sparse_streams: BTreeMap<u64, u64> = BTreeMap::new();
            for (key, value) in &mut them {
                let header = KeyHeader::read_from(key).expect("a key");
                let Some(ours) = mine.get(key) else { continue };
                match header.kind {
                    record_kind::INODE => {
                        let mut apple = Parts::of(value);
                        let mine = Parts::of(ours);
                        let flags = crate::bytes::get_u64(&apple.base, 48);
                        if apple.base[64..68] != mine.base[64..68] {
                            apple.base[64..68].copy_from_slice(&mine.base[64..68]);
                            set_aside.write_count += 1;
                        }
                        if header.id == inode_number::PRIVATE {
                            apple.base[16..48].copy_from_slice(&mine.base[16..48]);
                        }
                        if flags & 0x410 != 0 {
                            let w = crate::bytes::get_u64(&apple.base, 48) & !0x410;
                            crate::bytes::put_u64(&mut apple.base, 48, w);
                            // A clone lists its stream before its name, where a file written once
                            // lists its name first.
                            let order = |kind: u8| mine.fields.iter().position(|f| f.0 == kind);
                            apple.fields.sort_by_key(|f| order(f.0));
                            set_aside.clones += 1;
                        }
                        if flags & 0x200 != 0 {
                            let w = crate::bytes::get_u64(&apple.base, 48) & !0x200;
                            crate::bytes::put_u64(&mut apple.base, 48, w);
                            apple.drop_field(inode_field::SPARSE_BYTES);
                            let size = DataStream::read_from(
                                apple.field(inode_field::DATA_STREAM).expect("a stream"),
                            )
                            .expect("a stream")
                            .size;
                            let allocated = size.div_ceil(block) * block;
                            let stream =
                                apple.field_mut(inode_field::DATA_STREAM).expect("a stream");
                            crate::bytes::put_u64(stream, 8, allocated);
                            sparse_streams.insert(header.id, allocated);
                            set_aside.sparse += 1;
                        }
                        if flags & crate::apfs::ondisk::INTERNAL_COMPRESSED != 0
                            && mine.field(inode_field::DATA_STREAM).is_none()
                            && apple
                                .field(inode_field::DATA_STREAM)
                                .is_some_and(|d| crate::bytes::get_u64(d, 0) == 0)
                        {
                            apple.drop_field(inode_field::DATA_STREAM);
                            dropped_streams.push(header.id);
                            set_aside.compressed_in_place += 1;
                        }
                        if let (Some(a), Some(m)) = (
                            apple.field(inode_field::DATA_STREAM).cloned(),
                            mine.field(inode_field::DATA_STREAM),
                        ) && a[24..40] != m[24..40]
                        {
                            apple.field_mut(inode_field::DATA_STREAM).expect("a stream")[24..40]
                                .copy_from_slice(&m[24..40]);
                            set_aside.counters += 1;
                        }
                        let links = crate::bytes::get_u32(&apple.base, 56) as i32;
                        let own = (
                            apple.base[..8].to_vec(),
                            apple.field(inode_field::NAME).cloned(),
                        );
                        let theirs = (
                            mine.base[..8].to_vec(),
                            mine.field(inode_field::NAME).cloned(),
                        );
                        if (InodeValue::read_from(value).expect("an inode").mode & 0o170000)
                            != 0o040000
                            && links > 1
                            && own != theirs
                        {
                            // One of the file's names, chosen differently.
                            let parent = crate::bytes::get_u64(&own.0, 0);
                            let name = own
                                .1
                                .as_ref()
                                .and_then(|n| n.split_last())
                                .map(|(_, n)| n.to_vec())
                                .unwrap_or_default();
                            assert!(
                                our_names
                                    .get(&header.id)
                                    .is_some_and(|names| names.contains(&(parent, name))),
                                "{path}: inode {} records a name it has",
                                header.id
                            );
                            apple.base[..8].copy_from_slice(&mine.base[..8]);
                            apple.drop_field(inode_field::NAME);
                            if let Some(n) = mine.field(inode_field::NAME) {
                                apple.fields.insert(
                                    0,
                                    (
                                        inode_field::NAME,
                                        crate::apfs::records::NAME_FIELD_FLAGS,
                                        n.clone(),
                                    ),
                                );
                            }
                            set_aside.primary_name += 1;
                        }
                        *value = apple.value();
                    }
                    record_kind::DIR_ENTRY => {
                        if value[8..16] != ours[8..16] {
                            value[8..16].copy_from_slice(&ours[8..16]);
                            set_aside.date_added += 1;
                        }
                    }
                    record_kind::XATTR => {
                        let streamed = XattrValue::read_from(value).expect("an attribute").flags
                            & xattr_flags::STREAM
                            != 0;
                        // The stream's counters, after its identifier and three words.
                        if streamed && value[36..52] != ours[36..52] {
                            value[36..52].copy_from_slice(&ours[36..52]);
                            set_aside.counters += 1;
                        }
                    }
                    _ => {}
                }
            }
            for stream in dropped_streams {
                let key = rekeyed(&[0u8; 8], stream);
                let mut key = key;
                crate::bytes::put_u64(
                    &mut key,
                    0,
                    stream
                        | (u64::from(record_kind::DATA_STREAM_ID)
                            << crate::apfs::ondisk::KIND_SHIFT),
                );
                them.remove(&key).expect("the empty stream's record");
            }

            // A stream's extents, as its runs: a sparse one's holes written as zeros.
            let mut apple_runs = runs(&them);
            let our_runs = runs(&mine);
            for (stream, allocated) in &sparse_streams {
                let held = apple_runs.remove(stream).unwrap_or_default();
                assert!(
                    held.iter().all(|r| r.0 + r.1 <= *allocated),
                    "{path}: stream {stream}"
                );
                if *allocated > 0 {
                    apple_runs.insert(*stream, vec![(0, *allocated, 0, 0)]);
                }
            }
            for (stream, cut) in &apple_runs {
                let raw = them
                    .keys()
                    .filter(|k| {
                        let h = KeyHeader::read_from(k).expect("a key");
                        h.kind == record_kind::FILE_EXTENT && h.id == *stream
                    })
                    .count();
                let ours_raw = mine
                    .keys()
                    .filter(|k| {
                        let h = KeyHeader::read_from(k).expect("a key");
                        h.kind == record_kind::FILE_EXTENT && h.id == *stream
                    })
                    .count();
                if raw != ours_raw && !sparse_streams.contains_key(stream) {
                    set_aside.extents_cut += 1;
                }
                if our_runs.get(stream) != Some(cut) {
                    found.push(format!(
                        "{path}: stream {stream} runs {cut:?}, the writer's {:?}",
                        our_runs.get(stream)
                    ));
                }
            }
            for stream in our_runs.keys() {
                if !apple_runs.contains_key(stream) {
                    found.push(format!("{path}: stream {stream} runs only in the writer's"));
                }
            }
            let is_extent = |k: &Vec<u8>| {
                KeyHeader::read_from(k).expect("a key").kind == record_kind::FILE_EXTENT
            };
            them.retain(|k, _| !is_extent(k));
            let compared = them.len();

            for (key, value) in &them {
                match mine.get(key) {
                    None => found.push(format!("{path}: only macOS's: {}", describe(key, value))),
                    Some(ours) if ours != value => found.push(format!(
                        "{path}: differs: {}\n      macOS  {}\n      writer {}",
                        describe(key, value),
                        to_hex_short(value),
                        to_hex_short(ours)
                    )),
                    Some(_) => {}
                }
            }
            for (key, value) in &mine {
                if !is_extent(key) && !them.contains_key(key) {
                    found.push(format!(
                        "{path}: only the writer's: {}",
                        describe(key, value)
                    ));
                }
            }
            (found, set_aside, compared)
        }

        /// Apple's restore RAM disk, read back as a source and written again, holds the records
        /// Apple's writer wrote for the same files but for the named divergences, each counted and
        /// the counts held to what the pinned container gives. Its compressed files' headers and
        /// forks, every flag, protection class and attribute are Apple's to the byte.
        ///
        /// Run where `FERROSYS_APFS_RAMDISK_LISTING` asks for the gates on the RAM disk, as
        /// `tests/apfs_ramdisk.rs` has them: `ci/fetch-apple-ramdisk.sh` fetches it into a
        /// cache, the container is held to its digest, and nothing of it is committed.
        #[test]
        fn apples_restore_ram_disk_is_written_again_record_for_record() {
            use sha2::{Digest, Sha256};
            if std::env::var_os("FERROSYS_APFS_RAMDISK_LISTING").is_none() {
                return;
            }
            let ask = |flag: &str| {
                let out = std::process::Command::new("bash")
                    .arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../../ci/fetch-apple-ramdisk.sh"),
                    )
                    .arg(flag)
                    .output()
                    .expect("run ci/fetch-apple-ramdisk.sh");
                assert!(out.status.success(), "ci/fetch-apple-ramdisk.sh {flag}");
                String::from_utf8(out.stdout)
                    .expect("text")
                    .trim()
                    .to_string()
            };
            let image = ask("--print-path");
            let bytes =
                std::fs::read(&image).expect("the container ci/fetch-apple-ramdisk.sh fetches");
            assert_eq!(
                super::super::tests::to_hex(&Sha256::digest(&bytes)),
                ask("--print-sha256"),
                "the container"
            );
            let size = 4096;
            let zero = vec![0u8; size];
            let blocks: BTreeMap<u64, Vec<u8>> = (0u64..)
                .zip(bytes.chunks(size))
                .filter(|(_, b)| *b != zero.as_slice())
                .map(|(i, b)| (i, b.to_vec()))
                .collect();
            let len = bytes.len() as u64;
            drop(bytes);
            let held = || Held::with(size, len, blocks.clone());
            let (found, set_aside, compared) =
                compare_volume("26", &held, &crate::apfs::OpenOptions::new(), &image);
            assert!(
                found.is_empty(),
                "\n{}",
                found[..found.len().min(12)].join("\n")
            );
            assert_eq!(compared, 8084, "records compared");
            assert_eq!(
                set_aside,
                SetAside {
                    counters: 921,
                    extents_cut: 1,
                    write_count: 2093,
                    date_added: 2654,
                    ..SetAside::default()
                }
            );
        }

        /// What macOS changes in a container it accepted is what a mount and the accept probe's
        /// file add: objects of their own, and at the root, an entry for each, the attribute
        /// `purgeable-drecs-fixed`, and its modification and change times, its count of children
        /// and its write counter. No other record of an entry the writer wrote changes or goes,
        /// and no volume's feature words or encryption state.
        ///
        /// Each container an accept run sent is held beside the one it dumped after macOS mounted
        /// it read-write and the probe wrote its file. Run where `FERROSYS_APFS_WRITTEN` names a
        /// list of `SENT WRITTEN NAME RELEASE RUN` lines, each dump uncompressed; the dumps are
        /// the runs' own and are not committed.
        #[test]
        fn macos_changes_only_what_a_mount_and_the_probe_add_in_a_container_it_accepted() {
            let Some(list) = std::env::var_os("FERROSYS_APFS_WRITTEN") else {
                return;
            };
            let list = std::fs::read_to_string(list).expect("the list");
            let held_of = |path: &str| {
                let (len, blocks) = read_dump(&std::fs::read(path).expect("a dump"));
                let size = blocks[&0].len();
                move || Held::with(size, len, blocks.clone())
            };
            // The bytes of the root's inode a mount that adds to it changes: its modification and
            // change times, its count of children and its write counter.
            let root_may_change = |at: usize| {
                (24..40).contains(&at) || (56..60).contains(&at) || (64..68).contains(&at)
            };
            let mut problems = Vec::new();
            let mut volumes = 0;
            for line in list.lines().filter(|l| !l.is_empty()) {
                let w: Vec<&str> = line.split(' ').collect();
                let what = format!("{} {} {}", w[4], w[3], w[2]);
                let (sent, written) = (held_of(w[0]), held_of(w[1]));
                let slots = Container::open(sent()).expect("opens").volumes().len();
                for slot in 0..slots {
                    volumes += 1;
                    let open = crate::apfs::OpenOptions::new()
                        .volume(crate::apfs::VolumeSelector::Slot(slot));
                    let mut a = Reader::open_with(sent(), &open).expect("the sent volume");
                    let mut b = Reader::open_with(written(), &open).expect("the written volume");
                    let (sa, sb) = (a.superblock(), b.superblock());
                    if (
                        sa.features,
                        sa.readonly_compatible_features,
                        sa.incompatible_features,
                    ) != (
                        sb.features,
                        sb.readonly_compatible_features,
                        sb.incompatible_features,
                    ) || sa.meta_crypto != sb.meta_crypto
                    {
                        problems.push(format!("{what} slot {slot}: the volume's words"));
                    }
                    let ra: BTreeMap<Vec<u8>, Vec<u8>> =
                        a.every_record().expect("records").into_iter().collect();
                    let rb: BTreeMap<Vec<u8>, Vec<u8>> =
                        b.every_record().expect("records").into_iter().collect();
                    let held: std::collections::BTreeSet<u64> = ra
                        .keys()
                        .map(|k| KeyHeader::read_from(k).expect("a key").id)
                        .collect();
                    for key in ra.keys().chain(rb.keys().filter(|k| !ra.contains_key(*k))) {
                        let (x, y) = (ra.get(key), rb.get(key));
                        if x == y {
                            continue;
                        }
                        let h = KeyHeader::read_from(key).expect("a key");
                        let fine = match (x, y) {
                            _ if !held.contains(&h.id) => true,
                            _ if h.id != inode_number::ROOT => false,
                            (None, Some(_)) => match h.kind {
                                record_kind::DIR_ENTRY => true,
                                record_kind::XATTR => {
                                    crate::apfs::ondisk::xattr_name(key).expect("a key")
                                        == b"purgeable-drecs-fixed"
                                }
                                _ => false,
                            },
                            (Some(x), Some(y)) if h.kind == record_kind::INODE => {
                                x.len() == y.len()
                                    && (0..x.len()).all(|i| x[i] == y[i] || root_may_change(i))
                            }
                            _ => false,
                        };
                        if !fine {
                            problems.push(format!(
                                "{what} slot {slot}: {} changed",
                                describe(key, x.or(y).expect("one of them"))
                            ));
                        }
                    }
                }
            }
            assert!(volumes > 0, "no container to hold");
            assert!(
                problems.is_empty(),
                "\n{}",
                problems[..problems.len().min(12)].join("\n")
            );
        }

        /// Every volume of the corpus macOS made, and each of its snapshots, read back as a source and
        /// written again, holds the records macOS wrote but for the named divergences: its
        /// identifiers translated to the writer's by what each names, and each divergence set aside
        /// only where the two differ, counted, and the counts held to what the pinned corpus gives.
        ///
        /// Run where `FERROSYS_APFS_CORPUS_DIFFERENTIAL` is set, which the optimized workspace run of
        /// CI and of `ci/preflight.sh` sets: a debug build takes minutes over it. Where it is set,
        /// the corpus `ci/fetch-apfs-corpus.sh` unpacks must be present.
        #[test]
        fn every_corpus_volume_is_written_again_record_for_record() {
            if std::env::var_os("FERROSYS_APFS_CORPUS_DIFFERENTIAL").is_none() {
                return;
            }
            let corpus = apfs_corpus().expect("the corpus ci/fetch-apfs-corpus.sh unpacks");
            let views = views(&corpus);
            let next = std::sync::atomic::AtomicUsize::new(0);
            let results = std::sync::Mutex::new(Vec::new());
            let threads = std::thread::available_parallelism().map_or(4, usize::from);
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    scope.spawn(|| {
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(view) = views.get(i) else { break };
                            let outcome = compare_view(view);
                            results.lock().expect("a lock").push(outcome);
                        }
                    });
                }
            });
            let results = results.into_inner().expect("a lock");
            let mut set_aside = SetAside::default();
            let mut compared = 0;
            let mut report = Vec::new();
            for (found, aside, n) in results {
                set_aside += aside;
                compared += n;
                report.extend(found.into_iter().take(12));
            }
            assert!(report.is_empty(), "\n{}", report.join("\n"));
            // What the pinned corpus gives: a gate that compared less, or set more aside, fails.
            assert_eq!(
                (views.len(), compared),
                (100, 546_802),
                "views and records compared"
            );
            assert_eq!(
                set_aside,
                SetAside {
                    primary_name: 40,
                    counters: 440,
                    clones: 360,
                    sparse: 300,
                    compressed_in_place: 1000,
                    extents_cut: 140,
                    write_count: 9850,
                    date_added: 266_683,
                }
            );
        }
    }
}
