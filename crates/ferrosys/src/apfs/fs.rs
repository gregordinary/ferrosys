//! The volume view: inodes, the names they are known by, their attributes, and where their
//! bytes are.
//!
//! [`Container`] hands back objects and walks trees and knows nothing about files. This is the
//! layer that reads one volume's file-system tree as a filesystem — an inode record as a
//! `stat`, a directory entry as a name, a file extent as a run of a file's bytes — and it is
//! what [`Reader`] is.
//!
//! # One volume at a time
//!
//! A container holds up to a hundred volumes, each with its own tree and its own inode
//! numbers, and none of them inside another. So a reader reads one: the one an
//! [`OpenOptions::volume`] selection names, or the volume in the container's first slot.
//!
//! # Where a file lives
//!
//! A file is a run of records keyed by its inode number: the inode, its attributes, and, for a
//! directory, its entries. Its bytes are a second run keyed by its data stream's identifier,
//! which the inode names; two inodes share one stream after a clone. A directory's entries are
//! listed in the order the tree holds them — by a hash of the name — and a listing reads them
//! by range. Under a strict policy each entry's name is hashed as it is listed, and held to the
//! hash it is stored under.
//!
//! # What a file's content is read through
//!
//! An ordinary file's bytes are its data stream's extents, which cover the stream from its first
//! byte to the end of its allocation without a gap: a hole is an extent at block zero, read as
//! zeros, which is how macOS writes one when a file is extended past its data. A run no extent
//! covers is refused rather than read as zeros.
//!
//! A file whose BSD flags carry `UF_COMPRESSED` keeps its content in its `com.apple.decmpfs`
//! attribute or its `com.apple.ResourceFork` attribute instead, and its data stream is empty;
//! its content is read through the compression header, never through the empty stream, and a
//! compression type this build does not decode is an error naming the type.
//!
//! This module does I/O, through the container it owns.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};

use crate::bytes::{get_u32, get_u32_be};
use crate::fidelity::Synthesis;
use crate::finding::{Family, Severity};
use crate::policy::MAX_PATH;
use crate::source::{Darwin, Metadata};
use crate::time::Timestamp;
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};
use crate::xattr::Xattr;
use crate::{Limits, ReadPolicy};

use super::btree::{self, Children, Order, TreeRoot};
use super::container::{
    BlockZero, Container, Expect, ReadError, UnreadableVolume, VolumeEntry, Xid,
    map_is_changing_encryption, map_is_reverting,
};
use super::decmpfs::{self, Layout};
use super::names;
use super::ondisk::{
    BSD_COMPRESSED, DECMPFS_XATTR, DataStream, EntryKey, EntryValue, ExtendedField, FileExtent,
    INTERNAL_BEING_TRUNCATED, INTERNAL_COMPRESSED, INTERNAL_EVER_CLONED,
    INTERNAL_WITH_RESOURCE_FORK, INTERNAL_WITHOUT_RESOURCE_FORK, InodeValue, KeyHeader, MapKey,
    ParseError, PhysicalExtent, RESOURCE_FORK_XATTR, SIBLING_ID_FIELD, SYMLINK_XATTR, SiblingLink,
    SnapshotExtension, SnapshotMeta, Storage, VolumeSuperblock, XattrValue, container_incompat,
    extended_fields, field, inode_field, inode_number, kind, record_kind, split_device,
    volume_flags, xattr_flags, xattr_name,
};
use super::scan::{Category, Scan, ScanReport};

/// Which volume of a container to read.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum VolumeSelector {
    /// The volume in this slot of the container's list.
    Slot(usize),
    /// The volume with this name, compared byte for byte. A name more than one volume carries
    /// names none of them, and is refused as [`ReadError::AmbiguousVolume`].
    Name(Vec<u8>),
    /// The volume with this identifier.
    Uuid([u8; 16]),
}

impl std::fmt::Display for VolumeSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeSelector::Slot(slot) => write!(f, "in slot {slot}"),
            VolumeSelector::Name(name) => {
                write!(f, "named {}", crate::escape::printable(name))
            }
            VolumeSelector::Uuid(uuid) => write!(f, "with identifier {}", crate::escape::hex(uuid)),
        }
    }
}

/// How to open a volume: where the container begins, how strictly it is read, what one read
/// may allocate, and which volume.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Where the container begins, how strictly it is read, and what one read may allocate —
    /// the crate's [`OpenOptions`](crate::OpenOptions), which mean exactly what they mean
    /// there.
    pub common: crate::OpenOptions,
    /// The volume to read, or [`None`] for the volume in the container's first occupied slot.
    pub volume: Option<VolumeSelector>,
    /// The snapshot of that volume to read, by name, or [`None`] for the volume as it is.
    pub snapshot: Option<Vec<u8>>,
}

impl OpenOptions {
    /// The first volume, at the start of the source, strictly, with the default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            common: crate::OpenOptions::new(),
            volume: None,
            snapshot: None,
        }
    }

    /// Take the inputs every family takes from `common`.
    #[must_use]
    pub const fn common(mut self, common: crate::OpenOptions) -> Self {
        self.common = common;
        self
    }

    /// Read the volume `selector` names.
    #[must_use]
    pub fn volume(mut self, selector: VolumeSelector) -> Self {
        self.volume = Some(selector);
        self
    }

    /// Read the volume as its snapshot named `name` keeps it, compared byte for byte.
    #[must_use]
    pub fn snapshot(mut self, name: Vec<u8>) -> Self {
        self.snapshot = Some(name);
        self
    }
}

/// One snapshot of a volume: its name, the transaction it keeps the volume at, and when it was
/// taken.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Snapshot {
    /// The name, as the bytes are stored.
    pub name: Vec<u8>,
    /// The transaction that records the snapshot. Reading it resolves every node at the newest
    /// version no later than this one.
    pub xid: u64,
    /// When it was taken.
    pub created: Timestamp,
    /// The block holding its copy of the volume superblock.
    pub superblock: u64,
    /// Its flags: `0x1` dataless and pending, `0x2` a merge in progress. A snapshot carrying
    /// either is listed and not read.
    pub flags: u32,
    /// Its identifier, where the volume keeps one for it.
    pub uuid: Option<[u8; 16]>,
}

/// How a compressed file's content is stored: the compression header's type and the size of
/// the content it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Compression {
    /// The compression type the header records.
    pub method: u32,
    /// The content's size in bytes.
    pub size: u64,
}

/// One inode of the volume: its number and what it records.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Node {
    /// The inode number.
    pub inode: u64,
    /// The inode record.
    pub value: InodeValue,
    /// Its data stream, where it has one.
    pub stream: Option<DataStream>,
    /// A device node's device number, as Darwin packs it.
    pub device: Option<u32>,
    /// How a compressed file's content is stored, where its BSD flags say it is compressed: the
    /// header, or why the header could not be read, which a read of the content and a question
    /// of its size refuse with.
    pub compression: Option<Result<Compression, ReadError>>,
    /// A symbolic link's target length in bytes, without its terminator, where the inode is a
    /// symbolic link whose target attribute is present.
    pub link_size: Option<u64>,
}

impl Node {
    /// The `S_IFMT` bits of the inode's mode.
    #[must_use]
    pub const fn file_type(&self) -> u16 {
        self.value.mode & MODE_TYPE
    }

    /// Whether the inode is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.file_type() == MODE_DIR
    }

    /// Whether the inode is a regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.file_type() == MODE_REG
    }

    /// Whether the inode is a symbolic link.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.file_type() == MODE_LNK
    }

    /// Whether the inode is a regular file whose BSD flags carry `UF_COMPRESSED`, so its content
    /// is read through its compression header rather than its data stream.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.is_file() && self.value.bsd_flags & BSD_COMPRESSED != 0
    }

    /// The size of the inode's content in bytes: a compressed file's uncompressed size, a
    /// symbolic link's target length, or its data stream's.
    ///
    /// A symbolic link keeps its target in an attribute rather than a data stream, and its size
    /// is that target's length without the terminator, as `lstat` on macOS reports it (observed
    /// on every link of the corpus, macOS 14 to 27). A compressed file whose header could not be
    /// read, and a link whose target could not be, have no size known here, and are 0: a read
    /// of either refuses, and says why.
    #[must_use]
    pub fn size(&self) -> u64 {
        match (&self.compression, self.link_size, self.stream) {
            (Some(Ok(compression)), _, _) => compression.size,
            (Some(Err(_)), _, _) => 0,
            (None, Some(link), _) => link,
            (None, None, Some(stream)) => stream.size,
            (None, None, None) => 0,
        }
    }

    /// The inode's link count, for any inode but a directory; a directory's record holds its
    /// child count there instead.
    #[must_use]
    pub const fn links(&self) -> i32 {
        self.value.links_or_children
    }

    /// When the inode was created.
    #[must_use]
    pub fn birth_time(&self) -> Timestamp {
        timestamp(self.value.create_time)
    }

    /// When its content last changed.
    #[must_use]
    pub fn modify_time(&self) -> Timestamp {
        timestamp(self.value.modify_time)
    }

    /// When its attributes last changed.
    #[must_use]
    pub fn change_time(&self) -> Timestamp {
        timestamp(self.value.change_time)
    }

    /// When it was last read.
    #[must_use]
    pub fn access_time(&self) -> Timestamp {
        timestamp(self.value.access_time)
    }

    /// The inode's ownership, permission bits and times, as the shared vocabulary carries
    /// them: the twelve bits below the file type, and the four times, the creation time as
    /// the birth time.
    #[must_use]
    pub fn metadata(&self) -> Metadata {
        Metadata {
            mode: self.value.mode & 0o7777,
            uid: self.value.owner,
            gid: self.value.group,
            atime: self.access_time(),
            ctime: self.change_time(),
            mtime: self.modify_time(),
            btime: Some(self.birth_time()),
        }
    }
}

/// One entry of a directory, as it is stored.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Entry {
    /// The name, exactly as the bytes are stored, without the terminator the key carries.
    pub name: Vec<u8>,
    /// The inode it names.
    pub file_id: u64,
    /// The entry's `DT_*` type.
    pub entry_type: u8,
    /// When the entry was added to the directory.
    pub date_added: Timestamp,
    /// The hash the entry is sorted by, as stored.
    pub hash: u32,
    /// A hard link's sibling identifier, where the inode has more than one name.
    pub sibling_id: Option<u64>,
}

/// One name a walk reached, and the node at it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Absolute path from the volume's root, `/`-joined, always beginning with `/`. Empty for
    /// the root itself, which is the first entry a walk yields.
    pub path: Vec<u8>,
    /// The node at that path.
    pub node: Node,
}

/// One volume of an APFS container, opened over a seekable source and read as files.
///
/// ```no_run
/// use ferrosys::apfs::Reader;
///
/// let mut reader = Reader::open(std::fs::File::open("disk.img")?)?;
/// let node = reader.lookup(b"/Users/Shared/notes.txt")?;
/// println!("{} bytes", node.size());
/// print!("{}", String::from_utf8_lossy(&reader.read_data(&node)?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// The [`Container`] underneath stays reachable, because the two layers answer different
/// questions: which volumes are there and does every object verify is the container's, and
/// what is at this path is this.
pub struct Reader<R> {
    container: Container<R>,
    /// Boxed: a volume superblock is a kilobyte, and every family's reader shares one enum.
    volume: Box<VolumeEntry>,
    /// The snapshot being read and its copy of the volume superblock, or [`None`] for the
    /// volume as it is.
    view: Option<Box<(Snapshot, VolumeSuperblock)>>,
    /// The volume's object map's mapping tree, which a snapshot is read through as well.
    map_tree: TreeRoot,
    fs_tree: TreeRoot,
    /// The chunk table of the compressed file read last, by its inode: building one holds the
    /// file's resource fork to its extents whole, and a file is read a window at a time.
    /// Boxed, as the volume is.
    last_table: Option<Box<(u64, ChunkTable)>>,
}

impl<R: Read + Seek> Reader<R> {
    /// Open the first volume of the container at the start of `src`, strictly, with the
    /// default limits.
    ///
    /// # Errors
    ///
    /// See [`open_with`](Self::open_with).
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open the container `options.common.base` bytes into `src`, and the volume
    /// `options.volume` names in it.
    ///
    /// # Errors
    ///
    /// Whatever [`Container::open_with`] refuses; [`ReadError::NoSuchVolume`] where no volume
    /// answers the selection; for a selected volume whose superblock could not be read, why
    /// ([`Container::unreadable_volumes`]); and for the selected volume, [`ReadError::Encrypted`],
    /// [`ReadError::EncryptionChanging`], [`ReadError::RevertPending`] where the volume or its
    /// object map records a revert not yet carried out, [`ReadError::UnsupportedFeatures`] for an
    /// incompatible bit outside [`SUPPORTED_VOLUME_INCOMPAT`](super::SUPPORTED_VOLUME_INCOMPAT),
    /// [`ReadError::UnhashedNames`], and under a strict policy whatever a read of every node
    /// of the volume's object map refuses.
    pub fn open_with(src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let container = Container::open_with(src, &options.common)?;
        let volume = select(
            container.volumes(),
            container.unreadable_volumes(),
            options.volume.as_ref(),
        )?
        .clone();
        let reader = Self::over(container, volume)?;
        match &options.snapshot {
            None => Ok(reader),
            Some(name) => reader.at_snapshot(name),
        }
    }

    /// A reader of `volume`, one of `container`'s, at the container's live checkpoint.
    ///
    /// # Errors
    ///
    /// As [`open_with`](Self::open_with), for the volume.
    pub fn over(mut container: Container<R>, volume: VolumeEntry) -> Result<Self, ReadError> {
        if let Some(refusal) = volume.refusal() {
            return Err(refusal);
        }
        let xid = container.xid();
        let (map, map_tree) = container.object_map_at(volume.superblock.object_map_oid, xid)?;
        if map_is_changing_encryption(&map) {
            return Err(ReadError::EncryptionChanging { slot: volume.slot });
        }
        if map_is_reverting(&map) {
            return Err(ReadError::RevertPending { slot: volume.slot });
        }
        container.check_map(&map_tree)?;
        let fs_tree = TreeRoot {
            oid: volume.superblock.root_tree_oid,
            children: Children::Virtual {
                map_tree: map_tree.oid,
                map_xid: map_tree.max_xid,
                xid,
            },
            subtype: kind::FS_TREE,
            order: Order::FileSystem,
            max_xid: xid,
        };
        Ok(Self {
            container,
            volume: Box::new(volume),
            view: None,
            map_tree,
            fs_tree,
            last_table: None,
        })
    }

    /// This volume as its snapshot named `name` keeps it.
    ///
    /// The snapshot's tree is the one its copy of the volume superblock names, and every node
    /// of it is resolved through the volume's object map at the newest version no later than
    /// the snapshot's transaction. Every read after this one reads the snapshot.
    ///
    /// # Errors
    ///
    /// [`ReadError::NoSuchSnapshot`] where the volume has no snapshot of that name,
    /// [`ReadError::UnsupportedFeatures`] for a snapshot whose flags say it is dataless or
    /// being merged, [`ReadError::WrongObject`] for a superblock copy recording another
    /// volume's identifier or slot, whatever [`VolumeEntry::refusal`] refuses in the copy as
    /// in the live superblock, and whatever reading the snapshot list and the copy does.
    pub fn at_snapshot(mut self, name: &[u8]) -> Result<Self, ReadError> {
        let snapshot = self
            .snapshots()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ReadError::NoSuchSnapshot {
                name: name.to_vec(),
            })?;
        if snapshot.flags != 0 {
            return Err(ReadError::UnsupportedFeatures {
                scope: "snapshot",
                bits: u64::from(snapshot.flags),
                names: "a snapshot that is dataless or being merged".to_string(),
            });
        }
        let object = self.container.read_object(
            snapshot.superblock,
            &Expect {
                kinds: &[kind::VOLUME_SUPERBLOCK],
                subtype: None,
                storage: Storage::Physical,
                oid: snapshot.superblock,
                xid: Xid::Exactly(snapshot.xid),
            },
        )?;
        let copy = VolumeSuperblock::read_from(&object)?;
        // Every read of the snapshot takes its tree and its name rules from the copy, so the
        // copy is the volume's own, by identifier and slot, and is held to what the live
        // superblock is refused for.
        let live = &self.volume.superblock;
        if copy.uuid != live.uuid || copy.index != live.index {
            return Err(ReadError::WrongObject {
                block: snapshot.superblock,
                fault: "a superblock copy recording another volume's identifier or slot",
            });
        }
        let entry = VolumeEntry {
            slot: self.volume.slot,
            oid: self.volume.oid,
            address: snapshot.superblock,
            superblock: copy,
        };
        if let Some(refusal) = entry.refusal() {
            return Err(refusal);
        }
        let copy = entry.superblock;
        self.fs_tree = TreeRoot {
            oid: copy.root_tree_oid,
            children: Children::Virtual {
                map_tree: self.map_tree.oid,
                map_xid: self.map_tree.max_xid,
                xid: snapshot.xid,
            },
            subtype: kind::FS_TREE,
            order: Order::FileSystem,
            max_xid: snapshot.xid,
        };
        self.view = Some(Box::new((snapshot, copy)));
        self.last_table = None;
        Ok(self)
    }

    /// The snapshot being read, or [`None`] for the volume as it is.
    #[must_use]
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.view.as_ref().map(|view| &view.0)
    }

    /// Every snapshot of the volume, in the order of the transactions they keep.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadRecord`] where a record of the snapshot tree does not parse, and
    /// whatever reading the tree does.
    pub fn snapshots(&mut self) -> Result<Vec<Snapshot>, ReadError> {
        let extension = self.volume.superblock.snapshot_extension_oid;
        let mut out = Vec::new();
        for meta in self.snapshot_metas()? {
            let uuid = self.snapshot_uuid(extension, meta.xid)?;
            out.push(Snapshot {
                name: meta.name,
                xid: meta.xid,
                created: timestamp(meta.create_time),
                superblock: meta.superblock,
                flags: meta.flags,
                uuid,
            });
        }
        Ok(out)
    }

    /// Every metadata record of the volume's snapshot tree, in the order of the transactions
    /// they keep.
    fn snapshot_metas(&mut self) -> Result<Vec<SnapshotMeta>, ReadError> {
        let Some(tree) = self.snapshot_tree() else {
            return Ok(Vec::new());
        };
        let mut metas = Vec::new();
        let mut fault = None;
        btree::for_each(&mut self.container, &tree, &mut |key, value| {
            let header = KeyHeader::read_from(key)?;
            if header.kind == record_kind::SNAPSHOT_META {
                match SnapshotMeta::read_from(key, value) {
                    Ok(meta) => metas.push(meta),
                    Err(e) => {
                        fault = Some((header.id, e));
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })?;
        if let Some((id, e)) = fault {
            return Err(ReadError::BadRecord {
                id,
                kind: record_kind::SNAPSHOT_META,
                fault: e.to_string(),
            });
        }
        Ok(metas)
    }

    /// The volume's snapshot tree, where it has one: the live superblock's, whichever view is
    /// read.
    fn snapshot_tree(&self) -> Option<TreeRoot> {
        let oid = self.volume.superblock.snapshot_tree_oid;
        (oid != 0).then(|| TreeRoot {
            oid,
            children: Children::Physical,
            subtype: kind::SNAPSHOT_TREE,
            order: Order::FileSystem,
            max_xid: self.container.xid(),
        })
    }

    /// The identifier the volume's snapshot extension object holds for the snapshot at
    /// transaction `xid`: the object's version written at exactly that transaction. A volume
    /// with no extension object, or none written then, keeps none.
    fn snapshot_uuid(&mut self, oid: u64, xid: u64) -> Result<Option<[u8; 16]>, ReadError> {
        if oid == 0 {
            return Ok(None);
        }
        let map = self.map_tree;
        let found = match self.container.resolve(&map, oid, xid) {
            Ok((key, _)) => key.xid == xid,
            Err(ReadError::MissingObject { .. }) => false,
            Err(e) => return Err(e),
        };
        if !found {
            return Ok(None);
        }
        let (_, object) =
            self.container
                .read_virtual(&map, oid, xid, &[kind::SNAPSHOT_EXTENSION], None)?;
        let extension = SnapshotExtension::read_from(&object)?;
        Ok((extension.xid == xid).then_some(extension.uuid))
    }

    /// The container underneath, for the questions this layer does not ask.
    #[must_use]
    pub fn container(&self) -> &Container<R> {
        &self.container
    }

    /// Give the container back, and with it the source it was opened over.
    #[must_use]
    pub fn into_container(self) -> Container<R> {
        self.container
    }

    /// The volume being read.
    #[must_use]
    pub fn volume(&self) -> &VolumeEntry {
        &self.volume
    }

    /// The volume's superblock: the snapshot's copy of it where a snapshot is being read.
    #[must_use]
    pub fn superblock(&self) -> &VolumeSuperblock {
        self.view
            .as_ref()
            .map_or(&self.volume.superblock, |view| &view.1)
    }

    /// How strictly the volume is being read.
    #[must_use]
    pub fn policy(&self) -> ReadPolicy {
        self.container.policy()
    }

    /// The caps this read is held to.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.container.limits()
    }

    /// The volume's root directory.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingInode`] where the tree holds no record of it.
    pub fn root(&mut self) -> Result<Node, ReadError> {
        self.inode(inode_number::ROOT)
    }

    /// The inode numbered `inode`.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingInode`] where the tree holds no such inode, and
    /// [`ReadError::BadRecord`] where its record does not parse or, under a strict policy, its
    /// extended fields break the format's rules: a type met twice, a field of another size than
    /// its type's, or a device node without its number.
    pub fn inode(&mut self, inode: u64) -> Result<Node, ReadError> {
        let target = exact(inode, record_kind::INODE);
        let found = btree::find_at_or_before(&mut self.container, &self.fs_tree, &target)?;
        let Some((key, value)) = found else {
            return Err(ReadError::MissingInode { inode });
        };
        let header = KeyHeader::read_from(&key)?;
        if (header.id, header.kind) != (inode, record_kind::INODE) {
            return Err(ReadError::MissingInode { inode });
        }
        let bad = |fault: ParseError| ReadError::BadRecord {
            id: inode,
            kind: record_kind::INODE,
            fault: fault.to_string(),
        };
        let record = InodeValue::read_from(&value).map_err(bad)?;
        let fields = extended_fields(&value[InodeValue::SIZE..]).map_err(bad)?;
        // A read past what the rules refuse takes the first field of each type, and reads a
        // device node without its number as having none.
        if let Some((severity, fault)) = inode_field_rules(record.mode, &fields)
            && self.policy().is_fatal(severity)
        {
            return Err(ReadError::BadRecord {
                id: inode,
                kind: record_kind::INODE,
                fault,
            });
        }
        let stream = field(&fields, inode_field::DATA_STREAM)
            .map(DataStream::read_from)
            .transpose()
            .map_err(bad)?;
        let device = field(&fields, inode_field::DEVICE)
            .map(|data| {
                (data.len() >= 4)
                    .then(|| get_u32(data, 0))
                    .ok_or(ParseError::TooShort {
                        structure: "device number",
                        need: 4,
                        got: data.len(),
                    })
            })
            .transpose()
            .map_err(bad)?;
        let mut node = Node {
            inode,
            value: record,
            stream,
            device,
            compression: None,
            link_size: None,
        };
        // What the header says, or why it could not be read: a node is a name in its directory
        // whatever its content, so a fault in the header is carried to where the content or its
        // size is asked for, rather than refusing every walk and lookup that passes the node.
        // The source failing is no fault of the node's, and fails here.
        if node.is_compressed() {
            node.compression = match self.compression(inode) {
                Err(ReadError::Io { kind, message }) => {
                    return Err(ReadError::Io { kind, message });
                }
                header => Some(header),
            };
        }
        if node.is_symlink() {
            // The target's length is its attribute's, less the terminator. An attribute that is
            // missing or does not parse, or attribute records that do not read, leave the size
            // unknown here, and `link_target` is where reading the target refuses it.
            node.link_size = match self.parsed_xattr_records(inode) {
                Err(ReadError::Io { kind, message }) => {
                    return Err(ReadError::Io { kind, message });
                }
                Err(_) => None,
                Ok((records, _)) => records
                    .into_iter()
                    .find(|(name, _, _)| name == SYMLINK_XATTR)
                    .and_then(|(_, flags, data)| Stored::of(inode, flags, &data).ok())
                    .map(|stored| stored.size().saturating_sub(1)),
            };
        }
        Ok(node)
    }

    /// The compression header of inode `inode`: its type and its content's size.
    fn compression(&mut self, inode: u64) -> Result<Compression, ReadError> {
        let header =
            self.xattr_record(inode, DECMPFS_XATTR)?
                .ok_or_else(|| ReadError::BadCompressed {
                    inode,
                    fault: "the file is flagged compressed and has no compression header".into(),
                })?;
        let (flags, data) = header;
        // The attribute is in its record when it is short, and a stream of its own when the
        // compressed content follows the header in it and is longer.
        let stored = Stored::of(inode, flags, &data)?;
        let len = (decmpfs::HEADER_LEN as u64).min(stored.size());
        let header = decmpfs::Header::read_from(&self.stored_read(inode, &stored, 0, len)?)
            .ok_or_else(|| ReadError::BadCompressed {
                inode,
                fault: "the compression header is not one".into(),
            })?;
        Ok(Compression {
            method: header.method,
            size: header.size,
        })
    }

    /// Every entry of directory `dir`, in the order the tree holds them.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotADirectory`] where the node is not a directory, [`ReadError::BadRecord`]
    /// where an entry does not parse or, under a strict policy, is stored under another hash than
    /// its name's, has a name that is not UTF-8, or carries extended fields the format does not
    /// allow, and [`ReadError::TooManyEntries`] past the walk limit.
    pub fn read_dir(&mut self, dir: &Node) -> Result<Vec<Entry>, ReadError> {
        let mut out = Vec::new();
        let limit = self.limits().max_walk_entries;
        self.for_each_entry(dir, limit, &mut |entry| {
            out.push(entry);
            true
        })?;
        Ok(out)
    }

    /// Visit the entries of directory `dir` in the order the tree holds them, until `visit`
    /// answers `false`, reading no more than `limit` records.
    fn for_each_entry(
        &mut self,
        dir: &Node,
        limit: usize,
        visit: &mut dyn FnMut(Entry) -> bool,
    ) -> Result<(), ReadError> {
        if !dir.is_dir() {
            return Err(ReadError::NotADirectory {
                path: format!("inode {}", dir.inode).into_bytes(),
            });
        }
        let id = dir.inode;
        let policy = self.policy();
        let fold = self.superblock().is_case_insensitive();
        let mut fault = None;
        btree::for_each_from(
            &mut self.container,
            &self.fs_tree,
            &btree::records_of(id, record_kind::DIR_ENTRY),
            limit,
            &mut |key, value| {
                let header = KeyHeader::read_from(key)?;
                if (header.id, header.kind) != (id, record_kind::DIR_ENTRY) {
                    return Ok(false);
                }
                match entry(key, value, policy, fold) {
                    Ok(entry) => Ok(visit(entry)),
                    Err(e) => {
                        fault = Some(e);
                        Ok(false)
                    }
                }
            },
        )?;
        match fault {
            Some(fault) => Err(ReadError::BadRecord {
                id,
                kind: record_kind::DIR_ENTRY,
                fault,
            }),
            None => Ok(()),
        }
    }

    /// The entry of `dir` that `name` names: the one whose stored name is exactly `name` where
    /// there is one, and otherwise the one the volume takes to be the same name.
    ///
    /// A volume compares names by their canonical decomposition, case-folded and decomposed
    /// again where its names fold case, under Unicode 17.0's tables, which compare every name
    /// macOS 15, 26 and 27 wrote. So a name typed in another normalization, or on such a volume
    /// in another case, finds the entry macOS would find for it.
    ///
    /// The directory is read as far as an exact match, and no further; a lookup answers to no
    /// walk limit. An entry that matches only as the same name is held until the directory
    /// ends, since a stored name exactly `name` wins over it.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotADirectory`] where the node is not a directory, and
    /// [`ReadError::BadRecord`] where an entry the read reaches is one
    /// [`read_dir`](Self::read_dir) refuses.
    pub fn find_entry(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Entry>, ReadError> {
        let fold = self.superblock().is_case_insensitive();
        let want = names::key(name, fold);
        let want_hash = want.as_deref().map(names::hash);
        let mut exact = None;
        let mut same = None;
        self.for_each_entry(dir, usize::MAX, &mut |entry| {
            if entry.name == name {
                exact = Some(entry);
                return false;
            }
            if same.is_none()
                && want_hash == Some(entry.hash)
                && names::key(&entry.name, fold) == want
            {
                same = Some(entry);
            }
            true
        })?;
        Ok(exact.or(same))
    }

    /// The node at `path`, following a symbolic link anywhere in it, the last component
    /// included.
    ///
    /// A component finds the entry [`find_entry`](Self::find_entry) finds for it: the one whose
    /// stored name is exactly the component, or else the one the volume takes to be the same
    /// name.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotFound`], [`ReadError::NotADirectory`], [`ReadError::SymlinkLoop`], under
    /// a strict policy [`ReadError::MisplacedDirectory`] for a directory on the way named from
    /// outside its parent, and whatever reading the nodes on the way does.
    pub fn lookup(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        crate::resolve::drive(self, path, true)
    }

    /// The node at `path`, following a symbolic link anywhere in it but the last component.
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn lookup_no_follow(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        crate::resolve::drive(self, path, false)
    }

    /// Every extended attribute of `node`, in the order the tree holds them, with each
    /// stream attribute's bytes read in.
    ///
    /// Not listed are a symbolic link's `com.apple.fs.symlink`, which is its target and which
    /// [`link_target`](Self::link_target) reads, and a compressed file's compression header and
    /// resource fork, which are its content. Every other attribute is listed as the volume
    /// stores it, that name on a node of another kind included.
    ///
    /// A stream attribute's bytes are the blocks its extents hold, every byte of them: macOS
    /// writes an attribute's stream to blocks whole, so a hole in one is refused, and nothing
    /// is allocated for a value before its extents are found to hold it. Each value is held to
    /// [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), as a file's content is.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadRecord`] where an attribute does not parse,
    /// [`ReadError::AttributeTooLarge`] where a stream attribute is larger than the read's cap,
    /// [`ReadError::BadExtent`] where its stream's extents do not hold every byte of it, and
    /// whatever reading the blocks does.
    pub fn xattrs(&mut self, node: &Node) -> Result<Vec<Xattr>, ReadError> {
        let id = node.inode;
        let records = self.xattr_records(id)?;
        let mut out = Vec::with_capacity(records.len());
        for (name, flags, data) in records {
            // The symbolic link's target, and a compressed file's content: each is what the
            // node is, read through `link_target` or `read_into`, rather than an attribute of
            // it.
            if (node.is_symlink() && name == SYMLINK_XATTR)
                || (node.is_compressed() && (name == DECMPFS_XATTR || name == RESOURCE_FORK_XATTR))
            {
                continue;
            }
            let value = self.xattr_bytes(id, &name, flags, &data)?;
            out.push(Xattr { name, value });
        }
        Ok(out)
    }

    /// The bytes of inode `id`'s attribute `name`, whose record holds `flags` and `data`.
    ///
    /// A stream attribute's size is a number its record supplies, so nothing is allocated for
    /// it until its extents are found to hold every byte of it in blocks of the container, no
    /// block twice, and then the value grows a window at a time as the blocks are read. So an
    /// attribute is never larger than its container.
    fn xattr_bytes(
        &mut self,
        id: u64,
        name: &[u8],
        flags: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, ReadError> {
        match Stored::of(id, flags, data)? {
            Stored::Embedded(bytes) => Ok(bytes),
            Stored::Stream {
                id: stream,
                stream: ds,
            } => {
                let held = self
                    .container
                    .superblock()
                    .block_count
                    .saturating_mul(u64::from(self.container.block_size()));
                let limit = self.limits().max_file_bytes.min(held);
                let fits = usize::try_from(ds.size).is_ok_and(|n| isize::try_from(n).is_ok());
                if ds.size > limit || !fits {
                    return Err(ReadError::AttributeTooLarge {
                        inode: id,
                        name: name.to_vec(),
                        size: ds.size,
                        limit,
                    });
                }
                self.attribute_runs(stream, 0, ds.size)?;
                let mut out = Vec::new();
                while (out.len() as u64) < ds.size {
                    let at = out.len();
                    let take = (ds.size - at as u64).min(STREAM_BUFFER as u64) as usize;
                    out.resize(at + take, 0);
                    self.read_stream_into(
                        stream,
                        ds.size,
                        at as u64,
                        &mut out[at..],
                        Holes::Refused,
                    )?;
                }
                Ok(out)
            }
        }
    }

    /// Every attribute record of inode `id`: name, flags, and the record's data.
    fn xattr_records(&mut self, id: u64) -> Result<Vec<XattrRecord>, ReadError> {
        let (records, fault) = self.parsed_xattr_records(id)?;
        match fault {
            Some(fault) => Err(ReadError::BadRecord {
                id,
                kind: record_kind::XATTR,
                fault,
            }),
            None => Ok(records),
        }
    }

    /// Every attribute record of inode `id` whose name and value parse, and what is wrong with
    /// the first that does not.
    fn parsed_xattr_records(
        &mut self,
        id: u64,
    ) -> Result<(Vec<XattrRecord>, Option<String>), ReadError> {
        let mut out = Vec::new();
        let mut fault = None;
        let limit = self.limits().max_walk_entries;
        btree::for_each_from(
            &mut self.container,
            &self.fs_tree,
            &btree::records_of(id, record_kind::XATTR),
            limit,
            &mut |key, value| {
                let header = KeyHeader::read_from(key)?;
                if (header.id, header.kind) != (id, record_kind::XATTR) {
                    return Ok(false);
                }
                let parsed = attribute_name(key).and_then(|name| {
                    let xattr = XattrValue::read_from(value).map_err(|e| e.to_string())?;
                    Ok((name, xattr))
                });
                match parsed {
                    Ok((name, xattr)) => {
                        out.push((name.to_vec(), xattr.flags, xattr.data.to_vec()))
                    }
                    Err(e) => {
                        fault.get_or_insert(e);
                    }
                }
                Ok(true)
            },
        )?;
        Ok((out, fault))
    }

    /// The record of inode `id`'s attribute `name`, as its flags and data.
    fn xattr_record(&mut self, id: u64, name: &[u8]) -> Result<Option<(u16, Vec<u8>)>, ReadError> {
        Ok(self
            .xattr_records(id)?
            .into_iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, flags, data)| (flags, data)))
    }

    /// What `node` records that only a Darwin filesystem does: its BSD flags, and where it is
    /// a compressed file its compression header and its resource fork as stored, the bytes a
    /// read decodes its content from. [`None`] for a node with no BSD flag set.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadRecord`] where a compressed file's attribute does not parse, and what
    /// reading an attribute's stream does.
    pub fn darwin(&mut self, node: &Node) -> Result<Option<Darwin>, ReadError> {
        let bsd_flags = node.value.bsd_flags;
        if bsd_flags == 0 {
            return Ok(None);
        }
        let mut darwin = Darwin::new(bsd_flags);
        if node.is_compressed() {
            let mut stored = |name: &[u8]| -> Result<Option<Vec<u8>>, ReadError> {
                match self.xattr_record(node.inode, name)? {
                    Some((flags, data)) => {
                        Ok(Some(self.xattr_bytes(node.inode, name, flags, &data)?))
                    }
                    None => Ok(None),
                }
            };
            let header = stored(DECMPFS_XATTR)?.ok_or_else(|| ReadError::BadRecord {
                id: node.inode,
                kind: record_kind::XATTR,
                fault: "a compressed file has no compression header".to_string(),
            })?;
            let fork = stored(RESOURCE_FORK_XATTR)?;
            darwin.compressed = Some(crate::CompressedFile::new(header, fork));
        }
        Ok(Some(darwin))
    }

    /// The target of symbolic link `node`, as the bytes are stored.
    ///
    /// The target is the value of the link's `com.apple.fs.symlink` attribute, without the
    /// terminating NUL the value carries.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotASymlink`] where the node is not a symbolic link, and
    /// [`ReadError::BadRecord`] where it has no target, one without its terminator, one holding
    /// a NUL before it, or one longer than a path may be, which is refused by its recorded size
    /// before it is read.
    pub fn link_target(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        if !node.is_symlink() {
            return Err(ReadError::NotASymlink { inode: node.inode });
        }
        let bad = |fault: &str| ReadError::BadRecord {
            id: node.inode,
            kind: record_kind::XATTR,
            fault: fault.into(),
        };
        let (flags, data) = self
            .xattr_record(node.inode, SYMLINK_XATTR)?
            .ok_or_else(|| bad("a symbolic link without a target"))?;
        // A target and its terminator are held to the longest path from the size the record
        // gives them, before a byte is read, so a crafted size cannot make one link allocate
        // more than a path's worth.
        if Stored::of(node.inode, flags, &data)?.size() > MAX_PATH as u64 + 1 {
            return Err(bad("a symbolic link target longer than a path may be"));
        }
        let mut target = self.xattr_bytes(node.inode, SYMLINK_XATTR, flags, &data)?;
        if target.pop() != Some(0) {
            return Err(bad("a symbolic link target without its terminator"));
        }
        // A path holds no NUL, so a target holding one before its terminator is no one path: a
        // host refuses it and an archive reader takes the part before it.
        if target.contains(&0) {
            return Err(bad(
                "a symbolic link target holding a NUL before its terminator",
            ));
        }
        Ok(target)
    }

    /// Fill `buf` with the content of file `node` from byte `offset`, and say how many bytes
    /// that was: fewer than the buffer holds only where the file ends first. A node that is not
    /// a regular file has no content, whatever stream it records, and fills nothing.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnsupportedCompression`] for a compressed file whose content this build
    /// does not decode, [`ReadError::BadCompressed`] for one whose header, table or chunks do
    /// not decode as its type describes, and why its header could not be read where it could
    /// not; [`ReadError::BadExtent`] where an extent does not describe a run of the container;
    /// and whatever reading the blocks does.
    pub fn read_into(
        &mut self,
        node: &Node,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        if !node.is_file() {
            return Ok(0);
        }
        if let Some(compression) = &node.compression {
            let compression = compression.clone()?;
            return self.read_compressed(node.inode, compression, offset, buf);
        }
        let Some(stream) = node.stream else {
            return Ok(0);
        };
        self.read_stream_into(
            node.value.private_id,
            stream.size,
            offset,
            buf,
            Holes::Zeros,
        )
    }

    /// Fill `buf` from byte `offset` of a compressed file's content: the chunks that the window
    /// meets, each decoded whole and held to the share of the content its place gives it.
    fn read_compressed(
        &mut self,
        inode: u64,
        compression: Compression,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        let Some((layout, encoding)) =
            decmpfs::layout(compression.method).filter(|(_, e)| e.available())
        else {
            return Err(ReadError::UnsupportedCompression {
                inode,
                method: compression.method,
            });
        };
        let size = compression.size;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let held = match self.last_table.take() {
            Some(held) if held.0 == inode => held,
            _ => Box::new((inode, self.chunk_table(inode, layout, size)?)),
        };
        let read = self.read_chunks(inode, &held.1, encoding, size, offset, buf);
        self.last_table = Some(held);
        read
    }

    /// Fill `buf` from byte `offset` of a compressed file's `size` bytes of content, which is
    /// short of both, decoding the chunks `table` finds.
    fn read_chunks(
        &mut self,
        inode: u64,
        table: &ChunkTable,
        encoding: decmpfs::Encoding,
        size: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        let want = (buf.len() as u64).min(size - offset);
        let bad = |fault: String| ReadError::BadCompressed { inode, fault };
        let first = offset / decmpfs::CHUNK;
        let last = (offset + want - 1) / decmpfs::CHUNK;
        let runs = self.chunk_runs(inode, table, first, last - first + 1)?;
        let mut chunk = Vec::new();
        for (i, (start, end)) in (first..=last).zip(runs) {
            let stored = self.stored_read(inode, &table.source, start, end - start)?;
            let expect = decmpfs::chunk_len(size, i) as usize;
            chunk.clear();
            chunk.resize(expect, 0);
            // The one chunk after the header, holding the content itself at another length than
            // the header states: macOS reads it to the header's size, cut there or followed by
            // zeros (observed), which a lenient read does too. A strict read refuses it.
            let lenient = !self.policy().is_fatal(Severity::Conformance);
            let kept = (table.layout == Layout::Inline)
                .then(|| decmpfs::kept_inline(encoding, &stored))
                .flatten()
                .filter(|content| lenient && content.len() != expect);
            let produced = match kept {
                Some(content) => {
                    let take = content.len().min(expect);
                    chunk[..take].copy_from_slice(&content[..take]);
                    expect
                }
                None => decmpfs::decode_chunk(encoding, &stored, &mut chunk)
                    .map_err(|e| bad(format!("chunk {i}: {e}")))?,
            };
            if produced != expect {
                return Err(bad(format!(
                    "chunk {i} decodes to {produced} bytes where its place gives it {expect}"
                )));
            }
            let chunk_start = i * decmpfs::CHUNK;
            let lo = offset.max(chunk_start);
            let hi = (offset + want).min(chunk_start + expect as u64);
            buf[(lo - offset) as usize..(hi - offset) as usize]
                .copy_from_slice(&chunk[(lo - chunk_start) as usize..(hi - chunk_start) as usize]);
        }
        Ok(want as usize)
    }

    /// Where a compressed file of `size` bytes of content keeps its chunks, laid out as
    /// `layout` says, and the table that finds them.
    fn chunk_table(
        &mut self,
        inode: u64,
        layout: Layout,
        size: u64,
    ) -> Result<ChunkTable, ReadError> {
        let bad = |fault: &str| ReadError::BadCompressed {
            inode,
            fault: fault.into(),
        };
        let chunks = decmpfs::chunk_count(size);
        if layout == Layout::Inline {
            if chunks > 1 {
                return Err(bad(
                    "content kept in its compression attribute is larger than one chunk",
                ));
            }
            let (flags, data) = self
                .xattr_record(inode, DECMPFS_XATTR)?
                .ok_or_else(|| bad("the file has no compression header"))?;
            let source = Stored::of(inode, flags, &data)?;
            let ceiling = source.size();
            if ceiling > decmpfs::MAX_INLINE {
                return Err(bad(
                    "the compression attribute holding the content is longer than macOS keeps \
                     on a compressed file",
                ));
            }
            return Ok(ChunkTable {
                source,
                layout,
                chunks,
                entries_at: 0,
                base: 0,
                floor: decmpfs::HEADER_LEN as u64,
                ceiling,
            });
        }
        let (flags, data) = self
            .xattr_record(inode, RESOURCE_FORK_XATTR)?
            .ok_or_else(|| bad("the compressed content has no resource fork"))?;
        let source = Stored::of(inode, flags, &data)?;
        // The whole fork is held to its extents, as a scan holds it, so a size its blocks do not
        // hold is refused whichever chunks a read needs.
        if let Stored::Stream { id, stream } = &source {
            self.attribute_runs(*id, 0, stream.size)?;
        }
        let fork_len = source.size();
        if layout == Layout::Offsets {
            // One offset per chunk and one for the end, and the first chunk no earlier than the
            // table's end.
            let table_len = chunks
                .checked_add(1)
                .and_then(|n| n.checked_mul(4))
                .filter(|len| *len <= fork_len)
                .ok_or_else(|| bad("the chunk table does not fit the resource fork"))?;
            return Ok(ChunkTable {
                source,
                layout,
                chunks,
                entries_at: 0,
                base: 0,
                floor: table_len,
                ceiling: fork_len,
            });
        }
        // A classic resource fork: where its resource data begins, then the resource's own
        // length, then the chunk count and a pair of words for each chunk.
        let header = self.stored_read(inode, &source, 0, 16)?;
        let data_at = u64::from(get_u32_be(&header, 0));
        let base = data_at + 4;
        let resource_len = u64::from(get_u32_be(
            &self.stored_read(inode, &source, data_at, 4)?,
            0,
        ));
        let ceiling = base
            .checked_add(resource_len)
            .filter(|end| *end <= fork_len)
            .ok_or_else(|| bad("the resource runs past the end of the resource fork"))?;
        let count = decmpfs::word(&self.stored_read(inode, &source, base, 4)?, 0);
        if count != chunks {
            return Err(bad("the resource's chunk count is not the content's"));
        }
        let floor = chunks
            .checked_mul(8)
            .and_then(|pairs| pairs.checked_add(base + 4))
            .filter(|end| *end <= ceiling)
            .ok_or_else(|| bad("the chunk table does not fit the resource"))?;
        Ok(ChunkTable {
            source,
            layout,
            chunks,
            entries_at: base + 4,
            base,
            floor,
            ceiling,
        })
    }

    /// The runs `count` chunks from chunk `first` are stored in, each after its table, inside
    /// the region chunks may lie in, and no longer than a chunk is.
    fn chunk_runs(
        &mut self,
        inode: u64,
        table: &ChunkTable,
        first: u64,
        count: u64,
    ) -> Result<Vec<(u64, u64)>, ReadError> {
        let runs: Vec<(u64, u64)> = match table.layout {
            Layout::Inline => (0..count).map(|_| (table.floor, table.ceiling)).collect(),
            // One entry past the run: a chunk ends where the next one's entry says it begins.
            Layout::Offsets => {
                let entries = self.stored_read(inode, &table.source, 4 * first, 4 * (count + 1))?;
                (0..count as usize)
                    .map(|at| (decmpfs::word(&entries, at), decmpfs::word(&entries, at + 1)))
                    .collect()
            }
            // The entry before the run as well, where there is one: each chunk begins where the
            // one before it ends, and the first where the table does, so the entries tile the
            // resource, as on every classic resource fork of the corpus. An offset and a length
            // per entry would otherwise let two chunks trade places, each decoding to its share.
            Layout::Resource => {
                let from = first.saturating_sub(1);
                let taken = count + (first - from);
                let at = table.entries_at + 8 * from;
                let entries = self.stored_read(inode, &table.source, at, 8 * taken)?;
                let all: Vec<(u64, u64)> = (0..taken as usize)
                    .map(|at| {
                        let start = table.base + decmpfs::word(&entries, 2 * at);
                        (start, start + decmpfs::word(&entries, 2 * at + 1))
                    })
                    .collect();
                let mut begins = (first == 0).then_some(table.floor);
                for (i, &(start, end)) in (from..).zip(&all) {
                    if begins.is_some_and(|at| at != start) {
                        return Err(ReadError::BadCompressed {
                            inode,
                            fault: format!(
                                "chunk {i} does not begin where {} ends",
                                if i == 0 {
                                    "the table"
                                } else {
                                    "the chunk before it"
                                }
                            ),
                        });
                    }
                    begins = Some(end);
                }
                all[(first - from) as usize..].to_vec()
            }
        };
        for (i, (start, end)) in (first..).zip(&runs) {
            if i >= table.chunks
                || *start < table.floor
                || end <= start
                || *end > table.ceiling
                || end - start > MAX_CHUNK
            {
                return Err(ReadError::BadCompressed {
                    inode,
                    fault: format!("chunk {i} is not a run of bytes after its table"),
                });
            }
        }
        Ok(runs)
    }

    /// How many bytes a compressed file keeps after its header as its content itself, beside
    /// the size the header states, where the two differ. [`None`] where they agree, where the
    /// content is not kept so, and where the file cannot be read that far, which a scan reports
    /// on its own.
    fn kept_inline_mismatch(&mut self, node: &Node) -> Option<(u64, u64)> {
        let Some(Ok(compression)) = &node.compression else {
            return None;
        };
        let (Layout::Inline, encoding) = decmpfs::layout(compression.method)? else {
            return None;
        };
        let size = compression.size;
        let table = self.chunk_table(node.inode, Layout::Inline, size).ok()?;
        let (start, end) = *self.chunk_runs(node.inode, &table, 0, 1).ok()?.first()?;
        let stored = self
            .stored_read(node.inode, &table.source, start, end - start)
            .ok()?;
        let held = decmpfs::kept_inline(encoding, &stored)?.len() as u64;
        (held != size).then_some((held, size))
    }

    /// Hold every entry of a compressed file's chunk table to where its chunks may lie, a
    /// window of entries at a time, and a stored chunk to the marker it opens with, without
    /// decoding a chunk.
    fn check_chunk_table(
        &mut self,
        inode: u64,
        layout: Layout,
        encoding: decmpfs::Encoding,
        size: u64,
    ) -> Result<(), ReadError> {
        let table = self.chunk_table(inode, layout, size)?;
        let mut first = 0;
        while first < table.chunks {
            let take = (table.chunks - first).min(TABLE_WINDOW);
            let runs = self.chunk_runs(inode, &table, first, take)?;
            if matches!(encoding, decmpfs::Encoding::Stored) {
                for (i, (start, _)) in (first..).zip(runs) {
                    let opening = self.stored_read(inode, &table.source, start, 1)?[0];
                    if opening != decmpfs::STORED {
                        return Err(ReadError::BadCompressed {
                            inode,
                            fault: format!(
                                "chunk {i}: {}",
                                decmpfs::ChunkError::Unmarked(Some(opening))
                            ),
                        });
                    }
                }
            }
            first += take;
        }
        Ok(())
    }

    /// `len` bytes from byte `start` of an attribute's value, which must hold them all.
    fn stored_read(
        &mut self,
        inode: u64,
        fork: &Stored,
        start: u64,
        len: u64,
    ) -> Result<Vec<u8>, ReadError> {
        let short = || ReadError::BadCompressed {
            inode,
            fault: "the attribute ends before what its header or table names".into(),
        };
        let end = start
            .checked_add(len)
            .filter(|end| *end <= fork.size())
            .ok_or_else(short)?;
        match fork {
            Stored::Embedded(bytes) => Ok(bytes[start as usize..end as usize].to_vec()),
            Stored::Stream { id, stream } => {
                let mut out = vec![0u8; len as usize];
                let got =
                    self.read_stream_into(*id, stream.size, start, &mut out, Holes::Refused)?;
                if got as u64 != len {
                    return Err(short());
                }
                Ok(out)
            }
        }
    }

    /// The whole content of file `node`, and nothing for a node that is not a regular file.
    ///
    /// Held to [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), which defaults to no
    /// cap. A file's data stream size is a number the image supplies, and a hole, an extent at
    /// block zero, reads as zeros, so a stream claiming a terabyte and holding one hole costs a
    /// terabyte of them. A compressed file's content grows as its chunks decode, so the size
    /// its header records is never allocated before the chunk table that has to hold it is read.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the file is larger than the read's cap, and whatever
    /// [`read_into`](Self::read_into) does.
    pub fn read_data(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        if !node.is_file() {
            return Ok(Vec::new());
        }
        let size = self.capped(node.inode, node.size())?;
        if node.compression.is_some() {
            let mut out = Vec::new();
            self.read_data_to(node, &mut out)?;
            return Ok(out);
        }
        let mut buf = vec![0u8; size];
        let got = self.read_into(node, 0, &mut buf)?;
        buf.truncate(got);
        Ok(buf)
    }

    /// Write the whole content of file `node` to `out`, a window at a time, and say how many
    /// bytes that was.
    ///
    /// Bounded by a fixed buffer rather than by the file, so a file far larger than memory
    /// streams through. The same [`Limits::max_file_bytes`](crate::Limits::max_file_bytes) cap
    /// applies as to [`read_data`](Self::read_data), checked before a byte is written: what
    /// the cap expresses is distrust of the declared size, and a stream writes every byte that
    /// size claims — a hole reads back as zeros — as surely as a buffer holds them.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the file is larger than that cap, whatever
    /// [`read_into`](Self::read_into) does, and [`ReadError::Io`] where `out` fails.
    pub fn read_data_to(&mut self, node: &Node, mut out: impl Write) -> Result<u64, ReadError> {
        self.within_cap(node.inode, node.size())?;
        let mut buf = vec![0u8; STREAM_BUFFER];
        let mut offset = 0u64;
        loop {
            let got = self.read_into(node, offset, &mut buf)?;
            if got == 0 {
                return Ok(offset);
            }
            out.write_all(&buf[..got])?;
            offset += got as u64;
        }
    }

    /// Refuse `size` bytes of inode `inode` where they are more than this read's cap.
    fn within_cap(&self, inode: u64, size: u64) -> Result<(), ReadError> {
        let limit = self.limits().max_file_bytes;
        if size > limit {
            return Err(ReadError::FileTooLarge { inode, size, limit });
        }
        Ok(())
    }

    /// `size` as a length this read may allocate for inode `inode`.
    fn capped(&self, inode: u64, size: u64) -> Result<usize, ReadError> {
        self.within_cap(inode, size)?;
        let limit = self.limits().max_file_bytes;
        usize::try_from(size)
            .ok()
            .filter(|n| isize::try_from(*n).is_ok())
            .ok_or(ReadError::FileTooLarge { inode, size, limit })
    }

    /// Fill `buf` from byte `offset` of stream `stream`, `size` bytes long. An extent at block
    /// zero reads as `holes` says.
    fn read_stream_into(
        &mut self,
        stream: u64,
        size: u64,
        offset: u64,
        buf: &mut [u8],
        holes: Holes,
    ) -> Result<usize, ReadError> {
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(size - offset);
        let window = &mut buf[..want as usize];
        window.fill(0);
        let end = offset + want;
        let bs = u64::from(self.container.block_size());
        let runs = match holes {
            Holes::Zeros => self.stream_runs(stream, offset, end)?,
            Holes::Refused => self.attribute_runs(stream, offset, end)?,
        };
        for extent in runs {
            let lo = extent.logical.max(offset);
            let hi = (extent.logical + extent.length).min(end);
            if lo >= hi {
                continue;
            }
            // The run's bytes straight into the window, from where they begin in their block.
            let within = lo - extent.logical;
            let dest = &mut window[(lo - offset) as usize..(hi - offset) as usize];
            self.container
                .read_within(extent.physical_block + within / bs, within % bs, dest)?;
        }
        Ok(want as usize)
    }

    /// The extents of data stream `stream` that hold bytes of `offset..end`.
    ///
    /// Every extent the range meets is held to the container: its length a whole number of
    /// blocks, its blocks inside the container and in no other extent the range meets, and its
    /// start exactly the end of the extent before it, so that together they cover the range.
    /// An extent at block zero is a run of zeros, and is not among them.
    fn stream_runs(
        &mut self,
        stream: u64,
        offset: u64,
        end: u64,
    ) -> Result<Vec<FileExtent>, ReadError> {
        // The extent covering `offset`, or the first after it.
        let start = btree::find_at_or_before(
            &mut self.container,
            &self.fs_tree,
            &btree::extent_at(stream, offset),
        )?
        .and_then(|(key, value)| {
            let header = KeyHeader::read_from(&key).ok()?;
            ((header.id, header.kind) == (stream, record_kind::FILE_EXTENT))
                .then(|| btree::extent(&key, &value).ok())
                .flatten()
        })
        .map_or(0, |extent| extent.logical);
        let bs = u64::from(self.container.block_size());
        let block_count = self.container.superblock().block_count;
        let mut runs = Vec::new();
        // Where the next extent must begin: the start of the one covering `offset`, then the
        // end of each one met.
        let mut previous_end = start;
        let mut fault = None;
        let limit = self.limits().max_walk_entries;
        // The leaf of the record the walk stopped at, which is the record at fault where a fault
        // stopped it.
        let stopped = btree::for_each_from(
            &mut self.container,
            &self.fs_tree,
            &btree::extent_at(stream, start),
            limit,
            &mut |key, value| {
                let header = KeyHeader::read_from(key)?;
                if (header.id, header.kind) != (stream, record_kind::FILE_EXTENT) {
                    return Ok(false);
                }
                let extent = btree::extent(key, value)?;
                if extent.logical >= end {
                    return Ok(false);
                }
                let extent_end = extent.logical.checked_add(extent.length);
                let problem = if extent.flags != 0 {
                    Some("an extent carrying flags this crate does not read")
                } else if extent.length == 0 || extent.length % bs != 0 {
                    Some("an extent whose length is not a whole number of blocks")
                } else if extent.logical < previous_end {
                    Some("an extent overlapping the one before it")
                } else if extent.logical > previous_end {
                    fault = Some((previous_end, UNCOVERED));
                    return Ok(false);
                } else if extent_end.is_none() {
                    Some("an extent reaching past the largest offset")
                } else if extent.physical_block != 0
                    && extent
                        .physical_block
                        .checked_add(extent.length / bs)
                        .is_none_or(|last| last > block_count)
                {
                    Some("an extent whose blocks leave the container")
                } else {
                    None
                };
                if let Some(problem) = problem {
                    fault = Some((extent.logical, problem));
                    return Ok(false);
                }
                let extent_end = extent_end.unwrap_or(u64::MAX);
                previous_end = extent_end;
                if extent_end > offset && extent.physical_block != 0 {
                    runs.push(extent);
                }
                Ok(true)
            },
        )?;
        if let Some((logical, fault)) = fault {
            return Err(ReadError::BadExtent {
                stream,
                logical,
                block: stopped,
                fault,
            });
        }
        if previous_end < end {
            return Err(ReadError::BadExtent {
                stream,
                logical: previous_end.max(offset),
                block: None,
                fault: UNCOVERED,
            });
        }
        // Clones share blocks between streams; within one stream, a block read twice is a
        // byte the stream holds twice.
        if let Some(logical) = reused_block(&runs, bs) {
            return Err(ReadError::BadExtent {
                stream,
                logical,
                block: None,
                fault: REUSED,
            });
        }
        Ok(runs)
    }

    /// The extents of attribute stream `stream` that hold bytes of `offset..end`, every one of
    /// them at a block of the container.
    ///
    /// macOS writes every byte of an attribute's stream to blocks: no attribute stream of any
    /// image it wrote holds an extent at block zero, and a resource fork written as two pieces
    /// with sixteen megabytes between them is stored as one extent of blocks (observed, macOS
    /// 26). So a hole in one is refused, and what an attribute holds is what the container
    /// holds.
    fn attribute_runs(
        &mut self,
        stream: u64,
        offset: u64,
        end: u64,
    ) -> Result<Vec<FileExtent>, ReadError> {
        let runs = self.stream_runs(stream, offset, end)?;
        // The runs leave out the holes and cover the range with them, so a byte before a run,
        // between two, or after the last is a hole.
        let hole = |logical| ReadError::BadExtent {
            stream,
            logical,
            block: None,
            fault: HOLE,
        };
        let mut held = offset;
        for run in &runs {
            if run.logical > held {
                return Err(hole(held));
            }
            held = held.max(run.logical.saturating_add(run.length));
        }
        if held < end {
            return Err(hole(held));
        }
        Ok(runs)
    }

    /// Every name in the volume with the node at it, the root first and then depth first.
    ///
    /// # Errors
    ///
    /// Whatever reading a node or a directory does, [`ReadError::HostileName`] for a name no
    /// directory can hold, [`ReadError::WalkTooLarge`] past the walk limit, and under a strict
    /// policy [`ReadError::RepeatedDirectory`] for a directory reached by a second name and
    /// [`ReadError::MisplacedDirectory`] for one named from outside its parent.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, ReadError> {
        let mut out = Vec::new();
        self.walk_with::<ReadError, _>(|_, entry| {
            out.push(entry);
            Ok(())
        })?;
        Ok(out)
    }

    /// Visit every name in the volume with the node at it, the root first and then depth
    /// first, without gathering them.
    ///
    /// # Errors
    ///
    /// As [`walk`](Self::walk), and whatever `visit` returns.
    pub fn walk_with<E, F>(&mut self, mut visit: F) -> Result<(), E>
    where
        E: From<ReadError>,
        F: FnMut(&mut Self, WalkEntry) -> Result<(), E>,
    {
        let root = self.root()?;
        visit(
            self,
            WalkEntry {
                path: Vec::new(),
                node: root,
            },
        )?;
        crate::walk::drive(self, visit)
    }

    /// Every record of the volume's file-system tree, in key order: what a gate comparing two
    /// volumes record by record compares.
    #[cfg(test)]
    pub(crate) fn every_record(&mut self) -> Result<Vec<super::bulk::Record>, ReadError> {
        let tree = self.fs_tree;
        let mut out = Vec::new();
        btree::census(&mut self.container, &tree, &mut |key, value| {
            out.push((key.to_vec(), value.to_vec()));
            Ok(true)
        })?;
        Ok(out)
    }

    /// Walk the whole volume and report every deviation met, rather than stopping at the first.
    ///
    /// Block zero is held to the live checkpoint, and a checkpoint passed over at opening is
    /// reported as the interrupted write, the damage, or the other container's it is. Every node
    /// of the container's object map and the volume's is read and verified, and every node and
    /// record of the file-system tree, and each tree is held to what its root says it holds.
    /// Every record is held, wherever it is, to what a read of it refuses: an inode's fields, a
    /// directory entry's framing, its name and the inode it names, and an attribute's name, its
    /// value and how it keeps it; and every entry to its hash, every directory to its child
    /// count, and every extended field to its type's rules. Every stream's extents are held to
    /// its allocation, and every block they use to its reference count in the extent-reference
    /// trees, which are read whole as well. The volume superblock's counts are held to the inode
    /// records and its words to what the volume holds; each other inode's link count to the
    /// names reaching it, each directory to one name in its parent, and each entry's type to its
    /// inode. Every inode a name reaches is read as far as a read of it reads short of its
    /// content: the extents of each attribute stream, its own extents, a compressed file's chunk
    /// table, and a link's target. The scan stops looking once
    /// [`Limits::max_findings`](crate::Limits) findings are held, and its report says so.
    pub fn scan(&mut self) -> ScanReport {
        let mut scan = Scan::new(self.limits().max_findings, self.container.block_size());
        self.scan_checkpoint(&mut scan);
        let largest = self.scan_object_maps(&mut scan);
        self.scan_container(&mut scan, largest);
        super::space::check(&mut self.container, &mut scan);

        // Every record, so every node is verified on the way and every inode is counted.
        let tree = self.fs_tree;
        let fold = self.superblock().is_case_insensitive();
        let mut held = Held::default();
        let walked = btree::census(&mut self.container, &tree, &mut |key, value| {
            held.gather(&mut scan, key, value, fold)?;
            Ok(!scan.found.is_full())
        });
        let census = match walked {
            Ok(census) => census,
            Err(e) => {
                scan.failed(None, "the file-system tree", &e);
                return scan.finish();
            }
        };
        held.close();
        scan.census("file-system", &census);

        held.check_entries(&mut scan);
        held.check_directories(&mut scan);
        held.check_forks(&mut scan);
        held.check_streams(&mut scan);
        self.scan_extent_references(&mut scan, &held);
        self.scan_volume(&mut scan, &held);
        self.scan_namespace(&mut scan, &held);
        scan.finish()
    }

    /// How block zero stands to the live checkpoint, and each checkpoint opening passed over.
    fn scan_checkpoint(&self, scan: &mut Scan) {
        let live = self.container.xid();
        let block_zero = self.container.block_zero();
        match block_zero {
            BlockZero::Current => {}
            BlockZero::Older { .. } => scan.at(
                Category::Checkpoint,
                Severity::Cosmetic,
                Some(0),
                None,
                format!(
                    "{}; {block_zero}, and the container is read at transaction {live}",
                    crate::finding::NOT_CLEANLY_UNMOUNTED
                ),
            ),
            _ => scan.at(
                Category::Checkpoint,
                Severity::Integrity,
                Some(0),
                None,
                format!(
                    "{block_zero}, and the container is read at the live checkpoint, \
                     transaction {live}"
                ),
            ),
        }
        // A checkpoint block zero was written after is one a write finished, so one passed
        // over at or below block zero's transaction is damage rather than an interrupted write.
        let written = match block_zero {
            BlockZero::Newer { xid } | BlockZero::NotLoaded { xid } => xid,
            _ => live,
        };
        for passed in self.container.passed_over() {
            if passed.reason == super::container::SAME_TRANSACTION {
                scan.at(
                    Category::Checkpoint,
                    Severity::Integrity,
                    Some(passed.address),
                    None,
                    format!(
                        "two whole checkpoints record transaction {}, so which one the container \
                         is at is not known; it is read at the one in the lower slot",
                        passed.xid
                    ),
                );
                continue;
            }
            let (severity, what) = if passed.reason == super::container::FOREIGN {
                // Every checkpoint passed over is newer than the live one, so a read taking the
                // newest whole checkpoint, as the reference's procedure does, reads the other
                // container.
                (
                    Severity::Integrity,
                    "a read taking the newest whole checkpoint reads that container",
                )
            } else if passed.reason == super::container::QUEUE_LIMITS {
                // A finished write as much as an interrupted one: it is the space manager it
                // records, not where it stands to block zero, that macOS refuses.
                (Severity::Integrity, "macOS passes it over as well")
            } else if passed.xid <= written {
                (Severity::Integrity, "block zero records it as written")
            } else {
                (Severity::Cosmetic, crate::finding::NOT_CLEANLY_UNMOUNTED)
            };
            scan.at(
                Category::Checkpoint,
                severity,
                Some(passed.address),
                None,
                format!(
                    "the checkpoint at transaction {} is not whole ({}) and {what}; the \
                     container is read at transaction {live}",
                    passed.xid, passed.reason
                ),
            );
        }
    }

    /// Walk the container's object map and the volume's whole, every node of each held to
    /// every tree-shape check and each tree to what its root says it holds: a lookup through a
    /// map checks only the nodes it reaches. Answers the largest identifier either maps, where
    /// both were read whole.
    fn scan_object_maps(&mut self, scan: &mut Scan) -> Option<u64> {
        let maps = [
            ("container's object-map", self.container.container_map()),
            ("volume's object-map", self.map_tree),
        ];
        // The snapshot tree is read whole as well, though it maps nothing.
        if let Some(tree) = self.snapshot_tree() {
            match btree::census(&mut self.container, &tree, &mut |_, _| Ok(true)) {
                Ok(census) => scan.census("snapshot", &census),
                Err(e) => scan.failed(None, "the snapshot tree", &e),
            }
        }
        let mut largest = Some(0);
        for (what, tree) in maps {
            let mut most = 0;
            let walked = btree::census(&mut self.container, &tree, &mut |key, _| {
                most = most.max(MapKey::read_from(key)?.oid);
                Ok(true)
            });
            match walked {
                Ok(census) => {
                    scan.census(what, &census);
                    largest = largest.map(|l| l.max(most));
                }
                Err(e) => {
                    scan.failed(None, &format!("the {what} tree"), &e);
                    largest = None;
                }
            }
        }
        largest
    }

    /// Hold the live container superblock's account of the container to what it holds, where
    /// `largest` is the largest identifier the container's and the volume's object maps hold.
    ///
    /// The next object identifier is past every one in use, since new ones increase
    /// (reference p. 12), and the next transaction past the live one; the identifier is not
    /// zero; and the most volumes the container may hold is its size over 512 MiB, rounded up,
    /// at most 100 (p. 32), and no smaller than the volumes it lists. `fsck_apfs` refuses each of
    /// the first three, and its repair does not clear them, and every container `newfs_apfs`
    /// formats keeps the fourth (observed, macOS 15, 26 and 27). Each is a number the container
    /// keeps about itself, and a writer taking it from the image would reuse a transaction or an
    /// identifier, or offer a slot the container does not have.
    fn scan_container(&mut self, scan: &mut Scan, largest: Option<u64>) {
        // A container longer than its source: the blocks past the source's end are blocks it
        // counts on and does not have, as btrfs reports a device shorter than it describes.
        let sb = self.container.superblock().clone();
        let at = Some(self.container.checkpoint_address());
        let bytes = u128::from(sb.block_count) * u128::from(sb.block_size);
        match self.container.source_bytes() {
            Ok(have) if u128::from(have) < bytes => scan.at(
                Category::Checkpoint,
                Severity::Structural,
                at,
                None,
                format!(
                    "the container records {} blocks, {bytes} bytes, and the source holds {have} \
                     from where the container begins",
                    sb.block_count
                ),
            ),
            Ok(_) => {}
            Err(e) => scan.failed(None, "the source's length", &e),
        }
        if sb.incompatible_features & container_incompat::VERSION2 == 0 {
            scan.at(
                Category::Checkpoint,
                Severity::Conformance,
                at,
                None,
                "the container records no format version, and is read as the second".to_string(),
            );
        }
        // A volume whose superblock could not be read is one no read of the container reaches.
        for unread in self.container.unreadable_volumes() {
            scan.failed(
                None,
                &format!("the volume in slot {}", unread.slot),
                &unread.error,
            );
        }
        let sb = self.container.superblock();
        let mut deviation = |detail: String| {
            scan.at(
                Category::Checkpoint,
                Severity::Conformance,
                Some(self.container.checkpoint_address()),
                None,
                detail,
            );
        };
        if let Some(largest) = largest
            && largest >= sb.next_oid
        {
            deviation(format!(
                "the container records {} as its next object identifier and its object maps hold \
                 object {largest}",
                sb.next_oid
            ));
        }
        if sb.next_xid <= sb.header.xid {
            deviation(format!(
                "the container records {} as its next transaction and its live checkpoint is \
                 transaction {}",
                sb.next_xid, sb.header.xid
            ));
        }
        if sb.uuid == [0; 16] {
            deviation("the container's identifier is zero".to_string());
        }
        let bytes = u128::from(sb.block_count) * u128::from(sb.block_size);
        let most = bytes.div_ceil(512 << 20).min(100);
        if u128::from(sb.max_volumes) != most {
            deviation(format!(
                "the container records {} as the most volumes it holds, and a container of {bytes} \
                 bytes holds {most}",
                sb.max_volumes
            ));
        }
        if let Some((slot, _)) = sb.volumes().last()
            && slot >= sb.max_volumes as usize
        {
            deviation(format!(
                "the container lists a volume in slot {slot} and records {} as the most volumes \
                 it holds",
                sb.max_volumes
            ));
        }
    }

    /// Hold the blocks every extent at a nonzero block uses to the extent-reference trees that
    /// apply to the view: each snapshot's up to and including the one being read, and for the
    /// volume as it is, the volume's own as well. A tree records a run with its reference
    /// count, and a later tree records a change to a count an earlier one holds as a signed
    /// count, so a block's count is the sum over those trees; it is the number of streams
    /// whose extents use the block (observed on every volume and snapshot of macOS 14 to 27,
    /// through clones, removals, overwrites and snapshot deletions). Blocks more streams use
    /// than their count says may hold another file's data, and are [`Severity::Integrity`], as
    /// is a count below zero; a count no stream accounts for is space spent on nothing a reader
    /// reaches, [`Severity::Conformance`].
    ///
    /// A run records the stream or inode that wrote it, and keeps naming it after it stops
    /// using the run or is removed, so who wrote a run does not say who uses it. An inode
    /// never cloned does use only blocks it wrote (`INODE_WAS_EVER_CLONED`, reference p. 91),
    /// so where the volume keeps that flag exact, every extent of a stream only such inodes
    /// use lies in runs recorded as the stream's or as one of those inodes'. That holds two
    /// extents of different files that trade places, which leaves every count as it was.
    fn scan_extent_references(&mut self, scan: &mut Scan, held: &Held) {
        let at = self.view.as_ref().map(|view| view.0.xid);
        let mut roots = Vec::new();
        match self.snapshot_metas() {
            Ok(metas) => roots.extend(
                metas
                    .iter()
                    .filter(|meta| at.is_none_or(|xid| meta.xid <= xid))
                    .map(|meta| meta.extent_ref_tree_oid)
                    .filter(|oid| *oid != 0),
            ),
            Err(e) => {
                scan.failed(None, "the snapshot tree", &e);
                return;
            }
        }
        let live = self.volume.superblock.extent_ref_tree_oid;
        if at.is_none() && live != 0 {
            roots.push(live);
        }
        if roots.is_empty() {
            if let Some(first) = held.placed.first() {
                scan.at(
                    Category::Volume,
                    Severity::Conformance,
                    Some(first.block),
                    None,
                    "the volume keeps no extent-reference tree, so no extent's blocks are known \
                     to be its stream's"
                        .to_string(),
                );
            }
            return;
        }
        // Each block's count from every record, and the runs each record wrote.
        let mut counts: Vec<(u64, i64, i64)> = Vec::new();
        let mut written: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        for oid in roots {
            let tree = TreeRoot {
                oid,
                children: Children::Physical,
                subtype: kind::EXTENT_REF_TREE,
                order: Order::FileSystem,
                max_xid: self.container.xid(),
            };
            let walked = btree::census(&mut self.container, &tree, &mut |key, value| {
                let header = KeyHeader::read_from(key)?;
                if header.kind == record_kind::PHYSICAL_EXTENT {
                    match PhysicalExtent::read_from(key, value) {
                        Ok(run) => {
                            let end = run.start.saturating_add(run.blocks);
                            let count = i64::from(run.references);
                            counts.push((run.start, count, 0));
                            counts.push((end, -count, 0));
                            written.entry(run.owner).or_default().push((run.start, end));
                        }
                        Err(e) => scan.at(
                            Category::Record,
                            Severity::Structural,
                            Some(header.id),
                            None,
                            format!("the physical extent record at block {}: {e}", header.id),
                        ),
                    }
                }
                Ok(!scan.found.is_full())
            });
            match walked {
                Ok(census) => scan.census("extent-reference", &census),
                Err(e) => {
                    // A tree not read whole cannot give any block its count.
                    scan.failed(None, "the extent-reference tree", &e);
                    return;
                }
            }
        }
        // The streams using each block. A stream holding one block twice is refused where its
        // extents are read, and is counted here as using it once.
        let mut by_stream: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        for placed in &held.placed {
            let end = placed.block.saturating_add(placed.blocks);
            by_stream
                .entry(placed.stream)
                .or_default()
                .push((placed.block, end));
        }
        for runs in by_stream.values_mut() {
            merge_runs(runs);
            for &(start, end) in runs.iter() {
                counts.push((start, 0, 1));
                counts.push((end, 0, -1));
            }
        }
        // The inodes using each stream, for naming one in a finding and for the clone rule.
        let mut users: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (inode, stream, _) in held.streams.iter().chain(&held.attribute_streams) {
            users.entry(*stream).or_default().push(*inode);
        }
        // The extents at nonzero blocks by first block, beside the furthest block any of them up
        // to each reaches, so an extent meeting a run is found by search rather than by a scan
        // of every extent per disagreement.
        let mut by_block: Vec<&Placed> = held.placed.iter().collect();
        by_block.sort_unstable_by_key(|p| p.block);
        let reach: Vec<u64> = by_block
            .iter()
            .scan(0u64, |far, p| {
                *far = (*far).max(p.block.saturating_add(p.blocks));
                Some(*far)
            })
            .collect();
        let first_at = |start: u64, end: u64| {
            // Of the extents beginning before `end`, the first whose end passes `start`: where
            // the furthest reach first passes it, the extent there is the one that took it.
            let before = by_block.partition_point(|p| p.block < end);
            let at = reach[..before].partition_point(|far| *far <= start);
            by_block.get(at).filter(|_| at < before).copied()
        };
        let disagreeing = disagreements(counts);
        for &(start, end, count, using) in &disagreeing {
            if scan.found.is_full() {
                return;
            }
            if count < 0 {
                scan.at(
                    Category::Record,
                    Severity::Integrity,
                    Some(start),
                    None,
                    format!(
                        "blocks {start}..{end} have a reference count of {count}, which no run \
                         can have"
                    ),
                );
            } else if using > count {
                let first = first_at(start, end);
                let inode = first.map(|p| {
                    users
                        .get(&p.stream)
                        .and_then(|inodes| inodes.first())
                        .copied()
                        .unwrap_or(p.stream)
                });
                let which = first.map_or_else(String::new, |p| {
                    format!(
                        "; the first is the extent at byte {} of stream {}",
                        p.logical, p.stream
                    )
                });
                scan.at(
                    Category::Record,
                    Severity::Integrity,
                    Some(start),
                    inode,
                    format!(
                        "blocks {start}..{end} are used by {using} streams and have a reference \
                         count of {count}, so an extent may point at another file's blocks{which}"
                    ),
                );
            } else {
                scan.at(
                    Category::Record,
                    Severity::Conformance,
                    Some(start),
                    None,
                    format!(
                        "blocks {start}..{end} have a reference count of {count} and {using} \
                         streams use them, so the space is spent on nothing a reader reaches"
                    ),
                );
            }
        }
        // Where the volume keeps clone information exact: a stream only inodes never cloned
        // use lies in runs it wrote.
        let sb = self.superblock();
        let exact = sb.clone_info_xid != 0 && sb.clone_info_xid == sb.modified_by[0].last_xid;
        if !exact {
            return;
        }
        let epoch = sb.clone_info_epoch;
        for runs in written.values_mut() {
            merge_runs(runs);
        }
        let wrote = |id: u64, start: u64, end: u64| {
            written
                .get(&id)
                .is_some_and(|runs| covers(runs, start, end))
        };
        // The disagreements are in block order and do not overlap, so their ends are too.
        let in_disagreement = |start: u64, end: u64| {
            let at = disagreeing.partition_point(|d| d.1 <= start);
            disagreeing.get(at).is_some_and(|d| d.0 < end)
        };
        for placed in &held.placed {
            if scan.found.is_full() {
                return;
            }
            let end = placed.block.saturating_add(placed.blocks);
            let Some(inodes) = users.get(&placed.stream) else {
                continue;
            };
            if inodes
                .iter()
                .any(|inode| *inode <= epoch || held.ever_cloned.contains(inode))
                || in_disagreement(placed.block, end)
                || wrote(placed.stream, placed.block, end)
                || inodes.iter().any(|inode| wrote(*inode, placed.block, end))
            {
                continue;
            }
            scan.at(
                Category::Record,
                Severity::Integrity,
                Some(placed.block),
                inodes.first().copied(),
                format!(
                    "the extent at byte {} of stream {}, blocks {}..{end}, lies in a run another \
                     record wrote, and no inode using the stream has been cloned, so its blocks \
                     may hold another file's data",
                    placed.logical, placed.stream, placed.block
                ),
            );
        }
    }

    /// Hold the volume superblock's counts of inodes and its next object identifier to the
    /// records, and, on the volume as it is, its words to what the volume holds: the type of each
    /// tree's root, the snapshots it counts, and its flags.
    fn scan_volume(&mut self, scan: &mut Scan, held: &Held) {
        let counts = &held.counts;
        let sb = self.superblock().clone();
        let at = self
            .view
            .as_ref()
            .map_or(self.volume.address, |view| view.0.superblock);
        let recorded = [
            ("regular files", sb.file_count, counts[0]),
            // The root and the private directory are not counted.
            (
                "directories",
                sb.directory_count,
                counts[1].saturating_sub(2),
            ),
            ("symbolic links", sb.symlink_count, counts[2]),
            ("other nodes", sb.other_count, counts[3]),
        ];
        for (what, said, held) in recorded {
            if said != held {
                scan.at(
                    Category::Volume,
                    Severity::Conformance,
                    Some(at),
                    None,
                    format!("the volume records {said} {what} and holds {held}"),
                );
            }
        }
        // An identifier at or past the next one is one the volume would assign a second time.
        // Every volume and snapshot macOS 15, 26 and 27 wrote holds none.
        if held.largest_id >= sb.next_object_id {
            scan.at(
                Category::Volume,
                Severity::Conformance,
                Some(at),
                None,
                format!(
                    "the volume records {} as its next object identifier and its tree holds \
                     object {}",
                    sb.next_object_id, held.largest_id
                ),
            );
        }
        // A zero identifier is one `fsck_apfs` refuses, and its repair does not clear (observed,
        // macOS 15, 26 and 27).
        if sb.uuid == [0; 16] {
            scan.at(
                Category::Volume,
                Severity::Conformance,
                Some(at),
                None,
                "the volume's identifier is zero".to_string(),
            );
        }
        if self.view.is_some() {
            return;
        }
        let mut deviation = |detail: String| {
            scan.at(
                Category::Volume,
                Severity::Conformance,
                Some(at),
                None,
                detail,
            );
        };
        // The file-system tree's root is virtual, the other two physical, and each a tree's root.
        let virtual_root = u32::from(kind::BTREE_ROOT);
        let physical_root = 0x4000_0000 | virtual_root;
        for (tree, word, want) in [
            ("file-system", sb.root_tree_type, virtual_root),
            ("extent-reference", sb.extent_ref_tree_type, physical_root),
            ("snapshot", sb.snapshot_tree_type, physical_root),
        ] {
            if word != want {
                deviation(format!(
                    "the volume records its {tree} tree's root as of type {word:#010x}, and it \
                     is read as one of type {want:#010x}"
                ));
            }
        }
        // A snapshot tree that does not read is reported where the snapshot trees are read.
        if let Ok(metas) = self.snapshot_metas() {
            if metas.len() as u64 != sb.snapshot_count {
                deviation(format!(
                    "the volume records {} snapshots and holds {}",
                    sb.snapshot_count,
                    metas.len()
                ));
            }
            // The root-to transaction names the snapshot the volume roots from, by the
            // transaction that records it.
            if sb.root_to_xid != 0 && !metas.iter().any(|meta| meta.xid == sb.root_to_xid) {
                deviation(format!(
                    "the volume roots from the snapshot of transaction {} and holds no \
                     snapshot of it",
                    sb.root_to_xid
                ));
            }
        }
        let unknown = sb.flags & !volume_flags::DEFINED;
        if unknown != 0 {
            deviation(format!(
                "the volume's flags carry {unknown:#x}, which the format does not define"
            ));
        }
    }

    /// The namespace: the names each inode is reached by, each directory's parent, entry
    /// types, and a read of every inode a name reaches.
    ///
    /// The walk passes over what a strict read refuses — a directory reached by a second name,
    /// one named from outside its parent — and goes on, since a scan reports every deviation
    /// rather than the first; each is a finding here instead.
    fn scan_namespace(&mut self, scan: &mut Scan, held: &Held) {
        let mut names: BTreeMap<u64, (u64, i32)> = BTreeMap::new();
        let mut directories: BTreeMap<u64, u64> = BTreeMap::new();
        let policy = self.policy();
        self.container.set_policy(ReadPolicy::Lenient);
        let mut visit = |walk: &mut Namespace<'_, R>, named: Named| -> Result<(), ReadError> {
            let reader = &mut *walk.reader;
            let Named { path, node, entry } = named;
            let path = if path.is_empty() { b"/".to_vec() } else { path };
            let at = || crate::escape::printable(&path);
            if let Some((named_in, entry_type)) = entry {
                let want = (node.file_type() >> 12) as u8;
                if entry_type != want {
                    scan.at(
                        Category::Record,
                        Severity::Integrity,
                        None,
                        Some(node.inode),
                        format!(
                            "{}: the entry's type is {entry_type} and its inode's is {want}",
                            at()
                        ),
                    );
                }
                if node.is_dir() && node.value.parent_id != named_in {
                    scan.at(
                        Category::Record,
                        Severity::Integrity,
                        None,
                        Some(node.inode),
                        format!(
                            "{}: the entry names directory {} from directory {named_in}, and the \
                             directory records inode {} as its parent",
                            at(),
                            node.inode,
                            node.value.parent_id
                        ),
                    );
                }
            }
            let seen = if node.is_dir() {
                directories.entry(node.inode).or_default()
            } else {
                &mut names.entry(node.inode).or_insert((0, node.links())).0
            };
            *seen += 1;
            if *seen > 1 {
                return Ok(());
            }
            match reader.check_node(&node) {
                Ok(Some(method)) => scan.undecoded(method),
                Ok(None) => {}
                Err(e) => scan.failed(Some(node.inode), &at(), &e),
            }
            // macOS answers EPERM to every list and read of an attribute on a device node
            // (observed, macOS 15, 26 and 27), so one held there is one macOS does not reach.
            let mode = node.file_type();
            if (mode == MODE_CHR || mode == MODE_BLK)
                && reader
                    .parsed_xattr_records(node.inode)
                    .is_ok_and(|(records, _)| !records.is_empty())
            {
                scan.at(
                    Category::Record,
                    Severity::Conformance,
                    None,
                    Some(node.inode),
                    format!(
                        "{}: a device node carries attributes, which macOS neither lists nor reads",
                        at()
                    ),
                );
            }
            // A compressed file records its content's size twice, in the inode and in its
            // compression header, and a read takes the header's, the size the kernel reads
            // (observed). The size `stat` gives, the header's and what the kernel reads agree
            // on every type 9 file of the system volumes of macOS 14 to 27 (observed); an inode
            // recording another size than its header is reported.
            if let Some(Ok(compression)) = &node.compression
                && node.value.uncompressed_size != compression.size
            {
                scan.at(
                    Category::Record,
                    Severity::Conformance,
                    None,
                    Some(node.inode),
                    format!(
                        "{}: the inode records {} bytes of compressed content, and its \
                         compression header {}",
                        at(),
                        node.value.uncompressed_size,
                        compression.size
                    ),
                );
            }
            // Content kept after the header as itself, at another length than the header states,
            // is read to the header's size by macOS (observed) and by a lenient read, and refused
            // by a strict one.
            if let Some((held, stated)) = reader.kept_inline_mismatch(&node) {
                scan.at(
                    Category::Record,
                    Severity::Conformance,
                    None,
                    Some(node.inode),
                    format!(
                        "{}: {held} bytes of content are kept after the compression header, which \
                         states {stated}",
                        at()
                    ),
                );
            }
            Ok(())
        };
        let walked = self.root().and_then(|root| {
            let mut walk = Namespace { reader: self };
            visit(
                &mut walk,
                Named {
                    path: Vec::new(),
                    node: root,
                    entry: None,
                },
            )?;
            crate::walk::drive(&mut walk, &mut visit)
        });
        self.container.set_policy(policy);
        // A link count is held to the names a whole walk reaches, and a directory to being
        // reached at all; a walk that stopped short has names nobody counted.
        if let Err(e) = walked {
            scan.failed(None, "the namespace", &e);
            return;
        }
        for (inode, (seen, links)) in names {
            if i64::from(links) != seen as i64 {
                scan.at(
                    Category::Volume,
                    Severity::Conformance,
                    None,
                    Some(inode),
                    format!("the inode records {links} links and is reached by {seen} names"),
                );
            }
        }
        for (&directory, &seen) in &directories {
            if seen > 1 {
                scan.at(
                    Category::Volume,
                    Severity::Integrity,
                    None,
                    Some(directory),
                    format!(
                        "directory {directory}: {seen} names reach it, and an APFS directory \
                         has one"
                    ),
                );
            }
        }
        // The root and the private directory are the two no name reaches (the volume counts
        // neither among its directories).
        for &(directory, _) in &held.directories {
            if directory != inode_number::ROOT
                && directory != inode_number::PRIVATE
                && !directories.contains_key(&directory)
            {
                scan.at(
                    Category::Volume,
                    Severity::Integrity,
                    None,
                    Some(directory),
                    format!(
                        "directory {directory} is in the volume and no name reaches it, so \
                         nothing below it is read"
                    ),
                );
            }
        }
    }

    /// Read everything about `node` that a read of it reads, short of decoding its content:
    /// its attribute records and the extents of each attribute stream, its own extents, a
    /// compressed file's chunk table, and a link's target. Answers the compression type of a
    /// file whose content this build does not decode.
    fn check_node(&mut self, node: &Node) -> Result<Option<u32>, ReadError> {
        let id = node.inode;
        // An attribute record whose name, value or flags do not parse is the record pass's to
        // report, wherever the record is, so it is passed over here rather than found twice.
        let (records, _) = self.parsed_xattr_records(id)?;
        for (_, flags, data) in records {
            if let Ok(Stored::Stream {
                id: stream,
                stream: ds,
            }) = Stored::of(id, flags, &data)
            {
                self.attribute_runs(stream, 0, ds.size)?;
            }
        }
        if node.is_symlink() {
            self.link_target(node)?;
        }
        if let Some(compression) = &node.compression {
            let compression = compression.clone()?;
            let Some((layout, encoding)) = decmpfs::layout(compression.method) else {
                return Ok(Some(compression.method));
            };
            self.check_chunk_table(id, layout, encoding, compression.size)?;
            return Ok((!encoding.available()).then_some(compression.method));
        }
        if let Some(stream) = node.stream {
            self.stream_runs(node.value.private_id, 0, stream.size)?;
        }
        Ok(None)
    }

    /// Refuse under a strict policy `node`, reached by a name in directory `named_in`, where it
    /// is a directory recording another parent: an APFS directory has one name, in its parent
    /// (observed on every directory of every volume macOS 14 to 27 wrote), so its subtree would
    /// be read where it does not belong. A lenient read reads through it, and a scan reports it.
    /// A directory a walk reaches again, by a second name or round a cycle: every record
    /// parses, and the records disagree about the tree they make, which is integrity damage a
    /// strict read refuses and a lenient one passes over.
    fn hold_repeat(&self, node: &Node) -> Result<(), ReadError> {
        if self.policy().is_fatal(Severity::Integrity) {
            return Err(ReadError::RepeatedDirectory { inode: node.inode });
        }
        Ok(())
    }

    fn hold_parent(&self, node: &Node, named_in: u64) -> Result<(), ReadError> {
        if node.is_dir()
            && node.value.parent_id != named_in
            && self.policy().is_fatal(Severity::Integrity)
        {
            return Err(ReadError::MisplacedDirectory {
                inode: node.inode,
                named_in,
                parent: node.value.parent_id,
            });
        }
        Ok(())
    }

    /// The names below `dir`, at `path`, as frontier elements in reverse listing order: each
    /// path, with the inode it names, the directory that names it, and the entry's type.
    fn pending_children(&mut self, dir: &Node, path: &[u8]) -> Result<Vec<Unvisited>, ReadError> {
        let named_in = dir.inode;
        let entries = self
            .read_dir(dir)?
            .into_iter()
            .map(|e| (e.name, (e.file_id, named_in, e.entry_type)));
        crate::walk::frontier(
            path,
            entries,
            |name| ReadError::HostileName { name },
            |path| ReadError::PathTooLong { path },
        )
    }
}

/// The logical offset of the first of `runs`, by block, whose blocks another of them also
/// uses, or [`None`] where no block is in two.
fn reused_block(runs: &[FileExtent], bs: u64) -> Option<u64> {
    let mut by_block: Vec<(u64, u64, u64)> = runs
        .iter()
        .map(|run| {
            let end = run.physical_block.saturating_add(run.length / bs);
            (run.physical_block, end, run.logical)
        })
        .collect();
    by_block.sort_unstable();
    let mut reach = 0;
    for (start, end, logical) in by_block {
        if start < reach {
            return Some(logical);
        }
        reach = reach.max(end);
    }
    None
}

/// Sort `runs`, each a first block and the block past its end, and merge the ones that touch
/// or overlap, so a cover is a search for one run.
fn merge_runs(runs: &mut Vec<(u64, u64)>) {
    runs.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(runs.len());
    for &(start, end) in runs.iter() {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    *runs = merged;
}

/// Where two counts of the same blocks disagree, from `events`: each a block where one or both
/// counts change, and by how much. Each disagreement is a first block, the block past its last,
/// and the two counts, maximal for that pair of counts.
fn disagreements(mut events: Vec<(u64, i64, i64)>) -> Vec<(u64, u64, i64, i64)> {
    events.sort_unstable_by_key(|event| event.0);
    let mut out: Vec<(u64, u64, i64, i64)> = Vec::new();
    let (mut first, mut second) = (0i64, 0i64);
    let mut i = 0;
    while i < events.len() {
        let at = events[i].0;
        while let Some(&(block, a, b)) = events.get(i)
            && block == at
        {
            first = first.saturating_add(a);
            second = second.saturating_add(b);
            i += 1;
        }
        let Some(&(next, _, _)) = events.get(i) else {
            break;
        };
        if first != second {
            match out.last_mut() {
                Some(last) if last.1 == at && last.2 == first && last.3 == second => last.1 = next,
                _ => out.push((at, next, first, second)),
            }
        }
    }
    out
}

/// Whether one of `runs`, merged by [`merge_runs`], holds every block from `start` to `end`.
fn covers(runs: &[(u64, u64)], start: u64, end: u64) -> bool {
    let at = runs.partition_point(|run| run.0 <= start);
    at > 0 && runs[at - 1].1 >= end
}

/// What a scan's pass over every record of the file-system tree gathers, and the rules it holds
/// each record to as it goes.
#[derive(Default)]
struct Held {
    /// Inode records by kind: regular files, directories, symbolic links, and every other kind.
    counts: [u64; 4],
    /// The largest object identifier a record's key or an inode's data stream carries.
    largest_id: u64,
    /// Each inode with a data stream: its number, the stream's identifier, and the stream.
    streams: Vec<(u64, u64, DataStream)>,
    /// Each attribute kept as a stream: the inode it belongs to, the stream's identifier, and
    /// the stream.
    attribute_streams: Vec<(u64, u64, DataStream)>,
    /// Every stream the volume keeps a reference record for, with its count.
    referenced: BTreeMap<u64, u32>,
    /// How far each stream's extents cover it from its first byte.
    coverage: BTreeMap<u64, Coverage>,
    /// The stream whose extents are being met, and how far they cover it so far.
    open: Option<(u64, Coverage)>,
    /// Every extent at a nonzero block.
    placed: Vec<Placed>,
    /// Every inode whose internal flags say it has been cloned at least once.
    ever_cloned: BTreeSet<u64>,
    /// Each inode with its internal flags.
    internal_flags: Vec<(u64, u64)>,
    /// Every inode holding a resource fork.
    forks: BTreeSet<u64>,
    /// Each directory's inode, with the child count it records.
    directories: Vec<(u64, i32)>,
    /// Every inode the tree holds a record of, in the order the tree holds them.
    inodes: Vec<u64>,
    /// Each directory entry, as the directory holding it and the inode it names.
    named: Vec<(u64, u64)>,
    /// How many entries each directory holds, by its inode.
    entries: BTreeMap<u64, u64>,
    /// The entries met under the directory and the hash of the last entry met.
    hash_group: HashGroup,
}

/// The entries of one directory under one hash, as a scan meets them: each name as the volume
/// compares names, and as stored. A tree holds one directory's entries in hash order, so the
/// entries under one hash are met together.
#[derive(Default)]
struct HashGroup {
    dir: u64,
    hash: u32,
    met: Vec<(Vec<u32>, Vec<u8>)>,
}

/// How far a stream's extents cover it from its first byte, each beginning where the one
/// before it ends, and where they first fail to.
#[derive(Clone, Copy, Default)]
struct Coverage {
    /// Where the last extent that kept to the rule ends.
    end: u64,
    /// Where the extents first leave a gap or overlap, and which.
    fault: Option<(u64, &'static str)>,
}

/// An extent at a nonzero block: its stream, its offset in the stream, its first block and how
/// many blocks it takes.
struct Placed {
    stream: u64,
    logical: u64,
    block: u64,
    blocks: u64,
}

/// The extended-field types an inode is known to carry: the sixteen the reference defines
/// (pp. 109-112), and 17, which macOS 15, 26 and 27 write on a volume formatted with the
/// conformance option.
const INODE_FIELD_TYPES: std::ops::RangeInclusive<u8> = 1..=17;

/// The most UTF-16 units macOS makes a name of.
const MAX_NAME_UNITS: usize = 255;

/// The extended-field types a directory entry is known to carry (reference p. 109).
const ENTRY_FIELD_TYPES: std::ops::RangeInclusive<u8> = 1..=1;

/// The inode extended-field types this reader reads whose size the format fixes: a data stream
/// (`j_dstream_t`, reference p. 106, as the field of type 8 holds it, p. 111) and a device
/// number (`uint32_t`, p. 112).
const INODE_FIELD_SIZES: [(u8, usize); 2] = [
    (inode_field::DATA_STREAM, DataStream::SIZE),
    (inode_field::DEVICE, 4),
];

/// The directory-entry extended-field type whose size the format fixes: a hard link's sibling
/// identifier (`uint64_t`, reference p. 110).
const ENTRY_FIELD_SIZES: [(u8, usize); 1] = [(SIBLING_ID_FIELD, 8)];

/// The first rule of the format's that `fields` breaks, as how serious it is and a sentence: a
/// type met twice, where each type is held once (reference p. 109), so one field has two
/// values, or a field of a type `sizes` gives a size for, holding another.
fn field_rules(fields: &[ExtendedField<'_>], sizes: &[(u8, usize)]) -> Option<(Severity, String)> {
    let mut seen = [false; 256];
    for f in fields {
        if std::mem::replace(&mut seen[usize::from(f.kind)], true) {
            return Some((
                Severity::Integrity,
                format!(
                    "the extended field of type {} is met twice, and the format holds each type \
                     once",
                    f.kind
                ),
            ));
        }
        if let Some(&(_, want)) = sizes.iter().find(|(kind, _)| *kind == f.kind)
            && f.data.len() != want
        {
            return Some((
                Severity::Structural,
                format!(
                    "the extended field of type {} holds {} bytes, and its type takes {want}",
                    f.kind,
                    f.data.len()
                ),
            ));
        }
    }
    None
}

/// What is wrong with a directory entry stored under `hash`, given its name's form as the
/// volume compares names (`None` where the name is not UTF-8), as how serious it is and what
/// the entry does: a name with no hash, since it is not UTF-8, or a hash that is not its name's.
/// The hash steers macOS's lookup by name, so it does not find such an entry: `fsck_apfs`
/// repairs a hash off by one bit, and until then the file is not there under macOS (observed,
/// macOS 15, 26 and 27).
fn name_fault(hash: u32, form: Option<&[u32]>) -> Option<(Severity, String)> {
    match form {
        None => Some((
            Severity::Conformance,
            "has a name that is not UTF-8, and so no hash".to_string(),
        )),
        Some(form) if names::hash(form) != hash => Some((
            Severity::Integrity,
            format!(
                "is stored under hash {hash:#08x} and its name hashes to {:#08x}, so macOS does \
                 not find it by name",
                names::hash(form)
            ),
        )),
        Some(_) => None,
    }
}

/// The first rule an inode of `mode` breaks in its `fields`: one of [`field_rules`], or a device
/// node without the field recording its number, which every device node macOS 14 to 27 wrote
/// carries, a zero number included.
fn inode_field_rules(mode: u16, fields: &[ExtendedField<'_>]) -> Option<(Severity, String)> {
    field_rules(fields, &INODE_FIELD_SIZES).or_else(|| {
        (matches!(mode & MODE_TYPE, MODE_CHR | MODE_BLK)
            && field(fields, inode_field::DEVICE).is_none())
        .then(|| {
            (
                Severity::Structural,
                "a device node without the extended field recording its device number".to_string(),
            )
        })
    })
}

impl Held {
    /// Take one record of the tree: count it, hold it to its kind's rules, and keep what the
    /// rules over the whole volume need.
    fn gather(
        &mut self,
        scan: &mut Scan,
        key: &[u8],
        value: &[u8],
        fold: bool,
    ) -> Result<(), ReadError> {
        let header = KeyHeader::read_from(key)?;
        scan.met(header.kind);
        let id = header.id;
        self.largest_id = self.largest_id.max(id);
        // Extended-field types outside the known set, noted once the record is done.
        let mut kinds = Vec::new();
        let mut fault = |severity: Severity, detail: String| {
            scan.at(Category::Record, severity, None, Some(id), detail);
        };
        // Every inode the tree holds a record of, whether or not the record parses: an entry
        // naming one names an inode the volume has.
        if header.kind == record_kind::INODE {
            self.inodes.push(id);
        }
        match header.kind {
            record_kind::INODE => match inode_stream(value) {
                Ok((inode, stream, fields)) => {
                    self.counts[count_slot(inode.mode)] += 1;
                    self.largest_id = self.largest_id.max(inode.private_id);
                    if let Some(stream) = stream {
                        self.streams.push((id, inode.private_id, stream));
                    }
                    if inode.internal_flags & INTERNAL_EVER_CLONED != 0 {
                        self.ever_cloned.insert(id);
                    }
                    self.internal_flags.push((id, inode.internal_flags));
                    if inode.create_time < 0 {
                        fault(
                            Severity::Conformance,
                            format!(
                                "the inode was created at {} nanoseconds since 1970, before it, \
                                 which macOS 15 and later refuse to read",
                                inode.create_time
                            ),
                        );
                    }
                    // A compressed file records the size of its content beside its flags, and a
                    // read takes the content through its compression header only where its BSD
                    // flags say it is compressed: an inode recording the size without that flag
                    // has its content read from a data stream that does not hold it. No inode in
                    // the images macOS 14 to 27 wrote records the one without the other.
                    if inode.internal_flags & INTERNAL_COMPRESSED != 0
                        && inode.bsd_flags & BSD_COMPRESSED == 0
                    {
                        fault(
                            Severity::Integrity,
                            "the inode records the size of compressed content, and its BSD flags \
                             do not say it is compressed, so a read takes its content from its \
                             data stream"
                                .to_string(),
                        );
                    }
                    // A truncation a driver began and a crash cut short: the flag, or the field
                    // recording the size before it, which macOS finishes at its next mount
                    // (reference pp. 90, 111).
                    let prior = field(&fields, inode_field::PREV_FSIZE).is_some();
                    if inode.internal_flags & INTERNAL_BEING_TRUNCATED != 0 || prior {
                        fault(
                            Severity::Cosmetic,
                            "the inode records a truncation the last driver began and did not \
                             finish, which macOS finishes at its next mount"
                                .to_string(),
                        );
                    }
                    if inode.mode & MODE_TYPE == MODE_DIR {
                        self.directories.push((id, inode.links_or_children));
                    }
                    let blob = &value[InodeValue::SIZE..];
                    for (severity, problem) in field_faults(
                        blob,
                        &fields,
                        INODE_FIELD_TYPES,
                        |f| inode_field_rules(inode.mode, f),
                        &mut kinds,
                    ) {
                        fault(severity, format!("the inode record: {problem}"));
                    }
                    let name = field(&fields, inode_field::NAME);
                    if let Some(name) = name
                        && name.split_last().is_none_or(|(last, name)| {
                            *last != 0 || std::str::from_utf8(name).is_err()
                        })
                    {
                        fault(
                            Severity::Conformance,
                            format!(
                                "the inode's name field, {}, is not a UTF-8 name and its \
                                 terminator",
                                crate::escape::printable(name)
                            ),
                        );
                    }
                }
                Err(e) => fault(Severity::Structural, format!("the inode record: {e}")),
            },
            record_kind::XATTR => {
                // What a read of the attribute refuses, wherever the record is: its name, its
                // value's framing, flags saying both or neither of embedded and stream, and a
                // stream too short for its identifier and size.
                if xattr_name(key).is_ok_and(|name| name == RESOURCE_FORK_XATTR) {
                    self.forks.insert(id);
                }
                let stream = attribute_name(key)
                    .and_then(|_| XattrValue::read_from(value).map_err(|e| e.to_string()))
                    .and_then(|xattr| {
                        if in_stream(xattr.flags)? {
                            xattr.stream().map(Some).map_err(|e| e.to_string())
                        } else {
                            Ok(None)
                        }
                    });
                match stream {
                    Ok(Some((stream, ds))) => self.attribute_streams.push((id, stream, ds)),
                    Ok(None) => {}
                    Err(e) => fault(Severity::Structural, format!("an attribute record: {e}")),
                }
                // `fsck_apfs -W` fails a volume holding an attribute name that is not UTF-8
                // (observed, macOS 15, 26 and 27).
                if let Ok(name) = attribute_name(key)
                    && std::str::from_utf8(name).is_err()
                {
                    fault(
                        Severity::Conformance,
                        format!(
                            "the attribute name {} is not UTF-8, which fsck_apfs warns of",
                            crate::escape::printable(name)
                        ),
                    );
                }
            }
            record_kind::SIBLING_LINK => {
                if let Err(e) = SiblingLink::read_from(key, value) {
                    fault(Severity::Structural, format!("a sibling-link record: {e}"));
                }
            }
            record_kind::DATA_STREAM_ID => {
                let count = value.get(..4).map_or(0, |v| get_u32(v, 0));
                self.referenced.insert(id, count);
            }
            record_kind::FILE_EXTENT => match btree::extent(key, value) {
                Ok(extent) => self.extent(id, &extent, u64::from(scan.block_size())),
                Err(e) => fault(Severity::Structural, format!("a file extent record: {e}")),
            },
            record_kind::DIR_ENTRY => {
                *self.entries.entry(id).or_default() += 1;
                self.entry(scan, id, key, value, fold, &mut kinds);
            }
            _ => {}
        }
        for kind in kinds {
            scan.field(kind);
        }
        Ok(())
    }

    /// Hold one directory entry of directory `parent` to its name, its hash, and its fields,
    /// and to the entries before it under the same hash, wherever it is: an entry no walk
    /// reaches is held to them as well.
    fn entry(
        &mut self,
        scan: &mut Scan,
        parent: u64,
        key: &[u8],
        value: &[u8],
        fold: bool,
        kinds: &mut Vec<u8>,
    ) {
        let mut fault = |severity: Severity, inode: u64, detail: String| {
            scan.at(Category::Record, severity, None, Some(inode), detail);
        };
        let key = match EntryKey::read_from(key) {
            Ok(key) => key,
            Err(e) => {
                fault(
                    Severity::Structural,
                    parent,
                    format!("a directory entry record: {e}"),
                );
                return;
            }
        };
        let file_id = match EntryValue::read_from(value) {
            Ok(entry) => entry.file_id,
            Err(e) => {
                fault(
                    Severity::Structural,
                    parent,
                    format!("a directory entry record: {e}"),
                );
                return;
            }
        };
        let name = crate::escape::printable(key.name);
        self.named.push((parent, file_id));
        // What a read of the entry refuses, wherever it is: a name no directory can hold, and
        // extended fields that do not frame.
        if crate::path::is_hostile_component(key.name) {
            fault(
                Severity::Structural,
                file_id,
                format!(
                    "the entry {name} of directory {parent} is not a name a directory can hold"
                ),
            );
        }
        let blob = &value[EntryValue::SIZE..];
        let fields = extended_fields(blob)
            .inspect_err(|e| {
                fault(
                    Severity::Structural,
                    file_id,
                    format!("the entry {name} of directory {parent}: {e}"),
                );
            })
            .ok();
        // macOS refuses a name of more than 255 UTF-16 units, the 765 bytes of UTF-8 that many
        // three-byte characters take included (observed, macOS 15, 26 and 27).
        if let Ok(text) = std::str::from_utf8(key.name)
            && text.encode_utf16().count() > MAX_NAME_UNITS
        {
            fault(
                Severity::Conformance,
                file_id,
                format!(
                    "the entry {name} of directory {parent} is {} UTF-16 units long, and macOS \
                     makes no name longer than {MAX_NAME_UNITS}",
                    text.encode_utf16().count()
                ),
            );
        }
        let form = names::key(key.name, fold);
        if let Some(form) = &form {
            // Two stored names the volume compares as one are one name: a lookup by either
            // finds whichever it meets first, and the other is a file no name reaches.
            let group = &mut self.hash_group;
            if (group.dir, group.hash) != (parent, key.hash) {
                (group.dir, group.hash) = (parent, key.hash);
                group.met.clear();
            }
            if let Some((_, other)) = group.met.iter().find(|(seen, _)| seen == form) {
                fault(
                    Severity::Integrity,
                    file_id,
                    format!(
                        "the entries {} and {name} of directory {parent} are one name to the \
                         volume, so a lookup by that name finds only one of them",
                        crate::escape::printable(other)
                    ),
                );
            }
            group.met.push((form.clone(), key.name.to_vec()));
        }
        if let Some((severity, problem)) = name_fault(key.hash, form.as_deref()) {
            fault(
                severity,
                file_id,
                format!("the entry {name} of directory {parent} {problem}"),
            );
        }
        let rules = |f: &[ExtendedField<'_>]| field_rules(f, &ENTRY_FIELD_SIZES);
        // Fields that do not frame are refused above, and not graded here.
        let Some(fields) = fields else {
            return;
        };
        for (severity, problem) in field_faults(blob, &fields, ENTRY_FIELD_TYPES, rules, kinds) {
            fault(
                severity,
                file_id,
                format!("the entry {name} of directory {parent}: {problem}"),
            );
        }
    }

    /// Take one extent of stream `stream`, met in key order: after every earlier extent of the
    /// stream, and before every later one.
    fn extent(&mut self, stream: u64, extent: &FileExtent, block_size: u64) {
        if self.open.is_none_or(|(open, _)| open != stream) {
            self.close();
            self.open = Some((stream, Coverage::default()));
        }
        if let Some((_, coverage)) = &mut self.open
            && coverage.fault.is_none()
        {
            if extent.logical > coverage.end {
                coverage.fault = Some((coverage.end, "leave a gap"));
            } else if extent.logical < coverage.end {
                coverage.fault = Some((extent.logical, "overlap"));
            } else {
                coverage.end = extent.logical.saturating_add(extent.length);
            }
        }
        if extent.physical_block != 0 {
            self.placed.push(Placed {
                stream,
                logical: extent.logical,
                block: extent.physical_block,
                blocks: extent.length.div_ceil(block_size),
            });
        }
    }

    /// Keep the coverage of the stream whose extents were being met.
    fn close(&mut self) {
        if let Some((stream, coverage)) = self.open.take() {
            self.coverage.insert(stream, coverage);
        }
    }

    /// Hold every directory entry to naming an inode the volume holds, the ones no walk reaches
    /// included.
    fn check_entries(&mut self, scan: &mut Scan) {
        self.inodes.sort_unstable();
        for &(parent, file_id) in &self.named {
            if self.inodes.binary_search(&file_id).is_err() {
                scan.at(
                    Category::Record,
                    Severity::Structural,
                    None,
                    Some(file_id),
                    format!(
                        "an entry of directory {parent} names inode {file_id}, which the volume \
                         does not hold"
                    ),
                );
            }
        }
    }

    /// Hold every inode holding a resource fork to the internal flag that says so, in place of
    /// the one saying it holds none: what macOS 15, 26 and 27 write, and the only form their
    /// `fsck_apfs` passes or their kernel reads. macOS 14 adds a resource fork without changing
    /// either flag, so a volume it wrote may differ, and this is a difference of form.
    fn check_forks(&self, scan: &mut Scan) {
        for &(id, flags) in &self.internal_flags {
            if self.forks.contains(&id)
                && (flags & INTERNAL_WITH_RESOURCE_FORK == 0
                    || flags & INTERNAL_WITHOUT_RESOURCE_FORK != 0)
            {
                scan.at(
                    Category::Record,
                    Severity::Conformance,
                    None,
                    Some(id),
                    format!(
                        "the inode holds a resource fork and its internal flags {flags:#x} do not \
                         say so, which macOS 15 and later refuse to read"
                    ),
                );
            }
        }
    }

    /// Hold every directory's child count to the entries it holds, the ones no walk reaches
    /// included.
    fn check_directories(&self, scan: &mut Scan) {
        for (directory, children) in &self.directories {
            let held = self.entries.get(directory).copied().unwrap_or(0);
            if *children < 0 || u64::from(children.unsigned_abs()) != held {
                scan.at(
                    Category::Volume,
                    Severity::Conformance,
                    None,
                    Some(*directory),
                    format!("directory {directory} records {children} children and holds {held}"),
                );
            }
        }
    }

    /// Hold every stream to its records: its size to its allocation, its extents to both, and
    /// its reference record to the inodes naming it.
    fn check_streams(&self, scan: &mut Scan) {
        // Three rules every data stream macOS wrote keeps, sparse files included: its size is
        // no more than what is allocated to it, holes counted; a stream with an allocation has
        // a reference record; and the record counts the inodes whose content it is, which a
        // clone makes two. A stream an inode names by mistake is someone else's content.
        let mut users: BTreeMap<u64, u64> = BTreeMap::new();
        for (_, private_id, _) in &self.streams {
            *users.entry(*private_id).or_default() += 1;
        }
        for (stream, count) in &self.referenced {
            let used = users.get(stream).copied().unwrap_or(0);
            if u64::from(*count) != used {
                scan.at(
                    Category::Record,
                    Severity::Integrity,
                    None,
                    Some(*stream),
                    format!(
                        "data stream {stream} records {count} references and {used} inodes name \
                         it as their content"
                    ),
                );
            }
        }
        for (inode, private_id, stream) in &self.streams {
            if stream.allocated > 0 && !self.referenced.contains_key(private_id) {
                scan.at(
                    Category::Record,
                    Severity::Integrity,
                    None,
                    Some(*inode),
                    format!(
                        "the inode's data stream {private_id} has no reference record, so the \
                         extents it reads are not known to be its own"
                    ),
                );
            }
        }
        // A fourth, of attribute streams too: the stream's extents cover it from its first
        // byte to the end of its allocation, one after another, a hole included.
        let mut checked = std::collections::BTreeSet::new();
        for (inode, stream, ds) in self.streams.iter().chain(&self.attribute_streams) {
            if !checked.insert(*stream) {
                continue;
            }
            let mut fault = |severity: Severity, detail: String| {
                scan.at(Category::Record, severity, None, Some(*inode), detail);
            };
            if ds.size > ds.allocated {
                fault(
                    Severity::Conformance,
                    format!(
                        "stream {stream} is {} bytes and {} are allocated to it",
                        ds.size, ds.allocated
                    ),
                );
            }
            let coverage = self.coverage.get(stream).copied().unwrap_or_default();
            match coverage.fault {
                Some((at, what)) => fault(
                    Severity::Structural,
                    format!("the extents of stream {stream} {what} at byte {at}"),
                ),
                None if coverage.end != ds.allocated => fault(
                    Severity::Conformance,
                    format!(
                        "the extents of stream {stream} cover {} bytes and {} are allocated to it",
                        coverage.end, ds.allocated
                    ),
                ),
                None => {}
            }
        }
    }
}

/// What is wrong with `fields`, the extended fields `blob` frames as, each as how serious it is
/// and a sentence: the first rule `rules` finds them breaking, and the bytes the fields record
/// using against the bytes they take. The type of each field outside `types` is added to
/// `unknown`. A blob whose fields do not frame is refused by the read that parses it, and its
/// caller does not ask.
fn field_faults(
    blob: &[u8],
    fields: &[ExtendedField<'_>],
    types: std::ops::RangeInclusive<u8>,
    rules: impl Fn(&[ExtendedField<'_>]) -> Option<(Severity, String)>,
    unknown: &mut Vec<u8>,
) -> Vec<(Severity, String)> {
    let mut faults: Vec<(Severity, String)> = rules(fields).into_iter().collect();
    if blob.is_empty() {
        return faults;
    }
    unknown.extend(
        fields
            .iter()
            .map(|f| f.kind)
            .filter(|kind| !types.contains(kind)),
    );
    // The data the fields record using is each field's data rounded up to eight bytes, without
    // the descriptors, and the record ends where the last field's does: observed on every
    // record macOS wrote. The reference counts the descriptors in that total as well (p. 108);
    // what macOS writes is followed here.
    let used = usize::from(crate::bytes::get_u16(blob, 2));
    let take = fields
        .iter()
        .map(|f| f.data.len().next_multiple_of(8))
        .sum::<usize>();
    let after = blob.len() - 4 - 4 * fields.len();
    if used != take || after != take {
        faults.push((
            Severity::Conformance,
            format!(
                "the extended fields record using {used} bytes of data, take {take}, and the \
                 record holds {after}"
            ),
        ));
    }
    faults
}

/// One attribute record as it is stored: its name, its flags, and its record's data.
type XattrRecord = (Vec<u8>, u16, Vec<u8>);

/// A name a walk has reached and not yet visited: its path, the inode it names, the directory
/// that names it, and the entry's type.
type Unvisited = (Vec<u8>, (u64, u64, u8));

/// One name the namespace scan reaches: the path and node a walk yields, with the directory
/// naming it and the entry's type, which the root has none of.
struct Named {
    path: Vec<u8>,
    node: Node,
    entry: Option<(u64, u8)>,
}

/// The walk the namespace scan drives: the reader's own, keeping each entry's type and the
/// directory that names it, so each directory is listed and each name's inode read once.
struct Namespace<'a, R> {
    reader: &'a mut Reader<R>,
}

impl<R: Read + Seek> crate::walk::Walk for Namespace<'_, R> {
    type Pending = Unvisited;
    type Entry = Named;
    type Key = u64;
    type Error = ReadError;

    fn cap(&mut self) -> usize {
        crate::walk::Walk::cap(self.reader)
    }

    fn seed(&mut self) -> Result<crate::walk::Seed<Self>, ReadError> {
        crate::walk::Walk::seed(self.reader)
    }

    fn resolve(&mut self, (path, (inode, named_in, kind)): Unvisited) -> Result<Named, ReadError> {
        let entry = crate::walk::Walk::resolve(self.reader, (path, (inode, named_in, kind)))?;
        Ok(Named {
            path: entry.path,
            node: entry.node,
            entry: Some((named_in, kind)),
        })
    }

    fn descend_key(&self, entry: &Named) -> Option<u64> {
        entry.node.is_dir().then_some(entry.node.inode)
    }

    fn children(&mut self, entry: &Named) -> Result<Vec<Unvisited>, ReadError> {
        self.reader.pending_children(&entry.node, &entry.path)
    }

    fn repeated(&mut self, entry: &Named) -> Result<(), ReadError> {
        self.reader.hold_repeat(&entry.node)
    }

    fn too_large(limit: usize) -> ReadError {
        ReadError::WalkTooLarge { limit }
    }
}

/// An attribute record's name, held to what a host and an archive can carry: not empty, and no
/// NUL before its terminator, which a C string ends at and so renames the attribute. Every
/// writer refuses both, and a symbolic link's target is held to the same rule.
fn attribute_name(key: &[u8]) -> Result<&[u8], String> {
    let name = xattr_name(key).map_err(|e| e.to_string())?;
    if name.is_empty() {
        Err("an attribute with an empty name".to_string())
    } else if name.contains(&0) {
        Err("an attribute name holding a NUL before its terminator".to_string())
    } else {
        Ok(name)
    }
}

/// Why a read refuses a run of a stream no extent covers: every stream macOS wrote has its
/// extents cover it from its first byte to the end of its allocation, a hole included.
const UNCOVERED: &str = "a run of the stream no extent covers";

/// Why a read refuses a hole in an attribute's stream, which macOS writes to blocks whole.
const HOLE: &str = "a hole in an attribute's stream, which macOS writes to blocks";

/// Why a read refuses a stream two of whose extents use one block: clones share blocks between
/// streams, and no stream of any image macOS wrote holds one block twice.
const REUSED: &str = "an extent using a block another extent of its stream uses";

/// What a run of a stream that no block holds reads as.
#[derive(Clone, Copy)]
enum Holes {
    /// Zeros: a file's data stream, into which macOS writes a hole as an extent at block zero.
    Zeros,
    /// Nothing: an attribute's stream, which macOS writes to blocks whole, so a hole in one is
    /// refused.
    Refused,
}

/// The most stored bytes one resource-fork chunk may take. A chunk decodes to 64 KiB at most,
/// and an encoding of 64 KiB that does not compress costs a few hundred bytes more than its
/// content, so four times the content is a bound no real chunk approaches.
const MAX_CHUNK: u64 = 4 * decmpfs::CHUNK;

/// Where an attribute's value is: in its record, or a stream of its own. A compressed file's
/// resource fork is one.
enum Stored {
    /// The bytes are in the record.
    Embedded(Vec<u8>),
    /// The bytes are a stream, found by its identifier.
    Stream {
        /// The stream's identifier.
        id: u64,
        /// Its size and allocation.
        stream: DataStream,
    },
}

impl Stored {
    /// Where the value of inode `inode`'s attribute record holding `flags` and `data` is.
    fn of(inode: u64, flags: u16, data: &[u8]) -> Result<Self, ReadError> {
        let bad = |fault: String| ReadError::BadRecord {
            id: inode,
            kind: record_kind::XATTR,
            fault,
        };
        if !in_stream(flags).map_err(bad)? {
            return Ok(Stored::Embedded(data.to_vec()));
        }
        let (id, stream) = XattrValue { flags, data }
            .stream()
            .map_err(|e| bad(e.to_string()))?;
        Ok(Stored::Stream { id, stream })
    }

    /// The value's length in bytes.
    fn size(&self) -> u64 {
        match self {
            Stored::Embedded(bytes) => bytes.len() as u64,
            Stored::Stream { stream, .. } => stream.size,
        }
    }
}

/// Whether an attribute whose record holds `flags` keeps its value in a stream of its own rather
/// than in the record, or, where the flags say both or neither, a sentence saying so.
fn in_stream(flags: u16) -> Result<bool, String> {
    match (
        flags & xattr_flags::EMBEDDED != 0,
        flags & xattr_flags::STREAM != 0,
    ) {
        (true, false) => Ok(false),
        (false, true) => Ok(true),
        (true, true) => Err(format!(
            "an attribute whose flags {flags:#x} say both embedded and stream"
        )),
        (false, false) => Err(format!(
            "an attribute whose flags {flags:#x} say neither embedded nor stream"
        )),
    }
}

/// Where a compressed file's chunks are, and the table that finds them.
struct ChunkTable {
    /// The attribute the chunks are in: the compression attribute or the resource fork.
    source: Stored,
    layout: Layout,
    /// How many chunks the content is cut into.
    chunks: u64,
    /// Where a resource's chunk entries begin, and what its chunk offsets count from.
    entries_at: u64,
    base: u64,
    /// The first byte a chunk may begin at, past the table, and the byte none may reach past.
    floor: u64,
    ceiling: u64,
}

/// Which volume of `volumes` a selection names; with none, the one in the first occupied slot.
/// A slot of `unreadable` it names is refused with why its superblock could not be read.
fn select<'v>(
    volumes: &'v [VolumeEntry],
    unreadable: &[UnreadableVolume],
    selector: Option<&VolumeSelector>,
) -> Result<&'v VolumeEntry, ReadError> {
    let slot = match selector {
        None => volumes
            .first()
            .map(|v| v.slot)
            .into_iter()
            .chain(unreadable.first().map(|u| u.slot))
            .min(),
        Some(VolumeSelector::Slot(slot)) => Some(*slot),
        Some(_) => None,
    };
    if let Some(damaged) = unreadable.iter().find(|u| Some(u.slot) == slot) {
        return Err(damaged.error.clone());
    }
    let found = match selector {
        None => volumes.first(),
        Some(VolumeSelector::Slot(slot)) => volumes.iter().find(|v| v.slot == *slot),
        Some(VolumeSelector::Name(name)) => {
            let named: Vec<&VolumeEntry> = volumes
                .iter()
                .filter(|v| v.name() == name.as_slice())
                .collect();
            if named.len() > 1 {
                return Err(ReadError::AmbiguousVolume {
                    name: name.clone(),
                    slots: named.iter().map(|v| v.slot).collect(),
                });
            }
            named.first().copied()
        }
        Some(VolumeSelector::Uuid(uuid)) => volumes.iter().find(|v| v.superblock.uuid == *uuid),
    };
    found.ok_or_else(|| ReadError::NoSuchVolume {
        selector: selector.map_or_else(|| "at all".to_string(), ToString::to_string),
    })
}

/// A target equal to the key of object `id`'s record of `kind`, which has no third part.
fn exact(id: u64, kind: u8) -> impl Fn(&[u8]) -> Result<std::cmp::Ordering, ParseError> {
    move |key: &[u8]| {
        let header = KeyHeader::read_from(key)?;
        Ok((header.id, header.kind).cmp(&(id, kind)))
    }
}

/// A directory entry recovered from its record, on a volume whose names fold case where `fold`
/// says, refused as a sentence saying why where it does not parse, or where its name, its hash
/// or its extended fields break a rule `policy` holds fatal; a read past those takes the first
/// field of each type, and a sibling identifier from its first eight bytes.
fn entry(key: &[u8], value: &[u8], policy: ReadPolicy, fold: bool) -> Result<Entry, String> {
    let parsed = |e: ParseError| e.to_string();
    let entry_key = EntryKey::read_from(key).map_err(parsed)?;
    let entry_value = EntryValue::read_from(value).map_err(parsed)?;
    // A name's form is a normalization of it, so it is taken only where the policy refuses what
    // the hash is found to be.
    if policy.is_fatal(Severity::Conformance)
        && let Some((severity, problem)) =
            name_fault(entry_key.hash, names::key(entry_key.name, fold).as_deref())
        && policy.is_fatal(severity)
    {
        let name = crate::escape::printable(entry_key.name);
        return Err(format!("the entry {name} {problem}"));
    }
    let fields = extended_fields(&value[EntryValue::SIZE..]).map_err(parsed)?;
    if let Some((severity, fault)) = field_rules(&fields, &ENTRY_FIELD_SIZES)
        && policy.is_fatal(severity)
    {
        return Err(fault);
    }
    let sibling_id = field(&fields, SIBLING_ID_FIELD)
        .and_then(|data| data.get(..8))
        .map(|data| crate::bytes::get_u64(data, 0));
    Ok(Entry {
        name: entry_key.name.to_vec(),
        file_id: entry_value.file_id,
        entry_type: entry_value.entry_type(),
        date_added: timestamp(entry_value.date_added),
        hash: entry_key.hash,
        sibling_id,
    })
}

/// Nanoseconds since 1970 as a [`Timestamp`]; a time before 1970 is negative.
fn timestamp(nanos: i64) -> Timestamp {
    Timestamp {
        secs: nanos.div_euclid(1_000_000_000),
        nanos: nanos.rem_euclid(1_000_000_000) as u32,
    }
}

/// An inode record's fixed part, its data stream where it has one, and its extended fields.
fn inode_stream(
    value: &[u8],
) -> Result<(InodeValue, Option<DataStream>, Vec<ExtendedField<'_>>), ParseError> {
    let inode = InodeValue::read_from(value)?;
    let fields = extended_fields(&value[InodeValue::SIZE..])?;
    let stream = field(&fields, inode_field::DATA_STREAM)
        .map(DataStream::read_from)
        .transpose()?;
    Ok((inode, stream, fields))
}

/// Which of the volume superblock's four counts an inode of `mode` is counted in.
const fn count_slot(mode: u16) -> usize {
    match mode & MODE_TYPE {
        MODE_REG => 0,
        MODE_DIR => 1,
        MODE_LNK => 2,
        _ => 3,
    }
}

/// The bytes one window of a streamed read takes.
const STREAM_BUFFER: usize = 1 << 20;

/// The chunk-table entries a scan reads at once.
const TABLE_WINDOW: u64 = 4096;

/// The `S_IFMT` mask of a mode.
const MODE_TYPE: u16 = 0o170_000;
/// The `S_IFMT` value of a directory.
const MODE_DIR: u16 = 0o040_000;
/// The `S_IFMT` value of a regular file.
const MODE_REG: u16 = 0o100_000;
/// The `S_IFMT` value of a symbolic link.
const MODE_LNK: u16 = 0o120_000;
/// The `S_IFMT` value of a character-special device node.
const MODE_CHR: u16 = 0o020_000;
/// The `S_IFMT` value of a block-special device node.
const MODE_BLK: u16 = 0o060_000;
/// The `S_IFMT` value of a named pipe.
const MODE_FIFO: u16 = 0o010_000;
/// The `S_IFMT` value of a Unix-domain socket node.
const MODE_SOCK: u16 = 0o140_000;

/// What this family supplies to the crate's shared path resolution: a name found in a
/// directory, and the inode number to come back to.
impl<R: Read + Seek> crate::resolve::Resolve for Reader<R> {
    type Ancestor = u64;
    type Node = Node;
    type Error = ReadError;

    fn root_node(&mut self) -> Result<Node, ReadError> {
        self.root()
    }

    fn ancestor_of(&self, node: &Node) -> u64 {
        node.inode
    }

    fn node_at(&mut self, inode: u64) -> Result<Node, ReadError> {
        self.inode(inode)
    }

    fn is_directory(&self, node: &Node) -> bool {
        node.is_dir()
    }

    fn find_name(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Node>, ReadError> {
        let Some(entry) = self.find_entry(dir, name)? else {
            return Ok(None);
        };
        let node = self.inode(entry.file_id)?;
        self.hold_parent(&node, dir.inode)?;
        Ok(Some(node))
    }

    fn read_link(&mut self, node: &Node, path: &[u8]) -> Result<Option<Vec<u8>>, ReadError> {
        if !node.is_symlink() {
            return Ok(None);
        }
        // A target longer than a path can be names nothing, as on every family, and is refused
        // by the size its record gives it before it is read.
        if node.link_size.is_some_and(|size| size > MAX_PATH as u64) {
            return Err(self.not_found(path));
        }
        Ok(Some(self.link_target(node)?))
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

    fn too_many_links(&self, path: &[u8]) -> ReadError {
        ReadError::SymlinkLoop {
            path: path.to_vec(),
        }
    }
}

/// What this family supplies to the crate's shared depth-first walk: a path and the inode its
/// entry names, the inode number that identifies a directory, and how a directory's names are
/// read.
impl<R: Read + Seek> crate::walk::Walk for Reader<R> {
    type Pending = Unvisited;
    type Entry = WalkEntry;
    type Key = u64;
    type Error = ReadError;

    fn cap(&mut self) -> usize {
        self.limits().max_walk_entries
    }

    fn seed(&mut self) -> Result<crate::walk::Seed<Self>, ReadError> {
        let root = self.root()?;
        let children = self.pending_children(&root, b"")?;
        Ok((children, vec![root.inode]))
    }

    fn resolve(
        &mut self,
        (path, (inode, named_in, _)): Self::Pending,
    ) -> Result<WalkEntry, ReadError> {
        let node = self.inode(inode)?;
        self.hold_parent(&node, named_in)?;
        Ok(WalkEntry { path, node })
    }

    fn descend_key(&self, entry: &WalkEntry) -> Option<u64> {
        entry.node.is_dir().then_some(entry.node.inode)
    }

    fn children(&mut self, entry: &WalkEntry) -> Result<Vec<Self::Pending>, ReadError> {
        self.pending_children(&entry.node, &entry.path)
    }

    fn repeated(&mut self, entry: &WalkEntry) -> Result<(), ReadError> {
        self.hold_repeat(&entry.node)
    }

    fn too_large(limit: usize) -> ReadError {
        ReadError::WalkTooLarge { limit }
    }
}

/// Everything a walk through the shared surface can fail on, kept apart until it ends.
type WalkFail<E> = crate::tree::WalkFail<ReadError, E>;

impl<E> From<ReadError> for WalkFail<E> {
    fn from(err: ReadError) -> Self {
        WalkFail::Read(err)
    }
}

impl From<ReadError> for TreeError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::Io { kind, message } => TreeError::Io { kind, message },
            ReadError::FileTooLarge { .. }
            | ReadError::AttributeTooLarge { .. }
            | ReadError::TooManyEntries { .. }
            | ReadError::WalkTooLarge { .. } => TreeError::LimitExceeded {
                family: Family::Apfs,
                detail: err.to_string(),
            },
            // A volume that is entirely well-formed and beyond this build. Each names what it
            // would take to read it, which is what the shared frame calls unsupported rather
            // than malformed.
            ReadError::UnsupportedFeatures { .. }
            | ReadError::UnsupportedCheckpoint
            | ReadError::Encrypted { .. }
            | ReadError::EncryptionChanging { .. }
            | ReadError::RevertPending { .. }
            | ReadError::UnhashedNames { .. }
            | ReadError::UnsupportedCompression { .. } => TreeError::Unsupported {
                family: Family::Apfs,
                detail: err.to_string(),
            },
            other => TreeError::Malformed {
                family: Family::Apfs,
                detail: other.to_string(),
            },
        }
    }
}

impl<R: Read + Seek> FsTree for Reader<R> {
    type Node = Node;

    fn family(&self) -> Family {
        Family::Apfs
    }

    fn max_file_bytes(&self) -> u64 {
        self.limits().max_file_bytes
    }

    fn walk_tree<E, F>(&mut self, mut visit: F) -> Result<(), E>
    where
        E: From<TreeError>,
        F: FnMut(&mut Self, TreeEntry<Node>) -> Result<(), E>,
    {
        // Which nodes two names are both for, assigned as the walk meets them, by inode number.
        let mut shared: BTreeMap<u64, u64> = BTreeMap::new();
        let outcome = self.walk_with::<WalkFail<E>, _>(|reader, entry| {
            let node = entry.node;
            let kind = node_kind(&node).map_err(WalkFail::Tree)?;
            let inode = node.inode;
            let links = node.links();
            let mut out = TreeEntry::new(entry.path, kind, node);
            // A directory's record holds its child count where another inode holds its link
            // count, so only a node that is not a directory and has more than one name carries
            // an identity.
            if !matches!(kind, NodeKind::Directory) && links > 1 {
                let next = shared.len() as u64;
                out = out.shared(*shared.entry(inode).or_insert(next));
            }
            visit(reader, out).map_err(WalkFail::Visitor)
        });
        match outcome {
            Ok(()) => Ok(()),
            Err(WalkFail::Read(e)) => Err(E::from(TreeError::from(e))),
            Err(WalkFail::Tree(e)) => Err(E::from(e)),
            Err(WalkFail::Visitor(e)) => Err(e),
        }
    }

    fn stat(&mut self, node: &Node, _synthesis: &Synthesis) -> Result<Attributes, TreeError> {
        // Nothing is synthesized: APFS records an owner, a group, a mode, and four times of
        // nanosecond resolution, every property the shared frame carries.
        Ok(Attributes::read(node.metadata(), self.xattrs(node)?))
    }

    fn read_bytes(&mut self, node: &Node, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError> {
        Ok(Reader::read_into(self, node, offset, buf)?)
    }

    fn link_target(&mut self, node: &Node) -> Result<Vec<u8>, TreeError> {
        Ok(Reader::link_target(self, node)?)
    }

    fn darwin(&mut self, node: &Node) -> Result<Option<Darwin>, TreeError> {
        Ok(Reader::darwin(self, node)?)
    }

    fn bsd_flags(&mut self, node: &Node) -> Result<u32, TreeError> {
        Ok(node.value.bsd_flags)
    }
}

/// What kind of node the shared frame calls `node`.
fn node_kind(node: &Node) -> Result<NodeKind, TreeError> {
    let device = || split_device(node.device.unwrap_or(0));
    Ok(match node.file_type() {
        MODE_DIR => NodeKind::Directory,
        // A compressed file whose header could not be read has no size to give.
        MODE_REG => match &node.compression {
            Some(Err(e)) => return Err(TreeError::from(e.clone())),
            _ => NodeKind::File { size: node.size() },
        },
        MODE_LNK => NodeKind::Symlink,
        MODE_CHR => {
            let (major, minor) = device();
            NodeKind::CharDevice { major, minor }
        }
        MODE_BLK => {
            let (major, minor) = device();
            NodeKind::BlockDevice { major, minor }
        }
        MODE_FIFO => NodeKind::Fifo,
        MODE_SOCK => NodeKind::Socket,
        other => {
            return Err(TreeError::Malformed {
                family: Family::Apfs,
                detail: format!(
                    "inode {} records file type {other:#o}, which names no file type",
                    node.inode
                ),
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::forge::{
        self, BLOCK, DATA_AT, DESC_BASE, FS_ROOT_AT, Forge, Reference, VOLUME_AT, XID, pattern,
        sealed,
    };
    use crate::apfs::ondisk::{
        ContainerSuperblock, NodeFault, ObjectHeader, TREE_EPHEMERAL, TREE_HASHED, TREE_INFO_SIZE,
        TREE_NO_HEADER, container_incompat, node_flags,
    };
    use crate::bytes::{get_u16, get_u64, put_u16, put_u32, put_u64};
    use std::io::Cursor;

    /// A reader of the forged container's volume.
    fn open(forge: &Forge) -> Reader<Cursor<Vec<u8>>> {
        Reader::open(forge.cursor()).expect("a forged container opens")
    }

    /// Rewrite the checksum of the object at block `at`, after a gate changed it.
    fn reseal(image: &mut [u8], at: u64) {
        let range = at as usize * BLOCK..(at as usize + 1) * BLOCK;
        let block = sealed(image[range.clone()].to_vec());
        image[range].copy_from_slice(&block);
    }

    fn paths(reader: &mut Reader<Cursor<Vec<u8>>>) -> Vec<Vec<u8>> {
        let mut paths: Vec<Vec<u8>> = reader
            .walk()
            .expect("walks")
            .into_iter()
            .map(|e| e.path)
            .collect();
        paths.sort();
        paths
    }

    const EVERY_PATH: [&[u8]; 10] = [
        b"",
        b"/cdev",
        b"/dir",
        b"/dir/hard2",
        b"/dir/nested",
        b"/fifo",
        b"/hard1",
        b"/hello",
        b"/link",
        b"/sparse",
    ];

    #[test]
    fn a_time_before_1970_is_a_negative_second_and_a_positive_fraction() {
        assert_eq!(
            timestamp(-1),
            Timestamp {
                secs: -1,
                nanos: 999_999_999
            }
        );
        assert_eq!(
            timestamp(1_500_000_000),
            Timestamp {
                secs: 1,
                nanos: 500_000_000
            }
        );
    }

    #[test]
    fn a_walk_reaches_every_name_and_the_private_directory_is_not_one() {
        let mut reader = open(&Forge::populated());
        assert_eq!(paths(&mut reader), EVERY_PATH.map(<[u8]>::to_vec));
        assert_eq!(reader.volume().name(), b"Forged");
    }

    #[test]
    fn a_tree_split_across_leaves_reads_the_same_as_one_leaf() {
        let mut forge = Forge::populated();
        forge.per_leaf = Some(3);
        let mut reader = open(&forge);
        assert_eq!(paths(&mut reader), EVERY_PATH.map(<[u8]>::to_vec));
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(reader.read_data(&hello).expect("read"), pattern(5000, 1));
    }

    #[test]
    fn a_file_reads_whole_and_by_window_across_its_blocks() {
        let mut reader = open(&Forge::populated());
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(hello.size(), 5000);
        assert_eq!(reader.read_data(&hello).expect("read"), pattern(5000, 1));
        let mut window = [0u8; 20];
        assert_eq!(
            reader.read_into(&hello, 4090, &mut window).expect("read"),
            20
        );
        assert_eq!(&window[..], &pattern(5000, 1)[4090..4110]);
        // Past the end, nothing; up to it, only what is there.
        assert_eq!(
            reader.read_into(&hello, 5000, &mut window).expect("read"),
            0
        );
        assert_eq!(
            reader.read_into(&hello, 4995, &mut window).expect("read"),
            5
        );
    }

    #[test]
    fn a_hole_is_an_extent_at_block_zero_and_reads_as_zeros() {
        let mut reader = open(&Forge::populated());
        let sparse = reader.lookup(b"/sparse").expect("found");
        let data = reader.read_data(&sparse).expect("read");
        assert_eq!(data.len(), 3 * BLOCK);
        assert!(data[..BLOCK].iter().all(|b| *b == 0));
        assert_eq!(&data[BLOCK..2 * BLOCK], &pattern(BLOCK, 4)[..]);
        assert!(data[2 * BLOCK..].iter().all(|b| *b == 0));
    }

    #[test]
    fn attributes_read_embedded_and_from_their_own_stream() {
        let mut reader = open(&Forge::populated());
        let hello = reader.lookup(b"/hello").expect("found");
        let xattrs = reader.xattrs(&hello).expect("read");
        assert_eq!(xattrs.len(), 2);
        let get = |name: &[u8]| {
            xattrs
                .iter()
                .find(|x| x.name == name)
                .map(|x| x.value.clone())
        };
        assert_eq!(get(b"user.small"), Some(b"tiny".to_vec()));
        assert_eq!(get(b"user.big"), Some(pattern(6000, 2)));
    }

    #[test]
    fn a_symbolic_link_is_its_target_and_its_target_attribute_is_not_listed() {
        let mut reader = open(&Forge::populated());
        let link = reader.lookup_no_follow(b"/link").expect("found");
        assert!(link.is_symlink());
        assert_eq!(reader.link_target(&link).expect("read"), b"hello");
        assert!(reader.xattrs(&link).expect("read").is_empty());
        let followed = reader.lookup(b"/link").expect("found");
        assert_eq!(followed.inode, 16);
    }

    #[test]
    fn a_link_target_holding_a_nul_before_its_terminator_is_refused_and_found() {
        let mut forge = Forge::populated();
        let target = forge::xattr(19, b"com.apple.fs.symlink", 0x6, b"ta\0get\0");
        let key = target.0.clone();
        *forge
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the link's target") = target;
        // A path holds no NUL, so this is no one target, under any policy.
        for mut reader in [open(&forge), lenient(forge.image())] {
            let link = reader.lookup_no_follow(b"/link").expect("found");
            let err = reader.link_target(&link).expect_err("refused");
            assert!(
                matches!(&err, ReadError::BadRecord { id: 19, fault, .. } if fault.contains("NUL")),
                "{err}"
            );
            assert!(reader.lookup(b"/link").is_err());
        }
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Structural, Some(19))]
        );
    }

    #[test]
    fn an_attribute_name_empty_or_holding_a_nul_is_refused_and_found() {
        // A C string ends at its first NUL, so a name holding one is another attribute's name
        // to a host and to an archive reader, and an empty name is none at all: each is refused
        // under any policy, as a link target holding a NUL is.
        for (name, fault) in [
            (&b"user.a\0b"[..], "NUL before its terminator"),
            (&b""[..], "an empty name"),
        ] {
            let mut forge = Forge::populated();
            forge.add(forge::xattr(16, name, xattr_flags::EMBEDDED, b"value"));
            forge.settle();
            for mut reader in [open(&forge), lenient(forge.image())] {
                let hello = reader.lookup(b"/hello").expect("found");
                let err = reader.xattrs(&hello).expect_err("refused");
                assert!(
                    matches!(&err, ReadError::BadRecord { id: 16, fault: f, .. } if f.contains(fault)),
                    "{err}"
                );
            }
            assert_eq!(
                scanned(&forge),
                [(Category::Record, Severity::Structural, Some(16))],
                "{name:?}"
            );
        }
    }

    #[test]
    fn an_attribute_macos_does_not_reach_or_check_passes_is_found() {
        // On the forge's character device, and named in bytes that are not UTF-8: each read as
        // it is, and reported, since macOS lists neither as written.
        let mut forge = Forge::populated();
        forge.add(forge::xattr(22, b"user.a", xattr_flags::EMBEDDED, b"value"));
        forge.settle();
        let mut reader = open(&forge);
        let cdev = reader.lookup(b"/cdev").expect("found");
        assert_eq!(reader.xattrs(&cdev).expect("read").len(), 1);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Conformance, Some(22))]
        );
        let mut forge = Forge::populated();
        forge.add(forge::xattr(
            16,
            b"user.\xff",
            xattr_flags::EMBEDDED,
            b"value",
        ));
        forge.settle();
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Conformance, Some(16))]
        );
    }

    #[cfg(feature = "tar")]
    #[test]
    fn an_archive_of_a_volume_holds_what_a_read_of_it_reads() {
        // The shared frame is this family's mapping of a node to a kind, attributes and bytes,
        // and an archive is written from nothing else. Read back by a tar reader this crate
        // did not write, every member is held to what the reader reads of its node.
        use std::io::Read as _;
        let forge = Forge::populated();
        let mut archive = Vec::new();
        crate::ArchiveSink::new(&mut archive)
            .write_tree(&mut open(&forge))
            .expect("the archive is written");
        // Each member read raw, its extended header's records split by the length each one
        // records, as POSIX frames them: a value is bytes, and an attribute's may hold a newline.
        type Member = (tar::Header, BTreeMap<String, Vec<u8>>, Vec<u8>);
        let mut members: BTreeMap<Vec<u8>, Member> = BTreeMap::new();
        let mut tar = tar::Archive::new(archive.as_slice());
        let mut pax = BTreeMap::new();
        for entry in tar
            .entries()
            .expect("the archive lists its members")
            .raw(true)
        {
            let mut entry = entry.expect("a member");
            let mut body = Vec::new();
            entry.read_to_end(&mut body).expect("the body");
            if entry.header().entry_type() == tar::EntryType::XHeader {
                let mut data = body.as_slice();
                while !data.is_empty() {
                    let space = data.iter().position(|b| *b == b' ').expect("a length");
                    let len: usize = std::str::from_utf8(&data[..space])
                        .ok()
                        .and_then(|text| text.parse().ok())
                        .expect("a length in decimal");
                    let record = &data[space + 1..len - 1];
                    let equals = record.iter().position(|b| *b == b'=').expect("a key");
                    let key = String::from_utf8(record[..equals].to_vec()).expect("a key in text");
                    pax.insert(key, record[equals + 1..].to_vec());
                    data = &data[len..];
                }
                continue;
            }
            let pax = std::mem::take(&mut pax);
            let mut path = pax["path"].clone();
            path.drain(..1);
            if path.len() > 1 && path.ends_with(b"/") {
                path.pop();
            }
            members.insert(path, (entry.header().clone(), pax, body));
        }
        let mut reader = open(&forge);
        let mut first: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for walked in reader.walk().expect("walks") {
            let node = walked.node;
            let path = if walked.path.is_empty() {
                b"/".to_vec()
            } else {
                walked.path.clone()
            };
            let shown = String::from_utf8_lossy(&path).into_owned();
            let (header, pax, body) = members.remove(&path).expect(&shown);
            assert_eq!(
                header.mode().expect("a mode"),
                u32::from(node.value.mode & 0o7777)
            );
            assert_eq!(header.uid().expect("an owner"), u64::from(node.value.owner));
            assert_eq!(header.gid().expect("a group"), u64::from(node.value.group));
            let mtime = node.modify_time();
            assert_eq!(
                pax["mtime"],
                format!("{}.{:09}", mtime.secs, mtime.nanos).into_bytes(),
                "{shown}"
            );
            let attributes = reader.xattrs(&node).expect("attributes");
            let carried = pax
                .keys()
                .filter(|k| k.starts_with("SCHILY.xattr."))
                .count();
            assert_eq!(carried, attributes.len(), "{shown}");
            for xattr in &attributes {
                let key = format!("SCHILY.xattr.{}", String::from_utf8_lossy(&xattr.name));
                assert_eq!(pax.get(&key), Some(&xattr.value), "{shown}: {key}");
            }
            let kind = header.entry_type();
            match node.file_type() {
                MODE_DIR => assert_eq!(kind, tar::EntryType::Directory, "{shown}"),
                MODE_REG => match first.get(&node.inode) {
                    // A second name is a link to the member the first one wrote.
                    Some(earlier) => {
                        assert_eq!(kind, tar::EntryType::Link, "{shown}");
                        assert_eq!(pax["linkpath"], [b".", &earlier[..]].concat(), "{shown}");
                    }
                    None => {
                        assert_eq!(kind, tar::EntryType::Regular, "{shown}");
                        assert_eq!(body, reader.read_data(&node).expect("read"), "{shown}");
                        if node.links() > 1 {
                            first.insert(node.inode, path.clone());
                        }
                    }
                },
                MODE_LNK => {
                    assert_eq!(kind, tar::EntryType::Symlink, "{shown}");
                    let target = reader.link_target(&node).expect("a target");
                    assert_eq!(pax["linkpath"], target, "{shown}");
                }
                MODE_CHR => {
                    assert_eq!(kind, tar::EntryType::Char, "{shown}");
                    let (major, minor) = split_device(node.device.expect("a number"));
                    assert_eq!(header.device_major().expect("a major"), Some(major));
                    assert_eq!(header.device_minor().expect("a minor"), Some(minor));
                }
                MODE_FIFO => assert_eq!(kind, tar::EntryType::Fifo, "{shown}"),
                other => panic!("{shown}: a node of type {other:#o} the forge does not make"),
            }
        }
        assert!(members.is_empty(), "members no name reads: {members:?}");
    }

    #[test]
    fn only_a_link_keeps_its_target_out_of_its_attributes_and_only_a_file_has_content() {
        let mut forge = Forge::populated();
        // A file carrying the attribute a link keeps its target in, which on a file is an
        // attribute like any other; and a directory recording a data stream.
        forge.add(forge::xattr(
            16,
            b"com.apple.fs.symlink",
            xattr_flags::EMBEDDED,
            b"x\0",
        ));
        *inode_record(&mut forge, 17) = forge::inode(17, 2, 0o040_755, 17, Some(100), &[]);
        forge.extent(17, 0, 1, DATA_AT + 2);
        forge.settle();
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        let names: Vec<_> = reader
            .xattrs(&hello)
            .expect("read")
            .into_iter()
            .map(|x| x.name)
            .collect();
        assert!(
            names.contains(&b"com.apple.fs.symlink".to_vec()),
            "{names:?}"
        );
        // What a directory or a link reads as content is nothing, as the shared frame states.
        let mut buf = [0u8; 64];
        for path in [&b"/dir"[..], b"/link"] {
            let node = reader.lookup_no_follow(path).expect("found");
            assert_eq!(reader.read_into(&node, 0, &mut buf).expect("read"), 0);
            assert_eq!(
                FsTree::read_bytes(&mut reader, &node, 0, &mut buf).expect("read"),
                0
            );
            assert!(reader.read_data(&node).expect("read").is_empty());
        }
    }

    #[test]
    fn two_names_for_one_inode_share_an_identity() {
        let mut reader = open(&Forge::populated());
        let one = reader.lookup(b"/hard1").expect("found");
        let two = reader.lookup(b"/dir/hard2").expect("found");
        assert_eq!((one.inode, two.inode), (20, 20));
        assert_eq!(one.links(), 2);
        let mut shared = BTreeMap::new();
        reader
            .walk_tree::<TreeError, _>(|_, entry| {
                if let Some(id) = entry.shared {
                    shared.insert(entry.path.clone(), id);
                }
                Ok(())
            })
            .expect("walks");
        assert_eq!(shared.len(), 2);
        assert_eq!(shared[&b"/hard1".to_vec()], shared[&b"/dir/hard2".to_vec()]);
    }

    #[test]
    fn a_device_node_splits_its_number_as_darwin_packs_it() {
        let mut reader = open(&Forge::populated());
        let cdev = reader.lookup(b"/cdev").expect("found");
        assert_eq!(
            node_kind(&cdev),
            Ok(NodeKind::CharDevice { major: 3, minor: 4 })
        );
    }

    /// The populated volume holding `/packed`: a file compressed with type `method` into
    /// `fork`, its header claiming `len` bytes; a reader of it, and the file's node.
    fn packed(method: u32, len: u64, fork: &[u8]) -> (Reader<Cursor<Vec<u8>>>, Node) {
        let mut forge = Forge::populated();
        forge.compressed_file(b"packed", 24, method, len, fork, DATA_AT + 10);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/packed").expect("found");
        assert_eq!(node.size(), len, "the size the header records");
        (reader, node)
    }

    #[test]
    fn a_compression_header_that_does_not_read_is_refused_at_its_file_and_nowhere_else() {
        let mut forge = Forge::populated();
        forge.compressed_file(b"packed", 24, 8, 100, &[0u8; 16], DATA_AT + 10);
        let key = forge::xattr(24, b"com.apple.decmpfs", 0, b"").0;
        let header = forge
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the header");
        // The first byte of the header's magic, after the value's flags and length.
        header.1[4] = b'x';
        // And a link count elsewhere, which only a namespace walk that goes on finds.
        put_u32(&mut inode_record(&mut forge, 16).1, 56, 3);
        let mut reader = open(&forge);
        // A walk and a lookup reach the file and every other name.
        assert_eq!(reader.walk().expect("walks").len(), EVERY_PATH.len() + 1);
        let node = reader.lookup(b"/packed").expect("found");
        assert!(matches!(
            node.compression,
            Some(Err(ReadError::BadCompressed { inode: 24, .. }))
        ));
        // A read of its content refuses, and so does the extraction surface asking its size.
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadCompressed { .. })
        ));
        assert!(matches!(node_kind(&node), Err(TreeError::Malformed { .. })));
        // The scan reports it at the file, and the link count as well.
        let found = scanned(&forge);
        assert!(
            found.contains(&(Category::Record, Severity::Structural, Some(24))),
            "{found:?}"
        );
        assert!(
            found.contains(&(Category::Volume, Severity::Conformance, Some(16))),
            "{found:?}"
        );
    }

    // The decoder is a feature of its own, so the read is compiled where it is; the next case
    // is what a build without it does with the same file.
    #[cfg(feature = "lzvn")]
    #[test]
    fn a_compressed_file_reads_through_its_resource_fork_and_not_its_empty_stream() {
        // Two chunks: 64 KiB and 4,464 bytes, read whole and by a window across the boundary.
        let content = pattern(70_000, 9);
        let (mut reader, node) = packed(8, 70_000, &forge::resource_fork(&content));
        assert_eq!(reader.read_data(&node).expect("read"), content);
        let mut window = [0u8; 100];
        assert_eq!(
            reader.read_into(&node, 65_500, &mut window).expect("read"),
            100
        );
        assert_eq!(&window[..], &content[65_500..65_600]);
        // The two attributes the content is kept in are the content, not attributes of it.
        assert!(reader.xattrs(&node).expect("read").is_empty());
        assert_eq!(reader.scan().anomalies().len(), 0);
    }

    #[cfg(not(feature = "lzvn"))]
    #[test]
    fn a_build_without_the_decoder_refuses_a_compressed_file_by_its_type() {
        let content = pattern(70_000, 9);
        let (mut reader, node) = packed(8, 70_000, &forge::resource_fork(&content));
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::UnsupportedCompression {
                inode: 24,
                method: 8
            })
        ));
        // The scan still holds the chunk table to the fork, and counts the file as one it
        // does not decode.
        let report = reader.scan();
        let found = report.anomalies();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::Cosmetic);
        assert!(found[0].detail.contains("type 8"), "{}", found[0].detail);
    }

    #[test]
    fn a_compression_type_this_crate_has_not_observed_is_refused_by_its_number() {
        let (mut reader, node) = packed(5, 8, &forge::resource_fork(b"anything"));
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::UnsupportedCompression {
                inode: 24,
                method: 5
            })
        ));
        // To a scan it is a file this build does not decode, counted, and not a fault.
        let report = reader.scan();
        let found = report.anomalies();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            (found[0].category, found[0].severity),
            (Category::Record, Severity::Cosmetic)
        );
        assert!(found[0].detail.contains("type 5"), "{}", found[0].detail);
    }

    // A header claiming a terabyte over a fork of a few bytes. The table a terabyte's chunks
    // need does not fit the fork, and that is the answer; the terabyte is never allocated.
    #[cfg(all(feature = "lzvn", target_pointer_width = "64"))]
    #[test]
    fn a_compressed_files_size_is_not_allocated_on_its_headers_word() {
        let (mut reader, node) = packed(8, 1 << 40, &forge::resource_fork(b"tiny"));
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadCompressed { inode: 24, .. })
        ));
    }

    #[test]
    fn a_chunk_table_a_read_refuses_is_a_finding() {
        let content = pattern(70_000, 9);
        // The table's last offset past the end of the fork.
        let mut fork = forge::resource_fork(&content);
        let end = fork.len() as u32 + 1;
        fork[8..12].copy_from_slice(&end.to_le_bytes());
        let (mut reader, _) = packed(8, 70_000, &fork);
        let found: Vec<_> = reader
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.inode))
            .collect();
        assert!(
            found.contains(&(Category::Record, Severity::Structural, Some(24))),
            "{found:?}"
        );
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn a_chunk_table_that_does_not_frame_the_fork_is_refused() {
        let content = pattern(70_000, 9);
        // The table's last offset past the end of the fork.
        let mut fork = forge::resource_fork(&content);
        let end = fork.len() as u32 + 1;
        fork[8..12].copy_from_slice(&end.to_le_bytes());
        let (mut reader, node) = packed(8, 70_000, &fork);
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadCompressed { inode: 24, .. })
        ));
        // A header claiming more content than the chunks decode to.
        let (mut reader, node) = packed(8, 70_001, &forge::resource_fork(&content));
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadCompressed { inode: 24, .. })
        ));
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn a_chunk_table_with_room_to_spare_reads_from_where_its_first_offset_says() {
        // afsctool leaves room for twice the entries a table needs, and macOS reads the file.
        let content = pattern(70_000, 9);
        let chunks: Vec<Vec<u8>> = content
            .chunks(64 * 1024)
            .map(forge::lzvn_literals)
            .collect();
        let fork = forge::offset_fork(&chunks, 2 * chunks.len());
        let (mut reader, node) = packed(8, 70_000, &fork);
        assert_eq!(reader.read_data(&node).ok(), Some(content));
        assert_eq!(reader.scan().anomalies().len(), 0);
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn an_lzvn_chunk_that_does_not_compress_is_read_raw_after_its_marker() {
        // As macOS's compressor writes a file of text and bytes that do not compress: each
        // chunk that compresses is an LZVN stream, and each that does not is the end-of-stream
        // instruction and its content, a short last chunk among them.
        let text = forge::pattern(64 * 1024, 7)
            .iter()
            .map(|b| b'a' + b % 4)
            .collect::<Vec<u8>>();
        let random = pattern(64 * 1024, 8);
        let tail = pattern(5000, 9);
        let raw = |content: &[u8]| [&[0x06][..], content].concat();
        let chunks = vec![forge::lzvn_literals(&text), raw(&random), raw(&tail)];
        let fork = forge::offset_fork(&chunks, chunks.len() + 1);
        let content = [text, random, tail].concat();
        let (mut reader, node) = packed(8, content.len() as u64, &fork);
        assert_eq!(reader.read_data(&node).ok(), Some(content));
        assert_eq!(reader.scan().anomalies().len(), 0);
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn content_kept_after_its_header_reads_as_one_chunk() {
        // In the attribute's record, and in a stream of its own, as macOS keeps the attribute
        // once it is longer than a few dozen bytes.
        let content = pattern(1000, 5);
        for stream_at in [None, Some(DATA_AT + 10)] {
            let mut forge = Forge::populated();
            let stored = forge::lzvn_literals(&content);
            forge.inline_compressed_file(b"inline", 24, 7, 1000, &stored, stream_at);
            let mut reader = open(&forge);
            let node = reader.lookup(b"/inline").expect("found");
            assert_eq!(reader.read_data(&node).ok(), Some(content.clone()));
            let mut window = [0u8; 10];
            assert_eq!(reader.read_into(&node, 995, &mut window).ok(), Some(5));
            assert_eq!(&window[..5], &content[995..]);
            assert!(reader.xattrs(&node).expect("read").is_empty());
            assert_eq!(reader.scan().anomalies().len(), 0, "{stream_at:?}");
        }
    }

    #[test]
    fn content_after_its_header_is_held_to_one_chunk() {
        // Every file macOS keeps this way holds 64 KiB or less. A scan holds the attribute to
        // that whatever the build decodes, and a build with the decoder refuses the read.
        let mut forge = Forge::populated();
        forge.inline_compressed_file(b"inline", 24, 7, 70_000, &forge::lzvn_literals(b"x"), None);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/inline").expect("found");
        assert!(
            !cfg!(feature = "lzvn")
                || matches!(
                    reader.read_data(&node),
                    Err(ReadError::BadCompressed { inode: 24, .. })
                )
        );
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Structural, Some(24))]
        );
    }

    /// The populated volume with `/inline`, 1,000 bytes kept after its header as type
    /// `inline_type`, and `/forked`, 70,000 bytes kept in a resource fork as type `fork_type`,
    /// each chunk encoded by `encode` and the fork laid out by `fork_of`; then `more` adds what
    /// a gate needs beside them. Both files read whole and by a window across a chunk's end,
    /// and the volume scans clean.
    fn inline_and_forked_read(
        inline_type: u32,
        fork_type: u32,
        encode: fn(&[u8]) -> Vec<u8>,
        fork_of: fn(&[Vec<u8>]) -> Vec<u8>,
        more: impl FnOnce(&mut Forge, &mut Vec<(&'static [u8], Vec<u8>)>),
    ) {
        let small = pattern(1000, 10);
        let content = pattern(70_000, 11);
        let mut forge = Forge::populated();
        forge.per_leaf = Some(6);
        forge.inline_compressed_file(b"inline", 24, inline_type, 1000, &encode(&small), None);
        let chunks: Vec<Vec<u8>> = content.chunks(64 * 1024).map(encode).collect();
        forge.compressed_file(
            b"forked",
            25,
            fork_type,
            70_000,
            &fork_of(&chunks),
            DATA_AT + 10,
        );
        let mut want: Vec<(&'static [u8], Vec<u8>)> =
            vec![(b"/inline", small), (b"/forked", content.clone())];
        more(&mut forge, &mut want);
        let mut reader = open(&forge);
        for (path, content) in want {
            let node = reader.lookup(path).expect("found");
            assert_eq!(reader.read_data(&node).ok(), Some(content));
        }
        let forked = reader.lookup(b"/forked").expect("found");
        let mut window = [0u8; 100];
        assert_eq!(
            reader.read_into(&forked, 65_500, &mut window).ok(),
            Some(100)
        );
        assert_eq!(&window[..], &content[65_500..65_600]);
        assert_eq!(reader.scan().anomalies().len(), 0);
    }

    #[test]
    fn stored_content_reads_after_its_header_and_from_a_table_of_offsets() {
        // Types 9 and 10 need no decoder, so every build reads them. Beside the two files, the
        // smallest content macOS keeps as type 9, one byte, and an empty file.
        let fork_of = |chunks: &[Vec<u8>]| forge::offset_fork(chunks, chunks.len() + 1);
        inline_and_forked_read(9, 10, forge::stored, fork_of, |forge, want| {
            forge.inline_compressed_file(b"one", 26, 9, 1, &forge::stored(b"\n"), None);
            forge.inline_compressed_file(b"none", 27, 9, 0, &forge::stored(b""), None);
            want.push((b"/one", b"\n".to_vec()));
            want.push((b"/none", Vec::new()));
        });
    }

    #[test]
    fn a_stored_chunk_is_held_to_its_marker_and_its_share() {
        // macOS reads only chunks opening with the marker, and cuts or fills content that
        // differs from the header's size; a strict read refuses both.
        for (size, chunk) in [
            (40, [&[0xCD][..], &pattern(40, 3)].concat()),
            (40, forge::stored(&pattern(41, 3))),
            (41, forge::stored(&pattern(40, 3))),
        ] {
            let mut forge = Forge::populated();
            forge.inline_compressed_file(b"inline", 24, 9, size, &chunk, None);
            let mut reader = open(&forge);
            let node = reader.lookup(b"/inline").expect("found");
            assert!(
                matches!(
                    reader.read_data(&node),
                    Err(ReadError::BadCompressed { inode: 24, .. })
                ),
                "{size} {:#04x}",
                chunk[0]
            );
        }
    }

    #[test]
    fn content_kept_after_its_header_at_another_length_reads_to_the_headers_size_leniently() {
        // macOS reads type 7's chunk opening with 0x06 and type 9's opening with its marker to
        // the size the header states, the content cut there or followed by zeros. A lenient
        // read does the same, a strict read refuses, and a scan reports it.
        let mut kinds = vec![(9u32, decmpfs::STORED)];
        if cfg!(feature = "lzvn") {
            kinds.push((7, 0x06));
        }
        let content = pattern(1_000, 5);
        for (method, marker) in kinds {
            let chunk = [&[marker][..], &content].concat();
            for (size, want) in [
                (990u64, content[..990].to_vec()),
                (1_010, [&content[..], &[0u8; 10][..]].concat()),
            ] {
                let mut forge = Forge::populated();
                forge.inline_compressed_file(b"inline", 24, method, size, &chunk, None);
                let mut strict = open(&forge);
                let node = strict.lookup(b"/inline").expect("found");
                assert!(
                    matches!(
                        strict.read_data(&node),
                        Err(ReadError::BadCompressed { inode: 24, .. })
                    ),
                    "type {method}, {size}"
                );
                let mut lenient = lenient(forge.image());
                let node = lenient.lookup(b"/inline").expect("found");
                assert_eq!(
                    lenient.read_data(&node).ok(),
                    Some(want),
                    "type {method}, {size}"
                );
                assert_eq!(
                    scanned(&forge),
                    [(Category::Record, Severity::Conformance, Some(24))],
                    "type {method}, {size}"
                );
            }
        }
        // Content encoded rather than kept as itself is held to its share under either policy.
        if cfg!(feature = "zlib") {
            let chunk = [&[0xFF][..], &content].concat();
            let mut forge = Forge::populated();
            forge.inline_compressed_file(b"inline", 24, 3, 990, &chunk, None);
            let mut lenient = lenient(forge.image());
            let node = lenient.lookup(b"/inline").expect("found");
            assert!(matches!(
                lenient.read_data(&node),
                Err(ReadError::BadCompressed { inode: 24, .. })
            ));
        }
    }

    #[test]
    fn content_after_its_header_is_kept_in_an_attribute_of_at_most_3802_bytes() {
        // macOS keeps a file compressed with an attribute of 3,802 bytes and not with one a byte
        // longer, for every type kept there, so a compressed file with a longer one is not one
        // macOS wrote: here type 9, and zlib's raw chunk where the build has zlib.
        let mut kinds = vec![(9u32, decmpfs::STORED)];
        if cfg!(feature = "zlib") {
            kinds.push((3, 0xFF));
        }
        for (method, marker) in kinds {
            for (content_len, reads) in [(3_785, true), (3_786, false)] {
                let content = pattern(content_len, 4);
                let chunk = [&[marker][..], &content].concat();
                let mut forge = Forge::populated();
                let at = Some(DATA_AT + 10);
                forge.inline_compressed_file(b"inline", 24, method, content_len as u64, &chunk, at);
                let mut reader = open(&forge);
                let node = reader.lookup(b"/inline").expect("found");
                let read = reader.read_data(&node);
                if reads {
                    assert_eq!(read.ok(), Some(content), "type {method}");
                    assert_eq!(scanned(&forge), [], "type {method}");
                } else {
                    assert!(
                        matches!(read, Err(ReadError::BadCompressed { inode: 24, .. })),
                        "type {method}"
                    );
                    assert_eq!(
                        scanned(&forge),
                        [(Category::Record, Severity::Structural, Some(24))],
                        "type {method}"
                    );
                }
            }
        }
    }

    #[cfg(feature = "lzfse")]
    #[test]
    fn lzfse_content_reads_after_its_header_and_from_a_table_of_offsets() {
        let fork_of = |chunks: &[Vec<u8>]| forge::offset_fork(chunks, chunks.len() + 1);
        inline_and_forked_read(11, 12, forge::lzfse_raw, fork_of, |_, _| {});
    }

    #[cfg(feature = "lzbitmap")]
    #[test]
    fn lzbitmap_content_reads_after_its_header_and_from_a_table_of_offsets() {
        let fork_of = |chunks: &[Vec<u8>]| forge::offset_fork(chunks, chunks.len() + 1);
        inline_and_forked_read(13, 14, forge::lzbitmap_raw, fork_of, |_, _| {});
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn zlib_content_reads_after_its_header_and_from_a_classic_resource_fork() {
        inline_and_forked_read(
            3,
            4,
            forge::zlib_stored,
            forge::classic_fork,
            |forge, want| {
                // A last chunk of one byte stored raw after its marker, as afsctool stores one.
                let tail = pattern(65_537, 8);
                let chunks = [
                    forge::zlib_stored(&tail[..65_536]),
                    vec![0xFF, tail[65_536]],
                ];
                let fork = forge::classic_fork(&chunks);
                forge.compressed_file(b"tail", 26, 4, 65_537, &fork, DATA_AT + 30);
                want.push((b"/tail", tail));
            },
        );
    }

    #[test]
    fn a_chunk_table_is_read_and_scanned_alike_whatever_its_chunks_hold() {
        let outcome = |method: u32, len: u64, fork: &[u8], change: &dyn Fn(&mut Forge)| {
            let mut forge = Forge::populated();
            forge.compressed_file(b"packed", 24, method, len, fork, DATA_AT + 10);
            change(&mut forge);
            let mut reader = open(&forge);
            let node = reader.lookup(b"/packed").expect("found");
            let read = reader.read_data(&node);
            let scan: Vec<_> = reader
                .scan()
                .anomalies()
                .iter()
                .map(|a| (a.category, a.severity, a.inode))
                .collect();
            (read, scan)
        };
        let none = |_: &mut Forge| {};
        let chunk = decmpfs::CHUNK as usize;
        // Two chunks of a classic resource fork, each a full chunk, their entries in each
        // other's places: each lies after the table and inside the resource, and each decodes
        // to its share, so only a tiling sees the content come back out of order.
        let whole = pattern(2 * chunk, 7);
        let zlib: Vec<Vec<u8>> = whole.chunks(chunk).map(forge::zlib_stored).collect();
        let mut swapped = forge::classic_fork(&zlib);
        let (a, b) = (256 + 4 + 4, 256 + 4 + 4 + 8);
        let first: Vec<u8> = swapped[a..a + 8].to_vec();
        swapped.copy_within(b..b + 8, a);
        swapped[b..b + 8].copy_from_slice(&first);
        // A table of offsets whose first chunk is empty, and one whose stored chunk opens with
        // another byte than its marker: every read refuses each, and the scan must as well.
        let content = pattern(70_000, 9);
        let stored: Vec<Vec<u8>> = content.chunks(chunk).map(forge::stored).collect();
        let mut empty = forge::offset_fork(&stored, 3);
        let first_offset = crate::bytes::get_u32(&empty, 0);
        put_u32(&mut empty, 4, first_offset);
        let mut unmarked = forge::offset_fork(&stored, 3);
        unmarked[first_offset as usize] = 0;
        // A resource fork recording a terabyte its extents do not hold, which the scan finds and
        // a read reading only the chunks it needs did not.
        let fork = forge::offset_fork(&stored, 3);
        let terabyte = |forge: &mut Forge| {
            let key = forge::xattr(24, b"com.apple.ResourceFork", 0, b"").0;
            let record = forge
                .records
                .iter_mut()
                .find(|(k, _)| *k == key)
                .expect("the fork");
            put_u64(&mut record.1, 4 + 8, 1 << 40);
        };
        type Change<'c> = &'c dyn Fn(&mut Forge);
        let cases: [(u32, u64, &[u8], Change<'_>); 4] = [
            (4, whole.len() as u64, &swapped, &none),
            (10, 70_000, &empty, &none),
            (10, 70_000, &unmarked, &none),
            (10, 70_000, &fork, &terabyte),
        ];
        for (i, (method, len, fork, change)) in cases.into_iter().enumerate() {
            let (read, scan) = outcome(method, len, fork, change);
            if method != 4 || cfg!(feature = "zlib") {
                assert!(
                    read.is_err(),
                    "{i}: read {} bytes",
                    read.as_ref().map_or(0, Vec::len)
                );
            }
            // The terabyte fork is also longer than its allocation, a finding of its own.
            assert!(
                scan.contains(&(Category::Record, Severity::Structural, Some(24))),
                "{i}: {scan:?}"
            );
        }
    }

    #[test]
    fn a_classic_resource_fork_that_does_not_frame_its_chunks_is_refused() {
        let content = pattern(70_000, 7);
        let chunks: Vec<Vec<u8>> = content.chunks(64 * 1024).map(forge::zlib_stored).collect();
        let refused = |fork: &[u8]| {
            let (mut reader, node) = packed(4, 70_000, fork);
            let read = reader.read_data(&node);
            let scan = reader
                .scan()
                .anomalies()
                .iter()
                .map(|a| (a.category, a.severity, a.inode))
                .collect::<Vec<_>>();
            (read, scan)
        };
        // One chunk recorded for content that takes two, and three.
        let one = forge::classic_fork(&chunks[..1]);
        let three = forge::classic_fork(&[chunks[0].clone(), chunks[1].clone(), chunks[1].clone()]);
        // The resource data said to begin past the end of the fork.
        let mut beyond = forge::classic_fork(&chunks);
        let past = (beyond.len() as u32).to_be_bytes();
        beyond[..4].copy_from_slice(&past);
        // A chunk's length reaching past the resource.
        let mut long = forge::classic_fork(&chunks);
        let entry = 256 + 4 + 4 + 8 + 4;
        let len = crate::bytes::get_u32(&long, entry);
        put_u32(&mut long, entry, len + 1_000_000);
        for (fork, fault) in [
            (one, "chunk count"),
            (three, "chunk count"),
            (beyond, "header or table"),
            (long, "chunk 1"),
        ] {
            let (read, scan) = refused(&fork);
            // A build without the decoder refuses the read by the type, before the table; the
            // scan holds the table to the fork either way.
            assert!(
                !cfg!(feature = "zlib")
                    || matches!(&read, Err(ReadError::BadCompressed { inode: 24, fault: found })
                    if found.contains(fault)),
                "{fault}: {read:?}"
            );
            assert_eq!(scan, [(Category::Record, Severity::Structural, Some(24))]);
        }
    }

    #[test]
    fn a_volume_is_selected_by_slot_by_name_or_by_identifier() {
        let image = Forge::populated().image();
        for selector in [
            VolumeSelector::Slot(0),
            VolumeSelector::Name(b"Forged".to_vec()),
            VolumeSelector::Uuid([0x33; 16]),
        ] {
            let options = OpenOptions::new().volume(selector);
            assert!(Reader::open_with(Cursor::new(image.clone()), &options).is_ok());
        }
        let options = OpenOptions::new().volume(VolumeSelector::Name(b"Other".to_vec()));
        assert!(matches!(
            Reader::open_with(Cursor::new(image), &options),
            Err(ReadError::NoSuchVolume { .. })
        ));
    }

    #[test]
    fn a_snapshot_that_is_dataless_or_being_merged_is_refused_and_the_volume_still_reads() {
        // The metadata record's flags: a snapshot whose data is pending removal, and one being
        // merged into the volume (documented). Neither keeps a tree this reader can stand on.
        for flags in [0x1u32, 0x2, 0x3] {
            let mut forge = Forge::with_snapshot();
            forge.snapshot_flags = flags;
            let image = forge.image();
            let reader = Reader::open(Cursor::new(image.clone())).expect("the live volume");
            match reader.at_snapshot(b"before") {
                Err(ReadError::UnsupportedFeatures { scope, bits, .. }) => {
                    assert_eq!((scope, bits), ("snapshot", u64::from(flags)));
                }
                Err(e) => panic!("{flags:#x}: expected the snapshot refused, got {e}"),
                Ok(_) => panic!("{flags:#x}: a snapshot carrying the flag was read"),
            }
            let mut reader = Reader::open(Cursor::new(image)).expect("the live volume");
            assert!(reader.lookup(b"/hello").is_ok(), "{flags:#x}");
        }
        // The control: the same snapshot with no flag reads.
        let image = Forge::with_snapshot().image();
        let reader = Reader::open(Cursor::new(image)).expect("open");
        assert!(reader.at_snapshot(b"before").is_ok());
    }

    #[test]
    fn a_container_longer_than_its_region_is_found_short_and_one_inside_it_is_not() {
        // The forged container a mebibyte into a disk, and a neighbour's bytes after it. Its
        // structures sit in its first blocks, so a region of half of it opens, and the one
        // thing that says the region is short is the scan's account of the container's length.
        const BASE: u64 = 1 << 20;
        let image = Forge::populated().image();
        let len = image.len() as u64;
        let mut disk = vec![0u8; BASE as usize];
        disk.extend_from_slice(&image);
        disk.extend(vec![0xee; 1 << 20]);
        let scan = |len: Option<u64>| {
            let mut options = OpenOptions::new();
            options.common = crate::OpenOptions::new()
                .base(BASE)
                .policy(ReadPolicy::Lenient);
            options.common.len = len;
            Reader::open_with(Cursor::new(disk.as_slice()), &options)
                .expect("open")
                .scan()
        };
        let report = scan(Some(len / 2));
        let short: Vec<&crate::apfs::Anomaly> = report
            .anomalies()
            .iter()
            .filter(|a| a.detail.contains("and the source holds"))
            .collect();
        assert_eq!(short.len(), 1, "{:#?}", report.anomalies());
        assert_eq!(short[0].severity, Severity::Structural);
        assert!(
            short[0].detail.contains(&format!("holds {}", len / 2)),
            "{}",
            short[0].detail
        );
        for len in [Some(len), None] {
            let report = scan(len);
            assert!(
                !report
                    .anomalies()
                    .iter()
                    .any(|a| a.detail.contains("and the source holds")),
                "{len:?}: {:#?}",
                report.anomalies()
            );
        }
    }

    #[test]
    fn a_name_two_volumes_carry_selects_neither() {
        // A name compares byte for byte, and one two volumes carry identifies neither: the read
        // is refused and says which slots carry it, and each volume is still reached by its slot
        // and by its identifier. The command line refuses the same name the same way.
        let mut forge = Forge::populated();
        forge.second = Some(forge::second_volume(b"Forged", 1));
        let image = forge.image();
        let named = OpenOptions::new().volume(VolumeSelector::Name(b"Forged".to_vec()));
        match Reader::open_with(Cursor::new(image.clone()), &named) {
            Err(ReadError::AmbiguousVolume { name, slots }) => {
                assert_eq!(name, b"Forged");
                assert_eq!(slots, [0, 1]);
            }
            Err(e) => panic!("expected the name refused as ambiguous, got {e}"),
            Ok(_) => panic!("a name two volumes carry selected one of them"),
        }
        for selector in [VolumeSelector::Slot(1), VolumeSelector::Uuid([0x44; 16])] {
            let options = OpenOptions::new().volume(selector);
            assert!(Reader::open_with(Cursor::new(image.clone()), &options).is_ok());
        }
    }

    #[test]
    fn an_encrypted_sealed_or_unhashed_volume_is_refused_by_name() {
        let mut forge = Forge::populated();
        forge.volume.flags = 0;
        assert!(matches!(
            Reader::open(forge.cursor()),
            Err(ReadError::Encrypted { slot: 0 })
        ));
        let mut forge = Forge::populated();
        forge.volume.incompatible_features |= 0x20;
        assert!(matches!(
            Reader::open(forge.cursor()),
            Err(ReadError::UnsupportedFeatures {
                scope: "volume",
                bits: 0x20,
                ..
            })
        ));
        let mut forge = Forge::populated();
        forge.volume.incompatible_features = 0;
        assert!(matches!(
            Reader::open(forge.cursor()),
            Err(ReadError::UnhashedNames { slot: 0 })
        ));
    }

    #[test]
    fn a_damaged_node_is_refused_and_not_read_past() {
        let mut image = Forge::populated().image();
        image[FS_ROOT_AT as usize * BLOCK + 200] ^= 1;
        let mut reader = Reader::open(Cursor::new(image)).expect("opens: the tree is read lazily");
        assert!(matches!(
            reader.root(),
            Err(ReadError::BadChecksum {
                block: FS_ROOT_AT,
                ..
            })
        ));
    }

    #[test]
    fn a_node_from_another_transaction_than_its_map_says_is_refused() {
        let mut image = Forge::populated().image();
        let at = FS_ROOT_AT as usize * BLOCK;
        put_u64(&mut image[at..], 16, XID - 1);
        reseal(&mut image, FS_ROOT_AT);
        let mut reader = Reader::open(Cursor::new(image)).expect("opens");
        assert!(matches!(
            reader.root(),
            Err(ReadError::WrongObject {
                block: FS_ROOT_AT,
                ..
            })
        ));
    }

    #[test]
    fn an_index_key_that_is_not_its_childs_first_is_refused() {
        // Shapes only a descent catches: the root's keys stay in order, so the root reads, and
        // the fault is in what one of its keys says of the leaf it leads to. A walk enters every
        // leaf, so it meets each.
        let forge = Forge::populated();
        let leaves = leaves(&forge, 4);
        let walked = |separator: (usize, Vec<u8>)| {
            let mut forge = forge.clone();
            forge.per_leaf = Some(4);
            forge.separator = Some(separator);
            open(&forge).walk().err()
        };
        // A key above its leaf's first record.
        assert_eq!(
            walked((2, leaves[2][1].clone())),
            Some(ReadError::BadTree {
                block: FS_ROOT_AT + 3,
                fault: "a node whose first key is not its parent's key for it"
            })
        );
        // A key for the next leaf that the leaf before reaches: its last record's own key.
        assert_eq!(
            walked((2, leaves[1].last().expect("a record").clone())),
            Some(ReadError::BadTree {
                block: FS_ROOT_AT + 2,
                fault: "a node whose keys reach past its parent's key for the next node"
            })
        );
    }

    /// The keys of each leaf the forge lays `forge`'s tree out in, `per_leaf` records to a leaf.
    fn leaves(forge: &Forge, per_leaf: usize) -> Vec<Vec<Vec<u8>>> {
        let mut keys: Vec<Vec<u8>> = forge.records.iter().map(|r| r.0.clone()).collect();
        keys.sort_by(|a, b| {
            btree::compare_records(a, b)
                .ok()
                .flatten()
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        keys.chunks(per_leaf).map(<[Vec<u8>]>::to_vec).collect()
    }

    #[test]
    fn an_extent_leaving_the_container_is_refused() {
        let mut forge = Forge::populated();
        forge
            .records
            .retain(|(key, _)| key[..8] != forge::extent(16, 0, 0, 0).0[..8]);
        forge.extent(16, 0, 2, forge::BLOCKS - 1);
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert!(matches!(
            reader.read_data(&hello),
            Err(ReadError::BadExtent { stream: 16, .. })
        ));
        // The same file read short of the bad blocks is still refused, not read in part.
        let _ = DATA_AT;
    }

    #[test]
    fn a_newer_checkpoint_without_its_mapping_blocks_is_passed_over() {
        let forge = Forge::populated();
        let mut image = forge.image();
        // A superblock at transaction XID + 1 in the next slot, claiming a checkpoint of two
        // blocks whose mapping block was never written.
        let mut newer: ContainerSuperblock = forge.container.clone();
        newer.header.xid = XID + 1;
        newer.checkpoint.desc_index = 2;
        newer.checkpoint.desc_len = 2;
        let mut block = vec![0u8; BLOCK];
        newer.write_to(&mut block);
        let at = (DESC_BASE + 3) as usize * BLOCK;
        image[at..at + BLOCK].copy_from_slice(&sealed(block));
        let reader = Reader::open(Cursor::new(image)).expect("opens at the older checkpoint");
        assert_eq!(reader.container().xid(), XID);
        assert_eq!(reader.container().passed_over().len(), 1);
        assert_eq!(reader.container().passed_over()[0].xid, XID + 1);
    }

    #[test]
    fn a_volume_whose_superblock_cannot_be_read_is_refused_only_where_it_is_selected() {
        // Slot 0 names an object the container's map does not hold; the forged volume is in
        // slot 1. And the forged volume listed in both slots, where its superblock records 0.
        let mut missing = Forge::populated();
        missing.container.volume_oids[0] = forge::VOLUME_OID + 100;
        missing.container.volume_oids[1] = forge::VOLUME_OID;
        missing.volume.index = 1;
        missing.container.max_volumes = 2;
        missing.container.block_count = 2 * forge::BLOCKS;
        let mut twice = Forge::populated();
        twice.container.volume_oids[1] = forge::VOLUME_OID;
        twice.container.max_volumes = 2;
        twice.container.block_count = 2 * forge::BLOCKS;
        for (forge, damaged, readable) in [(missing, 0, 1), (twice, 1, 0)] {
            let mut image = forge.image();
            image.resize(2 * forge::BLOCKS as usize * BLOCK, 0);
            let container = Container::open(Cursor::new(image.clone())).expect("opens");
            let slots: Vec<_> = container.volumes().iter().map(|v| v.slot).collect();
            assert_eq!(slots, [readable]);
            let unreadable = container.unreadable_volumes();
            assert_eq!(unreadable.len(), 1);
            assert_eq!(unreadable[0].slot, damaged);
            let at = |slot| {
                let options = OpenOptions::new().volume(VolumeSelector::Slot(slot));
                Reader::open_with(Cursor::new(image.clone()), &options)
            };
            assert_eq!(at(damaged).err(), Some(unreadable[0].error.clone()));
            let mut reader = at(readable).expect("the other volume opens");
            // The first occupied slot is the one a read with no selection takes.
            let first = Reader::open(Cursor::new(image.clone()));
            assert_eq!(first.is_ok(), readable == 0);
            // The scan of the readable volume names the slot it could not read.
            let found: Vec<_> = reader
                .scan()
                .anomalies()
                .iter()
                .filter(|a| a.detail.contains(&format!("the volume in slot {damaged}")))
                .map(|a| a.severity)
                .collect();
            assert_eq!(found, [Severity::Structural]);
        }
    }

    /// A source that counts how many times each of its blocks is read.
    struct Counted {
        inner: Cursor<Vec<u8>>,
        reads: std::rc::Rc<std::cell::RefCell<BTreeMap<u64, u32>>>,
    }

    impl Counted {
        fn over(image: Vec<u8>) -> (Self, std::rc::Rc<std::cell::RefCell<BTreeMap<u64, u32>>>) {
            let reads = std::rc::Rc::default();
            let source = Self {
                inner: Cursor::new(image),
                reads: std::rc::Rc::clone(&reads),
            };
            (source, reads)
        }
    }

    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let at = self.inner.position();
            let n = self.inner.read(buf)?;
            let block = BLOCK as u64;
            for b in at / block..(at + n as u64).div_ceil(block) {
                *self.reads.borrow_mut().entry(b).or_default() += 1;
            }
            Ok(n)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(to)
        }
    }

    #[test]
    fn each_block_of_the_descriptor_area_is_read_once_to_choose_a_checkpoint() {
        // Choosing a checkpoint needs each ring block's checksum, type and transaction, which
        // one pass over the area reads. A candidate judged by reading its mapping blocks again
        // costs reads in the square of the area's length, on a crafted area of thousands.
        let forge = Forge::populated();
        let mut image = forge.image();
        let mut newer: ContainerSuperblock = forge.container.clone();
        newer.header.xid = XID + 1;
        newer.checkpoint.desc_index = 2;
        newer.checkpoint.desc_len = 2;
        let mut block = vec![0u8; BLOCK];
        newer.write_to(&mut block);
        let at = (DESC_BASE + 3) as usize * BLOCK;
        image[at..at + BLOCK].copy_from_slice(&sealed(block));
        let ring = DESC_BASE..DESC_BASE + u64::from(forge::DESC_BLOCKS);
        let once = |reads: &BTreeMap<u64, u32>| {
            ring.clone()
                .map(|b| reads.get(&b).copied().unwrap_or(0))
                .collect::<Vec<_>>()
        };
        let (source, reads) = Counted::over(image.clone());
        let container = Container::open(source).expect("opens");
        assert_eq!(container.passed_over().len(), 1);
        assert_eq!(once(&reads.borrow()), [1; 4]);
        // Detection reads the area where block zero does not verify, and reads it once too.
        image[300] ^= 1;
        let (source, reads) = Counted::over(image);
        assert!(crate::apfs::container::is_container(source, 0).expect("reads"));
        assert_eq!(once(&reads.borrow()), [1; 4]);
    }

    #[test]
    fn a_volume_superblock_from_another_slot_is_refused() {
        let mut image = Forge::populated().image();
        put_u32(&mut image[VOLUME_AT as usize * BLOCK..], 36, 7);
        reseal(&mut image, VOLUME_AT);
        assert!(matches!(
            Reader::open(Cursor::new(image)),
            Err(ReadError::WrongObject {
                block: VOLUME_AT,
                ..
            })
        ));
        let _ = ObjectHeader::SIZE;
    }

    /// The scan of `forge`'s volume, as `(category, severity, inode)` per finding.
    fn scanned(forge: &Forge) -> Vec<(Category, Severity, Option<u64>)> {
        open(forge)
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.inode))
            .collect()
    }

    #[test]
    fn a_volume_that_agrees_with_itself_scans_clean() {
        assert_eq!(scanned(&Forge::populated()), []);
        let mut split = Forge::populated();
        split.per_leaf = Some(2);
        assert_eq!(scanned(&split), []);
    }

    #[test]
    fn each_count_the_volume_keeps_about_itself_is_held_to_what_it_holds() {
        let mut forge = Forge::populated();
        forge.volume.file_count += 1;
        assert_eq!(
            scanned(&forge),
            [(Category::Volume, Severity::Conformance, None)]
        );

        // The root's child count, one more than its entries.
        let mut forge = Forge::populated();
        let root = forge
            .records
            .iter_mut()
            .find(|(k, _)| k[..8] == forge::inode(2, 1, 0, 0, None, &[]).0[..8])
            .expect("the root's inode");
        put_u32(&mut root.1, 56, 8);
        assert_eq!(
            scanned(&forge),
            [(Category::Volume, Severity::Conformance, Some(2))]
        );
    }

    #[test]
    fn a_link_count_and_an_entry_type_are_held_to_the_names_and_the_inode() {
        let mut forge = Forge::populated();
        let hard = forge
            .records
            .iter_mut()
            .find(|(k, _)| k[..8] == forge::inode(20, 1, 0, 0, None, &[]).0[..8])
            .expect("the hard link's inode");
        put_u32(&mut hard.1, 56, 3);
        assert_eq!(
            scanned(&forge),
            [(Category::Volume, Severity::Conformance, Some(20))]
        );

        let mut forge = Forge::populated();
        forge
            .records
            .retain(|(k, _)| k != &forge::entry(2, b"fifo", 21, 0, None).0);
        forge.entry(2, b"fifo", 21, forge::DT_DIR, None);
        // The entry and the inode contradict each other, which is integrity damage.
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Integrity, Some(21))]
        );
    }

    #[test]
    fn a_stream_two_inodes_name_and_one_reference_counts_is_found() {
        // `/hello` naming the hard link's stream as its own: it would read another file's
        // bytes, and its own stream has no reader at all.
        let mut forge = Forge::populated();
        let hello = forge
            .records
            .iter_mut()
            .find(|(k, _)| k[..8] == forge::inode(16, 1, 0, 0, None, &[]).0[..8])
            .expect("hello's inode");
        put_u64(&mut hello.1, 8, 20);
        let found = scanned(&forge);
        assert!(found.contains(&(Category::Record, Severity::Integrity, Some(20))));
        assert!(found.contains(&(Category::Record, Severity::Integrity, Some(16))));
    }

    /// The populated container with a whole checkpoint of another container in the ring's two
    /// free slots, at a later transaction: what a container written over an older one of the
    /// same geometry leaves, where whatever wrote it wrote only the blocks it uses.
    fn with_foreign_checkpoint() -> Vec<u8> {
        let forge = Forge::populated();
        let mut image = forge.image();
        let xid = XID + 1;
        let mut map = vec![0u8; BLOCK];
        ObjectHeader {
            checksum: 0,
            oid: DESC_BASE + 2,
            xid,
            type_word: 0x4000_0000 | u32::from(kind::CHECKPOINT_MAP),
            subtype: 0,
        }
        .write_to(&mut map);
        put_u32(&mut map, 32, 1);
        let mut other = forge.container.clone();
        other.header.xid = xid;
        other.uuid = [0xA5; 16];
        other.checkpoint.desc_index = 2;
        other.checkpoint.desc_len = 2;
        let mut superblock = vec![0u8; BLOCK];
        other.write_to(&mut superblock);
        for (slot, block) in [(2, map), (3, superblock)] {
            let at = (DESC_BASE + slot) as usize * BLOCK;
            image[at..at + BLOCK].copy_from_slice(&sealed(block));
        }
        image
    }

    #[test]
    fn a_checkpoint_of_another_container_is_passed_over_and_reported() {
        // Whole, verified and newer, it is the checkpoint the reference's procedure takes, and
        // reading it reads the other container. Block zero names the container, so a
        // checkpoint recording another identifier is not one of its own.
        let image = with_foreign_checkpoint();
        let ours = Forge::populated().container.uuid;
        let reader = Reader::open(Cursor::new(image.clone())).expect("opens");
        assert_eq!(reader.container().superblock().uuid, ours);
        assert_eq!(reader.container().xid(), XID);
        let passed: Vec<_> = reader
            .container()
            .passed_over()
            .iter()
            .map(|p| (p.address, p.xid, p.reason))
            .collect();
        assert_eq!(
            passed,
            [(DESC_BASE + 3, XID + 1, crate::apfs::container::FOREIGN)]
        );
        // A scan reports it as integrity damage, not as the interrupted write a newer
        // checkpoint of the container's own would be.
        let report = Reader::open(Cursor::new(image.clone()))
            .expect("opens")
            .scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.block))
            .collect();
        assert_eq!(
            found,
            [(
                Category::Checkpoint,
                Severity::Integrity,
                Some(DESC_BASE + 3)
            )]
        );
        // Where block zero does not verify, a lenient read still holds the ring to the
        // container block zero names.
        let mut damaged = image;
        damaged[1000] ^= 1;
        assert_eq!(lenient(damaged).container().superblock().uuid, ours);
    }

    #[test]
    fn a_checkpoint_passed_over_is_reported_as_an_interrupted_write() {
        let forge = Forge::populated();
        let mut image = forge.image();
        let mut newer: ContainerSuperblock = forge.container.clone();
        newer.header.xid = XID + 1;
        newer.checkpoint.desc_index = 2;
        let mut block = vec![0u8; BLOCK];
        newer.write_to(&mut block);
        let at = (DESC_BASE + 3) as usize * BLOCK;
        image[at..at + BLOCK].copy_from_slice(&sealed(block));
        let report = Reader::open(Cursor::new(image)).expect("opens").scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.block))
            .collect();
        assert_eq!(
            found,
            [(
                Category::Checkpoint,
                Severity::Cosmetic,
                Some(DESC_BASE + 3)
            )]
        );
    }

    #[test]
    fn a_damaged_node_is_a_finding_and_not_a_scan_that_stops_reporting() {
        let mut image = Forge::populated().image();
        image[FS_ROOT_AT as usize * BLOCK + 300] ^= 1;
        let report = Reader::open(Cursor::new(image)).expect("opens").scan();
        assert_eq!(report.anomalies().len(), 1);
        let finding = &report.anomalies()[0];
        assert_eq!(
            (finding.category, finding.severity, finding.block),
            (Category::Tree, Severity::Integrity, Some(FS_ROOT_AT))
        );
    }

    #[test]
    fn a_volume_lists_its_snapshots_with_their_transaction_and_identifier() {
        let mut reader = open(&Forge::with_snapshot());
        let snapshots = reader.snapshots().expect("listed");
        assert_eq!(snapshots.len(), 1);
        let snap = &snapshots[0];
        assert_eq!(snap.name, b"before");
        assert_eq!(snap.xid, forge::SNAPSHOT_XID);
        assert_eq!(snap.uuid, Some(forge::SNAPSHOT_UUID));
        assert_eq!(snap.superblock, forge::SNAPSHOT_SUPERBLOCK_AT);
        assert!(
            open(&Forge::populated())
                .snapshots()
                .expect("listed")
                .is_empty()
        );
    }

    #[test]
    fn a_snapshot_reads_the_tree_as_it_was_and_the_volume_as_it_is() {
        let image = Forge::with_snapshot().image();
        let options = OpenOptions::new().snapshot(b"before".to_vec());
        let mut past = Reader::open_with(Cursor::new(image.clone()), &options).expect("opens");
        assert_eq!(past.snapshot().map(|s| s.xid), Some(forge::SNAPSHOT_XID));
        let then = paths(&mut past);
        assert!(!then.contains(&b"/hello".to_vec()));
        assert!(then.contains(&b"/hard1".to_vec()));
        assert!(matches!(
            past.lookup(b"/hello"),
            Err(ReadError::NotFound { .. })
        ));
        let mut now = Reader::open(Cursor::new(image)).expect("opens");
        assert!(paths(&mut now).contains(&b"/hello".to_vec()));
    }

    #[test]
    fn a_snapshot_the_volume_does_not_have_is_refused_by_name() {
        let options = OpenOptions::new().snapshot(b"after".to_vec());
        assert!(matches!(
            Reader::open_with(Forge::with_snapshot().cursor(), &options),
            Err(ReadError::NoSuchSnapshot { .. })
        ));
    }

    #[test]
    fn a_superblock_copy_from_another_transaction_is_refused() {
        let mut image = Forge::with_snapshot().image();
        let at = forge::SNAPSHOT_SUPERBLOCK_AT;
        put_u64(
            &mut image[at as usize * BLOCK..],
            16,
            forge::SNAPSHOT_XID + 1,
        );
        reseal(&mut image, at);
        let options = OpenOptions::new().snapshot(b"before".to_vec());
        assert!(matches!(
            Reader::open_with(Cursor::new(image), &options),
            Err(ReadError::WrongObject { block, .. }) if block == at
        ));
    }

    #[test]
    fn a_superblock_copy_is_held_to_its_volume_and_to_what_the_live_one_is_refused_for() {
        let at = forge::SNAPSHOT_SUPERBLOCK_AT;
        let opened = |change: &dyn Fn(&mut [u8])| {
            let mut image = Forge::with_snapshot().image();
            change(&mut image[at as usize * BLOCK..(at as usize + 1) * BLOCK]);
            reseal(&mut image, at);
            let options = OpenOptions::new().snapshot(b"before".to_vec());
            Reader::open_with(Cursor::new(image), &options).err()
        };
        // The live superblock's refusals, met on the copy every read of the snapshot takes its
        // tree and its name rules from: the unencrypted flag cleared, an incompatible bit this
        // crate does not read, and neither name bit.
        assert_eq!(
            opened(&|b| put_u64(b, 264, 0)),
            Some(ReadError::Encrypted { slot: 0 })
        );
        assert!(matches!(
            opened(&|b| put_u64(b, 56, 0x101)),
            Some(ReadError::UnsupportedFeatures { bits: 0x100, .. })
        ));
        assert_eq!(
            opened(&|b| put_u64(b, 56, 0)),
            Some(ReadError::UnhashedNames { slot: 0 })
        );
        // A copy recording another volume's identifier, or another slot.
        assert!(matches!(
            opened(&|b| b[240] ^= 1),
            Some(ReadError::WrongObject { block, .. }) if block == at
        ));
        assert!(matches!(
            opened(&|b| put_u32(b, 36, 1)),
            Some(ReadError::WrongObject { block, .. }) if block == at
        ));
        assert_eq!(opened(&|_| {}), None);
    }

    #[test]
    fn a_name_in_another_case_or_normalization_finds_the_entry_the_volume_would() {
        let mut forge = Forge::populated();
        forge.entry(2, "caf\u{E9}".as_bytes(), 18, forge::DT_REG, None);
        forge.add(forge::inode(60, 2, 0o100_644, 0, None, &[]));
        forge.entry(2, b"Readme", 60, forge::DT_REG, None);
        forge.settle();
        let mut reader = open(&forge);
        assert_eq!(reader.lookup(b"/README").expect("found").inode, 60);
        // Case folds on this volume, and normalization is compared on every volume.
        assert_eq!(reader.lookup(b"/HELLO").expect("found").inode, 16);
        assert_eq!(reader.lookup(b"/Dir/Nested").expect("found").inode, 18);
        assert_eq!(
            reader
                .lookup("/cafe\u{301}".as_bytes())
                .expect("found")
                .inode,
            18
        );
        // The stored spelling is found exactly, whatever else might match it.
        assert_eq!(reader.lookup(b"/hello").expect("found").inode, 16);

        // A volume that keeps case finds the other normalization and not the other case. Its
        // names are hashed as it compares them, which for `Readme` is not as a folding one does.
        forge.volume.incompatible_features = 0x8;
        forge.rehash();
        let mut reader = open(&forge);
        for path in [&b"/HELLO"[..], b"/README"] {
            assert!(matches!(
                reader.lookup(path),
                Err(ReadError::NotFound { .. })
            ));
        }
        assert_eq!(reader.lookup(b"/Readme").expect("found").inode, 60);
        assert_eq!(
            reader
                .lookup("/cafe\u{301}".as_bytes())
                .expect("found")
                .inode,
            18
        );
    }

    #[test]
    fn a_checkpoint_is_held_to_the_identity_of_each_object_in_it() {
        // A container superblock is ephemeral and records identifier 1 (reference p. 13), and a
        // checkpoint-mapping block is physical and records its own address: an object of the
        // right type and no other identity is not one this checkpoint wrote.
        let mut forge = Forge::populated();
        forge.container.header.type_word = 0xF000_0001;
        forge.container.header.oid = 999;
        let mut images = vec![forge.image()];
        let mut image = Forge::populated().image();
        put_u64(&mut image[DESC_BASE as usize * BLOCK..], 8, 999);
        reseal(&mut image, DESC_BASE);
        images.push(image);
        let mut image = Forge::populated().image();
        put_u32(&mut image[DESC_BASE as usize * BLOCK..], 24, 0x000C);
        reseal(&mut image, DESC_BASE);
        images.push(image);
        for (i, image) in images.into_iter().enumerate() {
            for policy in [ReadPolicy::Strict, ReadPolicy::Lenient] {
                let options = crate::OpenOptions::new().policy(policy);
                assert_eq!(
                    Container::open_with(Cursor::new(image.clone()), &options).err(),
                    Some(ReadError::NoCheckpoint),
                    "{i} {policy:?}"
                );
            }
        }
    }

    #[test]
    fn an_object_recording_transaction_zero_is_refused_however_it_is_asked_for() {
        // Transaction zero is no transaction (reference p. 12), so an object recording it is not
        // one a write made, asked for at most a transaction or at exactly that one.
        let mut image = Forge::populated().image();
        let at = 200u64;
        let mut block = image[VOLUME_AT as usize * BLOCK..][..BLOCK].to_vec();
        put_u64(&mut block, 16, 0);
        image[at as usize * BLOCK..][..BLOCK].copy_from_slice(&sealed(block));
        let mut container = Container::open(Cursor::new(image)).expect("opens");
        for xid in [Xid::Exactly(0), Xid::AtMost(XID)] {
            let expect = Expect {
                kinds: &[kind::VOLUME_SUPERBLOCK],
                subtype: None,
                storage: Storage::Virtual,
                oid: forge::VOLUME_OID,
                xid,
            };
            assert!(
                matches!(
                    container.read_object(at, &expect),
                    Err(ReadError::WrongObject { .. })
                ),
                "{xid:?}"
            );
        }
    }

    #[test]
    fn a_key_its_node_cannot_order_is_found_at_the_node() {
        // An attribute name without its terminator, beside another attribute of the same inode:
        // the node's order check compares the two names, and the one does not parse.
        let mut forge = Forge::populated();
        let mut odd = forge::xattr(16, b"user.odd", xattr_flags::EMBEDDED, b"x");
        *odd.0.last_mut().expect("a name") = b'!';
        forge.add(odd);
        let found: Vec<_> = open(&forge)
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.block))
            .collect();
        assert!(
            found.contains(&(Category::Tree, Severity::Structural, Some(FS_ROOT_AT))),
            "{found:?}"
        );
    }

    #[test]
    fn a_tree_is_held_to_the_flags_it_is_read_by() {
        // macOS writes 0x42 on a file-system tree and 0x12 on an object map (every tree of the
        // corpus): the flags say how a tree's children are found and what its keys are.
        let flags_at = BLOCK - TREE_INFO_SIZE;
        let refused = |at: u64, flags: u32| {
            let mut image = Forge::populated().image();
            put_u32(&mut image[at as usize * BLOCK..], flags_at, flags);
            reseal(&mut image, at);
            match Reader::open(Cursor::new(image)) {
                Err(e) => Err(e),
                Ok(mut reader) => reader.walk().map(|_| ()),
            }
        };
        let fs = FS_ROOT_AT;
        let map = forge::VOLUME_MAP_TREE_AT;
        for (at, flags) in [
            // A file-system tree saying its children are found by address, and an object map
            // saying they are not.
            (fs, 0x52),
            (map, 0x02),
            // 64-bit integer keys, a tree not persisted, and a bit the format does not define.
            (fs, 0x43),
            (fs, 0x62),
            (fs, 0x242),
        ] {
            assert!(
                matches!(refused(at, flags), Err(ReadError::BadTree { .. })),
                "{at} {flags:#x}"
            );
        }
        assert!(refused(fs, 0x42).is_ok());
        assert!(refused(map, 0x12).is_ok());
        // An object map's node not flagged as holding entries of the fixed sizes its tree's
        // information gives.
        let mut image = Forge::populated().image();
        let at = map as usize * BLOCK;
        let held = crate::bytes::get_u16(&image[at..], 32);
        put_u16(&mut image[at..], 32, held & !node_flags::FIXED_SIZE);
        reseal(&mut image, map);
        assert!(matches!(
            Reader::open(Cursor::new(image)),
            Err(ReadError::BadNode { .. })
        ));
    }

    #[test]
    fn a_lookup_compares_a_number_of_keys_that_grows_with_the_log_of_a_node() {
        // One leaf of every record the populated volume holds and more; a search of it by halves
        // compares a handful of keys, where one key at a time compares most of them.
        let mut forge = Forge::populated();
        for i in 0..12u64 {
            forge.add(forge::inode(100 + i, 2, 0o100_644, 0, None, &[]));
        }
        let records = forge.records.len();
        let image = forge.image();
        let tree = Reader::open(Cursor::new(image.clone()))
            .expect("opens")
            .fs_tree;
        let mut container = Container::open(Cursor::new(image)).expect("opens");
        let target = exact(110, record_kind::INODE);
        let compared = std::cell::Cell::new(0usize);
        let counting = |key: &[u8]| {
            compared.set(compared.get() + 1);
            target(key)
        };
        let found = btree::find_at_or_before(&mut container, &tree, &counting)
            .expect("read")
            .expect("a record");
        assert_eq!(KeyHeader::read_from(&found.0).expect("a key").id, 110);
        let point = compared.replace(0);
        // And a range read from the same place, which takes the one record.
        btree::for_each_from(&mut container, &tree, &counting, usize::MAX, &mut |_, _| {
            Ok(false)
        })
        .expect("read");
        let range = compared.get();
        assert!(
            point <= 8 && range <= 8,
            "{point} and {range} of {records} keys compared"
        );
    }

    #[test]
    fn a_directory_of_exactly_the_walk_limit_is_listed() {
        // The root holds seven names, and the record after them, the private directory's
        // inode, is read to find where they end: it is not one the listing takes.
        let forge = Forge::populated();
        let at = |limit| limited(&forge, Limits::new().max_walk_entries(limit));
        let mut reader = at(7);
        let root = reader.root().expect("the root");
        assert_eq!(reader.read_dir(&root).expect("listed").len(), 7);
        let mut reader = at(6);
        let root = reader.root().expect("the root");
        assert!(matches!(
            reader.read_dir(&root),
            Err(ReadError::TooManyEntries { limit: 6 })
        ));
    }

    #[test]
    fn a_lookup_reads_a_directory_only_as_far_as_its_name() {
        // A lookup gathers nothing, so the cap on what a listing gathers is not its business:
        // a directory longer than the cap still resolves every name in it.
        let forge = Forge::populated();
        let options = OpenOptions::new()
            .common(crate::OpenOptions::new().limits(Limits::new().max_walk_entries(2)));
        let mut reader = Reader::open_with(forge.cursor(), &options).expect("opens");
        let root = reader.root().expect("the root");
        assert!(matches!(
            reader.read_dir(&root),
            Err(ReadError::TooManyEntries { limit: 2 })
        ));
        for path in [&b"/hello"[..], b"/sparse", b"/HELLO", b"/dir/hard2"] {
            assert!(
                reader.lookup(path).is_ok(),
                "{} is past the cap and found",
                String::from_utf8_lossy(path)
            );
        }
    }

    #[test]
    fn an_entry_past_the_match_does_not_refuse_a_lookup() {
        // A lookup stops at its name, so an entry it never reads cannot refuse it. One it reads
        // on the way still does, as a listing of the directory does.
        let mut forge = Forge::populated();
        let order: Vec<Vec<u8>> = {
            let mut reader = open(&forge);
            let root = reader.root().expect("the root");
            let entries = reader.read_dir(&root).expect("listed");
            entries.into_iter().map(|e| e.name).collect()
        };
        let (first, last) = (&order[0], &order[order.len() - 1]);
        let key = forge::entry(inode_number::ROOT, last, 0, 0, None).0;
        let record = forge.records.iter_mut().find(|(k, _)| *k == key);
        record.expect("the last entry").1.truncate(10);
        let mut reader = open(&forge);
        assert!(reader.lookup(&[b"/", first.as_slice()].concat()).is_ok());
        let root = reader.root().expect("the root");
        assert!(matches!(
            reader.read_dir(&root),
            Err(ReadError::BadRecord { id: 2, .. })
        ));
        assert!(matches!(
            reader.lookup(&[b"/", last.as_slice()].concat()),
            Err(ReadError::BadRecord { id: 2, .. })
        ));
    }

    #[test]
    fn what_a_read_of_an_inode_refuses_is_a_finding() {
        // Each of these leaves the tree and the volume's counts as they were; each is refused
        // by the read of one inode, so the scan reads every inode as a read of it would.
        let structural = |inode| [(Category::Record, Severity::Structural, Some(inode))];
        // An extent of /hello leaving the container, which its run in the extent-reference tree
        // leaves as well.
        let past_the_end = |inode| {
            [
                (Category::Space, Severity::Structural, None),
                (Category::Record, Severity::Structural, Some(inode)),
            ]
        };
        let mut forge = Forge::populated();
        let hello = forge::extent(16, 0, 0, 0).0;
        forge.records.retain(|(key, _)| key[..8] != hello[..8]);
        forge.extent(16, 0, 2, forge::BLOCKS - 1);
        assert_eq!(scanned(&forge), past_the_end(16));
        // An extent of /hello's attribute stream leaving it.
        let mut forge = Forge::populated();
        let big = forge::extent(40, 0, 0, 0).0;
        forge.records.retain(|(key, _)| key[..8] != big[..8]);
        forge.extent(40, 0, 2, forge::BLOCKS - 1);
        assert_eq!(scanned(&forge), past_the_end(16));
        // An attribute whose flags say neither embedded nor stream.
        let mut forge = Forge::populated();
        forge.add(forge::xattr(16, b"user.odd", 0, b"x"));
        assert_eq!(scanned(&forge), structural(16));
        // A symbolic link without its target.
        let mut forge = Forge::populated();
        let target = forge::xattr(19, b"com.apple.fs.symlink", 0, b"").0;
        forge.records.retain(|(key, _)| *key != target);
        assert_eq!(scanned(&forge), structural(19));
    }

    #[test]
    fn a_link_count_is_judged_only_by_a_walk_that_reached_every_name() {
        // Inode 50 has two names: one in the root, read early, and one in a directory read
        // late whose listing does not parse. The walk stops there, so the second name is never
        // reached, and that is the walk's finding rather than a link count's. The entry that
        // does not parse is the record pass's finding as well, which no walk is needed for.
        let mut forge = Forge::populated();
        let candidates = [&b"a"[..], b"b", b"c", b"d", b"e", b"f", b"g", b"h"];
        let early = candidates.iter().min_by_key(|n| forge::name_hash(n));
        let late = candidates.iter().max_by_key(|n| forge::name_hash(n));
        let (early, late) = (early.expect("a name"), late.expect("a name"));
        let root = inode_number::ROOT;
        forge.entry(root, early, 50, forge::DT_REG, Some(60));
        let mut linked = forge::inode(50, root, 0o100_644, 50, None, &[]);
        put_u32(&mut linked.1, 56, 2);
        forge.add(linked);
        forge.entry(root, late, 51, forge::DT_DIR, None);
        forge.add(forge::inode(51, root, 0o040_755, 0, None, &[]));
        forge.entry(51, b"second", 50, forge::DT_REG, Some(61));
        let mut broken = forge::entry(51, b"broken", 52, forge::DT_REG, None);
        broken.1.truncate(10);
        forge.add(broken);
        forge.settle();
        assert_eq!(
            scanned(&forge),
            [
                (Category::Record, Severity::Structural, Some(51)),
                (Category::Record, Severity::Structural, None)
            ]
        );
    }

    #[test]
    fn an_entry_stored_under_the_wrong_hash_or_a_name_with_none_is_refused_and_found() {
        let mut forge = Forge::populated();
        // The hash is bits 10 to 31 of the word after the header; flip its lowest bit.
        entry_record(&mut forge, 2, b"hello").0[9] ^= 0x04;
        let found = scanned(&forge);
        assert_eq!(found, [(Category::Record, Severity::Integrity, Some(16))]);
        // A name that is not UTF-8 has no hash at all.
        let mut unnamed = Forge::populated();
        let key = &mut entry_record(&mut unnamed, 2, b"hello").0;
        let last = key.len() - 2;
        key[last] = 0xFF;
        let found = scanned(&unnamed);
        assert_eq!(found, [(Category::Record, Severity::Conformance, Some(16))]);
        let bad_name = [&b"/hell"[..], &[0xFF]].concat();
        for (forge, path) in [(forge, &b"/hello"[..]), (unnamed, &bad_name[..])] {
            // A strict read refuses what macOS's lookup by name does not find, wherever it
            // meets it: a lookup reading past it, and a walk.
            let mut reader = open(&forge);
            let err = reader.lookup(path).expect_err("refused");
            assert!(
                matches!(&err, ReadError::BadRecord { id: 2, kind: 9, .. }),
                "{err}"
            );
            assert!(reader.walk().is_err());
            // A lenient one finds it by its stored bytes.
            assert_eq!(
                lenient(forge.image()).lookup(path).expect("found").inode,
                16
            );
        }
    }

    /// The forged container read leniently.
    fn lenient(image: Vec<u8>) -> Reader<Cursor<Vec<u8>>> {
        let common = crate::OpenOptions::new().policy(ReadPolicy::Lenient);
        Reader::open_with(Cursor::new(image), &OpenOptions::new().common(common))
            .expect("opens leniently")
    }

    /// Each finding of a scan as its category, severity and block.
    fn at_blocks(reader: &mut Reader<Cursor<Vec<u8>>>) -> Vec<(Category, Severity, Option<u64>)> {
        reader
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.block))
            .collect()
    }

    /// The inode record of inode `id` in `forge`.
    #[cfg(feature = "lzvn")]
    #[test]
    fn a_compressed_size_the_inode_and_its_header_disagree_on_is_found() {
        let mut forge = Forge::populated();
        let content = pattern(5000, 9);
        forge.compressed_file(b"packed", 70, 8, 5000, &forge::resource_fork(&content), 120);
        assert_eq!(scanned(&forge), []);
        put_u64(&mut inode_record(&mut forge, 70).1, 84, 999_999);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Conformance, Some(70))]
        );
        // A read takes the header's size.
        let mut reader = open(&forge);
        let packed = reader.lookup(b"/packed").expect("found");
        assert_eq!(reader.read_data(&packed).ok(), Some(content));
    }

    fn inode_record(forge: &mut Forge, id: u64) -> &mut (Vec<u8>, Vec<u8>) {
        let key = forge::inode(id, 0, 0, 0, None, &[]).0;
        forge
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the inode's record")
    }

    #[test]
    fn block_zero_at_the_live_transaction_with_other_bytes_is_damage_a_strict_open_refuses() {
        let mut image = Forge::populated().image();
        // A second volume in block zero's list, which the live superblock does not have.
        put_u64(&mut image, 192, 1100);
        reseal(&mut image, 0);
        assert!(matches!(
            Reader::open(Cursor::new(image.clone())),
            Err(ReadError::BlockZeroDisagrees {
                block_zero: BlockZero::Differs {
                    bytes: 2,
                    offset: 192,
                    field: "the volume list"
                },
                live: XID
            })
        ));
        let mut reader = lenient(image);
        assert_eq!(
            reader.container().volumes().len(),
            1,
            "the live list is read"
        );
        assert_eq!(
            at_blocks(&mut reader),
            [(Category::Checkpoint, Severity::Integrity, Some(0))]
        );
    }

    #[test]
    fn the_counters_are_the_one_field_block_zero_may_differ_in() {
        let mut image = Forge::populated().image();
        put_u64(&mut image, 984, 3);
        reseal(&mut image, 0);
        let mut reader = Reader::open(Cursor::new(image)).expect("opens strictly");
        assert_eq!(reader.container().block_zero(), BlockZero::Current);
        assert_eq!(at_blocks(&mut reader), []);
    }

    #[test]
    fn an_older_block_zero_is_an_unclean_unmount_and_not_damage() {
        let mut image = Forge::populated().image();
        put_u64(&mut image, 16, XID - 1);
        reseal(&mut image, 0);
        let mut reader = Reader::open(Cursor::new(image)).expect("opens strictly");
        assert_eq!(
            reader.container().block_zero(),
            BlockZero::Older { xid: XID - 1 }
        );
        assert_eq!(
            at_blocks(&mut reader),
            [(Category::Checkpoint, Severity::Cosmetic, Some(0))]
        );
    }

    #[test]
    fn a_checkpoint_block_zero_records_as_written_is_damage_and_not_an_interrupted_write() {
        let forge = Forge::populated();
        let mut image = forge.image();
        // As in an interrupted write, a superblock at XID + 1 whose checkpoint is not whole;
        // but block zero holds it too, and block zero is written after a checkpoint is.
        let mut newer: ContainerSuperblock = forge.container.clone();
        newer.header.xid = XID + 1;
        newer.checkpoint.desc_index = 2;
        let mut block = vec![0u8; BLOCK];
        newer.write_to(&mut block);
        let block = sealed(block);
        let at = (DESC_BASE + 3) as usize * BLOCK;
        image[at..at + BLOCK].copy_from_slice(&block);
        image[..BLOCK].copy_from_slice(&block);
        assert!(matches!(
            Reader::open(Cursor::new(image.clone())),
            Err(ReadError::BlockZeroDisagrees {
                block_zero: BlockZero::Newer { xid },
                live: XID
            }) if xid == XID + 1
        ));
        let mut reader = lenient(image);
        assert_eq!(reader.container().xid(), XID);
        assert_eq!(
            at_blocks(&mut reader),
            [
                (Category::Checkpoint, Severity::Integrity, Some(0)),
                (
                    Category::Checkpoint,
                    Severity::Integrity,
                    Some(DESC_BASE + 3)
                )
            ]
        );
    }

    /// The forged container with a whole checkpoint at XID + 1 in the ring's next two slots:
    /// its mapping block maps a copy of the space manager at a free block, giving the main free
    /// queue `main_limit` nodes where one is `Some`, and maps every other object as the older
    /// checkpoint does.
    fn after_a_newer_checkpoint(main_limit: Option<u16>) -> Vec<u8> {
        use crate::apfs::ondisk::{CheckpointMap, SpaceManager};
        let forge = Forge::populated();
        let mut image = forge.image();
        let block =
            |image: &[u8], at: u64| image[at as usize * BLOCK..(at as usize + 1) * BLOCK].to_vec();
        let copy = 200;
        assert!(block(&image, copy).iter().all(|b| *b == 0), "a free block");
        let mut sm = block(&image, forge::SPACE_MANAGER_AT);
        let mut manager = SpaceManager::read_from(&sm).expect("the space manager");
        manager.header.xid = XID + 1;
        if let Some(limit) = main_limit {
            manager.free_queues[SpaceManager::MAIN_QUEUE].tree_node_limit = limit;
        }
        manager.write_to(&mut sm);
        let map_at = DESC_BASE + 2;
        let (mut map, mut mappings) =
            CheckpointMap::read_from(&block(&image, DESC_BASE)).expect("the mapping block");
        map.header.oid = map_at;
        map.header.xid = XID + 1;
        mappings
            .iter_mut()
            .find(|m| m.oid == forge.container.space_manager_oid)
            .expect("the space manager's mapping")
            .address = copy;
        let mut mapped = vec![0u8; BLOCK];
        map.write_to(&mappings, &mut mapped);
        let mut newer: ContainerSuperblock = forge.container.clone();
        newer.header.xid = XID + 1;
        newer.checkpoint.desc_index = 2;
        newer.checkpoint.desc_len = 2;
        let mut superblock = vec![0u8; BLOCK];
        newer.write_to(&mut superblock);
        for (at, bytes) in [(copy, sm), (map_at, mapped), (DESC_BASE + 3, superblock)] {
            image[at as usize * BLOCK..(at as usize + 1) * BLOCK].copy_from_slice(&sealed(bytes));
        }
        image
    }

    #[test]
    fn a_newer_checkpoint_whose_space_manager_macos_does_not_load_is_passed_over() {
        // The same checkpoint is live where its space manager gives each queue the node limit a
        // container of its size has: the limit alone passes it over.
        let reader = Reader::open(Cursor::new(after_a_newer_checkpoint(None))).expect("opens");
        assert_eq!(reader.container().xid(), XID + 1);
        assert!(reader.container().passed_over().is_empty());

        let mut image = after_a_newer_checkpoint(Some(2));
        let mut reader = Reader::open(Cursor::new(image.clone())).expect("opens at the older");
        assert_eq!(reader.container().xid(), XID);
        assert_eq!(
            reader.container().passed_over()[0].reason,
            super::super::container::QUEUE_LIMITS
        );
        // Damage, not an interrupted write, though block zero holds the older transaction.
        let found = reader.scan();
        let found: Vec<_> = found
            .anomalies()
            .iter()
            .map(|a| {
                (
                    a.severity,
                    a.block,
                    a.detail.contains("macOS passes it over"),
                )
            })
            .collect();
        assert_eq!(found, [(Severity::Integrity, Some(DESC_BASE + 3), true)]);

        // Block zero written after it: macOS mounts the older checkpoint all the same, so a
        // strict open opens it, and block zero is damage beside the checkpoint.
        let at = (DESC_BASE + 3) as usize * BLOCK;
        let newer = image[at..at + BLOCK].to_vec();
        image[..BLOCK].copy_from_slice(&newer);
        let mut reader = Reader::open(Cursor::new(image)).expect("opens strictly");
        assert_eq!(reader.container().xid(), XID);
        assert_eq!(
            reader.container().block_zero(),
            BlockZero::NotLoaded { xid: XID + 1 }
        );
        assert_eq!(
            at_blocks(&mut reader),
            [
                (Category::Checkpoint, Severity::Integrity, Some(0)),
                (
                    Category::Checkpoint,
                    Severity::Integrity,
                    Some(DESC_BASE + 3)
                )
            ]
        );
    }

    #[test]
    fn a_block_zero_that_does_not_verify_is_damage_a_lenient_read_reports() {
        let mut image = Forge::populated().image();
        image[300] ^= 1;
        assert!(matches!(
            Reader::open(Cursor::new(image.clone())),
            Err(ReadError::BadChecksum { block: 0, .. })
        ));
        let mut reader = lenient(image);
        assert_eq!(reader.container().block_zero(), BlockZero::Unverified);
        assert_eq!(
            at_blocks(&mut reader),
            [(Category::Checkpoint, Severity::Integrity, Some(0))]
        );
    }

    #[test]
    fn two_entries_whose_keys_share_bytes_are_refused() {
        let mut image = Forge::populated().image();
        // The second entry's key offset made the first's: the two keys share their bytes.
        let root = FS_ROOT_AT as usize * BLOCK;
        let first = crate::bytes::get_u16(&image[root..], 56);
        crate::bytes::put_u16(&mut image[root..], 56 + 8, first);
        reseal(&mut image, FS_ROOT_AT);
        let walked = Reader::open(Cursor::new(image)).and_then(|mut r| r.walk());
        assert!(
            matches!(
                walked,
                Err(ReadError::BadNode {
                    block: FS_ROOT_AT,
                    fault: NodeFault::Overlap {
                        index: 1,
                        part: "key"
                    }
                })
            ),
            "{walked:?}"
        );
    }

    #[test]
    fn a_free_list_that_does_not_total_the_unused_bytes_of_its_area_is_a_finding() {
        let mut image = Forge::populated().image();
        let root = FS_ROOT_AT as usize * BLOCK;
        crate::bytes::put_u16(&mut image[root..], 50, 8);
        reseal(&mut image, FS_ROOT_AT);
        assert_eq!(
            at_blocks(&mut lenient(image)),
            [(Category::Tree, Severity::Conformance, Some(FS_ROOT_AT))]
        );
    }

    #[test]
    fn a_root_that_miscounts_its_tree_is_a_finding() {
        let mut image = Forge::populated().image();
        let info = (FS_ROOT_AT as usize + 1) * BLOCK - 40;
        put_u32(&mut image, info + 16, 8);
        put_u64(&mut image, info + 24, 1);
        put_u64(&mut image, info + 32, 2);
        reseal(&mut image, FS_ROOT_AT);
        assert_eq!(
            at_blocks(&mut lenient(image)),
            [(Category::Tree, Severity::Conformance, Some(FS_ROOT_AT)); 3]
        );
    }

    #[test]
    fn a_run_no_extent_covers_is_refused_and_not_read_as_zeros() {
        let mut forge = Forge::populated();
        // /sparse without the extent over its first hole.
        let hole = forge::extent(23, 0, BLOCK as u64, 0).0;
        forge.records.retain(|(k, _)| *k != hole);
        let mut reader = open(&forge);
        let sparse = reader.lookup(b"/sparse").expect("found");
        assert_eq!(
            reader.read_data(&sparse).err(),
            Some(ReadError::BadExtent {
                stream: 23,
                logical: 0,
                block: Some(FS_ROOT_AT),
                fault: UNCOVERED
            })
        );
        // A window its extents do cover still reads.
        let mut buf = vec![0u8; BLOCK];
        assert_eq!(
            reader.read_into(&sparse, BLOCK as u64, &mut buf).ok(),
            Some(BLOCK)
        );
        assert_eq!(buf, pattern(BLOCK, 4));
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Structural, Some(23)); 2]
        );
    }

    #[test]
    fn an_extent_moved_from_where_its_stream_begins_is_refused_and_not_read_as_zeros() {
        let mut forge = Forge::populated();
        let key = forge::extent(20, 0, BLOCK as u64, DATA_AT + 2).0;
        let record = forge
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the extent");
        record.0[8..16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        let mut reader = open(&forge);
        let hard = reader.lookup(b"/hard1").expect("found");
        assert!(matches!(
            reader.read_data(&hard),
            Err(ReadError::BadExtent {
                stream: 20,
                logical: 0,
                ..
            })
        ));
    }

    #[test]
    fn extents_covering_less_than_the_allocation_are_a_finding() {
        let mut forge = Forge::populated();
        // /hello's data stream, its last field, records three blocks allocated, and its extents
        // cover two.
        let record = inode_record(&mut forge, 16);
        let at = record.1.len() - 40 + 8;
        put_u64(&mut record.1, at, 3 * BLOCK as u64);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Conformance, Some(16))]
        );
    }

    #[test]
    fn a_stream_longer_than_its_allocation_is_a_finding_and_a_read_past_it_is_refused() {
        let mut forge = Forge::populated();
        // /hello's data stream, its last field, made three blocks long over two allocated.
        let record = inode_record(&mut forge, 16);
        let at = record.1.len() - 40;
        put_u64(&mut record.1, at, 3 * BLOCK as u64);
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.read_data(&hello).err(),
            Some(ReadError::BadExtent {
                stream: 16,
                logical: 2 * BLOCK as u64,
                block: None,
                fault: UNCOVERED
            })
        );
        assert_eq!(
            scanned(&forge),
            [
                (Category::Record, Severity::Conformance, Some(16)),
                (Category::Record, Severity::Structural, Some(16))
            ]
        );
    }

    #[test]
    fn a_stream_with_an_allocation_and_no_reference_record_is_a_finding() {
        let mut forge = Forge::populated();
        let reference = forge::stream_reference(20, 1).0;
        forge.records.retain(|(k, _)| *k != reference);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Integrity, Some(20))]
        );
    }

    /// Each finding of a scan as its category, severity, block and inode.
    fn located(forge: &Forge) -> Vec<(Category, Severity, Option<u64>, Option<u64>)> {
        open(forge)
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.block, a.inode))
            .collect()
    }

    #[test]
    fn an_extent_of_a_file_never_cloned_in_a_run_another_record_wrote_is_a_finding() {
        // /hard1's one run, recorded as written by a record that is not its stream or inode.
        let mut forge = Forge::populated();
        forge.owners.insert(20, 99);
        assert_eq!(
            located(&forge),
            [(
                Category::Record,
                Severity::Integrity,
                Some(DATA_AT + 2),
                Some(20)
            )]
        );
        // A file that has been cloned may use blocks another record wrote.
        let mut cloned = forge.clone();
        mark_cloned(&mut cloned, 20);
        assert_eq!(located(&cloned), []);
        // So may any file where the flag is not exact: an inode no later than the epoch, and a
        // volume written since by an implementation that does not keep the flag.
        let mut early = forge.clone();
        early.volume.clone_info_epoch = 20;
        assert_eq!(located(&early), []);
        let mut stale = forge.clone();
        stale.volume.clone_info_xid = XID - 1;
        assert_eq!(located(&stale), []);
        let mut unkept = forge;
        unkept.volume.clone_info_xid = 0;
        unkept.volume.modified_by[0].last_xid = 0;
        assert_eq!(located(&unkept), []);
    }

    #[test]
    fn two_extents_of_files_never_cloned_that_trade_places_are_a_finding() {
        // /hard1's block and /sparse's stored block swapped, which leaves every block's count as
        // it was: only who wrote each run says the two moved.
        let mut forge = Forge::populated();
        forge.references = Some(forge.derived_references());
        let swapped = |forge: &mut Forge, stream: u64, from: u64, to: u64| {
            let (key, value) = forge::extent(
                stream,
                if stream == 23 { BLOCK as u64 } else { 0 },
                BLOCK as u64,
                from,
            );
            let record = forge
                .records
                .iter_mut()
                .find(|(k, v)| *k == key && *v == value)
                .expect("the extent");
            put_u64(&mut record.1, 8, to);
        };
        swapped(&mut forge, 20, DATA_AT + 2, DATA_AT + 3);
        swapped(&mut forge, 23, DATA_AT + 3, DATA_AT + 2);
        assert_eq!(
            located(&forge),
            [
                (
                    Category::Record,
                    Severity::Integrity,
                    Some(DATA_AT + 3),
                    Some(20)
                ),
                (
                    Category::Record,
                    Severity::Integrity,
                    Some(DATA_AT + 2),
                    Some(23)
                ),
            ]
        );
        // Between files that have been cloned, no record says which inodes share a block, so
        // the same swap is not seen.
        mark_cloned(&mut forge, 20);
        mark_cloned(&mut forge, 23);
        assert_eq!(located(&forge), []);
    }

    /// Mark inode `id` of `forge` as cloned, as macOS marks both a clone and the inode cloned.
    fn mark_cloned(forge: &mut Forge, id: u64) {
        let value = &mut inode_record(forge, id).1;
        let flags = get_u64(value, 48) | INTERNAL_EVER_CLONED;
        put_u64(value, 48, flags);
    }

    /// Where a clone and its source stand.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Life {
        /// The clone has written its first block and shares its second with the source.
        Written,
        /// The source has since been removed.
        SourceRemoved,
        /// The source has since written its second block elsewhere.
        SourceOverwritten,
    }

    /// The source's first block, the block the two share, the clone's own, and where the
    /// source wrote its second block again.
    const LIFE: [u64; 4] = [DATA_AT + 8, DATA_AT + 9, DATA_AT + 10, DATA_AT + 11];

    /// The populated volume with `/src`, inode and stream 50, two blocks, and `/cl`, inode 51,
    /// a clone of it written since it was made, with stream 52 of its own: as macOS 14 to 27
    /// record each stage of their life. Both inodes are marked as cloned; each run is recorded
    /// as written by the record that wrote it, which it keeps naming after that record stops
    /// using it or is removed; and the run the two share has a count of two while both use it.
    fn clone_life(life: Life) -> Forge {
        let [first, shared, own, again] = LIFE;
        let mut f = Forge::populated();
        let mut references = f.derived_references();
        let root = inode_number::ROOT;
        if life != Life::SourceRemoved {
            let second = if life == Life::SourceOverwritten {
                again
            } else {
                shared
            };
            f.entry(root, b"src", 50, forge::DT_REG, None);
            f.add(forge::inode(
                50,
                root,
                0o100_644,
                50,
                Some(2 * BLOCK as u64),
                &[],
            ));
            mark_cloned(&mut f, 50);
            f.extent(50, 0, 1, first);
            f.extent(50, BLOCK as u64, 1, second);
            f.add(forge::stream_reference(50, 1));
            f.data_blocks(first, &pattern(BLOCK, 8));
            f.data_blocks(again, &pattern(BLOCK, 11));
        }
        f.entry(root, b"cl", 51, forge::DT_REG, None);
        f.add(forge::inode(
            51,
            root,
            0o100_644,
            52,
            Some(2 * BLOCK as u64),
            &[],
        ));
        mark_cloned(&mut f, 51);
        f.extent(52, 0, 1, own);
        f.extent(52, BLOCK as u64, 1, shared);
        f.add(forge::stream_reference(52, 1));
        f.data_blocks(own, &pattern(BLOCK, 10));
        f.data_blocks(shared, &pattern(BLOCK, 9));
        references.extend(match life {
            Life::Written => vec![
                Reference::run(first, 1, 50, 1),
                Reference::run(shared, 1, 50, 2),
                Reference::run(own, 1, 51, 1),
            ],
            Life::SourceRemoved => vec![
                Reference::run(shared, 1, 50, 1),
                Reference::run(own, 1, 51, 1),
            ],
            Life::SourceOverwritten => vec![
                Reference::run(first, 1, 50, 1),
                Reference::run(shared, 1, 50, 1),
                Reference::run(own, 1, 51, 1),
                Reference::run(again, 1, 50, 1),
            ],
        });
        f.references = Some(references);
        f.settle();
        f
    }

    /// `forge`'s run at `start`, in the volume's tree.
    fn run_at(forge: &mut Forge, start: u64) -> &mut Reference {
        forge
            .references
            .as_mut()
            .and_then(|references| references.iter_mut().find(|r| r.start == start))
            .expect("the run")
    }

    #[test]
    fn a_symbolic_link_is_the_size_of_its_target() {
        // The target is kept in an attribute rather than a data stream, and macOS's `lstat`
        // reports its length as the link's size.
        let mut reader = open(&Forge::populated());
        let link = reader.lookup_no_follow(b"/link").expect("the link");
        assert_eq!(reader.link_target(&link).expect("its target"), b"hello");
        assert_eq!(link.size(), 5);
    }

    #[test]
    fn a_clone_and_its_source_scan_clean_through_the_life_macos_gives_them() {
        for life in [Life::Written, Life::SourceRemoved, Life::SourceOverwritten] {
            let forge = clone_life(life);
            assert_eq!(scanned(&forge), [], "{life:?}");
            let mut reader = open(&forge);
            let clone = reader.lookup(b"/cl").expect("the clone");
            let mut want = pattern(BLOCK, 10);
            want.extend_from_slice(&pattern(BLOCK, 9));
            assert_eq!(
                reader.read_data(&clone).expect("read the clone"),
                want,
                "{life:?}"
            );
            if life != Life::SourceRemoved {
                let source = reader.lookup(b"/src").expect("the source");
                let mut want = pattern(BLOCK, 8);
                let second = if life == Life::Written { 9 } else { 11 };
                want.extend_from_slice(&pattern(BLOCK, second));
                assert_eq!(reader.read_data(&source).expect("read the source"), want);
            }
        }
    }

    #[test]
    fn blocks_more_streams_use_than_their_count_says_are_a_finding() {
        let [_, shared, ..] = LIFE;
        // The run the clone and its source share, recorded with a count of one.
        let mut forge = clone_life(Life::Written);
        run_at(&mut forge, shared).count = 1;
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Record, Severity::Integrity, Some(shared))]
        );
        // A third file's extent moved into that run, whose count of two still says shared.
        let mut forge = clone_life(Life::Written);
        forge.entry(inode_number::ROOT, b"third", 53, forge::DT_REG, None);
        forge.add(forge::inode(
            53,
            inode_number::ROOT,
            0o100_644,
            53,
            Some(BLOCK as u64),
            &[],
        ));
        forge.extent(53, 0, 1, shared);
        forge.add(forge::stream_reference(53, 1));
        forge.settle();
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Record, Severity::Integrity, Some(shared))]
        );
    }

    #[test]
    fn a_count_no_stream_accounts_for_is_a_finding() {
        let [_, shared, ..] = LIFE;
        // A count one too high, and a run no extent uses.
        let mut forge = clone_life(Life::Written);
        run_at(&mut forge, shared).count = 3;
        let unused = DATA_AT + 20;
        if let Some(references) = forge.references.as_mut() {
            references.push(Reference::run(unused, 2, 50, 1));
        }
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [
                (Category::Record, Severity::Conformance, Some(shared)),
                (Category::Record, Severity::Conformance, Some(unused)),
            ]
        );
        // A change that takes a count below zero: a tree records one change for a block where
        // an earlier tree records its run, and this one records none.
        let mut forge = clone_life(Life::Written);
        if let Some(references) = forge.references.as_mut() {
            references.retain(|run| run.start != LIFE[0]);
            references.push(Reference::change(LIFE[0], 1, -1));
        }
        let report = open(&forge).scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| {
                (
                    a.category,
                    a.severity,
                    a.block,
                    a.detail.contains("no run can have"),
                )
            })
            .collect();
        assert_eq!(
            found,
            [(Category::Record, Severity::Integrity, Some(LIFE[0]), true)]
        );
    }

    /// `/src` written and kept by a snapshot, then cloned and the clone written, as macOS 14 to
    /// 27 record it: the snapshot's tree holds the source's runs, and the volume's holds the
    /// clone's own run and a change of one to the count of the run the two now share.
    fn cloned_after_a_snapshot() -> Forge {
        let [first, shared, own, _] = LIFE;
        let mut f = clone_life(Life::Written);
        let kept: Vec<_> = f
            .records
            .iter()
            .filter(|(key, _)| {
                let word = u64::from_le_bytes(key[..8].try_into().expect("a key header"));
                let id = word & 0x0FFF_FFFF_FFFF_FFFF;
                !(id == 51 || id == 52 || (id == inode_number::ROOT && key.ends_with(b"cl\0")))
            })
            .cloned()
            .collect();
        f.snapshot = Some((b"before".to_vec(), kept));
        let mut before = f.references.clone().expect("the runs");
        before.retain(|r| r.start != shared && r.start != own);
        before.push(Reference::run(shared, 1, 50, 1));
        let _ = first;
        f.snapshot_references = Some(before);
        f.references = Some(vec![
            Reference::change(shared, 1, 1),
            Reference::run(own, 1, 51, 1),
        ]);
        f
    }

    #[test]
    fn a_clone_made_after_a_snapshot_is_counted_over_both_trees() {
        let forge = cloned_after_a_snapshot();
        assert_eq!(scanned(&forge), []);
        // The snapshot is held to its own tree alone, before the clone.
        let mut snapshot = open(&forge).at_snapshot(b"before").expect("the snapshot");
        assert!(snapshot.lookup(b"/cl").is_err());
        assert_eq!(at_blocks(&mut snapshot), []);
        // Without the change, the volume counts one stream where two use the block.
        let mut forge = cloned_after_a_snapshot();
        if let Some(references) = forge.references.as_mut() {
            references.retain(|r| r.kind == 1);
        }
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Record, Severity::Integrity, Some(LIFE[1]))]
        );
    }

    #[test]
    fn an_extent_whose_block_was_moved_is_a_finding() {
        let forge = Forge::populated();
        let mut image = forge.image();
        // /hard1's extent, one block at DATA_AT + 2, pointed at the block after it.
        let mut value = forge::extent(20, 0, BLOCK as u64, DATA_AT + 2).1;
        let root = FS_ROOT_AT as usize * BLOCK;
        let at = root
            + image[root..root + BLOCK]
                .windows(value.len())
                .position(|w| w == value.as_slice())
                .expect("the extent's value");
        put_u64(&mut value, 8, DATA_AT + 3);
        image[at..at + value.len()].copy_from_slice(&value);
        reseal(&mut image, FS_ROOT_AT);
        assert_eq!(
            at_blocks(&mut lenient(image)),
            [
                (Category::Record, Severity::Conformance, Some(DATA_AT + 2)),
                (Category::Record, Severity::Integrity, Some(DATA_AT + 3)),
            ]
        );
    }

    #[test]
    fn a_volume_without_an_extent_reference_tree_is_a_finding() {
        let mut image = Forge::populated().image();
        put_u64(&mut image, VOLUME_AT as usize * BLOCK + 144, 0);
        reseal(&mut image, VOLUME_AT);
        // The tree's block is still marked in use, and still counted as the volume's own.
        assert_eq!(
            at_blocks(&mut lenient(image)),
            [
                (Category::Space, Severity::Conformance, None),
                (
                    Category::Space,
                    Severity::Conformance,
                    Some(forge::EXTENT_REF_AT)
                ),
                (Category::Volume, Severity::Conformance, Some(DATA_AT))
            ]
        );
    }

    #[test]
    fn a_volume_with_a_snapshot_scans_clean_as_it_is() {
        assert_eq!(scanned(&Forge::with_snapshot()), []);
    }

    #[test]
    fn an_entry_no_walk_reaches_is_held_to_its_name_and_hash() {
        let mut forge = Forge::populated();
        // macOS keeps entries for the root and the private directory under their parent,
        // which no path reaches.
        let parent = inode_number::ROOT_PARENT;
        let mut root = forge::entry(parent, b"root", 2, forge::DT_DIR, None);
        root.0[9] ^= 0x04;
        forge.add(root);
        let mut private = forge::entry(parent, b"private-dir", 3, forge::DT_DIR, None);
        let last = private.0.len() - 2;
        private.0[last] = 0xFF;
        forge.add(private);
        let found = scanned(&forge);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.contains(&(Category::Record, Severity::Integrity, Some(2))));
        assert!(found.contains(&(Category::Record, Severity::Conformance, Some(3))));
    }

    #[test]
    fn a_directory_no_walk_reaches_is_held_to_its_child_count() {
        let mut forge = Forge::populated();
        // An entry in the private directory, which no path reaches, after its count was taken.
        forge.add(forge::inode(
            60,
            inode_number::PRIVATE,
            0o100_644,
            0,
            None,
            &[],
        ));
        forge.entry(inode_number::PRIVATE, b"kept", 60, forge::DT_REG, None);
        forge.volume.file_count += 1;
        assert_eq!(
            scanned(&forge),
            [(
                Category::Volume,
                Severity::Conformance,
                Some(inode_number::PRIVATE)
            )]
        );
    }

    #[test]
    fn a_record_no_walk_reaches_is_held_to_what_a_read_of_it_refuses() {
        type Shape = fn(u64) -> (Vec<u8>, Vec<u8>);
        let entries: [(Shape, u64); 3] = [
            // Extended fields claiming a hundred bytes the value does not hold.
            (
                |parent| {
                    let mut e = forge::entry(parent, b"framed", 18, forge::DT_REG, None);
                    e.1.extend_from_slice(&[1, 0, 0, 0, 1, 0, 100, 0]);
                    e
                },
                18,
            ),
            (
                |parent| forge::entry(parent, b"nes/ed", 18, forge::DT_REG, None),
                18,
            ),
            (
                |parent| forge::entry(parent, b"gone", 999, forge::DT_REG, None),
                999,
            ),
        ];
        let attributes: [Shape; 3] = [
            |id| {
                let mut a = forge::xattr(id, b"user.x", xattr_flags::EMBEDDED, b"v");
                *a.0.last_mut().expect("a name") = b'!';
                a
            },
            // Data that reads as a stream, so only the flags are wrong.
            |id| forge::xattr(id, b"user.both", 0x3, &[0; 48]),
            |id| forge::xattr(id, b"user.none", 0x0, b"v"),
        ];
        // Each as a record no walk reaches — an entry under the root's parent, where macOS
        // keeps only the root's and the private directory's, and an attribute of the private
        // directory — and as one a walk reaches.
        let mut cases: Vec<(Shape, u64, u64, u64)> = Vec::new();
        for (shape, inode) in entries {
            cases.push((shape, inode_number::ROOT_PARENT, inode_number::ROOT, inode));
        }
        // /dir/nested holds no other attribute, so no name of its is compared with another's.
        for shape in attributes {
            cases.push((shape, inode_number::PRIVATE, 18, 0));
        }
        for (i, (shape, unreached, reached, inode)) in cases.into_iter().enumerate() {
            let inode = |at: u64| if inode == 0 { at } else { inode };
            let mut forge = Forge::populated();
            forge.add(shape(unreached));
            forge.settle();
            let want = (
                Category::Record,
                Severity::Structural,
                Some(inode(unreached)),
            );
            assert_eq!(scanned(&forge), [want], "{i}: where no walk reaches it");
            let mut forge = Forge::populated();
            forge.add(shape(reached));
            forge.settle();
            let want = (Category::Record, Severity::Structural, Some(inode(reached)));
            assert!(scanned(&forge).contains(&want), "{i}: where a walk does");
        }
    }

    #[test]
    fn a_name_longer_than_macos_makes_and_a_sibling_record_that_does_not_parse_are_found() {
        // macOS refuses a name of more than 255 UTF-16 units (observed, macOS 15, 26 and 27).
        for (len, found) in [(255, false), (256, true)] {
            let mut forge = Forge::populated();
            forge.add(forge::inode(60, 2, 0o100_644, 0, None, &[]));
            forge.entry(2, &vec![b'a'; len], 60, forge::DT_REG, None);
            forge.settle();
            let want = if found {
                vec![(Category::Record, Severity::Conformance, Some(60))]
            } else {
                Vec::new()
            };
            assert_eq!(scanned(&forge), want, "{len}");
        }
        // A sibling-link record of `/hard1`'s inode whose value is shorter than its fields.
        let mut forge = Forge::populated();
        let mut key = forge::inode(20, 0, 0, 0, None, &[]).0;
        key[7] = (key[7] & 0x0F) | (record_kind::SIBLING_LINK << 4);
        key.extend_from_slice(&30u64.to_le_bytes());
        forge.add((key, vec![2, 0, 0]));
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Structural, Some(20))]
        );
    }

    #[test]
    fn a_container_longer_than_its_source_or_of_no_format_version_is_a_finding() {
        // Half the image: every block the forge uses is in the first half, so the container
        // reads, and it says it is twice what the source holds.
        let mut image = Forge::populated().image();
        image.truncate(image.len() / 2);
        let found: Vec<_> = Reader::open(Cursor::new(image))
            .expect("opens")
            .scan()
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity))
            .collect();
        assert_eq!(found, [(Category::Checkpoint, Severity::Structural)]);
        // No format version: refused strictly, read leniently as the second, and found.
        let mut forge = Forge::populated();
        forge.container.incompatible_features = 0;
        assert!(matches!(
            Container::open(forge.cursor()),
            Err(ReadError::BadGeometry { value: 0, .. })
        ));
        let found = at_blocks(&mut lenient(forge.image()));
        assert_eq!(
            found,
            [(
                Category::Checkpoint,
                Severity::Conformance,
                Some(DESC_BASE + 1)
            )]
        );
    }

    #[test]
    fn two_whole_checkpoints_of_one_transaction_are_found() {
        // The checkpoint at slots 0 and 1 again at slots 2 and 3, its superblock saying so.
        let forge = Forge::populated();
        let mut image = forge.image();
        let map = image[DESC_BASE as usize * BLOCK..][..BLOCK].to_vec();
        image[(DESC_BASE + 2) as usize * BLOCK..][..BLOCK].copy_from_slice(&map);
        put_u64(
            &mut image[(DESC_BASE + 2) as usize * BLOCK..],
            8,
            DESC_BASE + 2,
        );
        reseal(&mut image, DESC_BASE + 2);
        let mut again: ContainerSuperblock = forge.container.clone();
        again.checkpoint.desc_index = 2;
        let mut block = vec![0u8; BLOCK];
        again.write_to(&mut block);
        image[(DESC_BASE + 3) as usize * BLOCK..][..BLOCK].copy_from_slice(&sealed(block));
        let mut reader = lenient(image);
        assert_eq!(reader.container().passed_over().len(), 1);
        let found: Vec<_> = reader
            .scan()
            .anomalies()
            .iter()
            .map(|a| {
                (
                    a.category,
                    a.severity,
                    a.block,
                    a.detail.contains("two whole"),
                )
            })
            .collect();
        assert_eq!(
            found,
            [(
                Category::Checkpoint,
                Severity::Integrity,
                Some(DESC_BASE + 3),
                true
            )]
        );
    }

    #[test]
    fn an_inode_recording_compressed_content_without_the_flag_saying_so_is_found() {
        // The size of compressed content recorded, beside the flag saying no resource fork is
        // held, and no UF_COMPRESSED among the BSD flags.
        let mut forge = Forge::populated();
        let record = inode_record(&mut forge, 18);
        put_u64(&mut record.1, 48, 0x8000 | 0x4_0000);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Integrity, Some(18))]
        );
    }

    #[test]
    fn a_truncation_the_last_driver_did_not_finish_is_found() {
        // The internal flag, and the field recording the size before it (reference pp. 90, 111).
        let mut flagged = Forge::populated();
        let record = inode_record(&mut flagged, 18);
        put_u64(&mut record.1, 48, 0x8000 | 0x80);
        let mut sized = Forge::populated();
        let prior = [(5, 4096u64.to_le_bytes().to_vec())];
        *inode_record(&mut sized, 18) = forge::inode(18, 17, 0o100_600, 0, None, &prior);
        for forge in [flagged, sized] {
            assert_eq!(
                scanned(&forge),
                [(Category::Record, Severity::Cosmetic, Some(18))]
            );
        }
    }

    #[test]
    fn a_snapshot_tree_that_miscounts_itself_is_a_finding() {
        let mut image = Forge::with_snapshot().image();
        // The root's record count, in the information at the end of its block.
        let at = forge::SNAPSHOT_TREE_AT;
        put_u64(
            &mut image[at as usize * BLOCK..],
            BLOCK - TREE_INFO_SIZE + 24,
            5,
        );
        reseal(&mut image, at);
        let found: Vec<_> = Reader::open(Cursor::new(image))
            .expect("opens")
            .scan()
            .anomalies()
            .iter()
            .map(|a| {
                (
                    a.category,
                    a.severity,
                    a.block,
                    a.detail.contains("snapshot tree"),
                )
            })
            .collect();
        assert_eq!(
            found,
            [(Category::Tree, Severity::Conformance, Some(at), true)]
        );
    }

    #[test]
    fn extended_fields_recording_other_than_the_bytes_they_take_are_a_finding() {
        let mut forge = Forge::populated();
        let record = inode_record(&mut forge, 16);
        put_u16(&mut record.1, InodeValue::SIZE + 2, 48);
        assert_eq!(
            scanned(&forge),
            [(Category::Record, Severity::Conformance, Some(16))]
        );
    }

    /// A data stream field: `size` bytes, `allocated` allocated, and `extra` bytes past the
    /// forty its type takes.
    fn stream_field(size: u64, allocated: u64, extra: usize) -> (u8, Vec<u8>) {
        let mut data = vec![0u8; DataStream::SIZE + extra];
        put_u64(&mut data, 0, size);
        put_u64(&mut data, 8, allocated);
        (inode_field::DATA_STREAM, data)
    }

    /// The directory entry record of `parent` named `name` in `forge`.
    fn entry_record<'f>(
        forge: &'f mut Forge,
        parent: u64,
        name: &[u8],
    ) -> &'f mut (Vec<u8>, Vec<u8>) {
        let key = forge::entry(parent, name, 0, 0, None).0;
        forge
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the entry's record")
    }

    #[test]
    fn an_extended_field_met_twice_or_of_another_size_than_its_type_is_refused_and_found() {
        let mut cases: Vec<(Forge, &[u8], Severity, u64)> = Vec::new();
        // A second data stream field, the first forged to 100 bytes of a 5000-byte file.
        let mut forge = Forge::populated();
        let first = [stream_field(100, 8192, 0)];
        *inode_record(&mut forge, 16) = forge::inode(16, 2, 0o100_644, 16, Some(5000), &first);
        cases.push((forge, b"/hello", Severity::Integrity, 16));
        // A data stream, and a device number, each longer than its type.
        let mut forge = Forge::populated();
        let longer = [stream_field(5000, 8192, 8)];
        *inode_record(&mut forge, 16) = forge::inode(16, 2, 0o100_644, 16, None, &longer);
        cases.push((forge, b"/hello", Severity::Structural, 16));
        let mut forge = Forge::populated();
        let device = [(inode_field::DEVICE, 0x0300_0004u64.to_le_bytes().to_vec())];
        *inode_record(&mut forge, 22) = forge::inode(22, 2, 0o020_644, 0, None, &device);
        cases.push((forge, b"/cdev", Severity::Structural, 22));
        // An entry's sibling identifier given twice, and given in four bytes.
        for (fields, severity) in [
            (
                vec![(1, 30u64.to_le_bytes().to_vec()); 2],
                Severity::Integrity,
            ),
            (
                vec![(1, 30u32.to_le_bytes().to_vec())],
                Severity::Structural,
            ),
        ] {
            let mut forge = Forge::populated();
            let record = entry_record(&mut forge, 2, b"hard1");
            record.1.truncate(EntryValue::SIZE);
            record.1.extend_from_slice(&forge::blob(&fields));
            cases.push((forge, b"/hard1", severity, 20));
        }
        for (i, (forge, path, severity, inode)) in cases.into_iter().enumerate() {
            let err = open(&forge)
                .lookup(path)
                .expect_err("a strict read refuses it");
            assert!(
                matches!(&err, ReadError::BadRecord { fault, .. } if fault.contains("type")),
                "{i}: {err}"
            );
            let mut reader = lenient(forge.image());
            let node = reader.lookup(path).expect("a lenient read reads past it");
            if i == 0 {
                // The first of the two.
                assert_eq!(node.size(), 100);
            }
            let found: Vec<_> = reader
                .scan()
                .anomalies()
                .iter()
                .filter(|a| a.detail.contains("extended field of type"))
                .map(|a| (a.category, a.severity, a.inode))
                .collect();
            assert_eq!(found, [(Category::Record, severity, Some(inode))], "{i}");
        }
    }

    #[test]
    fn a_device_node_without_its_device_number_is_refused_and_found() {
        let mut forge = Forge::populated();
        *inode_record(&mut forge, 22) = forge::inode(22, 2, 0o020_644, 0, None, &[]);
        let err = open(&forge)
            .lookup(b"/cdev")
            .expect_err("a strict read refuses it");
        assert!(
            matches!(&err, ReadError::BadRecord { id: 22, fault, .. } if fault.contains("device")),
            "{err}"
        );
        let mut reader = lenient(forge.image());
        assert_eq!(reader.lookup(b"/cdev").expect("read past").device, None);
        assert_eq!(
            reader
                .scan()
                .anomalies()
                .iter()
                .map(|a| (a.category, a.severity, a.inode))
                .collect::<Vec<_>>(),
            [(Category::Record, Severity::Structural, Some(22))]
        );
    }

    #[test]
    fn a_field_of_a_type_this_reader_does_not_know_is_noted_once_and_skipped() {
        let mut forge = Forge::populated();
        let fields = [(17, vec![1; 4]), (40, vec![2; 4])];
        forge.add(forge::inode(60, 2, 0o100_644, 0, None, &fields));
        forge.entry(2, b"fields", 60, forge::DT_REG, None);
        forge.settle();
        let report = open(&forge).scan();
        let found = report.anomalies();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            (found[0].category, found[0].severity),
            (Category::Record, Severity::Cosmetic)
        );
        assert!(found[0].detail.contains("type 40"), "{}", found[0].detail);
    }

    #[test]
    fn an_inode_name_field_is_held_to_being_a_utf8_name_and_its_terminator() {
        for (name, clean) in [
            (&b"named\0"[..], true),
            (b"bad\xff\0", false),
            (b"unended", false),
        ] {
            let mut forge = Forge::populated();
            let fields = [(inode_field::NAME, name.to_vec())];
            forge.add(forge::inode(60, 2, 0o100_644, 0, None, &fields));
            forge.entry(2, b"named", 60, forge::DT_REG, None);
            forge.settle();
            let want = if clean {
                vec![]
            } else {
                vec![(Category::Record, Severity::Conformance, Some(60))]
            };
            assert_eq!(scanned(&forge), want, "{name:?}");
        }
    }

    #[test]
    fn a_volume_whose_keys_once_rolled_reads_as_the_plain_volume_it_is() {
        // macOS sets the bit when it first encrypts a volume and leaves it set through every
        // decryption after, so a plain volume carrying it is one macOS writes.
        let mut plain = open(&Forge::populated());
        let mut forge = Forge::populated();
        forge.volume.incompatible_features |=
            crate::apfs::ondisk::volume_incompat::ENCRYPTION_ROLLED;
        let mut rolled = open(&forge);
        assert_eq!(paths(&mut rolled), paths(&mut plain));
        let hello = rolled.lookup(b"/hello").expect("found");
        let want = plain.read_data(&hello).expect("reads");
        assert_eq!(rolled.read_data(&hello).expect("reads"), want);
        assert_eq!(rolled.scan().anomalies(), []);
        // An encrypted volume carrying it is still the encrypted volume it is.
        forge.volume.flags = 0;
        assert!(matches!(
            Reader::open(forge.cursor()),
            Err(ReadError::Encrypted { slot: 0 })
        ));
    }

    #[test]
    fn a_volume_whose_encryption_is_being_changed_is_refused() {
        let mut forge = Forge::populated();
        forge.volume.encryption_rolling_oid = 1090;
        let err = Reader::open(forge.cursor()).err();
        assert_eq!(err, Some(ReadError::EncryptionChanging { slot: 0 }));
        // A volume in a state this build does not read, rather than a malformed one.
        assert!(matches!(
            err.map(TreeError::from),
            Some(TreeError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_volume_with_a_revert_pending_is_refused_by_name() {
        // Each of the three ways the volume and its object map record a revert not yet carried
        // out: to a snapshot's transaction, to a superblock, and the map's range of
        // transactions being undone.
        let mut forge = Forge::populated();
        forge.volume.revert_to_xid = 7;
        let mut images = vec![forge.image()];
        let mut forge = Forge::populated();
        forge.volume.revert_to_superblock = 40;
        images.push(forge.image());
        for (at, value) in [(72, 8u64), (80, 11u64)] {
            let mut image = Forge::populated().image();
            let map = forge::VOLUME_MAP_AT;
            put_u64(&mut image[map as usize * BLOCK..], at, value);
            reseal(&mut image, map);
            images.push(image);
        }
        for (i, image) in images.into_iter().enumerate() {
            let err = Reader::open(Cursor::new(image)).err();
            assert_eq!(err, Some(ReadError::RevertPending { slot: 0 }), "{i}");
            assert!(
                matches!(
                    err.map(TreeError::from),
                    Some(TreeError::Unsupported { .. })
                ),
                "{i}"
            );
        }
    }

    #[test]
    fn the_containers_account_of_itself_is_held_to_what_it_holds() {
        let live = Some(DESC_BASE + 1);
        type Change = fn(&mut Forge);
        let words: [(Change, usize); 5] = [
            // The next object identifier at one the volume's object map holds.
            (|f| f.container.next_oid = forge::FS_ROOT_OID, 1),
            // The next transaction at the live one.
            (|f| f.container.next_xid = XID, 1),
            (|f| f.container.uuid = [0; 16], 1),
            // A container of 1 MiB holds one volume, and says it holds more.
            (|f| f.container.max_volumes = 2, 1),
            // Or says it holds none, and lists one.
            (|f| f.container.max_volumes = 0, 2),
        ];
        for (i, (change, count)) in words.into_iter().enumerate() {
            let mut forge = Forge::populated();
            change(&mut forge);
            assert_eq!(
                at_blocks(&mut open(&forge)),
                vec![(Category::Checkpoint, Severity::Conformance, live); count],
                "{i}"
            );
        }
        let mut forge = Forge::populated();
        forge.volume.uuid = [0; 16];
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Volume, Severity::Conformance, Some(VOLUME_AT))]
        );
    }

    #[test]
    fn volume_words_that_disagree_with_the_volume_are_findings() {
        let mut forge = Forge::populated();
        forge.volume.root_tree_type = 0x4000_0002;
        forge.volume.flags |= 0x400;
        forge.volume.snapshot_count = 2;
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Volume, Severity::Conformance, Some(VOLUME_AT)); 3]
        );
    }

    #[test]
    fn a_volume_roots_only_from_a_snapshot_it_holds() {
        // The snapshot's own transaction, then one no snapshot is recorded in, then one with no
        // snapshot at all.
        let held = crate::apfs::forge::SNAPSHOT_XID;
        for (snapshot, root_to, found) in [(true, held, 0), (true, held + 1, 1), (false, held, 1)] {
            let mut forge = if snapshot {
                Forge::with_snapshot()
            } else {
                Forge::populated()
            };
            forge.volume.root_to_xid = root_to;
            assert_eq!(
                at_blocks(&mut open(&forge)),
                vec![(Category::Volume, Severity::Conformance, Some(VOLUME_AT)); found],
                "snapshot {snapshot}, roots from {root_to}"
            );
        }
    }

    /// The forged container's volume, read under `limits`.
    fn limited(forge: &Forge, limits: Limits) -> Reader<Cursor<Vec<u8>>> {
        let options = OpenOptions::new().common(crate::OpenOptions::new().limits(limits));
        Reader::open_with(forge.cursor(), &options).expect("opens")
    }

    /// Every record of the file-system tree visited in order, or the first refusal.
    fn every_record(image: Vec<u8>) -> Result<(), ReadError> {
        let mut reader = Reader::open(Cursor::new(image))?;
        let tree = reader.fs_tree;
        btree::for_each(&mut reader.container, &tree, &mut |_, _| Ok(true))
    }

    /// Swap the `size`-byte table entries `a` and `b` of the node at block `at`.
    fn swap_entries(image: &mut [u8], at: u64, size: usize, a: usize, b: usize) {
        let table = at as usize * BLOCK + NODE_TABLE;
        let held = image[table + size * a..table + size * (a + 1)].to_vec();
        image.copy_within(table + size * b..table + size * (b + 1), table + size * a);
        image[table + size * b..table + size * (b + 1)].copy_from_slice(&held);
        reseal(image, at);
    }

    /// Where a node's table of entries begins: directly after its header.
    const NODE_TABLE: usize = 56;

    /// The record of `(id, kind)` with no more key than its header, holding `value`.
    fn bare_record(id: u64, kind: u8, value: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        (((u64::from(kind) << 60) | id).to_le_bytes().to_vec(), value)
    }

    #[test]
    fn a_name_no_directory_can_hold_stops_a_walk_rather_than_becoming_a_path() {
        // A stored name runs to its terminator, so nothing about the field keeps a separator, a
        // NUL or a dot entry out of it, and a volume stores no dot entry of its own. Written
        // into an extraction, `../escape` climbs out of the directory it was read from.
        for name in [&b"../escape"[..], b"a/b", b"a\0b", b"..", b".", b""] {
            let mut forge = Forge::populated();
            forge.entry(inode_number::ROOT, name, 18, forge::DT_REG, None);
            let walked = open(&forge).walk();
            assert!(
                matches!(&walked, Err(ReadError::HostileName { name: held }) if held == name),
                "{name:?}: {walked:?}"
            );
        }
        // Nor is it reachable as a path: written out, it is an ascent and then a component, and
        // the root holds no `escape`.
        let mut forge = Forge::populated();
        forge.entry(inode_number::ROOT, b"../escape", 18, forge::DT_REG, None);
        assert!(matches!(
            open(&forge).lookup(b"/../escape"),
            Err(ReadError::NotFound { .. })
        ));
    }

    #[test]
    fn a_finding_reports_its_block_as_a_coordinate_and_as_the_byte_the_block_begins_at() {
        // Every block this family reports is physical, a virtual node being reported at the
        // block its map record led to, so the block is the addressed coordinate, in units of the
        // container's block size, and the product is a byte of the image.
        let mut image = Forge::populated().image();
        image[FS_ROOT_AT as usize * BLOCK + 300] ^= 1;
        let report = Reader::open(Cursor::new(image))
            .expect("opens")
            .scan()
            .to_report();
        let [finding] = report.findings() else {
            panic!("one finding: {:?}", report.findings());
        };
        assert_eq!(
            (finding.family, &*finding.category, finding.offset),
            (Family::Apfs, "tree", Some(FS_ROOT_AT * BLOCK as u64))
        );
        let named: Vec<(&str, u64)> = finding
            .coordinates
            .iter()
            .map(|(name, value)| (name.as_ref(), *value))
            .collect();
        assert_eq!(named, [("block", FS_ROOT_AT)]);

        // A finding about an inode and no block names no byte.
        let mut forge = Forge::populated();
        put_u32(&mut inode_record(&mut forge, 20).1, 56, 3);
        let report = open(&forge).scan().to_report();
        let [finding] = report.findings() else {
            panic!("one finding: {:?}", report.findings());
        };
        assert_eq!(finding.offset, None);
        let named: Vec<(&str, u64)> = finding
            .coordinates
            .iter()
            .map(|(name, value)| (name.as_ref(), *value))
            .collect();
        assert_eq!(named, [("inode", 20)]);
    }

    #[test]
    fn an_entry_naming_an_inode_the_volume_does_not_hold_is_refused() {
        // An inode number is a key, so there is no count to bound it by: the tree holds the
        // record or it does not, and an entry naming one it does not is a name for nothing.
        let mut forge = Forge::populated();
        forge.entry(inode_number::ROOT, b"ghost", 99, forge::DT_REG, None);
        forge.settle();
        let mut reader = open(&forge);
        let missing = Some(ReadError::MissingInode { inode: 99 });
        assert_eq!(reader.lookup(b"/ghost").err(), missing);
        assert_eq!(reader.walk().err(), missing);
        // The record pass's finding of the entry, and the walk it stopped.
        assert_eq!(
            scanned(&forge),
            [
                (Category::Record, Severity::Structural, Some(99)),
                (Category::Record, Severity::Structural, None)
            ]
        );
    }

    #[test]
    fn a_path_longer_than_this_crate_builds_stops_a_walk() {
        // A stored name takes up to 1,022 bytes, so four directories of 1,000-byte names are
        // within the longest path a walk builds and a fifth is past it. A directory's names are
        // read before it is handed out, so the walk stops at the fourth, which it does not hand
        // out.
        let mut forge = Forge::new();
        let name = vec![b'a'; 1000];
        let mut parent = inode_number::ROOT;
        for id in 60..65 {
            forge.entry(parent, &name, id, forge::DT_DIR, None);
            forge.add(forge::inode(id, parent, 0o040_755, 0, None, &[]));
            parent = id;
        }
        forge.settle();
        forge.per_leaf = Some(3);
        let mut reader = open(&forge);
        let mut reached = Vec::new();
        let walked = reader.walk_with::<ReadError, _>(|_, entry| {
            reached.push(entry.path.len());
            Ok(())
        });
        assert!(
            matches!(&walked, Err(ReadError::PathTooLong { path }) if path.len() == 5 * 1001),
            "{walked:?}"
        );
        assert_eq!(reached, [0, 1001, 2002, 3003]);
    }

    #[test]
    fn a_directory_reachable_from_itself_is_refused_strictly_and_descended_once_leniently() {
        // Every record is well formed, so nothing about one entry sees this, and a walk that
        // followed the entries would not end. An APFS directory has one name, in its parent,
        // so a strict walk refuses the name in `/down`, which is not the root's parent.
        let mut forge = Forge::new();
        let root = inode_number::ROOT;
        forge.entry(root, b"down", 60, forge::DT_DIR, None);
        forge.add(forge::inode(60, root, 0o040_755, 0, None, &[]));
        forge.entry(60, b"up", root, forge::DT_DIR, None);
        forge.settle();
        assert_eq!(
            open(&forge).walk().err(),
            Some(ReadError::MisplacedDirectory {
                inode: root,
                named_in: 60,
                parent: inode_number::ROOT_PARENT
            })
        );
        // Leniently, the second name for the root is a name the volume holds, so it is
        // yielded; what does not happen is a descent into it.
        assert_eq!(
            paths(&mut lenient(forge.image())),
            [b"".to_vec(), b"/down".to_vec(), b"/down/up".to_vec()]
        );
        // Two names for one directory, both in its parent: the repeat itself is what a strict
        // walk refuses, and a scan reports it and walks on.
        let mut forge = Forge::populated();
        forge.entry(root, b"again", 17, forge::DT_DIR, None);
        forge.settle();
        assert_eq!(
            open(&forge).walk().err(),
            Some(ReadError::RepeatedDirectory { inode: 17 })
        );
        assert_eq!(
            namespace_findings(&forge),
            [(Category::Volume, Severity::Integrity, Some(17), "names")]
        );
    }

    /// Each finding a strict scan of `forge` makes, as its category, severity and inode, and
    /// which of the namespace's rules it is: `"names"`, `"parent"`, `"unnamed"` or `"type"`,
    /// or `"other"`.
    fn namespace_findings(forge: &Forge) -> Vec<(Category, Severity, Option<u64>, &'static str)> {
        open(forge)
            .scan()
            .anomalies()
            .iter()
            .map(|a| {
                let rule = if a.detail.contains("names reach it") {
                    "names"
                } else if a.detail.contains("as its parent") {
                    "parent"
                } else if a.detail.contains("no name reaches") {
                    "unnamed"
                } else if a.detail.contains("the entry's type is") {
                    "type"
                } else {
                    "other"
                };
                (a.category, a.severity, a.inode, rule)
            })
            .collect()
    }

    #[test]
    fn a_directory_named_from_anywhere_but_its_parent_is_integrity_damage() {
        // An APFS directory records its parent and has one name, in it. Named from anywhere
        // else, its subtree is read where it does not belong, and where its own name is gone
        // nothing else about the records notices. A strict read refuses it where a walk or a
        // lookup meets it; a lenient one reads through; a scan reports it and walks on.
        let root = inode_number::ROOT;
        let mut forge = Forge::populated();
        forge.records.retain(|(key, _)| {
            EntryKey::read_from(key).map_or(true, |entry| {
                KeyHeader::read_from(key).map_or(true, |h| h.id != root) || entry.name != b"dir"
            })
        });
        forge.entry(root, b"other", 62, forge::DT_DIR, None);
        forge.add(forge::inode(62, root, 0o040_755, 0, None, &[]));
        forge.entry(62, b"dir", 17, forge::DT_DIR, None);
        forge.settle();
        let misplaced = Some(ReadError::MisplacedDirectory {
            inode: 17,
            named_in: 62,
            parent: root,
        });
        assert_eq!(open(&forge).walk().err(), misplaced);
        assert_eq!(open(&forge).lookup(b"/other/dir/nested").err(), misplaced);
        assert!(paths(&mut lenient(forge.image())).contains(&b"/other/dir/nested".to_vec()));
        assert_eq!(
            namespace_findings(&forge),
            [(Category::Record, Severity::Integrity, Some(17), "parent")]
        );
    }

    #[test]
    fn a_directory_no_name_reaches_is_integrity_damage() {
        // Every file below it is in the volume and out of every read, and nothing about one
        // record says so. The root and the private directory have no name, and are not one.
        let root = inode_number::ROOT;
        let mut forge = Forge::populated();
        forge.add(forge::inode(63, root, 0o040_755, 0, None, &[]));
        forge.entry(63, b"lost", 64, forge::DT_REG, None);
        forge.add(forge::inode(64, 63, 0o100_644, 0, None, &[]));
        forge.settle();
        assert_eq!(
            namespace_findings(&forge),
            [(Category::Volume, Severity::Integrity, Some(63), "unnamed")]
        );
    }

    #[test]
    fn an_entry_whose_type_is_not_its_inodes_is_integrity_damage() {
        // The two records contradict each other, and a reader that trusts the entry's type
        // reads a named pipe as a file.
        let root = inode_number::ROOT;
        let mut forge = Forge::populated();
        forge.entry(root, b"typed", 65, forge::DT_REG, None);
        forge.add(forge::inode(65, root, 0o010_644, 0, None, &[]));
        forge.settle();
        assert_eq!(
            namespace_findings(&forge),
            [(Category::Record, Severity::Integrity, Some(65), "type")]
        );
    }

    #[test]
    fn a_whole_file_read_is_held_to_the_cap_the_caller_set() {
        // A size is a number the image supplies, so a whole read costs what the inode claims;
        // an attribute kept in a stream of its own is a whole read of that stream, and is
        // refused as the attribute it is.
        let mut reader = limited(&Forge::populated(), Limits::new().max_file_bytes(4096));
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.read_data(&hello).err(),
            Some(ReadError::FileTooLarge {
                inode: 16,
                size: 5000,
                limit: 4096
            })
        );
        assert!(matches!(
            reader.xattrs(&hello),
            Err(ReadError::AttributeTooLarge {
                inode: 16,
                size: 6000,
                limit: 4096,
                ..
            })
        ));
        // Streaming is held to it as well: what the cap expresses is distrust of the declared
        // size, and a stream writes every byte that size claims as surely as a buffer holds
        // them. Nothing is written before the refusal.
        let mut out = Vec::new();
        assert_eq!(
            reader.read_data_to(&hello, &mut out).err(),
            Some(ReadError::FileTooLarge {
                inode: 16,
                size: 5000,
                limit: 4096
            })
        );
        assert!(out.is_empty());
        let hard = reader.lookup(b"/hard1").expect("found");
        assert_eq!(reader.read_data(&hard).ok(), Some(pattern(100, 3)));
        assert_eq!(reader.read_data_to(&hard, &mut out).ok(), Some(100));
        assert_eq!(out, pattern(100, 3));
        // A compressed file is held to its content's size, before a chunk is decoded.
        let mut forge = Forge::populated();
        let content = pattern(5000, 9);
        forge.compressed_file(b"packed", 70, 8, 5000, &forge::resource_fork(&content), 120);
        let mut reader = limited(&forge, Limits::new().max_file_bytes(4096));
        let packed = reader.lookup(b"/packed").expect("found");
        assert_eq!(
            reader.read_data_to(&packed, &mut out).err(),
            Some(ReadError::FileTooLarge {
                inode: 70,
                size: 5000,
                limit: 4096
            })
        );
    }

    #[test]
    fn a_stream_holding_one_block_twice_is_refused_and_reported() {
        // Clones share blocks between streams and never within one, so a stream two of whose
        // extents use one block reads that block's bytes twice behind extents that tile it.
        let mut forge = Forge::populated();
        let root = inode_number::ROOT;
        forge.entry(root, b"twice", 60, forge::DT_REG, None);
        forge.add(forge::inode(
            60,
            root,
            0o100_644,
            60,
            Some(2 * BLOCK as u64),
            &[],
        ));
        forge.extent(60, 0, 1, DATA_AT + 12);
        forge.extent(60, BLOCK as u64, 1, DATA_AT + 12);
        forge.data_blocks(DATA_AT + 12, &pattern(BLOCK, 9));
        forge.add(forge::stream_reference(60, 1));
        forge.settle();
        let mut reader = open(&forge);
        let twice = reader.lookup(b"/twice").expect("named");
        assert_eq!(
            reader.read_data(&twice).err(),
            Some(ReadError::BadExtent {
                stream: 60,
                logical: BLOCK as u64,
                block: None,
                fault: REUSED
            })
        );
        // A window that meets one of the two reads; the scan reads the stream whole.
        let mut window = vec![0u8; BLOCK];
        assert_eq!(reader.read_into(&twice, 0, &mut window).ok(), Some(BLOCK));
        let report = reader.scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| (a.severity, a.inode, a.detail.contains(REUSED)))
            .collect();
        assert_eq!(found, [(Severity::Structural, Some(60), true)]);
    }

    /// Add to inode 16 of a populated forge attribute `name`, a stream of `size` bytes whose
    /// one extent, `blocks` long, is at block `physical`: zero for a hole.
    fn attribute_stream(forge: &mut Forge, name: &[u8], size: u64, blocks: u64, physical: u64) {
        let stream = 90;
        let mut data = vec![0u8; 48];
        put_u64(&mut data, 0, stream);
        put_u64(&mut data, 8, size);
        put_u64(&mut data, 16, blocks * BLOCK as u64);
        forge.add(forge::xattr(16, name, xattr_flags::STREAM | 0x10, &data));
        forge.extent(stream, 0, blocks, physical);
    }

    #[test]
    fn an_attribute_is_read_from_blocks_and_nothing_is_allocated_for_it_first() {
        // macOS writes every byte of an attribute's stream to blocks, a resource fork written
        // with a gap included, so a hole in one is refused rather than read as zeros: an
        // attribute's size is then what the container holds, never only what its record says.
        let mut forge = Forge::populated();
        attribute_stream(&mut forge, b"user.hole", 3 * BLOCK as u64, 3, 0);
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.xattrs(&hello).err(),
            Some(ReadError::BadExtent {
                stream: 90,
                logical: 0,
                block: None,
                fault: HOLE
            })
        );
        // A terabyte the record claims is more than the container holds, and is refused before
        // a byte of it is allocated, at the default limits, which have no cap.
        let container = forge::BLOCKS * BLOCK as u64;
        let mut forge = Forge::populated();
        attribute_stream(
            &mut forge,
            b"user.vast",
            1 << 40,
            (1 << 40) / BLOCK as u64,
            0,
        );
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.xattrs(&hello).err(),
            Some(ReadError::AttributeTooLarge {
                inode: 16,
                name: b"user.vast".to_vec(),
                size: 1 << 40,
                limit: container,
            })
        );
        // A size the container could hold and its extents do not reach is refused at the extents.
        let mut forge = Forge::populated();
        attribute_stream(&mut forge, b"user.short", container, 1, DATA_AT + 4);
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert!(matches!(
            reader.xattrs(&hello),
            Err(ReadError::BadExtent { stream: 90, .. })
        ));
        // And extents that tile it from one block, used again for every block of the size, are
        // refused at the second: the container holds that block once.
        let mut forge = Forge::populated();
        attribute_stream(&mut forge, b"user.alias", 8 * BLOCK as u64, 1, DATA_AT + 4);
        for i in 1..8 {
            forge.extent(90, i * BLOCK as u64, 1, DATA_AT + 4);
        }
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.xattrs(&hello).err(),
            Some(ReadError::BadExtent {
                stream: 90,
                logical: BLOCK as u64,
                block: None,
                fault: REUSED
            })
        );
        // A scan reports the hole, as a read of the file would meet it.
        let mut forge = Forge::populated();
        attribute_stream(&mut forge, b"user.hole", 3 * BLOCK as u64, 3, 0);
        let report = open(&forge).scan();
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.inode == Some(16) && a.detail.contains(HOLE)),
            "{:?}",
            report.anomalies()
        );
    }

    #[test]
    fn an_attribute_over_the_cap_is_named_as_the_attribute_it_is() {
        let mut reader = limited(&Forge::populated(), Limits::new().max_file_bytes(4096));
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.xattrs(&hello).err(),
            Some(ReadError::AttributeTooLarge {
                inode: 16,
                name: b"user.big".to_vec(),
                size: 6000,
                limit: 4096
            })
        );
    }

    #[test]
    fn a_link_target_longer_than_a_path_is_refused_before_it_is_read() {
        // A target is held to the longest path from the size its record gives it, so a crafted
        // size cannot make one link allocate more than a path's worth. One byte past a path and
        // its terminator, stored in blocks a read would otherwise take whole:
        let long = MAX_PATH as u64 + 2;
        let mut forge = Forge::populated();
        forge.records.retain(|(key, _)| {
            KeyHeader::read_from(key).map_or(true, |h| (h.id, h.kind) != (19, record_kind::XATTR))
        });
        let mut target = vec![b'a'; long as usize - 1];
        target.push(0);
        forge.stream_xattr(19, SYMLINK_XATTR, 91, &target, DATA_AT + 8);
        let mut reader = open(&forge);
        let link = reader.lookup_no_follow(b"/link").expect("found");
        assert_eq!(link.size(), long - 1);
        assert_eq!(
            reader.link_target(&link).err(),
            Some(ReadError::BadRecord {
                id: 19,
                kind: record_kind::XATTR,
                fault: "a symbolic link target longer than a path may be".into()
            })
        );
        // Followed in a path, it names nothing, as on every family.
        assert_eq!(
            reader.lookup(b"/link").err(),
            Some(ReadError::NotFound {
                path: b"/link".to_vec()
            })
        );
    }

    #[test]
    fn a_geometry_the_format_does_not_define_is_refused_at_open() {
        // A block size outside 4 KiB to 64 KiB, or not a power of two, is refused, and is not
        // claimed by detection either.
        for size in [2048, 4097, 6144, 128 * 1024] {
            let mut forge = Forge::populated();
            forge.container.block_size = size;
            let image = forge.image();
            assert_eq!(
                Reader::open(Cursor::new(image.clone())).err(),
                Some(ReadError::BadGeometry {
                    field: "block size",
                    value: u64::from(size),
                    why: "which the format does not define",
                })
            );
            let options = crate::detect::DetectOptions::new();
            assert_eq!(
                crate::apfs::detect::claim(Cursor::new(image), &options),
                Ok(None)
            );
        }
        // A descriptor area that leaves the container.
        let mut forge = Forge::populated();
        forge.container.checkpoint.desc_base = forge::BLOCKS - 2;
        assert_eq!(
            Reader::open(forge.cursor()).err(),
            Some(ReadError::BadGeometry {
                field: "the checkpoint descriptor area, in blocks,",
                value: u64::from(forge::DESC_BLOCKS),
                why: "which runs past the container's last block",
            })
        );
        // A live superblock recording no blocks at all, under a block zero that records some.
        let mut image = Forge::populated().image();
        let live = DESC_BASE + 1;
        put_u64(&mut image[live as usize * BLOCK..], 40, 0);
        reseal(&mut image, live);
        assert_eq!(
            Reader::open(Cursor::new(image)).err(),
            Some(ReadError::BadGeometry {
                field: "block count",
                value: 0,
                why: "which the format does not define",
            })
        );
    }

    #[test]
    fn a_parent_component_ascends_whether_a_caller_wrote_it_or_a_link_stored_it() {
        let mut forge = Forge::populated();
        forge.entry(17, b"up", 60, forge::DT_LNK, None);
        forge.add(forge::inode(60, 17, 0o120_755, 0, None, &[]));
        forge.add(forge::xattr(
            60,
            b"com.apple.fs.symlink",
            0x6,
            b"../hello\0",
        ));
        forge.entry(17, b"sub", 61, forge::DT_DIR, None);
        forge.add(forge::inode(61, 17, 0o040_755, 0, None, &[]));
        forge.settle();
        let mut reader = open(&forge);
        assert_eq!(reader.lookup(b"/dir/../hello").expect("found").inode, 16);
        assert_eq!(reader.lookup(b"/dir/up").expect("found").inode, 16);
        // An ascent comes back to the directory it descended through, not to the root.
        assert_eq!(
            reader.lookup(b"/dir/sub/../nested").expect("found").inode,
            18
        );
        assert_eq!(
            reader.lookup(b"/dir/../dir/nested").expect("found").inode,
            18
        );
        // At the root there is nothing to ascend to, so however many of them a path holds it
        // names nothing outside the volume.
        for path in [&b"/.."[..], b"/../..", b"/dir/../../.."] {
            let stayed = reader
                .lookup(path)
                .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(path)));
            assert_eq!(stayed.inode, inode_number::ROOT);
        }
    }

    #[test]
    fn a_chain_of_links_that_does_not_end_is_refused() {
        // Two links naming each other: a resolution with no budget follows them until something
        // else stops it.
        let mut forge = Forge::populated();
        let root = inode_number::ROOT;
        for (id, name, target) in [(60, b"a", b"b\0"), (61, b"b", b"a\0")] {
            forge.entry(root, name, id, forge::DT_LNK, None);
            forge.add(forge::inode(id, root, 0o120_755, 0, None, &[]));
            forge.add(forge::xattr(id, b"com.apple.fs.symlink", 0x6, target));
        }
        forge.settle();
        let mut reader = open(&forge);
        assert!(matches!(
            reader.lookup(b"/a"),
            Err(ReadError::SymlinkLoop { .. })
        ));
        // Stopping at the last component expands no link, so it spends none of the budget.
        let link = reader.lookup_no_follow(b"/a").expect("the link itself");
        assert!(link.is_symlink());
    }

    #[test]
    fn a_physical_object_recording_another_address_than_its_own_is_refused() {
        // A physical object's identifier is the block it sits at, inside what the checksum
        // covers: a copy of the volume's object map written to another block verifies, and says
        // the wrong thing about itself.
        let mut forge = Forge::populated();
        forge.volume.object_map_oid = 100;
        let mut image = forge.image();
        let from = forge::VOLUME_MAP_AT as usize * BLOCK;
        image.copy_within(from..from + BLOCK, 100 * BLOCK);
        assert_eq!(
            Reader::open(Cursor::new(image)).err(),
            Some(ReadError::WrongObject {
                block: 100,
                fault: "an object recording another identifier"
            })
        );
    }

    #[test]
    fn a_lone_key_is_held_to_parse_as_every_key_of_two_or_more_is() {
        // A tree of one record whose key is too short for its header.
        let mut forge = Forge::new();
        forge.records = vec![(vec![0u8; 4], vec![0u8; 8])];
        forge.references = Some(Vec::new());
        let mut reader = Reader::open(Cursor::new(forge.image())).expect("read lazily");
        assert_eq!(
            reader.root().err(),
            Some(ReadError::BadTree {
                block: FS_ROOT_AT,
                fault: "a key that does not parse"
            })
        );
    }

    #[test]
    fn a_root_index_node_holding_nothing_is_refused_before_any_lookup() {
        // An empty tree is a root leaf with no entries. A root one level up with none would
        // steer every lookup into an entry it does not have, so it is refused where the node is
        // read: the file-system tree's root, and the container object map's.
        let refusal = |block| ReadError::BadTree {
            block,
            fault: "an index node holding nothing",
        };
        let empty_index = |image: &mut Vec<u8>, at: u64| {
            let node = at as usize * BLOCK;
            let flags = get_u16(image, node + 32) & !node_flags::LEAF;
            put_u16(image, node + 32, flags);
            put_u16(image, node + 34, 1);
            put_u32(image, node + 36, 0);
            reseal(image, at);
        };
        let mut forge = Forge::populated();
        forge.per_leaf = Some(3);
        let mut image = forge.image();
        empty_index(&mut image, FS_ROOT_AT);
        assert_eq!(every_record(image.clone()), Err(refusal(FS_ROOT_AT)));
        let mut strict = Reader::open(Cursor::new(image.clone())).expect("the tree is read lazily");
        assert_eq!(strict.root().err(), Some(refusal(FS_ROOT_AT)));
        assert_eq!(lenient(image).root().err(), Some(refusal(FS_ROOT_AT)));

        let mut image = Forge::populated().image();
        empty_index(&mut image, forge::CONTAINER_MAP_TREE_AT);
        assert_eq!(
            Reader::open(Cursor::new(image)).err(),
            Some(refusal(forge::CONTAINER_MAP_TREE_AT))
        );
    }

    #[test]
    fn a_descent_is_held_to_a_falling_level_and_reaches_no_node_twice() {
        // Each covers what the other cannot: a crafted tree can name a fresh block at every
        // step, so a visited set alone is no bound, and index entries sharing a child are not a
        // cycle, so the level alone does not see them.
        let mut forge = Forge::populated();
        forge.per_leaf = Some(3);
        let clean = forge.image();
        let root = FS_ROOT_AT as usize * BLOCK;
        assert_eq!(every_record(clean.clone()), Ok(()));

        // The second index entry naming the first leaf.
        let mut image = clean.clone();
        let second = usize::from(get_u16(&image, root + NODE_TABLE + 8 + 4));
        put_u64(
            &mut image,
            root + BLOCK - TREE_INFO_SIZE - second,
            forge::FS_ROOT_OID + 1,
        );
        reseal(&mut image, FS_ROOT_AT);
        assert_eq!(
            every_record(image),
            Err(ReadError::BadTree {
                block: FS_ROOT_AT + 1,
                fault: "a node reached twice"
            })
        );

        // A leaf recording a level other than its parent's less one.
        let mut image = clean.clone();
        put_u16(&mut image, root + BLOCK + 34, 1);
        reseal(&mut image, FS_ROOT_AT + 1);
        assert_eq!(
            every_record(image),
            Err(ReadError::BadTree {
                block: FS_ROOT_AT + 1,
                fault: "a node not one level below its parent"
            })
        );

        // A root higher than any tree a container could hold.
        let mut image = clean;
        put_u16(&mut image, root + 34, btree::MAX_LEVEL + 1);
        reseal(&mut image, FS_ROOT_AT);
        assert_eq!(
            every_record(image),
            Err(ReadError::BadTree {
                block: FS_ROOT_AT,
                fault: "a root higher than any tree the container could hold"
            })
        );
    }

    #[test]
    fn keys_out_of_order_are_refused_where_a_node_is_read() {
        // A search over keys out of order misses records rather than failing, so a node's keys
        // are held in order whenever it is read, a lookup's descent included. The root's inode
        // record and its first directory entry, swapped:
        let mut image = Forge::populated().image();
        swap_entries(&mut image, FS_ROOT_AT, 8, 0, 1);
        let mut reader = Reader::open(Cursor::new(image)).expect("opens: the tree is read lazily");
        let out_of_order = |block| {
            Some(ReadError::BadTree {
                block,
                fault: "keys out of order",
            })
        };
        assert_eq!(reader.root().err(), out_of_order(FS_ROOT_AT));

        // An object map's keys, in a node of fixed-size entries, the same. A strict open reads
        // the volume's map whole before trusting a lookup through it, so it refuses the map
        // there; a lenient one reads through it, meets the fault where a lookup does, and its
        // scan names the map.
        let mut forge = Forge::populated();
        forge.per_leaf = Some(3);
        let mut image = forge.image();
        swap_entries(&mut image, forge::VOLUME_MAP_TREE_AT, 4, 0, 1);
        assert_eq!(
            Reader::open(Cursor::new(image.clone())).err(),
            out_of_order(forge::VOLUME_MAP_TREE_AT)
        );
        let mut reader = lenient(image);
        assert_eq!(reader.root().err(), out_of_order(forge::VOLUME_MAP_TREE_AT));
        let report = reader.scan();
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.block == Some(forge::VOLUME_MAP_TREE_AT)
                    && a.detail.starts_with("the volume's object-map tree")),
            "{:?}",
            report.anomalies()
        );
    }

    /// Every key of a forged volume's one-leaf tree, in the order the leaf holds them.
    fn leaf_order(image: &[u8]) -> Vec<Vec<u8>> {
        let mut reader = Reader::open(Cursor::new(image.to_vec())).expect("opens");
        let tree = reader.fs_tree;
        let mut keys = Vec::new();
        btree::for_each(&mut reader.container, &tree, &mut |key, _| {
            keys.push(key.to_vec());
            Ok(true)
        })
        .expect("walks");
        keys
    }

    /// Where the first record of `(id, kind)` sits in the forged volume's one leaf.
    fn leaf_index(image: &[u8], id: u64, kind: u8) -> usize {
        leaf_order(image)
            .iter()
            .position(|key| KeyHeader::read_from(key).is_ok_and(|h| (h.id, h.kind) == (id, kind)))
            .expect("the record is in the leaf")
    }

    #[test]
    fn a_file_system_tree_holds_one_record_per_key_in_the_order_macos_keeps() {
        // macOS keeps a directory's entries in hash order and an inode's attributes in name
        // order, and never stores one key twice, so a tree that does either holds records a
        // read takes the first or the last of without saying so. Every one is refused where its
        // node is read.
        let out_of_order = Some(ReadError::BadTree {
            block: FS_ROOT_AT,
            fault: "keys out of order",
        });
        let root = inode_number::ROOT;
        let read = |image: Vec<u8>| Reader::open(Cursor::new(image)).and_then(|mut r| r.root());

        // Two entries of the root out of hash order, and two attributes out of name order.
        for (id, kind) in [(root, record_kind::DIR_ENTRY), (16, record_kind::XATTR)] {
            let mut image = Forge::populated().image();
            let first = leaf_index(&image, id, kind);
            swap_entries(&mut image, FS_ROOT_AT, 8, first, first + 1);
            assert_eq!(read(image).err(), out_of_order, "kind {kind}");
        }

        // A name, an attribute and an inode each stored twice, the second differing in what it
        // holds.
        let twice: [&dyn Fn(&mut Forge); 3] = [
            &|f| f.entry(root, b"hello", 18, forge::DT_REG, None),
            &|f| {
                f.add(forge::xattr(
                    16,
                    b"user.small",
                    xattr_flags::EMBEDDED,
                    b"other",
                ))
            },
            &|f| f.add(forge::inode(16, root, 0o100_600, 16, Some(4000), &[])),
        ];
        for (i, add) in twice.iter().enumerate() {
            let mut forge = Forge::populated();
            add(&mut forge);
            forge.settle();
            assert_eq!(read(forge.image()).err(), out_of_order, "repeat {i}");
        }
    }

    #[test]
    fn two_names_the_volume_compares_as_one_are_integrity_damage() {
        // On a volume whose names fold case and normalization, `hello` and `HELLO` are one name,
        // and so are a precomposed and a decomposed `café`: each pair hashes alike, so a lookup
        // meets both and finds one, and the other names a file no lookup reaches. The bytes
        // differ, so the tree's order holds; the scan is what sees it.
        let root = inode_number::ROOT;
        let mut forge = Forge::populated();
        forge.entry(root, b"HELLO", 70, forge::DT_REG, None);
        forge.add(forge::inode(70, root, 0o100_644, 0, None, &[]));
        forge.entry(root, "caf\u{e9}".as_bytes(), 71, forge::DT_REG, None);
        forge.add(forge::inode(71, root, 0o100_644, 0, None, &[]));
        forge.entry(root, "cafe\u{301}".as_bytes(), 72, forge::DT_REG, None);
        forge.add(forge::inode(72, root, 0o100_644, 0, None, &[]));
        forge.settle();
        let report = open(&forge).scan();
        let mut found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| {
                (
                    a.category,
                    a.severity,
                    a.inode,
                    a.detail.contains("are one name to the volume"),
                )
            })
            .collect();
        found.sort_by_key(|f| f.2);
        // The second of each pair the tree holds, by its bytes: `hello` after `HELLO`, and the
        // precomposed name after the decomposed one.
        assert_eq!(
            found,
            [
                (Category::Record, Severity::Integrity, Some(16), true),
                (Category::Record, Severity::Integrity, Some(71), true),
            ]
        );
    }

    #[test]
    fn a_key_that_steers_a_lookup_past_a_record_is_refused_rather_than_answered_around() {
        // A root's key for a leaf, sitting above the leaf's first record, steers a lookup for
        // that record into the leaf before, whose last record is real, verified, and not the
        // answer: an inode that exists reads as missing, and in an object map an older version
        // of a node reads as the one asked for. A lookup holds an answer that is the last
        // record of its leaf to the record after it, which is where the wrong key is met.
        let (forge, leaf, inode) = (2..8)
            .find_map(|per_leaf| {
                let mut forge = Forge::populated();
                forge.per_leaf = Some(per_leaf);
                leaves(&forge, per_leaf)
                    .iter()
                    .enumerate()
                    .skip(1)
                    .find_map(|(i, leaf)| {
                        let first = KeyHeader::read_from(&leaf[0]).ok()?;
                        (first.kind == record_kind::INODE && leaf.len() > 1).then(|| {
                            forge.separator = Some((i, leaf[1].clone()));
                            (forge.clone(), i, first.id)
                        })
                    })
            })
            .expect("a leaf that begins with an inode");
        let mut reader = open(&forge);
        assert_eq!(
            reader.inode(inode).err(),
            Some(ReadError::BadTree {
                block: FS_ROOT_AT + 1 + leaf as u64,
                fault: "a node whose first key is not its parent's key for it"
            })
        );
        // The same tree with the leaf's own first key is read whole, which is the control.
        let mut good = forge.clone();
        good.separator = None;
        assert_eq!(open(&good).inode(inode).map(|n| n.inode).ok(), Some(inode));
    }

    #[test]
    fn a_target_before_every_key_of_the_root_is_held_to_the_first_record_it_leads_to() {
        // A lookup for a key below the root's first key answers that nothing is there, which
        // is right only where the root's first key is its first leaf's: so it descends, and
        // the first leaf's first record is held to the root's key for it.
        let mut forge = Forge::populated();
        forge.per_leaf = Some(4);
        let first = leaves(&forge, 4)[0][0].clone();
        // The root inode's record is the tree's first, so the key of the root's attributes,
        // after it and before the root's first entry, is a key the leaf does not begin with.
        assert_eq!(
            KeyHeader::read_from(&first).ok().map(|h| (h.id, h.kind)),
            Some((inode_number::ROOT, record_kind::INODE))
        );
        forge.separator = Some((
            0,
            ((u64::from(record_kind::XATTR) << 60) | inode_number::ROOT)
                .to_le_bytes()
                .to_vec(),
        ));
        let mut reader = open(&forge);
        assert_eq!(
            reader.root().err(),
            Some(ReadError::BadTree {
                block: FS_ROOT_AT + 1,
                fault: "a node whose first key is not its parent's key for it"
            })
        );
    }

    #[test]
    fn every_record_of_a_kind_this_reader_does_not_interpret_is_one_finding() {
        // A used volume carries many records of kinds nothing here interprets, and one finding
        // each is a report nobody reads. What survives the folding is the kind, the one thing
        // that says what was skipped.
        let mut forge = Forge::populated();
        for id in [inode_number::ROOT, 17] {
            forge.add(bare_record(id, record_kind::DIR_STATS, vec![0; 32]));
        }
        forge.add(bare_record(16, 15, vec![0; 8]));
        let report = open(&forge).scan();
        let found: Vec<_> = report
            .anomalies()
            .iter()
            .map(|a| (a.category, a.severity, a.detail.as_str()))
            .collect();
        let folded = |detail: &'static str| (Category::Record, Severity::Cosmetic, detail);
        assert_eq!(
            found,
            [
                folded(
                    "2 records of kind 10, which this reader does not interpret; each was skipped"
                ),
                folded(
                    "1 record of kind 15, which this reader does not interpret; each was skipped"
                )
            ]
        );
    }

    #[test]
    fn a_tree_is_read_only_the_way_its_root_says_its_nodes_are_read() {
        // A hashed node's index values carry each child's hash beside its identifier, and a
        // headerless node has no object header to verify: read as ordinary nodes, each is a
        // well-framed node whose children are misread.
        let refusal = |image: Vec<u8>| match every_record(image) {
            Err(ReadError::BadTree { block, fault }) => (block, fault),
            other => panic!("{other:?}"),
        };
        let root = FS_ROOT_AT as usize * BLOCK;
        let info = root + BLOCK - TREE_INFO_SIZE;
        let changed = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut image = Forge::populated().image();
            change(&mut image);
            reseal(&mut image, FS_ROOT_AT);
            image
        };

        // An ephemeral tree is read through the checkpoint's mappings, which a volume's tree is
        // not, so the flag on it is a root contradicting how its children are found.
        for (flag, fault) in [
            (TREE_HASHED, "a tree whose nodes are hashed or headerless"),
            (
                TREE_NO_HEADER,
                "a tree whose nodes are hashed or headerless",
            ),
            (
                TREE_EPHEMERAL,
                "a tree whose root says its children are found otherwise than they are",
            ),
        ] {
            let image = changed(&|image| {
                let flags = crate::bytes::get_u32(image, info);
                put_u32(image, info, flags | flag);
            });
            assert_eq!(refusal(image), (FS_ROOT_AT, fault), "{flag:#x}");
        }
        let image = changed(&|image| {
            put_u32(image, info + 4, 2 * BLOCK as u32);
        });
        assert_eq!(
            refusal(image),
            (FS_ROOT_AT, "a tree whose nodes are not one block")
        );

        // The node flags, on the root, which here is the tree's one leaf.
        let flags = get_u16(&Forge::populated().image(), root + 32);
        for (set, fault) in [
            (
                flags | node_flags::HASHED,
                "a node carrying flags this crate does not read",
            ),
            (
                flags & !node_flags::ROOT,
                "a root without its tree information",
            ),
            (
                flags & !node_flags::LEAF,
                "a node whose leaf flag disagrees with its level",
            ),
        ] {
            let image = changed(&|image| put_u16(image, root + 32, set));
            assert_eq!(refusal(image), (FS_ROOT_AT, fault), "{set:#x}");
        }
        // Its first entry's value offset made the one that says it has none.
        let image = changed(&|image| {
            put_u16(image, root + NODE_TABLE + 4, 0xFFFF);
        });
        assert_eq!(refusal(image), (FS_ROOT_AT, "a key without a value"));

        // Below a root: a leaf flagged as one, and a leaf holding nothing.
        let split = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut forge = Forge::populated();
            forge.per_leaf = Some(3);
            let mut image = forge.image();
            change(&mut image);
            reseal(&mut image, FS_ROOT_AT + 1);
            image
        };
        let leaf = root + BLOCK;
        let image = split(&|image| {
            let flags = get_u16(image, leaf + 32);
            put_u16(image, leaf + 32, flags | node_flags::ROOT);
        });
        assert_eq!(
            refusal(image),
            (
                FS_ROOT_AT + 1,
                "a node whose root flag disagrees with its place"
            )
        );
        let image = split(&|image| put_u32(image, leaf + 36, 0));
        assert_eq!(
            refusal(image),
            (FS_ROOT_AT + 1, "a node other than the root holding nothing")
        );
    }

    #[test]
    fn an_extent_with_a_flag_a_partial_block_an_overlap_or_no_end_is_refused() {
        // /hard1's one extent, one block at DATA_AT + 2, its length word changed.
        let key = forge::extent(20, 0, BLOCK as u64, DATA_AT + 2).0;
        for (word, fault) in [
            (
                BLOCK as u64 | (1 << 56),
                "an extent carrying flags this crate does not read",
            ),
            (
                100,
                "an extent whose length is not a whole number of blocks",
            ),
            (0, "an extent whose length is not a whole number of blocks"),
        ] {
            let mut forge = Forge::populated();
            let record = forge
                .records
                .iter_mut()
                .find(|(k, _)| *k == key)
                .expect("the extent");
            put_u64(&mut record.1, 0, word);
            let mut reader = open(&forge);
            let hard = reader.lookup(b"/hard1").expect("found");
            assert_eq!(
                reader.read_data(&hard).err(),
                Some(ReadError::BadExtent {
                    stream: 20,
                    logical: 0,
                    block: Some(FS_ROOT_AT),
                    fault
                }),
                "{word:#x}"
            );
        }

        // /hello's second block covered twice.
        let mut forge = Forge::populated();
        forge.extent(16, BLOCK as u64, 1, DATA_AT + 5);
        let mut reader = open(&forge);
        let hello = reader.lookup(b"/hello").expect("found");
        assert_eq!(
            reader.read_data(&hello).err(),
            Some(ReadError::BadExtent {
                stream: 16,
                logical: BLOCK as u64,
                block: Some(FS_ROOT_AT),
                fault: "an extent overlapping the one before it"
            })
        );
        // And a scan finds it at the leaf holding the record, for the file it belongs to.
        let found = open(&forge).scan();
        assert!(
            found.anomalies().iter().any(|a| {
                (a.category, a.block, a.inode) == (Category::Record, Some(FS_ROOT_AT), Some(16))
                    && a.detail.contains("overlapping")
            }),
            "{:?}",
            found.anomalies()
        );

        // A stream reaching the largest offset, its last extent running past it.
        let mut forge = Forge::populated();
        let near = u64::MAX - 2 * BLOCK as u64 + 1;
        forge.entry(inode_number::ROOT, b"far", 60, forge::DT_REG, None);
        forge.add(forge::inode(
            60,
            inode_number::ROOT,
            0o100_644,
            60,
            Some(u64::MAX - BLOCK as u64 + 1),
            &[],
        ));
        forge.extent(60, near, 3, DATA_AT + 20);
        forge.settle();
        let mut reader = open(&forge);
        let far = reader.lookup(b"/far").expect("found");
        let mut window = vec![0u8; BLOCK];
        assert_eq!(
            reader.read_into(&far, near, &mut window).err(),
            Some(ReadError::BadExtent {
                stream: 60,
                logical: near,
                block: Some(FS_ROOT_AT),
                fault: "an extent reaching past the largest offset"
            })
        );
    }

    #[test]
    fn a_fusion_container_and_an_object_map_under_encryption_are_refused_by_name() {
        let mut forge = Forge::populated();
        forge.container.incompatible_features |= container_incompat::FUSION;
        assert_eq!(
            Reader::open(forge.cursor()).err(),
            Some(ReadError::UnsupportedFeatures {
                scope: "container",
                bits: container_incompat::FUSION,
                names: "Fusion".to_string()
            })
        );
        // Each flag that says the volume's objects are being encrypted, decrypted or re-keyed.
        for flag in [0x2, 0x4, 0x8] {
            let mut image = Forge::populated().image();
            let map = forge::VOLUME_MAP_AT;
            put_u32(&mut image[map as usize * BLOCK..], 32, flag);
            reseal(&mut image, map);
            assert_eq!(
                Reader::open(Cursor::new(image)).err(),
                Some(ReadError::EncryptionChanging { slot: 0 }),
                "{flag:#x}"
            );
        }
    }

    #[test]
    fn an_encryption_generation_is_read_past_and_an_encrypted_object_is_refused() {
        // The generation bit names the encryption configuration an object was last written
        // under; whether the object is encrypted is its record's own flag (reference p. 48). So
        // on a volume of plain objects the bit, matched or not, leaves every read as it was.
        let with = |map_flag: u32, value_flag: u32| {
            let mut image = Forge::populated().image();
            let map = forge::VOLUME_MAP_AT;
            put_u32(&mut image[map as usize * BLOCK..], 32, map_flag);
            reseal(&mut image, map);
            let tree = forge::VOLUME_MAP_TREE_AT;
            let leaf = tree as usize * BLOCK;
            let count = u32::from_le_bytes(image[leaf + 36..leaf + 40].try_into().expect("4"));
            for i in 0..count as usize {
                let entry = leaf + NODE_TABLE + 4 * i;
                let value = usize::from(u16::from_le_bytes([image[entry + 2], image[entry + 3]]));
                // A root's values end where its tree information begins.
                put_u32(&mut image[leaf + BLOCK - 40 - value..], 0, value_flag);
            }
            reseal(&mut image, tree);
            Reader::open(Cursor::new(image))
        };
        let mut plain = open(&Forge::populated());
        let hello = plain.lookup(b"/hello").expect("found");
        let content = plain.read_data(&hello).expect("reads");
        for (map_flag, value_flag) in [(0x10, 0x10), (0x10, 0), (0, 0x10)] {
            let mut reader = with(map_flag, value_flag).expect("opens");
            assert_eq!(paths(&mut reader), paths(&mut plain));
            let hello = reader.lookup(b"/hello").expect("found");
            assert_eq!(reader.read_data(&hello).expect("reads"), content);
            assert_eq!(reader.scan().anomalies(), []);
        }
        let mut encrypted = with(0x10, 0x14).expect("opens");
        assert!(matches!(
            encrypted.root().err(),
            Some(ReadError::BadMapValue { flags: 0x14, .. })
        ));
    }

    #[test]
    fn a_tree_holding_an_identifier_the_volume_would_assign_again_is_a_finding() {
        // /hello's attribute stream is object 40, the largest the populated volume holds.
        let mut forge = Forge::populated();
        forge.volume.next_object_id = 41;
        assert_eq!(scanned(&forge), []);
        forge.volume.next_object_id = 40;
        assert_eq!(
            at_blocks(&mut open(&forge)),
            [(Category::Volume, Severity::Conformance, Some(VOLUME_AT))]
        );
        // An inode's data stream is an identifier too, though no record is keyed by it.
        let mut forge = Forge::populated();
        put_u64(&mut inode_record(&mut forge, 18).1, 8, 2000);
        assert_eq!(
            scanned(&forge),
            [(Category::Volume, Severity::Conformance, None)]
        );
    }

    #[test]
    fn detection_claims_what_a_lenient_open_reads_and_nothing_it_cannot() {
        let claim = |image: &[u8]| {
            let options = crate::detect::DetectOptions::new();
            crate::apfs::detect::claim(Cursor::new(image.to_vec()), &options)
        };
        // Block zero damaged and the checkpoint whole: a lenient open reads the container, so
        // detection claims it, and a strict open refuses it.
        let mut image = Forge::populated().image();
        image[300] ^= 1;
        assert_eq!(claim(&image), Ok(Some(crate::Filesystem::Apfs)));
        assert!(Reader::open(Cursor::new(image.clone())).is_err());
        assert_eq!(lenient(image.clone()).container().xid(), XID);

        // The checkpoint's superblock damaged as well: no copy says these bytes are a
        // container, and neither claims them.
        image[(DESC_BASE + 1) as usize * BLOCK + 300] ^= 1;
        assert_eq!(claim(&image), Ok(None));
        let common = crate::OpenOptions::new().policy(ReadPolicy::Lenient);
        assert_eq!(
            Reader::open_with(Cursor::new(image), &OpenOptions::new().common(common)).err(),
            Some(ReadError::NoCheckpoint)
        );
    }

    #[test]
    fn a_checkpoint_area_described_by_a_tree_is_refused_in_either_copy() {
        // A tree-described area is a form this crate does not read: refused in block zero, and
        // in the ring's superblock a checkpoint passed over, the descriptor area's word compared
        // whole with block zero's.
        for offset in [104, 108] {
            let mut image = Forge::populated().image();
            let flag = |image: &mut Vec<u8>, at: u64| {
                let word = at as usize * BLOCK + offset;
                let held = get_u32(image, word);
                put_u32(
                    image,
                    word,
                    held | crate::apfs::ondisk::CHECKPOINT_AREA_IS_TREE,
                );
                reseal(image, at);
            };
            flag(&mut image, DESC_BASE + 1);
            assert_eq!(
                Reader::open(Cursor::new(image.clone())).err(),
                Some(ReadError::NoCheckpoint),
                "offset {offset}"
            );
            flag(&mut image, 0);
            assert_eq!(
                Reader::open(Cursor::new(image)).err(),
                Some(ReadError::UnsupportedCheckpoint),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn a_descriptor_area_past_the_cap_is_refused_before_it_is_read() {
        // Block zero names the area's length, and a damaged block zero names any length; the cap
        // is what bounds the read, at open and in detection alike.
        let cap = (crate::apfs::container::MAX_DESCRIPTOR_BYTES / BLOCK as u64) as u32;
        let mut forge = Forge::populated();
        forge.container.block_count = 1 << 20;
        forge.container.checkpoint.desc_blocks = cap + 1;
        assert_eq!(
            Reader::open(forge.cursor()).err(),
            Some(ReadError::BadGeometry {
                field: "the checkpoint descriptor area, in blocks,",
                value: u64::from(cap + 1),
                why: "more than the 16 MiB of descriptor area this crate reads",
            })
        );
        let mut image = forge.image();
        image[300] ^= 1;
        let options = crate::detect::DetectOptions::new();
        assert_eq!(
            crate::apfs::detect::claim(Cursor::new(image), &options),
            Ok(None)
        );
        // An area of the cap's length is read, and here it runs past the image.
        forge.container.checkpoint.desc_blocks = cap;
        assert!(matches!(
            Reader::open(forge.cursor()),
            Err(ReadError::Io { .. })
        ));
    }

    #[test]
    fn the_root_opens_and_detects_a_forged_container() {
        let image = Forge::populated().image();
        assert_eq!(
            crate::detect(Cursor::new(image.clone())),
            Ok(crate::Filesystem::Apfs)
        );
        let opened = crate::open(Cursor::new(image)).expect("opens");
        assert_eq!(opened.family(), Family::Apfs);
    }
}
