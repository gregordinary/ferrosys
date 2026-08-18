//! The filesystem view: inodes, the names they are known by, and where their bytes are.
//!
//! [`Volume`] hands back tree blocks at logical addresses and knows nothing about files. This
//! is the layer that reads the records inside them as a filesystem — an inode item as a `stat`,
//! a directory item as a name, an extent record as a run of a file's bytes — and it is what
//! [`Reader`] is.
//!
//! # Where a file lives, and how little of it is in one place
//!
//! A btrfs inode is not a structure holding pointers to its data. It is a *run of one tree*,
//! keyed by its own number: the `INODE_ITEM` first, then the names it has, then its extended
//! attributes, then its extents in file order. Everything about one file is contiguous in the
//! tree and everything about the filesystem is in the same tree as everything else, so reading
//! a file is one descent to its number and a walk forward from there.
//!
//! # A directory holds every entry twice, on purpose
//!
//! A `DIR_ITEM` is keyed by the hash of the entry's name, so [`lookup`](Reader::lookup) finds a
//! name in one descent. A `DIR_INDEX` is keyed by the entry's sequence number, so
//! [`read_dir`](Reader::read_dir) lists a directory in the order its entries were created. Both
//! records hold the same thing and this reader uses each for what it is keyed for.
//!
//! # A subvolume is a directory that is a different tree
//!
//! A directory entry whose location names a `ROOT_ITEM` rather than an inode is where a
//! subvolume is mounted, and stepping through it means continuing in another tree entirely. A
//! walk crosses those seams, so what it yields is every name in the filesystem rather than
//! every name in one tree — and [`Node::tree`] is what says which tree a node was found in,
//! because an inode number means nothing without it.
//!
//! This module does I/O, through the volume it owns.

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};

use crate::compress::Algorithm;
use crate::fidelity::Synthesis;
use crate::finding::{Family, Severity};
use crate::path::is_hostile_component;
use crate::policy::MAX_PATH;
use crate::source::Metadata;
use crate::time::Timestamp;
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};
use crate::xattr::Xattr;
use crate::{Limits, OpenOptions, ReadPolicy};

use super::decode;
use super::ondisk::{
    DirEntryType, DirItem, DiskKey, ExtentKind, FileExtentItem, InodeItem, ItemType, RootFlags,
    RootItem, RootRef, for_each_packed, name_hash, objectid,
};
use super::scan::{
    Category, Scan, ScanReport, has_live_log, mirror_anomaly, tree_name, walk_anomaly,
};
use super::volume::{ReadError, TreeRoot, Volume};

/// One inode of one subvolume: the tree it is in, the number it has there, and what it records.
///
/// **The pair is the identity.** An inode number is unique within a subvolume and no further,
/// so two subvolumes each have an inode 256 and they are different files. Every operation here
/// takes the pair, and a node handed to one taken out of another is a node from the wrong tree
/// rather than a coincidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Node {
    /// Which subvolume's tree the inode lives in, by that subvolume's id.
    pub tree: u64,
    /// The inode number within that tree.
    pub inode: u64,
    /// What the inode records: mode, ownership, size, and the four times.
    pub item: InodeItem,
}

impl Node {
    /// Whether the inode is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.item.mode_type() == MODE_DIR
    }

    /// Whether the inode is a regular file, which is the only kind that holds bytes to read.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.item.mode_type() == MODE_REG
    }

    /// Whether the inode is a symbolic link.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.item.mode_type() == MODE_LNK
    }
}

/// The `S_IFMT` value of a directory.
const MODE_DIR: u32 = 0o040_000;
/// The `S_IFMT` value of a regular file.
const MODE_REG: u32 = 0o100_000;
/// The `S_IFMT` value of a symbolic link.
const MODE_LNK: u32 = 0o120_000;

/// One entry of a directory, as it is stored.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Entry {
    /// The name, exactly as the bytes are stored. btrfs stores a name as a byte string and
    /// interprets no encoding, and neither does this.
    pub name: Vec<u8>,
    /// What the entry says it names, which the inode it points at says again.
    pub kind: DirEntryType,
    /// The key of what it names: an `INODE_ITEM` in the same tree, or a `ROOT_ITEM` where the
    /// entry is where a subvolume is mounted.
    pub location: DiskKey,
    /// The entry's sequence number in the directory, which is what it is ordered by.
    pub index: u64,
}

impl Entry {
    /// Whether stepping through this entry means continuing in another tree.
    #[must_use]
    pub const fn is_subvolume(&self) -> bool {
        matches!(self.location.kind, ItemType::ROOT_ITEM)
    }
}

/// One subvolume of the filesystem: an independent tree of files, reachable as a directory of
/// another.
///
/// The top-level tree is one of these too. It is the one with no parent, and its
/// [`id`](Self::id) is the fixed number the format gives it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Subvolume {
    /// Its id, which is its tree's objectid and what a directory entry names it by.
    pub id: u64,
    /// Where its tree begins.
    pub root: TreeRoot,
    /// The inode its root directory has within its own tree.
    pub root_dir: u64,
    /// Whether it is read-only, which is what a snapshot taken for sending is.
    pub read_only: bool,
    /// Its own identity, which survives being sent elsewhere.
    pub uuid: [u8; 16],
    /// The subvolume this one was snapshotted from, all zeros where it was created outright.
    pub parent_uuid: [u8; 16],
    /// When it was created.
    pub otime: Timestamp,
    /// The subvolume it appears in, or [`None`] for the top-level tree.
    pub parent: Option<u64>,
    /// The inode of the directory it appears in, within its parent's tree.
    pub parent_dir: u64,
    /// The name it appears under there, empty for the top-level tree.
    pub name: Vec<u8>,
}

/// One name a walk reached, and the node at it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Absolute path from the filesystem root, `/`-joined, always beginning with `/`. Empty
    /// for the root itself, which is the first entry a walk yields.
    pub path: Vec<u8>,
    /// The node at that path.
    pub node: Node,
}

/// A btrfs filesystem opened over a seekable source, read as files rather than as trees.
///
/// ```no_run
/// use ferrosys::btrfs::Reader;
///
/// let mut reader = Reader::open(std::fs::File::open("root.img")?)?;
/// let node = reader.lookup(b"/etc/hostname")?;
/// println!("{} bytes", node.item.size);
/// print!("{}", String::from_utf8_lossy(&reader.read_data(&node)?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// The [`Volume`] underneath stays reachable, because the two layers answer different
/// questions: which trees are there and does every block verify is the volume's, and what is at
/// this path is this.
pub struct Reader<R> {
    volume: Volume<R>,
    subvolumes: Vec<Subvolume>,
    top: Subvolume,
    default_subvolume: u64,
}

impl<R: Read + Seek> Reader<R> {
    /// Open the filesystem at the start of `src`, strictly, with the default limits.
    ///
    /// # Errors
    ///
    /// See [`open_with`](Self::open_with).
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open the filesystem `options.base` bytes into `src`.
    ///
    /// Opening reads the volume — every superblock copy, the bootstrap, and the chunk tree —
    /// and then the root tree, which is what says how many subvolumes there are and where each
    /// one's tree begins. The filesystem tree of the top-level subvolume is the view a path is
    /// resolved in.
    ///
    /// # Errors
    ///
    /// Whatever [`Volume::open_with`] refuses, and [`ReadError::MissingTree`] where the root
    /// tree holds no record of the top-level filesystem tree.
    pub fn open_with(src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let mut volume = Volume::open_with(src, *options)?;
        let subvolumes = read_subvolumes(&mut volume)?;
        let top = subvolumes
            .iter()
            .find(|sub| sub.id == objectid::FS_TREE)
            .cloned()
            .ok_or(ReadError::MissingTree {
                objectid: objectid::FS_TREE,
            })?;
        let default_subvolume = read_default_subvolume(&mut volume)?.unwrap_or(objectid::FS_TREE);
        Ok(Self {
            volume,
            subvolumes,
            top,
            default_subvolume,
        })
    }

    /// The address space and the trees underneath, for the questions this layer does not ask.
    #[must_use]
    pub fn volume(&self) -> &Volume<R> {
        &self.volume
    }

    /// The same, for an operation that reads — walking a tree, fetching a block.
    pub fn volume_mut(&mut self) -> &mut Volume<R> {
        &mut self.volume
    }

    /// Give the volume back, and with it the source it was opened over.
    #[must_use]
    pub fn into_volume(self) -> Volume<R> {
        self.volume
    }

    /// How strictly this filesystem is being read.
    #[must_use]
    pub fn policy(&self) -> ReadPolicy {
        self.volume.policy()
    }

    /// The caps this read is held to.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.volume.limits()
    }

    /// Every subvolume the filesystem has, the top-level tree first and the rest in key order.
    #[must_use]
    pub fn subvolumes(&self) -> &[Subvolume] {
        &self.subvolumes
    }

    /// The subvolume a path is resolved in and a walk begins at: the top-level filesystem tree.
    #[must_use]
    pub fn top_level(&self) -> &Subvolume {
        &self.top
    }

    /// The subvolume the filesystem asks to be mounted at, which is the top-level tree unless
    /// something has changed it.
    ///
    /// A fact about the filesystem rather than a choice this reader makes: what is read here is
    /// always the whole tree from the top level down, subvolumes included, so nothing about a
    /// read depends on this. It is what a mount would do, reported.
    #[must_use]
    pub fn default_subvolume(&self) -> u64 {
        self.default_subvolume
    }

    /// The root directory of the top-level subvolume.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingInode`] where the tree holds no record of its own root directory.
    pub fn root(&mut self) -> Result<Node, ReadError> {
        let top = self.top.clone();
        self.inode(top.id, top.root_dir)
    }

    /// One inode of one subvolume.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingTree`] where the filesystem has no such subvolume, and
    /// [`ReadError::MissingInode`] where that subvolume's tree holds no such inode.
    pub fn inode(&mut self, tree: u64, inode: u64) -> Result<Node, ReadError> {
        let root = self.tree_root(tree)?;
        let key = DiskKey::new(inode, ItemType::INODE_ITEM, 0);
        let found = self
            .volume
            .tree(root)
            .find_exact(key)?
            .ok_or(ReadError::MissingInode { tree, inode })?;
        Ok(Node {
            tree,
            inode,
            item: InodeItem::read_from(&found.data)?,
        })
    }

    /// Every entry of a directory, in the order the directory stores them.
    ///
    /// The order is the `DIR_INDEX` one, which is the order the entries were created and what a
    /// readdir of the mounted filesystem yields. btrfs stores no `.` or `..` entry, so what
    /// comes back is the directory's own contents and nothing else.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotADirectory`] where the node is not one, whatever a walk of the tree
    /// refuses, and [`ReadError::BadDirEntry`] where an entry does not describe a name.
    pub fn read_dir(&mut self, node: &Node) -> Result<Vec<Entry>, ReadError> {
        if !node.is_dir() {
            return Err(ReadError::NotADirectory { path: Vec::new() });
        }
        let root = self.tree_root(node.tree)?;
        let from = DiskKey::first_of(node.inode, ItemType::DIR_INDEX);
        let mut entries = Vec::new();
        let mut failure = None;
        self.volume
            .tree(root)
            .for_each_item_from(from, |key, data| {
                if key.objectid != node.inode || key.kind != ItemType::DIR_INDEX {
                    return false;
                }
                // A `DIR_INDEX` key is one entry, so an item holding more than one record is
                // a filesystem saying two entries have one sequence number. Framed the same
                // way regardless, and every record kept: dropping the second would hide a
                // name rather than report it.
                let framed = for_each_packed::<DirItem, _>(data, |head, tail| {
                    let (name, _) = head.split(tail);
                    entries.push(Entry {
                        name: name.to_vec(),
                        kind: head.kind,
                        location: head.location,
                        index: key.offset,
                    });
                    true
                });
                match framed {
                    Ok(()) => true,
                    Err(e) => {
                        failure = Some(e.into());
                        false
                    }
                }
            })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(entries),
        }
    }

    /// The node at `path`, resolved from the root of the top-level subvolume, expanding every
    /// symbolic link along the way including one in the last component.
    ///
    /// Each component is found through the `DIR_ITEM` keyed by the hash of its name, so a
    /// resolution costs one descent per component rather than a listing per directory. A
    /// component naming a subvolume continues in that subvolume's tree, which is what makes a
    /// path across a subvolume boundary one path.
    ///
    /// A `..` component ascends to the directory the resolution descended from, staying at the
    /// root where there is nothing to ascend to — so it crosses back out of a subvolume the
    /// way it came in, and nothing outside the filesystem can be named.
    ///
    /// Resolution follows at most [`MAX_SYMLINK_HOPS`](crate::MAX_SYMLINK_HOPS) links, so
    /// a cycle terminates. A link whose target begins with `/` restarts at the top-level
    /// subvolume's root; one that does not continues from the directory holding the link.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotFound`] where no such name exists, [`ReadError::NotADirectory`] where a
    /// component names something a name cannot be looked up in, and
    /// [`ReadError::SymlinkLoop`] where the resolution follows too many links.
    pub fn lookup(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        self.resolve(path, true)
    }

    /// The node at `path`, expanding symbolic links in every component *except* the last — so a
    /// path naming a link yields the link and not what it points at. Otherwise as
    /// [`lookup`](Self::lookup).
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn lookup_no_follow(&mut self, path: &[u8]) -> Result<Node, ReadError> {
        self.resolve(path, false)
    }

    /// Walk `path` component by component from the root, expanding symbolic links.
    ///
    /// `follow_final` decides whether a link in the last component is expanded; the ones before
    /// it always are, because a path cannot continue through a link without going where it
    /// points. A distribution's root filesystem is the case that makes this obligatory rather
    /// than a nicety: `/bin`, `/lib`, and `/sbin` are links to directories under `/usr` on every
    /// current one, so a resolver that stopped at a link would find nothing under any of them.
    fn resolve(&mut self, path: &[u8], follow_final: bool) -> Result<Node, ReadError> {
        crate::resolve::drive(self, path, follow_final)
    }

    /// The entry of `dir` named `name`, or [`None`] where the directory holds no such name.
    ///
    /// # Errors
    ///
    /// Whatever a descent refuses, and [`ReadError::BadDirEntry`] where an item under the
    /// name's own hash does not frame as entries.
    pub fn find_entry(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Entry>, ReadError> {
        let root = self.tree_root(dir.tree)?;
        let key = DiskKey::new(dir.inode, ItemType::DIR_ITEM, name_hash(name));
        let Some(found) = self.volume.tree(root).find_exact(key)? else {
            return Ok(None);
        };
        let mut entry = None;
        for_each_packed::<DirItem, _>(&found.data, |head, tail| {
            let (stored, _) = head.split(tail);
            if stored == name {
                entry = Some(Entry {
                    name: stored.to_vec(),
                    kind: head.kind,
                    location: head.location,
                    // The hashed copy of an entry does not carry its sequence number; the
                    // indexed copy is keyed by it. A caller that needs the order asks
                    // `read_dir`, which reads the copy that has it.
                    index: 0,
                });
                return false;
            }
            true
        })?;
        Ok(entry)
    }

    /// The node an entry of `dir` names, crossing into another subvolume where it names one.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingTree`] where an entry names a subvolume the root tree has no record
    /// of, [`ReadError::MissingInode`] where it names an inode its tree does not hold, and
    /// [`ReadError::BadDirEntry`] where it names neither.
    pub fn step(&mut self, dir: &Node, entry: &Entry) -> Result<Node, ReadError> {
        self.at_location(dir.tree, entry.location)
    }

    /// Every extended attribute of a node, in the order the tree holds them.
    ///
    /// The values are the boundary form — what `getxattr` would have returned — which is what
    /// btrfs stores, so nothing is decoded on the way out. POSIX ACLs are `system.posix_acl_*`
    /// attributes holding the bytes [`Acl::encode`](crate::Acl::encode) produces, like every
    /// other value here.
    ///
    /// # Errors
    ///
    /// Whatever a walk of the tree refuses, and [`ReadError::BadXattr`] where a record does not
    /// frame as a name and a value.
    pub fn xattrs(&mut self, node: &Node) -> Result<Vec<Xattr>, ReadError> {
        let root = self.tree_root(node.tree)?;
        let from = DiskKey::first_of(node.inode, ItemType::XATTR_ITEM);
        let mut out = Vec::new();
        let mut failure = None;
        self.volume
            .tree(root)
            .for_each_item_from(from, |key, data| {
                if key.objectid != node.inode || key.kind != ItemType::XATTR_ITEM {
                    return false;
                }
                let framed = for_each_packed::<DirItem, _>(data, |head, tail| {
                    let (name, value) = head.split(tail);
                    out.push(Xattr {
                        name: name.to_vec(),
                        value: value.to_vec(),
                    });
                    true
                });
                match framed {
                    Ok(()) => true,
                    Err(_) => {
                        failure = Some(ReadError::BadXattr {
                            tree: node.tree,
                            inode: node.inode,
                        });
                        false
                    }
                }
            })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Fill `buf` from `offset` in a regular file, returning how many bytes were placed.
    ///
    /// A short fill means the file ends there. A run the file never had written — a hole, or a
    /// preallocated extent nothing has been put in — reads back as zeros, which is what it is.
    ///
    /// A node that is not a regular file holds no bytes and yields none: a directory's storage
    /// is its entries and a device node's is a pair of numbers, and handing either back as
    /// contents would be a record read as data.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadExtent`] where an extent record does not describe a run of the file,
    /// [`ReadError::UnsupportedCompression`] where its bytes are stored in a form this build
    /// does not decode, and whatever reading the tree or the data refuses.
    pub fn read_into(
        &mut self,
        node: &Node,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        if !node.is_file() && !node.is_symlink() {
            return Ok(0);
        }
        let size = node.item.size;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((size - offset) as usize);
        let out = &mut buf[..want];
        // Everything the extents do not cover is a hole, so the answer starts as zeros and
        // what is read overwrites them. A record that covers nothing therefore leaves the
        // right bytes rather than whatever the caller's buffer held.
        out.fill(0);
        let end = offset + want as u64;
        for (at, item, raw) in self.extent_records(node, offset, end)? {
            self.place_extent(node, at, &item, &raw, offset, out)?;
        }
        Ok(want)
    }

    /// Every byte of a regular file, gathered into memory.
    ///
    /// Held to [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), which defaults to no
    /// cap: a file's declared length is a number an image supplies, and a hole reads back as
    /// zeros, so an inode claiming a terabyte and mapping nothing costs a terabyte of them.
    /// Behind the caller's cap sits the machine's — a buffer no allocation can represent is
    /// refused with the same error, never attempted.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] where the file is longer than that cap, and whatever
    /// [`read_into`](Self::read_into) refuses.
    pub fn read_data(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        let size = node.item.size;
        // The declared size is a number the image supplies. The caller's cap defaults to
        // trusting it, but a buffer is addressed in `isize`, so a size past that bound has no
        // allocation to trust it into — asking would abort rather than fail, and every other
        // value an image oversupplies is a refusal.
        let cap = self.limits().max_file_bytes.min(isize::MAX as u64);
        if size > cap {
            return Err(ReadError::FileTooLarge {
                tree: node.tree,
                inode: node.inode,
                size,
                cap,
            });
        }
        let mut out = vec![0u8; size as usize];
        let mut at = 0usize;
        while at < out.len() {
            let placed = self.read_into(node, at as u64, &mut out[at..])?;
            if placed == 0 {
                break;
            }
            at += placed;
        }
        out.truncate(at);
        Ok(out)
    }

    /// Stream a regular file's bytes to `out`, returning how many were written.
    ///
    /// Bounded by a fixed buffer rather than by the file, so a file far larger than memory
    /// streams through. [`Limits::max_file_bytes`](crate::Limits::max_file_bytes) is not
    /// applied: what a caller has asked for here is a stream, and it costs the buffer.
    ///
    /// # Errors
    ///
    /// Whatever [`read_into`](Self::read_into) refuses, and [`ReadError::Io`] where the
    /// destination could not be written.
    pub fn read_data_to(&mut self, node: &Node, mut out: impl Write) -> Result<u64, ReadError> {
        let mut buf = vec![0u8; STREAM_BUFFER];
        let mut at = 0u64;
        loop {
            let placed = self.read_into(node, at, &mut buf)?;
            if placed == 0 {
                return Ok(at);
            }
            out.write_all(&buf[..placed])?;
            at += placed as u64;
        }
    }

    /// A symbolic link's target, exactly as the filesystem records it.
    ///
    /// A link's target is its contents, and btrfs stores it as an inline extent — so this is a
    /// whole-file read with the length the inode declares, and nothing here resolves what comes
    /// back.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotASymlink`] where the node is not one, and whatever reading its bytes
    /// refuses.
    pub fn link_target(&mut self, node: &Node) -> Result<Vec<u8>, ReadError> {
        if !node.is_symlink() {
            return Err(ReadError::NotASymlink {
                tree: node.tree,
                inode: node.inode,
            });
        }
        self.read_data(node)
    }

    /// Every name in the filesystem, gathered.
    ///
    /// The root comes first under the empty path, then depth-first with a parent before its
    /// children and siblings in the order their directory stores them.
    ///
    /// # Errors
    ///
    /// As [`walk_with`](Self::walk_with).
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, ReadError> {
        let mut out = Vec::new();
        self.walk_with::<ReadError, _>(|_, entry| {
            out.push(entry);
            Ok(())
        })?;
        Ok(out)
    }

    /// Walk every name in the filesystem, calling `visit` for each.
    ///
    /// The visitor is handed the reader back, so it can stat, read, and resolve while the walk
    /// is in progress and nothing has to be gathered up front.
    ///
    /// **Subvolume boundaries are crossed**, so what is walked is the filesystem rather than
    /// one tree. Every bound a walk of an untrusted tree needs — the cycle a crafted image can
    /// describe, the frontier, the depth — is the crate's shared walk rather than this
    /// family's, and what this family supplies is the three things it genuinely decides: what
    /// sits on the frontier, what identifies a directory, and how a directory's names are read.
    ///
    /// # Errors
    ///
    /// Whatever the visitor returns, and a [`ReadError`] converted into it where the filesystem
    /// cannot be walked — including [`ReadError::WalkTooLarge`] where the walk reaches the
    /// caller's cap.
    pub fn walk_with<E, F>(&mut self, mut visit: F) -> Result<(), E>
    where
        E: From<ReadError>,
        F: FnMut(&mut Self, WalkEntry) -> Result<(), E>,
    {
        // The root has no name, so the walk seeds from its children rather than from it.
        // Yielding it first under the empty path is what lets a sink apply the root's own
        // metadata without a second way of asking for it.
        let root = self.root().map_err(E::from)?;
        visit(
            self,
            WalkEntry {
                path: Vec::new(),
                node: root,
            },
        )?;
        crate::walk::drive(self, |reader, entry| visit(reader, entry))
    }

    /// Walk the whole filesystem and report every deviation, rather than stopping at the first.
    ///
    /// A read stops where it cannot go on. This does not: every tree the filesystem has is
    /// walked block by block — which verifies the checksum of every one of them — and what
    /// cannot be read becomes a finding rather than an error. An empty report is a filesystem
    /// nothing here objects to.
    ///
    /// Two of what it reports are this family's alone: **a live log tree**, which means the
    /// committed trees are stale with respect to writes this crate never replays, and **item
    /// types this reader has no opinion about**, which are skipped, counted, and named.
    ///
    /// What it does *not* do is verify file data. That is
    /// [`verify_data`](Self::verify_data), per file, because it reads every byte of the volume
    /// rather than every byte of its metadata — a different order of cost, and a caller asking
    /// whether an image is sound should not pay it without asking.
    #[must_use]
    pub fn scan(&mut self) -> ScanReport {
        let mut scan = Scan::new(self.limits().max_findings);
        let live = self.volume.superblock().generation;
        for (index, &state) in self.volume.mirrors().iter().enumerate() {
            if let Some((severity, detail)) = mirror_anomaly(state, live) {
                scan.at(
                    Category::Superblock,
                    severity,
                    None,
                    None,
                    format!("copy {index} of the superblock: {detail}"),
                );
            }
        }

        if has_live_log(&self.volume) {
            // The one instance of this rule across the families where "cosmetic" is
            // arguable. The message
            // says what is missing rather than which field held an unexpected value: the
            // filesystem genuinely holds writes the committed trees do not, and every byte
            // this reader hands back is nonetheless the last committed transaction's.
            scan.at(
                Category::Superblock,
                Severity::Cosmetic,
                None,
                Some(self.volume.superblock().log_root),
                "the filesystem was not cleanly unmounted and holds a log tree; what is read \
                 here is the last committed transaction, without the writes the log holds"
                    .to_string(),
            );
        }

        let roots = match self.volume.tree_roots() {
            Ok(roots) => roots,
            Err(e) => {
                let (category, severity) = walk_anomaly(&e);
                scan.at(
                    category,
                    severity,
                    Some(objectid::ROOT_TREE),
                    None,
                    format!("the root tree, which names every other: {e}"),
                );
                return scan.finish();
            }
        };
        for &root in &roots {
            if scan.found.is_full() {
                break;
            }
            // Every item of every tree, so the checksum of every block is verified on the way
            // and every item type met is counted. What the walk *means* is not asked here:
            // this pass is about whether the filesystem describes itself consistently.
            let walked = self.volume.tree(root).for_each_item(|key, _| {
                scan.met_unknown(key.kind);
                !scan.found.is_full()
            });
            if let Err(e) = walked {
                let (category, severity) = walk_anomaly(&e);
                scan.at(
                    category,
                    severity,
                    Some(root.objectid),
                    Some(root.bytenr),
                    format!("{}: {e}", tree_name(root.objectid)),
                );
            }
        }
        self.scan_uuid_mapping(&roots, &mut scan);
        scan.finish()
    }

    /// Hold the UUID tree and the subvolume root items to each other.
    ///
    /// Each names the other: a subvolume's root item records its identifier, and the UUID tree
    /// maps that identifier back to the subvolume. The pair can disagree while every block and
    /// every item of both trees verifies — a lookup by identifier then misses, and the format's
    /// own tooling rewrites the tree on the next writable mount — so the agreement is a check
    /// of its own rather than a property a walk implies. An all-zero identifier records that
    /// none was set, and has no entry to be held to.
    fn scan_uuid_mapping(&mut self, roots: &[TreeRoot], scan: &mut Scan) {
        let Some(&uuid_root) = roots
            .iter()
            .find(|root| root.objectid == objectid::UUID_TREE)
        else {
            return;
        };
        // What the root items record, keyed by subvolume id. Gathered when the filesystem was
        // opened, so this reads it rather than walking the root tree again.
        let recorded: std::collections::HashMap<u64, [u8; 16]> = self
            .subvolumes
            .iter()
            .map(|sub| (sub.id, sub.uuid))
            .collect();
        let mut satisfied: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let walked = self.volume.tree(uuid_root).for_each_item(|key, data| {
            if key.kind != ItemType::UUID_SUBVOL {
                return true;
            }
            // The key is the identifier split in half; the data is the subvolume ids it maps
            // to, 8 bytes each.
            let mut uuid = [0u8; 16];
            uuid[..8].copy_from_slice(&key.objectid.to_le_bytes());
            uuid[8..].copy_from_slice(&key.offset.to_le_bytes());
            if data.is_empty() || data.len() % 8 != 0 {
                scan.at(
                    Category::Item,
                    Severity::Structural,
                    Some(objectid::UUID_TREE),
                    None,
                    format!(
                        "the UUID tree's entry for {} holds {} bytes, which is not a list of \
                         8-byte subvolume ids",
                        crate::escape::hex(&uuid),
                        data.len()
                    ),
                );
                return !scan.found.is_full();
            }
            for id in data.chunks_exact(8) {
                let id = u64::from_le_bytes(id.try_into().expect("eight bytes"));
                match recorded.get(&id) {
                    Some(held) if *held == uuid => {
                        satisfied.insert(id);
                    }
                    Some(_) => scan.at(
                        Category::Item,
                        Severity::Structural,
                        Some(objectid::UUID_TREE),
                        None,
                        format!(
                            "the UUID tree maps identifier {} to subvolume {id}, whose root \
                             item records a different identifier",
                            crate::escape::hex(&uuid)
                        ),
                    ),
                    None => scan.at(
                        Category::Item,
                        Severity::Structural,
                        Some(objectid::UUID_TREE),
                        None,
                        format!(
                            "the UUID tree maps identifier {} to subvolume {id}, which does \
                             not exist",
                            crate::escape::hex(&uuid)
                        ),
                    ),
                }
            }
            !scan.found.is_full()
        });
        if walked.is_err() {
            // The walk of this tree failed in the pass above and was reported there; the
            // mapping cannot be judged on a tree that does not walk.
            return;
        }
        for sub in &self.subvolumes {
            if scan.found.is_full() {
                break;
            }
            if sub.uuid != [0; 16] && !satisfied.contains(&sub.id) {
                scan.at(
                    Category::Item,
                    Severity::Structural,
                    Some(objectid::UUID_TREE),
                    None,
                    format!(
                        "subvolume {} records identifier {} and the UUID tree has no entry \
                         mapping it back",
                        sub.id,
                        crate::escape::hex(&sub.uuid)
                    ),
                );
            }
        }
    }

    /// Hold every byte of a regular file against the checksums the filesystem recorded for it.
    ///
    /// **The check no other family in this crate can make.** ext4 checksums its metadata and
    /// not its data; neither FAT nor exFAT checksums anything. btrfs keeps a crc32c per sector
    /// of every data extent in a tree of its own, so an extent that has decayed on the medium,
    /// or a file whose bytes were replaced under a correct-looking tree, is detectable — and a
    /// reader that verified only what it walked through would not detect either.
    ///
    /// What is verified is the bytes **on the volume**, which is what the checksums cover. A
    /// compressed extent is therefore verifiable without being decompressed, and this verifies
    /// one.
    ///
    /// Three kinds of run are skipped, and each for a reason the format states: a hole and a
    /// preallocated extent hold nothing to check, and a file whose inode carries
    /// [`NODATASUM`](super::ondisk::InodeFlags::NODATASUM) has no checksums recorded at all.
    ///
    /// # Errors
    ///
    /// [`ReadError::DataChecksum`] naming the address whose bytes do not match,
    /// [`ReadError::MissingDataChecksum`] where a file that should have one has none, and
    /// whatever reading the trees or the data refuses.
    pub fn verify_data(&mut self, node: &Node) -> Result<(), ReadError> {
        if !node.is_file() && !node.is_symlink() {
            return Ok(());
        }
        if node
            .item
            .flags
            .contains(super::ondisk::InodeFlags::NODATASUM)
        {
            return Ok(());
        }
        let sector = u64::from(self.volume.superblock().sectorsize);
        let records = self.extent_records(node, 0, u64::MAX)?;
        for (at, item, _) in records {
            if item.kind.is_inline() || item.is_hole() || item.kind == ExtentKind::Prealloc {
                continue;
            }
            // The whole extent rather than this record's share of it: the checksums are keyed
            // by the extent's own address, and a record that takes the middle of a shared
            // extent is still asking about bytes the tree records under that address.
            let mut logical = item.disk_bytenr;
            let end = logical
                .checked_add(item.disk_num_bytes)
                .ok_or(ReadError::BadExtent {
                    tree: node.tree,
                    inode: node.inode,
                    at,
                    fault: "the extent's address runs past the end of the address space",
                })?;
            let mut buf = vec![0u8; sector as usize];
            while logical < end {
                let take = (end - logical).min(sector) as usize;
                self.volume.read_at(logical, &mut buf[..take])?;
                let recorded = self
                    .data_checksum(logical)?
                    .ok_or(ReadError::MissingDataChecksum { logical })?;
                if super::ondisk::crc32c_over(&buf[..take]) != recorded {
                    return Err(ReadError::DataChecksum { logical });
                }
                logical += take as u64;
            }
        }
        Ok(())
    }

    /// The checksum the checksum tree records for the sector at `logical`, or [`None`] where it
    /// records none.
    ///
    /// An `EXTENT_CSUM` item is keyed by the logical address its first checksum covers and
    /// holds one digest per sector from there, so finding the one covering an address is the
    /// last item keyed at or before it — and whether it reaches that far is arithmetic on its
    /// own length.
    fn data_checksum(&mut self, logical: u64) -> Result<Option<u32>, ReadError> {
        let sector = u64::from(self.volume.superblock().sectorsize);
        let Some(digest) = self.volume.superblock().csum_type.digest_len() else {
            return Ok(None);
        };
        let root = self.tree_root_of(objectid::CSUM_TREE)?;
        let wanted = DiskKey::new(objectid::EXTENT_CSUM, ItemType::EXTENT_CSUM, logical);
        let Some(found) = self.volume.tree(root).find_at_or_before(wanted)? else {
            return Ok(None);
        };
        if found.key.objectid != objectid::EXTENT_CSUM || found.key.kind != ItemType::EXTENT_CSUM {
            return Ok(None);
        }
        let covered = (found.data.len() / digest) as u64 * sector;
        // Checked, because the offset is a key the image supplies: an item keyed near the
        // top of the address space would wrap the sum, and a wrapped bound answers "covered"
        // for addresses the record never reached.
        let end = found.key.offset.checked_add(covered);
        if end.is_none_or(|end| logical >= end) {
            return Ok(None);
        }
        let index = ((logical - found.key.offset) / sector) as usize * digest;
        // Only the four bytes a crc32c fills are the digest; the rest of a record is another
        // algorithm's, and a filesystem using one never reaches here because opening it names
        // the algorithm as the reason it cannot be read.
        Ok((index + 4 <= found.data.len()).then(|| crate::bytes::get_u32(&found.data, index)))
    }

    /// Where one of the filesystem's own trees begins, found through the root tree.
    ///
    /// Separate from [`tree_root`](Self::tree_root), which answers for a subvolume: a subvolume
    /// is gathered at open because a walk crosses into one, and the filesystem's own trees are
    /// reached rarely and looked up when they are.
    fn tree_root_of(&mut self, objectid: u64) -> Result<TreeRoot, ReadError> {
        let root_tree = self.volume.root_tree();
        let key = DiskKey::new(objectid, ItemType::ROOT_ITEM, 0);
        let found = self
            .volume
            .tree(root_tree)
            .find_first(key)?
            .filter(|found| found.key.objectid == objectid && found.key.kind == ItemType::ROOT_ITEM)
            .ok_or(ReadError::MissingTree { objectid })?;
        let item = RootItem::read_from(&found.data)
            .map_err(|source| ReadError::BadRootItem { objectid, source })?;
        Ok(TreeRoot {
            objectid,
            bytenr: item.bytenr,
            level: item.level,
            generation: item.generation,
        })
    }

    /// The names below `dir`, as frontier elements under `path`, in reverse order so a stack
    /// pops them in the order the directory stores them.
    ///
    /// A name no directory can hold stops the walk here rather than becoming a path: a name
    /// carrying a separator would traverse out of its own directory in every path built from
    /// it, which is what an extraction would then write.
    fn pending_children(
        &mut self,
        dir: &Node,
        path: &[u8],
    ) -> Result<Vec<(Vec<u8>, u64, DiskKey)>, ReadError> {
        let mut out = Vec::new();
        for entry in self.read_dir(dir)? {
            if is_hostile_component(&entry.name) {
                return Err(ReadError::HostileName { name: entry.name });
            }
            let child = crate::walk::child_path(path, &entry.name).ok_or_else(|| {
                let mut too_long = path.to_vec();
                too_long.push(b'/');
                too_long.extend_from_slice(&entry.name);
                ReadError::PathTooLong { path: too_long }
            })?;
            out.push((child, dir.tree, entry.location));
        }
        out.reverse();
        Ok(out)
    }

    /// The node a directory entry's location names, given the subvolume the entry was found in.
    fn at_location(&mut self, tree: u64, location: DiskKey) -> Result<Node, ReadError> {
        match location.kind {
            ItemType::INODE_ITEM => self.inode(tree, location.objectid),
            ItemType::ROOT_ITEM => {
                let id = location.objectid;
                let root_dir = self
                    .subvolumes
                    .iter()
                    .find(|sub| sub.id == id)
                    .ok_or(ReadError::MissingTree { objectid: id })?
                    .root_dir;
                self.inode(id, root_dir)
            }
            other => Err(ReadError::BadDirEntry {
                tree,
                inode: location.objectid,
                fault: "the entry names neither an inode nor a subvolume",
                kind: other.value(),
            }),
        }
    }

    /// Where the tree of one subvolume begins.
    fn tree_root(&self, id: u64) -> Result<TreeRoot, ReadError> {
        self.subvolumes
            .iter()
            .find(|sub| sub.id == id)
            .map(|sub| sub.root)
            .ok_or(ReadError::MissingTree { objectid: id })
    }

    /// Every extent record of `node` that overlaps `[offset, end)`, in file order.
    ///
    /// Two descents rather than one per record: the first finds the record covering `offset`,
    /// which is the last one keyed at or before it, and the walk forward from there stops at
    /// the first record beyond the range. Reading from the middle of a file is what makes the
    /// first descent necessary — the record covering a position is keyed by where it *begins*,
    /// which is below the position asked for.
    fn extent_records(
        &mut self,
        node: &Node,
        offset: u64,
        end: u64,
    ) -> Result<Vec<(u64, FileExtentItem, Vec<u8>)>, ReadError> {
        let root = self.tree_root(node.tree)?;
        let wanted = DiskKey::new(node.inode, ItemType::EXTENT_DATA, offset);
        let covering = self.volume.tree(root).find_at_or_before(wanted)?;
        let from = match covering {
            Some(found)
                if found.key.objectid == node.inode && found.key.kind == ItemType::EXTENT_DATA =>
            {
                found.key
            }
            // Nothing at or before it belongs to this file, so the range begins at whatever
            // the file's first record is — and a file with none reads back as all zeros.
            _ => DiskKey::first_of(node.inode, ItemType::EXTENT_DATA),
        };
        let mut out = Vec::new();
        let mut failure = None;
        self.volume
            .tree(root)
            .for_each_item_from(from, |key, data| {
                if key.objectid != node.inode
                    || key.kind != ItemType::EXTENT_DATA
                    || key.offset >= end
                {
                    return false;
                }
                match FileExtentItem::read_from(data) {
                    Ok(item) => {
                        out.push((key.offset, item, data.to_vec()));
                        true
                    }
                    Err(e) => {
                        failure = Some(e.into());
                        false
                    }
                }
            })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Copy whatever one extent record contributes to `out`, which covers `[offset, ..)` of the
    /// file.
    fn place_extent(
        &mut self,
        node: &Node,
        at: u64,
        item: &FileExtentItem,
        raw: &[u8],
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), ReadError> {
        let bad = |fault: &'static str| ReadError::BadExtent {
            tree: node.tree,
            inode: node.inode,
            at,
            fault,
        };
        // Which encoding the bytes on the volume are in, and whether this build can undo it.
        // An algorithm the format has not defined and one this build carries no decoder for
        // are the same answer to a caller — the file cannot be read here — and the message
        // names which it was.
        let encoding = match decode::algorithm(item.compression) {
            None => None,
            Some(Some(algorithm)) if algorithm.available() => Some(algorithm),
            Some(_) => {
                return Err(ReadError::UnsupportedCompression {
                    tree: node.tree,
                    inode: node.inode,
                    compression: item.compression.to_u8(),
                });
            }
        };
        if item.encryption != 0 || item.other_encoding != 0 {
            return Err(ReadError::UnsupportedEncoding {
                tree: node.tree,
                inode: node.inode,
                encryption: item.encryption,
                other: item.other_encoding,
            });
        }

        // How much of the file this record claims, and where in `out` that lands. Both are
        // computed against the record's own declared length, which is a number the image
        // supplied — so every step of it is checked rather than assumed to fit.
        let covers = if item.kind.is_inline() {
            item.ram_bytes
        } else {
            item.num_bytes
        };
        let record_end = at
            .checked_add(covers)
            .ok_or_else(|| bad("the record's length runs past the end of the address space"))?;
        let start = at.max(offset);
        let stop = record_end.min(offset + out.len() as u64);
        if stop <= start {
            return Ok(());
        }
        let into = (start - offset) as usize;
        let len = (stop - start) as usize;
        let within = start - at;

        if item.kind.is_inline() {
            let stored = item.inline_data(raw)?;
            if let Some(algorithm) = encoding {
                // The record's own bytes are the stream, and what it expands to is the whole
                // of what the record covers — so the window is taken from the expansion at
                // the same position it would have been taken from the item.
                let whole = self.expand(node, at, item, algorithm, stored)?;
                let from = within as usize;
                out[into..into + len].copy_from_slice(&whole[from..from + len]);
                return Ok(());
            }
            // The item's own length is what says how many bytes are there, and a record
            // claiming more than the item holds is refused rather than padded: padding it
            // would hand back zeros the file does not have.
            if (stored.len() as u64) < covers {
                return Err(bad("the record claims more bytes than the item holds"));
            }
            let from = within as usize;
            out[into..into + len].copy_from_slice(&stored[from..from + len]);
            return Ok(());
        }

        // A hole and a preallocated extent both read back as zeros, which `out` already holds.
        if item.is_hole() || item.kind == ExtentKind::Prealloc {
            return Ok(());
        }
        if item.kind != ExtentKind::Regular {
            return Err(bad("the record is of a shape this reader does not define"));
        }

        if let Some(algorithm) = encoding {
            // A compressed extent is undone whole: the bytes on the volume are one framed run
            // that expands to `ram_bytes`, and nothing inside it says where a position in the
            // file lands. So the extent is read, expanded, and the window taken from what it
            // expanded to — which is also why `offset` is measured against that length here
            // and against the stored length below.
            if item.disk_num_bytes > decode::MAX_COMPRESSED {
                return Err(bad(
                    "the extent stores more than this format compresses into",
                ));
            }
            let mut stored = vec![0u8; item.disk_num_bytes as usize];
            self.volume.read_at(item.disk_bytenr, &mut stored)?;
            let whole = self.expand(node, at, item, algorithm, &stored)?;
            let skip = item
                .offset
                .checked_add(within)
                .ok_or_else(|| bad("the record begins past the end of the extent it names"))?;
            let last = skip
                .checked_add(len as u64)
                .ok_or_else(|| bad("the record's run leaves the extent it names"))?;
            if last > whole.len() as u64 {
                return Err(bad("the record's run leaves the extent it names"));
            }
            let from = skip as usize;
            out[into..into + len].copy_from_slice(&whole[from..from + len]);
            return Ok(());
        }

        // Where in the extent this record's bytes begin, plus how far into the record the
        // wanted run starts. Both are the image's numbers, and the sum must stay inside the
        // extent the record names — otherwise the read is of whatever follows it on the
        // volume, under this file's name.
        let skip = item
            .offset
            .checked_add(within)
            .ok_or_else(|| bad("the record begins past the end of the extent it names"))?;
        let last = skip
            .checked_add(len as u64)
            .ok_or_else(|| bad("the record's run leaves the extent it names"))?;
        if last > item.disk_num_bytes {
            return Err(bad("the record's run leaves the extent it names"));
        }
        let logical = item
            .disk_bytenr
            .checked_add(skip)
            .ok_or_else(|| bad("the record's address runs past the end of the address space"))?;
        self.volume.read_at(logical, &mut out[into..into + len])
    }

    /// The bytes one compressed extent expands to, whole.
    ///
    /// The buffer is the size the record declares, and that declaration is a number the image
    /// supplied — so it is held to what this format compresses in before a byte is allocated
    /// for it. A record claiming a gibibyte costs a refusal rather than a gibibyte.
    ///
    /// A stream that stops before it has produced what the record declared is refused rather
    /// than zero-filled, which is the same rule the uncompressed inline path follows: the tail
    /// would be zeros the file does not have.
    fn expand(
        &mut self,
        node: &Node,
        at: u64,
        item: &FileExtentItem,
        algorithm: Algorithm,
        stored: &[u8],
    ) -> Result<Vec<u8>, ReadError> {
        if item.ram_bytes > decode::MAX_UNCOMPRESSED {
            return Err(ReadError::BadExtent {
                tree: node.tree,
                inode: node.inode,
                at,
                fault: "the record expands to more than this format compresses in",
            });
        }
        let sector_size = self.volume.superblock().sectorsize;
        let mut whole = vec![0u8; item.ram_bytes as usize];
        let produced = decode::decode(algorithm, stored, &mut whole, sector_size).map_err(|e| {
            ReadError::BadCompressedExtent {
                tree: node.tree,
                inode: node.inode,
                at,
                fault: e.to_string(),
            }
        })?;
        if produced != whole.len() {
            return Err(ReadError::BadCompressedExtent {
                tree: node.tree,
                inode: node.inode,
                at,
                fault: format!(
                    "it expands to {produced} bytes and the record declares {}",
                    whole.len()
                ),
            });
        }
        Ok(whole)
    }
}

/// How much of a file is held in memory at once while it is streamed. A megabyte, which is
/// large enough that the per-call descent is amortized and small enough to be nothing.
const STREAM_BUFFER: usize = 1 << 20;

/// Every subvolume the root tree records, the top-level tree first.
///
/// Three item types in one pass over the root tree, because they are three views of the same
/// thing: a `ROOT_ITEM` says where a tree is, a `ROOT_BACKREF` says which subvolume it appears
/// in and under what name, and everything else in the tree is one of the filesystem's own trees
/// rather than a subvolume.
fn read_subvolumes<R: Read + Seek>(volume: &mut Volume<R>) -> Result<Vec<Subvolume>, ReadError> {
    let root_tree = volume.root_tree();
    let mut items: BTreeMap<u64, (RootItem, TreeRoot)> = BTreeMap::new();
    let mut links: BTreeMap<u64, (u64, u64, Vec<u8>)> = BTreeMap::new();
    let mut failure = None;
    volume.tree(root_tree).for_each_item(|key, data| {
        if !is_subvolume_id(key.objectid) {
            return true;
        }
        match key.kind {
            ItemType::ROOT_ITEM => match RootItem::read_from(data) {
                Ok(item) => {
                    let root = TreeRoot {
                        objectid: key.objectid,
                        bytenr: item.bytenr,
                        level: item.level,
                        generation: item.generation,
                    };
                    items.insert(key.objectid, (item, root));
                    true
                }
                Err(e) => {
                    failure = Some(ReadError::BadRootItem {
                        objectid: key.objectid,
                        source: e,
                    });
                    false
                }
            },
            // The child's own copy of the link, so the parent is the key's offset and one
            // pass over the tree finds every subvolume's parent without a second descent.
            ItemType::ROOT_BACKREF => {
                let mut link = None;
                let framed = for_each_packed::<RootRef, _>(data, |head, name| {
                    link = Some((key.offset, head.dirid, name.to_vec()));
                    false
                });
                match framed {
                    Ok(()) => {
                        if let Some(link) = link {
                            links.insert(key.objectid, link);
                        }
                        true
                    }
                    Err(e) => {
                        failure = Some(e.into());
                        false
                    }
                }
            }
            _ => true,
        }
    })?;
    if let Some(e) = failure {
        return Err(e);
    }

    let mut out: Vec<Subvolume> = items
        .into_iter()
        .map(|(id, (item, root))| {
            let (parent, parent_dir, name) = links
                .remove(&id)
                .map_or((None, 0, Vec::new()), |(parent, dir, name)| {
                    (Some(parent), dir, name)
                });
            Subvolume {
                id,
                root,
                root_dir: item.root_dirid,
                read_only: item.flags.contains(RootFlags::SUBVOL_RDONLY),
                uuid: item.uuid,
                parent_uuid: item.parent_uuid,
                otime: item.otime,
                parent,
                parent_dir,
                name,
            }
        })
        .collect();
    out.sort_by_key(|sub| (sub.id != objectid::FS_TREE, sub.id));
    Ok(out)
}

/// The subvolume the filesystem asks to be mounted at, or [`None`] where nothing has said.
///
/// It is a directory entry rather than a field: the root tree has a directory of its own, and
/// the entry named `default` in it is what a mount follows.
fn read_default_subvolume<R: Read + Seek>(
    volume: &mut Volume<R>,
) -> Result<Option<u64>, ReadError> {
    let root_tree = volume.root_tree();
    let key = DiskKey::new(
        objectid::ROOT_TREE_DIR,
        ItemType::DIR_ITEM,
        name_hash(b"default"),
    );
    let Some(found) = volume.tree(root_tree).find_exact(key)? else {
        return Ok(None);
    };
    let mut id = None;
    for_each_packed::<DirItem, _>(&found.data, |head, tail| {
        let (name, _) = head.split(tail);
        if name == b"default" && head.location.kind == ItemType::ROOT_ITEM {
            id = Some(head.location.objectid);
            return false;
        }
        true
    })?;
    Ok(id)
}

/// What this family supplies to the crate's shared path resolution: a hashed lookup to find a
/// name in a directory, and the pair that names an inode to come back to.
///
/// The ascent a `..` component makes is the shared resolution's, and this family is the reason
/// it holds directories rather than inode numbers: an inode number means one thing in one
/// subvolume's tree and something else in another, so a path that descends into a subvolume and
/// ascends back out of it needs the tree it came from as much as the number.
impl<R: Read + Seek> crate::resolve::Resolve for Reader<R> {
    /// A subvolume and an inode number, which is what [`Reader::inode`] takes and what a node
    /// is identified by anywhere in this family.
    type Ancestor = (u64, u64);
    type Node = Node;
    type Error = ReadError;

    fn root_node(&mut self) -> Result<Node, ReadError> {
        self.root()
    }

    fn ancestor_of(&self, node: &Node) -> (u64, u64) {
        (node.tree, node.inode)
    }

    fn node_at(&mut self, (tree, inode): (u64, u64)) -> Result<Node, ReadError> {
        self.inode(tree, inode)
    }

    fn is_directory(&self, node: &Node) -> bool {
        node.is_dir()
    }

    fn find_name(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Node>, ReadError> {
        // One descent per component rather than a listing per directory: a name is found
        // through the `DIR_ITEM` keyed by its own hash. A component naming a subvolume steps
        // into that subvolume's tree, which is what makes a path across the boundary one path.
        let Some(entry) = self.find_entry(dir, name)? else {
            return Ok(None);
        };
        Ok(Some(self.step(dir, &entry)?))
    }

    fn read_link(&mut self, node: &Node, path: &[u8]) -> Result<Option<Vec<u8>>, ReadError> {
        if !node.is_symlink() {
            return Ok(None);
        }
        // A target longer than a path can be is refused before it is read, so a crafted size
        // cannot make one link allocate more than a path's worth.
        if node.item.size > MAX_PATH as u64 {
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

/// What this family supplies to the crate's shared depth-first walk: what sits on the frontier,
/// what identifies a directory, and how a directory's names are read.
///
/// The three bounds a walk of an untrusted tree needs — the cycle, the frontier, the depth —
/// are the shared walk's and not restated here. What is this family's alone is that a frontier
/// element carries **the subvolume its parent was in**: a location naming an inode is an inode
/// of that same tree, and one naming a root is where another tree begins.
impl<R: Read + Seek> crate::walk::Walk for Reader<R> {
    /// A name reached and not yet visited: its path, the subvolume the directory holding it is
    /// in, and the key of what it names.
    ///
    /// The node itself is not kept. The frontier holds every name reached and not yet visited,
    /// and re-reading an inode is one descent — so what rides here is the least that can find
    /// it again.
    type Pending = (Vec<u8>, u64, DiskKey);
    type Entry = WalkEntry;
    type Key = (u64, u64);
    type Error = ReadError;

    fn cap(&mut self) -> usize {
        self.limits().max_walk_entries
    }

    fn seed(&mut self) -> Result<crate::walk::Seed<Self>, ReadError> {
        let root = self.root()?;
        let children = self.pending_children(&root, b"")?;
        Ok((children, vec![(root.tree, root.inode)]))
    }

    fn resolve(&mut self, pending: Self::Pending) -> Result<WalkEntry, ReadError> {
        let (path, tree, location) = pending;
        let node = self.at_location(tree, location)?;
        Ok(WalkEntry { path, node })
    }

    fn descend_key(&self, entry: &WalkEntry) -> Option<(u64, u64)> {
        entry
            .node
            .is_dir()
            .then_some((entry.node.tree, entry.node.inode))
    }

    fn children(&mut self, entry: &WalkEntry) -> Result<Vec<Self::Pending>, ReadError> {
        self.pending_children(&entry.node, &entry.path)
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
            ReadError::FileTooLarge { .. } | ReadError::TooManyEntries { .. } => {
                TreeError::LimitExceeded {
                    family: Family::Btrfs,
                    detail: err.to_string(),
                }
            }
            // A filesystem that is entirely well-formed and beyond this build. Every one of
            // these names what it would take to read it, which is what the shared frame calls
            // unsupported rather than malformed.
            ReadError::UnsupportedFeatures { .. }
            | ReadError::UnsupportedChecksum { .. }
            | ReadError::UnsupportedProfile { .. }
            | ReadError::UnsupportedCompression { .. }
            | ReadError::UnsupportedEncoding { .. }
            | ReadError::MultiDevice { .. } => TreeError::Unsupported {
                family: Family::Btrfs,
                detail: err.to_string(),
            },
            other => TreeError::Malformed {
                family: Family::Btrfs,
                detail: other.to_string(),
            },
        }
    }
}

impl<R: Read + Seek> FsTree for Reader<R> {
    type Node = Node;

    fn family(&self) -> Family {
        Family::Btrfs
    }

    fn max_file_bytes(&self) -> u64 {
        self.limits().max_file_bytes
    }

    fn walk_tree<E, F>(&mut self, mut visit: F) -> Result<(), E>
    where
        E: From<TreeError>,
        F: FnMut(&mut Self, TreeEntry<Node>) -> Result<(), E>,
    {
        // Which nodes two names are both for, assigned as the walk meets them. The pair
        // `(subvolume, inode)` is what identifies a node here and a shared identity is one
        // number, so the mapping cannot be arithmetic: inode 257 exists in every subvolume,
        // and a scheme that mixed the two into one integer would claim two unrelated files
        // were hard links to each other.
        let mut shared: BTreeMap<(u64, u64), u64> = BTreeMap::new();
        let outcome = self.walk_with::<WalkFail<E>, _>(|reader, entry| {
            let node = entry.node;
            let kind = match node.item.mode_type() {
                MODE_DIR => NodeKind::Directory,
                MODE_REG => NodeKind::File {
                    size: node.item.size,
                },
                MODE_LNK => NodeKind::Symlink,
                MODE_CHR => {
                    let (major, minor) = node.item.device();
                    NodeKind::CharDevice { major, minor }
                }
                MODE_BLK => {
                    let (major, minor) = node.item.device();
                    NodeKind::BlockDevice { major, minor }
                }
                MODE_FIFO => NodeKind::Fifo,
                MODE_SOCK => NodeKind::Socket,
                other => {
                    return Err(WalkFail::Tree(TreeError::Malformed {
                        family: Family::Btrfs,
                        detail: format!(
                            "inode {} of subvolume {} records file type {other:#o}, which names \
                             no file type",
                            node.inode, node.tree
                        ),
                    }));
                }
            };
            let mut out = TreeEntry::new(entry.path, kind, node);
            // A directory has one name by construction, so its link count says nothing and it
            // is never a second name for anything. Only a node the image says has more than
            // one name carries an identity, which keeps a sink's table down to the tree's
            // actual links rather than a path per file in it.
            if !matches!(kind, NodeKind::Directory) && node.item.nlink > 1 {
                let next = shared.len() as u64;
                out = out.shared(*shared.entry((node.tree, node.inode)).or_insert(next));
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
        // Nothing is synthesized. btrfs records an owner, a group, a mode, and four times of
        // full nanosecond resolution, so every property the shared frame carries is one this
        // filesystem holds — and the caller's fallbacks are ignored rather than mixed in.
        let meta = Metadata {
            mode: node.item.mode as u16,
            uid: node.item.uid,
            gid: node.item.gid,
            atime: node.item.atime,
            ctime: node.item.ctime,
            mtime: node.item.mtime,
        };
        Ok(Attributes::read(meta, self.xattrs(node)?))
    }

    fn read_bytes(&mut self, node: &Node, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError> {
        Ok(Reader::read_into(self, node, offset, buf)?)
    }

    fn link_target(&mut self, node: &Node) -> Result<Vec<u8>, TreeError> {
        Ok(Reader::link_target(self, node)?)
    }
}

/// The `S_IFMT` value of a character-special device node.
const MODE_CHR: u32 = 0o020_000;
/// The `S_IFMT` value of a block-special device node.
const MODE_BLK: u32 = 0o060_000;
/// The `S_IFMT` value of a named pipe.
const MODE_FIFO: u32 = 0o010_000;
/// The `S_IFMT` value of a Unix-domain socket node.
const MODE_SOCK: u32 = 0o140_000;

/// Whether an id in the root tree names a subvolume rather than one of the filesystem's own
/// trees.
///
/// The top-level tree has a fixed id below the free range, and every other subvolume is inside
/// it. The relocation trees sit at the top of the range and are neither.
const fn is_subvolume_id(objectid: u64) -> bool {
    objectid == objectid::FS_TREE
        || (objectid >= objectid::FIRST_FREE && objectid <= objectid::LAST_FREE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::forge::{
        DATA_AT, DATA_BYTE, FS_TREE_AT, Forge, NODE_SIZE, ROOT_DIR, TIME, addressed_extent,
        compressed_extent, csum_item, entry, fs_tree, inline_extent, inode_item, leaf, root_item,
    };
    use crate::btrfs::ondisk::{Compression, InodeFlags};
    use crate::btrfs::scan::Anomaly;

    /// Where a second subvolume's tree sits in the forged image.
    const SUB_TREE_AT: u64 = FS_TREE_AT + NODE_SIZE as u64;

    /// The id a nested subvolume takes.
    const SUB_ID: u64 = 257;

    /// A filesystem whose root directory holds `items`, and nothing else.
    ///
    /// What each gate below builds for itself: the filesystem that is wrong in the way that
    /// gate is about. The one that is right is `Forge::populated`.
    fn a_filesystem_holding(items: Vec<(DiskKey, Vec<u8>)>) -> Forge {
        let mut all = vec![(
            DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
            inode_item(MODE_DIR | 0o755, 0, 1),
        )];
        all.extend(items);
        let mut forge = Forge::new();
        forge.block(FS_TREE_AT, &fs_tree(FS_TREE_AT, objectid::FS_TREE, all));
        forge.data(DATA_AT, &[DATA_BYTE; 4096]);
        forge.root_leaf(&[(
            DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0),
            root_item(FS_TREE_AT, 0, ROOT_DIR),
        )]);
        forge
    }

    /// One file at `/name`, of `mode`, `size` bytes long, whose bytes `record` describes.
    fn a_file(name: &[u8], mode: u32, size: u64, record: Vec<u8>) -> Vec<(DiskKey, Vec<u8>)> {
        let mut items = vec![
            (
                DiskKey::new(257, ItemType::INODE_ITEM, 0),
                inode_item(mode, size, 1),
            ),
            (DiskKey::new(257, ItemType::EXTENT_DATA, 0), record),
        ];
        items.extend(entry(
            ROOT_DIR,
            2,
            name,
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        items
    }

    /// The same, with a subvolume mounted at `/nested` and a file inside it.
    fn a_filesystem_with_a_subvolume() -> Forge {
        let mut top = vec![
            (
                DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
                inode_item(MODE_DIR | 0o755, 0, 1),
            ),
            (
                DiskKey::new(257, ItemType::INODE_ITEM, 0),
                inode_item(MODE_REG | 0o644, 3, 1),
            ),
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 0),
                inline_extent(b"up\n"),
            ),
        ];
        top.extend(entry(
            ROOT_DIR,
            2,
            b"above",
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        // The entry a subvolume is mounted at names a `ROOT_ITEM`, not an inode.
        top.extend(entry(
            ROOT_DIR,
            3,
            b"nested",
            DiskKey::new(SUB_ID, ItemType::ROOT_ITEM, u64::MAX),
            DirEntryType::Dir,
        ));

        let mut sub = vec![
            (
                DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
                inode_item(MODE_DIR | 0o755, 0, 1),
            ),
            (
                DiskKey::new(257, ItemType::INODE_ITEM, 0),
                inode_item(MODE_REG | 0o644, 6, 1),
            ),
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 0),
                inline_extent(b"inside"),
            ),
        ];
        sub.extend(entry(
            ROOT_DIR,
            2,
            b"within",
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));

        let mut forge = Forge::new();
        forge.block(FS_TREE_AT, &fs_tree(FS_TREE_AT, objectid::FS_TREE, top));
        forge.block(SUB_TREE_AT, &fs_tree(SUB_TREE_AT, SUB_ID, sub));
        let mut backref = vec![0u8; 18];
        RootRef {
            dirid: ROOT_DIR,
            sequence: 3,
            name_len: 6,
        }
        .write_to(&mut backref);
        backref.extend_from_slice(b"nested");
        forge.root_leaf(&[
            (
                DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0),
                root_item(FS_TREE_AT, 0, ROOT_DIR),
            ),
            (
                DiskKey::new(SUB_ID, ItemType::ROOT_ITEM, 0),
                root_item(SUB_TREE_AT, 0, ROOT_DIR),
            ),
            (
                DiskKey::new(SUB_ID, ItemType::ROOT_BACKREF, objectid::FS_TREE),
                backref,
            ),
        ]);
        forge
    }

    fn open(forge: &Forge) -> Reader<crate::btrfs::forge::Sparse> {
        Reader::open(forge.source()).expect("a forged filesystem opens")
    }

    #[test]
    fn a_filesystem_opens_at_the_root_of_its_top_level_subvolume() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        assert_eq!(reader.subvolumes().len(), 1);
        assert_eq!(reader.top_level().id, objectid::FS_TREE);
        assert_eq!(reader.default_subvolume(), objectid::FS_TREE);
        let root = reader.root().expect("the root directory");
        assert_eq!(root.inode, ROOT_DIR);
        assert!(root.is_dir());
        assert_eq!(root.item.mode & 0o7777, 0o755);
        // The four times a btrfs inode carries, all of them read rather than derived.
        assert_eq!(root.item.mtime, TIME);
        assert_eq!(root.item.otime, TIME);
    }

    #[test]
    fn a_directory_lists_its_entries_in_the_order_it_stores_them() {
        // The order is the indexed copy's, which is creation order — not the hashed copy's,
        // which is an order nothing about the filesystem chose.
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let root = reader.root().expect("the root");
        let names: Vec<Vec<u8>> = reader
            .read_dir(&root)
            .expect("the root lists")
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            names,
            vec![
                b"hello.txt".to_vec(),
                b"big".to_vec(),
                b"link".to_vec(),
                b"sub".to_vec()
            ]
        );
        // And a directory holds no `.` or `..` entry, so what comes back is its contents.
        assert!(!names.iter().any(|name| name == b"." || name == b".."));
    }

    #[test]
    fn a_name_is_found_through_the_hash_it_is_keyed_by() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let node = reader.lookup(b"/hello.txt").expect("the file");
        assert!(node.is_file());
        assert_eq!(node.item.size, 6);
        // A path more than one component deep crosses a directory at each step.
        let inner = reader.lookup(b"/sub/inner").expect("the nested file");
        assert_eq!(reader.read_data(&inner).expect("its bytes"), b"in\n");
        // A name that is not there is not an error about the tree.
        assert!(matches!(
            reader.lookup(b"/missing"),
            Err(ReadError::NotFound { .. })
        ));
        // And a name looked up inside something that is not a directory says so.
        assert!(matches!(
            reader.lookup(b"/hello.txt/deeper"),
            Err(ReadError::NotADirectory { .. })
        ));
    }

    #[test]
    fn a_small_file_is_read_out_of_the_record_that_holds_it() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let node = reader.lookup(b"/hello.txt").expect("the file");
        assert_eq!(reader.read_data(&node).expect("its bytes"), b"hello\n");
        // And read from the middle, which is what the covering-record search is for: the
        // record is keyed at zero and the position asked for is not.
        let mut buf = [0u8; 3];
        assert_eq!(
            reader
                .read_into(&node, 2, &mut buf)
                .expect("a partial read"),
            3
        );
        assert_eq!(&buf, b"llo");
        // Past the end is no bytes rather than a failure.
        assert_eq!(
            reader.read_into(&node, 6, &mut buf).expect("past the end"),
            0
        );
    }

    #[test]
    fn a_large_file_is_read_through_the_extent_that_addresses_it() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let node = reader.lookup(b"/big").expect("the file");
        let bytes = reader.read_data(&node).expect("its bytes");
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.iter().all(|&b| b == 0xab));
        // Streamed to a destination it is the same bytes, which is what says the two paths
        // through the extents agree.
        let mut streamed = Vec::new();
        assert_eq!(
            reader
                .read_data_to(&node, &mut streamed)
                .expect("streaming it"),
            4096
        );
        assert_eq!(streamed, bytes);
    }

    #[test]
    fn a_symbolic_link_hands_back_the_target_it_records() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let link = reader.lookup_no_follow(b"/link").expect("the link");
        assert!(link.is_symlink());
        assert_eq!(reader.link_target(&link).expect("its target"), b"hello.txt");
        // The target is reproduced as it stands: reading one is not resolving one.
        let file = reader.lookup_no_follow(b"/hello.txt").expect("the file");
        assert_ne!(link.inode, file.inode);
        // And a node that is not a link has no target rather than an empty one.
        assert!(matches!(
            reader.link_target(&file),
            Err(ReadError::NotASymlink { .. })
        ));
    }

    /// A symbolic link numbered `inode`, entered in `dir` at `index` under `name`, pointing at
    /// `target`.
    fn a_link(
        dir: u64,
        inode: u64,
        index: u64,
        name: &[u8],
        target: &[u8],
    ) -> Vec<(DiskKey, Vec<u8>)> {
        let mut items = vec![
            (
                DiskKey::new(inode, ItemType::INODE_ITEM, 0),
                inode_item(MODE_LNK | 0o777, target.len() as u64, 1),
            ),
            (
                DiskKey::new(inode, ItemType::EXTENT_DATA, 0),
                inline_extent(target),
            ),
        ];
        items.extend(entry(
            dir,
            index,
            name,
            DiskKey::new(inode, ItemType::INODE_ITEM, 0),
            DirEntryType::Symlink,
        ));
        items
    }

    #[test]
    fn a_path_continues_through_a_link_naming_a_directory() {
        // The shape every current distribution's root filesystem has: `/bin`, `/lib`, and
        // `/sbin` are links to directories under `/usr`, so a resolver that stopped at a link
        // would find nothing under any of them and report the tree as missing most of itself.
        let mut items = vec![
            (
                DiskKey::new(260, ItemType::INODE_ITEM, 0),
                inode_item(MODE_DIR | 0o755, 0, 1),
            ),
            (
                DiskKey::new(261, ItemType::INODE_ITEM, 0),
                inode_item(MODE_REG | 0o644, 3, 1),
            ),
            (
                DiskKey::new(261, ItemType::EXTENT_DATA, 0),
                inline_extent(b"in\n"),
            ),
        ];
        items.extend(entry(
            ROOT_DIR,
            2,
            b"sub",
            DiskKey::new(260, ItemType::INODE_ITEM, 0),
            DirEntryType::Dir,
        ));
        items.extend(entry(
            260,
            2,
            b"inner",
            DiskKey::new(261, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        items.extend(a_link(ROOT_DIR, 259, 3, b"to-sub", b"sub"));
        let forge = a_filesystem_holding(items);
        let mut reader = open(&forge);

        let through = reader
            .lookup(b"/to-sub/inner")
            .expect("a path continuing through a link to a directory");
        let direct = reader
            .lookup(b"/sub/inner")
            .expect("the same file directly");
        assert_eq!((through.tree, through.inode), (direct.tree, direct.inode));
        assert_eq!(reader.read_data(&through).expect("its bytes"), b"in\n");

        // And a link in a component that is not the last is expanded whichever lookup asks,
        // because a path cannot continue through a link without going where it points.
        let stopped = reader
            .lookup_no_follow(b"/to-sub/inner")
            .expect("the same, not following the last component");
        assert_eq!((stopped.tree, stopped.inode), (direct.tree, direct.inode));
    }

    #[test]
    fn a_target_beginning_at_the_root_restarts_there() {
        let mut items = vec![
            (
                DiskKey::new(260, ItemType::INODE_ITEM, 0),
                inode_item(MODE_DIR | 0o755, 0, 1),
            ),
            (
                DiskKey::new(261, ItemType::INODE_ITEM, 0),
                inode_item(MODE_REG | 0o644, 3, 1),
            ),
            (
                DiskKey::new(261, ItemType::EXTENT_DATA, 0),
                inline_extent(b"at\n"),
            ),
        ];
        items.extend(entry(
            ROOT_DIR,
            2,
            b"sub",
            DiskKey::new(260, ItemType::INODE_ITEM, 0),
            DirEntryType::Dir,
        ));
        items.extend(entry(
            ROOT_DIR,
            3,
            b"top.txt",
            DiskKey::new(261, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        // A link two directories down whose target begins at the root. Resolved against the
        // directory holding it, it would name nothing; resolved against the root, it names the
        // file. The two readings differ on every absolute link in a real tree.
        items.extend(a_link(260, 259, 2, b"up", b"/top.txt"));
        // And the relative form of the same reach, which is the shape a distribution's
        // `/usr/lib64` has: the target ascends out of the directory holding the link and comes
        // back down. It names the same file by a route that never mentions the root.
        items.extend(a_link(260, 262, 3, b"over", b"../top.txt"));
        let forge = a_filesystem_holding(items);
        let mut reader = open(&forge);

        let found = reader
            .lookup(b"/sub/up")
            .expect("resolving the absolute target");
        assert_eq!(reader.read_data(&found).expect("its bytes"), b"at\n");

        let ascended = reader
            .lookup(b"/sub/over")
            .expect("resolving the ascending relative target");
        assert_eq!((ascended.tree, ascended.inode), (found.tree, found.inode));
    }

    #[test]
    fn a_chain_of_links_that_does_not_end_is_refused() {
        // Two links naming each other. A resolver with no budget follows this until something
        // else stops it, which on an image this crate did not write is the caller's patience.
        let mut items = a_link(ROOT_DIR, 259, 2, b"a", b"b");
        items.extend(a_link(ROOT_DIR, 260, 3, b"b", b"a"));
        let forge = a_filesystem_holding(items);
        let mut reader = open(&forge);

        assert!(matches!(
            reader.lookup(b"/a"),
            Err(ReadError::SymlinkLoop { .. })
        ));
        // Not following the last component reaches the link itself, which is not a loop: the
        // budget is spent by expanding links, and this expands none.
        let stopped = reader.lookup_no_follow(b"/a").expect("the link itself");
        assert!(stopped.is_symlink());
    }

    #[test]
    fn a_lookup_follows_a_link_and_a_no_follow_lookup_stops_at_it() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        // The same path, resolved the two ways, reaches two different inodes — which is the
        // whole of the difference between the pair and the reason both exist. A caller
        // extracting a tree wants the link; a caller reading a file wants what it points at.
        let followed = reader.lookup(b"/link").expect("resolving through the link");
        let stopped = reader.lookup_no_follow(b"/link").expect("stopping at it");
        let target = reader.lookup(b"/hello.txt").expect("the file it names");
        assert_eq!((followed.tree, followed.inode), (target.tree, target.inode));
        assert!(stopped.is_symlink());
        assert_ne!(stopped.inode, followed.inode);
    }

    #[test]
    fn a_nodes_extended_attributes_come_back_in_the_boundary_form() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let node = reader.lookup(b"/hello.txt").expect("the file");
        assert_eq!(
            reader.xattrs(&node).expect("its attributes"),
            vec![Xattr {
                name: b"user.note".to_vec(),
                value: b"a value".to_vec(),
            }]
        );
        // A node with none has none, rather than the previous node's.
        let root = reader.root().expect("the root");
        assert!(reader.xattrs(&root).expect("no attributes").is_empty());
    }

    #[test]
    fn a_walk_yields_the_root_first_and_then_every_name_below_it() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let paths: Vec<Vec<u8>> = reader
            .walk()
            .expect("a walk")
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                Vec::new(),
                b"/hello.txt".to_vec(),
                b"/big".to_vec(),
                b"/link".to_vec(),
                b"/sub".to_vec(),
                b"/sub/inner".to_vec(),
            ],
            "a parent comes before its children, in the order its directory stores them"
        );
    }

    #[test]
    fn a_subvolume_is_crossed_into_as_though_it_were_a_directory() {
        // The seam that makes this family different from the other three: an entry names a
        // tree rather than an inode, and a path across it is one path.
        let forge = a_filesystem_with_a_subvolume();
        let mut reader = open(&forge);
        assert_eq!(reader.subvolumes().len(), 2);
        let nested = &reader.subvolumes()[1];
        assert_eq!(nested.id, SUB_ID);
        assert_eq!(nested.name, b"nested");
        assert_eq!(nested.parent, Some(objectid::FS_TREE));
        assert_eq!(nested.parent_dir, ROOT_DIR);

        let node = reader.lookup(b"/nested/within").expect("the nested file");
        assert_eq!(node.tree, SUB_ID, "the node is in the subvolume's own tree");
        assert_eq!(reader.read_data(&node).expect("its bytes"), b"inside");

        let paths: Vec<Vec<u8>> = reader
            .walk()
            .expect("a walk")
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                Vec::new(),
                b"/above".to_vec(),
                b"/nested".to_vec(),
                b"/nested/within".to_vec(),
            ]
        );
    }

    #[test]
    fn a_parent_component_ascends_back_out_of_the_subvolume_it_descended_into() {
        // The ascent holds the directories a resolution went through, not the inode numbers
        // they have — and this family is why. Inode 257 exists in every subvolume, so a
        // number popped off a stack would name a file in whichever tree happened to be
        // current. What comes back must be the directory that was left, tree and all.
        let forge = a_filesystem_with_a_subvolume();
        let mut reader = open(&forge);
        let above = reader.lookup(b"/above").expect("the file above the seam");
        let within = reader.lookup(b"/nested/within").expect("the nested file");
        assert_eq!(within.tree, SUB_ID);

        // Down into the subvolume and back out of it, which is a path that changes tree
        // twice.
        let ascended = reader
            .lookup(b"/nested/../above")
            .expect("out of the subvolume and back down");
        assert_eq!((ascended.tree, ascended.inode), (above.tree, above.inode));
        assert_eq!(ascended.tree, objectid::FS_TREE);

        // And back down into it again, so the ascent left the resolution where it started
        // rather than one step to the side.
        let returned = reader
            .lookup(b"/nested/../nested/within")
            .expect("back into the subvolume");
        assert_eq!((returned.tree, returned.inode), (within.tree, within.inode));

        // The subvolume's own root ascends to the directory it is mounted in, which is in
        // the tree above it.
        let seam = reader
            .lookup(b"/nested/..")
            .expect("the mount point's parent");
        assert_eq!(seam.tree, objectid::FS_TREE);
        assert_eq!(seam.inode, ROOT_DIR);
        // At the root there is nothing to ascend to, so nothing outside the filesystem can
        // be named however many of them a caller writes.
        let root = reader.root().expect("the root");
        for path in [&b"/.."[..], b"/../..", b"/nested/../../.."] {
            let stayed = reader
                .lookup(path)
                .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(path)));
            assert_eq!((stayed.tree, stayed.inode), (root.tree, root.inode));
        }
    }

    #[test]
    fn an_inode_number_is_only_an_identity_within_its_own_subvolume() {
        // Two subvolumes each hold an inode 257 and they are different files. A reader that
        // keyed a node by its number alone would hand back one of them for the other, and
        // both are perfectly ordinary filesystems.
        let forge = a_filesystem_with_a_subvolume();
        let mut reader = open(&forge);
        let above = reader.lookup(b"/above").expect("the top-level file");
        let within = reader.lookup(b"/nested/within").expect("the nested file");
        assert_eq!(above.inode, within.inode);
        assert_ne!(above.tree, within.tree);
        assert_eq!(reader.read_data(&above).expect("bytes"), b"up\n");
        assert_eq!(reader.read_data(&within).expect("bytes"), b"inside");
    }

    #[test]
    fn a_run_of_a_file_that_was_never_written_reads_back_as_zeros() {
        // Both spellings of a gap. With `no-holes` there is no record at all and the reader
        // has to notice the absence; without it there is a record whose extent address is
        // zero. Neither may read back as whatever was on the volume.
        let mut items = vec![
            (
                DiskKey::new(257, ItemType::INODE_ITEM, 0),
                inode_item(MODE_REG | 0o644, 12288, 1),
            ),
            // Nothing at all for the first 4 KiB, a written extent, then a recorded hole.
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 4096),
                addressed_extent(ExtentKind::Regular, DATA_AT, 4096, 0, 4096),
            ),
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 8192),
                addressed_extent(ExtentKind::Regular, 0, 0, 0, 4096),
            ),
        ];
        items.extend(entry(
            ROOT_DIR,
            2,
            b"sparse",
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        let forge = a_filesystem_holding(items);

        let mut reader = open(&forge);
        let node = reader.lookup(b"/sparse").expect("the file");
        let bytes = reader.read_data(&node).expect("its bytes");
        assert_eq!(bytes.len(), 12288);
        assert!(bytes[..4096].iter().all(|&b| b == 0), "the unrecorded gap");
        assert!(
            bytes[4096..8192].iter().all(|&b| b == DATA_BYTE),
            "the extent"
        );
        assert!(bytes[8192..].iter().all(|&b| b == 0), "the recorded hole");
        // And a read that begins inside the written run finds the record covering it rather
        // than the one keyed at or after the position.
        let mut buf = [0u8; 8];
        reader
            .read_into(&node, 5000, &mut buf)
            .expect("a read from the middle of an extent");
        assert!(buf.iter().all(|&b| b == DATA_BYTE));
    }

    #[test]
    fn a_preallocated_extent_reads_back_as_zeros_rather_than_as_what_is_on_the_volume() {
        // An extent that has been allocated and not written holds whatever the volume held
        // before it. Handing that back would be handing back another file's deleted bytes.
        let forge = a_filesystem_holding(a_file(
            b"reserved",
            MODE_REG | 0o644,
            4096,
            addressed_extent(ExtentKind::Prealloc, DATA_AT, 4096, 0, 4096),
        ));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/reserved").expect("the file");
        assert!(
            reader
                .read_data(&node)
                .expect("its bytes")
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn an_extent_whose_run_leaves_the_extent_it_names_is_refused() {
        // The bound that matters most in this module: the record's own numbers decide which
        // bytes of the volume are handed back under this file's name, so a run reaching past
        // the extent would return whatever follows it — another file's contents, or metadata.
        let forge = a_filesystem_holding(a_file(
            b"overreaching",
            MODE_REG | 0o644,
            4096,
            // The extent is 512 bytes long and the record claims 4096 of it.
            addressed_extent(ExtentKind::Regular, DATA_AT, 512, 0, 4096),
        ));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/overreaching").expect("the file");
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadExtent { .. })
        ));
    }

    #[test]
    fn an_extent_encoded_in_a_way_the_format_has_not_defined_is_refused_by_its_byte() {
        // A filesystem that may be entirely well-formed and is beyond every build of this
        // crate, because the byte names nothing any release of the format defines. What the
        // refusal must not be is a read of the encoded bytes as though they were the file's.
        let record = compressed_extent(Compression::Unknown(9), b"encoded somehow", 4096);
        let forge = a_filesystem_holding(a_file(b"squeezed", MODE_REG | 0o644, 4096, record));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/squeezed").expect("the file");
        let err = reader.read_data(&node).expect_err("an encoded extent");
        assert!(matches!(
            err,
            ReadError::UnsupportedCompression { compression: 9, .. }
        ));
        assert!(
            format!("{err}").contains("an algorithm the format has not defined"),
            "{err}"
        );
    }

    /// One payload and the zlib stream it compresses to.
    ///
    /// Recorded rather than produced: this crate writes no compressed extent, so the fixture
    /// has to come from something that does — here `python3 -c "import zlib;
    /// zlib.compress(b'ferrosys' * 8, 9)"`. The payload repeats, which is what makes the
    /// stream shorter than what it stands for and therefore a compressed extent at all.
    #[cfg(feature = "zlib")]
    const ZLIB_STREAM: &[u8] = &[
        0x78, 0xda, 0x4b, 0x4b, 0x2d, 0x2a, 0xca, 0x2f, 0xae, 0x2c, 0x4e, 0x23, 0x93, 0x06, 0x00,
        0x88, 0x65, 0x1b, 0xe9,
    ];

    #[cfg(feature = "zlib")]
    fn zlib_payload() -> Vec<u8> {
        b"ferrosys".repeat(8)
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn a_compressed_extent_reads_back_as_the_bytes_it_stands_for() {
        // Both shapes a compressed extent takes, because the two reach the stream by
        // different routes: an inline record carries it inside the item, and an addressed one
        // names a run of logical space holding it.
        let want = zlib_payload();

        let record = compressed_extent(Compression::Zlib, ZLIB_STREAM, want.len() as u64);
        let forge = a_filesystem_holding(a_file(
            b"inline",
            MODE_REG | 0o644,
            want.len() as u64,
            record,
        ));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/inline").expect("the file");
        assert_eq!(reader.read_data(&node).expect("it decodes"), want);

        let mut record = addressed_extent(
            ExtentKind::Regular,
            DATA_AT,
            ZLIB_STREAM.len() as u64,
            0,
            64,
        );
        record[16] = Compression::Zlib.to_u8();
        // `ram_bytes` is what the *extent* expands to, which for a record covering all of it
        // is also what the record covers.
        record[8..16].copy_from_slice(&(want.len() as u64).to_le_bytes());
        let mut forge = a_filesystem_holding(a_file(
            b"addressed",
            MODE_REG | 0o644,
            want.len() as u64,
            record,
        ));
        forge.data(DATA_AT, ZLIB_STREAM);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/addressed").expect("the file");
        assert_eq!(reader.read_data(&node).expect("it decodes"), want);

        // And a read from the middle of it, which is the case the expansion exists for: the
        // stream says nothing about where a position in the file lands, so the whole extent
        // is undone and the window taken from what it became.
        let mut middle = [0u8; 8];
        assert_eq!(
            reader
                .read_into(&node, 20, &mut middle)
                .expect("it decodes"),
            8
        );
        assert_eq!(&middle, &want[20..28]);
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn a_compressed_extent_that_does_not_decode_is_a_fault_in_the_filesystem() {
        // Apart from an algorithm this build has no decoder for, which is a filesystem that
        // is sound and beyond it. Here the build *does* decode the algorithm and the bytes
        // are not a stream of it, which is damage and says so.
        let record = compressed_extent(Compression::Zlib, b"not a stream", 64);
        let forge = a_filesystem_holding(a_file(b"damaged", MODE_REG | 0o644, 64, record));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/damaged").expect("the file");
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::BadCompressedExtent { .. })
        ));
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn a_record_expanding_to_more_than_the_format_compresses_in_is_refused_before_it_costs_it() {
        // The bound that keeps a crafted record from being an allocation. The expanded length
        // is a number the image supplied and it is the size of a buffer, so a record naming a
        // gibibyte must cost a refusal rather than a gibibyte.
        let mut record = compressed_extent(Compression::Zlib, ZLIB_STREAM, 64);
        record[8..16].copy_from_slice(&(1u64 << 30).to_le_bytes());
        let forge = a_filesystem_holding(a_file(b"greedy", MODE_REG | 0o644, 1 << 30, record));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/greedy").expect("the file");
        let mut out = [0u8; 64];
        assert!(matches!(
            reader.read_into(&node, 0, &mut out),
            Err(ReadError::BadExtent { .. })
        ));
    }

    #[test]
    fn a_directory_reachable_from_itself_is_descended_into_once_rather_than_forever() {
        // No formatter writes this and a crafted image is exactly where it appears. Nothing
        // about a bound on one entry sees it: every record is well-formed, and a walk that
        // followed the entries would not terminate.
        let mut items = vec![(
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            inode_item(MODE_DIR | 0o755, 0, 1),
        )];
        items.extend(entry(
            ROOT_DIR,
            2,
            b"down",
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::Dir,
        ));
        items.extend(entry(
            257,
            2,
            b"up",
            DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
            DirEntryType::Dir,
        ));
        let forge = a_filesystem_holding(items);
        let mut reader = open(&forge);
        let paths: Vec<Vec<u8>> = reader
            .walk()
            .expect("a walk terminates")
            .into_iter()
            .map(|walked| walked.path)
            .collect();
        // The second name for the root is yielded, because it is a name the filesystem holds.
        // What does not happen is descending into it, which is what would not terminate.
        assert_eq!(
            paths,
            vec![Vec::new(), b"/down".to_vec(), b"/down/up".to_vec()]
        );
    }

    #[test]
    fn a_name_no_directory_can_hold_stops_a_walk_rather_than_becoming_a_path() {
        // A name carrying a separator would traverse out of its own directory in every path
        // built from it, which is what an extraction would then write.
        let forge = a_filesystem_holding(a_file(
            b"../escape",
            MODE_REG | 0o644,
            0,
            inline_extent(b""),
        ));
        let mut reader = open(&forge);
        assert!(matches!(reader.walk(), Err(ReadError::HostileName { .. })));
        // And it is unreachable as a path, which is the other half of the same claim: written
        // out, the name is an ascent and then a component, so what a resolution looks for is
        // an entry called `escape` in the root — a name this filesystem does not hold. The
        // entry it does hold cannot be named at all, which is what refusing it where it is
        // read is for.
        assert!(matches!(
            reader.lookup(b"/../escape"),
            Err(ReadError::NotFound { .. })
        ));
    }

    /// A filesystem holding one addressed file and a checksum tree covering `covering` — which
    /// is the bytes the extent is *said* to hold, and need not be the bytes on the volume.
    fn a_filesystem_with_checksums(on_the_volume: &[u8], covering: &[u8]) -> Forge {
        let items = a_file(
            b"data",
            MODE_REG | 0o644,
            4096,
            addressed_extent(ExtentKind::Regular, DATA_AT, 4096, 0, 4096),
        );
        let mut forge = Forge::new();
        let mut all = vec![(
            DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
            inode_item(MODE_DIR | 0o755, 0, 1),
        )];
        all.extend(items);
        forge.block(FS_TREE_AT, &fs_tree(FS_TREE_AT, objectid::FS_TREE, all));
        forge.data(DATA_AT, on_the_volume);
        forge.block(
            SUB_TREE_AT,
            &fs_tree(
                SUB_TREE_AT,
                objectid::CSUM_TREE,
                vec![(
                    DiskKey::new(objectid::EXTENT_CSUM, ItemType::EXTENT_CSUM, DATA_AT),
                    csum_item(covering, NODE_SIZE),
                )],
            ),
        );
        // In key order, which the format requires of every tree and a walk checks: the
        // filesystem tree is 5 and the checksum tree is 7.
        forge.root_leaf(&[
            (
                DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0),
                root_item(FS_TREE_AT, 0, ROOT_DIR),
            ),
            (
                DiskKey::new(objectid::CSUM_TREE, ItemType::ROOT_ITEM, 0),
                root_item(SUB_TREE_AT, 0, 0),
            ),
        ]);
        forge
    }

    #[test]
    fn a_files_bytes_are_held_against_the_checksums_the_filesystem_recorded_for_them() {
        // The check no other family here can make: every tree is well-formed, every metadata
        // block verifies, and the bytes of the file are still not the bytes that were written.
        let bytes = [DATA_BYTE; 4096];
        let forge = a_filesystem_with_checksums(&bytes, &bytes);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/data").expect("the file");
        reader.verify_data(&node).expect("the bytes are the bytes");

        // One byte of the volume changed, with nothing else touched — which is exactly the
        // damage a medium does and the one an ordinary read hands straight back.
        let mut decayed = bytes;
        decayed[100] ^= 0xff;
        let forge = a_filesystem_with_checksums(&decayed, &bytes);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/data").expect("the file");
        assert_eq!(
            reader.read_data(&node).expect("a read still succeeds")[100],
            DATA_BYTE ^ 0xff,
            "an ordinary read hands back what is there"
        );
        assert!(matches!(
            reader.verify_data(&node),
            Err(ReadError::DataChecksum { logical }) if logical == DATA_AT
        ));
    }

    #[test]
    fn a_file_with_no_checksum_recorded_for_it_is_reported_rather_than_passed() {
        // A run with no record is not a run that verified. Treating a missing checksum as a
        // pass would make the whole check vacuous on an image whose checksum tree was lost.
        let forge = a_filesystem_with_checksums(&[DATA_BYTE; 4096], &[]);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/data").expect("the file");
        assert!(matches!(
            reader.verify_data(&node),
            Err(ReadError::MissingDataChecksum { .. })
        ));
    }

    #[test]
    fn a_file_the_filesystem_does_not_checksum_is_not_held_to_one() {
        // `NODATASUM` says there is nothing recorded, so asking for a checksum would report a
        // healthy file as one whose checksums are missing.
        let mut record = inode_item(MODE_REG | 0o644, 4096, 1);
        // The flags word sits at offset 64 of an inode item.
        record[64] = InodeFlags::NODATASUM.bits() as u8;
        let mut items = vec![
            (DiskKey::new(257, ItemType::INODE_ITEM, 0), record),
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 0),
                addressed_extent(ExtentKind::Regular, DATA_AT, 4096, 0, 4096),
            ),
        ];
        items.extend(entry(
            ROOT_DIR,
            2,
            b"raw",
            DiskKey::new(257, ItemType::INODE_ITEM, 0),
            DirEntryType::RegFile,
        ));
        let forge = a_filesystem_holding(items);
        let mut reader = open(&forge);
        let node = reader.lookup(b"/raw").expect("the file");
        assert!(node.item.flags.contains(InodeFlags::NODATASUM));
        reader
            .verify_data(&node)
            .expect("nothing is recorded, so nothing is held against");
        // And a hole or a preallocated extent has nothing to check either, on a filesystem
        // that does checksum — so a file of them verifies without a checksum tree being
        // consulted at all.
        let forge = a_filesystem_holding(a_file(
            b"reserved",
            MODE_REG | 0o644,
            4096,
            addressed_extent(ExtentKind::Prealloc, DATA_AT, 4096, 0, 4096),
        ));
        let mut reader = open(&forge);
        let node = reader.lookup(b"/reserved").expect("the file");
        reader.verify_data(&node).expect("nothing has been written");
    }

    #[test]
    fn a_filesystem_nothing_is_wrong_with_scans_clean() {
        let forge = Forge::populated();
        let mut reader = open(&forge);
        let report = reader.scan();
        assert!(report.is_clean(), "{:?}", report.anomalies());
        assert!(!report.is_truncated());
    }

    #[test]
    fn a_filesystem_that_was_not_cleanly_unmounted_says_what_is_missing() {
        // The instance where "cosmetic" is arguable: the image is
        // conformant and every byte read is trustworthy, and the filesystem genuinely holds
        // writes the committed trees do not. So the message says what is missing rather than
        // which field held an unexpected value.
        let mut forge = Forge::populated();
        forge.amend_superblock(0, |sb| sb.log_root = FS_TREE_AT);
        let mut reader = open(&forge);
        let report = reader.scan();
        let logged: Vec<&Anomaly> = report
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::Superblock)
            .collect();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].severity, Severity::Cosmetic);
        assert!(logged[0].detail.contains("last committed transaction"));
        assert!(logged[0].detail.contains("not cleanly unmounted"));
        // A scan reports rather than refuses, so the filesystem still reads.
        let node = reader.lookup(b"/hello.txt").expect("the file");
        assert_eq!(reader.read_data(&node).expect("its bytes"), b"hello\n");
    }

    #[test]
    fn a_scan_reports_a_block_that_does_not_verify_rather_than_stopping_at_it() {
        // The difference between a scan and a read: a read stops where it cannot go on, and a
        // scan is what a caller asking "is anything wrong with this image" runs.
        let mut forge = Forge::populated();
        forge.break_checksum(FS_TREE_AT);
        let mut reader = Reader::open_with(
            forge.source(),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("the superblock and the root tree are intact");
        let report = reader.scan();
        assert!(!report.is_clean());
        let damaged: Vec<&Anomaly> = report
            .anomalies()
            .iter()
            .filter(|a| a.severity == Severity::Integrity)
            .collect();
        assert_eq!(damaged.len(), 1, "{:?}", report.anomalies());
        assert_eq!(damaged[0].category, Category::Tree);
        assert_eq!(damaged[0].tree, Some(objectid::FS_TREE));
        // And a read of the same filesystem fails at that block, which is the other half of
        // the contract: what a scan reports, a read refuses.
        assert!(matches!(
            reader.lookup(b"/hello.txt"),
            Err(ReadError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_scan_reports_a_uuid_tree_that_disagrees_with_the_root_items() {
        // A subvolume's root item records its identifier and the UUID tree maps the identifier
        // back to the subvolume, and the pair can disagree while every block of both trees
        // verifies: no checksum covers the agreement, and a walk of either tree alone meets
        // nothing wrong. A lookup by identifier then misses, and the format's own tooling
        // rewrites the tree on the next writable mount — so the scan is where the disagreement
        // has to surface.
        const UUID_TREE_AT: u64 = FS_TREE_AT + 3 * NODE_SIZE as u64;
        let held = [0x44u8; 16];
        let mut item = root_item(FS_TREE_AT, 0, ROOT_DIR);
        let mut with_uuid = RootItem::read_from(&item).expect("the forge's root item reads back");
        with_uuid.uuid = held;
        with_uuid.write_to(&mut item);

        let mut forge = Forge::new();
        forge.block(
            FS_TREE_AT,
            &fs_tree(
                FS_TREE_AT,
                objectid::FS_TREE,
                vec![(
                    DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
                    inode_item(MODE_DIR | 0o755, 0, 1),
                )],
            ),
        );
        // The tree's one entry maps the null identifier to the subvolume, while the root item
        // records 0x44…44 — the two halves of one fact, filled from different sources.
        forge.block(
            UUID_TREE_AT,
            &leaf(
                UUID_TREE_AT,
                objectid::UUID_TREE,
                &[(
                    DiskKey::new(0, ItemType::UUID_SUBVOL, 0),
                    objectid::FS_TREE.to_le_bytes().to_vec(),
                )],
            ),
        );
        forge.root_leaf(&[
            (
                DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0),
                item,
            ),
            (
                DiskKey::new(objectid::UUID_TREE, ItemType::ROOT_ITEM, 0),
                root_item(UUID_TREE_AT, 0, 0),
            ),
        ]);

        let mut reader = open(&forge);
        let report = reader.scan();
        let details: Vec<&str> = report
            .anomalies()
            .iter()
            .filter(|a| a.tree == Some(objectid::UUID_TREE))
            .map(|a| a.detail.as_str())
            .collect();
        assert_eq!(details.len(), 2, "{:?}", report.anomalies());
        assert!(
            details[0].contains("records a different identifier"),
            "{details:?}"
        );
        assert!(
            details[1].contains("no entry mapping it back"),
            "{details:?}"
        );
        // Both directions hold severity below refusal: the filesystem still reads.
        reader.root().expect("the root directory");
    }

    #[test]
    fn a_filesystem_with_no_top_level_tree_is_refused_at_open() {
        // The root tree names every tree there is, so one with no record of the filesystem
        // tree is an image with nowhere for a path to start.
        let mut forge = Forge::new();
        forge.root_leaf(&[]);
        assert!(matches!(
            Reader::open(forge.source()),
            Err(ReadError::MissingTree { objectid: 5 })
        ));
    }

    #[test]
    fn a_whole_file_read_is_held_to_the_cap_the_caller_set() {
        // A file's declared length is a number the image supplies and a hole reads back as
        // zeros, so a whole-file read of an inode claiming more than the image holds costs
        // exactly what the inode claims.
        let forge = Forge::populated();
        let mut reader = Reader::open_with(
            forge.source(),
            &OpenOptions::new().limits(Limits::new().max_file_bytes(4)),
        )
        .expect("a forged filesystem");
        let node = reader.lookup(b"/hello.txt").expect("the file");
        assert!(matches!(
            reader.read_data(&node),
            Err(ReadError::FileTooLarge {
                size: 6,
                cap: 4,
                ..
            })
        ));
        // Streaming is not held to it, because what it costs is the buffer rather than the
        // file — and that is the escape hatch the cap leaves.
        let mut out = Vec::new();
        assert_eq!(reader.read_data_to(&node, &mut out).expect("streaming"), 6);
    }
}
