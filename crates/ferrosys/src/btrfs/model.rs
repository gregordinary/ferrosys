//! The pure model built from a [`Source`](crate::Source) before any byte is written: which
//! subvolume every object belongs to, what number it is, what names it has, and how its bytes
//! divide.
//!
//! Everything a populated format can fail on happens here, so a caller finds out whether a
//! build will work before the destination is touched. The materializer that consumes a model
//! turns it into records and writes them; it makes no further decisions about the tree.
//!
//! # What btrfs records, and why nothing is lost here
//!
//! An inode carries an owner, a group, a full mode, a link count, a device number, and four
//! timestamps each to the nanosecond; a name is up to [`MAX_NAME_LEN`] bytes and an object may
//! have as many as a caller states; an extended attribute is a record of its own. That is every
//! property a [`SourceEntry`] carries, so a tree goes in whole — this is the one family here
//! where the fidelity report is empty in both directions rather than merely small, and
//! [`BtrfsModel::fidelity`] says so rather than leaving it to be assumed.
//!
//! The one thing a source states that the format holds *differently* is a second name for a
//! file: btrfs keeps hard links, and keeps them within one tree. A link whose two names fall on
//! opposite sides of a subvolume boundary is refused rather than copied, because no btrfs holds
//! one — see [`ModelError::HardlinkCrossesSubvolume`].
//!
//! # Reproducibility
//!
//! Entries are sorted by path before anything is numbered, so an object's inode number, the
//! sequence its name sits at in its directory, and the order two names of one file appear in are
//! all functions of the tree rather than of the order a source happened to yield it in. Two
//! models of one tree are the same model.

use std::collections::{BTreeMap, HashMap};

use crate::fidelity::FidelityReport;
use crate::path::canonical_key;
use crate::source::{
    ClassifyError, EntryKind, FileContent, MODE_TYPE_MASK, Metadata, PathFault, SourceEntry,
    classify_paths,
};
use crate::time::Timestamp;
use crate::xattr::Xattr;

use super::geometry::Content;
use super::ondisk::{DirEntryType, DirItem, FileExtentItem, Header, Item, objectid};

/// The longest name the format holds, in bytes.
///
/// One value for every kind of name: a directory entry, a hard link, and a subvolume are all
/// named through the same record.
pub const MAX_NAME_LEN: usize = 255;

/// The most bytes of a file one data extent holds.
///
/// A mebibyte, which is what the format's own tooling splits a file into. Nothing on disk
/// requires it — an extent's length is a 64-bit field — and a bound is worth having anyway: it
/// is what keeps the largest read a format performs a function of this constant rather than of
/// the largest file a caller names.
pub const MAX_EXTENT_BYTES: u64 = 1 << 20;

/// The sequence the first entry of a directory sits at.
///
/// Two rather than zero: the name a directory has for its parent is at zero, and one is left
/// where the format's own tooling leaves it.
pub(crate) const FIRST_DIR_INDEX: u64 = 2;

/// A subvolume a caller asks the filesystem to carry, beyond the one every btrfs has.
///
/// A subvolume root is still a directory — the source declares it as one, and this names which
/// of those declared directories becomes the root of a tree of its own. That is why it is a
/// keyed-by-path option rather than a kind of entry: subvolume-ness is a layout instruction, and
/// a directory that is one looks like a directory to everything that reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SubvolumeRequest {
    /// The path of the directory that becomes the subvolume's root.
    pub path: Vec<u8>,
    /// The subvolume's own id, which the root item and the UUID tree record.
    ///
    /// A value a caller states rather than one this crate invents, for the reason every other
    /// identifier here is: a filesystem whose bytes depend on a random source is not
    /// reproducible. Each subvolume's must be its own — the UUID tree is keyed by it — and
    /// all zeros records that none was set: the root item carries the zeros and the UUID tree
    /// carries no entry, which is the state the format's own tooling leaves an identifier it
    /// never wrote.
    pub uuid: [u8; 16],
    /// Whether a driver refuses to write into it.
    pub read_only: bool,
}

impl SubvolumeRequest {
    /// A writable subvolume at `path`, identified by `uuid`.
    #[must_use]
    pub fn new(path: impl Into<Vec<u8>>, uuid: [u8; 16]) -> Self {
        Self {
            path: path.into(),
            uuid,
            read_only: false,
        }
    }

    /// This request with the read-only flag set.
    #[must_use]
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
}

/// Something a source states that this filesystem cannot hold.
///
/// A path in a message is rendered rather than repeated: a source path is a byte string that
/// need not be text and may hold anything a terminal acts on. Naming the offending path
/// imperfectly is worth far more than refusing to name it, so an unrepresentable byte becomes
/// U+FFFD and anything a terminal would act on becomes a visible escape.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A path component was `..`, which a source may not use — a path is where an entry goes,
    /// not a traversal to be resolved.
    #[error("path {} has a `..` component", crate::escape::printable(.path))]
    #[non_exhaustive]
    InvalidComponent {
        /// The offending path.
        path: Vec<u8>,
    },
    /// Two entries resolve to the same path. Rejected rather than resolved by keeping the last,
    /// so the filesystem an ambiguous source would produce is never guessed at.
    #[error("path {} is used by more than one entry", crate::escape::printable(.path))]
    #[non_exhaustive]
    Duplicate {
        /// The duplicated path.
        path: Vec<u8>,
    },
    /// A name is longer than the format's field for one.
    #[error(
        "{}: a name of {bytes} bytes is longer than the {MAX_NAME_LEN} this format holds",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    NameTooLong {
        /// The offending path.
        path: Vec<u8>,
        /// How long the name is, in bytes.
        bytes: usize,
    },
    /// An entry's parent directory was not declared.
    #[error("path {} has no parent directory", crate::escape::printable(.path))]
    #[non_exhaustive]
    ParentMissing {
        /// The path whose parent is absent.
        path: Vec<u8>,
    },
    /// An entry's parent path exists but is not a directory.
    #[error("path {} has a parent that is not a directory", crate::escape::printable(.path))]
    #[non_exhaustive]
    ParentNotDir {
        /// The path whose parent is not a directory.
        path: Vec<u8>,
    },
    /// An entry naming the root is not a directory. The root is a directory, so an entry that
    /// would place anything else there is rejected rather than ignored.
    #[error("entry {} names the root but is not a directory", crate::escape::printable(.path))]
    #[non_exhaustive]
    RootNotDirectory {
        /// The offending path.
        path: Vec<u8>,
    },
    /// An entry's `mode` carries file-type bits, which the entry's kind supplies.
    ///
    /// [`Metadata::mode`](crate::Metadata::mode) holds the permission and
    /// set-user/group/sticky bits alone. A raw `st_mode` passed through whole would put a
    /// second file type on the inode — one the directory entry contradicts — and the write
    /// would succeed while every checker and driver reads the result as corrupt.
    #[error(
        "{}: mode {mode:#o} carries file-type bits, which the entry's kind supplies",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    ModeCarriesFileType {
        /// The offending path.
        path: Vec<u8>,
        /// The mode as given.
        mode: u16,
    },
    /// A hard link's target does not exist.
    #[error(
        "hard link {} targets {}, which does not exist",
        crate::escape::printable(.path),
        crate::escape::printable(.target)
    )]
    #[non_exhaustive]
    HardlinkTargetMissing {
        /// The link's path.
        path: Vec<u8>,
        /// The target it names.
        target: Vec<u8>,
    },
    /// A hard link states extended attributes other than its target's, which no filesystem
    /// holds: a link is a name for an object, and attributes belong to the object. A member
    /// that repeats the target's attributes exactly states nothing new and is accepted —
    /// some archive producers write hard-link members that way — and anything else is
    /// refused rather than half-applied. State changes on the target instead.
    #[error(
        "hard link {} states extended attributes other than its target's, and attributes \
         belong to the target",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    LinkCarriesXattrs {
        /// The link's path.
        path: Vec<u8>,
    },
    /// A hard link targets a directory, which no filesystem permits.
    #[error(
        "hard link {} targets the directory {}",
        crate::escape::printable(.path),
        crate::escape::printable(.target)
    )]
    #[non_exhaustive]
    HardlinkTargetIsDirectory {
        /// The link's path.
        path: Vec<u8>,
        /// The target it names.
        target: Vec<u8>,
    },
    /// A chain of hard links closes on itself, so no end of it names a file.
    #[error(
        "hard link {} names a chain of links that returns to itself",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    HardlinkCycle {
        /// The link the walk started from.
        path: Vec<u8>,
    },
    /// A hard link and what it names are in two different subvolumes.
    ///
    /// A hard link is a second name in one tree for one inode, and a subvolume *is* a tree — so
    /// no btrfs holds a link across the boundary and none ever will. The format's own tooling
    /// writes a second copy of the file instead, silently; this refuses, because two files where
    /// a caller asked for one is a filesystem other than the one they described.
    #[error(
        "hard link {} and its target {} are in different subvolumes, and no hard link spans two",
        crate::escape::printable(.path),
        crate::escape::printable(.target)
    )]
    #[non_exhaustive]
    HardlinkCrossesSubvolume {
        /// The link's path.
        path: Vec<u8>,
        /// The target it names.
        target: Vec<u8>,
    },
    /// A subvolume was asked for at a path the source does not declare as a directory.
    #[error(
        "the subvolume {} names no directory this source declares",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    SubvolumeNotADirectory {
        /// The path the subvolume was asked for at.
        path: Vec<u8>,
    },
    /// A subvolume was asked for at the root, which is the subvolume every btrfs already has.
    #[error("the root is already a subvolume and cannot be asked for as another")]
    SubvolumeAtRoot,
    /// Two subvolumes were asked for at one path.
    #[error(
        "a subvolume is asked for twice at {}",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    SubvolumeDuplicate {
        /// The repeated path.
        path: Vec<u8>,
    },
    /// Two subvolumes share one identifier, which would key the UUID tree's entry for each of
    /// them alike — one record standing for two subvolumes, which no driver expects and no
    /// checker accepts. An all-zero identifier records that none was set and does not collide.
    #[error(
        "subvolumes {} and {} share the identifier {}",
        crate::escape::printable(.first),
        crate::escape::printable(.second),
        crate::escape::hex(.uuid)
    )]
    #[non_exhaustive]
    SubvolumeUuidRepeated {
        /// The path that held the identifier first; `/` where that is the top-level subvolume.
        first: Vec<u8>,
        /// The path that repeated it.
        second: Vec<u8>,
        /// The identifier both carry.
        uuid: [u8; 16],
    },
    /// The default subvolume names a path that is not a subvolume.
    #[error(
        "the default subvolume {} is not the root and is not a subvolume that was asked for",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    DefaultSubvolumeUnknown {
        /// The path that was named.
        path: Vec<u8>,
    },
    /// A record is larger than a whole tree block, so no leaf can hold it.
    ///
    /// Reached by three things a caller controls: an extended attribute whose name and value
    /// together outgrow a leaf, a symbolic link whose target does, and a file small enough to be
    /// stored inside the metadata on a filesystem whose tree blocks are smaller than its
    /// sectors' worth of data. The message names which.
    #[error(
        "{}: the {what} needs {bytes} bytes and a leaf of this filesystem holds {capacity}",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    RecordTooLarge {
        /// The entry that could not be placed.
        path: Vec<u8>,
        /// What about it did not fit.
        what: &'static str,
        /// Bytes the record needs.
        bytes: usize,
        /// Bytes one leaf of this filesystem holds.
        capacity: usize,
    },
}

/// What one object of a filesystem is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum ObjectKind {
    /// A directory, and the entries in it.
    Directory(Vec<DirEntry>),
    /// A regular file: which of the model's contents holds its bytes, how long it is, and
    /// whether those bytes go inside the metadata.
    File {
        /// Index into [`BtrfsModel::contents`].
        content: usize,
        /// The file's length in bytes.
        size: u64,
        /// Whether the bytes are stored in the record rather than in a data extent.
        inline: bool,
    },
    /// A symbolic link, and where it points. The target is always stored in the record.
    Symlink(Vec<u8>),
    /// A device node: whether it is block-special, and its number.
    Device {
        /// Whether the node is block-special rather than character-special.
        block: bool,
        /// The device's major number.
        major: u32,
        /// The device's minor number.
        minor: u32,
    },
    /// A named pipe.
    Fifo,
    /// A Unix-domain socket node.
    Socket,
}

impl ObjectKind {
    /// The bits of a mode that say what this is.
    pub(crate) const fn mode_bits(&self) -> u32 {
        match self {
            Self::Directory(_) => 0o040_000,
            Self::File { .. } => 0o100_000,
            Self::Symlink(_) => 0o120_000,
            Self::Device { block: true, .. } => 0o060_000,
            Self::Device { block: false, .. } => 0o020_000,
            Self::Fifo => 0o010_000,
            Self::Socket => 0o140_000,
        }
    }

    /// What a directory entry naming this says it names.
    pub(crate) const fn entry_type(&self) -> DirEntryType {
        match self {
            Self::Directory(_) => DirEntryType::Dir,
            Self::File { .. } => DirEntryType::RegFile,
            Self::Symlink(_) => DirEntryType::Symlink,
            Self::Device { block: true, .. } => DirEntryType::BlockDev,
            Self::Device { block: false, .. } => DirEntryType::CharDev,
            Self::Fifo => DirEntryType::Fifo,
            Self::Socket => DirEntryType::Socket,
        }
    }
}

/// One name a directory holds, and what it names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct DirEntry {
    /// The name itself.
    pub name: Vec<u8>,
    /// Where in the directory's sequence it sits, which is what reading in order follows.
    pub index: u64,
    /// What it names.
    pub target: EntryTarget,
}

/// What a directory entry points at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EntryTarget {
    /// An object of this same subvolume.
    Inode {
        /// Its number.
        inode: u64,
        /// What it is, which the entry repeats so a reader need not fetch the inode to know.
        kind: DirEntryType,
    },
    /// The root of another subvolume, which appears in a directory as though it were one.
    Subvolume {
        /// The subvolume's id.
        id: u64,
    },
}

/// One name an object answers to: which directory holds it, where in that directory's
/// sequence, and the name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ObjectName {
    /// The directory's inode number, within the same subvolume.
    pub parent: u64,
    /// The sequence the name sits at in that directory.
    pub index: u64,
    /// The name.
    pub name: Vec<u8>,
}

/// One object of a subvolume: everything about it that does not depend on where its bytes land.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelObject {
    /// Its number within its subvolume, from [`objectid::FIRST_FREE`] upward.
    pub inode: u64,
    /// What it is.
    pub kind: ObjectKind,
    /// Ownership, permission bits, and the three times a source carries.
    pub meta: Metadata,
    /// Its extended attributes, in the order the source gave them.
    pub xattrs: Vec<Xattr>,
    /// Every name it answers to, in the order the sorted source reached them.
    pub names: Vec<ObjectName>,
}

impl ModelObject {
    /// What the inode's size field holds.
    ///
    /// A directory's is the bytes of name its entries occupy, counted twice — once for the
    /// record a lookup finds and once for the record reading in order finds. That is what the
    /// format's own tooling writes and what a driver keeps up to date; it is not a count of
    /// anything a caller can see.
    pub(crate) fn size(&self) -> u64 {
        match &self.kind {
            ObjectKind::Directory(entries) => entries.iter().map(|e| 2 * e.name.len() as u64).sum(),
            ObjectKind::File { size, .. } => *size,
            ObjectKind::Symlink(target) => target.len() as u64,
            _ => 0,
        }
    }
}

/// One subvolume: its identity, where it is named, and everything in it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelSubvolume {
    /// The tree's objectid: [`objectid::FS_TREE`] for the top-level one, and
    /// [`objectid::FIRST_FREE`] upward for the rest.
    pub id: u64,
    /// The subvolume's own identifier.
    pub uuid: [u8; 16],
    /// Whether a driver refuses to write into it.
    pub read_only: bool,
    /// Where it is named, or [`None`] for the top-level subvolume, which the root tree's own
    /// directory names instead.
    pub link: Option<SubvolumeLink>,
    /// Every object in it, the root directory first and then in ascending inode order — which
    /// is the order they were numbered in and therefore sorted path order.
    pub objects: Vec<ModelObject>,
}

/// Where a subvolume is named.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct SubvolumeLink {
    /// The id of the subvolume whose tree holds the name.
    pub parent: u64,
    /// The inode of the directory in that tree.
    pub dir: u64,
    /// The sequence the name sits at in that directory.
    pub index: u64,
    /// The name.
    pub name: Vec<u8>,
}

/// A tree placed in a filesystem: every subvolume, every object, and what the planner is owed.
#[derive(Debug)]
pub(crate) struct BtrfsModel {
    /// Every subvolume, the top-level one first and each parent before its children.
    pub subvolumes: Vec<ModelSubvolume>,
    /// Which subvolume a mount resolves to when it is told none.
    pub default_subvolume: u64,
    /// Every distinct file's bytes, indexed by [`ObjectKind::File::content`].
    pub contents: Vec<FileContent>,
    /// What the geometry must be planned to hold.
    pub content: Content,
    /// What the format could not carry, which for this family is nothing.
    pub fidelity: FidelityReport,
}

/// Build the model a source implies, for a filesystem of these two block sizes.
///
/// `sector_size` decides which files are small enough to be stored inside the metadata, and
/// `node_size` decides what a single record may weigh. Both are resolved from the plan request
/// before this is called, so the model and the geometry agree about them by construction.
/// `subvolume_uuid` is the top-level subvolume's identifier, held by the model so that every
/// record naming it reads one value. `time` is what a subvolume's root directory is stamped
/// with where no source entry describes it, which is the only instant here that does not come
/// from the source.
///
/// # Errors
///
/// A [`ModelError`] for anything the filesystem cannot hold: a path used twice or holding `..`,
/// a name longer than the format's field, a missing parent, an unresolvable hard link, a hard
/// link across a subvolume boundary, a subvolume asked for at a path that is not a directory,
/// two subvolumes sharing one identifier, or a record larger than a tree block.
pub(crate) fn build_model(
    entries: Vec<SourceEntry>,
    subvolumes: &[SubvolumeRequest],
    default_subvolume: Option<&[u8]>,
    subvolume_uuid: [u8; 16],
    sector_size: u32,
    node_size: u32,
    time: Timestamp,
) -> Result<BtrfsModel, ModelError> {
    Builder::new(sector_size, node_size, time).build(
        entries,
        subvolumes,
        default_subvolume,
        subvolume_uuid,
    )
}

/// What a path holds, decided before anything is numbered.
///
/// A hard link may name a target that sorts after it — `/also` before `/bin` — so what every
/// path is has to be known before any of them becomes an object.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Class {
    /// A directory.
    Directory,
    /// Something with an inode of its own: a file, a link, a node.
    Object,
    /// A hard link, by the canonical key of what it names.
    Link(Vec<u8>),
}

/// A hard link whose target had not been reached when the link was.
struct PendingLink {
    /// The directory the name is in.
    parent: Placed,
    /// Which of that directory's entries it is.
    at: usize,
    /// The path the link names.
    target: Vec<u8>,
    /// The link's own path, for a refusal to name.
    path: Vec<u8>,
    /// The name itself.
    name: Vec<u8>,
    /// The sequence it sits at.
    index: u64,
    /// Attributes the source stated on the link, held until the target exists so they can
    /// be compared with its.
    xattrs: Vec<Xattr>,
}

/// Where an object ended up, so a name added later finds it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Placed {
    /// Which subvolume, by index into [`Builder::subvolumes`].
    subvolume: usize,
    /// Which object of it, by index.
    object: usize,
}

/// The tree under construction.
struct Builder {
    sector_size: u32,
    /// What a root directory nothing describes is stamped with.
    time: Timestamp,
    /// The most bytes one item of this filesystem may hold, which is a whole leaf less the entry
    /// describing it.
    capacity: usize,
    subvolumes: Vec<ModelSubvolume>,
    contents: Vec<FileContent>,
    /// What every declared path holds, from the classifying pass.
    classes: BTreeMap<Vec<u8>, Class>,
    /// Which subvolume each declared directory path is the root of.
    subvolume_at: HashMap<Vec<u8>, usize>,
    /// Where every declared path ended up.
    placed: HashMap<Vec<u8>, Placed>,
    /// Names whose object was not yet placed when they were reached.
    pending: Vec<PendingLink>,
    /// The largest single value any record must hold.
    longest_value: u64,
    longest_name: u32,
    names: u64,
    xattrs: u64,
    directories: u64,
    files: u64,
    data_bytes: u64,
    data_extents: u64,
}

impl Builder {
    fn new(sector_size: u32, node_size: u32, time: Timestamp) -> Self {
        Self {
            sector_size,
            time,
            capacity: node_size as usize - Header::SIZE - Item::SIZE,
            subvolumes: Vec::new(),
            contents: Vec::new(),
            classes: BTreeMap::new(),
            subvolume_at: HashMap::new(),
            placed: HashMap::new(),
            pending: Vec::new(),
            longest_value: 0,
            longest_name: 0,
            names: 0,
            xattrs: 0,
            directories: 0,
            files: 0,
            data_bytes: 0,
            data_extents: 0,
        }
    }

    fn build(
        mut self,
        mut entries: Vec<SourceEntry>,
        requested: &[SubvolumeRequest],
        default_subvolume: Option<&[u8]>,
        subvolume_uuid: [u8; 16],
    ) -> Result<BtrfsModel, ModelError> {
        // Sorted by canonical path, which does three things at once: a parent is always seen
        // before its children, because a path sorts before every path it prefixes; a directory's
        // entries are numbered in one order whatever order the source yielded them; and a
        // subvolume is created before anything that goes in it.
        entries.sort_by_key(|entry| canonical_key(&entry.path));
        self.classify(&entries)?;

        // The top-level subvolume, whose root directory exists whether or not a source describes
        // it. It carries the caller's identifier from the start, so every record naming it —
        // the root item and the UUID tree alike — reads the identifier from one place.
        // Placed under the empty key, which is what every path at the top level finds as its
        // parent — the root is where the tree begins rather than something a source declares.
        let root = self.open_subvolume(objectid::FS_TREE, subvolume_uuid, false, None);
        self.placed.insert(
            Vec::new(),
            Placed {
                subvolume: root,
                object: 0,
            },
        );

        let mut wanted = self.subvolume_requests(requested, subvolume_uuid)?;
        for entry in entries {
            self.place(entry, &mut wanted)?;
        }
        self.resolve_links()?;

        let default_subvolume = match default_subvolume {
            None => objectid::FS_TREE,
            Some(path) => {
                let key = canonical_key(path);
                if key.is_empty() {
                    objectid::FS_TREE
                } else {
                    let at = self.subvolume_at.get(&key).copied().ok_or_else(|| {
                        ModelError::DefaultSubvolumeUnknown {
                            path: path.to_vec(),
                        }
                    })?;
                    self.subvolumes[at].id
                }
            }
        };

        let content = Content {
            directories: self.directories,
            files: self.files,
            names: self.names,
            longest_name: self.longest_name,
            longest_value: self.longest_value,
            xattrs: self.xattrs,
            subvolumes: self.subvolumes.len() as u64 - 1,
            data_bytes: self.data_bytes,
            data_extents: self.data_extents,
        };
        Ok(BtrfsModel {
            subvolumes: self.subvolumes,
            default_subvolume,
            contents: self.contents,
            content,
            fidelity: FidelityReport::new(),
        })
    }

    /// Decide what every path holds.
    ///
    /// The faults a path has whatever format is holding it are the shared pass's; what is this
    /// family's is the bound on a name, which is checked on the components that pass already
    /// split rather than on a second splitting of the same path.
    fn classify(&mut self, entries: &[SourceEntry]) -> Result<(), ModelError> {
        self.classes = classify_paths(
            entries,
            |entry, parts| match parts.last() {
                Some(name) if name.len() > MAX_NAME_LEN => Err(ModelError::NameTooLong {
                    path: entry.path.clone(),
                    bytes: name.len(),
                }),
                _ => Ok(match &entry.kind {
                    EntryKind::Directory => Class::Directory,
                    EntryKind::HardLink { target } => Class::Link(canonical_key(target)),
                    _ => Class::Object,
                }),
            },
            |class| *class == Class::Directory,
        )
        .map_err(|e| match e {
            ClassifyError::Class(e) => e,
            ClassifyError::Path(PathFault::Traversal, path) => {
                ModelError::InvalidComponent { path }
            }
            ClassifyError::Path(PathFault::Duplicate, path) => ModelError::Duplicate { path },
            ClassifyError::Path(PathFault::RootNotDirectory, path) => {
                ModelError::RootNotDirectory { path }
            }
        })?;
        Ok(())
    }

    /// The subvolumes to create, keyed by the canonical path each is asked for at.
    ///
    /// Checked here rather than where a subvolume is created, so a request naming a path the
    /// source never declares is refused before any of the tree has been built — and so the
    /// refusal names the path the caller wrote.
    fn subvolume_requests<'a>(
        &self,
        requested: &'a [SubvolumeRequest],
        top_level_uuid: [u8; 16],
    ) -> Result<HashMap<Vec<u8>, &'a SubvolumeRequest>, ModelError> {
        let mut wanted: HashMap<Vec<u8>, &SubvolumeRequest> = HashMap::new();
        // Which path holds each identifier, so a repeat is refused naming both holders. The
        // top-level subvolume's is in from the start: it is a subvolume like the others, and
        // its identifier collides like theirs. An all-zero identifier records that none was
        // set, so it is absent here as it is absent from the UUID tree.
        let mut identified: HashMap<[u8; 16], Vec<u8>> = HashMap::new();
        if top_level_uuid != [0; 16] {
            identified.insert(top_level_uuid, b"/".to_vec());
        }
        for request in requested {
            let key = canonical_key(&request.path);
            if key.is_empty() {
                return Err(ModelError::SubvolumeAtRoot);
            }
            if self.classes.get(&key) != Some(&Class::Directory) {
                return Err(ModelError::SubvolumeNotADirectory {
                    path: request.path.clone(),
                });
            }
            if wanted.insert(key, request).is_some() {
                return Err(ModelError::SubvolumeDuplicate {
                    path: request.path.clone(),
                });
            }
            if request.uuid != [0; 16]
                && let Some(first) = identified.insert(request.uuid, request.path.clone())
            {
                return Err(ModelError::SubvolumeUuidRepeated {
                    first,
                    second: request.path.clone(),
                    uuid: request.uuid,
                });
            }
        }
        Ok(wanted)
    }

    /// Add one source entry to the tree.
    fn place(
        &mut self,
        entry: SourceEntry,
        wanted: &mut HashMap<Vec<u8>, &SubvolumeRequest>,
    ) -> Result<(), ModelError> {
        let SourceEntry {
            path,
            kind,
            meta,
            xattrs,
        } = entry;
        // The kind supplies the file-type bits, so a mode arriving with its own — a raw
        // `st_mode` passed through whole is the natural way — would put a second type on
        // the inode, and the write would succeed while every checker and driver reads the
        // result as corrupt.
        if meta.mode & MODE_TYPE_MASK != 0 {
            return Err(ModelError::ModeCarriesFileType {
                path,
                mode: meta.mode,
            });
        }
        let key = canonical_key(&path);

        // The root directory of the top-level subvolume already exists; a source naming it says
        // what it is like rather than that it is there.
        if key.is_empty() {
            let root = &mut self.subvolumes[0].objects[0];
            root.meta = meta;
            self.account_xattrs(&xattrs, &path)?;
            self.subvolumes[0].objects[0].xattrs = xattrs;
            self.placed.insert(
                key,
                Placed {
                    subvolume: 0,
                    object: 0,
                },
            );
            return Ok(());
        }

        let split = key.iter().rposition(|&b| b == b'/');
        let (parent_key, name) = match split {
            Some(at) => (key[..at].to_vec(), key[at + 1..].to_vec()),
            None => (Vec::new(), key.clone()),
        };
        let parent = match self.placed.get(&parent_key) {
            Some(placed) => *placed,
            None if self.classes.contains_key(&parent_key) => {
                return Err(ModelError::ParentNotDir { path });
            }
            None => return Err(ModelError::ParentMissing { path }),
        };
        if !matches!(
            self.subvolumes[parent.subvolume].objects[parent.object].kind,
            ObjectKind::Directory(_)
        ) {
            return Err(ModelError::ParentNotDir { path });
        }

        self.longest_name = self.longest_name.max(name.len() as u32);
        self.names += 1;

        // A hard link adds a name to an object rather than making one — and the object may
        // be one no pass has reached yet, since a link at `/also` sorts before its target
        // at `/bin`. So the name takes its place in the directory now, which keeps the
        // sequence in sorted order, and what it names is filled in once every object
        // exists. Answered before the attribute accounting below: attributes belong to
        // objects, so a link has none of its own to account, and accounting them would
        // refuse a format over a record nothing writes.
        if let EntryKind::HardLink { target } = kind {
            // Attributes stated on the link itself belong to the object, which is the
            // target's: no filesystem holds an attribute of a *name*. They are held with
            // the pending link rather than judged here, because the target the comparison
            // needs may not exist yet — a link at `/also` sorts before its target at
            // `/bin` — and the judgement is [`resolve_links`](Self::resolve_links)'s.
            let index = self.next_index(parent);
            let at = self.add_entry(
                parent,
                name.clone(),
                index,
                EntryTarget::Inode {
                    inode: 0,
                    kind: DirEntryType::Unknown,
                },
            );
            self.pending.push(PendingLink {
                parent,
                at,
                target,
                path,
                name,
                index,
                xattrs,
            });
            return Ok(());
        }

        self.account_xattrs(&xattrs, &path)?;

        // A directory that was asked for as a subvolume becomes the root of a tree of its own,
        // and the name its parent holds points at that tree rather than at an inode.
        if let Some(request) = wanted.remove(&key) {
            let index = self.next_index(parent);
            let id = self.next_subvolume_id();
            let at = self.open_subvolume(
                id,
                request.uuid,
                request.read_only,
                Some(SubvolumeLink {
                    parent: self.subvolumes[parent.subvolume].id,
                    dir: self.inode_at(parent),
                    index,
                    name: name.clone(),
                }),
            );
            self.subvolumes[at].objects[0].meta = meta;
            self.subvolumes[at].objects[0].xattrs = xattrs;
            self.add_entry(parent, name, index, EntryTarget::Subvolume { id });
            self.subvolume_at.insert(key.clone(), at);
            self.placed.insert(
                key,
                Placed {
                    subvolume: at,
                    object: 0,
                },
            );
            return Ok(());
        }

        let object_kind = self.kind_of(kind, &path)?;
        match &object_kind {
            ObjectKind::Directory(_) => self.directories += 1,
            _ => self.files += 1,
        }
        let index = self.next_index(parent);
        let entry_type = object_kind.entry_type();
        let subvolume = parent.subvolume;
        let inode = self.next_inode(subvolume);
        let holder = self.inode_at(parent);
        self.subvolumes[subvolume].objects.push(ModelObject {
            inode,
            kind: object_kind,
            meta,
            xattrs,
            names: vec![ObjectName {
                parent: holder,
                index,
                name: name.clone(),
            }],
        });
        let object = self.subvolumes[subvolume].objects.len() - 1;
        self.add_entry(
            parent,
            name,
            index,
            EntryTarget::Inode {
                inode,
                kind: entry_type,
            },
        );
        self.placed.insert(key, Placed { subvolume, object });
        Ok(())
    }

    /// Fill in what every hard link names, now that every object it could name exists.
    fn resolve_links(&mut self) -> Result<(), ModelError> {
        for link in std::mem::take(&mut self.pending) {
            let found = self.follow_link(&link.target, &link.path)?;
            if found.subvolume != link.parent.subvolume {
                return Err(ModelError::HardlinkCrossesSubvolume {
                    path: link.path,
                    target: link.target,
                });
            }
            // Attributes belong to the object, which is the target's. A member repeating
            // the target's attributes exactly states nothing new — archive producers
            // exist that write hard-link members that way — and anything else is refused
            // rather than half-applied.
            if !link.xattrs.is_empty()
                && !crate::xattr::same_xattrs(
                    &link.xattrs,
                    &self.subvolumes[found.subvolume].objects[found.object].xattrs,
                )
            {
                return Err(ModelError::LinkCarriesXattrs { path: link.path });
            }
            let inode = self.inode_at(found);
            let kind = self.subvolumes[found.subvolume].objects[found.object]
                .kind
                .entry_type();
            let holder = self.inode_at(link.parent);
            self.subvolumes[found.subvolume].objects[found.object]
                .names
                .push(ObjectName {
                    parent: holder,
                    index: link.index,
                    name: link.name,
                });
            match &mut self.subvolumes[link.parent.subvolume].objects[link.parent.object].kind {
                ObjectKind::Directory(entries) => {
                    entries[link.at].target = EntryTarget::Inode { inode, kind };
                }
                _ => unreachable!("a name is only ever added to a directory"),
            }
        }
        Ok(())
    }

    /// What an entry becomes, with the sizes it will cost checked against a leaf.
    fn kind_of(&mut self, kind: EntryKind, path: &[u8]) -> Result<ObjectKind, ModelError> {
        Ok(match kind {
            EntryKind::Directory => ObjectKind::Directory(Vec::new()),
            EntryKind::File(content) => {
                let size = content.len();
                // Small enough to live in the metadata: below one sector, which is what the
                // format's own tooling uses, and small enough for one record to hold. The second
                // is not implied by the first — a filesystem may have tree blocks smaller than
                // its sectors.
                let inline = size > 0
                    && size < u64::from(self.sector_size)
                    && FileExtentItem::INLINE_DATA_START + size as usize <= self.capacity;
                if inline {
                    self.longest_value = self.longest_value.max(size);
                } else if size > 0 {
                    let stored =
                        size.div_ceil(u64::from(self.sector_size)) * u64::from(self.sector_size);
                    self.data_bytes += stored;
                    // One extent per mebibyte, charged twice: an extent that meets the end of a
                    // data chunk is split there, and each can meet at most one end — no data
                    // chunk is shorter than an extent — so a file crossing several chunks costs
                    // at most one split per extent. A bound rather than a count: what it feeds
                    // is a reservation, and a reservation that was short is the one way to be
                    // wrong.
                    self.data_extents += stored.div_ceil(MAX_EXTENT_BYTES) * 2;
                }
                let at = self.contents.len();
                self.contents.push(content);
                ObjectKind::File {
                    content: at,
                    size,
                    inline,
                }
            }
            EntryKind::Symlink(target) => {
                let need = FileExtentItem::INLINE_DATA_START + target.len();
                if need > self.capacity {
                    return Err(ModelError::RecordTooLarge {
                        path: path.to_vec(),
                        what: "symbolic link's target",
                        bytes: need,
                        capacity: self.capacity,
                    });
                }
                self.longest_value = self.longest_value.max(target.len() as u64);
                ObjectKind::Symlink(target)
            }
            EntryKind::CharDevice { major, minor } => ObjectKind::Device {
                block: false,
                major,
                minor,
            },
            EntryKind::BlockDevice { major, minor } => ObjectKind::Device {
                block: true,
                major,
                minor,
            },
            EntryKind::Fifo => ObjectKind::Fifo,
            EntryKind::Socket => ObjectKind::Socket,
            // A hard link never reaches here: it adds a name to an object that already exists,
            // which is decided before this is called.
            EntryKind::HardLink { .. } => unreachable!("a hard link is not a kind of object"),
        })
    }

    /// Count an entry's extended attributes, refusing one no leaf can hold.
    fn account_xattrs(&mut self, xattrs: &[Xattr], path: &[u8]) -> Result<(), ModelError> {
        for xattr in xattrs {
            let need = DirItem::SIZE + xattr.name.len() + xattr.value.len();
            if need > self.capacity {
                return Err(ModelError::RecordTooLarge {
                    path: path.to_vec(),
                    what: "extended attribute",
                    bytes: need,
                    capacity: self.capacity,
                });
            }
            self.longest_value = self
                .longest_value
                .max((xattr.name.len() + xattr.value.len()) as u64);
        }
        self.xattrs += xattrs.len() as u64;
        Ok(())
    }

    /// Where the chain of hard links beginning at `target` ends.
    ///
    /// A link may name another link, so this is a walk rather than a lookup, and one that has to
    /// terminate on a source that names a cycle. Every step consumes one declared path, so a
    /// walk longer than the source's own path count has come back to somewhere it has been.
    ///
    /// Run once every object exists, which is what lets a link name a target that sorts after
    /// it — `/also` before `/bin` — without a second classification of what each path holds.
    fn follow_link(&self, target: &[u8], path: &[u8]) -> Result<Placed, ModelError> {
        let mut at = canonical_key(target);
        for _ in 0..=self.classes.len() {
            match self.classes.get(&at) {
                None => {
                    return Err(ModelError::HardlinkTargetMissing {
                        path: path.to_vec(),
                        target: target.to_vec(),
                    });
                }
                Some(Class::Directory) => {
                    return Err(ModelError::HardlinkTargetIsDirectory {
                        path: path.to_vec(),
                        target: target.to_vec(),
                    });
                }
                Some(Class::Link(next)) => at = next.clone(),
                Some(Class::Object) => {
                    return Ok(*self
                        .placed
                        .get(&at)
                        .expect("every object was placed before any link was resolved"));
                }
            }
        }
        Err(ModelError::HardlinkCycle {
            path: path.to_vec(),
        })
    }

    /// Start a subvolume, with the root directory every one has.
    fn open_subvolume(
        &mut self,
        id: u64,
        uuid: [u8; 16],
        read_only: bool,
        link: Option<SubvolumeLink>,
    ) -> usize {
        self.directories += 1;
        self.subvolumes.push(ModelSubvolume {
            id,
            uuid,
            read_only,
            link,
            objects: vec![ModelObject {
                inode: objectid::FIRST_FREE,
                kind: ObjectKind::Directory(Vec::new()),
                meta: root_metadata(self.time),
                xattrs: Vec::new(),
                names: Vec::new(),
            }],
        });
        self.subvolumes.len() - 1
    }

    /// The id the next subvolume takes.
    ///
    /// Subvolume roots are numbered in the root tree's own id space, which begins where the
    /// filesystem's own trees end.
    fn next_subvolume_id(&self) -> u64 {
        objectid::FIRST_FREE + self.subvolumes.len() as u64 - 1
    }

    /// The inode number the next object of this subvolume takes.
    fn next_inode(&self, subvolume: usize) -> u64 {
        objectid::FIRST_FREE + self.subvolumes[subvolume].objects.len() as u64
    }

    /// The inode number of a placed object.
    fn inode_at(&self, placed: Placed) -> u64 {
        self.subvolumes[placed.subvolume].objects[placed.object].inode
    }

    /// The sequence the next name added to this directory sits at.
    fn next_index(&self, dir: Placed) -> u64 {
        match &self.subvolumes[dir.subvolume].objects[dir.object].kind {
            ObjectKind::Directory(entries) => FIRST_DIR_INDEX + entries.len() as u64,
            _ => unreachable!("a name is only ever added to a directory"),
        }
    }

    /// Add a name to a directory, answering where in that directory's list it landed.
    fn add_entry(&mut self, dir: Placed, name: Vec<u8>, index: u64, target: EntryTarget) -> usize {
        match &mut self.subvolumes[dir.subvolume].objects[dir.object].kind {
            ObjectKind::Directory(entries) => {
                entries.push(DirEntry {
                    name,
                    index,
                    target,
                });
                entries.len() - 1
            }
            _ => unreachable!("a name is only ever added to a directory"),
        }
    }
}

/// What a subvolume's root directory is like where nothing describes it.
///
/// Traversable by everyone and writable by its owner, owned by root, and stamped with the
/// instant the format was told to stamp the filesystem with.
fn root_metadata(time: Timestamp) -> Metadata {
    Metadata::new(0o755, time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Source, TreeBuilder};

    const SECTOR: u32 = 4096;
    const NODE: u32 = 16384;
    const TIME: Timestamp = Timestamp {
        secs: 1_700_000_000,
        nanos: 0,
    };

    fn meta() -> Metadata {
        Metadata::new(0o644, crate::Timestamp::from_secs(1_700_000_000))
    }

    fn dir_meta() -> Metadata {
        Metadata::new(0o755, crate::Timestamp::from_secs(1_700_000_000))
    }

    fn model_of(source: impl Source) -> BtrfsModel {
        build_model(
            source.into_entries(),
            &[],
            None,
            [0; 16],
            SECTOR,
            NODE,
            TIME,
        )
        .expect("a buildable tree")
    }

    fn error_of(source: impl Source) -> ModelError {
        build_model(
            source.into_entries(),
            &[],
            None,
            [0; 16],
            SECTOR,
            NODE,
            TIME,
        )
        .expect_err("the tree is refused")
    }

    /// The object at `path`, found by walking the names rather than by index.
    fn object(model: &BtrfsModel, subvolume: usize, inode: u64) -> &ModelObject {
        model.subvolumes[subvolume]
            .objects
            .iter()
            .find(|o| o.inode == inode)
            .expect("an object with that number")
    }

    #[test]
    fn an_empty_source_is_one_subvolume_holding_one_empty_directory() {
        let model = model_of(TreeBuilder::new());
        assert_eq!(model.subvolumes.len(), 1);
        assert_eq!(model.subvolumes[0].objects.len(), 1, "the root directory");
        assert_eq!(model.subvolumes[0].id, objectid::FS_TREE);
        assert_eq!(model.default_subvolume, objectid::FS_TREE);
        assert_eq!(model.content.directories, 1);
        assert_eq!(model.content.files, 0);
        assert!(model.fidelity.is_faithful());
    }

    #[test]
    fn objects_are_numbered_in_sorted_path_order_whatever_order_a_source_yields() {
        // The whole of the reproducibility claim at this layer: two sources describing one tree
        // in two orders are one model.
        let forward = model_of(
            TreeBuilder::new()
                .directory(b"/a".to_vec(), dir_meta())
                .file(b"/a/one".to_vec(), b"1", meta())
                .file(b"/b".to_vec(), b"2", meta()),
        );
        let backward = model_of(
            TreeBuilder::new()
                .file(b"/b".to_vec(), b"2", meta())
                .file(b"/a/one".to_vec(), b"1", meta())
                .directory(b"/a".to_vec(), dir_meta()),
        );
        assert_eq!(forward.subvolumes, backward.subvolumes);
        // 256 is the root, 257 `/a`, 258 `/a/one`, 259 `/b` — sorted path order, and `/a/one`
        // before `/b` because `a/one` sorts before `b`.
        let numbers: Vec<u64> = forward.subvolumes[0]
            .objects
            .iter()
            .map(|o| o.inode)
            .collect();
        assert_eq!(numbers, [256, 257, 258, 259]);
    }

    #[test]
    fn a_directorys_entries_are_numbered_from_two_and_its_size_counts_them_twice() {
        let model = model_of(TreeBuilder::new().file(b"/aa".to_vec(), b"x", meta()).file(
            b"/bbb".to_vec(),
            b"y",
            meta(),
        ));
        let root = object(&model, 0, 256);
        let ObjectKind::Directory(entries) = &root.kind else {
            panic!("the root is a directory")
        };
        assert_eq!(
            entries.iter().map(|e| e.index).collect::<Vec<_>>(),
            [FIRST_DIR_INDEX, FIRST_DIR_INDEX + 1]
        );
        // Two records hold every name — one a lookup finds and one reading in order finds — and
        // the size field counts the bytes of both.
        assert_eq!(root.size(), 2 * (2 + 3));
    }

    #[test]
    fn a_hard_link_is_a_second_name_for_one_object() {
        let model = model_of(
            TreeBuilder::new()
                .file(b"/one".to_vec(), b"x", meta())
                .hardlink(b"/two".to_vec(), b"/one".to_vec(), meta()),
        );
        // One object, two names, and one file counted rather than two.
        assert_eq!(model.subvolumes[0].objects.len(), 2);
        assert_eq!(model.content.files, 1);
        assert_eq!(model.content.names, 2);
        let file = object(&model, 0, 257);
        assert_eq!(
            file.names.iter().map(|n| &n.name).collect::<Vec<_>>(),
            [b"one".as_slice(), b"two".as_slice()]
        );
        // And the directory holds both, at consecutive sequences.
        let ObjectKind::Directory(entries) = &object(&model, 0, 256).kind else {
            panic!("the root is a directory")
        };
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|e| matches!(e.target, EntryTarget::Inode { inode: 257, .. }))
        );
    }

    #[test]
    fn a_chain_of_hard_links_ends_at_the_file_and_a_cycle_is_refused() {
        let model = model_of(
            TreeBuilder::new()
                .file(b"/a".to_vec(), b"x", meta())
                .hardlink(b"/b".to_vec(), b"/a".to_vec(), meta())
                .hardlink(b"/c".to_vec(), b"/b".to_vec(), meta()),
        );
        assert_eq!(object(&model, 0, 257).names.len(), 3);

        let err = error_of(
            TreeBuilder::new()
                .hardlink(b"/a".to_vec(), b"/b".to_vec(), meta())
                .hardlink(b"/b".to_vec(), b"/a".to_vec(), meta()),
        );
        assert!(matches!(err, ModelError::HardlinkCycle { .. }), "{err:?}");
    }

    #[test]
    fn a_file_below_a_sector_goes_in_the_metadata_and_one_at_a_sector_does_not() {
        let model = model_of(
            TreeBuilder::new()
                .file(b"/small".to_vec(), vec![b'x'; SECTOR as usize - 1], meta())
                .file(b"/large".to_vec(), vec![b'x'; SECTOR as usize], meta()),
        );
        let large = object(&model, 0, 257);
        let small = object(&model, 0, 258);
        assert!(matches!(large.kind, ObjectKind::File { inline: false, .. }));
        assert!(matches!(small.kind, ObjectKind::File { inline: true, .. }));
        assert_eq!(model.content.data_bytes, u64::from(SECTOR));
    }

    #[test]
    fn a_file_too_large_for_a_leaf_is_not_stored_in_one_however_small_the_sector() {
        // A filesystem whose tree blocks are smaller than its sectors is legal, and on one the
        // "below a sector" rule alone would put a record in a leaf that cannot hold it.
        let source = TreeBuilder::new().file(b"/f".to_vec(), vec![b'x'; 8000], meta());
        let model = build_model(source.into_entries(), &[], None, [0; 16], 16384, 4096, TIME)
            .expect("a buildable tree");
        assert!(matches!(
            object(&model, 0, 257).kind,
            ObjectKind::File { inline: false, .. }
        ));
    }

    #[test]
    fn an_extended_attribute_no_leaf_holds_is_refused_and_names_the_entry() {
        let err = error_of(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"x", meta())
                .xattr(b"user.big".to_vec(), vec![0u8; NODE as usize]),
        );
        let ModelError::RecordTooLarge { path, what, .. } = &err else {
            panic!("{err:?}")
        };
        assert_eq!(path, b"/f");
        assert_eq!(*what, "extended attribute");
    }

    #[test]
    fn a_hard_link_stating_attributes_other_than_its_targets_is_refused() {
        // Attributes belong to objects and a link is a name, so an attribute stated on
        // the link alone is one no image can carry. Refused rather than dropped — this
        // family's fidelity report answers empty because nothing is quietly lost on the
        // way in — and refused rather than counted, since accounting a record nothing
        // writes once refused a whole format over leaf capacity it never needed.
        let err = error_of(
            TreeBuilder::new()
                .file(b"/target".to_vec(), b"x", meta())
                .hardlink(b"/link".to_vec(), b"/target".to_vec(), meta())
                .xattr(b"user.note".to_vec(), b"v".to_vec()),
        );
        assert!(
            matches!(err, ModelError::LinkCarriesXattrs { .. }),
            "{err:?}"
        );

        // A member that repeats the target's attributes exactly states nothing new —
        // archive producers exist that write hard-link members that way — and builds the
        // image the target alone describes.
        let m = model_of(
            TreeBuilder::new()
                .file(b"/target".to_vec(), b"x", meta())
                .xattr(b"user.note".to_vec(), b"v".to_vec())
                .hardlink(b"/link".to_vec(), b"/target".to_vec(), meta())
                .xattr(b"user.note".to_vec(), b"v".to_vec()),
        );
        let target = m.subvolumes[0]
            .objects
            .iter()
            .find(|object| object.names.len() == 2)
            .expect("the target has two names");
        assert_eq!(target.xattrs.len(), 1, "the one attribute, held once");
    }

    #[test]
    fn a_mode_carrying_file_type_bits_is_rejected() {
        // The natural mistake: a raw `st_mode` passed through whole. The kind supplies
        // the type bits here, so accepting a mode with its own would write an inode
        // carrying two file types — one its directory entry contradicts.
        let err = error_of(TreeBuilder::new().file(b"/f".to_vec(), b"x", {
            let mut m = meta();
            m.mode = 0o100_644;
            m
        }));
        assert!(
            matches!(
                err,
                ModelError::ModeCarriesFileType {
                    mode: 0o100_644,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_subvolume_takes_the_directory_it_names_and_the_tree_beneath_it() {
        let source = TreeBuilder::new()
            .directory(b"/@home".to_vec(), dir_meta())
            .file(b"/@home/user".to_vec(), b"x", meta())
            .file(b"/top".to_vec(), b"y", meta());
        let model = build_model(
            source.into_entries(),
            &[SubvolumeRequest::new(b"/@home".to_vec(), [0x55; 16])],
            Some(b"/@home"),
            [0; 16],
            SECTOR,
            NODE,
            TIME,
        )
        .expect("a buildable tree");

        assert_eq!(model.subvolumes.len(), 2);
        let sub = &model.subvolumes[1];
        assert_eq!(sub.id, objectid::FIRST_FREE);
        assert_eq!(sub.uuid, [0x55; 16]);
        assert_eq!(model.default_subvolume, objectid::FIRST_FREE);

        // Its root directory is the subvolume's inode 256 and its child is 257 — a subvolume is
        // a tree of its own and numbers from the beginning.
        assert_eq!(
            sub.objects.iter().map(|o| o.inode).collect::<Vec<_>>(),
            [256, 257]
        );
        let link = sub
            .link
            .as_ref()
            .expect("a subvolume other than the top is named");
        assert_eq!(link.parent, objectid::FS_TREE);
        assert_eq!(link.dir, 256);
        assert_eq!(link.name, b"@home");

        // And the top-level tree holds the name, pointing at the tree rather than at an inode.
        let ObjectKind::Directory(entries) = &model.subvolumes[0].objects[0].kind else {
            panic!("the root is a directory")
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].target,
            EntryTarget::Subvolume {
                id: objectid::FIRST_FREE
            }
        );
        assert_eq!(model.content.subvolumes, 1);
    }

    #[test]
    fn a_hard_link_across_a_subvolume_boundary_is_refused_rather_than_copied() {
        // The format's own tooling writes a second copy of the file here, silently. Two files
        // where a caller asked for one is a filesystem other than the one they described.
        let source = TreeBuilder::new()
            .directory(b"/sub".to_vec(), dir_meta())
            .file(b"/target".to_vec(), b"x", meta())
            .hardlink(b"/sub/link".to_vec(), b"/target".to_vec(), meta());
        let err = build_model(
            source.into_entries(),
            &[SubvolumeRequest::new(b"/sub".to_vec(), [0x55; 16])],
            None,
            [0; 16],
            SECTOR,
            NODE,
            TIME,
        )
        .expect_err("the tree is refused");
        assert!(
            matches!(err, ModelError::HardlinkCrossesSubvolume { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_subvolume_asked_for_where_no_directory_is_declared_is_refused() {
        let source = TreeBuilder::new().file(b"/f".to_vec(), b"x", meta());
        for (request, default) in [
            (Some(b"/f".to_vec()), None),
            (Some(b"/nowhere".to_vec()), None),
        ] {
            let requests = request.map(|p| SubvolumeRequest::new(p, [0; 16]));
            let err = build_model(
                source.clone().into_entries(),
                requests.as_slice(),
                default,
                [0; 16],
                SECTOR,
                NODE,
                TIME,
            )
            .expect_err("the request is refused");
            assert!(
                matches!(err, ModelError::SubvolumeNotADirectory { .. }),
                "{err:?}"
            );
        }
    }

    #[test]
    fn every_refusal_a_path_can_earn_names_the_path() {
        let cases: Vec<(ModelError, &[u8])> = vec![
            (
                error_of(TreeBuilder::new().file(b"/../x".to_vec(), b"x", meta())),
                b"/../x",
            ),
            (
                error_of(TreeBuilder::new().file(b"/x".to_vec(), b"x", meta()).file(
                    b"//x".to_vec(),
                    b"y",
                    meta(),
                )),
                b"//x",
            ),
            (
                error_of(TreeBuilder::new().file(vec![b'n'; MAX_NAME_LEN + 1], b"x", meta())),
                &[b'n'; MAX_NAME_LEN + 1],
            ),
            (
                error_of(TreeBuilder::new().file(b"/missing/x".to_vec(), b"x", meta())),
                b"/missing/x",
            ),
            (
                error_of(TreeBuilder::new().file(b"/f".to_vec(), b"x", meta()).file(
                    b"/f/under".to_vec(),
                    b"y",
                    meta(),
                )),
                b"/f/under",
            ),
            (
                error_of(
                    TreeBuilder::new()
                        .root(meta())
                        .file(b"/".to_vec(), b"x", meta()),
                ),
                b"/",
            ),
        ];
        for (err, path) in cases {
            let text = err.to_string();
            let printable = crate::escape::printable(path);
            assert!(
                text.contains(&printable),
                "{text} does not name {printable}"
            );
        }
    }

    #[test]
    fn the_root_is_described_by_a_source_rather_than_created_by_one() {
        let model = model_of(
            TreeBuilder::new()
                .root(Metadata::new(0o700, crate::Timestamp::from_secs(42)).owned_by(1, 2))
                .xattr(b"user.on-the-root".to_vec(), b"v".to_vec()),
        );
        let root = object(&model, 0, 256);
        assert_eq!(root.meta.mode, 0o700);
        assert_eq!((root.meta.uid, root.meta.gid), (1, 2));
        assert_eq!(root.xattrs.len(), 1);
        // One directory, still: naming the root does not add one.
        assert_eq!(model.content.directories, 1);
    }
}
