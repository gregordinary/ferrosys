//! The pure model built from a [`Source`](crate::Source) before any byte is written: the
//! directory tree, the name every entry takes, the clusters each one occupies, and the
//! accounting of what the format could not carry.
//!
//! Everything a populated format can fail on happens here, which is what lets a caller find
//! out whether a build will work before the destination is touched. The materializer that
//! consumes a model only writes.
//!
//! # What FAT records, and what it does not
//!
//! A FAT directory entry holds a name, one attribute byte, three coarse timestamps, a first
//! cluster, and a length. It has no field for an owner, a group, permission bits, a symbolic
//! link, a second name for a file, a device number, or an extended attribute — so a tree
//! carrying any of those loses something on the way in.
//!
//! A property is **dropped** when the value a reader gets back is not the value the source
//! stated, which is a narrower thing than "the format has no field for it". A tree owned by
//! root with `0644` files and `0755` directories goes into a FAT image and comes back out of
//! it unchanged, because those are exactly the values [`Synthesis`](crate::Synthesis) hands back for a
//! filesystem that records none — so nothing was lost and the report says so. A file at
//! `0755` did lose something, and so the build refuses until the caller has said it accepts
//! that ([`AcceptedLoss`](crate::AcceptedLoss)).
//!
//! Two things are outside that accounting, each for a stated reason:
//!
//! - **The precision of a time is recorded and never refuses.** Every timestamp the format
//!   holds is coarser than the source's, so a refusal here would fire on nearly every tree
//!   and could not be avoided by changing one — and an acknowledgement that must always be
//!   given is one a caller learns to give blanket, which would accept the losses that do
//!   depend on the tree along with it.
//! - **The root directory's own metadata is ignored, and is not a record.** The format
//!   stores no owner, mode, or time for the root on any volume, so there is no input that
//!   would make it survive and nothing a caller could act on. A `SourceEntry` naming the
//!   root is accepted, and describes a directory that exists either way.
//!
//! # Reproducibility
//!
//! Entries are sorted by path before anything is placed, so the order of a directory, the
//! numeric tails its short names take, and the cluster every file lands on are all functions
//! of the tree rather than of the order a source happened to yield it in. Two models of one
//! tree are the same model.

use std::collections::{BTreeMap, HashMap};

use crate::fidelity::{Direction, FidelityReport, LossPolicy, Property, WRITE_BITS};
use crate::path::canonical_key;
use crate::source::{
    ClassifyError, EntryKind, FileContent, LinkEnd, LinkStep, Metadata, PathFault, SourceEntry,
    classify_paths, follow_hard_link,
};
use crate::time::{DosTimestamp, Timestamp};

use super::geometry::FatLayout;
use super::name::{DirNames, NameError, PlacedName, folded};
use super::ondisk::{Attributes, DIR_ENTRY_SIZE};

/// The largest file the format records a length for: the length field is 32 bits.
pub const MAX_FILE_BYTES: u64 = u32::MAX as u64;

/// Which of an entry's times a range refusal is about, so the message names a field rather
/// than an instant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum TimeField {
    /// The modification time, which the entry records as both its write and creation time.
    Modification,
    /// The access time, which the entry records as a date.
    Access,
}

impl TimeField {
    /// The lowercase name of the field, for a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TimeField::Modification => "modification time",
            TimeField::Access => "access time",
        }
    }
}

impl core::fmt::Display for TimeField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An input a FAT volume cannot hold.
///
/// A path in a message is rendered rather than repeated: a source path is a byte string that
/// need not be text and may hold anything a terminal acts on. Naming the offending path
/// imperfectly is worth far more than refusing to name it, so an unrepresentable byte becomes
/// U+FFFD and anything a terminal would act on becomes a visible escape.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A name the format cannot represent. Every one of these is a refusal rather than a
    /// recorded loss: a name is what a file is found by, so substituting one would hand back
    /// a tree whose entries are not the entries that were asked for.
    #[error("{}: {source}", crate::escape::printable(.path))]
    #[non_exhaustive]
    Name {
        /// The offending path.
        path: Vec<u8>,
        /// Why the name cannot be stored.
        #[source]
        source: NameError,
    },
    /// A path component was `..`, which a source may not use — a path is where an entry
    /// goes, not a traversal to be resolved.
    #[error("path {} has a `..` component", crate::escape::printable(.path))]
    #[non_exhaustive]
    InvalidComponent {
        /// The offending path.
        path: Vec<u8>,
    },
    /// Two entries resolve to the same path. Rejected rather than resolved by keeping the
    /// last, so the filesystem an ambiguous source would produce is never guessed at.
    #[error("path {} is used by more than one entry", crate::escape::printable(.path))]
    #[non_exhaustive]
    Duplicate {
        /// The duplicated path.
        path: Vec<u8>,
    },
    /// Two entries in one directory have names a driver cannot tell apart.
    ///
    /// A FAT name is matched without regard to case, so two names differing only in case are
    /// one name to every driver that reads the volume — a directory holding both is
    /// ambiguous however well-formed each entry is, and a lookup finds whichever it meets
    /// first.
    #[error(
        "{} and {} differ only in case, which no FAT driver distinguishes",
        crate::escape::printable(.path),
        crate::escape::printable(.other)
    )]
    #[non_exhaustive]
    Indistinguishable {
        /// The path that could not be placed.
        path: Vec<u8>,
        /// The path already in that directory.
        other: Vec<u8>,
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
    /// An entry naming the root is not a directory. The root is a directory, so an entry
    /// that would place anything else there is rejected rather than ignored.
    #[error("entry {} names the root but is not a directory", crate::escape::printable(.path))]
    #[non_exhaustive]
    RootNotDirectory {
        /// The offending path.
        path: Vec<u8>,
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
    /// A time the entry records is outside the range the format represents.
    ///
    /// Refused rather than recorded as a loss, because a year that overflowed the field's
    /// seven bits would land in the 1980s and look entirely plausible — which is the one
    /// failure a report after the fact cannot make safe.
    #[error(
        "{}: a {field} of {secs} seconds past the epoch is outside the {min} to {max} a FAT \
         directory entry represents",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    TimeOutOfRange {
        /// The offending path.
        path: Vec<u8>,
        /// Which of the entry's times it was.
        field: TimeField,
        /// The seconds given.
        secs: i64,
        /// The earliest the format represents.
        min: i64,
        /// The latest the format represents.
        max: i64,
    },
    /// A file longer than the entry's 32-bit length field records.
    #[error(
        "{}: a file of {bytes} bytes exceeds the {limit} a directory entry's length field \
         records",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    FileTooLarge {
        /// The offending path.
        path: Vec<u8>,
        /// Bytes the file holds.
        bytes: u64,
        /// The most the field records.
        limit: u64,
    },
    /// The format cannot carry a property this entry states, and the caller has not said it
    /// accepts losing it.
    ///
    /// Add the property to [`AcceptedLoss`](crate::AcceptedLoss) to build anyway; what was lost then comes back
    /// in the [`FidelityReport`], entry by entry.
    #[error(
        "{}: a FAT volume cannot carry the {} of this entry",
        crate::escape::printable(.path),
        .property.as_str()
    )]
    #[non_exhaustive]
    LossNotAccepted {
        /// The entry that would lose something.
        path: Vec<u8>,
        /// What it would lose.
        property: Property,
    },
    /// The root directory region is full.
    ///
    /// FAT12 and FAT16 give the root a fixed region rather than a cluster chain, so its
    /// capacity is decided when the volume is planned and cannot grow. A long name costs one
    /// entry per thirteen characters on top of the entry it names, which is what usually
    /// fills one. Raise [`RootEntries`](super::RootEntries) or move the files into a
    /// subdirectory, which has no such limit.
    #[error(
        "the root directory needs {needed} entries and its region holds {capacity}; FAT12 \
         and FAT16 fix that capacity when the volume is planned"
    )]
    #[non_exhaustive]
    RootDirectoryFull {
        /// Entries the tree needs there, long names included.
        needed: u32,
        /// Entries the planned region holds.
        capacity: u32,
    },
    /// The tree needs more clusters than the volume has.
    #[error("the tree needs {needed} clusters and the volume has {available}")]
    #[non_exhaustive]
    VolumeFull {
        /// Clusters the tree needs.
        needed: u64,
        /// Clusters the volume has.
        available: u32,
    },
}

/// The length field's value for a file of `bytes`.
fn file_size(bytes: u64, path: &[u8]) -> Result<u32, ModelError> {
    u32::try_from(bytes).map_err(|_| ModelError::FileTooLarge {
        path: path.to_vec(),
        bytes,
        limit: MAX_FILE_BYTES,
    })
}

/// Which entry of [`FatModel::dirs`] the root directory is.
pub(crate) const ROOT_DIR: usize = 0;

/// A run of consecutive clusters: everything one entry occupies.
///
/// Every chain this crate writes is contiguous. A formatter builds a fresh filesystem in one
/// pass with nothing to work around, so there is no fragmentation to represent and a chain is
/// a first cluster and a count rather than a list — which is also what keeps the model's
/// memory a function of the entry count rather than of the volume's size.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct ClusterRun {
    /// The first cluster, or zero where the entry occupies none — an empty file, or the
    /// fixed root region of a FAT12 or FAT16 volume.
    pub first: u32,
    /// How many clusters follow it, itself included.
    pub count: u32,
}

impl ClusterRun {
    /// Whether the run holds no clusters.
    pub(crate) const fn is_empty(self) -> bool {
        self.count == 0
    }
}

/// The three times a directory entry records, already in the form it stores them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct EntryTimes {
    /// The creation date, time, and hundredths.
    pub create: DosTimestamp,
    /// The write date and time. Its hundredths are not stored — the entry has one such
    /// field and it belongs to the creation time.
    pub write: DosTimestamp,
    /// The access date. The format has no access *time*.
    pub access_date: u16,
}

/// What an entry points at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Node {
    /// A subdirectory, by index into [`FatModel::dirs`].
    Dir(usize),
    /// A regular file.
    File {
        /// Its bytes, by index into [`FatModel::contents`]. Two entries share one index
        /// where a hard link was copied.
        content: usize,
        /// Its length, which the entry records.
        size: u32,
        /// The clusters it occupies. Each entry has its own, so a copied hard link is two
        /// files rather than two names for cross-linked clusters.
        run: ClusterRun,
    },
}

/// One entry of a directory, ready to be written.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelEntry {
    /// Its name, short and long.
    pub name: PlacedName,
    /// Its attribute byte.
    pub attributes: Attributes,
    /// Its times.
    pub times: EntryTimes,
    /// What it points at.
    pub node: Node,
}

/// A directory: what is in it, where it lives, and what its own `.` entry records.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelDir {
    /// The directory holding this one, or `None` for the root.
    pub parent: Option<usize>,
    /// Its entries, in the order they are written — sorted by name, which is what makes two
    /// formats of one tree identical.
    pub entries: Vec<ModelEntry>,
    /// The times its `.` and `..` entries record.
    pub times: EntryTimes,
    /// The clusters it occupies, empty for the fixed root region of a FAT12 or FAT16 volume.
    pub run: ClusterRun,
}

impl ModelDir {
    /// Directory entries this directory occupies: everything in it, the long-name entries
    /// each one carries, and whatever leads them.
    ///
    /// `index` and `has_label` decide the leading entries, and they are parameters rather
    /// than fields because this is the one place that decides how much room a directory
    /// needs. Two callers computing it separately is how a directory ends up given fewer
    /// clusters than it is written into — which does not show up in the bytes, because the
    /// file placed on the cluster after it is written second and lands on top of the
    /// overflow.
    fn slots(&self, index: usize, has_label: bool) -> u64 {
        let leading = if index == ROOT_DIR {
            // The volume label leads the root directory, and it is an entry like any other.
            u64::from(has_label)
        } else {
            // `.` and `..`, which every directory but the root carries.
            2
        };
        leading
            + self
                .entries
                .iter()
                .map(|e| e.name.slots() as u64)
                .sum::<u64>()
    }
}

/// A tree placed on a volume: every directory, every file's bytes, the clusters they hold,
/// and what the format could not carry.
#[derive(Debug)]
pub(crate) struct FatModel {
    /// Every directory, the root at index 0. A parent always has a lower index than its
    /// children, because the entries were sorted by path before any of them was created.
    pub dirs: Vec<ModelDir>,
    /// Every distinct file's bytes. An entry names one by index, and two entries name one
    /// where a hard link was copied.
    pub contents: Vec<FileContent>,
    /// What the format could not carry, and what it stored more coarsely.
    pub fidelity: FidelityReport,
    /// Clusters the tree occupies, which the information sector's free count is derived
    /// from.
    pub used_clusters: u32,
    /// The first cluster no entry holds, which the information sector records as its hint.
    pub next_free: u32,
}

/// Inputs the model needs beyond the source and the geometry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ModelConfig {
    /// Which losses the caller has accepted, and what a read would invent in their place.
    pub loss: LossPolicy,
    /// Whether the volume carries a label, which occupies an entry of the root directory.
    pub has_label: bool,
}

/// Build the model a `source` and a `layout` imply.
///
/// # Errors
///
/// A [`ModelError`] for anything the volume cannot hold: a name, a shape, a time outside the
/// format's range, a tree larger than the volume, or a property the caller has not accepted
/// losing.
/// Decide everything about a tree that does not depend on how large the volume is.
///
/// The half of [`build_model`] a fit search runs once, so that what it runs per candidate is
/// [`PlacedTree::allocate`] alone.
pub(crate) fn place_tree(
    entries: Vec<SourceEntry>,
    config: &ModelConfig,
) -> Result<PlacedTree, ModelError> {
    Builder::new(config).place_all(entries)
}

pub(crate) fn build_model(
    entries: Vec<SourceEntry>,
    layout: &FatLayout,
    config: &ModelConfig,
) -> Result<FatModel, ModelError> {
    let mut placed = Builder::new(config).place_all(entries)?;
    let (used_clusters, next_free) = placed.allocate(layout, config)?;
    Ok(placed.finish(used_clusters, next_free))
}

/// What a path holds, decided before anything is placed.
///
/// A hard link may name a target that sorts *after* it — `/also` before `/bin` — so what
/// every path is has to be known before any of them is turned into an entry. This is that
/// pass's answer.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Class {
    /// A directory.
    Dir,
    /// A regular file: which content it is, and how long.
    File {
        /// Index into [`FatModel::contents`], assigned in the order the sorted entries run.
        content: usize,
        /// Its length, which the entry records.
        size: u32,
    },
    /// A hard link, by the canonical key of what it names.
    Link(Vec<u8>),
    /// Something the format has no field for, which leaves no entry behind.
    Unrepresentable,
}

/// The tree under construction.
struct Builder<'a> {
    config: &'a ModelConfig,
    dirs: Vec<ModelDir>,
    contents: Vec<FileContent>,
    fidelity: FidelityReport,
    /// What every declared path holds, from the classifying pass.
    classes: BTreeMap<Vec<u8>, Class>,
    /// Which directory each declared path is, so a child finds its parent in one lookup.
    dir_of: HashMap<Vec<u8>, usize>,
    /// The short names each directory has handed out.
    names: Vec<DirNames>,
    /// The case-folded names each directory holds, and the path that took each, so a pair a
    /// driver cannot distinguish names both of them.
    folded: Vec<HashMap<String, Vec<u8>>>,
}

impl<'a> Builder<'a> {
    fn new(config: &'a ModelConfig) -> Self {
        let root = ModelDir {
            parent: None,
            entries: Vec::new(),
            times: EntryTimes::default(),
            run: ClusterRun::default(),
        };
        Self {
            config,
            dirs: vec![root],
            contents: Vec::new(),
            fidelity: FidelityReport::new(),
            classes: BTreeMap::new(),
            dir_of: HashMap::from([(Vec::new(), 0usize)]),
            names: vec![DirNames::new()],
            folded: vec![HashMap::new()],
        }
    }

    /// Everything about a tree that does not depend on how large the volume is.
    ///
    /// Naming, classification, directory shape, and what the format could not carry are all
    /// decided here, once. What clusters any of it takes is [`PlacedTree::allocate`], which
    /// is the only part a search over candidate sizes has to run again.
    fn place_all(mut self, mut entries: Vec<SourceEntry>) -> Result<PlacedTree, ModelError> {
        // Sorted by canonical path, which does three things at once: a parent is always seen
        // before its children, because a path sorts before every path it prefixes; a
        // directory's entries come out in one order whatever order the source yielded them;
        // and the numeric tails short names take are therefore reproducible.
        entries.sort_by_key(|entry| canonical_key(&entry.path));

        self.classify(&entries)?;
        for entry in entries {
            self.place(entry)?;
        }
        Ok(PlacedTree {
            dirs: self.dirs,
            contents: self.contents,
            fidelity: self.fidelity,
        })
    }

    /// Decide what every path holds.
    ///
    /// The faults a path has whatever format is holding it are the shared pass's. Content
    /// indices are handed out here, in the sorted order — the placing pass walks the same list
    /// in the same order and pushes each file's bytes as it reaches them, so the two agree by
    /// construction.
    fn classify(&mut self, entries: &[SourceEntry]) -> Result<(), ModelError> {
        let mut next_content = 0usize;
        self.classes = classify_paths(
            entries,
            |entry, _| {
                Ok(match &entry.kind {
                    EntryKind::Directory => Class::Dir,
                    EntryKind::File(content) => {
                        let size = file_size(content.len(), &entry.path)?;
                        let content = next_content;
                        next_content += 1;
                        Class::File { content, size }
                    }
                    EntryKind::HardLink { target } => Class::Link(canonical_key(target)),
                    _ => Class::Unrepresentable,
                })
            },
            |class| *class == Class::Dir,
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

    /// Add one source entry to the tree.
    fn place(&mut self, entry: SourceEntry) -> Result<(), ModelError> {
        let SourceEntry {
            path,
            kind,
            meta,
            xattrs,
        } = entry;
        let key = canonical_key(&path);

        // The root's own metadata goes nowhere: the format records no owner, mode, or time
        // for it on any volume, so a source describing it describes something already true
        // and there is nothing for a report to say that a caller could act on.
        if key.is_empty() {
            return Ok(());
        }

        let split = key.iter().rposition(|&b| b == b'/');
        let (parent_key, name) = match split {
            Some(at) => (key[..at].to_vec(), key[at + 1..].to_vec()),
            None => (Vec::new(), key.clone()),
        };
        let parent = match self.dir_of.get(&parent_key) {
            Some(&index) => index,
            None if self.classes.contains_key(&parent_key) => {
                return Err(ModelError::ParentNotDir { path });
            }
            None => return Err(ModelError::ParentMissing { path }),
        };

        // What the entry becomes, before it is named — a kind the format cannot hold leaves
        // no entry behind, so its name and its times are never consulted. That is the honest
        // order: refusing an absent entry's name would be refusing over something the image
        // does not have.
        let Some(node) = self.node_for(kind, &key, &path)? else {
            return Ok(());
        };

        let placed = self.name_in(parent, &name, &path)?;
        let times = self.times_for(&meta, &path)?;
        let is_dir = matches!(node, Node::Dir(_));
        self.record_losses(&meta, &xattrs, is_dir, &path)?;

        let mut attributes = if is_dir {
            Attributes::DIRECTORY
        } else {
            // Every mainstream driver sets the archive attribute on a file it creates, and
            // backup software is what clears it. It says nothing about a POSIX mode.
            Attributes::ARCHIVE
        };
        // The one bit of a mode the format carries: a driver that meets it clears the write
        // bits of whatever mode it hands back, so writing it is what makes a `0444` file
        // read back as one.
        if meta.mode & WRITE_BITS == 0 {
            attributes |= Attributes::READ_ONLY;
        }

        if let Node::Dir(index) = node {
            self.dirs[index].times = times;
        }
        self.dirs[parent].entries.push(ModelEntry {
            name: placed,
            attributes,
            times,
            node,
        });
        Ok(())
    }

    /// What this entry becomes, or `None` where the format has nowhere to put it and the
    /// caller has accepted losing it.
    fn node_for(
        &mut self,
        kind: EntryKind,
        key: &[u8],
        path: &[u8],
    ) -> Result<Option<Node>, ModelError> {
        match kind {
            EntryKind::Directory => {
                let index = self.dirs.len();
                self.dirs.push(ModelDir {
                    parent: None,
                    entries: Vec::new(),
                    times: EntryTimes::default(),
                    run: ClusterRun::default(),
                });
                self.names.push(DirNames::new());
                self.folded.push(HashMap::new());
                self.dir_of.insert(key.to_vec(), index);
                Ok(Some(Node::Dir(index)))
            }
            EntryKind::File(content) => {
                let Some(Class::File { content: at, size }) = self.classes.get(key).cloned() else {
                    unreachable!("a file was classified as something else")
                };
                // The classifying pass and this one index the same list, and a drift between
                // them would give a file another file's bytes — an image that reads
                // perfectly and holds the wrong contents. One comparison, in every build.
                assert_eq!(at, self.contents.len(), "the two passes fell out of step");
                self.contents.push(content);
                Ok(Some(Node::File {
                    content: at,
                    size,
                    run: ClusterRun::default(),
                }))
            }
            // A second name for a file, in a format that has no second name for one. The
            // target is named inside this source, so resolving it reads nothing this crate
            // was not already given, and the file is one FAT holds perfectly well — so the
            // bytes are written again rather than the entry being lost.
            EntryKind::HardLink { target } => match self.resolve_link(&target, path)? {
                Some((content, size)) => {
                    self.lose(Property::Kind, path)?;
                    Ok(Some(Node::File {
                        content,
                        size,
                        run: ClusterRun::default(),
                    }))
                }
                // The target was itself something the format cannot hold, so there is
                // nothing left to be a second name for.
                None => {
                    self.lose(Property::Kind, path)?;
                    Ok(None)
                }
            },
            // A symbolic link is never followed. Its target is an arbitrary path rather than
            // something this source named, so resolving one would copy whatever it happens to
            // point at into the image — a link to `/etc/shadow` in a root filesystem would
            // produce an image holding `/etc/shadow`. Everything below is the same: there is
            // nothing to resolve and nothing to copy.
            _ => {
                self.lose(Property::Kind, path)?;
                Ok(None)
            }
        }
    }

    /// The file a hard link is a second name for, or `None` where what it names is itself
    /// something the format cannot hold.
    fn resolve_link(&self, target: &[u8], path: &[u8]) -> Result<Option<(usize, u32)>, ModelError> {
        match follow_hard_link(target, self.classes.len(), |key| {
            match self.classes.get(key) {
                Some(Class::File { content, size }) => LinkStep::File((*content, *size)),
                Some(Class::Dir) => LinkStep::Directory,
                Some(Class::Unrepresentable) => LinkStep::Unrepresentable,
                Some(Class::Link(next)) => LinkStep::Link(next.clone()),
                None => LinkStep::Missing,
            }
        }) {
            LinkEnd::File(found) => Ok(Some(found)),
            LinkEnd::Unrepresentable => Ok(None),
            LinkEnd::Directory => Err(ModelError::HardlinkTargetIsDirectory {
                path: path.to_vec(),
                target: target.to_vec(),
            }),
            LinkEnd::Missing => Err(ModelError::HardlinkTargetMissing {
                path: path.to_vec(),
                target: target.to_vec(),
            }),
            LinkEnd::Cycle => Err(ModelError::HardlinkCycle {
                path: path.to_vec(),
            }),
        }
    }

    /// Give `name` a short name no other entry in `parent` holds, refusing a pair no driver
    /// would tell apart.
    fn name_in(
        &mut self,
        parent: usize,
        name: &[u8],
        path: &[u8],
    ) -> Result<PlacedName, ModelError> {
        // The case-insensitive check comes first, so a colliding pair is reported as the
        // ambiguity it is rather than as two entries that happened to need different tails.
        if let Some(key) = folded(name) {
            if let Some(other) = self.folded[parent].get(&key) {
                return Err(ModelError::Indistinguishable {
                    path: path.to_vec(),
                    other: other.clone(),
                });
            }
            self.folded[parent].insert(key, path.to_vec());
        }
        let placed = self.names[parent]
            .place(name)
            .map_err(|source| ModelError::Name {
                path: path.to_vec(),
                source,
            })?;

        // A derived short name is a name in the directory too, and every driver that reads
        // the volume matches a lookup against *either* namespace. So one directory holding
        // `A Long File Name.txt` and `ALONGFIL.TXT` is ambiguous even though neither name
        // collides with the other in its own namespace: the first takes the plain short name
        // `ALONGFIL.TXT`, and opening that name returns whichever entry the driver reaches
        // first while the other is unreachable by its own name.
        //
        // Real Windows cannot reach this state, because creating a file goes through a
        // lookup that would have found the first entry. A formatter writing a directory
        // wholesale has no such lookup, so it does the cross-namespace check itself. Only
        // where the rendered short name differs from the name it was derived from: where the
        // two are the same, the check above already made it.
        let rendered = crate::fat::name::render(&placed.short);
        if let Some(key) = folded(rendered.as_bytes())
            && folded(name).as_deref() != Some(key.as_str())
        {
            if let Some(other) = self.folded[parent].get(&key) {
                return Err(ModelError::Indistinguishable {
                    path: path.to_vec(),
                    other: other.clone(),
                });
            }
            self.folded[parent].insert(key, path.to_vec());
        }
        Ok(placed)
    }

    /// The times this entry records, refusing an instant the fields cannot hold.
    ///
    /// The creation time is derived from the modification time, as no source carries a birth
    /// time and reading the clock would make two formats of one tree differ.
    fn times_for(&mut self, meta: &Metadata, path: &[u8]) -> Result<EntryTimes, ModelError> {
        let write = self.encode(meta.mtime, TimeField::Modification, path)?;
        let access = self.encode(meta.atime, TimeField::Access, path)?;
        // The write field counts seconds in twos and has no hundredths of its own — the
        // creation field has the only one — so an odd second is where a modification time
        // stops surviving. It is recorded and never refuses: a build can avoid it by naming
        // an even second, so the count is worth having, and a refusal would fire on half of
        // all trees over two seconds.
        //
        // The access field is a *date*. No build keeps a time of day in it, so there is
        // nothing a caller could act on and nothing to record per entry; that the format
        // stores an access date rather than an access time is said here once instead.
        if meta.mtime.secs % 2 != 0 || meta.mtime.nanos != 0 {
            self.fidelity
                .record(Direction::Dropped, path, Property::TimePrecision);
        }
        Ok(EntryTimes {
            create: write,
            write,
            access_date: access.date,
        })
    }

    /// `time` in the form the entry stores it, or the refusal its range earns.
    fn encode(
        &self,
        time: Timestamp,
        field: TimeField,
        path: &[u8],
    ) -> Result<DosTimestamp, ModelError> {
        DosTimestamp::encode(time).ok_or_else(|| ModelError::TimeOutOfRange {
            path: path.to_vec(),
            field,
            secs: time.secs,
            min: DosTimestamp::SECS_MIN,
            max: DosTimestamp::SECS_MAX,
        })
    }

    /// Record every property of this entry the format cannot carry, refusing each the caller
    /// has not accepted.
    ///
    /// The accounting itself is shared: this family and the one it shares a name with lose the
    /// same six things for the same reason, so there is one answer and each wraps its refusal
    /// in its own wording.
    fn record_losses(
        &mut self,
        meta: &Metadata,
        xattrs: &[crate::xattr::Xattr],
        is_dir: bool,
        path: &[u8],
    ) -> Result<(), ModelError> {
        self.config
            .loss
            .record_losses(&mut self.fidelity, meta, xattrs, is_dir, path)
            .map_err(|property| ModelError::LossNotAccepted {
                path: path.to_vec(),
                property,
            })
    }

    /// Record a loss the entry's metadata does not decide — a kind the format has no
    /// representation for — after checking the caller accepted it.
    fn lose(&mut self, property: Property, path: &[u8]) -> Result<(), ModelError> {
        if !self.config.loss.accepts(property) {
            return Err(ModelError::LossNotAccepted {
                path: path.to_vec(),
                property,
            });
        }
        self.fidelity.record(Direction::Dropped, path, property);
        Ok(())
    }
}

/// A tree with everything decided but its size: what a search over candidate volumes holds
/// once and re-allocates against each one.
///
/// Nothing here knows how large a volume is. [`allocate`](Self::allocate) is what applies a
/// geometry, and it is total — it assigns every run in one ascending pass — so a run that
/// failed against one layout leaves nothing behind to disturb the next.
#[derive(Debug)]
pub(crate) struct PlacedTree {
    dirs: Vec<ModelDir>,
    contents: Vec<FileContent>,
    fidelity: FidelityReport,
}

impl PlacedTree {
    /// Give the tree a geometry: refuse a root region too small for it, then hand out every
    /// cluster, and report what it occupies.
    ///
    /// Runs against as many layouts as a caller likes, and a successful run overwrites every
    /// run in the same ascending order, so nothing survives from the attempt before it.
    ///
    /// A *failed* run leaves the tree partly allocated against the layout that failed, and no
    /// caller may read the runs in that state — a run set at mixed cluster sizes describes no
    /// volume at all. The runs mean something again only after a run that returned `Ok`, so
    /// whoever searches over layouts allocates the one it settles on last.
    pub(crate) fn allocate(
        &mut self,
        layout: &FatLayout,
        config: &ModelConfig,
    ) -> Result<(u32, u32), ModelError> {
        self.check_root_capacity(layout, config)?;
        self.allocate_clusters(layout, config)
    }

    /// A count of sectors no volume holding this tree can be below.
    ///
    /// Each file's bytes rounded up to whole sectors, plus one sector for each directory.
    /// It understates on purpose — the real cost adds a table, a reserved region, and a
    /// cluster's rounding per file — because a floor's only job is to be a size the answer
    /// cannot be beneath, and every sector it saves is a probe not spent.
    pub(crate) fn content_sectors(&self, bytes_per_sector: u64) -> u64 {
        let mut total = 0u64;
        for dir in &self.dirs {
            total = total.saturating_add(1);
            for entry in &dir.entries {
                if let Node::File { size, .. } = entry.node {
                    total = total.saturating_add(u64::from(size).div_ceil(bytes_per_sector));
                }
            }
        }
        total
    }

    /// Turn this into the finished model, at the geometry it was last allocated against.
    pub(crate) fn finish(self, used_clusters: u32, next_free: u32) -> FatModel {
        FatModel {
            dirs: self.dirs,
            contents: self.contents,
            fidelity: self.fidelity,
            used_clusters,
            next_free,
        }
    }

    /// Refuse a root directory the planned region cannot hold.
    ///
    /// FAT32's root is an ordinary chain and grows, so this is a FAT12 and FAT16 question
    /// alone.
    fn check_root_capacity(
        &self,
        layout: &FatLayout,
        config: &ModelConfig,
    ) -> Result<(), ModelError> {
        if layout.root_entries == 0 {
            return Ok(());
        }
        let needed = self.dirs[ROOT_DIR].slots(ROOT_DIR, config.has_label);
        if needed > u64::from(layout.root_entries) {
            return Err(ModelError::RootDirectoryFull {
                // The count is what the tree needs, so it is reported whole rather than
                // saturated at the capacity it just exceeded.
                needed: u32::try_from(needed).unwrap_or(u32::MAX),
                capacity: layout.root_entries,
            });
        }
        Ok(())
    }

    /// Give every directory and every file the clusters it needs, in one ascending pass.
    ///
    /// Sequential and without gaps, so every chain is contiguous: there is nothing on a fresh
    /// volume to allocate around. The FAT32 root takes the first cluster, which is what its
    /// planned `root_cluster` names.
    fn allocate_clusters(
        &mut self,
        layout: &FatLayout,
        config: &ModelConfig,
    ) -> Result<(u32, u32), ModelError> {
        let per_cluster = u64::from(layout.bytes_per_cluster());
        let available = layout.clusters;
        let mut next: u64 = 2;
        let mut take = |count: u64| -> Result<ClusterRun, ModelError> {
            let first = next;
            next += count;
            // Clusters number from 2, so the highest one a volume has is `clusters + 1`.
            if next > u64::from(available) + 2 {
                return Err(ModelError::VolumeFull {
                    needed: next - 2,
                    available,
                });
            }
            Ok(ClusterRun {
                first: if count == 0 { 0 } else { first as u32 },
                count: count as u32,
            })
        };

        for index in 0..self.dirs.len() {
            // A FAT12 or FAT16 root is a fixed region rather than a chain, so it takes no
            // cluster. Every other directory takes at least one, an empty one included: it
            // still holds `.` and `..`, and a chain has to start somewhere.
            if index != ROOT_DIR || layout.fat32.is_some() {
                let slots = self.dirs[index].slots(index, config.has_label);
                let bytes = slots * DIR_ENTRY_SIZE as u64;
                self.dirs[index].run = take(bytes.div_ceil(per_cluster).max(1))?;
            }
            // The entries of this directory, in the order they will be written, so a file's
            // clusters follow the directory that names it.
            for at in 0..self.dirs[index].entries.len() {
                if let Node::File { size, .. } = self.dirs[index].entries[at].node {
                    let run = take(u64::from(size).div_ceil(per_cluster))?;
                    if let Node::File { run: slot, .. } = &mut self.dirs[index].entries[at].node {
                        *slot = run;
                    }
                }
            }
        }
        // Every directory but the root records its parent, which is what the `..` entry
        // points at. It is filled in here rather than at creation because a directory is
        // created before the entry naming it is pushed.
        for index in 0..self.dirs.len() {
            for at in 0..self.dirs[index].entries.len() {
                if let Node::Dir(child) = self.dirs[index].entries[at].node {
                    self.dirs[child].parent = Some(index);
                }
            }
        }
        let used = (next - 2) as u32;
        Ok((used, next as u32))
    }
}

impl FatModel {
    /// The last cluster of every chain, ascending.
    ///
    /// The table is what a chain *is*, and every entry in it says the next cluster except at
    /// a chain's end. Allocation runs in one ascending pass with no gaps, so the clusters
    /// from 2 up to [`next_free`](Self::next_free) are exactly the allocated ones and these
    /// are where the counting stops and an end-of-chain mark goes — which is all a writer
    /// needs to lay the table down a batch at a time rather than holding one.
    pub fn chain_ends(&self) -> Vec<u32> {
        let mut ends = Vec::new();
        let mut push = |run: ClusterRun| {
            if !run.is_empty() {
                ends.push(run.first + run.count - 1);
            }
        };
        // The same walk `allocate` made, so the result is ascending by construction rather
        // than by a sort that could disagree with the order the clusters were handed out in.
        for dir in &self.dirs {
            push(dir.run);
            for entry in &dir.entries {
                if let Node::File { run, .. } = entry.node {
                    push(run);
                }
            }
        }
        // The table writer answers "does a chain end here?" with a binary search, which is
        // only an answer at all while this is ascending. Held in every build: an unordered
        // list gives wrong answers rather than no answer, and a chain that stops early or
        // runs on is a file the volume reads back short or long.
        assert!(
            ends.windows(2).all(|w| w[0] < w[1]),
            "the chain ends are not ascending, so allocation and this walk disagree"
        );
        ends
    }

    /// The cluster a directory entry records for `node`, and its length.
    pub fn entry_target(&self, node: Node) -> (u32, u32) {
        match node {
            Node::Dir(index) => (self.dirs[index].run.first, 0),
            // A file with no bytes owns no cluster, and the format says so with a zero.
            Node::File { size, run, .. } => (if run.is_empty() { 0 } else { run.first }, size),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::geometry::{FatTypeRequest, PlanRequest, plan_layout};
    use crate::fidelity::{AcceptedLoss, Synthesis};
    use crate::source::{Source, TreeBuilder};

    /// An even second inside the format's range, so nothing under test is also exercising a
    /// rounding.
    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn meta(mode: u16) -> Metadata {
        Metadata::new(mode, TIME)
    }

    fn layout() -> FatLayout {
        plan_layout(&PlanRequest::new(64 << 20)).expect("plan")
    }

    fn config(accepted: AcceptedLoss) -> ModelConfig {
        ModelConfig {
            loss: LossPolicy {
                accepted,
                synthesis: Synthesis::new(),
            },
            has_label: false,
        }
    }

    /// Build a model of `source` against a 64 MiB volume, accepting `accepted`.
    fn model_of(source: impl Source, accepted: AcceptedLoss) -> Result<FatModel, ModelError> {
        build_model(source.into_entries(), &layout(), &config(accepted))
    }

    /// A small tree with a directory, a nested one, and files of a few sizes.
    fn tree() -> TreeBuilder {
        TreeBuilder::new()
            .directory(b"/etc".to_vec(), meta(0o755))
            .file(
                b"/etc/hostname".to_vec(),
                b"ferrosys\n".to_vec(),
                meta(0o644),
            )
            .directory(b"/etc/conf.d".to_vec(), meta(0o755))
            .file(b"/etc/conf.d/net".to_vec(), vec![b'x'; 9000], meta(0o644))
            .file(b"/big".to_vec(), vec![0xAB; 70_000], meta(0o644))
    }

    #[test]
    fn re_allocating_a_placed_tree_at_two_layouts_matches_two_fresh_builds() {
        // The split's whole claim: what a probe re-runs is a function of the layout alone,
        // so a tree placed once and allocated against N volumes says what N fresh builds
        // would have said. Anything the placing pass leaked into the allocation would show
        // up here as a second answer.
        let cfg = config(AcceptedLoss::ALL);
        let small = plan_layout(&PlanRequest::new(16 << 20)).expect("plan 16 MiB");
        let large = plan_layout(&PlanRequest::new(64 << 20)).expect("plan 64 MiB");

        let mut placed = Builder::new(&cfg)
            .place_all(tree().into_entries())
            .expect("place");

        for layout in [&small, &large] {
            let (used, next) = placed.allocate(layout, &cfg).expect("allocate");
            let fresh = build_model(tree().into_entries(), layout, &cfg).expect("fresh build");
            assert_eq!(used, fresh.used_clusters);
            assert_eq!(next, fresh.next_free);
            assert_eq!(format!("{:?}", placed.dirs), format!("{:?}", fresh.dirs));
        }
    }

    #[test]
    fn a_failed_allocation_leaves_the_tree_re_allocatable() {
        // A search spends most of its probes below the answer, so the state a refusal leaves
        // behind is the state every later probe starts from. Allocation overwrites every run
        // in the same order each time, which is what makes that safe rather than lucky.
        let cfg = config(AcceptedLoss::ALL);
        let mut placed = Builder::new(&cfg)
            .place_all(tree().into_entries())
            .expect("place");

        let tiny = plan_layout(&PlanRequest::new(64 << 10)).expect("plan 64 KiB");
        assert!(
            matches!(
                placed.allocate(&tiny, &cfg),
                Err(ModelError::VolumeFull { .. })
            ),
            "the tree does not fit a 64 KiB volume"
        );

        let large = plan_layout(&PlanRequest::new(64 << 20)).expect("plan 64 MiB");
        let (used, next) = placed
            .allocate(&large, &cfg)
            .expect("the tree allocates after a refusal");
        let fresh = build_model(tree().into_entries(), &large, &cfg).expect("fresh build");
        assert_eq!((used, next), (fresh.used_clusters, fresh.next_free));
        assert_eq!(format!("{:?}", placed.dirs), format!("{:?}", fresh.dirs));
    }

    /// The names of a directory's entries, as text.
    fn names(dir: &ModelDir) -> Vec<String> {
        dir.entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name.short).into_owned())
            .collect()
    }

    #[test]
    fn a_root_owned_tree_with_conventional_modes_is_carried_whole() {
        // The claim the recoverable-value rule rests on: an ESP tree needs no
        // acknowledgement, and the report saying it lost nothing is true rather than
        // vacuous.
        let source = TreeBuilder::new()
            .directory(b"/EFI".to_vec(), meta(0o755))
            .directory(b"/EFI/BOOT".to_vec(), meta(0o755))
            .file(b"/EFI/BOOT/BOOTX64.EFI".to_vec(), b"MZ", meta(0o644));
        let model = model_of(source, AcceptedLoss::NONE).expect("a faithful tree");
        assert!(model.fidelity.is_faithful());
        assert_eq!(model.dirs.len(), 3);
        assert_eq!(names(&model.dirs[0]), ["EFI        "]);
        // A read-only file is carried too, because the attribute is the one bit of a mode
        // the format holds.
        let source = TreeBuilder::new().file(b"/RO.TXT".to_vec(), b"x", meta(0o444));
        let model = model_of(source, AcceptedLoss::NONE).expect("read-only is carried");
        assert!(model.fidelity.is_faithful());
        assert!(
            model.dirs[0].entries[0]
                .attributes
                .contains(Attributes::READ_ONLY)
        );
    }

    #[test]
    fn a_property_the_format_cannot_carry_refuses_until_it_is_accepted() {
        // One case per property, each refused on its own and each accepted on its own — the
        // whole reason the acknowledgement names properties rather than being one switch.
        let cases: Vec<(&str, Property, TreeBuilder)> = vec![
            (
                "an owner",
                Property::Ownership,
                TreeBuilder::new().file(b"/f".to_vec(), b"x", meta(0o644).owned_by(1000, 1000)),
            ),
            (
                "an executable bit",
                Property::Permissions,
                TreeBuilder::new().file(b"/f".to_vec(), b"x", meta(0o755)),
            ),
            (
                // The permission bits are the recoverable ones, so this entry loses the
                // set-user-id bit and nothing else — which is what makes it a case for
                // `SpecialBits` alone rather than for both.
                "a setuid bit",
                Property::SpecialBits,
                TreeBuilder::new().file(b"/f".to_vec(), b"x", meta(0o4644)),
            ),
            (
                "a symbolic link",
                Property::Kind,
                TreeBuilder::new().symlink(b"/f".to_vec(), b"/t".to_vec(), meta(0o777)),
            ),
            (
                "an extended attribute",
                Property::ExtendedAttributes,
                TreeBuilder::new()
                    .file(b"/f".to_vec(), b"x", meta(0o644))
                    .xattr(b"user.note".to_vec(), b"v".to_vec()),
            ),
            (
                "a change time",
                Property::ChangeTime,
                TreeBuilder::new().file(
                    b"/f".to_vec(),
                    b"x",
                    meta(0o644).with_times(TIME, Timestamp::from_secs(TIME.secs + 100), TIME),
                ),
            ),
        ];
        for (what, property, source) in cases {
            let refused = model_of(source.clone(), AcceptedLoss::NONE);
            assert!(
                matches!(refused, Err(ModelError::LossNotAccepted { property: p, .. }) if p == property),
                "{what} was not refused: {refused:?}"
            );
            // Accepting a different property does not accept this one.
            let other = if property == Property::Ownership {
                Property::Permissions
            } else {
                Property::Ownership
            };
            assert!(
                model_of(source.clone(), AcceptedLoss::NONE.and(other)).is_err(),
                "{what} was accepted by an unrelated property"
            );
            // And accepting it lets the build through, with the loss counted.
            let model = model_of(source, AcceptedLoss::NONE.and(property))
                .unwrap_or_else(|e| panic!("{what} was still refused: {e}"));
            assert_eq!(
                model.fidelity.count(Direction::Dropped, property),
                1,
                "{what}"
            );
        }
    }

    #[test]
    fn a_rounded_time_is_recorded_and_never_refuses() {
        // The one property outside the acknowledgement, and the reason: every timestamp the
        // format holds is coarser than the source's, so a refusal here would fire on nearly
        // every tree and could not be avoided by changing one.
        let odd = Timestamp::from_secs(TIME.secs + 1);
        let source = TreeBuilder::new().file(b"/f".to_vec(), b"x", Metadata::new(0o644, odd));
        let model = model_of(source, AcceptedLoss::NONE).expect("precision never refuses");
        assert_eq!(
            model
                .fidelity
                .count(Direction::Dropped, Property::TimePrecision),
            1
        );
        assert!(!model.fidelity.is_faithful(), "the loss is still reported");

        // The access field is a date, and no build keeps a time of day in one — so an odd
        // access second is not a per-entry record. What the format stores there is stated
        // once, in the documentation, rather than counted on every entry forever.
        let source = TreeBuilder::new().file(
            b"/f".to_vec(),
            b"x",
            meta(0o644).with_times(odd, TIME, TIME),
        );
        let model = model_of(source, AcceptedLoss::NONE).expect("build");
        assert!(model.fidelity.is_faithful());
        // And the date it does keep is the access time's own, not the modification time's.
        let times = model.dirs[0].entries[0].times;
        assert_eq!(
            times.access_date,
            DosTimestamp::encode(odd).expect("in range").date
        );
        assert_eq!(times.write, DosTimestamp::encode(TIME).expect("in range"));
    }

    #[test]
    fn a_hard_link_is_copied_and_a_symbolic_link_is_not_followed() {
        // The asymmetry, and it is a security property: a hard link names something inside
        // this source, and a symbolic link names an arbitrary path on the host.
        let source = TreeBuilder::new()
            .file(b"/bin".to_vec(), b"payload", meta(0o644))
            .hardlink(b"/also".to_vec(), b"/bin".to_vec(), meta(0o644))
            .symlink(b"/link".to_vec(), b"/etc/shadow".to_vec(), meta(0o777));
        let model = model_of(source, AcceptedLoss::NONE.and(Property::Kind)).expect("build");

        // Two entries, not three: the symbolic link left nothing behind.
        assert_eq!(model.dirs[0].entries.len(), 2);
        assert_eq!(names(&model.dirs[0]), ["ALSO       ", "BIN        "]);
        // Both name one content and neither shares a cluster with the other, which is what
        // makes the copy a copy rather than a cross-linked chain.
        let runs: Vec<(usize, ClusterRun)> = model.dirs[0]
            .entries
            .iter()
            .map(|e| match e.node {
                Node::File { content, run, .. } => (content, run),
                Node::Dir(_) => panic!("a file was modelled as a directory"),
            })
            .collect();
        assert_eq!(runs[0].0, runs[1].0, "one content, named twice");
        assert_ne!(runs[0].1.first, runs[1].1.first, "and two chains");
        assert_eq!(model.fidelity.count(Direction::Dropped, Property::Kind), 2);
    }

    #[test]
    fn every_kind_the_format_has_no_field_for_leaves_nothing_behind() {
        let source = TreeBuilder::new()
            .char_device(b"/null".to_vec(), 1, 3, meta(0o666))
            .block_device(b"/sda".to_vec(), 8, 0, meta(0o660))
            .fifo(b"/pipe".to_vec(), meta(0o644))
            .socket(b"/sock".to_vec(), meta(0o644))
            .symlink(b"/link".to_vec(), b"/t".to_vec(), meta(0o777));
        let model = model_of(source, AcceptedLoss::ALL).expect("build");
        assert!(model.dirs[0].entries.is_empty());
        assert_eq!(model.fidelity.count(Direction::Dropped, Property::Kind), 5);
        // The dropped entries record their kind and nothing else: an entry that is not there
        // did not also lose its owner.
        assert_eq!(model.fidelity.summary().len(), 1);
    }

    #[test]
    fn a_hard_link_to_something_that_was_itself_dropped_is_dropped_too() {
        // There is nothing left to be a second name for, and inventing one would be worse
        // than losing it.
        let source = TreeBuilder::new()
            .symlink(b"/link".to_vec(), b"/t".to_vec(), meta(0o777))
            .hardlink(b"/also".to_vec(), b"/link".to_vec(), meta(0o644));
        let model = model_of(source, AcceptedLoss::ALL).expect("build");
        assert!(model.dirs[0].entries.is_empty());
        assert_eq!(model.fidelity.count(Direction::Dropped, Property::Kind), 2);
    }

    #[test]
    fn a_hard_link_the_source_never_declared_is_a_refusal_rather_than_a_loss() {
        let source = TreeBuilder::new().hardlink(b"/a".to_vec(), b"/nowhere".to_vec(), meta(0o644));
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::HardlinkTargetMissing { .. })
        ));
        let source = TreeBuilder::new()
            .directory(b"/d".to_vec(), meta(0o755))
            .hardlink(b"/a".to_vec(), b"/d".to_vec(), meta(0o644));
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::HardlinkTargetIsDirectory { .. })
        ));
    }

    #[test]
    fn two_names_one_driver_cannot_tell_apart_are_refused() {
        // Distinct paths in a POSIX tree, one name to every FAT driver — so a directory
        // holding both is one a lookup cannot choose in.
        let source = TreeBuilder::new()
            .file(b"/readme.txt".to_vec(), b"a", meta(0o644))
            .file(b"/README.TXT".to_vec(), b"b", meta(0o644));
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::Indistinguishable { .. })
        ));
        // In different directories they are different names, and both are placed.
        let source = TreeBuilder::new()
            .directory(b"/d".to_vec(), meta(0o755))
            .file(b"/readme.txt".to_vec(), b"a", meta(0o644))
            .file(b"/d/README.TXT".to_vec(), b"b", meta(0o644));
        assert!(model_of(source, AcceptedLoss::NONE).is_ok());
    }

    #[test]
    fn a_derived_short_name_that_is_another_entrys_name_is_refused() {
        // The ambiguity across the two namespaces rather than within one. Neither name
        // collides with the other as given: one is long and one is 8.3. But the long one is
        // *shortened* to exactly the other, and every driver — Linux vfat and Windows both —
        // matches a lookup against either namespace. Sorted order places the long name
        // first, so it takes the plain short name and the literal file is pushed to a tail:
        // opening `ALONGFIL.TXT` then returns the wrong file's contents, and the right one
        // is unreachable by its own name.
        //
        // Real Windows cannot reach this state, because creating a file goes through a
        // lookup that would have found the first entry. A formatter writing a directory
        // wholesale has no such lookup, so it makes the check itself.
        let source = TreeBuilder::new()
            .file(b"/A Long File Name.txt".to_vec(), b"a", meta(0o644))
            .file(b"/ALONGFIL.TXT".to_vec(), b"b", meta(0o644));
        assert!(
            matches!(
                model_of(source, AcceptedLoss::ALL),
                Err(ModelError::Indistinguishable { .. })
            ),
            "a name reachable two ways is refused"
        );

        // And a long name whose shortening is nobody else's name is placed as it always was:
        // the check refuses an ambiguity, not a tail.
        let source = TreeBuilder::new()
            .file(b"/A Long File Name.txt".to_vec(), b"a", meta(0o644))
            .file(b"/Another Long Name.txt".to_vec(), b"b", meta(0o644));
        assert!(model_of(source, AcceptedLoss::ALL).is_ok());
    }

    #[test]
    fn the_tree_is_placed_in_sorted_order_whatever_order_it_arrives_in() {
        // What makes two formats of one tree identical: the order a source yielded its
        // entries in reaches neither the directory nor the clusters.
        let forwards = TreeBuilder::new()
            .directory(b"/d".to_vec(), meta(0o755))
            .file(b"/d/a".to_vec(), b"a", meta(0o644))
            .file(b"/d/b".to_vec(), b"b", meta(0o644))
            .file(b"/z".to_vec(), b"z", meta(0o644));
        let backwards = TreeBuilder::new()
            .file(b"/z".to_vec(), b"z", meta(0o644))
            .file(b"/d/b".to_vec(), b"b", meta(0o644))
            .file(b"/d/a".to_vec(), b"a", meta(0o644))
            .directory(b"/d".to_vec(), meta(0o755));
        let one = model_of(forwards, AcceptedLoss::NONE).expect("build");
        let two = model_of(backwards, AcceptedLoss::NONE).expect("build");
        assert_eq!(one.dirs, two.dirs);
        assert_eq!(names(&one.dirs[0]), ["D          ", "Z          "]);
        assert_eq!(names(&one.dirs[1]), ["A          ", "B          "]);
    }

    #[test]
    fn a_malformed_tree_is_refused_by_shape() {
        let cases: Vec<(&str, TreeBuilder)> = vec![
            (
                "a missing parent",
                TreeBuilder::new().file(b"/d/f".to_vec(), b"x", meta(0o644)),
            ),
            (
                "a parent that is a file",
                TreeBuilder::new()
                    .file(b"/d".to_vec(), b"x", meta(0o644))
                    .file(b"/d/f".to_vec(), b"x", meta(0o644)),
            ),
            (
                "a duplicate path",
                TreeBuilder::new()
                    .file(b"/f".to_vec(), b"a", meta(0o644))
                    .file(b"//f".to_vec(), b"b", meta(0o644)),
            ),
            (
                "a traversal",
                TreeBuilder::new().file(b"/d/../f".to_vec(), b"x", meta(0o644)),
            ),
        ];
        for (what, source) in cases {
            assert!(
                model_of(source, AcceptedLoss::ALL).is_err(),
                "{what} was accepted"
            );
        }
    }

    #[test]
    fn the_root_is_a_directory_and_its_metadata_is_not_a_loss() {
        // The format records no owner, mode, or time for the root on any volume, so a source
        // that describes it describes something already true — there is no input that would
        // make it survive and so nothing a report could tell a caller to do.
        let source = TreeBuilder::new()
            .root(meta(0o700).owned_by(1000, 1000))
            .file(b"/f".to_vec(), b"x", meta(0o644));
        let model = model_of(source, AcceptedLoss::NONE).expect("the root is accepted");
        assert!(model.fidelity.is_faithful());
        assert_eq!(model.dirs[0].entries.len(), 1);

        // Something that is not a directory at the root is still refused, because it would
        // describe a filesystem that cannot exist.
        let source = TreeBuilder::new().file(b"/".to_vec(), b"x", meta(0o644));
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::RootNotDirectory { .. })
        ));
    }

    #[test]
    fn a_time_outside_the_format_is_refused_rather_than_wrapped() {
        // A year that overflowed the field's seven bits would land in the 1980s and look
        // entirely plausible, which is the one failure a report cannot make safe.
        let source = TreeBuilder::new().file(
            b"/f".to_vec(),
            b"x",
            Metadata::new(0o644, Timestamp::from_secs(0)),
        );
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::TimeOutOfRange {
                field: TimeField::Modification,
                secs: 0,
                ..
            })
        ));
        // The access time is refused by the same rule and names itself.
        let source = TreeBuilder::new().file(
            b"/f".to_vec(),
            b"x",
            meta(0o644).with_times(Timestamp::from_secs(0), TIME, TIME),
        );
        assert!(matches!(
            model_of(source, AcceptedLoss::ALL),
            Err(ModelError::TimeOutOfRange {
                field: TimeField::Access,
                ..
            })
        ));
    }

    #[test]
    fn clusters_are_handed_out_in_one_ascending_pass_and_every_chain_is_contiguous() {
        // A fresh volume has nothing to allocate around, so a chain is a first cluster and a
        // count — which is what keeps the model's memory a function of the entry count.
        let bytes = layout().bytes_per_cluster() as usize;
        let source = TreeBuilder::new()
            .file(b"/big".to_vec(), vec![7u8; bytes * 3 + 1], meta(0o644))
            .file(b"/empty".to_vec(), Vec::new(), meta(0o644))
            .directory(b"/d".to_vec(), meta(0o755));
        let model = model_of(source, AcceptedLoss::NONE).expect("build");

        // A FAT16 root is a fixed region, so the first cluster goes to the first file.
        assert!(model.dirs[0].run.is_empty());
        let entries = &model.dirs[0].entries;
        assert_eq!(
            names(&model.dirs[0]),
            ["BIG        ", "D          ", "EMPTY      "]
        );
        let Node::File { run, .. } = entries[0].node else {
            panic!("BIG is a file")
        };
        assert_eq!(run, ClusterRun { first: 2, count: 4 });
        // The subdirectory follows it, and an empty file owns nothing at all.
        assert_eq!(model.dirs[1].run, ClusterRun { first: 6, count: 1 });
        assert_eq!(model.entry_target(entries[2].node), (0, 0));
        assert_eq!(model.used_clusters, 5);
        assert_eq!(model.next_free, 7);
    }

    #[test]
    fn a_fat32_root_takes_the_cluster_its_layout_names() {
        let layout = plan_layout(
            &PlanRequest::new(512 << 20)
                .fat_type(FatTypeRequest::Exactly(super::super::FatType::Fat32)),
        )
        .expect("plan");
        let source = TreeBuilder::new().file(b"/f".to_vec(), b"x", meta(0o644));
        let model = build_model(source.into_entries(), &layout, &config(AcceptedLoss::NONE))
            .expect("build");
        assert_eq!(
            model.dirs[0].run.first,
            layout.fat32.expect("fat32").root_cluster
        );
        assert_eq!(model.dirs[0].run.count, 1);
    }

    #[test]
    fn a_tree_larger_than_the_volume_is_refused_before_anything_is_written() {
        let layout = plan_layout(&PlanRequest::new(1 << 20)).expect("plan");
        let bytes = layout.bytes_per_cluster() as usize;
        let source = TreeBuilder::new().file(
            b"/f".to_vec(),
            vec![0u8; bytes * (layout.clusters as usize + 1)],
            meta(0o644),
        );
        assert!(matches!(
            build_model(source.into_entries(), &layout, &config(AcceptedLoss::NONE)),
            Err(ModelError::VolumeFull { .. })
        ));
    }

    #[test]
    fn a_root_region_the_tree_overflows_is_refused_and_names_the_counts() {
        // FAT12 and FAT16 fix the root's capacity when the volume is planned, and a long
        // name costs an entry per thirteen characters on top of the one it names — which is
        // what usually fills it.
        let layout = plan_layout(
            &PlanRequest::new(64 << 20).root_entries(super::super::RootEntries::Count(16)),
        )
        .expect("plan");
        // Read the capacity back rather than assuming it: the region is rounded up to a
        // cluster boundary, so what a volume ends up with is the planner's answer and not
        // the count that was asked for. One file per entry then needs twice the room, since
        // each takes a long-name entry as well as its own.
        let capacity = layout.root_entries;
        let mut source = TreeBuilder::new();
        for i in 0..capacity {
            source = source.file(format!("/file{i}").into_bytes(), b"x", meta(0o644));
        }
        let err = build_model(source.into_entries(), &layout, &config(AcceptedLoss::NONE))
            .expect_err("the region is too small");
        assert!(
            matches!(err, ModelError::RootDirectoryFull { needed, capacity: c }
                if needed == capacity * 2 && c == capacity),
            "{err:?}"
        );
        // A subdirectory has no such limit, and the same files fit in one.
        let mut source = TreeBuilder::new().directory(b"/d".to_vec(), meta(0o755));
        for i in 0..capacity {
            source = source.file(format!("/d/file{i}").into_bytes(), b"x", meta(0o644));
        }
        assert!(build_model(source.into_entries(), &layout, &config(AcceptedLoss::NONE)).is_ok());
    }

    #[test]
    fn an_empty_source_models_an_empty_volume() {
        let model = model_of(TreeBuilder::new(), AcceptedLoss::NONE).expect("build");
        assert_eq!(model.dirs.len(), 1);
        assert!(model.dirs[0].entries.is_empty());
        assert!(model.fidelity.is_faithful());
        // A FAT16 root is a fixed region, so an empty tree takes no cluster at all.
        assert_eq!(model.used_clusters, 0);
        assert_eq!(model.next_free, 2);
        assert!(model.chain_ends().is_empty());
    }

    #[test]
    fn the_report_names_every_entry_and_exactly_what_it_lost() {
        // The whole of the accounting, over one tree that loses something of every kind:
        // per entry, per property, and nothing recorded for the entries that lost nothing.
        let other = TIME.secs + 100;
        let source = TreeBuilder::new()
            // Carried whole: root-owned, conventionally moded, an even second.
            .file(b"/plain".to_vec(), b"x", meta(0o644))
            .directory(b"/d".to_vec(), meta(0o755))
            // One property each, so a record cannot be attributed to the wrong entry.
            .file(b"/owned".to_vec(), b"x", meta(0o644).owned_by(1000, 1000))
            .file(b"/exec".to_vec(), b"x", meta(0o755))
            .file(b"/setuid".to_vec(), b"x", meta(0o4644))
            .file(b"/attrs".to_vec(), b"x", meta(0o644))
            .xattr(b"user.note".to_vec(), b"v".to_vec())
            .file(
                b"/changed".to_vec(),
                b"x",
                meta(0o644).with_times(TIME, Timestamp::from_secs(other), TIME),
            )
            .file(
                b"/odd".to_vec(),
                b"x",
                Metadata::new(0o644, Timestamp::from_secs(TIME.secs + 1)),
            )
            .symlink(b"/link".to_vec(), b"/plain".to_vec(), meta(0o777));
        let model = model_of(source, AcceptedLoss::ALL).expect("build");

        // Entry by entry: the path, and the properties recorded against it, named rather
        // than compared as values so a failure reads as the accounting it is about.
        let mut by_path: Vec<(String, Vec<&str>)> = Vec::new();
        for record in model.fidelity.records() {
            let path = String::from_utf8_lossy(&record.path).into_owned();
            match by_path.iter_mut().find(|(p, _)| *p == path) {
                Some((_, props)) => props.push(record.property.as_str()),
                None => by_path.push((path, vec![record.property.as_str()])),
            }
        }
        by_path.sort();
        assert_eq!(
            by_path,
            vec![
                ("/attrs".to_string(), vec!["extended attributes"]),
                ("/changed".to_string(), vec!["change time"]),
                ("/exec".to_string(), vec!["permissions"]),
                ("/link".to_string(), vec!["kind"]),
                ("/odd".to_string(), vec!["time precision"]),
                ("/owned".to_string(), vec!["ownership"]),
                ("/setuid".to_string(), vec!["special bits"]),
            ],
            "the report does not name exactly the entries that lost something"
        );
        // `/plain` and `/d` lost nothing, so they are not in it at all — which is what makes
        // the report readable on a tree where most entries are fine.
        assert!(!by_path.iter().any(|(p, _)| p == "/plain" || p == "/d"));
        assert!(!model.fidelity.is_truncated());
    }

    #[test]
    fn every_subdirectory_knows_the_directory_that_holds_it() {
        // Which is what the `..` entry points at, and getting it wrong puts a tree's parent
        // links somewhere else on the volume.
        let source = TreeBuilder::new()
            .directory(b"/a".to_vec(), meta(0o755))
            .directory(b"/a/b".to_vec(), meta(0o755))
            .directory(b"/a/b/c".to_vec(), meta(0o755));
        let model = model_of(source, AcceptedLoss::NONE).expect("build");
        assert_eq!(model.dirs[0].parent, None);
        assert_eq!(model.dirs[1].parent, Some(0));
        assert_eq!(model.dirs[2].parent, Some(1));
        assert_eq!(model.dirs[3].parent, Some(2));
    }
}
