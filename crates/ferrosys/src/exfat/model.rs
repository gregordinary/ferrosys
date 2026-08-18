//! The pure model built from a [`Source`](crate::Source) before any byte is written: the
//! directory tree, the name every entry takes, the clusters each one occupies, and the
//! accounting of what the format could not carry.
//!
//! Everything a populated format can fail on happens here, which is what lets a caller find
//! out whether a build will work before the destination is touched. The materializer that
//! consumes a model only writes.
//!
//! # What exFAT records, and what it does not
//!
//! An exFAT directory entry set holds a name of up to 255 UTF-16 code units, five attribute
//! bits, three timestamps with their zone offsets, a first cluster, and two lengths. It has no
//! field for an owner, a group, permission bits, a symbolic link, a second name for a file, a
//! device number, or an extended attribute — so a tree carrying any of those loses something
//! on the way in.
//!
//! A property is **dropped** when the value a reader gets back is not the value the source
//! stated, which is a narrower thing than "the format has no field for it". A tree owned by
//! root with `0644` files and `0755` directories goes into an exFAT image and comes back out
//! of it unchanged, because those are exactly the values [`Synthesis`](crate::Synthesis) hands back for a
//! filesystem that records none — so nothing was lost and the report says so. A file at `0755`
//! did lose something, and so the build refuses until the caller has said it accepts that
//! ([`AcceptedLoss`](crate::AcceptedLoss)).
//!
//! Two things are outside that accounting, each for a stated reason:
//!
//! - **The precision of a time is recorded and never refuses.** Every timestamp the format
//!   holds is coarser than the source's, so a refusal here would fire on nearly every tree and
//!   could not be avoided by changing one — and an acknowledgement that must always be given
//!   is one a caller learns to give blanket, which would accept the losses that do depend on
//!   the tree along with it.
//! - **The root directory's own metadata is ignored, and is not a record.** The format stores
//!   no entry for the root on any volume, so there is no owner, mode, or time of its own to
//!   lose and nothing a caller could act on. A `SourceEntry` naming the root is accepted, and
//!   describes a directory that exists either way.
//!
//! # Reproducibility
//!
//! Entries are sorted by path before anything is placed, so the order of a directory and the
//! cluster every file lands on are functions of the tree rather than of the order a source
//! happened to yield it in. Two models of one tree are the same model.

use std::collections::{BTreeMap, HashMap};

use crate::fidelity::{Direction, FidelityReport, LossPolicy, Property, WRITE_BITS};
use crate::path::canonical_key;
use crate::source::{
    ClassifyError, EntryKind, FileContent, LinkEnd, LinkStep, Metadata, PathFault, SourceEntry,
    classify_paths, follow_hard_link,
};
use crate::time::{DosTimestamp, Timestamp};

use super::geometry::{ExfatLayout, FIRST_CLUSTER};
use super::name::{NameError, PlacedName, place};
use super::ondisk::{DIR_ENTRY_SIZE, FileAttributes, UpcaseTable};

/// The largest a directory may be, which the format states as a bound on the `DataLength` of
/// a directory rather than as a count of entries.
///
/// It is the one capacity limit exFAT puts on a tree's *shape*. A file has none of its own —
/// the length field is 64 bits wide, so what bounds a file is the volume.
pub const MAX_DIRECTORY_BYTES: u64 = 256 << 20;

/// Directory entries the largest directory holds.
pub const MAX_DIRECTORY_ENTRIES: u64 = MAX_DIRECTORY_BYTES / DIR_ENTRY_SIZE as u64;

/// Entries a format writes into the root directory ahead of anything a source names: the
/// volume label, the reserved volume GUID slot, the allocation bitmap's describing entry, and
/// the up-case table's.
///
/// All four are written on every volume, an unnamed one included — the label entry carries a
/// character count of zero rather than being omitted — so this is a constant rather than
/// something the options decide.
pub(crate) const ROOT_LEADING_SLOTS: u32 = 4;

/// Which entry of [`ExfatModel::dirs`] the root directory is.
pub(crate) const ROOT_DIR: usize = 0;

/// Which of an entry's times a range refusal is about, so the message names a field rather
/// than an instant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum TimeField {
    /// The modification time, which the entry records as both its creation and modification
    /// time.
    Modification,
    /// The access time.
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

/// An input an exFAT volume cannot hold.
///
/// A path in a message is rendered rather than repeated: a source path is a byte string that
/// need not be text and may hold anything a terminal acts on. Naming the offending path
/// imperfectly is worth far more than refusing to name it, so an unrepresentable byte becomes
/// U+FFFD and anything a terminal would act on becomes a visible escape.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A name the format cannot represent. Every one of these is a refusal rather than a
    /// recorded loss: a name is what a file is found by, so substituting one would hand back a
    /// tree whose entries are not the entries that were asked for.
    #[error("{}: {source}", crate::escape::printable(.path))]
    #[non_exhaustive]
    Name {
        /// The offending path.
        path: Vec<u8>,
        /// Why the name cannot be stored.
        #[source]
        source: NameError,
    },
    /// A path component was `..`, which a source may not use — a path is where an entry goes,
    /// not a traversal to be resolved.
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
    /// exFAT compares names through the volume's own up-case table, so two names that fold
    /// alike are one name to every driver that reads the volume — a directory holding both is
    /// ambiguous however well-formed each entry is, and a lookup finds whichever it meets
    /// first while the other file is unreachable by its own name.
    #[error(
        "{} and {} fold to one name through this volume's up-case table, which is what every \
         exFAT lookup compares through",
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
    /// An entry naming the root is not a directory. The root is a directory, so an entry that
    /// would place anything else there is rejected rather than ignored.
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
        "{}: a {field} of {secs} seconds past the epoch is outside the {min} to {max} an exFAT \
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
    /// The format cannot carry a property this entry states, and the caller has not said it
    /// accepts losing it.
    ///
    /// Add the property to [`AcceptedLoss`](crate::AcceptedLoss) to build anyway; what was lost then comes back in
    /// the [`FidelityReport`], entry by entry.
    #[error(
        "{}: an exFAT volume cannot carry the {} of this entry",
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
    /// A directory needs more room than the format lets one have.
    ///
    /// The bound is on a directory's length rather than on its entry count, and it is the only
    /// capacity limit exFAT puts on the shape of a tree. Every directory has it, the root
    /// included — unlike its FAT counterpart, exFAT's root is an ordinary chain, so this is not
    /// a limit that a subdirectory escapes.
    #[error(
        "the directory {} needs {needed} bytes of entries and the format holds {limit} in one",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    DirectoryTooLarge {
        /// The directory that could not be laid out.
        path: Vec<u8>,
        /// Bytes of entries the tree puts in it.
        needed: u64,
        /// Bytes the format holds in one directory.
        limit: u64,
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

/// A run of consecutive clusters: everything one entry occupies.
///
/// Every stream this crate writes is contiguous. A formatter builds a fresh filesystem in one
/// pass with nothing to work around, so there is no fragmentation to represent and an
/// allocation is a first cluster and a count rather than a list — which is also what lets every
/// stream declare `NoFatChain`, and what keeps the model's memory a function of the entry count
/// rather than of the volume's size.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct ClusterRun {
    /// The first cluster, or zero where the entry occupies none — an empty file.
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

/// The three times a file entry records, already in the form it stores them.
///
/// exFAT keeps hundredths for two of the three. The access time has no such field, so it is
/// granular to two seconds where the other two are granular to ten milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct EntryTimes {
    /// The creation date, time, and hundredths.
    pub create: DosTimestamp,
    /// The modification date, time, and hundredths.
    pub modify: DosTimestamp,
    /// The access date and time. Its hundredths are dropped: the entry has no field for them.
    pub access: DosTimestamp,
}

/// What an entry points at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Node {
    /// A subdirectory, by index into [`ExfatModel::dirs`].
    Dir(usize),
    /// A regular file.
    File {
        /// Its bytes, by index into [`ExfatModel::contents`]. Two entries share one index
        /// where a hard link was copied.
        content: usize,
        /// Its length, which the stream extension records as both the data length and the
        /// valid data length — a format writes every byte it allocates.
        size: u64,
        /// The clusters it occupies. Each entry has its own, so a copied hard link is two files
        /// rather than two names for cross-linked clusters.
        run: ClusterRun,
    },
}

/// One entry set of a directory, ready to be written.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelEntry {
    /// Its name, and the hash of the folded form.
    pub name: PlacedName,
    /// Its attribute word.
    pub attributes: FileAttributes,
    /// Its times.
    pub times: EntryTimes,
    /// What it points at.
    pub node: Node,
}

/// A directory: what is in it, and where it lives.
///
/// There are no `.` and `..` entries to account for. exFAT records a directory's own times in
/// the entry set naming it, in the directory above, and a parent is reached by the path a
/// caller walked rather than by an entry inside the child.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ModelDir {
    /// Its entries, in the order they are written — sorted by name, which is what makes two
    /// formats of one tree identical.
    pub entries: Vec<ModelEntry>,
    /// The clusters it occupies. Every directory has at least one, an empty one included.
    pub run: ClusterRun,
    /// The path it was declared at, for a message naming a directory that will not fit.
    pub path: Vec<u8>,
}

impl ModelDir {
    /// Bytes of directory entries this directory occupies: every set in it, and whatever the
    /// format writes ahead of them.
    ///
    /// `index` decides the leading entries, and it is a parameter rather than a field because
    /// this is the one place that decides how much room a directory needs. Two callers
    /// computing it separately is how a directory ends up given fewer clusters than it is
    /// written into — which does not show up in the bytes, because the file placed on the
    /// cluster after it is written second and lands on top of the overflow.
    fn bytes(&self, index: usize) -> u64 {
        let leading = if index == ROOT_DIR {
            u64::from(ROOT_LEADING_SLOTS)
        } else {
            0
        };
        let slots = leading
            + self
                .entries
                .iter()
                .map(|e| u64::from(e.name.slots()))
                .sum::<u64>();
        slots * DIR_ENTRY_SIZE as u64
    }
}

/// A tree placed on a volume: every directory, every file's bytes, the clusters they hold, and
/// what the format could not carry.
#[derive(Debug)]
pub(crate) struct ExfatModel {
    /// Every directory, the root at index 0. A parent always has a lower index than its
    /// children, because the entries were sorted by path before any of them was created.
    pub dirs: Vec<ModelDir>,
    /// Every distinct file's bytes. An entry names one by index, and two entries name one where
    /// a hard link was copied.
    pub contents: Vec<FileContent>,
    /// What the format could not carry, and what it stored more coarsely.
    pub fidelity: FidelityReport,
    /// Clusters the volume has in use: the three the format itself put in the heap, and every
    /// one the tree occupies.
    ///
    /// Allocation is one ascending pass with no gaps, so this is also where it stopped — the
    /// first free cluster is `used_clusters + FIRST_CLUSTER`, and there is no on-disk field
    /// recording it. exFAT has no counterpart to FAT's information sector: what is free is the
    /// allocation bitmap's clear bits and nothing else claims to know.
    pub used_clusters: u32,
}

/// Inputs the model needs beyond the source and the geometry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ModelConfig<'a> {
    /// Which losses the caller has accepted, and what a read would invent in their place.
    pub loss: LossPolicy,
    /// The folding this volume's names are compared through, which is the table the volume
    /// carries and not this crate's idea of case.
    pub upcase: &'a UpcaseTable,
}

/// Build the model a `source` and a `layout` imply.
///
/// # Errors
///
/// A [`ModelError`] for anything the volume cannot hold: a name, a shape, a time outside the
/// format's range, a directory larger than the format holds, a tree larger than the volume, or
/// a property the caller has not accepted losing.
pub(crate) fn build_model(
    entries: Vec<SourceEntry>,
    layout: &ExfatLayout,
    config: &ModelConfig<'_>,
) -> Result<ExfatModel, ModelError> {
    let mut placed = Builder::new(config).place_all(entries)?;
    let used_clusters = placed.allocate(layout)?;
    Ok(placed.finish(used_clusters))
}

/// What a path holds, decided before anything is placed.
///
/// A hard link may name a target that sorts *after* it — `/also` before `/bin` — so what every
/// path is has to be known before any of them is turned into an entry. This is that pass's
/// answer.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Class {
    /// A directory.
    Dir,
    /// A regular file: which content it is, and how long.
    File {
        /// Index into [`ExfatModel::contents`], assigned in the order the sorted entries run.
        content: usize,
        /// Its length, which the stream extension records.
        size: u64,
    },
    /// A hard link, by the canonical key of what it names.
    Link(Vec<u8>),
    /// Something the format has no field for, which leaves no entry behind.
    Unrepresentable,
}

/// The tree under construction.
struct Builder<'a> {
    config: &'a ModelConfig<'a>,
    dirs: Vec<ModelDir>,
    contents: Vec<FileContent>,
    fidelity: FidelityReport,
    /// What every declared path holds, from the classifying pass.
    classes: BTreeMap<Vec<u8>, Class>,
    /// Which directory each declared path is, so a child finds its parent in one lookup.
    dir_of: HashMap<Vec<u8>, usize>,
    /// The folded names each directory holds, and the path that took each, so a pair a driver
    /// cannot distinguish names both of them.
    folded: Vec<HashMap<Vec<u16>, Vec<u8>>>,
}

impl<'a> Builder<'a> {
    fn new(config: &'a ModelConfig<'a>) -> Self {
        let root = ModelDir {
            entries: Vec::new(),
            run: ClusterRun::default(),
            path: b"/".to_vec(),
        };
        Self {
            config,
            dirs: vec![root],
            contents: Vec::new(),
            fidelity: FidelityReport::new(),
            classes: BTreeMap::new(),
            dir_of: HashMap::from([(Vec::new(), 0usize)]),
            folded: vec![HashMap::new()],
        }
    }

    /// Everything about a tree that does not depend on how large the volume is.
    fn place_all(mut self, mut entries: Vec<SourceEntry>) -> Result<PlacedTree, ModelError> {
        // Sorted by canonical path, which does two things at once: a parent is always seen
        // before its children, because a path sorts before every path it prefixes; and a
        // directory's entries come out in one order whatever order the source yielded them.
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
                        let size = content.len();
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

        // The root's own metadata goes nowhere: the format records no entry for it on any
        // volume, so a source describing it describes something already true and there is
        // nothing for a report to say that a caller could act on.
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

        // What the entry becomes, before it is named — a kind the format cannot hold leaves no
        // entry behind, so its name and its times are never consulted. That is the honest
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
            FileAttributes::DIRECTORY
        } else {
            // Every mainstream driver sets the archive attribute on a file it creates, and
            // backup software is what clears it. It says nothing about a POSIX mode.
            FileAttributes::ARCHIVE
        };
        // The one bit of a mode the format carries: a driver that meets it clears the write
        // bits of whatever mode it hands back, so writing it is what makes a `0444` file read
        // back as one.
        if meta.mode & WRITE_BITS == 0 {
            attributes |= FileAttributes::READ_ONLY;
        }

        self.dirs[parent].entries.push(ModelEntry {
            name: placed,
            attributes,
            times,
            node,
        });
        Ok(())
    }

    /// What this entry becomes, or `None` where the format has nowhere to put it and the caller
    /// has accepted losing it.
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
                    entries: Vec::new(),
                    run: ClusterRun::default(),
                    path: path.to_vec(),
                });
                self.folded.push(HashMap::new());
                self.dir_of.insert(key.to_vec(), index);
                Ok(Some(Node::Dir(index)))
            }
            EntryKind::File(content) => {
                let Some(Class::File { content: at, size }) = self.classes.get(key).cloned() else {
                    unreachable!("a file was classified as something else")
                };
                // The classifying pass and this one index the same list, and a drift between
                // them would give a file another file's bytes — an image that reads perfectly
                // and holds the wrong contents. One comparison, in every build.
                assert_eq!(at, self.contents.len(), "the two passes fell out of step");
                self.contents.push(content);
                Ok(Some(Node::File {
                    content: at,
                    size,
                    run: ClusterRun::default(),
                }))
            }
            // A second name for a file, in a format that has no second name for one. The target
            // is named inside this source, so resolving it reads nothing this crate was not
            // already given, and the file is one exFAT holds perfectly well — so the bytes are
            // written again rather than the entry being lost.
            EntryKind::HardLink { target } => match self.resolve_link(&target, path)? {
                Some((content, size)) => {
                    self.lose(Property::Kind, path)?;
                    Ok(Some(Node::File {
                        content,
                        size,
                        run: ClusterRun::default(),
                    }))
                }
                // The target was itself something the format cannot hold, so there is nothing
                // left to be a second name for.
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
    fn resolve_link(&self, target: &[u8], path: &[u8]) -> Result<Option<(usize, u64)>, ModelError> {
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

    /// Place `name` in `parent`, refusing a pair the volume's own folding makes one name.
    fn name_in(
        &mut self,
        parent: usize,
        name: &[u8],
        path: &[u8],
    ) -> Result<PlacedName, ModelError> {
        let (placed, folded) =
            place(name, self.config.upcase).map_err(|source| ModelError::Name {
                path: path.to_vec(),
                source,
            })?;
        if let Some(other) = self.folded[parent].get(&folded) {
            return Err(ModelError::Indistinguishable {
                path: path.to_vec(),
                other: other.clone(),
            });
        }
        self.folded[parent].insert(folded, path.to_vec());
        Ok(placed)
    }

    /// The times this entry records, refusing an instant the fields cannot hold.
    ///
    /// The creation time is derived from the modification time, as no source carries a birth
    /// time and reading the clock would make two formats of one tree differ.
    fn times_for(&mut self, meta: &Metadata, path: &[u8]) -> Result<EntryTimes, ModelError> {
        let modify = self.encode(meta.mtime, TimeField::Modification, path)?;
        let mut access = self.encode(meta.atime, TimeField::Access, path)?;
        // The access field has no hundredths byte, so what the entry stores is the two-second
        // unit alone. Dropped here rather than at the write, so the model holds what the volume
        // will hold and a reader of the model is not told a precision the image has not got.
        access.tenth = 0;

        // What survives, field by field: the creation and modification times keep hundredths,
        // so a modification time is stored to ten milliseconds and is lost only below that; the
        // access time keeps none, so it is stored to two seconds. Recorded and never refused —
        // a build can avoid the first by naming a rounder instant, and the second fires on half
        // of all trees, so a refusal would be one a caller learns to accept blanket.
        let modify_precise = meta.mtime.nanos.is_multiple_of(10_000_000);
        let access_precise = meta.atime.secs % 2 == 0 && meta.atime.nanos == 0;
        if !modify_precise || !access_precise {
            self.fidelity
                .record(Direction::Dropped, path, Property::TimePrecision);
        }
        Ok(EntryTimes {
            create: modify,
            modify,
            access,
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

/// A tree with everything decided but its size.
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
    /// Give the tree a geometry: refuse a directory the format cannot hold, then hand out every
    /// cluster, and report what the volume has in use.
    ///
    /// A *failed* run leaves the tree partly allocated against the layout that failed, and no
    /// caller may read the runs in that state — a run set at mixed cluster sizes describes no
    /// volume at all. The runs mean something again only after a run that returned `Ok`.
    pub(crate) fn allocate(&mut self, layout: &ExfatLayout) -> Result<u32, ModelError> {
        self.check_directory_capacity()?;
        self.allocate_clusters(layout)
    }

    /// Turn this into the finished model, at the geometry it was last allocated against.
    pub(crate) fn finish(self, used_clusters: u32) -> ExfatModel {
        ExfatModel {
            dirs: self.dirs,
            contents: self.contents,
            fidelity: self.fidelity,
            used_clusters,
        }
    }

    /// Refuse a directory longer than the format lets one be.
    ///
    /// Every directory, the root included: exFAT's root is an ordinary cluster chain, so the
    /// limit is on all of them equally rather than on the fixed region its FAT counterpart
    /// gives the root.
    fn check_directory_capacity(&self) -> Result<(), ModelError> {
        for (index, dir) in self.dirs.iter().enumerate() {
            let needed = dir.bytes(index);
            if needed > MAX_DIRECTORY_BYTES {
                return Err(ModelError::DirectoryTooLarge {
                    path: dir.path.clone(),
                    needed,
                    limit: MAX_DIRECTORY_BYTES,
                });
            }
        }
        Ok(())
    }

    /// Give every directory and every file the clusters it needs, in one ascending pass.
    ///
    /// Sequential and without gaps, so every allocation is contiguous: there is nothing on a
    /// fresh volume to allocate around. The count starts where the format's own three residents
    /// end — the allocation bitmap, the up-case table, and the root directory's first cluster —
    /// because the root is where the tree begins and the planner has already placed it.
    fn allocate_clusters(&mut self, layout: &ExfatLayout) -> Result<u32, ModelError> {
        let per_cluster = u64::from(layout.bytes_per_cluster);
        let available = layout.cluster_count;
        let mut next = u64::from(layout.first_cluster_of_root);
        let mut take = |count: u64| -> Result<ClusterRun, ModelError> {
            let first = next;
            next += count;
            // Clusters number from `FIRST_CLUSTER`, so the highest one a volume has is
            // `cluster_count + FIRST_CLUSTER - 1`.
            if next > u64::from(available) + u64::from(FIRST_CLUSTER) {
                return Err(ModelError::VolumeFull {
                    needed: next - u64::from(FIRST_CLUSTER),
                    available,
                });
            }
            Ok(ClusterRun {
                first: if count == 0 { 0 } else { first as u32 },
                count: count as u32,
            })
        };

        for index in 0..self.dirs.len() {
            // Every directory takes at least one cluster, an empty one included: the format
            // states a directory's length as a whole number of clusters and no driver reads a
            // directory that has none.
            let bytes = self.dirs[index].bytes(index);
            self.dirs[index].run = take(bytes.div_ceil(per_cluster).max(1))?;
            // The entries of this directory, in the order they will be written, so a file's
            // clusters follow the directory that names it.
            for at in 0..self.dirs[index].entries.len() {
                if let Node::File { size, .. } = self.dirs[index].entries[at].node {
                    let run = take(size.div_ceil(per_cluster))?;
                    if let Node::File { run: slot, .. } = &mut self.dirs[index].entries[at].node {
                        *slot = run;
                    }
                }
            }
        }
        // The root's first cluster is where allocation began, and everything the format itself
        // put in the heap is behind it — so what is in use is every cluster from the heap's
        // first up to the last one handed out.
        Ok((next - u64::from(FIRST_CLUSTER)) as u32)
    }
}

impl ExfatModel {
    /// The cluster and the two lengths a stream extension records for `node`.
    ///
    /// A directory's length is its whole allocation, because the format states one as a number
    /// of clusters; a file's is its bytes. The valid data length is the same as the data length
    /// in both cases — a format writes every byte it allocates, so there is no allocated tail
    /// whose contents are undefined.
    pub(crate) fn entry_target(&self, node: Node, bytes_per_cluster: u32) -> (ClusterRun, u64) {
        match node {
            Node::Dir(index) => {
                let run = self.dirs[index].run;
                (run, u64::from(run.count) * u64::from(bytes_per_cluster))
            }
            Node::File { size, run, .. } => (run, size),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exfat::geometry::{PlanRequest, plan_layout};
    use crate::fidelity::{AcceptedLoss, Synthesis};
    use crate::source::{Source, TreeBuilder};

    /// An instant every field of an entry holds exactly: an even second with no fraction, so
    /// nothing under test is also exercising a rounding. The access field is the one that
    /// makes the second's parity matter — it has no hundredths byte to carry an odd one.
    const TIME: Timestamp = Timestamp {
        secs: 1_426_325_212,
        nanos: 0,
    };

    /// A 32 MiB volume's geometry, which convention formats at four-kilobyte clusters.
    fn layout() -> ExfatLayout {
        plan_layout(&PlanRequest::new(32 << 20)).expect("a geometry")
    }

    /// The folding every model in this module is built against.
    fn upcase() -> UpcaseTable {
        UpcaseTable::recommended()
    }

    /// A configuration accepting nothing, which is the default a caller meets.
    fn config<'a>(upcase: &'a UpcaseTable) -> ModelConfig<'a> {
        ModelConfig {
            loss: LossPolicy {
                accepted: AcceptedLoss::NONE,
                synthesis: Synthesis::new(),
            },
            upcase,
        }
    }

    /// The model `source` builds against a 32 MiB volume, accepting nothing.
    fn model(source: impl Source) -> Result<ExfatModel, ModelError> {
        let upcase = upcase();
        build_model(source.into_entries(), &layout(), &config(&upcase))
    }

    #[test]
    fn a_tree_becomes_directories_and_files_in_sorted_order() {
        let m = model(
            TreeBuilder::new()
                .file(b"/zebra.txt".to_vec(), b"z", Metadata::new(0o644, TIME))
                .directory(b"/dir".to_vec(), Metadata::new(0o755, TIME))
                .file(b"/dir/apple.txt".to_vec(), b"a", Metadata::new(0o644, TIME))
                .file(b"/alpha.txt".to_vec(), b"al", Metadata::new(0o644, TIME)),
        )
        .expect("a tree the format holds");

        assert_eq!(m.dirs.len(), 2);
        let names: Vec<String> = m.dirs[ROOT_DIR]
            .entries
            .iter()
            .map(|e| String::from_utf16(&e.name.units).expect("well-formed"))
            .collect();
        assert_eq!(names, ["alpha.txt", "dir", "zebra.txt"]);
        assert!(m.fidelity.is_faithful(), "nothing was lost");

        // Every directory has a cluster, and the root's is the one the planner placed.
        assert_eq!(m.dirs[ROOT_DIR].run.first, layout().first_cluster_of_root);
        assert!(m.dirs[1].run.count >= 1);
    }

    #[test]
    fn allocation_is_contiguous_and_begins_where_the_format_left_off() {
        let m = model(
            TreeBuilder::new()
                .file(b"/a".to_vec(), vec![0u8; 9_000], Metadata::new(0o644, TIME))
                .file(b"/b".to_vec(), vec![0u8; 1], Metadata::new(0o644, TIME)),
        )
        .expect("a tree the format holds");
        let layout = layout();

        // Every run this crate hands out is consecutive and gapless, which is what lets every
        // stream declare that the allocation table holds no chain for it.
        let mut expected = layout.first_cluster_of_root;
        assert_eq!(m.dirs[ROOT_DIR].run.first, expected);
        expected += m.dirs[ROOT_DIR].run.count;
        for entry in &m.dirs[ROOT_DIR].entries {
            let Node::File { run, .. } = entry.node else {
                unreachable!("both entries are files")
            };
            assert_eq!(run.first, expected);
            expected += run.count;
        }
        assert_eq!(m.used_clusters + FIRST_CLUSTER, expected);
        // A 9000-byte file at four-kilobyte clusters is three of them.
        assert_eq!(
            m.dirs[ROOT_DIR].entries[0].node,
            Node::File {
                content: 0,
                size: 9_000,
                run: ClusterRun {
                    first: layout.first_cluster_of_root + 1,
                    count: 3
                }
            }
        );
    }

    #[test]
    fn an_empty_file_owns_no_cluster() {
        let m = model(TreeBuilder::new().file(b"/empty".to_vec(), b"", Metadata::new(0o644, TIME)))
            .expect("a tree the format holds");
        let Node::File { run, size, .. } = m.dirs[ROOT_DIR].entries[0].node else {
            unreachable!("a file")
        };
        assert_eq!(size, 0);
        assert!(run.is_empty());
        assert_eq!(run.first, 0, "the format says so with a zero");
    }

    #[test]
    fn two_names_the_volumes_folding_makes_one_are_refused_with_both_paths_named() {
        // The pair a driver cannot resolve: a lookup has two answers and returns whichever it
        // met first, leaving the other file unreachable by its own name.
        let err = model(
            TreeBuilder::new()
                .file(b"/README".to_vec(), b"a", Metadata::new(0o644, TIME))
                .file(b"/readme".to_vec(), b"b", Metadata::new(0o644, TIME)),
        )
        .expect_err("a directory that cannot hold both");
        assert!(matches!(err, ModelError::Indistinguishable { .. }), "{err}");
        let message = err.to_string();
        assert!(
            message.contains("README") && message.contains("readme"),
            "{message}"
        );

        // The same two names in different directories are two names, and both are held.
        assert!(
            model(
                TreeBuilder::new()
                    .directory(b"/d".to_vec(), Metadata::new(0o755, TIME))
                    .file(b"/README".to_vec(), b"a", Metadata::new(0o644, TIME))
                    .file(b"/d/readme".to_vec(), b"b", Metadata::new(0o644, TIME)),
            )
            .is_ok()
        );
    }

    #[test]
    fn the_folding_is_the_volumes_own_rather_than_the_hosts() {
        // A volume carrying a table that folds nothing has case-sensitive lookups, and the
        // pair above is then two names it can hold. This is what makes the up-case table an
        // input to the model rather than a constant inside it: the comparison a driver will
        // make is the one this crate has to make.
        let identity = UpcaseTable::new(&[crate::exfat::ondisk::UPCASE_IDENTITY_RUN, 0]);
        let source = TreeBuilder::new()
            .file(b"/README".to_vec(), b"a", Metadata::new(0o644, TIME))
            .file(b"/readme".to_vec(), b"b", Metadata::new(0o644, TIME));
        assert!(
            build_model(source.into_entries(), &layout(), &config(&identity)).is_ok(),
            "a volume that folds nothing distinguishes them"
        );
    }

    #[test]
    fn a_property_the_format_cannot_carry_refuses_until_it_is_accepted() {
        let source = TreeBuilder::new().file(
            b"/owned".to_vec(),
            b"x",
            Metadata {
                uid: 1000,
                gid: 1000,
                ..Metadata::new(0o644, TIME)
            },
        );
        let err = model(source.clone()).expect_err("ownership has nowhere to go");
        assert!(matches!(
            err,
            ModelError::LossNotAccepted {
                property: Property::Ownership,
                ..
            }
        ));

        let upcase = upcase();
        let m = build_model(
            source.into_entries(),
            &layout(),
            &ModelConfig {
                loss: LossPolicy {
                    accepted: AcceptedLoss::NONE.and(Property::Ownership),
                    ..config(&upcase).loss
                },
                ..config(&upcase)
            },
        )
        .expect("accepted");
        assert!(!m.fidelity.is_faithful());
        assert_eq!(m.fidelity.count(Direction::Dropped, Property::Ownership), 1);
    }

    #[test]
    fn a_conventionally_moded_root_owned_tree_loses_nothing() {
        // The claim `is_faithful` has to be able to make, or it is a claim that is never true.
        // These are exactly the values a read of a filesystem recording none of them hands
        // back, so nothing about this tree fails to survive.
        let m = model(
            TreeBuilder::new()
                .directory(b"/etc".to_vec(), Metadata::new(0o755, TIME))
                .file(
                    b"/etc/hostname".to_vec(),
                    b"host\n",
                    Metadata::new(0o644, TIME),
                ),
        )
        .expect("a tree the format holds");
        assert!(m.fidelity.is_faithful());
        assert!(m.fidelity.records().is_empty());
    }

    #[test]
    fn a_read_only_file_keeps_its_mode_through_the_one_bit_the_format_has() {
        let m = model(TreeBuilder::new().file(b"/ro".to_vec(), b"x", Metadata::new(0o444, TIME)))
            .expect("a tree the format holds");
        assert!(
            m.dirs[ROOT_DIR].entries[0]
                .attributes
                .contains(FileAttributes::READ_ONLY)
        );
        assert!(
            m.fidelity.is_faithful(),
            "the write bits a driver clears are the mode that was asked for"
        );
    }

    #[test]
    fn the_precision_a_time_loses_is_recorded_and_never_refuses() {
        // A modification time is stored to ten milliseconds, so a fraction below that is what
        // it loses — and an odd second is not, which is where this family is richer than the
        // one it shares a name with.
        let odd = Timestamp {
            secs: TIME.secs + 1,
            nanos: 0,
        };
        assert_eq!(odd.secs % 2, 1);
        let m = model(TreeBuilder::new().file(b"/f".to_vec(), b"x", Metadata::new(0o644, odd)))
            .expect("recorded, not refused");
        // The access time has no hundredths field, so the odd second is what *it* loses.
        assert_eq!(
            m.fidelity
                .count(Direction::Dropped, Property::TimePrecision),
            1
        );
        let entry = &m.dirs[ROOT_DIR].entries[0];
        assert_eq!(
            entry.times.modify.tenth, 100,
            "the odd second rides in the hundredths"
        );
        assert_eq!(
            entry.times.access.tenth, 0,
            "the access field has no such byte"
        );
        assert_eq!(
            entry.times.create, entry.times.modify,
            "a creation time is derived"
        );

        // An even second with no fraction survives whole, in all three fields — and a
        // fraction the hundredths byte holds exactly survives in the two that have one, which
        // is where this family is richer than the one it shares a name with.
        let m = model(TreeBuilder::new().file(b"/f".to_vec(), b"x", Metadata::new(0o644, TIME)))
            .expect("a tree the format holds");
        assert!(m.fidelity.is_faithful());
        let hundredth = Timestamp {
            secs: TIME.secs,
            nanos: 370_000_000,
        };
        let m = model(TreeBuilder::new().file(
            b"/f".to_vec(),
            b"x",
            Metadata {
                atime: TIME,
                ..Metadata::new(0o644, hundredth)
            },
        ))
        .expect("a tree the format holds");
        assert!(m.fidelity.is_faithful());
        assert_eq!(m.dirs[ROOT_DIR].entries[0].times.modify.tenth, 37);
    }

    #[test]
    fn an_instant_outside_the_range_is_refused_by_field_rather_than_wrapped() {
        for (meta, field) in [
            (
                Metadata::new(0o644, Timestamp::from_secs(0)),
                TimeField::Modification,
            ),
            (
                Metadata {
                    atime: Timestamp::from_secs(DosTimestamp::SECS_MAX + 1),
                    ..Metadata::new(0o644, TIME)
                },
                TimeField::Access,
            ),
        ] {
            let err = model(TreeBuilder::new().file(b"/f".to_vec(), b"x", meta))
                .expect_err("outside the range");
            assert!(
                matches!(err, ModelError::TimeOutOfRange { field: f, .. } if f == field),
                "{err}"
            );
        }
    }

    #[test]
    fn a_hard_link_is_written_as_a_second_copy_and_says_so() {
        let upcase = upcase();
        let m = build_model(
            TreeBuilder::new()
                .file(b"/a".to_vec(), b"contents", Metadata::new(0o644, TIME))
                .hardlink(b"/b".to_vec(), b"/a".to_vec(), Metadata::new(0o644, TIME))
                .into_entries(),
            &layout(),
            &ModelConfig {
                loss: LossPolicy {
                    accepted: AcceptedLoss::NONE.and(Property::Kind),
                    ..config(&upcase).loss
                },
                ..config(&upcase)
            },
        )
        .expect("accepted");

        // Two entries naming one content, with clusters of their own — a second copy rather
        // than two names for cross-linked clusters, which no exFAT driver would understand.
        let runs: Vec<_> = m.dirs[ROOT_DIR]
            .entries
            .iter()
            .map(|e| match e.node {
                Node::File { content, run, .. } => (content, run),
                Node::Dir(_) => unreachable!("both are files"),
            })
            .collect();
        assert_eq!(runs[0].0, runs[1].0, "one content");
        assert_ne!(runs[0].1.first, runs[1].1.first, "two allocations");
        assert_eq!(m.fidelity.count(Direction::Dropped, Property::Kind), 1);
    }

    #[test]
    fn a_shape_no_filesystem_has_is_refused_by_name() {
        let dup = TreeBuilder::new()
            .file(b"/a".to_vec(), b"x", Metadata::new(0o644, TIME))
            .file(b"//a".to_vec(), b"y", Metadata::new(0o644, TIME));
        assert!(matches!(
            model(dup).expect_err("one path twice"),
            ModelError::Duplicate { .. }
        ));

        let orphan = TreeBuilder::new().file(b"/d/f".to_vec(), b"x", Metadata::new(0o644, TIME));
        assert!(matches!(
            model(orphan).expect_err("no parent"),
            ModelError::ParentMissing { .. }
        ));

        let under_file = TreeBuilder::new()
            .file(b"/f".to_vec(), b"x", Metadata::new(0o644, TIME))
            .file(b"/f/g".to_vec(), b"y", Metadata::new(0o644, TIME));
        assert!(matches!(
            model(under_file).expect_err("a file is not a directory"),
            ModelError::ParentNotDir { .. }
        ));

        let ascending = TreeBuilder::new()
            .directory(b"/d".to_vec(), Metadata::new(0o755, TIME))
            .file(b"/d/../f".to_vec(), b"x", Metadata::new(0o644, TIME));
        assert!(matches!(
            model(ascending).expect_err("a path is not a traversal"),
            ModelError::InvalidComponent { .. }
        ));

        let root_file = TreeBuilder::new().file(b"/".to_vec(), b"x", Metadata::new(0o644, TIME));
        assert!(matches!(
            model(root_file).expect_err("the root is a directory"),
            ModelError::RootNotDirectory { .. }
        ));
    }

    #[test]
    fn a_tree_larger_than_the_volume_is_refused_before_anything_is_written() {
        let mut source = TreeBuilder::new();
        for n in 0..40u32 {
            source = source.file(
                format!("/f{n}").into_bytes(),
                vec![0u8; 1 << 20],
                Metadata::new(0o644, TIME),
            );
        }
        assert!(matches!(
            model(source).expect_err("forty megabytes into thirty-two"),
            ModelError::VolumeFull { .. }
        ));
    }

    #[test]
    fn the_root_carries_the_four_entries_a_format_writes_ahead_of_the_tree() {
        // Sized here rather than at the write: the label, the reserved volume GUID slot, and
        // the two entries describing the heap's residents are in the root of every volume, so
        // a root sized without them is one the tree overruns.
        let empty = model(TreeBuilder::new()).expect("an empty tree");
        assert!(empty.dirs[ROOT_DIR].entries.is_empty());
        assert_eq!(
            empty.dirs[ROOT_DIR].run.count, 1,
            "an empty root is one cluster"
        );

        // A file's set is three slots, so seven slots is still one cluster and the arithmetic
        // is visible in the model rather than only in the bytes.
        let one = model(TreeBuilder::new().file(b"/f".to_vec(), b"x", Metadata::new(0o644, TIME)))
            .expect("a tree the format holds");
        assert_eq!(
            one.dirs[ROOT_DIR].bytes(ROOT_DIR),
            u64::from(ROOT_LEADING_SLOTS + 3) * DIR_ENTRY_SIZE as u64
        );
    }

    #[test]
    fn a_directory_larger_than_the_format_holds_is_refused_by_path() {
        // The one capacity limit exFAT puts on a tree's shape, and the root has it too — its
        // FAT counterpart's fixed region is not what this is.
        let mut placed = Builder::new(&config(&upcase()))
            .place_all(
                TreeBuilder::new()
                    .directory(b"/d".to_vec(), Metadata::new(0o755, TIME))
                    .into_entries(),
            )
            .expect("a tree");
        // Reaching the limit through real entries would need eight million of them, so the
        // directory is grown directly: what is under test is the refusal, not the arithmetic
        // that counts to two hundred and fifty-six megabytes.
        placed.dirs[1].entries = std::iter::repeat_with(|| ModelEntry {
            name: PlacedName {
                units: vec![u16::from(b'a'); 255],
                hash: 0,
            },
            attributes: FileAttributes::ARCHIVE,
            times: EntryTimes::default(),
            node: Node::File {
                content: 0,
                size: 0,
                run: ClusterRun::default(),
            },
        })
        .take((MAX_DIRECTORY_ENTRIES / 19) as usize + 1)
        .collect();

        let err = placed
            .allocate(&layout())
            .expect_err("too large a directory");
        assert!(
            matches!(err, ModelError::DirectoryTooLarge { limit, .. } if limit == MAX_DIRECTORY_BYTES),
            "{err}"
        );
        assert!(err.to_string().contains("/d"), "{err}");
    }

    #[test]
    fn two_models_of_one_tree_are_the_same_model() {
        // The order a source yields entries in must not reach the image, or two builds of one
        // tree differ in which cluster every file landed on.
        let forward = model(
            TreeBuilder::new()
                .directory(b"/d".to_vec(), Metadata::new(0o755, TIME))
                .file(b"/d/a".to_vec(), b"a", Metadata::new(0o644, TIME))
                .file(b"/z".to_vec(), b"z", Metadata::new(0o644, TIME)),
        )
        .expect("a tree");
        let shuffled = model(
            TreeBuilder::new()
                .file(b"/z".to_vec(), b"z", Metadata::new(0o644, TIME))
                .file(b"/d/a".to_vec(), b"a", Metadata::new(0o644, TIME))
                .directory(b"/d".to_vec(), Metadata::new(0o755, TIME)),
        )
        .expect("a tree");
        assert_eq!(forward.dirs, shuffled.dirs);
        assert_eq!(forward.used_clusters, shuffled.used_clusters);
    }
}
