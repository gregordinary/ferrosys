//! What a whole-volume scan finds, in APFS's own taxonomy.
//!
//! A read stops at the first thing it cannot do. A scan does not: it walks the whole volume and
//! reports every deviation it meets, which is what a caller asking "is anything wrong with this
//! image" wants and what a caller asking "give me this file" does not.
//!
//! # What it holds the volume to
//!
//! Block zero is held to the live checkpoint ([`BlockZero`](super::BlockZero)), and a checkpoint
//! opening passed over is reported as the interrupted write it is, as damage where block zero
//! records it as written, or as integrity damage where it is another container's or its space
//! manager is one macOS does not load. Every node of
//! the container's object map, the volume's object map, the file-system tree and each
//! extent-reference tree is read, so every checksum, every tree-shape check and every
//! node-layout check in [`btree`](super::btree) is made. Then the volume is held to its own
//! account of itself, by rules each observed on every volume macOS 15, 26 and 27 wrote:
//!
//! - **A tree's root** records how many records and nodes the tree holds, and no key or value
//!   longer than the longest it records, which is the longest ever stored in the tree
//!   (Apple File System Reference, p. 126); **a node's free lists** total the bytes its key area
//!   and its value area leave unused.
//! - **The container superblock's account of itself**: its next object identifier is past
//!   every identifier the container's and the volume's object maps hold, its next transaction
//!   past the live one, its identifier is not zero, and the most volumes it records is the one
//!   its size gives, one per 512 MiB rounded up and at most 100 (Apple File System Reference,
//!   p. 32), and takes in every slot it lists.
//! - **The counts in the volume superblock** are of inode records, not of names: regular files,
//!   symbolic links and every other kind as their records number, and directories less two —
//!   the root and the private directory, which no path reaches.
//! - **The volume superblock's words**: the file-system tree's root is a virtual tree root and
//!   the other two trees' are physical, the snapshot count is the snapshots the volume holds,
//!   the flags carry only bits the format names, the identifier is not zero, and the next object
//!   identifier is past every identifier the tree holds, a snapshot's copy of it past every
//!   identifier the snapshot's tree holds.
//! - **A directory's child count** is the number of entries it holds, for every directory.
//! - **A directory has one name, in its parent:** a walk reaches every directory but the root
//!   and the private directory, by exactly one name, in the directory it records as its
//!   parent.
//! - **Every other inode's link count** is the number of names the walk reaches it by.
//! - **A directory entry's type** is the type of the inode it names.
//! - **Every record, wherever it is**, is what a read of it would take: a directory entry's
//!   extended fields frame, its name is one a directory can hold, and it names an inode the
//!   volume holds; an attribute's name and value parse, and its flags say it is kept either in
//!   its record or in a stream of its own.
//! - **A directory entry's hash** is the hash of its name's normalized form, for every entry,
//!   the ones no path reaches included, and no two entries of one directory are one name to
//!   the volume: names that differ only in case on a volume that folds it, or only in
//!   normalization.
//! - **An inode's or an entry's extended fields** record using exactly the bytes their data
//!   takes, padding included, and the record ends there; an inode's name field is a UTF-8 name
//!   and its terminator.
//! - **A stream's extents** cover it from its first byte to the end of its allocation, each
//!   beginning where the one before it ends, a hole being an extent at block zero.
//! - **A block's reference count**, summed over the extent-reference trees that apply to the
//!   view — each snapshot's up to the one read, and for the volume as it is its own as well — is
//!   the number of streams whose extents use the block. Where the volume keeps its clone
//!   information exact, an extent of a stream that only inodes never cloned use lies in a run
//!   recorded as written by the stream or by one of those inodes. A run's writer says who wrote
//!   it and not who uses it, so it is held only there.
//!
//! - **The container's record of the blocks it uses**: every block in use marked in use, every
//!   block marked in use reached, and every count the space manager, its free queues and each
//!   volume keep about those blocks the number of them, held as [`space`](super::space)
//!   says.
//!
//! A number the volume keeps about itself that disagrees with what it holds is a
//! [`Severity::Conformance`] finding, and so is a reference count no stream accounts for, which
//! is space spent on nothing a reader reaches. Two copies of the container superblock that
//! disagree, an entry stored under a hash its name does not have, two entries that are one
//! name, an entry whose type is not its inode's, a directory reached by no name, by two, or
//! from outside its parent, an extended field met twice, and blocks more streams use than their
//! count says, a count below zero, or an extent of a file never cloned in a run another record
//! wrote — each a way for an extent to point at another file's blocks — are
//! [`Severity::Integrity`] findings. Extents that leave a run of their stream uncovered, and any
//! record a read of it refuses, are [`Severity::Structural`]. `fsck_apfs` passes a wrong link
//! count, a mistyped entry, a run recorded as written by another record, and a checkpoint
//! superblock whose volume list differs from block zero's, which is why this checks them.
//!
//! A record of a kind, or an extended field of a type, this reader has no opinion about is
//! counted and named, not refused, and so is a file compressed by a type this build does not
//! decode: none of the three is a fault in the volume.
//!
//! Every inode a name reaches is also read as a read of it would be, short of decoding its
//! content, and whatever that read refuses is a finding: an extent, an attribute record, a
//! compressed file's chunk table, a link's target.

use std::collections::BTreeMap;

use crate::finding::{Deviation, Family, Finding, Findings, Severity, project};

use super::btree::Census;
use super::container::ReadError;
use super::ondisk::record_kind;

/// What a whole-volume [`scan`](super::Reader::scan) found.
///
/// This is the crate's [`ScanReport`](crate::ScanReport) over APFS's [`Anomaly`].
pub type ScanReport = crate::ScanReport<Anomaly>;

/// The part of a container a deviation was found in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Category {
    /// The source the container is read from, rather than the container: a read the source
    /// failed for a reason other than ending. A scan holds these apart from its findings, as
    /// [`source_failures`](crate::ScanReport::source_failures).
    Source,
    /// The container superblock, or the checkpoint it heads.
    Checkpoint,
    /// A tree node: its checksum, its own account of what it is, or its shape.
    Tree,
    /// One record of the file-system tree.
    Record,
    /// The volume's account of itself: its counts, a directory's child count, a link count.
    Volume,
    /// The container's record of which blocks are in use: the space manager, its free queues and
    /// its internal pool.
    Space,
}

impl Category {
    /// The lowercase name this category is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Source => "source",
            Category::Checkpoint => "checkpoint",
            Category::Tree => "tree",
            Category::Record => "record",
            Category::Volume => "volume",
            Category::Space => "space",
        }
    }
}

/// One deviation a scan found: where it was, how serious it is, and what it was.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Anomaly {
    /// The part of the container it was found in.
    pub category: Category,
    /// How serious it is.
    pub severity: Severity,
    /// The block it was found at, where one applies.
    pub block: Option<u64>,
    /// The inode it concerns, where one applies.
    pub inode: Option<u64>,
    /// What was wrong, in a sentence a person reads.
    pub detail: String,
}

impl Deviation for Anomaly {
    fn severity(&self) -> Severity {
        self.severity
    }

    fn is_source_failure(&self) -> bool {
        self.category == Category::Source
    }

    fn to_finding(&self, unit: u32) -> Finding {
        // A block address is a physical place in the container, so it is the addressed
        // coordinate: the unit is the container's block size.
        project(
            self.severity,
            Family::Apfs,
            self.category.as_str(),
            &[("block", self.block), ("inode", self.inode)],
            self.block,
            unit,
            &self.detail,
        )
    }
}

/// Everything a scan gathers while walking.
pub(super) struct Scan {
    pub(super) found: Findings<Anomaly>,
    /// Every record kind met that this reader has no opinion about, and how many of each.
    unknown: BTreeMap<u8, u64>,
    /// Every extended-field type met that this reader does not know, and how many of each.
    fields: BTreeMap<u8, u64>,
    /// Every compression type met that this build does not decode, and how many files of each.
    undecoded: BTreeMap<u32, u64>,
    block_size: u32,
}

impl Scan {
    pub(super) fn new(cap: usize, block_size: u32) -> Self {
        Self {
            found: Findings::new(cap),
            unknown: BTreeMap::new(),
            fields: BTreeMap::new(),
            undecoded: BTreeMap::new(),
            block_size,
        }
    }

    /// Record a deviation.
    pub(super) fn at(
        &mut self,
        category: Category,
        severity: Severity,
        block: Option<u64>,
        inode: Option<u64>,
        detail: String,
    ) {
        self.found.push(Anomaly {
            category,
            severity,
            block,
            inode,
            detail,
        });
    }

    /// Record a read that failed, under the category and severity its error belongs to.
    pub(super) fn failed(&mut self, inode: Option<u64>, context: &str, err: &ReadError) {
        let (category, severity, block) = classify(err);
        self.at(
            category,
            severity,
            block,
            inode,
            format!("{context}: {err}"),
        );
    }

    /// Bytes in every block of the container.
    pub(super) fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Hold the `what` tree a census counted to what its root says it holds: its records, its
    /// nodes, its longest key and value (the longest ever stored, so at least the longest it
    /// holds; reference p. 126), and each node's free lists to the bytes its areas leave
    /// unused. Every tree macOS 15, 26 and 27 wrote keeps all of these.
    pub(super) fn census(&mut self, what: &str, census: &Census) {
        let info = &census.info;
        let mut deviation = |block: u64, detail: String| {
            self.at(
                Category::Tree,
                Severity::Conformance,
                Some(block),
                None,
                format!("the {what} tree: {detail}"),
            );
        };
        if info.key_count != census.records {
            deviation(
                census.root,
                format!(
                    "its root records {} records and it holds {}",
                    info.key_count, census.records
                ),
            );
        }
        if info.node_count != census.nodes {
            deviation(
                census.root,
                format!(
                    "its root records {} nodes and it has {}",
                    info.node_count, census.nodes
                ),
            );
        }
        let (key, value) = census.longest;
        if key > info.longest_key as usize {
            deviation(
                census.root,
                format!(
                    "it holds a {key}-byte key and its root records {} as the longest",
                    info.longest_key
                ),
            );
        }
        if value > info.longest_value as usize {
            deviation(
                census.root,
                format!(
                    "it holds a {value}-byte value and its root records {} as the longest",
                    info.longest_value
                ),
            );
        }
        for (block, area, said, held) in &census.free_lists {
            deviation(
                *block,
                format!(
                    "the node's {area} free list records {said} bytes and {held} of the {area} \
                     area are unused"
                ),
            );
        }
    }

    /// Note that a record of `kind` was met and not interpreted.
    pub(super) fn met(&mut self, kind: u8) {
        if !INTERPRETED.contains(&kind) {
            *self.unknown.entry(kind).or_default() += 1;
        }
    }

    /// Note that an extended field of type `kind` was met, which this reader does not know.
    pub(super) fn field(&mut self, kind: u8) {
        *self.fields.entry(kind).or_default() += 1;
    }

    /// Note that a file compressed by type `method` was met, whose content this build does not
    /// decode.
    pub(super) fn undecoded(&mut self, method: u32) {
        *self.undecoded.entry(method).or_default() += 1;
    }

    /// The report, with the uninterpreted kinds and the undecoded compression types folded
    /// into one finding each.
    pub(super) fn finish(mut self) -> ScanReport {
        let unknown = std::mem::take(&mut self.unknown);
        for (kind, count) in unknown {
            self.at(
                Category::Record,
                Severity::Cosmetic,
                None,
                None,
                format!(
                    "{count} record{} of kind {kind}, which this reader does not interpret; \
                     each was skipped",
                    if count == 1 { "" } else { "s" }
                ),
            );
        }
        let fields = std::mem::take(&mut self.fields);
        for (kind, count) in fields {
            self.at(
                Category::Record,
                Severity::Cosmetic,
                None,
                None,
                format!(
                    "{count} extended field{} of type {kind}, which this reader does not know; \
                     each was skipped",
                    if count == 1 { "" } else { "s" }
                ),
            );
        }
        let undecoded = std::mem::take(&mut self.undecoded);
        for (method, count) in undecoded {
            self.at(
                Category::Record,
                Severity::Cosmetic,
                None,
                None,
                format!(
                    "{count} file{} compressed by type {method}, which this build does not \
                     decode; {} content was not read",
                    if count == 1 { "" } else { "s" },
                    if count == 1 { "its" } else { "their" }
                ),
            );
        }
        self.found.into_report(self.block_size)
    }
}

/// The record kinds this reader interprets, or knows to need nothing from.
const INTERPRETED: [u8; 7] = [
    record_kind::INODE,
    record_kind::XATTR,
    record_kind::SIBLING_LINK,
    record_kind::DATA_STREAM_ID,
    record_kind::FILE_EXTENT,
    record_kind::DIR_ENTRY,
    record_kind::SIBLING_MAP,
];

/// The category, severity and block a failed read is reported under.
fn classify(err: &ReadError) -> (Category, Severity, Option<u64>) {
    match err {
        // A read the source failed for a reason other than ending says nothing about the
        // container. A short read is the image's, and falls to the default below.
        ReadError::Io { kind, .. } if *kind != std::io::ErrorKind::UnexpectedEof => {
            (Category::Source, Severity::Structural, None)
        }
        ReadError::BadChecksum { block, .. } => (Category::Tree, Severity::Integrity, Some(*block)),
        ReadError::BadNode { block, .. }
        | ReadError::BadTree { block, .. }
        | ReadError::WrongObject { block, .. } => {
            (Category::Tree, Severity::Structural, Some(*block))
        }
        ReadError::NoCheckpoint | ReadError::UnsupportedCheckpoint => {
            (Category::Checkpoint, Severity::Structural, None)
        }
        ReadError::BlockZeroDisagrees { .. } => {
            (Category::Checkpoint, Severity::Integrity, Some(0))
        }
        ReadError::BadExtent { block, .. } => (Category::Record, Severity::Structural, *block),
        ReadError::RepeatedDirectory { .. } | ReadError::MisplacedDirectory { .. } => {
            (Category::Record, Severity::Integrity, None)
        }
        _ => (Category::Record, Severity::Structural, None),
    }
}
