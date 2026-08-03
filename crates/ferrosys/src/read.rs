//! The reader: parse an ext4 filesystem back into inodes, directories, and file
//! contents.
//!
//! It reads filesystems other tools wrote, not only the ones this crate writes. Both
//! block mappings are followed to any depth — the extent tree, and the direct/indirect
//! map ext2 and ext3 use for every file; any inode size is honored, down to the 128-byte
//! inode that has no extended area at all; and every checksum is verified against the
//! object's own bytes, so a field an image carries and this crate does not model does not
//! read as corruption. [`Reader::lookup`] resolves a path against the image's own root,
//! following symbolic links as it goes.
//!
//! # Robustness and strictness
//!
//! Two properties are kept apart. *Robustness* is always on: every on-disk field is
//! bounds-checked and every fallible step returns a [`ReadError`] rather than panicking
//! or reading out of range, on any input — including one built to break it.
//!
//! *Conformance strictness* is a policy: a threshold over the [`Severity`] of the
//! [`Anomaly`] a deviation carries. [`ReadPolicy::Strict`], the default, is fatal at any
//! anomaly a conformant ext4 would not carry, so a strict read either yields the
//! filesystem the image describes or names the deviation that stopped it.
//!
//! [`ReadPolicy::Lenient`] moves that threshold above every severity, so nothing is
//! fatal. A whole-image [`scan`](Reader::scan) walks the superblock, every group
//! descriptor, and every in-use inode and its extent tree, collecting each deviation
//! as an [`Anomaly`] into a [`ScanReport`] instead of stopping at the first — the
//! forensic counterpart to a strict read. The report projects to JSON, SARIF, or a
//! human table, and [`ScanReport::has_fatal`] applies a policy's threshold back to what
//! the scan found.
//!
//! The handle opens over any [`Read`] + [`Seek`] source at an arbitrary byte offset,
//! so it reads a filesystem embedded in a larger device or partition image as
//! readily as a bare one.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::csum::{Checksummer, Crc32c};
use crate::extent::{ExtentNode, MAX_EXTENT_DEPTH, parse_node, tail_offset};
use crate::feature::{FeatureSet, Incompat, LARGE_FILE_MIN_SIZE, Profile};
use crate::model::ROOT_INO;
use crate::ondisk::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, DIR_TAIL_LEN, DX_CHECKSUM_OFFSET, DX_ENTRY_LEN,
    DX_NODE_COUNT_OFFSET, DX_ROOT_COUNT_OFFSET, DX_TAIL_LEN, DirEntry, EXTENT_ENTRY_SIZE,
    EXTENT_TAIL_LEN, FileType, GOOD_OLD_FIRST_INODE, GOOD_OLD_INODE_SIZE, GroupDescriptor, Inode,
    InodeFlags, ParseError, SuperBlock, Xattr, decode_device, dx_tail_offset, get_u16, get_u32,
    orphan_entries_len, parse_block, parse_inline, put_u16, read_dx_entries, read_dx_root_info,
    read_orphan_tail,
};

/// The `incompat` features whose on-disk layout this reader interprets. Every one is a
/// format this crate reads and, where relevant, writes: typed directory entries, extent
/// trees, 64-bit geometry, flex block groups, and a superblock-stored checksum seed. A
/// set `incompat` bit outside this mask means the reader cannot be certain it reads the
/// image correctly — an unknown extension, or `meta_bg`, whose distributed group
/// descriptors this reader's contiguous-table parsing does not follow. The `incompat`
/// word is the one an implementation must refuse when it does not recognize a bit, so
/// this mask is what a strict read enforces and a scan reports against.
const SUPPORTED_INCOMPAT: u32 = Incompat::FILETYPE.bits()
    | Incompat::EXTENTS.bits()
    | Incompat::SIXTY_FOUR_BIT.bits()
    | Incompat::FLEX_BG.bits()
    | Incompat::CSUM_SEED.bits();

/// The `incompat` bits set in `incompat` that this reader does not interpret: the word
/// with every [`SUPPORTED_INCOMPAT`] bit cleared. Zero means every feature the image
/// advertises is one the reader follows.
fn unsupported_incompat(incompat: Incompat) -> u32 {
    incompat.bits() & !SUPPORTED_INCOMPAT
}

/// The `incompat` features ext4 defines that [`Incompat`] does not model, paired with
/// the names `dumpe2fs` and `tune2fs` print for them, so a report can be read straight
/// against those tools' output.
///
/// Naming a bit here is diagnosis, not support. What the reader will follow is
/// [`SUPPORTED_INCOMPAT`] and nothing else, and what a caller may ask a formatter for
/// is what [`Incompat`] models and nothing else — a name in this table reaches neither.
/// It exists so that an image the reader turns away is turned away by name.
const UNMODELLED_INCOMPAT: &[(&str, u32)] = &[
    ("compression", 0x0000_0001),
    ("needs_recovery", 0x0000_0004),
    ("journal_dev", 0x0000_0008),
    ("mmp", 0x0000_0100),
    ("ea_inode", 0x0000_0400),
    ("dirdata", 0x0000_1000),
    ("large_dir", 0x0000_4000),
    ("inline_data", 0x0000_8000),
    ("encrypt", 0x0001_0000),
    ("casefold", 0x0002_0000),
];

/// Describe the unsupported `incompat` bits for an anomaly's detail: the on-disk name
/// of each feature, in ascending bit order, and any bit ext4 itself does not define
/// gathered into one hexadecimal word. All of them are what the reader cannot vouch for
/// having read correctly.
fn describe_unsupported_incompat(bits: u32) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut undefined = 0u32;
    for i in 0..u32::BITS {
        let bit = 1u32 << i;
        if bits & bit == 0 {
            continue;
        }
        // A bit the feature word models carries its name there; the rest of ext4's
        // vocabulary is named by the table above. Anything in neither belongs to no
        // feature ext4 defines, so there is no name to give it.
        if let Some(name) = Incompat::from_bits(bit).names().first() {
            parts.push((*name).to_string());
        } else if let Some((name, _)) = UNMODELLED_INCOMPAT.iter().find(|(_, b)| *b == bit) {
            parts.push((*name).to_string());
        } else {
            undefined |= bit;
        }
    }
    if undefined != 0 {
        parts.push(format!("{undefined:#010x}"));
    }
    format!(
        "unsupported incompatible feature(s) {}: the reader cannot be certain it \
         interprets the on-disk format correctly",
        parts.join(", ")
    )
}

/// Direct block pointers in the classic map: `i_block[0..12]` name data blocks
/// outright, and the three words after them are one, two, and three levels of
/// indirection.
const DIRECT_BLOCKS: usize = 12;

/// Levels of indirection the classic block map reaches: single, double, and triple.
/// This bounds [`Reader::walk_indirect_window`]'s recursion by construction.
const INDIRECT_LEVELS: u32 = 3;

/// The most logical blocks one mapping window covers, which is what makes streaming a
/// file a fixed cost: the map for a window is eight bytes per block, so 4096 blocks is
/// 32 KiB of map covering 16 MiB of file at a 4 KiB block size. A file of any length is
/// read as a succession of these rather than as one map of everything its size claims.
const MAP_WINDOW_BLOCKS: usize = 4096;

/// The number of logical blocks a file can address: a logical block number is 32
/// bits wide in both the extent (`ee_block`) and classic maps, so a file spans at
/// most 2^32 blocks whatever its `i_size` claims. This is the ceiling a logical
/// offset is bounded by, distinct from the physical block count a block *number* is
/// bounded by — the distinction a sparse file turns on, where a high logical offset
/// is valid over a filesystem far smaller than the offset.
const MAX_LOGICAL_BLOCKS: u64 = 1 << 32;

/// The most symlinks a path resolution will follow before calling it a loop, matching
/// the kernel's `MAXSYMLINKS`. A cycle (`a -> b -> a`) is the obvious case, but a chain
/// long enough to be an effective denial of service is the one that matters on an image
/// this crate did not write.
pub const MAX_SYMLINK_HOPS: u32 = 40;

/// The longest symbolic-link target a resolution will read, matching Linux's `PATH_MAX`.
/// A link's target is bounded by its block on a well-formed image; this bounds it on one
/// whose `i_size` claims otherwise, before the bytes are read.
const MAX_PATH: usize = 4096;

/// The fewest bytes one directory record can occupy: the eight-byte header plus a name of
/// at least one byte, rounded up to the four-byte alignment every `rec_len` obeys.
///
/// This is [`min_rec_len(1)`](crate::ondisk::min_rec_len), which is where that rule is
/// spelled; the value appears again here because it divides a `u64` and the rule's
/// function is not `const`. A unit test holds the two equal, so a change to the record
/// header or to the alignment cannot move one without moving the other.
///
/// Every name a well-formed filesystem holds costs at least this much of its own blocks,
/// which is what turns the source's length into a bound on how many names it can
/// describe — and what makes that bound one no well-formed image reaches.
pub const MIN_DIRENT_LEN: u64 = 12;

/// Split a path into the components a resolution walks: `/`-separated, with empty
/// components and `.` dropped. `..` is left in, and resolves through the directory's own
/// entry for it — which is the only thing that knows where the parent is.
fn components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(<[u8]>::to_vec)
        .collect()
}

/// Whether an inode is a directory (`S_IFDIR`).
fn is_dir(inode: &Inode) -> bool {
    inode.mode & 0o170000 == 0o040000
}

/// Whether an inode is a symbolic link (`S_IFLNK`).
fn is_symlink(inode: &Inode) -> bool {
    inode.mode & 0o170000 == 0o120000
}

/// Whether an inode is a regular file (`S_IFREG`). The `large_file` feature is scoped to
/// these alone, which is the same scope the kernel and `e2fsck` apply it in.
fn is_regular(inode: &Inode) -> bool {
    inode.mode & 0o170000 == 0o100000
}

/// Whether a directory-entry name is one a real ext4 filesystem could not hold: it
/// contains a path separator or a NUL. The kernel's `ext4_check_dir_entry` forbids
/// both, so either marks a crafted or corrupt image. A name carrying `/` traverses out
/// of its directory (`../../etc/...`); one carrying a NUL ends early at the C-string
/// boundary a consumer would build a host path against. A walk builds no path from such
/// a name, and a scan reports it.
fn name_is_hostile(name: &[u8]) -> bool {
    name.contains(&b'/') || name.contains(&0)
}

/// Whether a symlink stores its target inline in the inode's `i_block` area rather
/// than in a data block.
///
/// The distinction is block usage, not target length: a symlink that owns no data
/// block is a *fast* one, whatever its size field says. `i_blocks` counts 512-byte
/// sectors, and an external attribute block is charged to it as well, so that block —
/// one filesystem block's worth of sectors, present exactly when `i_file_acl` names
/// one — is discounted first. What remains is the storage the target itself occupies,
/// and a fast symlink occupies none.
///
/// Keying on the target length instead would read a short target held in a data block
/// straight out of the block area, returning a block pointer as a filename.
fn is_fast_symlink(inode: &Inode, block_size: usize) -> bool {
    let ea_blocks = if inode.file_acl != 0 {
        (block_size / 512) as u64
    } else {
        0
    };
    inode.blocks == ea_blocks
}

/// Whether an inode's `i_block` area maps data blocks at all.
///
/// Only a regular file, a directory, and a symlink whose target lives in a data block
/// have a mapping there. A *fast* symlink stores its target string in that area, and a
/// device node stores its major and minor numbers — so a reader that walks every
/// inode's `i_block` as a block map reads a filename, or a device number, as a list of
/// block numbers. An inode with no data (a FIFO, a socket, an unused reserved inode)
/// maps nothing.
fn maps_data(inode: &Inode, block_size: usize) -> bool {
    match inode.mode & 0o170000 {
        0o100000 | 0o040000 => true, // regular file, directory
        0o120000 => !is_fast_symlink(inode, block_size), // a slow symlink only
        _ => false,
    }
}

/// How serious a deviation from what this crate emits is, ordered least to most
/// serious so a policy can set a fatal threshold over it.
///
/// The order is the comparison order: `Cosmetic < Conformance < Integrity <
/// Structural`. [`ReadPolicy::Strict`] is fatal at [`Conformance`](Self::Conformance)
/// and above.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Severity {
    /// Valid and harmless: a representation a conformant reader accepts without
    /// remark.
    Cosmetic,
    /// Valid ext4, but not the form this crate emits.
    Conformance,
    /// Parses, but fails its own checksum — the bytes are self-inconsistent.
    Integrity,
    /// Cannot be parsed further: a structure the reader must follow is unreadable or
    /// out of range.
    Structural,
}

impl Severity {
    /// The lowercase name of this severity, for a rendered report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Cosmetic => "cosmetic",
            Severity::Conformance => "conformance",
            Severity::Integrity => "integrity",
            Severity::Structural => "structural",
        }
    }
}

/// The subsystem a deviation was found in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Category {
    /// The primary or a backup superblock.
    Superblock,
    /// The group descriptor table.
    GroupDescriptor,
    /// A block or inode bitmap.
    Bitmap,
    /// An inode.
    Inode,
    /// An inode's extent tree.
    ExtentTree,
    /// A directory block or its hash-tree index.
    Directory,
    /// An extended-attribute block or inline set.
    Xattr,
    /// The journal.
    Journal,
    /// The orphan file, which records the inodes awaiting deletion.
    Orphan,
}

impl Category {
    /// The lowercase name of this subsystem, for a rendered report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Superblock => "superblock",
            Category::GroupDescriptor => "group descriptor",
            Category::Bitmap => "bitmap",
            Category::Inode => "inode",
            Category::ExtentTree => "extent tree",
            Category::Directory => "directory",
            Category::Xattr => "xattr",
            Category::Journal => "journal",
            Category::Orphan => "orphan",
        }
    }
}

/// The version of the emitted scan schema — the JSON a report renders and the record
/// each anomaly renders within it.
///
/// The Rust types are pinned by the compiler and by the crate's API snapshot; the
/// *emitted document* is a contract of its own that neither of those sees, so it carries
/// a version a consumer can branch on. It changes only when the shape changes: a field
/// added, renamed, or removed, or a value's spelling altered. The
/// [SARIF](ScanReport::to_sarif) projection is versioned by SARIF itself and does not
/// carry this.
pub const SCAN_SCHEMA_VERSION: u32 = 1;

/// Where in the image a deviation sits. Every field is optional: a deviation carries
/// only the coordinates that locate it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Location {
    /// Block number, when the deviation is block-addressed.
    pub block: Option<u64>,
    /// Group number, when the deviation is group-addressed.
    pub group: Option<u32>,
    /// Inode number, when the deviation is inode-addressed.
    pub inode: Option<u32>,
}

/// A typed deviation from what this crate would emit, carrying its severity, the
/// subsystem it was found in, where it sits, and a human description.
///
/// This is the structured value; a JSON record, a rendered table, and a SARIF finding are
/// projections of it. The projections live here rather than at the edge, and deliberately:
/// a projection written outside this crate would enumerate the fields from outside, where
/// `#[non_exhaustive]` blocks the exhaustive destructure that keeps it complete — so a
/// fact learned about a finding would silently stop being reported. Here, adding a field
/// is a compile error in [`to_json`](Self::to_json), and the emitted shape is pinned by a
/// golden test and versioned by [`SCAN_SCHEMA_VERSION`].
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    /// How serious the deviation is.
    pub severity: Severity,
    /// The subsystem it was found in.
    pub category: Category,
    /// Where it sits in the image.
    pub location: Location,
    /// A human-readable description.
    pub detail: String,
}

impl Anomaly {
    /// Render this anomaly as a single JSON object: `severity`, `category`, a
    /// `location` holding only the coordinates that are set, and the `detail` string.
    /// This is a projection of the typed value computed here, not a stored wire
    /// format.
    #[must_use]
    pub fn to_json(&self) -> String {
        // Destructured exhaustively on purpose: a field added to `Anomaly` is a compile
        // error here, which forces a decision about the emitted record rather than
        // letting a new fact about a finding go silently unreported.
        let Self {
            severity,
            category,
            location,
            detail,
        } = self;
        let mut out = String::from("{\"severity\":\"");
        out.push_str(severity.as_str());
        out.push_str("\",\"category\":\"");
        out.push_str(category.as_str());
        out.push_str("\",\"location\":");
        push_location_json(&mut out, location);
        out.push_str(",\"detail\":");
        push_json_string(&mut out, detail);
        out.push('}');
        out
    }
}

/// Append a JSON object for a location, emitting only the coordinates that are set.
fn push_location_json(out: &mut String, loc: &Location) {
    // Exhaustive on purpose: a coordinate added to `Location` is a compile error here.
    let Location {
        block,
        group,
        inode,
    } = *loc;
    out.push('{');
    let mut first = true;
    if let Some(b) = block {
        push_json_field(out, &mut first, "block", b);
    }
    if let Some(g) = group {
        push_json_field(out, &mut first, "group", u64::from(g));
    }
    if let Some(i) = inode {
        push_json_field(out, &mut first, "inode", u64::from(i));
    }
    out.push('}');
}

/// Append `"key":value` to a JSON object, with a leading comma once past the first
/// field.
fn push_json_field(out: &mut String, first: &mut bool, key: &str, value: u64) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

/// Append a JSON string literal, escaping the characters JSON requires.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let byte = c as u32;
                out.push_str("\\u00");
                out.push(char::from_digit(byte >> 4, 16).expect("high nibble is 0..16"));
                out.push(char::from_digit(byte & 0xf, 16).expect("low nibble is 0..16"));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A compact one-line location for the human table: the set coordinates joined by
/// spaces, or `-` when none are.
fn location_compact(loc: &Location) -> String {
    let mut parts = Vec::new();
    if let Some(g) = loc.group {
        parts.push(format!("group {g}"));
    }
    if let Some(i) = loc.inode {
        parts.push(format!("inode {i}"));
    }
    if let Some(b) = loc.block {
        parts.push(format!("block {b}"));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

/// The SARIF result level an anomaly severity maps to. SARIF offers three actionable
/// levels; `structural` and `integrity` both mean the image is unsound, so both are
/// `error`, and the exact severity is preserved in the result's `properties`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Structural | Severity::Integrity => "error",
        Severity::Conformance => "warning",
        Severity::Cosmetic => "note",
    }
}

/// Append the SARIF `rules` array: one rule per distinct anomaly category present, in the
/// order the categories first appear, so every `ruleId` a result names is defined without
/// emitting a rule for a subsystem the scan said nothing about.
fn push_sarif_rules(out: &mut String, anomalies: &[Anomaly]) {
    let mut seen: Vec<&'static str> = Vec::new();
    for a in anomalies {
        let id = a.category.as_str();
        if !seen.contains(&id) {
            if !seen.is_empty() {
                out.push(',');
            }
            seen.push(id);
            out.push_str("{\"id\":");
            push_json_string(out, id);
            out.push_str(",\"name\":");
            push_json_string(out, id);
            out.push_str(",\"shortDescription\":{\"text\":");
            push_json_string(out, &format!("{id} anomaly"));
            out.push_str("}}");
        }
    }
}

/// Append one SARIF result for an anomaly: its rule (the category), level (from the
/// severity), message (the detail), a location carrying the artifact and the logical
/// address when either is known, and the full typed value in `properties`.
fn push_sarif_result(out: &mut String, a: &Anomaly, artifact_uri: Option<&str>) {
    out.push_str("{\"ruleId\":");
    push_json_string(out, a.category.as_str());
    out.push_str(",\"level\":\"");
    out.push_str(sarif_level(a.severity));
    out.push_str("\",\"message\":{\"text\":");
    push_json_string(out, &a.detail);
    out.push('}');

    // Emit `locations` only when there is a coordinate to record: an empty location object
    // would carry nothing.
    let address = location_compact(&a.location);
    let has_address = address != "-";
    if artifact_uri.is_some() || has_address {
        out.push_str(",\"locations\":[{");
        let mut first = true;
        if let Some(uri) = artifact_uri {
            out.push_str("\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
            push_json_string(out, uri);
            out.push_str("}}");
            first = false;
        }
        if has_address {
            if !first {
                out.push(',');
            }
            out.push_str("\"logicalLocations\":[{\"fullyQualifiedName\":");
            push_json_string(out, &address);
            out.push_str("}]");
        }
        out.push_str("}]");
    }

    out.push_str(",\"properties\":");
    push_sarif_properties(out, a);
    out.push('}');
}

/// Append the SARIF `properties` bag for an anomaly: the exact severity and category as
/// strings, then whichever of block/group/inode are set — the coordinates and the precise
/// severity SARIF's three-level `level` cannot itself carry.
fn push_sarif_properties(out: &mut String, a: &Anomaly) {
    out.push_str("{\"severity\":");
    push_json_string(out, a.severity.as_str());
    out.push_str(",\"category\":");
    push_json_string(out, a.category.as_str());
    // `severity` and `category` are already written, so every further field takes a leading
    // comma: seed `first` false so `push_json_field` emits one.
    let mut first = false;
    if let Some(b) = a.location.block {
        push_json_field(out, &mut first, "block", b);
    }
    if let Some(g) = a.location.group {
        push_json_field(out, &mut first, "group", u64::from(g));
    }
    if let Some(i) = a.location.inode {
        push_json_field(out, &mut first, "inode", u64::from(i));
    }
    out.push('}');
}

/// Project a [`ReadError`] to an [`Anomaly`] and stamp it with the inode it was found
/// under, keeping any more specific inode the error already carried.
fn anomaly_at_inode(err: &ReadError, ino: u32) -> Anomaly {
    let mut a = err.anomaly();
    a.location.inode.get_or_insert(ino);
    a
}

/// Redirect an out-of-range *block* reference to the subsystem whose walk named it.
///
/// The bare projection of an `OutOfRange { what: "block" }` blames the superblock,
/// because a block number alone names no owning structure. A scanner that followed a
/// reference into that block does know the owner and threads it here, so a consumer
/// filtering by category sees the bad block filed under the extent tree, directory,
/// bitmap, or attribute block that pointed at it — not the one object the image
/// demonstrably got right. An error that carries its own subsystem (a parse or checksum
/// failure) keeps it, as does an out-of-range *inode* or *group*, which the inode and
/// group-descriptor subsystems already own.
fn redirect_block_ref(a: &mut Anomaly, err: &ReadError, category: Category) {
    if matches!(err, ReadError::OutOfRange { what: "block", .. }) {
        a.category = category;
    }
}

/// Project an error found while walking `ino`'s block mapping — its extent tree, classic
/// block map, directory blocks, or external attribute block — filing an out-of-range
/// block against `category` and stamping the owning inode. Inode 0 is the null inode,
/// never a real one, so a fault with no known owner carries no inode stamp.
fn anomaly_in_mapping(err: &ReadError, ino: u32, category: Category) -> Anomaly {
    let mut a = err.anomaly();
    redirect_block_ref(&mut a, err, category);
    if ino != 0 {
        a.location.inode.get_or_insert(ino);
    }
    a
}

/// A structural anomaly for a directory holding a name a real ext4 filesystem could
/// not: one carrying a path separator or a NUL (see [`name_is_hostile`]). The offending
/// name is deliberately not echoed into the detail — it is attacker-controlled and may
/// carry terminal control bytes — so the anomaly names the directory, not the name.
fn hostile_name_anomaly(ino: u32) -> Anomaly {
    Anomaly {
        severity: Severity::Structural,
        category: Category::Directory,
        location: Location {
            inode: Some(ino),
            ..Location::default()
        },
        detail: "a directory entry name contains a path separator or NUL".to_string(),
    }
}

/// Project an error found while checking group `g`'s bitmaps, filing an out-of-range
/// bitmap block against `category` — the bitmap subsystem the descriptor named it for —
/// and stamping the owning group. A descriptor that cannot be reached at all is an
/// out-of-range *group*, which the group-descriptor subsystem keeps.
fn anomaly_in_bitmap(err: &ReadError, group: u32, category: Category) -> Anomaly {
    let mut a = err.anomaly();
    redirect_block_ref(&mut a, err, category);
    a.location.group.get_or_insert(group);
    a
}

/// The on-disk structure a [`ParseError`] is about.
fn parse_structure(err: &ParseError) -> &'static str {
    match err {
        ParseError::TooShort { structure, .. }
        | ParseError::BadMagic { structure, .. }
        | ParseError::InvalidField { structure, .. } => structure,
    }
}

/// The [`Category`] an on-disk structure name belongs to, so a parse failure is filed
/// against the object that actually failed.
fn parse_category(structure: &str) -> Category {
    match structure {
        "Inode" => Category::Inode,
        "GroupDescriptor" => Category::GroupDescriptor,
        "ExtentHeader" | "ExtentNode" => Category::ExtentTree,
        "DirEntry" | "DirEntryTail" => Category::Directory,
        s if s.starts_with("Dx") => Category::Directory,
        s if s.starts_with("Xattr") => Category::Xattr,
        s if s.starts_with("JournalSuperblock") => Category::Journal,
        "OrphanBlockTail" => Category::Orphan,
        _ => Category::Superblock,
    }
}

/// The read-only state one inode's extent scan threads through its recursion: which
/// inode it is under, the tree's checksum seed, whether checksums are on, and the
/// checksummer to recompute them with.
struct ExtentScanCtx<'a> {
    ino: u32,
    seed: u32,
    has_csum: bool,
    csum: &'a Crc32c,
}

/// Where an external extent node's checksum tail sits, taken from the node's own
/// declared capacity (`eh_max`) as the kernel does, not from the block size. The tail
/// follows the header and every entry slot the node declares room for, so a node that
/// does not fill its block is read where its tail actually is, matching a foreign tool
/// that wrote a short node. A capacity too large for the block is malformed; the
/// block-filling offset is used then, which stays in bounds and reads back as a
/// mismatch, so a crafted `eh_max` can neither move the tail out of the block nor pass
/// verification.
fn extent_tail_offset(node: &[u8], node_bytes: usize) -> usize {
    if node.len() >= EXTENT_ENTRY_SIZE {
        let eh_max = usize::from(get_u16(node, 4));
        let tail = EXTENT_ENTRY_SIZE * (eh_max + 1);
        if tail + EXTENT_TAIL_LEN <= node.len() {
            return tail;
        }
    }
    tail_offset(node_bytes)
}

/// The conformance-strictness policy a read applies: a threshold over [`Severity`].
///
/// Robustness (bounds-checking, never-panic) is unconditional and not governed by
/// this; the policy decides only where the fatal line sits on the anomaly severity
/// scale.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReadPolicy {
    /// Fatal at [`Severity::Conformance`] and above: the read fails on anything a
    /// conformant ext4 would not carry, so what a strict read returns is a filesystem
    /// whose every field it recognized.
    #[default]
    Strict,
    /// Fatal at nothing: a lenient read collects every [`Anomaly`] as structured data
    /// and rejects no image, so a malformed image is reported rather than refused.
    /// This is the reading a whole-image [`scan`](Reader::scan) reports under.
    Lenient,
}

impl ReadPolicy {
    /// Whether an anomaly of this severity is fatal under the policy.
    #[must_use]
    pub fn is_fatal(self, severity: Severity) -> bool {
        match self {
            ReadPolicy::Strict => severity >= Severity::Conformance,
            ReadPolicy::Lenient => false,
        }
    }
}

/// A failure reading an image.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The underlying source could not be read or sought.
    ///
    /// The `kind` is [`std::io::Error`]'s own classification, carried separately because
    /// it is what a caller acts on: a truncated image
    /// ([`UnexpectedEof`](std::io::ErrorKind::UnexpectedEof)) is a property of the image
    /// being examined, while a permission failure
    /// ([`PermissionDenied`](std::io::ErrorKind::PermissionDenied)) is a property of the
    /// environment, and telling them apart should not require matching on the message.
    ///
    /// It does not appear in the rendered message because the message already says it:
    /// `message` is the underlying error rendered by [`std::io::Error`], which opens with
    /// the kind's own description. The field is the machine-readable half of a fact the
    /// text already carries.
    #[error("i/o error: {message}")]
    #[non_exhaustive]
    Io {
        /// How the underlying [`std::io::Error`] classified itself.
        kind: std::io::ErrorKind,
        /// The error rendered as text, for a message a person reads.
        message: String,
    },
    /// A structure failed to parse.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// A block or inode reference pointed outside the image.
    #[error("reference to {what} {index} is out of range")]
    #[non_exhaustive]
    OutOfRange {
        /// What was referenced (a block or an inode).
        what: &'static str,
        /// The offending index.
        index: u64,
    },
    /// An inode number was zero or beyond the filesystem's inode count.
    #[error("inode {inode} does not exist")]
    #[non_exhaustive]
    NoSuchInode {
        /// The inode number that does not exist.
        inode: u32,
    },
    /// An extent tree was deeper than the reader follows, or malformed.
    #[error("extent tree is too deep or malformed")]
    BadExtentTree,
    /// A directory block or its hash-tree index was malformed: a zero-length record,
    /// an entry running past the block, or a tree deeper than the reader follows.
    #[error("directory structure is malformed")]
    BadDirectory,
    /// The journal inode or its jbd2 superblock was malformed.
    #[error("journal structure is malformed")]
    BadJournal,
    /// The orphan file was malformed: the feature is set but no inode holds the file, the
    /// file claims more blocks than the filesystem has (it is a fixed array of entry
    /// blocks, so it is never sparse), or one of its blocks does not end in the orphan
    /// magic word.
    #[error("orphan file structure is malformed")]
    BadOrphanFile,
    /// The superblock advertises an `incompat` feature this reader does not interpret —
    /// an unknown extension, or `meta_bg`. Such a feature may change the on-disk format
    /// in ways that make unaware access unsafe, so a strict read refuses it at open. The
    /// anomaly this projects to names the features; the bare error carries the bits.
    #[error(
        "unsupported incompatible feature bits {bits:#010x}: the reader cannot be certain \
         it interprets the on-disk format correctly"
    )]
    #[non_exhaustive]
    UnsupportedIncompat {
        /// The unsupported `incompat` bits: the feature word with every bit this reader
        /// interprets cleared.
        bits: u32,
    },
    /// An inode carries the extent-format flag, but the superblock does not enable the
    /// `extent` feature, so the two disagree about how the inode maps its blocks. This is
    /// the incoherence `e2fsck` reports as "inode is in extent format, but superblock is
    /// missing EXTENTS feature".
    #[error(
        "inode {inode} is in extent format, but the superblock does not enable the \
         extent feature"
    )]
    #[non_exhaustive]
    ExtentFlagWithoutFeature {
        /// The inode carrying the extent-format flag.
        inode: u32,
    },
    /// An inode names an external extended-attribute block (`i_file_acl`), but the
    /// superblock does not enable the `ext_attr` feature, so the feature word says the
    /// filesystem holds no attributes while an inode points at a block of them. This is
    /// the incoherence `e2fsck` reports as "i_file_acl for inode N is B, should be zero".
    #[error(
        "inode {inode} names attribute block {block}, but the superblock does not enable \
         the ext_attr feature"
    )]
    #[non_exhaustive]
    XattrBlockWithoutFeature {
        /// The inode naming the block.
        inode: u32,
        /// The block it names.
        block: u64,
    },
    /// A regular file is [`LARGE_FILE_MIN_SIZE`] or
    /// larger, but the superblock does not enable the `large_file` feature that describes
    /// such a file. This is the incoherence `e2fsck` reports as "filesystem contains large
    /// files, but lacks LARGE_FILE flag in superblock". The bound is on regular files
    /// alone: a directory of any size leaves the feature unneeded.
    #[error(
        "inode {inode} is a {size}-byte regular file, but the superblock does not enable \
         the large_file feature"
    )]
    #[non_exhaustive]
    LargeFileWithoutFeature {
        /// The inode holding the file.
        inode: u32,
        /// Its size in bytes.
        size: u64,
    },
    /// A directory carries the hash-index flag, but the superblock does not enable the
    /// `dir_index` feature that permits one. This is the incoherence `e2fsck` reports as
    /// "inode N has INDEX_FL flag set on filesystem without htree support".
    #[error(
        "inode {inode} is marked hash-indexed, but the superblock does not enable the \
         dir_index feature"
    )]
    #[non_exhaustive]
    IndexFlagWithoutFeature {
        /// The directory inode carrying the hash-index flag.
        inode: u32,
    },
    /// An inode that is not a directory carries the hash-index flag, which describes how a
    /// directory's blocks are organized and means nothing on anything else. This is the
    /// incoherence `e2fsck` reports as "inode N has INDEX_FL flag set but is not a
    /// directory".
    ///
    /// It is a separate fault from [`IndexFlagWithoutFeature`](Self::IndexFlagWithoutFeature),
    /// which is a directory whose flag the superblock's feature words deny. An inode can
    /// carry both faults, and each names a different thing to fix.
    #[error("inode {inode} is marked hash-indexed, but it is not a directory")]
    #[non_exhaustive]
    IndexFlagOnNonDirectory {
        /// The inode carrying the hash-index flag.
        inode: u32,
    },
    /// A group descriptor places a bitmap or inode table outside the group it belongs to
    /// on a filesystem without `flex_bg`, where each group's metadata must lie within it.
    /// This is the corruption `e2fsck` reports as "block bitmap for group N is not in
    /// group".
    #[error("{what} for group {group} lies at block {block}, outside the group")]
    #[non_exhaustive]
    MetadataOutsideGroup {
        /// The metadata that is out of place (`block bitmap`, `inode bitmap`, or `inode
        /// table`).
        what: &'static str,
        /// The group whose descriptor named it.
        group: u32,
        /// The block it was placed at.
        block: u64,
    },
    /// A path named no entry in the filesystem.
    #[error("no such path: {}", String::from_utf8_lossy(path))]
    #[non_exhaustive]
    NotFound {
        /// The path that named no entry.
        path: Vec<u8>,
    },
    /// A path used something that is not a directory as one.
    #[error("not a directory: {}", String::from_utf8_lossy(path))]
    #[non_exhaustive]
    NotADirectory {
        /// The path whose component is not a directory.
        path: Vec<u8>,
    },
    /// Resolving a path followed more symbolic links than the reader will, which a cycle
    /// (`a -> b -> a`) and a chain long enough to be a denial of service both produce.
    #[error("too many symbolic links resolving: {}", String::from_utf8_lossy(path))]
    #[non_exhaustive]
    SymlinkLoop {
        /// The path whose resolution ran out of link budget.
        path: Vec<u8>,
    },
    /// A tree holds more names than a walk is bounded to gather.
    ///
    /// The bound is the smaller of [`Limits::max_walk_entries`] and the number of names
    /// the source has room to describe. A well-formed filesystem never reaches the second,
    /// so this names either a caller's own cap or an image whose directories share blocks
    /// to describe more names than they hold.
    #[error("the tree holds more than {limit} names, the bound this walk is held to")]
    #[non_exhaustive]
    WalkTooLarge {
        /// The bound that was reached.
        limit: usize,
    },
    /// A whole-file read was asked for a file larger than [`Limits::max_file_bytes`], the
    /// cap the caller set on it.
    ///
    /// The bound is the caller's alone — no structural bound exists behind it, since a
    /// legitimate all-hole file and a crafted `i_size` are the same shape from the outside.
    /// Reaching it is an error rather than a short buffer for the same reason
    /// [`WalkTooLarge`](Self::WalkTooLarge) is: a caller extracting a file from a truncated
    /// read would write an incomplete one and see success. To read part of a file
    /// deliberately, use [`Reader::read_into`], which is bounded by the buffer given to it
    /// and reports how much it filled.
    #[error("the file is {size} bytes, more than the {limit}-byte cap this read is held to")]
    #[non_exhaustive]
    FileTooLarge {
        /// The file's logical size, as its inode declares it.
        size: u64,
        /// The cap that was exceeded.
        limit: u64,
    },
    /// A metadata object's stored checksum did not match its recomputed value.
    #[error("{object} {index} checksum mismatch: stored {stored:#010x}, computed {computed:#010x}")]
    #[non_exhaustive]
    ChecksumMismatch {
        /// The kind of object that failed (`superblock`, `group descriptor`, `inode`,
        /// `extent node`, `block bitmap`, `inode bitmap`, `directory block`,
        /// `xattr block`, or `orphan block`).
        object: &'static str,
        /// The object's index (group, inode, or block number; zero for the
        /// superblock).
        index: u64,
        /// The checksum stored on disk.
        stored: u32,
        /// The checksum recomputed from the object's bytes.
        computed: u32,
    },
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

impl ReadError {
    /// Classify this error as a typed [`Anomaly`]: its severity, subsystem, and
    /// location. A strict read fails on the first such anomaly; this projection is
    /// what a lenient read would collect instead.
    #[must_use]
    pub fn anomaly(&self) -> Anomaly {
        let (severity, category, location) = match self {
            // The source itself failed: nothing could be parsed, so it is structural.
            ReadError::Io { .. } => (
                Severity::Structural,
                Category::Superblock,
                Location::default(),
            ),
            // A parse failure is reported against the object that failed to parse. The
            // structure name each `ParseError` carries is what names it; defaulting to
            // the superblock would file a malformed inode under the one object the
            // image demonstrably got right.
            ReadError::Parse(e) => (
                Severity::Structural,
                parse_category(parse_structure(e)),
                Location::default(),
            ),
            ReadError::OutOfRange { what, index } => {
                let category = if *what == "inode" {
                    Category::Inode
                } else if *what == "group" {
                    Category::GroupDescriptor
                } else {
                    Category::Superblock
                };
                let location = match *what {
                    "block" => Location {
                        block: Some(*index),
                        ..Location::default()
                    },
                    "inode" => Location {
                        inode: Some(*index as u32),
                        ..Location::default()
                    },
                    "group" => Location {
                        group: Some(*index as u32),
                        ..Location::default()
                    },
                    _ => Location::default(),
                };
                (Severity::Structural, category, location)
            }
            ReadError::NoSuchInode { inode: n } => (
                Severity::Structural,
                Category::Inode,
                Location {
                    inode: Some(*n),
                    ..Location::default()
                },
            ),
            ReadError::BadExtentTree => (
                Severity::Structural,
                Category::ExtentTree,
                Location::default(),
            ),
            ReadError::BadDirectory => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            ReadError::BadJournal => (Severity::Structural, Category::Journal, Location::default()),
            ReadError::BadOrphanFile => {
                (Severity::Structural, Category::Orphan, Location::default())
            }
            // Path resolution failures are about the directory tree, and arise only from
            // a lookup: a whole-image scan resolves no paths.
            // A bound reached is a fact about the walk, not about the image's soundness
            // — a caller's own cap reaches it too — so it is filed as a structural
            // finding about the directory tree it stopped in.
            ReadError::WalkTooLarge { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            // The same reasoning one object down: a cap the caller set is not a fault in
            // the image, but the read it stopped could not be completed, so it is filed
            // against the inode whose size exceeded it.
            ReadError::FileTooLarge { .. } => {
                (Severity::Structural, Category::Inode, Location::default())
            }
            ReadError::NotFound { .. }
            | ReadError::NotADirectory { .. }
            | ReadError::SymlinkLoop { .. } => (
                Severity::Structural,
                Category::Directory,
                Location::default(),
            ),
            ReadError::ChecksumMismatch { object, index, .. } => {
                let (category, location) = match *object {
                    "superblock" => (Category::Superblock, Location::default()),
                    "group descriptor" => (
                        Category::GroupDescriptor,
                        Location {
                            group: Some(*index as u32),
                            ..Location::default()
                        },
                    ),
                    "inode" => (
                        Category::Inode,
                        Location {
                            inode: Some(*index as u32),
                            ..Location::default()
                        },
                    ),
                    "extent node" => (
                        Category::ExtentTree,
                        Location {
                            block: Some(*index),
                            ..Location::default()
                        },
                    ),
                    "block bitmap" | "inode bitmap" => (
                        Category::Bitmap,
                        Location {
                            group: Some(*index as u32),
                            ..Location::default()
                        },
                    ),
                    "directory block" => (
                        Category::Directory,
                        Location {
                            block: Some(*index),
                            ..Location::default()
                        },
                    ),
                    "xattr block" => (
                        Category::Xattr,
                        Location {
                            block: Some(*index),
                            ..Location::default()
                        },
                    ),
                    "orphan block" => (
                        Category::Orphan,
                        Location {
                            block: Some(*index),
                            ..Location::default()
                        },
                    ),
                    _ => (Category::Superblock, Location::default()),
                };
                (Severity::Integrity, category, location)
            }
            // An `incompat` feature the reader does not follow means it cannot vouch for
            // the whole image, so it is structural and filed against the superblock that
            // advertised it.
            ReadError::UnsupportedIncompat { .. } => (
                Severity::Structural,
                Category::Superblock,
                Location::default(),
            ),
            ReadError::ExtentFlagWithoutFeature { inode } => (
                Severity::Structural,
                Category::Inode,
                Location {
                    inode: Some(*inode),
                    ..Location::default()
                },
            ),
            // A pointer at a block the feature word denies: the reader cannot be certain
            // what that block holds, so it is structural, and it is the attribute
            // subsystem the pointer claims to belong to.
            ReadError::XattrBlockWithoutFeature { inode, block } => (
                Severity::Structural,
                Category::Xattr,
                Location {
                    inode: Some(*inode),
                    block: Some(*block),
                    ..Location::default()
                },
            ),
            // The size and the index are read correctly either way; what is missing is the
            // feature word that should advertise them. Both are conformance deviations —
            // valid ext4 as bytes, not as a self-consistent filesystem.
            ReadError::LargeFileWithoutFeature { inode, .. } => (
                Severity::Conformance,
                Category::Inode,
                Location {
                    inode: Some(*inode),
                    ..Location::default()
                },
            ),
            ReadError::IndexFlagWithoutFeature { inode } => (
                Severity::Conformance,
                Category::Directory,
                Location {
                    inode: Some(*inode),
                    ..Location::default()
                },
            ),
            // The flag on a non-directory is a fact about that inode, not about any
            // directory tree, so it is filed against the inode.
            ReadError::IndexFlagOnNonDirectory { inode } => (
                Severity::Conformance,
                Category::Inode,
                Location {
                    inode: Some(*inode),
                    ..Location::default()
                },
            ),
            ReadError::MetadataOutsideGroup {
                what, group, block, ..
            } => {
                // A bitmap out of place is the bitmap subsystem's; a misplaced inode table
                // is the group descriptor's, which is what positions it.
                let category = if what.ends_with("bitmap") {
                    Category::Bitmap
                } else {
                    Category::GroupDescriptor
                };
                (
                    Severity::Structural,
                    category,
                    Location {
                        group: Some(*group),
                        block: Some(*block),
                        ..Location::default()
                    },
                )
            }
        };
        // The unsupported-feature anomaly names the features it found; every other
        // anomaly's detail is its own message.
        let detail = match self {
            ReadError::UnsupportedIncompat { bits } => describe_unsupported_incompat(*bits),
            _ => self.to_string(),
        };
        Anomaly {
            severity,
            category,
            location,
            detail,
        }
    }
}

/// The result of a whole-image [`scan`](Reader::scan): every [`Anomaly`] the scan
/// found, in the order it walked them — the superblock, then each group descriptor,
/// then each in-use inode and its extent tree.
///
/// A lenient read rejects no image, so an empty report means the image is
/// byte-conformant to what this crate emits and a non-empty one is a list of
/// findings, not a failure. [`has_fatal`](Self::has_fatal) applies a [`ReadPolicy`]
/// threshold back to those findings, and [`to_json`](Self::to_json) /
/// [`to_table`](Self::to_table) project them for a machine or a person.
///
/// A report holds at most [`Limits::max_anomalies`] findings and says so through
/// [`is_truncated`](Self::is_truncated) when it stopped there.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScanReport {
    anomalies: Vec<Anomaly>,
    truncated: bool,
    /// The findings cap the scan that produced this report ran under — the
    /// [`Limits::max_anomalies`] it was opened with, which a caller may set to anything.
    /// Kept so a truncation notice names the bound that actually applied rather than the
    /// default constant, which need not be the same number.
    ///
    /// It is not serialized: the cap is a property of the scan that ran, not of the
    /// report's findings, and `truncated` already says whether it was reached.
    #[cfg_attr(feature = "serde", serde(skip))]
    cap: usize,
}

impl Default for ScanReport {
    /// An empty report from a scan under the default limits.
    fn default() -> Self {
        Self {
            anomalies: Vec::new(),
            truncated: false,
            cap: Self::MAX_ANOMALIES,
        }
    }
}

impl ScanReport {
    /// The default of [`Limits::max_anomalies`]: the most findings one report holds
    /// unless a caller names another cap.
    ///
    /// A scan reads an image it has no reason to trust, and how many findings that image
    /// yields is the image's own claim: a handful of crafted inodes can name the same
    /// blocks over and over, and each faulty block is a finding carrying an owned
    /// description. The cap is what keeps a report's memory a property of this crate
    /// rather than of the bytes it was pointed at, and it is far past the count anyone
    /// reads: a filesystem with ten thousand findings is diagnosed by its first ten.
    pub const MAX_ANOMALIES: usize = 10_000;

    /// The anomalies found, in scan order.
    #[must_use]
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Whether the scan stopped at its findings cap with the image still unfinished.
    ///
    /// A truncated report is a floor, not a full accounting: the image holds at least
    /// these findings, and the scan did not look at the rest of it. Everything derived
    /// from the report — [`worst_severity`](Self::worst_severity),
    /// [`has_fatal`](Self::has_fatal) — is likewise a floor, and
    /// [`is_clean`](Self::is_clean) is `false` whatever the report holds, since a scan
    /// that stopped short has seen nothing that would let it call an image clean.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the scan looked at the whole image and found nothing.
    ///
    /// A [`truncated`](Self::is_truncated) report is never clean, however few findings it
    /// holds. The cap can be set low enough that a scan stops before reporting anything —
    /// at zero, before reading a single group — and an empty report from a scan that
    /// stopped is an absence of looking, not an absence of faults.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.truncated && self.anomalies.is_empty()
    }

    /// The severity of the most serious anomaly, or `None` when the report is clean.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }

    /// Whether any anomaly the scan found is fatal under `policy` — the same threshold
    /// [`ReadPolicy::Strict`] enforces when opening an image. Under
    /// [`ReadPolicy::Lenient`] it is always `false`.
    ///
    /// This is the scan's verdict, which is not the whole of a strict read. A scan
    /// checks the metadata a strict read checks — feature support, every checksum, and
    /// structural placement — but it does not parse every directory entry or follow
    /// every path, so a fault only a full read reaches (a malformed directory block on
    /// an image that carries no checksum to catch it, say) leaves the scan clean while
    /// the read that reaches it still fails.
    #[must_use]
    pub fn has_fatal(&self, policy: ReadPolicy) -> bool {
        self.anomalies.iter().any(|a| policy.is_fatal(a.severity))
    }

    /// Render the report as a JSON object: `clean` (bool), `count`, `truncated` (bool),
    /// and an `anomalies` array of [`Anomaly::to_json`] records. A projection computed
    /// here, not a stored wire format.
    ///
    /// `truncated` is always present, true or false: a consumer must be able to tell a
    /// complete report from one that stopped at its findings cap, and an absent field
    /// would read as complete.
    ///
    /// The document opens with `"schema"`, holding [`SCAN_SCHEMA_VERSION`]. A downstream
    /// parser has a contract that no Rust signature describes, so the emitted shape names
    /// its own version rather than leaving a change to be discovered by a parse failure.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"schema\":");
        out.push_str(&SCAN_SCHEMA_VERSION.to_string());
        out.push_str(",\"clean\":");
        out.push_str(if self.is_clean() { "true" } else { "false" });
        out.push_str(",\"count\":");
        out.push_str(&self.anomalies.len().to_string());
        out.push_str(",\"truncated\":");
        out.push_str(if self.truncated { "true" } else { "false" });
        out.push_str(",\"anomalies\":[");
        for (i, a) in self.anomalies.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&a.to_json());
        }
        out.push_str("]}");
        out
    }

    /// Render the report as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log: a
    /// single run whose tool is this reader and whose results are the anomalies, one per
    /// finding, for a static-analysis or forensic pipeline that speaks SARIF.
    ///
    /// Severity maps onto SARIF's three actionable levels — `structural` and `integrity`
    /// are `error`, `conformance` is `warning`, `cosmetic` is `note` — and the exact
    /// severity, subsystem, and block/group/inode coordinates ride in each result's
    /// `properties`, so nothing the level collapse would lose is lost. The block/group/inode
    /// address becomes a SARIF logical location. Like [`to_json`](Self::to_json), the
    /// document is a pure function of the report — no tool version or timestamp enters it —
    /// so identical findings render identical bytes.
    ///
    /// A report that stopped at its findings cap carries a warning-level
    /// `toolExecutionNotifications` entry saying so, naming the cap that applied, which is
    /// where SARIF records something about the run rather than about the artifact. A
    /// complete report emits no `invocations` at all, so the document a clean or short
    /// scan renders is unchanged by the cap existing.
    ///
    /// `artifact_uri`, when set, becomes each result's physical artifact location: the
    /// reader reads an anonymous stream, so the image's identity is the caller's to supply.
    /// It is written through unchanged, which makes it a precondition that the string is
    /// already a URI reference as [RFC 3986] defines one. A host path is not: a space is
    /// not allowed in a URI at all, and `#`, `?`, and `%` each mean something else, so a
    /// strict SARIF consumer rejects a document carrying one. Percent-encode a path — every
    /// byte outside `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, `~`, keeping `/` — before
    /// passing it here.
    ///
    /// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986
    #[must_use]
    pub fn to_sarif(&self, artifact_uri: Option<&str>) -> String {
        let mut out = String::from(
            "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
             \"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"ferrosys\",\"rules\":[",
        );
        push_sarif_rules(&mut out, &self.anomalies);
        out.push_str("]}},\"results\":[");
        for (i, a) in self.anomalies.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_sarif_result(&mut out, a, artifact_uri);
        }
        out.push(']');
        if self.truncated {
            // `executionSuccessful` is required of an invocation: the scan did run to the
            // cap, so it succeeded — the notification is what says the results stop short
            // of the image.
            out.push_str(
                ",\"invocations\":[{\"executionSuccessful\":true,\
                 \"toolExecutionNotifications\":[{\"level\":\"warning\",\"message\":{\"text\":",
            );
            push_json_string(&mut out, &self.truncation_notice());
            out.push_str("}}]}]");
        }
        out.push_str("}]}");
        out
    }

    /// Render the report as a fixed-column human table: a header row, then one line
    /// per anomaly with its severity, category, location, and detail. A clean report
    /// renders a single `no anomalies` line.
    ///
    /// A [`truncated`](Self::is_truncated) report ends with the notice saying so, whether
    /// or not it holds findings — an empty one is the case where saying so matters most,
    /// since `no anomalies` on its own would read as a verdict the scan never reached.
    #[must_use]
    pub fn to_table(&self) -> String {
        if self.anomalies.is_empty() {
            let mut out = String::from("no anomalies\n");
            if self.truncated {
                out.push('\n');
                out.push_str(&self.truncation_notice());
                out.push('\n');
            }
            return out;
        }
        let rows: Vec<(&str, &str, String, &str)> = self
            .anomalies
            .iter()
            .map(|a| {
                (
                    a.severity.as_str(),
                    a.category.as_str(),
                    location_compact(&a.location),
                    a.detail.as_str(),
                )
            })
            .collect();
        let mut sev_w = "SEVERITY".len();
        let mut cat_w = "CATEGORY".len();
        let mut loc_w = "LOCATION".len();
        for (s, c, l, _) in &rows {
            sev_w = sev_w.max(s.len());
            cat_w = cat_w.max(c.len());
            loc_w = loc_w.max(l.len());
        }
        let mut out = format!(
            "{:<sev_w$}  {:<cat_w$}  {:<loc_w$}  {}\n",
            "SEVERITY", "CATEGORY", "LOCATION", "DETAIL"
        );
        for (s, c, l, d) in &rows {
            out.push_str(&format!("{s:<sev_w$}  {c:<cat_w$}  {l:<loc_w$}  {d}\n"));
        }
        if self.truncated {
            out.push('\n');
            out.push_str(&self.truncation_notice());
            out.push('\n');
        }
        out
    }

    /// The one sentence a truncated report renders, in whichever projection asks for it.
    ///
    /// It names the cap the scan actually ran under, which is a caller's
    /// [`Limits::max_anomalies`] and not necessarily
    /// [`MAX_ANOMALIES`](Self::MAX_ANOMALIES): a report that stopped at seven findings
    /// because seven is what was asked for must not say it stopped at ten thousand.
    fn truncation_notice(&self) -> String {
        format!(
            "report truncated at {} anomalies; the rest of the image was not scanned",
            self.cap
        )
    }
}

/// One resolved directory entry: a name and the inode it points at.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Entry {
    /// Entry name.
    pub name: Vec<u8>,
    /// Inode the name points at.
    pub inode: u32,
    /// File type recorded in the entry.
    pub file_type: FileType,
}

/// One name a [`walk`](Reader::walk) reached: its path, the inode number the name
/// points at, and that inode.
///
/// The number is what distinguishes a name from the file it names. Two paths sharing an
/// inode are two names for one file — a hard link — and nothing in the inode itself says
/// which other paths those are, so a consumer reconstructing the links (writing an
/// archive, counting the bytes a tree occupies) needs the number to tell one file with
/// two names from two files with identical contents.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct WalkEntry {
    /// Absolute path from the filesystem root, `/`-joined, always beginning with `/`.
    pub path: Vec<u8>,
    /// The inode number the name points at.
    pub number: u32,
    /// The inode itself.
    pub inode: Inode,
}

/// A read-only handle over an ext4 image on any [`Read`] + [`Seek`] source.
///
/// The filesystem may sit at an arbitrary byte offset within the source — a partition
/// inside a whole-disk image — fixed at open time. Reads seek relative to that offset
/// and return owned buffers, so nothing is borrowed from the source between calls.
pub struct Reader<R> {
    src: R,
    base: u64,
    sb: SuperBlock,
    /// The superblock exactly as it sits on disk.
    ///
    /// A checksum covers the bytes an object *has*, not the bytes this crate's model of
    /// it can reproduce. The superblock carries fields no formatter is obliged to leave
    /// zero and this crate does not model — the kernel's error record, the last-orphan
    /// pointer, the mount options — and recomputing its checksum from a re-serialized
    /// [`SuperBlock`] silently zeroes every one of them. That verifies only images this
    /// crate wrote, and rejects healthy ones it did not. So the raw bytes are kept, and
    /// the checksum is computed over them.
    sb_raw: Vec<u8>,
    feature: FeatureSet,
    block_size: usize,
    policy: ReadPolicy,
    limits: Limits,
    csum_seed: Option<u32>,
}

/// How a filesystem is opened: where it begins, how strictly it is read, what it may
/// allocate, and which checksum seed its metadata is verified against.
///
/// Every input to [`Reader::open_with`] is a field here rather than a parameter, so a
/// knob the reader grows arrives as a field a caller may ignore.
///
/// ```
/// # use ferrosys::ext::{OpenOptions, ReadPolicy, Reader};
/// # let image: Vec<u8> = Vec::new();
/// // A filesystem inside a partition, read leniently so a scan can describe what is
/// // wrong with it rather than the open refusing it.
/// let options = OpenOptions::new().base(1 << 20).policy(ReadPolicy::Lenient);
/// # let _ = options;
/// # let _ = image;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Byte offset within the source at which the filesystem begins — zero for a bare
    /// image, the partition's start for one inside a disk image. Every read the reader
    /// makes is relative to it.
    pub base: u64,
    /// How strictly the image is held to the format. Defaults to
    /// [`ReadPolicy::Strict`].
    pub policy: ReadPolicy,
    /// Caps on what one read may allocate, over and above the structural bounds the
    /// reader always applies.
    pub limits: Limits,
    /// The `metadata_csum` seed to verify against, overriding the one the image implies.
    ///
    /// A filesystem's checksums are computed from a seed: the value stored in the
    /// superblock when `metadata_csum_seed` is set, and one derived from the UUID
    /// otherwise. Naming a seed here is for the image whose stored seed and UUID
    /// disagree — a UUID changed after the fact — where the checksums are valid against
    /// a seed the image no longer implies. `None`, the default, uses the image's own.
    pub csum_seed: Option<u32>,
}

impl OpenOptions {
    /// Open at the start of the source, strictly, with the default limits and the
    /// image's own checksum seed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: 0,
            policy: ReadPolicy::Strict,
            limits: Limits::new(),
            csum_seed: None,
        }
    }

    /// Open a filesystem that begins `base` bytes into the source.
    #[must_use]
    pub const fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    /// Read under `policy`.
    #[must_use]
    pub const fn policy(mut self, policy: ReadPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Cap what one read may allocate.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Verify metadata checksums against `seed` rather than the one the image implies.
    #[must_use]
    pub const fn csum_seed(mut self, seed: u32) -> Self {
        self.csum_seed = Some(seed);
        self
    }
}

/// Caps on what one read of an untrusted image may allocate.
///
/// **These are caller-imposed caps on top of bounds the reader applies regardless.** A
/// count or size field in an image is the image's own claim, so every read that
/// allocates from one is bounded by what the source could actually hold: a file cannot
/// be larger than the filesystem containing it, and a tree cannot hold more names than
/// its blocks have room for. Those structural bounds are always on and cannot reject a
/// well-formed filesystem, because a well-formed filesystem satisfies them by
/// construction.
///
/// What is left for a caller is a *tighter* bound than the structure implies — reading a
/// 9 TiB image with a gigabyte of memory, say — and one read where no structural bound
/// exists at all ([`max_file_bytes`](Self::max_file_bytes)). The defaults impose none, so
/// a legitimate image of any size reads back at the default settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// The most findings one [`scan`](Reader::scan) reports before stopping and marking
    /// its report [`truncated`](ScanReport::is_truncated). Defaults to
    /// [`ScanReport::MAX_ANOMALIES`].
    pub max_anomalies: usize,
    /// The most entries one [`walk`](Reader::walk) gathers before refusing with
    /// [`ReadError::WalkTooLarge`]. Defaults to no caller-imposed cap; the walk is bounded
    /// regardless by the names the image's blocks have room to hold.
    pub max_walk_entries: usize,
    /// The largest file a whole-file read will read. Defaults to no cap, which is the
    /// documented contract: [`read_data`](Reader::read_data) trusts `i_size`.
    ///
    /// A file larger than this is [`ReadError::FileTooLarge`], not a shortened buffer. The
    /// three caps here agree on that shape wherever a short answer could be mistaken for a
    /// whole one: a walk that reached its bound errors, a read that reached this one errors,
    /// and only a scan — whose report says [`is_truncated`](ScanReport::is_truncated) in
    /// the document it emits — returns what it managed to gather. A caller extracting a
    /// file from a truncated read would otherwise write an incomplete one and see success.
    ///
    /// It bounds both whole-file forms, [`read_data`](Reader::read_data) and
    /// [`read_data_to`](Reader::read_data_to), because what it expresses is distrust of the
    /// declared size rather than a memory bound. To read part of a file deliberately, use
    /// [`read_into`](Reader::read_into): it is bounded by the buffer the caller supplies —
    /// mapping included — and reports how much of it was filled, so a partial read is
    /// representable rather than silent.
    ///
    /// This one has no structural bound behind it, and that is a property of the format
    /// rather than an omission. A sparse file's holes cost no blocks, so a file whose
    /// logical size dwarfs the filesystem holding it is well-formed and must read back at
    /// its full size — which makes a legitimate all-hole file indistinguishable from a
    /// crafted `i_size`. Set this when reading an image that has not earned that trust,
    /// or use [`scan`](Reader::scan), which allocates nothing per logical block.
    pub max_file_bytes: u64,
}

impl Limits {
    /// No caller-imposed cap beyond the structural bounds the reader always applies,
    /// except on findings, which stop at [`ScanReport::MAX_ANOMALIES`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_anomalies: ScanReport::MAX_ANOMALIES,
            max_walk_entries: usize::MAX,
            max_file_bytes: u64::MAX,
        }
    }

    /// Report at most `max` findings per scan.
    #[must_use]
    pub const fn max_anomalies(mut self, max: usize) -> Self {
        self.max_anomalies = max;
        self
    }

    /// Refuse a walk that would gather more than `max` entries.
    #[must_use]
    pub const fn max_walk_entries(mut self, max: usize) -> Self {
        self.max_walk_entries = max;
        self
    }

    /// Return at most `max` bytes per file read.
    #[must_use]
    pub const fn max_file_bytes(mut self, max: u64) -> Self {
        self.max_file_bytes = max;
        self
    }
}

impl Default for Limits {
    /// The limits in [`Limits::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Read + Seek> Reader<R> {
    /// Open a filesystem at the start of `src` under the default [`OpenOptions`].
    ///
    /// # Errors
    ///
    /// [`ReadError::Parse`] if the superblock's magic is wrong; [`ReadError::Io`] if
    /// the source cannot be read; [`ReadError::UnsupportedIncompat`] if it advertises an
    /// `incompat` feature this reader does not follow (the default policy is strict).
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open a filesystem under `options`: where in `src` it begins, how strictly to read
    /// it, what it may allocate, and which checksum seed to verify against.
    ///
    /// # Errors
    ///
    /// [`ReadError::Parse`] if the superblock's magic is wrong; [`ReadError::Io`] if
    /// the source cannot be read or sought (a source too short to hold a superblock
    /// among them); [`ReadError::UnsupportedIncompat`] if it advertises an `incompat`
    /// feature this reader does not follow and the policy is [`ReadPolicy::Strict`]. A
    /// lenient open accepts such an image so a [`scan`](Self::scan) can report it.
    pub fn open_with(mut src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let &OpenOptions {
            base,
            policy,
            limits,
            csum_seed,
        } = options;
        // The primary superblock is 1024 bytes into the filesystem. A `base` a caller
        // pushed near the top of the 64-bit range cannot overflow into a small seek: the
        // sum is checked, and an offset that leaves no room for a superblock is reported
        // as out of range rather than wrapped.
        let sb_offset = base.checked_add(1024).ok_or(ReadError::OutOfRange {
            what: "bytes",
            index: base,
        })?;
        src.seek(SeekFrom::Start(sb_offset))?;
        let mut sb_bytes = vec![0u8; SuperBlock::SIZE];
        src.read_exact(&mut sb_bytes)?;
        let mut sb = SuperBlock::read_from(&sb_bytes)?;
        // A revision-0 filesystem predates the fields that describe an inode's size and
        // the first inode a file may use: the words hold zero and the values are fixed
        // by the revision — the 128-byte classic inode, and inode 11. Resolving them
        // here is what lets the rest of the reader treat every revision alike, and it is
        // the resolved value a caller sees. The raw bytes the checksum covers are kept
        // separately, so this does not disturb it.
        if sb.rev_level == 0 {
            sb.inode_size = GOOD_OLD_INODE_SIZE as u16;
            sb.first_ino = GOOD_OLD_FIRST_INODE;
        }
        // ext4 block sizes are 1024 << (0..=6) bytes; a larger shift value is a
        // malformed superblock, rejected rather than shifted into overflow.
        if sb.log_block_size > 6 {
            return Err(ReadError::Parse(ParseError::InvalidField {
                structure: "superblock",
                field: "s_log_block_size",
                value: u64::from(sb.log_block_size),
            }));
        }
        let block_size = 1024usize << sb.log_block_size;
        // The inode size is a power of two from 128 up to the block size; an odd value
        // such as 33-63 would give a descriptor stride the on-disk format never uses and
        // make every inode offset wrong, so it is rejected here rather than read into
        // garbage.
        if !sb.inode_size.is_power_of_two()
            || sb.inode_size < 128
            || usize::from(sb.inode_size) > block_size
        {
            return Err(ReadError::Parse(ParseError::InvalidField {
                structure: "superblock",
                field: "s_inode_size",
                value: u64::from(sb.inode_size),
            }));
        }
        let feature = FeatureSet {
            compat: crate::feature::Compat::from_bits(sb.feature_compat),
            incompat: Incompat::from_bits(sb.feature_incompat),
            ro_compat: crate::feature::RoCompat::from_bits(sb.feature_ro_compat),
            block_size: block_size as u32,
            inode_size: sb.inode_size,
        };
        // The group-descriptor size is load-bearing only under `64bit`: it sets both the
        // stride between descriptors and the width their checksum covers. Without the
        // feature the reader uses the 32-byte classic form whatever the word holds, so
        // the field is not consulted and not constrained — matching the kernel, which
        // ignores it there. Under `64bit` it must satisfy the kernel's bounds: a power of
        // two from `EXT4_MIN_DESC_SIZE_64BIT` (64) up to the block size. A 32-byte value
        // would read a 64-bit table at half its stride and check it at the wrong width; a
        // value past the block size would run each descriptor beyond its own block.
        //
        // This is also the bound [`desc_size`](Self::desc_size) rests on: it is what makes
        // every width the reader hands the on-disk layer one that layer has a form for.
        if feature.is_64bit()
            && (!sb.desc_size.is_power_of_two()
                || usize::from(sb.desc_size) < GroupDescriptor::SIZE_64
                || usize::from(sb.desc_size) > block_size)
        {
            return Err(ReadError::Parse(ParseError::InvalidField {
                structure: "superblock",
                field: "s_desc_size",
                value: u64::from(sb.desc_size),
            }));
        }
        // The `incompat` word is the one an implementation must refuse when it carries a
        // bit it does not recognize: those features change the on-disk format in ways that
        // make unaware access unsafe. A strict read refuses such an image at open; a
        // lenient read opens it so a [`scan`](Self::scan) reports the feature as an anomaly
        // rather than the open failing. `unknown_bits` on the individual words is what a
        // description still reports either way.
        let unsupported = unsupported_incompat(feature.incompat);
        if unsupported != 0 && policy.is_fatal(Severity::Structural) {
            return Err(ReadError::UnsupportedIncompat { bits: unsupported });
        }
        Ok(Self {
            src,
            base,
            sb,
            sb_raw: sb_bytes,
            feature,
            block_size,
            policy,
            limits,
            csum_seed,
        })
    }

    /// The parsed superblock.
    #[must_use]
    pub fn superblock(&self) -> &SuperBlock {
        &self.sb
    }

    /// The feature set the image advertises.
    #[must_use]
    pub fn feature(&self) -> FeatureSet {
        self.feature
    }

    /// The ext filesystem family the image's feature words classify to
    /// ([`Profile::of`]): its ext2, ext3, or ext4 label.
    #[must_use]
    pub fn profile(&self) -> Profile {
        Profile::of(self.feature)
    }

    /// The conformance-strictness policy this handle reads under.
    #[must_use]
    pub fn policy(&self) -> ReadPolicy {
        self.policy
    }

    /// Read `len` bytes at `offset` bytes into the filesystem into an owned buffer. A
    /// read that runs off the end of the source is reported as an out-of-range
    /// reference, not a raw i/o error, so callers can relabel it to the referent.
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, ReadError> {
        // A base-relative offset a malformed field pushed past the 64-bit range is an
        // out-of-range reference, not an overflow.
        let pos = self.base.checked_add(offset).ok_or(ReadError::OutOfRange {
            what: "bytes",
            index: offset,
        })?;
        self.src.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; len];
        match self.src.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(ReadError::OutOfRange {
                what: "bytes",
                index: offset,
            }),
            Err(e) => Err(ReadError::Io {
                kind: e.kind(),
                message: e.to_string(),
            }),
        }
    }

    /// The bytes of block `block`, read into an owned buffer.
    fn block(&mut self, block: u64) -> Result<Vec<u8>, ReadError> {
        let start = block
            .checked_mul(self.block_size as u64)
            .ok_or(ReadError::OutOfRange {
                what: "block",
                index: block,
            })?;
        match self.read_at(start, self.block_size) {
            Err(ReadError::OutOfRange { .. }) => Err(ReadError::OutOfRange {
                what: "block",
                index: block,
            }),
            other => other,
        }
    }

    /// Read the descriptor for group `group` from the primary descriptor table.
    ///
    /// # Errors
    ///
    /// [`ReadError::Parse`] if the descriptor cannot be read; [`ReadError::OutOfRange`]
    /// if the table does not reach it.
    pub fn group_descriptor(&mut self, group: u32) -> Result<GroupDescriptor, ReadError> {
        let raw = self.group_descriptor_raw(group)?;
        Ok(GroupDescriptor::read_from(&raw, self.desc_size())?)
    }

    /// The stride of one group descriptor on disk.
    ///
    /// `s_desc_size` describes the descriptor only under `64bit`; without that feature
    /// the field means nothing and every descriptor is the 32-byte classic form,
    /// whatever the word happens to hold. Honoring a stale 64 there would read every
    /// descriptor at the wrong offset and check it at the wrong checksum width, so the
    /// feature bit decides and the field is consulted only when it is meaningful.
    ///
    /// What bounds the `64bit` arm is [`open_with`](Self::open_with), which refuses any
    /// image whose `s_desc_size` is not a power of two from
    /// [`GroupDescriptor::SIZE_64`] up to the block size: no opened reader reaches here
    /// with a smaller one. The clamp restates that floor where the value is used, so the
    /// width handed to the on-disk layer is one it has a form for however the field was
    /// arrived at.
    fn desc_size(&self) -> usize {
        if self.feature.is_64bit() {
            debug_assert!(
                usize::from(self.sb.desc_size) >= GroupDescriptor::SIZE_64,
                "open_with admitted a 64bit image with s_desc_size {}",
                self.sb.desc_size
            );
            self.sb.desc_size.max(GroupDescriptor::SIZE_32 as u16) as usize
        } else {
            GroupDescriptor::SIZE_32
        }
    }

    /// The descriptor for group `group` exactly as it sits on disk.
    ///
    /// Its checksum covers these bytes, not a re-serialization of the parsed value, so
    /// the verifier works from them.
    fn group_descriptor_raw(&mut self, group: u32) -> Result<Vec<u8>, ReadError> {
        let desc_size = self.desc_size();
        let table = u64::from(self.sb.first_data_block) + 1;
        let off = table * self.block_size as u64 + u64::from(group) * desc_size as u64;
        match self.read_at(off, desc_size) {
            Err(ReadError::OutOfRange { .. }) => Err(ReadError::OutOfRange {
                what: "group",
                index: u64::from(group),
            }),
            other => other,
        }
    }

    /// The number of block groups, derived from the superblock geometry. Zero when
    /// the geometry is degenerate (`blocks_per_group` of zero, or a first data block
    /// past the end), so a malformed superblock yields no groups rather than a
    /// division-by-zero or underflow.
    ///
    /// It is the bound to iterate [`group_descriptor`](Self::group_descriptor) over,
    /// and the guards are why: the same derivation performed on a caller's side would
    /// divide by a zero `s_blocks_per_group` on a hostile image.
    #[must_use]
    pub fn group_count(&self) -> u32 {
        let bpg = u64::from(self.sb.blocks_per_group);
        if bpg == 0 {
            return 0;
        }
        let addressable = self
            .sb
            .blocks_count
            .saturating_sub(u64::from(self.sb.first_data_block));
        addressable.div_ceil(bpg).min(u64::from(u32::MAX)) as u32
    }

    /// The length the underlying source reports, in bytes. The forensic scan uses it
    /// to bound how far it will look, so a superblock count field a bit-flip inflated
    /// cannot drive a loop past the end of the source. An unseekable source reports
    /// zero, which bounds the scan to nothing rather than looping.
    ///
    /// This is the source's apparent length, which is the only length a `Seek` source
    /// offers: a sparse file reports the size it claims, not the blocks it occupies.
    /// The bound is therefore a real limit on how far a walk reaches, and the cost of
    /// reaching it scales with the size an image claims rather than with the bytes
    /// stored for it.
    fn source_len(&mut self) -> u64 {
        self.src.seek(SeekFrom::End(0)).unwrap_or(0)
    }

    /// The in-use inode numbers in group `g`, taken from its inode bitmap.
    ///
    /// A set bit marks an in-use inode: the reserved inodes, and every inode a
    /// directory operation has since allocated, wherever the allocator placed it. This
    /// is what a live filesystem's inodes must be enumerated from — assuming they run
    /// densely from one holds only for a freshly formatted image, and both misses an
    /// inode a `mkdir` scattered into a later group and reads a never-initialized table
    /// slot as though it held one.
    ///
    /// A group the descriptor marks `BG_INODE_UNINIT` has no inode in use and yields
    /// nothing. Bits past the group's inode count are padding, and a number past the
    /// filesystem's inode count is not an inode; both are ignored. Inodes are numbered
    /// from one, so group `g`'s first is `g * inodes_per_group + 1`. The scan reads at
    /// most one block of bitmap, so a hostile `inodes_per_group` cannot drive the bit
    /// loop past the bytes that exist.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the group descriptor or its inode bitmap cannot be
    /// read.
    fn group_in_use_inodes(&mut self, g: u32) -> Result<Vec<u32>, ReadError> {
        let desc = self.group_descriptor(g)?;
        if desc.flags & BG_INODE_UNINIT != 0 {
            return Ok(Vec::new());
        }
        let ipg = self.sb.inodes_per_group;
        let base = u64::from(g) * u64::from(ipg);
        let bmp = self.block(desc.inode_bitmap)?;
        let mut out = Vec::new();
        for i in 0..ipg {
            let byte = (i / 8) as usize;
            if byte >= bmp.len() {
                break;
            }
            if bmp[byte] & (1u8 << (i % 8)) == 0 {
                continue;
            }
            let number = base + u64::from(i) + 1;
            if number > u64::from(self.sb.inodes_count) {
                break;
            }
            out.push(number as u32);
        }
        Ok(out)
    }

    /// The crc32c the primary superblock should carry: `crc32c(!0, ..)` over the
    /// record's own bytes up to its checksum field.
    fn superblock_checksum(&self, csum: &Crc32c) -> u32 {
        csum.crc32c(!0, &self.sb_raw[..SuperBlock::SIZE - 4])
    }

    /// The 16-bit crc32c group descriptor `group` should carry: the filesystem seed
    /// folded with the group number, then the descriptor's own bytes with the checksum
    /// field zeroed.
    fn descriptor_checksum(&self, group: u32, raw: &[u8], csum: &Crc32c) -> u16 {
        let mut buf = raw.to_vec();
        // `bg_checksum` participates as zero; every other byte participates as it is,
        // including any this crate does not model.
        put_u16(&mut buf, GroupDescriptor::CHECKSUM_OFFSET, 0);
        let seed = csum.base_seed();
        let mut c = csum.crc32c(seed, &group.to_le_bytes());
        c = csum.crc32c(c, &buf);
        (c & 0xffff) as u16
    }

    /// The checksum inode `number` should carry, and the stored value to compare it
    /// against: the filesystem seed folded with the inode number and generation, then
    /// the inode's own bytes with its checksum fields zeroed.
    ///
    /// The comparison is sixteen bits wide on an inode that carries no `i_checksum_hi`
    /// — the kernel's `calculated &= 0xFFFF` — because there is no high half stored to
    /// compare a full-width value against. `mke2fs` leaves the reserved inodes in
    /// exactly that state, so on any filesystem it formatted, checking them at full
    /// width rejects seven healthy inodes.
    fn inode_checksum(&self, number: u32, raw: &[u8], csum: &Crc32c, seed: u32) -> (u32, u32) {
        let inode_size = self.sb.inode_size;
        let extra_isize = if usize::from(inode_size) > GOOD_OLD_INODE_SIZE {
            get_u16(raw, 0x80)
        } else {
            0
        };
        let has_hi = Inode::has_checksum_hi(inode_size, extra_isize);

        let mut buf = raw.to_vec();
        put_u16(&mut buf, Inode::CHECKSUM_LO_OFFSET, 0);
        let stored = {
            let lo = u32::from(get_u16(raw, Inode::CHECKSUM_LO_OFFSET));
            if has_hi {
                // The high half participates as zero only when it is a checksum field
                // at all. On an inode without one, those two bytes hold something else
                // — the head of the inline attribute region, say — and zeroing them
                // would checksum bytes the filesystem never had.
                put_u16(&mut buf, Inode::CHECKSUM_HI_OFFSET, 0);
                lo | (u32::from(get_u16(raw, Inode::CHECKSUM_HI_OFFSET)) << 16)
            } else {
                lo
            }
        };

        let mut c = csum.crc32c(seed, &number.to_le_bytes());
        c = csum.crc32c(c, &get_u32(raw, 0x64).to_le_bytes()); // i_generation
        c = csum.crc32c(c, &buf);
        let computed = if has_hi { c } else { c & 0xffff };
        (stored, computed)
    }

    /// Verify the metadata checksums the image carries: the primary superblock, every
    /// group descriptor and its block and inode bitmaps, and every in-use inode with its
    /// extent tree, directory-block tails, and external attribute block, then the
    /// journal superblock's structure.
    ///
    /// Each object's crc32c is recomputed from the bytes on disk and compared to the
    /// field the image stores, so corruption of the filesystem's own metadata is caught
    /// wherever it lies rather than surfacing later as a wrong read.
    ///
    /// This verifies *checksums*, and an image carries them only under `metadata_csum`.
    /// On an ext2 or ext3 image — or any ext4 image without the feature — there is
    /// nothing to verify and this is a no-op returning `Ok`: a clean result here means
    /// "no stored checksum disagreed," not "the image is intact." It is not a
    /// whole-image integrity gate. [`scan`](Self::scan) is that entry point — it reports
    /// structural anomalies and the jbd2 journal superblock's soundness whether or not
    /// the image checksums its metadata.
    ///
    /// # Errors
    ///
    /// [`ReadError::ChecksumMismatch`] on the first object whose stored checksum does
    /// not match its recomputed value; other [`ReadError`] variants if an object
    /// cannot be read.
    pub fn verify_checksums(&mut self) -> Result<(), ReadError> {
        if !self.feature.has_metadata_csum() {
            return Ok(());
        }
        let csum = self.checksummer();
        let seed = csum.base_seed();

        // Superblock.
        let computed = self.superblock_checksum(&csum);
        if computed != self.sb.checksum {
            return Err(ReadError::ChecksumMismatch {
                object: "superblock",
                index: 0,
                stored: self.sb.checksum,
                computed,
            });
        }

        // Every group descriptor, then its two bitmap checksums.
        for g in 0..self.group_count() {
            let raw = self.group_descriptor_raw(g)?;
            let desc = GroupDescriptor::read_from(&raw, self.desc_size())?;
            let computed = self.descriptor_checksum(g, &raw, &csum);
            if computed != desc.checksum {
                return Err(ReadError::ChecksumMismatch {
                    object: "group descriptor",
                    index: u64::from(g),
                    stored: u32::from(desc.checksum),
                    computed: u32::from(computed),
                });
            }
            self.verify_bitmap_checksums(g, &csum, seed)?;
        }

        // Every in-use inode, taken from the inode bitmaps: its checksum, its extent
        // tree, its directory tails, and its attribute block. Reading the bitmaps rather
        // than assuming inodes run densely from one finds an inode a live filesystem
        // scattered past that range and skips a never-initialized table slot, whose
        // bytes are not an inode to checksum. The examined count is capped at the inodes
        // the source can hold, so a hostile bitmap cannot drive an unbounded loop.
        let max_inodes = self.source_len() / u64::from(self.sb.inode_size.max(128));
        let mut examined = 0u64;
        'inodes: for g in 0..self.group_count() {
            for n in self.group_in_use_inodes(g)? {
                if examined >= max_inodes {
                    break 'inodes;
                }
                examined += 1;
                let raw = self.inode_raw(n)?;
                let inode = Inode::read_from(&raw, self.sb.inode_size)?;
                let (stored, computed) = self.inode_checksum(n, &raw, &csum, seed);
                if computed != stored {
                    return Err(ReadError::ChecksumMismatch {
                        object: "inode",
                        index: u64::from(n),
                        stored,
                        computed,
                    });
                }
                self.verify_extent_nodes(n, &inode, &csum)?;
                self.verify_directory_checksums(n, &inode, &csum, seed)?;
                self.verify_xattr_block_checksum(&inode, &csum, seed)?;
            }
        }
        // The journal is a structural object, not a checksummed one under the v2 log
        // this crate reads; a malformed journal superblock surfaces as its own error.
        self.journal_superblock()?;
        self.verify_orphan_blocks(&csum, seed)?;
        Ok(())
    }

    /// The checksummer this image's metadata checksums are built on.
    ///
    /// With `metadata_csum_seed` the seed is the one stored in the superblock, which is what the
    /// filesystem's checksums were computed from even if its UUID has since been
    /// changed. Without it, the seed is derived from the UUID, as ext4 does. A seed named
    /// in [`OpenOptions::csum_seed`] overrides both, for the image whose stored seed and
    /// UUID no longer agree with the checksums it carries.
    fn checksummer(&self) -> Crc32c {
        match self.csum_seed {
            Some(seed) => Crc32c::with_seed(seed),
            None if self.feature.has_csum_seed() => Crc32c::with_seed(self.sb.checksum_seed),
            None => Crc32c::new(&self.sb.uuid),
        }
    }

    /// Verify every block of the orphan file: that it ends in the orphan magic word and,
    /// where the image carries checksums, that its checksum matches. The checksum covers
    /// the block's entry array behind the file's identity and the block's own number, so
    /// two blocks holding the same entries still carry different checksums.
    ///
    /// Without `orphan_file` there is no such file and nothing to check.
    fn verify_orphan_blocks(&mut self, csum: &Crc32c, seed: u32) -> Result<(), ReadError> {
        let mut faults = Vec::new();
        self.collect_orphan_faults(csum, seed, &mut faults);
        faults.into_iter().next().map_or(Ok(()), Err)
    }

    /// Collect the faults in every block of the orphan file, rather than stopping at the
    /// first: a file with two bad blocks yields two. Each block must end in the orphan
    /// magic word and, where the image carries checksums, match its checksum, which
    /// covers the block's entry array behind the file's identity and the block's own
    /// number so two blocks holding the same entries still checksum differently. Without
    /// `orphan_file` there is no such file and nothing to check.
    fn collect_orphan_faults(&mut self, csum: &Crc32c, seed: u32, faults: &mut Vec<ReadError>) {
        if !self.feature.has_orphan_file() {
            return;
        }
        let has_csum = self.feature.has_metadata_csum();
        let ino = self.sb.orphan_file_inum;
        if ino == 0 {
            // The feature promises a file; a superblock naming no inode for it is
            // malformed rather than an empty orphan list.
            faults.push(ReadError::BadOrphanFile);
            return;
        }
        let inode = match self.inode(ino) {
            Ok(inode) => inode,
            Err(e) => {
                faults.push(e);
                return;
            }
        };
        let generation = inode.generation;
        // The orphan file is a fixed array of entry blocks, never sparse, so it cannot
        // span more blocks than the image holds. One that claims to is malformed — and
        // saying so here is what keeps a claimed size from driving the map built below.
        let bound = self.materialized_block_bound();
        if inode.size.div_ceil(self.block_size as u64) > bound {
            faults.push(ReadError::BadOrphanFile);
            return;
        }
        let blocks = match self.data_blocks(&inode) {
            Ok(blocks) => blocks,
            Err(e) => {
                faults.push(e);
                return;
            }
        };
        for phys in blocks {
            // Every block of the orphan file is materialized: it is a fixed array of
            // entry blocks, so a mapping that names none is not a sparse file.
            if phys == 0 {
                faults.push(ReadError::BadOrphanFile);
                continue;
            }
            let block = match self.block(phys) {
                Ok(block) => block,
                Err(e) => {
                    faults.push(e);
                    continue;
                }
            };
            let stored = match read_orphan_tail(&block) {
                Ok(stored) => stored,
                Err(_) => {
                    faults.push(ReadError::BadOrphanFile);
                    continue;
                }
            };
            if !has_csum {
                continue; // no checksums: the magic word is the whole of the format
            }
            let entries = &block[..orphan_entries_len(block.len())];
            let mut c = csum.crc32c(seed, &ino.to_le_bytes());
            c = csum.crc32c(c, &generation.to_le_bytes());
            c = csum.crc32c(c, &phys.to_le_bytes());
            c = csum.crc32c(c, entries);
            if c != stored {
                faults.push(ReadError::ChecksumMismatch {
                    object: "orphan block",
                    index: phys,
                    stored,
                    computed: c,
                });
            }
        }
    }

    /// Verify the checksum tail of every external node in an inode's extent tree.
    /// A tree that fits inline in the inode has no external node, so nothing to do:
    /// the inode's own checksum already covers its root.
    fn verify_extent_nodes(
        &mut self,
        ino: u32,
        inode: &Inode,
        csum: &Crc32c,
    ) -> Result<(), ReadError> {
        if !inode.flags.contains(InodeFlags::EXTENTS) {
            return Ok(());
        }
        // Every node in one inode's tree shares a seed: the filesystem seed folded
        // with the inode's number and generation.
        let mut seed = csum.crc32c(csum.base_seed(), &ino.to_le_bytes());
        seed = csum.crc32c(seed, &inode.generation.to_le_bytes());
        let mut visited = HashSet::new();
        self.verify_extent_subtree(&inode.block, 0, seed, csum, &mut visited)
    }

    fn verify_extent_subtree(
        &mut self,
        node: &[u8],
        depth: u16,
        seed: u32,
        csum: &Crc32c,
        visited: &mut HashSet<u64>,
    ) -> Result<(), ReadError> {
        if depth > MAX_EXTENT_DEPTH {
            return Err(ReadError::BadExtentTree);
        }
        let ExtentNode::Index { entries, .. } = parse_node(node)? else {
            return Ok(());
        };
        for idx in entries {
            // A child reached twice is a cyclic or fan-out tree; bound the walk.
            if !visited.insert(idx.leaf) {
                return Err(ReadError::BadExtentTree);
            }
            let child = self.block(idx.leaf)?;
            let tail = extent_tail_offset(&child, self.block_size);
            let stored = u32::from_le_bytes(
                child[tail..tail + EXTENT_TAIL_LEN]
                    .try_into()
                    .expect("tail slice is exactly EXTENT_TAIL_LEN bytes"),
            );
            let computed = csum.crc32c(seed, &child[..tail]);
            if stored != computed {
                return Err(ReadError::ChecksumMismatch {
                    object: "extent node",
                    index: idx.leaf,
                    stored,
                    computed,
                });
            }
            self.verify_extent_subtree(&child, depth + 1, seed, csum, visited)?;
        }
        Ok(())
    }

    /// Collect the group-`g` metadata a non-`flex_bg` filesystem places outside the group
    /// it belongs to. Without `flex_bg` each group's block bitmap, inode bitmap, and inode
    /// table must lie within the group's own block range; `flex_bg` is the feature that
    /// permits packing them into the flex head instead, so the check does nothing when it
    /// is set. This is geometry, so it holds on the checksumless ext2 and ext3 images too,
    /// and it is the placement rule `e2fsck` enforces as "bitmap for group N is not in
    /// group". The values come from the descriptor already read; no block is fetched.
    fn collect_metadata_placement_faults(
        &self,
        g: u32,
        desc: &GroupDescriptor,
        faults: &mut Vec<ReadError>,
    ) {
        if self.feature.has_flex_bg() {
            return;
        }
        let bpg = u64::from(self.sb.blocks_per_group);
        if bpg == 0 {
            return;
        }
        // The group spans `blocks_per_group` blocks from its first, and the last group is
        // cut short at the end of the filesystem.
        let start = u64::from(self.sb.first_data_block) + u64::from(g) * bpg;
        let end = start.saturating_add(bpg).min(self.sb.blocks_count);
        let in_group = |block: u64| block >= start && block < end;
        for (what, block) in [
            ("block bitmap", desc.block_bitmap),
            ("inode bitmap", desc.inode_bitmap),
            ("inode table", desc.inode_table),
        ] {
            if !in_group(block) {
                faults.push(ReadError::MetadataOutsideGroup {
                    what,
                    group: g,
                    block,
                });
            }
        }
    }

    /// Verify group `g`'s block-bitmap and inode-bitmap checksums against the values
    /// recorded in its descriptor. Each is a crc32c of the used portion of the bitmap
    /// block seeded from the filesystem seed, stored 32 bits wide under a 64-byte
    /// descriptor and 16 bits wide under a 32-byte one. A bitmap the descriptor marks
    /// uninitialized carries a zero checksum by construction and is not recomputed.
    fn verify_bitmap_checksums(
        &mut self,
        g: u32,
        csum: &Crc32c,
        seed: u32,
    ) -> Result<(), ReadError> {
        let mut faults = Vec::new();
        self.collect_bitmap_faults(g, csum, seed, &mut faults);
        faults.into_iter().next().map_or(Ok(()), Err)
    }

    /// Collect both bitmap faults in group `g`, rather than stopping at the first: a
    /// group whose block bitmap and inode bitmap both fail their checksum yields two
    /// faults, not one. Each is a crc32c of the used portion of the bitmap block seeded
    /// from the filesystem seed, stored 32 bits wide under a 64-byte descriptor and 16
    /// wide under a 32-byte one. A bitmap the descriptor marks uninitialized carries a
    /// zero checksum by construction and is not recomputed.
    fn collect_bitmap_faults(
        &mut self,
        g: u32,
        csum: &Crc32c,
        seed: u32,
        faults: &mut Vec<ReadError>,
    ) {
        let desc = match self.group_descriptor(g) {
            Ok(desc) => desc,
            Err(e) => {
                faults.push(e);
                return;
            }
        };
        let wide = self.desc_size() >= GroupDescriptor::SIZE_64;
        let fold = |c: u32| if wide { c } else { c & 0xffff };

        if desc.flags & BG_BLOCK_UNINIT == 0 {
            let len = (self.sb.blocks_per_group / 8) as usize;
            match self.block(desc.block_bitmap) {
                Ok(bmp) => {
                    let computed = fold(csum.crc32c(seed, &bmp[..len.min(bmp.len())]));
                    if computed != desc.block_bitmap_csum {
                        faults.push(ReadError::ChecksumMismatch {
                            object: "block bitmap",
                            index: u64::from(g),
                            stored: desc.block_bitmap_csum,
                            computed,
                        });
                    }
                }
                Err(e) => faults.push(e),
            }
        }
        if desc.flags & BG_INODE_UNINIT == 0 {
            // `ext4_inode_bitmap_csum_set` covers `(inodes_per_group + 7) / 8` bytes,
            // rounding up so a count that is not a multiple of eight still has its final
            // partial byte covered. The block bitmap above divides exactly, because a
            // group's block count is always a multiple of eight.
            let len = self.sb.inodes_per_group.div_ceil(8) as usize;
            match self.block(desc.inode_bitmap) {
                Ok(bmp) => {
                    let computed = fold(csum.crc32c(seed, &bmp[..len.min(bmp.len())]));
                    if computed != desc.inode_bitmap_csum {
                        faults.push(ReadError::ChecksumMismatch {
                            object: "inode bitmap",
                            index: u64::from(g),
                            stored: desc.inode_bitmap_csum,
                            computed,
                        });
                    }
                }
                Err(e) => faults.push(e),
            }
        }
    }

    /// Verify the tail checksum of every block of directory inode `ino`. A block of
    /// entries carries a twelve-byte tail whose crc32c covers the block up to it; a
    /// hash-tree index block carries an eight-byte tail covering its in-use entries
    /// followed by the tail with its checksum field zeroed. Both are seeded from the
    /// filesystem seed folded with the directory's number and generation. Non-directory
    /// inodes have nothing to check.
    fn verify_directory_checksums(
        &mut self,
        ino: u32,
        inode: &Inode,
        csum: &Crc32c,
        seed: u32,
    ) -> Result<(), ReadError> {
        let mut faults = Vec::new();
        self.collect_directory_faults(ino, inode, csum, seed, &mut faults);
        faults.into_iter().next().map_or(Ok(()), Err)
    }

    /// Collect the tail-checksum faults in every block of directory inode `ino`, rather
    /// than stopping at the first: a directory with two corrupt blocks yields two.
    ///
    /// A directory's blocks fall into three roles, each with its own checksum tail: the
    /// root (always logical block 0), the interior index nodes, and the leaves that hold
    /// the names. The roles are found by following the index down from the root, not by
    /// position, so a tree another tool grew leaves-first is read the same as one this
    /// crate wrote. Non-directory inodes have nothing to check.
    ///
    /// Each *physical* block is checked once, as [`scan_extent_node`](Self::scan_extent_node)
    /// and [`scan_indirect`](Self::scan_indirect) also do: a block's tail checksum is a
    /// property of that block and the directory that owns it, so a map naming one block
    /// from many logical offsets — which only a crafted image does — would otherwise
    /// report the same verdict once per offset.
    fn collect_directory_faults(
        &mut self,
        ino: u32,
        inode: &Inode,
        csum: &Crc32c,
        seed: u32,
        faults: &mut Vec<ReadError>,
    ) {
        if inode.mode & 0o170000 != 0o040000 {
            return;
        }
        let indexed = inode.flags.contains(InodeFlags::INDEX);
        let base = {
            let c = csum.crc32c(seed, &ino.to_le_bytes());
            csum.crc32c(c, &inode.generation.to_le_bytes())
        };
        let blocks = match self.data_blocks(inode) {
            Ok(blocks) => blocks,
            Err(e) => {
                faults.push(e);
                return;
            }
        };
        let (root_indexed, interior) = match self.directory_index_layout(&blocks, indexed) {
            Ok(layout) => layout,
            Err(e) => {
                faults.push(e);
                return;
            }
        };

        let mut checked = HashSet::new();
        for (logical, &phys) in blocks.iter().enumerate() {
            // A directory has no holes: every logical block is materialized. A zero here
            // is a mapping that names none, and there is no block to check.
            if phys == 0 {
                continue;
            }
            // One verdict per block, taken at the first logical offset naming it.
            if !checked.insert(phys) {
                continue;
            }
            let logical = logical as u64;
            let block = match self.block(phys) {
                Ok(block) => block,
                Err(e) => {
                    faults.push(e);
                    continue;
                }
            };
            let count_offset = if logical == 0 && root_indexed {
                Some(DX_ROOT_COUNT_OFFSET)
            } else if interior.contains(&logical) {
                Some(DX_NODE_COUNT_OFFSET)
            } else {
                None
            };
            if let Err(e) = self.verify_one_dir_block(phys, &block, base, count_offset, csum) {
                faults.push(e);
            }
        }
    }

    /// The index layout of a directory: whether its logical block 0 is a hash-tree
    /// root, and which of its logical blocks are interior index nodes.
    ///
    /// A hash tree's blocks fall into three roles — the root (always block 0), the
    /// interior index nodes, and the leaves — and these are not positional. `mke2fs`
    /// and the kernel grow a tree by filling leaves and allocate an interior node only
    /// when the level above it overflows, so a foreign tree's interior nodes sit at
    /// high logical blocks while its low blocks are leaves; this crate's own writer
    /// places them right after the root instead. Following the root's index pointers
    /// down its `indirect_levels` levels names the interior nodes wherever they sit, so
    /// the two layouts read the same.
    ///
    /// `blocks` is the directory's logical-to-physical map. A child naming a block
    /// outside it, naming block 0, or already seen is ignored, so a malformed or cyclic
    /// index cannot drive this past the directory's own blocks and each is read at most
    /// once. A directory without the index flag, or one whose first block is a hole,
    /// has no interior nodes and every block is treated as leaf entries.
    fn directory_index_layout(
        &mut self,
        blocks: &[u64],
        indexed: bool,
    ) -> Result<(bool, HashSet<u64>), ReadError> {
        let mut interior = HashSet::new();
        if !indexed {
            return Ok((false, interior));
        }
        // Block 0 is the root. A directory flagged indexed whose first block is a hole
        // has no readable root to follow.
        let Some(root_phys) = blocks.first().copied().filter(|&b| b != 0) else {
            return Ok((false, interior));
        };
        let root = self.block(root_phys)?;
        let levels = match read_dx_root_info(&root) {
            Ok((_, levels)) => levels,
            // A root too short to hold its info is not a tree to walk; block 0 is still
            // its root, with no interior nodes below it.
            Err(_) => return Ok((true, interior)),
        };
        // Descend `levels` levels from the root, following each index block's child
        // pointers. The blocks reached along the way are the interior nodes; the ones a
        // further level down are the leaves, so they are not collected.
        let mut frontier = vec![0u64];
        for _ in 0..levels {
            let mut next = Vec::new();
            for &logical in &frontier {
                let Some(phys) = blocks.get(logical as usize).copied().filter(|&b| b != 0) else {
                    continue;
                };
                let block = self.block(phys)?;
                let count_offset = if logical == 0 {
                    DX_ROOT_COUNT_OFFSET
                } else {
                    DX_NODE_COUNT_OFFSET
                };
                // A block whose count is malformed contributes no children; its bad
                // tail is caught by the checksum pass that follows.
                let Ok(entries) = read_dx_entries(&block, count_offset) else {
                    continue;
                };
                for entry in entries {
                    let child = u64::from(entry.block);
                    // Block 0 is the root, never a child; an out-of-range or repeated
                    // child is a malformed or cyclic pointer. Skipping all three bounds
                    // the walk and visits each block at most once.
                    if child != 0 && (child as usize) < blocks.len() && interior.insert(child) {
                        next.push(child);
                    }
                }
            }
            frontier = next;
        }
        Ok((true, interior))
    }

    /// Verify one directory block's tail checksum. `count_offset` is `Some` for a
    /// hash-tree index block (the offset its entry count sits at) and `None` for a block
    /// of entries. `base` is the seed already folded with the directory's number and
    /// generation.
    fn verify_one_dir_block(
        &self,
        phys: u64,
        block: &[u8],
        base: u32,
        count_offset: Option<usize>,
        csum: &Crc32c,
    ) -> Result<(), ReadError> {
        match count_offset {
            None => {
                if block.len() < DIR_TAIL_LEN + 4 {
                    return Ok(());
                }
                let covered = block.len() - DIR_TAIL_LEN;
                let computed = csum.crc32c(base, &block[..covered]);
                let stored = get_u32(block, block.len() - 4);
                if computed != stored {
                    return Err(ReadError::ChecksumMismatch {
                        object: "directory block",
                        index: phys,
                        stored,
                        computed,
                    });
                }
            }
            Some(count_offset) => {
                let limit = usize::from(get_u16(block, count_offset));
                let count = usize::from(get_u16(block, count_offset + 2));
                let covered = count_offset + DX_ENTRY_LEN * count;
                let tail = dx_tail_offset(count_offset, limit);
                // The checksum sits in the last word of the `DX_TAIL_LEN`-byte tail, read
                // at `tail + 4` as bytes [tail+4, tail+8), so the block must reach
                // `tail + DX_TAIL_LEN`. Guarding only `tail + 4` would leave the read of
                // the checksum word itself unbounded.
                if covered > block.len() || tail + DX_TAIL_LEN > block.len() {
                    return Ok(());
                }
                // The tail is folded as its own bytes up to `dt_checksum`, then four
                // zeros standing in for that field. Only the checksum word is treated as
                // absent; `dt_reserved` before it is covered as it lies on disk, so an
                // image that leaves anything there still verifies.
                let mut c = csum.crc32c(base, &block[..covered]);
                c = csum.crc32c(c, &block[tail..tail + DX_CHECKSUM_OFFSET]);
                c = csum.crc32c(c, &[0u8; DX_TAIL_LEN - DX_CHECKSUM_OFFSET]);
                let stored = get_u32(block, tail + 4);
                if c != stored {
                    return Err(ReadError::ChecksumMismatch {
                        object: "directory block",
                        index: phys,
                        stored,
                        computed: c,
                    });
                }
            }
        }
        Ok(())
    }

    /// Verify the `h_checksum` of an inode's external attribute block, if it has one.
    /// The checksum is a crc32c over the whole block with its own field zeroed, seeded
    /// from the filesystem seed folded with the block number as a 64-bit value. An inode
    /// with no external attribute block has nothing to check; the inline attribute
    /// region is covered by the inode's own checksum instead.
    fn verify_xattr_block_checksum(
        &mut self,
        inode: &Inode,
        csum: &Crc32c,
        seed: u32,
    ) -> Result<(), ReadError> {
        let phys = inode.file_acl;
        if phys == 0 {
            return Ok(());
        }
        self.check_data_block(phys)?;
        let mut block = self.block(phys)?;
        if block.len() < 20 {
            return Ok(());
        }
        let stored = get_u32(&block, 16);
        crate::ondisk::put_u32(&mut block, 16, 0);
        let mut c = csum.crc32c(seed, &phys.to_le_bytes());
        c = csum.crc32c(c, &block);
        if c != stored {
            return Err(ReadError::ChecksumMismatch {
                object: "xattr block",
                index: phys,
                stored,
                computed: c,
            });
        }
        Ok(())
    }

    /// Scan the whole image and collect every deviation as an [`Anomaly`], reporting
    /// rather than rejecting: the lenient counterpart to the fail-fast accessors.
    ///
    /// The scan walks the superblock, every group descriptor and its bitmap checksums,
    /// and every in-use inode with its extent tree, directory-block tails, and external
    /// attribute block, plus the journal superblock — checking each metadata checksum
    /// the image carries and the bounds of every reference it follows. It never stops at
    /// the first finding and, like every read, never panics on malformed input. Apply a
    /// [`ReadPolicy`] threshold to the result with [`ScanReport::has_fatal`].
    ///
    /// Every allocation the scan makes is bounded by the bytes the source actually holds,
    /// not by a count an image claims: the objects walked are capped at the groups and
    /// inodes the source can physically hold, each metadata block is read once, and the
    /// findings themselves stop at [`Limits::max_anomalies`] with
    /// [`ScanReport::is_truncated`] recording that they did. That is what makes this the
    /// path to point at an image that may have been built to be hostile.
    #[must_use]
    pub fn scan(&mut self) -> ScanReport {
        let mut anomalies = Vec::new();
        let mut truncated = false;
        let has_csum = self.feature.has_metadata_csum();
        let csum = self.checksummer();
        let seed = csum.base_seed();

        // Bound the walk by the length the source reports, so a count field a bit-flip
        // inflated cannot drive a loop past the end of it.
        let source_len = self.source_len();
        let block_size = self.block_size as u64;
        let max_blocks = source_len / block_size;

        // An `incompat` feature the reader does not follow taints the whole image: it may
        // change the layout of the structures walked below, so it is reported first. A
        // strict open would have refused it, so this is what a lenient scan surfaces in
        // its place.
        let unsupported = unsupported_incompat(self.feature.incompat);
        if unsupported != 0 {
            anomalies.push(ReadError::UnsupportedIncompat { bits: unsupported }.anomaly());
        }

        // Superblock checksum.
        if has_csum {
            let computed = self.superblock_checksum(&csum);
            if computed != self.sb.checksum {
                anomalies.push(
                    ReadError::ChecksumMismatch {
                        object: "superblock",
                        index: 0,
                        stored: self.sb.checksum,
                        computed,
                    }
                    .anomaly(),
                );
            }
        }

        // Every group descriptor: that it reads, and its checksum. The group count is
        // capped at the groups the source can physically hold.
        let bpg = u64::from(self.sb.blocks_per_group.max(1));
        let group_bound = (max_blocks / bpg)
            .saturating_add(2)
            .min(u64::from(u32::MAX)) as u32;
        let desc_size = self.desc_size();
        for g in 0..self.group_count().min(group_bound) {
            if anomalies.len() >= self.limits.max_anomalies {
                truncated = true;
                break;
            }
            let raw = match self.group_descriptor_raw(g) {
                Err(e) => {
                    anomalies.push(e.anomaly());
                    continue;
                }
                Ok(raw) => raw,
            };
            match GroupDescriptor::read_from(&raw, desc_size) {
                Err(e) => anomalies.push(ReadError::Parse(e).anomaly()),
                Ok(desc) => {
                    // Placement is geometry, not checksums: it is checked on every image,
                    // including the checksumless ext2 and ext3 ones whose every group must
                    // hold its own metadata.
                    let mut placement = Vec::new();
                    self.collect_metadata_placement_faults(g, &desc, &mut placement);
                    for e in &placement {
                        anomalies.push(e.anomaly());
                    }
                    if has_csum {
                        let computed = self.descriptor_checksum(g, &raw, &csum);
                        if computed != desc.checksum {
                            anomalies.push(
                                ReadError::ChecksumMismatch {
                                    object: "group descriptor",
                                    index: u64::from(g),
                                    stored: u32::from(desc.checksum),
                                    computed: u32::from(computed),
                                }
                                .anomaly(),
                            );
                        }
                        let mut faults = Vec::new();
                        self.collect_bitmap_faults(g, &csum, seed, &mut faults);
                        for e in &faults {
                            anomalies.push(anomaly_in_bitmap(e, g, Category::Bitmap));
                        }
                    }
                }
            }
        }

        // Every in-use inode, taken from the inode bitmaps: that it reads, its checksum,
        // and its block mapping. Reading the bitmaps rather than assuming inodes run
        // densely from one finds an inode a live filesystem scattered past that range
        // and skips a never-initialized table slot, which is not an inode to read. The
        // examined count is capped at the inodes the source can hold.
        let max_inodes = source_len / u64::from(self.sb.inode_size.max(128));
        // One visited set for the whole scan: a metadata block belongs to a single
        // structure, so an external extent or indirect node read once is never read
        // again, and a crafted or cyclic tree cannot fan the walk out without bound.
        let mut visited = HashSet::new();
        let inode_size = self.sb.inode_size;
        let mut examined = 0u64;
        // The same physical bound the descriptor loop uses. A group past it has no
        // bitmap block inside the source, so every iteration could only record that the
        // bitmap is unreadable — and a superblock claiming `u32::MAX` groups would turn
        // that into billions of anomalies, which is an allocation driven by a claimed
        // count rather than by the bytes that exist. The `examined` cap below cannot
        // stand in for this one: it is only reached once a group yields an inode, and a
        // group whose bitmap does not read yields none.
        'inodes: for g in 0..self.group_count().min(group_bound) {
            if examined >= max_inodes {
                break;
            }
            // A report already at its cap collects nothing more, so the walk stops here
            // rather than reading every remaining group's bitmap for findings it would
            // discard.
            if anomalies.len() >= self.limits.max_anomalies {
                truncated = true;
                break;
            }
            let in_use = match self.group_in_use_inodes(g) {
                Ok(v) => v,
                Err(e) => {
                    anomalies.push(anomaly_in_bitmap(&e, g, Category::Bitmap));
                    continue;
                }
            };
            for n in in_use {
                if examined >= max_inodes {
                    break 'inodes;
                }
                // The findings cap is applied between inodes: one inode's checks run to
                // completion, so a report never holds half an inode's account of itself.
                // Each contributes at most one finding per distinct block it names, so the
                // overshoot past the cap is bounded by the blocks the image holds.
                if anomalies.len() >= self.limits.max_anomalies {
                    truncated = true;
                    break 'inodes;
                }
                examined += 1;
                let raw = match self.inode_raw(n) {
                    Err(e) => {
                        anomalies.push(anomaly_at_inode(&e, n));
                        continue;
                    }
                    Ok(raw) => raw,
                };
                match Inode::read_from(&raw, inode_size) {
                    Err(e) => anomalies.push(anomaly_at_inode(&ReadError::Parse(e), n)),
                    Ok(inode) => {
                        if has_csum {
                            let (stored, computed) = self.inode_checksum(n, &raw, &csum, seed);
                            if computed != stored {
                                anomalies.push(
                                    ReadError::ChecksumMismatch {
                                        object: "inode",
                                        index: u64::from(n),
                                        stored,
                                        computed,
                                    }
                                    .anomaly(),
                                );
                            }
                        }
                        // What the inode's own bytes say against what the superblock's
                        // feature words promise. Checked on every image, checksums or not:
                        // it is a disagreement between two fields, not a corruption a
                        // checksum would catch.
                        self.scan_feature_coherence(n, &inode, &mut anomalies);
                        self.scan_inode_map(
                            n,
                            &inode,
                            has_csum,
                            &csum,
                            &mut visited,
                            &mut anomalies,
                        );
                        // A directory-entry name a real filesystem could not hold is a
                        // structural fault whether or not the image carries checksums, so
                        // it is checked outside the `has_csum` block below.
                        self.scan_dirent_names(n, &inode, &mut anomalies);
                        if has_csum {
                            let mut faults = Vec::new();
                            self.collect_directory_faults(n, &inode, &csum, seed, &mut faults);
                            for e in &faults {
                                anomalies.push(anomaly_in_mapping(e, n, Category::Directory));
                            }
                            if let Err(e) = self.verify_xattr_block_checksum(&inode, &csum, seed) {
                                anomalies.push(anomaly_in_mapping(&e, n, Category::Xattr));
                            }
                        }
                    }
                }
            }
        }

        // The journal superblock is structural: a malformed one is a Journal anomaly.
        if let Err(e) = self.journal_superblock() {
            anomalies.push(e.anomaly());
        }

        // The orphan file: its blocks' magic words always, and their checksums when the
        // image carries them. Its length is fixed by the file itself rather than by any
        // per-inode claim, so it is walked whatever the inode loop found.
        let mut orphan_faults = Vec::new();
        self.collect_orphan_faults(&csum, seed, &mut orphan_faults);
        let orphan_ino = self.sb.orphan_file_inum;
        for e in &orphan_faults {
            anomalies.push(anomaly_in_mapping(e, orphan_ino, Category::Orphan));
        }

        // The cap is a bound on what a report holds, so it is applied to the collected
        // findings as well as to the walk that gathered them.
        if anomalies.len() > self.limits.max_anomalies {
            anomalies.truncate(self.limits.max_anomalies);
            truncated = true;
        }
        ScanReport {
            anomalies,
            truncated,
            cap: self.limits.max_anomalies,
        }
    }

    /// Collect the anomalies in one inode's block mapping, whichever kind it carries.
    ///
    /// For an extent tree: external-node checksum mismatches, unreadable or
    /// unparseable nodes, index pointers out of range, a tree deeper than the reader
    /// follows, and leaf runs that fall outside the filesystem. An inode whose mapping
    /// fits inline has no external node to check.
    ///
    /// For a classic block map: that every pointer names a block the filesystem has.
    /// An indirect block carries no checksum — the classic map predates them — so
    /// there is nothing to recompute, but the map is still walked. Skipping it would
    /// let a scan report a clean bill of health for a mapping it never looked at, which
    /// on ext2 and ext3, where *every* inode is mapped this way, means reporting a
    /// clean bill of health for the whole filesystem.
    fn scan_inode_map(
        &mut self,
        ino: u32,
        inode: &Inode,
        has_csum: bool,
        csum: &Crc32c,
        visited: &mut HashSet<u64>,
        out: &mut Vec<Anomaly>,
    ) {
        if !inode.flags.contains(InodeFlags::EXTENTS) {
            // A fast symlink's target and a device node's major and minor share the
            // i_block area a classic map's pointers would occupy; only an inode that
            // maps data has pointers there to validate. Walking the others would read a
            // target string or a device number as block numbers.
            if !maps_data(inode, self.block_size) {
                return;
            }
            if let Err(e) = self.scan_block_map(inode, visited) {
                // A classic block map is no subsystem of its own: a pointer that falls
                // outside the filesystem belongs to the inode that holds the map, or the
                // directory the map is for.
                let owner = if is_dir(inode) {
                    Category::Directory
                } else {
                    Category::Inode
                };
                out.push(anomaly_in_mapping(&e, ino, owner));
            }
            return;
        }
        // The inode is extent-mapped. Whether the feature word agrees is reported by
        // `scan_feature_coherence`, which holds every such rule; the tree itself is
        // scanned here whatever that word says.
        //
        // Every node in one inode's tree shares a seed: the filesystem seed folded
        // with the inode's number and generation.
        let mut seed = csum.crc32c(csum.base_seed(), &ino.to_le_bytes());
        seed = csum.crc32c(seed, &inode.generation.to_le_bytes());
        let ctx = ExtentScanCtx {
            ino,
            seed,
            has_csum,
            csum,
        };
        self.scan_extent_node(&ctx, &inode.block, 0, visited, out);
    }

    /// Report every disagreement between one inode's own bytes and the feature words the
    /// superblock advertises.
    ///
    /// A feature word is a promise about what the filesystem's structures look like, so an
    /// inode that carries a structure the word denies makes the image self-contradictory:
    /// a reader cannot tell which of the two to believe, and a kernel that trusts the word
    /// reads the inode wrongly. Each rule here is one `e2fsck` enforces, and each has a
    /// counterpart on the writing side, where the formatter refuses to emit the pair —
    /// these are what catch the same incoherence in an image this crate did not write.
    ///
    /// The mapping flag and the attribute-block pointer are structural: they decide how
    /// the reader interprets bytes, so a disagreement leaves it unable to vouch for what
    /// it read. The size and the hash-index flag are conformance deviations, read
    /// correctly either way — for the size and for a directory's flag, what is missing is
    /// the word that should advertise it; for the flag on anything but a directory, the
    /// flag itself describes an organization that file does not have.
    fn scan_feature_coherence(&self, ino: u32, inode: &Inode, out: &mut Vec<Anomaly>) {
        if inode.flags.contains(InodeFlags::EXTENTS) && !self.feature.has_extents() {
            out.push(ReadError::ExtentFlagWithoutFeature { inode: ino }.anomaly());
        }
        if inode.file_acl != 0 && !self.feature.has_ext_attr() {
            out.push(
                ReadError::XattrBlockWithoutFeature {
                    inode: ino,
                    block: inode.file_acl,
                }
                .anomaly(),
            );
        }
        if is_regular(inode) && inode.size >= LARGE_FILE_MIN_SIZE && !self.feature.has_large_file()
        {
            out.push(
                ReadError::LargeFileWithoutFeature {
                    inode: ino,
                    size: inode.size,
                }
                .anomaly(),
            );
        }
        // The hash-index flag is two rules, not one, and each names a different thing to
        // fix: a directory whose flag the feature words deny, and an inode carrying the
        // flag that is not a directory at all. An inode can be both. Reporting the first
        // for the second would describe a regular file as a hash-indexed directory.
        if inode.flags.contains(InodeFlags::INDEX) {
            if is_dir(inode) {
                if !self.feature.has_dir_index() {
                    out.push(ReadError::IndexFlagWithoutFeature { inode: ino }.anomaly());
                }
            } else {
                out.push(ReadError::IndexFlagOnNonDirectory { inode: ino }.anomaly());
            }
        }
    }

    /// Flag directory `ino` when any entry's name is one a real ext4 filesystem could not
    /// hold — one carrying a path separator or a NUL (see [`name_is_hostile`]). Such a
    /// name is impossible on a kernel-checked filesystem, so its presence is a structural
    /// fault and the diagnostic that keeps `walk`'s silent skip of it from being the only
    /// signal. A non-directory has no entries.
    ///
    /// The blocks are walked here rather than through [`read_dir`](Self::read_dir), which
    /// is strict: it abandons a whole directory at its first malformed record, and a
    /// directory carrying a hostile name is exactly the one likely to carry a malformed
    /// record too — so reading through it would skip the check on the directories that
    /// most need it. A record this cannot parse ends that *block*, and the walk goes on to
    /// the next. Each physical block is read once, and one anomaly stands for the whole
    /// directory, so a crafted map cannot make one inode's finding into thousands.
    fn scan_dirent_names(&mut self, ino: u32, inode: &Inode, out: &mut Vec<Anomaly>) {
        if !is_dir(inode) {
            return;
        }
        // An unreadable mapping is already faulted by the block-map and checksum checks,
        // so it yields nothing here rather than a second, redundant fault.
        let Ok(blocks) = self.data_blocks(inode) else {
            return;
        };
        let mut read = HashSet::new();
        for phys in blocks {
            if phys == 0 || !read.insert(phys) {
                continue;
            }
            let Ok(block) = self.block(phys) else {
                continue;
            };
            let mut off = 0;
            while off < block.len() {
                let Ok((entry, rec_len)) = DirEntry::read_from(&block[off..], self.block_size)
                else {
                    break; // this block is malformed from here on; the next one may not be
                };
                // The same guard `read_dir` carries, for the same reason: `read_from`
                // returns nothing shorter than an eight-byte header, and a scan that could
                // stop advancing would never finish the image.
                if rec_len == 0 {
                    break;
                }
                if entry.inode != 0 && name_is_hostile(&entry.name) {
                    out.push(hostile_name_anomaly(ino));
                    return;
                }
                off += rec_len;
            }
        }
    }

    fn scan_extent_node(
        &mut self,
        ctx: &ExtentScanCtx,
        node: &[u8],
        depth: u16,
        visited: &mut HashSet<u64>,
        out: &mut Vec<Anomaly>,
    ) {
        if depth > MAX_EXTENT_DEPTH {
            out.push(anomaly_at_inode(&ReadError::BadExtentTree, ctx.ino));
            return;
        }
        let parsed = match parse_node(node) {
            Ok(n) => n,
            Err(e) => {
                out.push(anomaly_at_inode(&ReadError::Parse(e), ctx.ino));
                return;
            }
        };
        match parsed {
            ExtentNode::Leaves(leaves) => {
                for leaf in leaves {
                    let end = leaf.start.saturating_add(u64::from(leaf.len));
                    if leaf.start >= self.sb.blocks_count || end > self.sb.blocks_count {
                        out.push(anomaly_in_mapping(
                            &ReadError::OutOfRange {
                                what: "block",
                                index: leaf.start,
                            },
                            ctx.ino,
                            Category::ExtentTree,
                        ));
                    }
                }
            }
            ExtentNode::Index { entries, .. } => {
                for idx in entries {
                    // Read each external node once: a repeated or cyclic child pointer
                    // is skipped, so a crafted tree cannot fan the walk out unbounded.
                    if !visited.insert(idx.leaf) {
                        continue;
                    }
                    let child = match self.block(idx.leaf) {
                        Ok(c) => c,
                        Err(e) => {
                            out.push(anomaly_in_mapping(&e, ctx.ino, Category::ExtentTree));
                            continue;
                        }
                    };
                    if ctx.has_csum {
                        let tail = extent_tail_offset(&child, self.block_size);
                        let stored = u32::from_le_bytes(
                            child[tail..tail + EXTENT_TAIL_LEN]
                                .try_into()
                                .expect("tail slice is exactly EXTENT_TAIL_LEN bytes"),
                        );
                        let computed = ctx.csum.crc32c(ctx.seed, &child[..tail]);
                        if stored != computed {
                            out.push(anomaly_at_inode(
                                &ReadError::ChecksumMismatch {
                                    object: "extent node",
                                    index: idx.leaf,
                                    stored,
                                    computed,
                                },
                                ctx.ino,
                            ));
                        }
                    }
                    self.scan_extent_node(ctx, &child, depth + 1, visited, out);
                }
            }
        }
    }

    /// Read inode `number`.
    ///
    /// # Errors
    ///
    /// [`ReadError::NoSuchInode`] if the number is zero or past the inode count;
    /// [`ReadError`] variants if its bytes cannot be located or parsed.
    pub fn inode(&mut self, number: u32) -> Result<Inode, ReadError> {
        let raw = self.inode_raw(number)?;
        Ok(Inode::read_from(&raw, self.sb.inode_size)?)
    }

    /// Read inode `number` exactly as it sits on disk, at this filesystem's
    /// `s_inode_size`.
    ///
    /// Its checksum covers these bytes. An inode carries fields this crate does not
    /// model — `l_i_version`, which the kernel bumps on every update, and `i_projid` —
    /// so recomputing the checksum from a re-serialized [`Inode`] would zero them and
    /// reject every inode of any filesystem that has been mounted.
    fn inode_raw(&mut self, number: u32) -> Result<Vec<u8>, ReadError> {
        if number == 0 || number > self.sb.inodes_count {
            return Err(ReadError::NoSuchInode { inode: number });
        }
        let ipg = self.sb.inodes_per_group;
        if ipg == 0 {
            // A malformed superblock with no inodes per group has nowhere to place
            // this inode; report it missing rather than dividing by zero.
            return Err(ReadError::NoSuchInode { inode: number });
        }
        let group = (number - 1) / ipg;
        let index = u64::from((number - 1) % ipg);
        let desc = self.group_descriptor(group)?;
        let isize = self.sb.inode_size as usize;
        // The inode table block comes from the group descriptor, so a malformed one
        // can push the byte offset past the 64-bit range: treat that as out of range
        // rather than overflowing. `index * isize` is bounded by the group geometry.
        let off = desc
            .inode_table
            .checked_mul(self.block_size as u64)
            .and_then(|base| base.checked_add(index * isize as u64))
            .ok_or(ReadError::OutOfRange {
                what: "inode",
                index: u64::from(number),
            })?;
        match self.read_at(off, isize) {
            Err(ReadError::OutOfRange { .. }) => Err(ReadError::OutOfRange {
                what: "inode",
                index: u64::from(number),
            }),
            other => other,
        }
    }

    /// Resolve an inode's extent tree to its leaves, following index nodes to any
    /// depth.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadExtentTree`] if the tree exceeds [`MAX_EXTENT_DEPTH`];
    /// [`ReadError`] variants if a node cannot be read.
    fn extent_leaves(
        &mut self,
        inode: &Inode,
    ) -> Result<Vec<crate::ondisk::ExtentLeaf>, ReadError> {
        let mut leaves = Vec::new();
        // One visited set per tree: a well-formed extent tree references each external
        // node once, so a repeated child pointer is a cycle or fan-out and bounds the
        // walk to the blocks that actually exist rather than looping.
        let mut visited = HashSet::new();
        self.walk_extent_node(&inode.block, 0, &mut visited, &mut leaves)?;
        // Leaves come out in logical order because entries within a node are sorted
        // and index nodes are visited in order.
        Ok(leaves)
    }

    fn walk_extent_node(
        &mut self,
        node: &[u8],
        depth: u16,
        visited: &mut HashSet<u64>,
        out: &mut Vec<crate::ondisk::ExtentLeaf>,
    ) -> Result<(), ReadError> {
        if depth > MAX_EXTENT_DEPTH {
            return Err(ReadError::BadExtentTree);
        }
        match parse_node(node)? {
            ExtentNode::Leaves(leaves) => {
                // Validate each leaf against the block count before it reaches a reader
                // that would allocate for and read every block it names, the same bound
                // `scan_extent_node` applies. A leaf past the filesystem is a reference
                // out of range, not silently followed.
                for leaf in &leaves {
                    let end = leaf.start.saturating_add(u64::from(leaf.len));
                    if leaf.start >= self.sb.blocks_count || end > self.sb.blocks_count {
                        return Err(ReadError::OutOfRange {
                            what: "block",
                            index: leaf.start,
                        });
                    }
                }
                out.extend(leaves);
            }
            ExtentNode::Index { entries, .. } => {
                for idx in entries {
                    // A child block reached twice is a cyclic or fan-out tree, not a
                    // tree: reject it rather than walk it unbounded.
                    if !visited.insert(idx.leaf) {
                        return Err(ReadError::BadExtentTree);
                    }
                    let child = self.block(idx.leaf)?;
                    self.walk_extent_node(&child, depth + 1, visited, out)?;
                }
            }
        }
        Ok(())
    }

    /// Reject a block pointer naming a block the filesystem does not have.
    fn check_data_block(&self, block: u64) -> Result<(), ReadError> {
        if block >= self.sb.blocks_count {
            return Err(ReadError::OutOfRange {
                what: "block",
                index: block,
            });
        }
        Ok(())
    }

    /// Map an inode's logical blocks to physical ones, in logical order, with a zero
    /// standing for a block that reads as zeros without occupying any.
    ///
    /// This is the one place that decides how an inode maps its blocks. An inode with
    /// [`InodeFlags::EXTENTS`] roots an extent tree; every other inode uses the classic
    /// direct/indirect map, which is how ext2 and ext3 map every file, and how ext4
    /// still maps the resize inode. Reading the second as the first finds an extent
    /// header where a block number lives and calls a healthy filesystem corrupt.
    ///
    /// The map holds one entry per logical block the file's size covers, so it is
    /// bounded by that size — not by the blocks physically present. A hole costs no
    /// block on disk, so a sparse file's size can far exceed the filesystem it lives
    /// on, and its logical offsets can too; bounding the map by the physical block
    /// count would truncate such a file or reject a valid high-offset extent. The
    /// bound is instead the 2^32-block logical ceiling ([`MAX_LOGICAL_BLOCKS`]), so a
    /// self-consistent image claiming a large sparse file drives an allocation up to
    /// that claimed size. Each physical block *number* the map records is still
    /// checked against the filesystem's block count.
    ///
    /// A *directory* is the exception, and is bounded by the blocks the image physically
    /// holds. A directory is never sparse — the kernel materializes every logical block it
    /// declares — so one claiming more blocks than the filesystem has is malformed
    /// whatever its size field says, and reading it as though it might be sparse would let
    /// a two-byte edit to `i_size` drive a map of billions of entries. That bound is
    /// loss-free on any well-formed image, where a directory's blocks are blocks that
    /// exist.
    ///
    /// A hostile `i_size` and a genuine sparse file are the same shape — a small
    /// physical footprint under a large logical size — so for a regular file this
    /// materialization trusts the declared size, and a whole-file read through
    /// [`read_data`](Self::read_data) allocates in proportion to it. The forensic
    /// [`scan`](Self::scan) path never materializes a file's map at all, and bounds what
    /// it collects, so it is the bounded way to inspect an untrusted image.
    ///
    /// # Errors
    ///
    /// [`ReadError::OutOfRange`] if the mapping names a block outside the filesystem;
    /// [`ReadError::BadExtentTree`] if an extent tree is cyclic or too deep;
    /// [`ReadError`] variants if a mapping block cannot be read.
    fn data_blocks(&mut self, inode: &Inode) -> Result<Vec<u64>, ReadError> {
        let want = self.logical_block_count(inode);
        self.map_window(inode, 0, want)
    }

    /// The blocks the image can actually hold: the filesystem's own block count, bounded
    /// by the blocks the source is long enough to carry.
    ///
    /// This is the ceiling on any structure that is *not* sparse — a directory, the orphan
    /// file — whose logical extent is therefore a physical one. Both terms matter: the
    /// first is the filesystem's own account of itself, and the second is the only one a
    /// crafted superblock cannot inflate.
    fn materialized_block_bound(&mut self) -> u64 {
        self.sb
            .blocks_count
            .min(self.source_len() / self.block_size as u64)
    }

    /// How many logical blocks an inode's size covers — the length of the map
    /// [`data_blocks`](Self::data_blocks) builds for it.
    ///
    /// The classic map is positional and carries no length of its own, so this is what
    /// says where it ends; for an extent tree it is what extends a file whose final blocks
    /// are a hole the tree does not name. It is a logical count, capped at the logical
    /// ceiling and not at the physical block count — that is what keeps a sparse file
    /// whole — except for a directory, which holds no holes and so cannot span more blocks
    /// than the image has.
    fn logical_block_count(&mut self, inode: &Inode) -> usize {
        let want = usize::try_from(
            inode
                .size
                .div_ceil(self.block_size as u64)
                .min(MAX_LOGICAL_BLOCKS),
        )
        .unwrap_or(usize::MAX);
        if is_dir(inode) {
            let bound = self.materialized_block_bound();
            return want.min(usize::try_from(bound).unwrap_or(usize::MAX));
        }
        want
    }

    /// The logical-to-physical map of `count` logical blocks beginning at logical block
    /// `first`, with a zero standing for a block that reads as zeros without occupying
    /// any. The returned map is exactly `count` long.
    ///
    /// This is the one place that decides how an inode maps its blocks, and it is windowed
    /// so that reading part of a file costs part of a map: only the mapping structures the
    /// window touches are read, so a block far into a file is reached through the indirect
    /// blocks above it rather than by materializing everything before it. A caller that
    /// needs only the head of a file — the journal's superblock is its first block — asks
    /// for a window of one.
    ///
    /// Pointers outside the window are neither read nor validated: a read validates the
    /// map it follows. The forensic [`scan`](Self::scan) is what validates a whole map.
    fn map_window(
        &mut self,
        inode: &Inode,
        first: usize,
        count: usize,
    ) -> Result<Vec<u64>, ReadError> {
        // Not every inode's `i_block` area holds block pointers. A *fast* symlink keeps
        // its target string there, and a device node its major and minor; reading either
        // as a mapping interprets a filename or a device number as block numbers.
        if count == 0 || !maps_data(inode, self.block_size) {
            return Ok(Vec::new());
        }
        // Zero-filled, so every hole the walk below leaves untouched already reads as one.
        let mut map = vec![0u64; count];
        if inode.flags.contains(InodeFlags::EXTENTS) {
            self.extent_window(inode, first, &mut map)?;
        } else {
            self.block_map_window(inode, first, &mut map)?;
        }
        Ok(map)
    }

    /// Place the part of an inode's extent tree that falls in the window.
    ///
    /// [`extent_leaves`](Self::extent_leaves) has already checked every leaf's physical
    /// run against the block count, so placing a leaf here is a matter of its logical
    /// offset: a run is clipped to the window and a run entirely outside it is skipped.
    fn extent_window(
        &mut self,
        inode: &Inode,
        first: usize,
        map: &mut [u64],
    ) -> Result<(), ReadError> {
        let end = first.saturating_add(map.len());
        for leaf in self.extent_leaves(inode)? {
            let lo = leaf.block as usize;
            let hi = lo.saturating_add(leaf.len as usize);
            // An uninitialized run occupies blocks but holds no data: it reads back as
            // zeros, exactly as a hole does, so it is left as one.
            if hi <= first || lo >= end || !leaf.initialized {
                continue;
            }
            for logical in lo.max(first)..hi.min(end) {
                map[logical - first] = leaf.start + (logical - lo) as u64;
            }
        }
        Ok(())
    }

    /// Place the part of an inode's classic block map that falls in the window: twelve
    /// direct pointers, then one, two, and three levels of indirection, each level
    /// covering `per_block^level` logical blocks after the last.
    ///
    /// A zero pointer is a hole, at every level — a hole in an indirect pointer means
    /// every block that indirect block would have mapped is a hole too, which is how a
    /// sparse ext2 file stores a gigabyte of nothing in one word. A level whose span lies
    /// outside the window is skipped without reading its blocks at all.
    fn block_map_window(
        &mut self,
        inode: &Inode,
        first: usize,
        map: &mut [u64],
    ) -> Result<(), ReadError> {
        let end = first.saturating_add(map.len());
        for i in first..DIRECT_BLOCKS.min(end) {
            let ptr = u64::from(get_u32(&inode.block, i * 4));
            if ptr != 0 {
                self.check_data_block(ptr)?;
            }
            map[i - first] = ptr;
        }
        let per_block = self.block_size / 4;
        let mut base = DIRECT_BLOCKS;
        for level in 1..=INDIRECT_LEVELS {
            if base >= end {
                break;
            }
            let next = base.saturating_add(per_block.saturating_pow(level));
            if next > first {
                let slot = DIRECT_BLOCKS + level as usize - 1;
                let root = u64::from(get_u32(&inode.block, slot * 4));
                self.walk_indirect_window(root, level, base, first, map)?;
            }
            base = next;
        }
        Ok(())
    }

    /// Place the blocks an indirect block maps that fall in the window, `level` levels
    /// deep, where the block's own span begins at logical block `base`.
    ///
    /// The recursion is at most [`INDIRECT_LEVELS`] deep by construction, one block is read
    /// per level, and a slot whose span misses the window is skipped without descending
    /// into it — so a crafted map can neither exhaust the stack nor drive reads without
    /// bound, and a window deep into a sparse file costs one read per level rather than a
    /// walk of everything before it.
    fn walk_indirect_window(
        &mut self,
        block: u64,
        level: u32,
        base: usize,
        first: usize,
        map: &mut [u64],
    ) -> Result<(), ReadError> {
        // A hole this far up stands for every block below it, which the zero-filled map
        // already records.
        if block == 0 {
            return Ok(());
        }
        self.check_data_block(block)?;
        let buf = self.block(block)?;
        let per_block = self.block_size / 4;
        // What one slot of this block covers: a slot of a single-indirect block is one
        // logical block, and each further level multiplies by the pointers a block holds.
        let span = per_block.saturating_pow(level - 1);
        let end = first.saturating_add(map.len());
        for i in 0..per_block {
            let lo = base.saturating_add(i.saturating_mul(span));
            if lo >= end {
                break;
            }
            if lo.saturating_add(span) <= first {
                continue;
            }
            let ptr = u64::from(get_u32(&buf, i * 4));
            if level == 1 {
                if ptr != 0 {
                    self.check_data_block(ptr)?;
                }
                map[lo - first] = ptr;
            } else {
                self.walk_indirect_window(ptr, level - 1, lo, first, map)?;
            }
        }
        Ok(())
    }

    /// Validate every pointer in an inode's classic map without materializing it: each
    /// direct, indirect, and data-block pointer must name a block the filesystem has.
    ///
    /// This is the classic-map counterpart to
    /// [`scan_extent_node`](Self::scan_extent_node): a forensic walk that checks the
    /// structure a read would follow but allocates nothing per logical block, so a
    /// hostile `i_size` cannot turn a scan into the runaway allocation materializing
    /// the full hole-padded map would be. The walk reads each indirect block once — a
    /// block reached twice is a cyclic or fan-out map and is not followed again — and
    /// is [`INDIRECT_LEVELS`] deep by construction, so it is bounded by the blocks the
    /// filesystem actually holds.
    fn scan_block_map(
        &mut self,
        inode: &Inode,
        visited: &mut HashSet<u64>,
    ) -> Result<(), ReadError> {
        for i in 0..DIRECT_BLOCKS {
            let ptr = u64::from(get_u32(&inode.block, i * 4));
            if ptr != 0 {
                self.check_data_block(ptr)?;
            }
        }
        for level in 1..=INDIRECT_LEVELS {
            let slot = DIRECT_BLOCKS + level as usize - 1;
            let root = u64::from(get_u32(&inode.block, slot * 4));
            self.scan_indirect(root, level, visited)?;
        }
        Ok(())
    }

    /// Validate the pointers an indirect block maps, `level` levels deep, reading each
    /// indirect block once. A zero pointer is a hole and names no block.
    fn scan_indirect(
        &mut self,
        block: u64,
        level: u32,
        visited: &mut HashSet<u64>,
    ) -> Result<(), ReadError> {
        if block == 0 {
            return Ok(());
        }
        self.check_data_block(block)?;
        // A repeated indirect block is a cycle or fan-out, not a map: validated once, it
        // is not walked again, so a crafted map cannot fan the walk out without bound.
        if !visited.insert(block) {
            return Ok(());
        }
        let buf = self.block(block)?;
        let per_block = self.block_size / 4;
        for i in 0..per_block {
            let ptr = u64::from(get_u32(&buf, i * 4));
            if level == 1 {
                if ptr != 0 {
                    self.check_data_block(ptr)?;
                }
            } else {
                self.scan_indirect(ptr, level - 1, visited)?;
            }
        }
        Ok(())
    }

    /// Read the full contents of a regular file or slow symlink, truncated to the
    /// inode's size. Works from whichever mapping the inode carries.
    ///
    /// The returned buffer is the inode's whole logical size, holes materialized as
    /// zeros, so this allocates in proportion to `i_size`. On an untrusted image that
    /// size is attacker-controlled and a genuine sparse file is indistinguishable in
    /// shape from a crafted one, so a large declared size drives a large allocation
    /// either way: this method trusts `i_size`. To inspect an image this crate did not
    /// write without materializing its files, use [`scan`](Self::scan), which allocates
    /// nothing per logical block.
    ///
    /// [`Limits::max_file_bytes`] is what withdraws that trust: a file larger than the cap
    /// is [`ReadError::FileTooLarge`] rather than a shortened buffer, so a truncated read
    /// can never be mistaken for a whole one. To read part of a file deliberately, use
    /// [`read_into`](Self::read_into), which is bounded by the buffer given to it and
    /// reports how much of it was filled; to read a large file without holding it, use
    /// [`read_data_to`](Self::read_data_to).
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] if the file is larger than [`Limits::max_file_bytes`];
    /// other [`ReadError`] variants if the mapping or a data block cannot be read.
    pub fn read_data(&mut self, inode: &Inode) -> Result<Vec<u8>, ReadError> {
        // There is no structural bound to apply here, and that is a fact about the
        // format rather than a gap. A sparse file's holes cost no blocks, so a file whose
        // logical size dwarfs the filesystem holding it is well-formed and must read back
        // at its full size — which makes a legitimate all-hole file and a crafted `i_size`
        // the same shape from the outside. So this trusts `i_size`, as its documentation
        // says, and the only cap is the one a caller sets.
        let want = self.whole_file_len(inode)?;
        let len = usize::try_from(want).map_err(|_| ReadError::FileTooLarge {
            size: want,
            limit: usize::MAX as u64,
        })?;
        let mut data = vec![0u8; len];
        // The read is bounded by the buffer, which is bounded by the cap checked above, so
        // the mapping it builds is bounded with it: eight bytes per logical block of the
        // window, never one per block the size claims.
        let filled = self.read_into(inode, 0, &mut data)?;
        data.truncate(filled);
        Ok(data)
    }

    /// Stream the full contents of a regular file or slow symlink to `out`, returning the
    /// bytes written.
    ///
    /// This is [`read_data`](Self::read_data) without holding the file: the contents are
    /// written out a window at a time, so memory is a fixed working set rather than the
    /// file's size — which is what extracting a multi-gigabyte file out of an image needs.
    /// Holes are written as zeros, exactly as they read.
    ///
    /// The same [`Limits::max_file_bytes`] cap applies, since what it expresses is distrust
    /// of the declared size rather than a memory bound.
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] if the file is larger than [`Limits::max_file_bytes`];
    /// [`ReadError::Io`] if `out` cannot be written; other [`ReadError`] variants if the
    /// mapping or a data block cannot be read.
    pub fn read_data_to(&mut self, inode: &Inode, mut out: impl Write) -> Result<u64, ReadError> {
        let want = self.whole_file_len(inode)?;
        let bs = self.block_size as u64;
        let zeros = vec![0u8; self.block_size];
        let mut written = 0u64;
        // One window's map at a time, so the map is a fixed cost however large the file:
        // `MAP_WINDOW_BLOCKS` entries of eight bytes each. The windows are walked in order,
        // so each costs one pass over the inode's mapping structures — a few block reads
        // for an extent tree, the indirect blocks the window covers for a classic map.
        while written < want {
            let first = usize::try_from(written / bs).unwrap_or(usize::MAX);
            let remaining_blocks = (want - written).div_ceil(bs);
            let count = usize::try_from(remaining_blocks.min(MAP_WINDOW_BLOCKS as u64))
                .unwrap_or(MAP_WINDOW_BLOCKS);
            for phys in self.map_window(inode, first, count)? {
                let left = want - written;
                let take = usize::try_from(left.min(bs)).unwrap_or(self.block_size);
                if phys == 0 {
                    // A hole: it reads as zeros without occupying a block to read.
                    out.write_all(&zeros[..take])?;
                } else {
                    let block = self.block(phys)?;
                    out.write_all(&block[..take])?;
                }
                written += take as u64;
                if written >= want {
                    break;
                }
            }
        }
        Ok(written)
    }

    /// Read a file's bytes at `offset` into `buf`, returning how many were filled.
    ///
    /// This is the ranged read the whole-file forms are built on: it fills at most
    /// `buf.len()` bytes and stops at the file's logical size, so a short return means the
    /// range reached the end of the file rather than that anything was dropped. An `offset`
    /// at or past the size fills nothing. Holes are filled with zeros, exactly as they
    /// read.
    ///
    /// Everything it allocates is bounded by `buf`: the logical-to-physical map covers the
    /// window the buffer spans and no more, so a hostile `i_size` costs the caller nothing
    /// beyond the buffer they chose. [`Limits::max_file_bytes`] therefore does not apply
    /// here — the buffer *is* the bound — and the mapping structures are followed only for
    /// the window, so blocks outside it are neither read nor validated.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the mapping or a data block cannot be read.
    pub fn read_into(
        &mut self,
        inode: &Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        let size = self.file_len(inode);
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let bs = self.block_size as u64;
        let want = (size - offset).min(buf.len() as u64);
        // The window is the logical blocks the range touches: the block holding `offset`
        // through the one holding its last byte.
        let first = usize::try_from(offset / bs).unwrap_or(usize::MAX);
        let last = usize::try_from((offset + want - 1) / bs).unwrap_or(usize::MAX);
        let count = last - first + 1;
        // Where the range begins inside its first block, and so where each block's bytes
        // land in the buffer.
        let mut skip = usize::try_from(offset % bs).unwrap_or(0);
        let mut filled = 0usize;
        for phys in self.map_window(inode, first, count)? {
            let take =
                (self.block_size - skip).min(usize::try_from(want).unwrap_or(usize::MAX) - filled);
            if phys == 0 {
                // A hole reads as zeros; the buffer is filled rather than left as it was,
                // so a caller reusing one buffer never sees a previous read's bytes.
                buf[filled..filled + take].fill(0);
            } else {
                let block = self.block(phys)?;
                buf[filled..filled + take].copy_from_slice(&block[skip..skip + take]);
            }
            filled += take;
            skip = 0;
            if filled as u64 >= want {
                break;
            }
        }
        Ok(filled)
    }

    /// A file's logical size as a whole-file read sees it: the length
    /// [`file_len`](Self::file_len) reports, held to [`Limits::max_file_bytes`].
    ///
    /// # Errors
    ///
    /// [`ReadError::FileTooLarge`] if the size exceeds the cap.
    fn whole_file_len(&mut self, inode: &Inode) -> Result<u64, ReadError> {
        let size = self.file_len(inode);
        if size > self.limits.max_file_bytes {
            return Err(ReadError::FileTooLarge {
                size,
                limit: self.limits.max_file_bytes,
            });
        }
        Ok(size)
    }

    /// The logical size of the data an inode maps.
    ///
    /// Three things narrow the inode's own size field. An inode whose block area holds
    /// something else — a fast symlink's target, a device's numbers — maps no data at all,
    /// whatever the field claims. A size past the 2^32-block logical ceiling cannot be
    /// mapped past it. And a directory holds no holes, so it cannot span more blocks than
    /// the image has; both bounds come from [`logical_block_count`](Self::logical_block_count).
    ///
    /// This is the length every read of an inode's data yields, so it is also the length
    /// anything declaring that data — a tar member's header — must state, or the
    /// declaration and the bytes disagree.
    pub(crate) fn file_len(&mut self, inode: &Inode) -> u64 {
        if !maps_data(inode, self.block_size) {
            return 0;
        }
        let mapped =
            (self.logical_block_count(inode) as u64).saturating_mul(self.block_size as u64);
        inode.size.min(mapped)
    }

    /// The most names the source has room to describe: every name a well-formed
    /// filesystem holds occupies a directory record of at least [`MIN_DIRENT_LEN`] bytes
    /// in a block of its own filesystem, so the source's length divided by that is a
    /// bound no well-formed image reaches and a crafted one cannot exceed.
    fn max_names(&mut self) -> usize {
        usize::try_from(self.source_len() / MIN_DIRENT_LEN).unwrap_or(usize::MAX)
    }

    /// Parse the jbd2 journal superblock, or `None` when the image carries no journal.
    ///
    /// The journal lives in inode 8 (`s_journal_inum`); its first data block is the
    /// journal superblock. This confirms the log is a well-formed, empty v2 journal.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the journal inode or its first block cannot be read,
    /// or the block is not a valid journal superblock.
    pub fn journal_superblock(
        &mut self,
    ) -> Result<Option<crate::journal::JournalSuperblock>, ReadError> {
        let Some(first) = self.journal_superblock_block()? else {
            return Ok(None);
        };
        let block = self.block(first)?;
        Ok(Some(crate::journal::JournalSuperblock::read_from(&block)?))
    }

    /// The block holding the journal superblock, or `None` when the image carries no
    /// journal.
    ///
    /// Separate from [`journal_superblock`](Self::journal_superblock) because a caller
    /// writing the log's recorded identity back needs where it is, not only what it says.
    pub(crate) fn journal_superblock_block(&mut self) -> Result<Option<u64>, ReadError> {
        if !self.feature.has_journal() || self.sb.journal_inum == 0 {
            return Ok(None);
        }
        let inode = self.inode(self.sb.journal_inum)?;
        // On ext3 the journal is block-mapped, so this must not assume an extent tree.
        // Only the log's first block is wanted, so only that much of the map is built: an
        // inode whose size claims terabytes of journal costs one entry to read, not one
        // per block it claims.
        let want = self.logical_block_count(&inode).min(1);
        let first = self
            .map_window(&inode, 0, want)?
            .first()
            .copied()
            .filter(|&b| b != 0)
            .ok_or(ReadError::BadJournal)?;
        Ok(Some(first))
    }

    /// Read a symlink's target, whether stored inline (fast) or in a data block (slow).
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if a slow symlink's block cannot be read.
    pub fn read_symlink(&mut self, inode: &Inode) -> Result<Vec<u8>, ReadError> {
        // Whether the target is stored inline is a matter of the blocks the inode owns,
        // not of its size: a symlink holding a data block keeps its target there however
        // short it is. An inline target is bounded by the block area whatever the size
        // field claims, so a size past the area's end yields the area, not a panic.
        if is_fast_symlink(inode, self.block_size) {
            let len = usize::try_from(inode.size)
                .unwrap_or(usize::MAX)
                .min(inode.block.len());
            return Ok(inode.block[..len].to_vec());
        }
        self.read_data(inode)
    }

    /// Read an inode's extended attributes, both the inline set stored in the inode
    /// and the set in its external attribute block, if any.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the attribute block or an entry cannot be read.
    pub fn xattrs(&mut self, inode: &Inode) -> Result<Vec<Xattr>, ReadError> {
        let mut out = parse_inline(&inode.inline_xattr)?;
        if inode.file_acl != 0 {
            // The attribute-block pointer is checked against the filesystem's block
            // count exactly as a data-block pointer is. Bounding it by the source alone
            // would let a pointer past the filesystem but inside a larger disk image
            // read whatever sits beyond the partition as attributes.
            self.check_data_block(inode.file_acl)?;
            let block = self.block(inode.file_acl)?;
            out.extend(parse_block(&block)?);
        }
        Ok(out)
    }

    /// Decode a device node's `(major, minor)` numbers from its block area. Only
    /// meaningful for a character- or block-special inode.
    #[must_use]
    pub fn device(&self, inode: &Inode) -> (u32, u32) {
        let b0 = u32::from_le_bytes([
            inode.block[0],
            inode.block[1],
            inode.block[2],
            inode.block[3],
        ]);
        let b1 = u32::from_le_bytes([
            inode.block[4],
            inode.block[5],
            inode.block[6],
            inode.block[7],
        ]);
        decode_device(b0, b1)
    }

    /// Read a directory's entries, skipping the unused slots and the checksum tail.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if the directory's blocks cannot be read or parsed.
    pub fn read_dir(&mut self, inode: &Inode) -> Result<Vec<Entry>, ReadError> {
        let mut entries = Vec::new();
        for phys in self.data_blocks(inode)? {
            // A directory block a mapping does not name holds no entries.
            if phys == 0 {
                continue;
            }
            let block = self.block(phys)?;
            let mut off = 0;
            // Walk to the end of the block. Under `metadata_csum` the final twelve
            // bytes are a checksum tail, which parses as a zero-inode slot and is
            // skipped by the `inode != 0` test below; without the feature the kernel
            // tiles real entries across the whole block, so a legitimate entry can begin
            // in those last twelve bytes. Stopping short of the block's end would drop
            // it.
            while off < self.block_size {
                let (entry, rec_len) = DirEntry::read_from(&block[off..], self.block_size)?;
                // [`DirEntry::read_from`] returns no record shorter than the eight-byte
                // header it parses, so `off` always advances and this cannot fire. It
                // guards that invariant rather than describing a record an image holds: a
                // zero-length one would turn the walk below into the one thing a reader of
                // hostile bytes must never do.
                if rec_len == 0 {
                    return Err(ReadError::BadDirectory);
                }
                if entry.inode != 0 {
                    entries.push(Entry {
                        name: entry.name,
                        inode: entry.inode,
                        file_type: entry.file_type,
                    });
                }
                off += rec_len;
            }
        }
        Ok(entries)
    }

    /// Resolve a path to its inode number and inode, following symbolic links.
    ///
    /// The path is resolved against *this filesystem's* root, never the host's — an
    /// absolute link target restarts at inode 2 of this image, and nothing here can name
    /// a file outside it. A leading `/` is optional, `.` and empty components are
    /// skipped, and `..` resolves through the directory's own entry for it.
    ///
    /// Symbolic links in the path are followed, including in the final component.
    /// This is not a nicety on a Linux root filesystem: a merged-`/usr` distribution
    /// makes `/lib`, `/bin`, and `/sbin` links into `/usr`, so `/lib/modules` — the
    /// first place to look when a kernel boots without drivers — is unreachable without
    /// following one.
    ///
    /// Resolution follows at most [`MAX_SYMLINK_HOPS`] links, so a cycle terminates.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotFound`] if a component names no entry;
    /// [`ReadError::NotADirectory`] if a non-final component is not a directory;
    /// [`ReadError::SymlinkLoop`] if the path follows too many links;
    /// [`ReadError`] variants if a directory or link along the way cannot be read.
    pub fn lookup(&mut self, path: &[u8]) -> Result<(u32, Inode), ReadError> {
        self.resolve(path, true)
    }

    /// Resolve a path to its inode number and inode, following symbolic links in every
    /// component *except* the last — so a path naming a symlink yields the link itself,
    /// not its target. Otherwise as [`lookup`](Self::lookup).
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn lookup_no_follow(&mut self, path: &[u8]) -> Result<(u32, Inode), ReadError> {
        self.resolve(path, false)
    }

    /// Walk `path` component by component from the root, expanding symbolic links.
    ///
    /// `follow_final` decides whether a link in the last component is expanded; the
    /// links before it always are, because a path cannot continue through a link
    /// without going where it points.
    fn resolve(&mut self, path: &[u8], follow_final: bool) -> Result<(u32, Inode), ReadError> {
        let mut pending: VecDeque<Vec<u8>> = components(path);
        let mut number = ROOT_INO;
        let mut inode = self.inode(number)?;
        let mut hops = 0u32;

        while let Some(name) = pending.pop_front() {
            if !is_dir(&inode) {
                return Err(ReadError::NotADirectory {
                    path: path.to_vec(),
                });
            }
            let entry = self
                .read_dir(&inode)?
                .into_iter()
                .find(|e| e.name == name)
                .ok_or_else(|| ReadError::NotFound {
                    path: path.to_vec(),
                })?;
            let next = self.inode(entry.inode)?;

            let final_component = pending.is_empty();
            if is_symlink(&next) && (follow_final || !final_component) {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(ReadError::SymlinkLoop {
                        path: path.to_vec(),
                    });
                }
                // A target longer than a path can be is refused before it is read, so a
                // crafted `i_size` cannot make one link allocate the whole image.
                if next.size > MAX_PATH as u64 {
                    return Err(ReadError::NotFound {
                        path: path.to_vec(),
                    });
                }
                let target = self.read_symlink(&next)?;
                if target.is_empty() {
                    return Err(ReadError::NotFound {
                        path: path.to_vec(),
                    });
                }
                // An absolute target restarts at this filesystem's root; a relative one
                // continues from the directory holding the link, which `inode` still is,
                // because the walk did not descend into the link.
                if target.starts_with(b"/") {
                    number = ROOT_INO;
                    inode = self.inode(number)?;
                }
                for c in components(&target).into_iter().rev() {
                    pending.push_front(c);
                }
                continue;
            }
            number = entry.inode;
            inode = next;
        }
        Ok((number, inode))
    }

    /// Walk the whole tree, yielding one [`WalkEntry`] per name below the root.
    ///
    /// Entries come out in depth-first order, each directory's names sorted. The walk
    /// starts *below* the root: the root directory itself has no name and so no entry,
    /// and every path begins with `/`. `.` and `..` are not yielded.
    ///
    /// A directory inode is descended into only the first time it is reached, so a
    /// directory cycle or a hard-linked directory bounds the walk rather than fanning
    /// it out; the repeat still appears as an entry, it is simply not descended.
    ///
    /// # Bounds
    ///
    /// The walk is bounded by [`Limits::max_walk_entries`] and by the number of names the
    /// source has room to hold, whichever is smaller. Reaching either is an error rather
    /// than a short list: a walk that returned what it managed to gather would drop names
    /// with nothing to say it had, and a caller extracting a tree would write an
    /// incomplete one and see success.
    ///
    /// The structural bound is what makes this safe to point at an image built to be
    /// hostile: distinct directory inodes may map the *same* data blocks, so a small image
    /// can describe an unbounded number of names, while a well-formed one spends at least
    /// [`MIN_DIRENT_LEN`] bytes of its own blocks per name and so can never reach the
    /// bound.
    ///
    /// # Errors
    ///
    /// [`ReadError`] variants if any directory along the walk cannot be read, or
    /// [`ReadError::WalkTooLarge`] if the tree holds more names than the bounds allow.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, ReadError> {
        let mut out = Vec::new();
        self.walk_with::<ReadError>(|_, entry| {
            out.push(entry);
            Ok(())
        })?;
        Ok(out)
    }

    /// Walk the whole tree, handing each [`WalkEntry`] to `visit` as it is reached rather
    /// than gathering them all first.
    ///
    /// The order, the bounds, and the cycle handling are [`walk`](Self::walk)'s exactly;
    /// what differs is that nothing accumulates, so a tree of any size costs the walk's own
    /// state rather than one full [`Inode`] and path per name. That is what makes a whole
    /// tree processable in a fixed working set — writing an archive, counting a tree,
    /// building an index.
    ///
    /// `visit` receives the reader itself, so it may read each entry's contents,
    /// attributes, or link target as it goes. It is called once per name, in walk order,
    /// and an error it returns stops the walk and is returned unchanged — so a consumer's
    /// own failure is not reported as a fault in the image.
    ///
    /// The error type is the consumer's, and the walk's own [`ReadError`]s convert into it,
    /// so a caller whose work has failures of its own — writing an archive, say — reports
    /// them in its own vocabulary rather than forcing them through this one.
    ///
    /// # Errors
    ///
    /// Whatever `visit` returns, or the [`walk`](Self::walk) errors converted into it:
    /// [`ReadError`] variants if a directory cannot be read, or [`ReadError::WalkTooLarge`]
    /// if the tree holds more names than the bounds allow.
    pub fn walk_with<E: From<ReadError>>(
        &mut self,
        mut visit: impl FnMut(&mut Self, WalkEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        let cap = self.limits.max_walk_entries.min(self.max_names());
        let mut seen = 0usize;
        let root = self.inode(ROOT_INO).map_err(E::from)?;
        // Track the directory inodes descended into: a well-formed tree reaches each
        // exactly once, so declining to re-descend a repeat bounds the walk against a
        // directory cycle or a hard-linked directory rather than fanning out.
        let mut visited = HashSet::new();
        visited.insert(ROOT_INO);
        // An explicit stack of entries still to visit, rather than recursion, so a tree
        // nested arbitrarily deep is walked without a call-stack bound. The root has no
        // name, so the walk seeds from its children. Children are pushed in reverse name
        // order, so popping yields them in order and a directory's whole subtree is
        // emitted before its next sibling — the documented depth-first, names-sorted
        // order the recursion produced.
        let mut stack = self.walk_children(&root, &[]).map_err(E::from)?;
        while let Some(entry) = stack.pop() {
            if seen >= cap {
                return Err(E::from(ReadError::WalkTooLarge { limit: cap }));
            }
            seen += 1;
            // Descend into a subdirectory only the first time its inode is reached; a
            // repeat is a directory cycle or hard link, so re-descending would not
            // terminate. The visited set bounds fan-out; the explicit stack bounds
            // nothing but the heap, so depth is limited only by the image.
            if is_dir(&entry.inode) && visited.insert(entry.number) {
                let children = self
                    .walk_children(&entry.inode, &entry.path)
                    .map_err(E::from)?;
                stack.extend(children);
            }
            visit(self, entry)?;
        }
        Ok(())
    }

    /// The child entries of directory `inode` as walk entries, in reverse name order so
    /// a stack pops them in name order. `.` and `..` are skipped; each child's inode is
    /// read once here.
    fn walk_children(&mut self, inode: &Inode, prefix: &[u8]) -> Result<Vec<WalkEntry>, ReadError> {
        let mut entries = self.read_dir(inode)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut children = Vec::new();
        for e in entries.iter().rev() {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            // A name a real directory could not hold is not built into a path: a `/`
            // would traverse out of the tree and a NUL would truncate the path a
            // consumer forms from it. The entry is skipped here; a scan reports it.
            if name_is_hostile(&e.name) {
                continue;
            }
            let mut path = prefix.to_vec();
            path.push(b'/');
            path.extend_from_slice(&e.name);
            let child = self.inode(e.inode)?;
            children.push(WalkEntry {
                path,
                number: e.inode,
                inode: child,
            });
        }
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GrowReservation;
    use crate::materialize::{FormatOptions, format};
    use crate::ondisk::Timestamp;
    use crate::source::{Metadata, TreeBuilder};

    const MIB: u64 = 1024 * 1024;

    fn opts() -> FormatOptions {
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
        o
    }

    #[test]
    fn an_io_failure_keeps_the_kind_it_was_classified_as() {
        // A truncated image and an unreadable one are different outcomes, and a caller
        // that only sees the message has to match on text to tell them apart. The kind
        // travels alongside so it does not have to.
        let truncated = ReadError::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "image ends mid-superblock",
        ));
        let ReadError::Io { kind, message } = &truncated else {
            panic!("expected an i/o error, got {truncated:?}");
        };
        assert_eq!(*kind, std::io::ErrorKind::UnexpectedEof);
        assert!(message.contains("image ends mid-superblock"), "{message}");
        // And the text a caller logs still carries the message, so the richer payload did
        // not come at the cost of the rendering.
        assert!(
            truncated.to_string().contains("image ends mid-superblock"),
            "{truncated}"
        );

        let denied = ReadError::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(
            denied,
            ReadError::Io {
                kind: std::io::ErrorKind::PermissionDenied,
                ..
            }
        ));
    }

    #[test]
    fn a_size_past_the_logical_ceiling_is_not_a_length_a_read_yields() {
        // A file's size field is the image's own claim; the length a read yields is what
        // the map reaches, and no map reaches past 2^32 logical blocks. Anything that
        // declares an inode's data ahead of streaming it — a tar member's header — states
        // the second, or it promises bytes the body will never carry.
        let time = Timestamp::from_secs(1_700_000_000);
        let source = TreeBuilder::new().file(
            b"/hello".to_vec(),
            b"hi\n".to_vec(),
            Metadata::new(0o644, time),
        );
        let image = format(source, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let (_, mut inode) = r.lookup(b"/hello").unwrap();
        assert_eq!(r.file_len(&inode), 3);

        // 16 TiB at a 4 KiB block is the whole logical reach of a map; past it the size
        // field is the only thing saying the bytes are there.
        let ceiling = MAX_LOGICAL_BLOCKS * r.block_size as u64;
        for claimed in [ceiling + 1, ceiling * 2, u64::MAX] {
            inode.size = claimed;
            assert_eq!(r.file_len(&inode), ceiling, "claimed {claimed}");
        }
        // Below the ceiling the two agree, so nothing an ordinary image holds is narrowed.
        inode.size = ceiling;
        assert_eq!(r.file_len(&inode), ceiling);
    }

    /// The walk as a path-to-inode map, for the tests that ask what is at a path rather
    /// than which paths share an inode.
    fn walk_tree<R: Read + Seek>(r: &mut Reader<R>) -> std::collections::BTreeMap<Vec<u8>, Inode> {
        r.walk()
            .unwrap()
            .into_iter()
            .map(|e| (e.path, e.inode))
            .collect()
    }

    #[test]
    fn reads_back_an_empty_filesystem() {
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        assert_eq!(r.superblock().inodes_count, 16384);
        // Root has only lost+found.
        let root = r.inode(2).unwrap();
        let entries = r.read_dir(&root).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&b".".to_vec()));
        assert!(names.contains(&b"..".to_vec()));
        assert!(names.contains(&b"lost+found".to_vec()));
    }

    #[test]
    fn default_image_carries_a_readable_empty_journal() {
        // The default profile has a journal: inode 8 is a regular extent file, the
        // superblock points at it and backs up its block map, and its first block is a
        // well-formed, empty v2 jbd2 superblock. A 512 MiB image sizes to 4096 blocks.
        let image = format(TreeBuilder::new(), 512 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        assert!(r.feature().has_journal());
        assert_eq!(r.superblock().journal_inum, 8);
        assert_eq!(r.superblock().jnl_backup_type, 1);

        let jsb = r.journal_superblock().unwrap().expect("has a journal");
        assert_eq!(jsb.block_size, 4096);
        assert_eq!(jsb.max_len, 4096);
        assert_eq!(jsb.first, 1);
        assert_eq!(jsb.sequence, 1);
        assert_eq!(jsb.start, 0);
        assert_eq!(jsb.nr_users, 1);
        assert_eq!(jsb.uuid, [1u8; 16]);

        // The journal inode is a regular extent file of the journal's size, and the
        // superblock's s_jnl_blocks backup mirrors its i_block map.
        let inode = r.inode(8).unwrap();
        assert_eq!(inode.mode, 0o100600);
        assert_eq!(inode.links_count, 1);
        assert!(inode.flags.contains(InodeFlags::EXTENTS));
        assert_eq!(inode.size, 4096 * 4096);
        for (i, word) in inode.block.chunks_exact(4).enumerate() {
            let w = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            assert_eq!(r.superblock().jnl_blocks[i], w, "jnl_blocks[{i}]");
        }
        assert_eq!(r.superblock().jnl_blocks[16], inode.size as u32);
    }

    #[test]
    fn no_journal_feature_leaves_inode_eight_empty() {
        // Clearing has_journal reverts inode 8 to an empty reserved inode with no
        // superblock journal pointer — the reader reports no journal. The orphan file's
        // entries are journalled, so it goes with the journal.
        let mut o = opts();
        o.feature.compat = crate::feature::Compat::from_bits(
            o.feature.compat.bits()
                & !(crate::feature::Compat::HAS_JOURNAL.bits()
                    | crate::feature::Compat::ORPHAN_FILE.bits()),
        );
        let image = format(TreeBuilder::new(), 64 * MIB, o).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        assert!(!r.feature().has_journal());
        assert_eq!(r.superblock().journal_inum, 0);
        assert_eq!(r.superblock().jnl_backup_type, 0);
        assert!(r.journal_superblock().unwrap().is_none());
        // Inode 8 is an empty reserved inode (it still carries a metadata checksum, so
        // compare the content fields rather than the whole struct).
        let inode = r.inode(8).unwrap();
        assert_eq!(inode.mode, 0);
        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.size, 0);
        assert_eq!(inode.blocks, 0);
    }

    #[test]
    fn round_trips_a_populated_tree() {
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), m(0o755))
            .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
            .symlink(
                b"/etc/mtab".to_vec(),
                b"/proc/self/mounts".to_vec(),
                m(0o777),
            )
            .file(
                b"/big".to_vec(),
                vec![0x42; 20_000],
                m(0o600).owned_by(7, 9),
            );
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let tree = walk_tree(&mut r);

        // File contents survive.
        let hostname = &tree[&b"/etc/hostname".to_vec()];
        assert_eq!(r.read_data(hostname).unwrap(), b"ferrosys\n");
        assert_eq!(hostname.mode, 0o100644);

        // A large file spanning several blocks reads back byte-for-byte.
        let big = &tree[&b"/big".to_vec()];
        assert_eq!(r.read_data(big).unwrap(), vec![0x42; 20_000]);
        assert_eq!(big.uid, 7);
        assert_eq!(big.gid, 9);

        // A fast symlink's target reads back.
        let mtab = &tree[&b"/etc/mtab".to_vec()];
        assert_eq!(r.read_symlink(mtab).unwrap(), b"/proc/self/mounts");
        assert_eq!(mtab.mode & 0o170000, 0o120000);
    }

    #[test]
    fn round_trips_hardlinks_as_a_shared_inode() {
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .file(b"/a".to_vec(), b"shared".to_vec(), m(0o644))
            .hardlink(b"/b".to_vec(), b"/a".to_vec(), m(0o644));
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let root = r.inode(2).unwrap();
        let entries = r.read_dir(&root).unwrap();
        let a = entries.iter().find(|e| e.name == b"a").unwrap().inode;
        let b = entries.iter().find(|e| e.name == b"b").unwrap().inode;
        assert_eq!(a, b, "hard links share one inode");
        assert_eq!(r.inode(a).unwrap().links_count, 2);
    }

    #[test]
    fn round_trips_a_slow_symlink() {
        let time = Timestamp::from_secs(1_700_000_000);
        let target = vec![b'p'; 200];
        let src = TreeBuilder::new().symlink(
            b"/link".to_vec(),
            target.clone(),
            Metadata::new(0o777, time),
        );
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let root = r.inode(2).unwrap();
        let link_ino = r
            .read_dir(&root)
            .unwrap()
            .iter()
            .find(|e| e.name == b"link")
            .unwrap()
            .inode;
        let link = r.inode(link_ino).unwrap();
        assert_eq!(r.read_symlink(&link).unwrap(), target);
    }

    /// The byte offset of inode `number` within `bytes`, for the tests that reach past
    /// the accessors to corrupt one field. Group 0's table holds the low inode numbers
    /// every tree here uses.
    fn inode_offset(bytes: &[u8], number: u32) -> usize {
        let mut r = Reader::open(std::io::Cursor::new(bytes)).unwrap();
        let inode_size = r.superblock().inode_size as usize;
        let table = r.group_descriptor(0).unwrap().inode_table as usize;
        table * 4096 + (number as usize - 1) * inode_size
    }

    #[test]
    fn a_symlink_owning_a_data_block_reads_its_target_from_the_block() {
        // Whether a target is stored inline is a matter of the blocks the inode owns,
        // not of its size: a symlink holding a data block keeps its target there however
        // short its size field says it is. Splitting on the length instead returns the
        // extent header that sits in the block area where the target is not — a silent
        // wrong read of a filesystem an older kernel wrote.
        let time = Timestamp::from_secs(1_700_000_000);
        let target = vec![b'p'; 200];
        let src = TreeBuilder::new().symlink(
            b"/link".to_vec(),
            target.clone(),
            Metadata::new(0o777, time),
        );
        let mut bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let ino = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.lookup_no_follow(b"/link").expect("lookup /link").0
        };
        let off = inode_offset(&bytes, ino);
        // i_size_lo sits at inode offset 0x04. Shortened to a length the inline area
        // could have held, while the target stays in the data block the inode owns.
        crate::ondisk::put_u32(&mut bytes[off..], 0x04, 40);

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let link = r.inode(ino).unwrap();
        assert!(link.blocks > 0, "the symlink owns a data block");
        assert_eq!(
            r.read_symlink(&link).unwrap(),
            target[..40].to_vec(),
            "the target came from the block the inode owns, not from its block area"
        );
    }

    #[test]
    fn a_fast_symlink_carrying_an_attribute_block_still_reads_inline() {
        // An external attribute block is charged to `i_blocks`, so a fast symlink that
        // carries one owns a block without keeping its target in one. Discounting that
        // block before asking whether any storage remains is what keeps the target
        // readable; counting it reads the inline target as a block map instead.
        let time = Timestamp::from_secs(1_700_000_000);
        let target = b"/proc/self/mounts".to_vec();
        let src = TreeBuilder::new()
            .symlink(
                b"/mtab".to_vec(),
                target.clone(),
                Metadata::new(0o777, time),
            )
            .xattr(b"user.blob".to_vec(), vec![0xAB; 300]);
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let (_, link) = r.lookup_no_follow(b"/mtab").expect("lookup /mtab");

        assert_ne!(link.file_acl, 0, "the attribute set spilled to a block");
        assert_ne!(link.blocks, 0, "which is charged to i_blocks");
        assert_eq!(r.read_symlink(&link).unwrap(), target);
    }

    #[test]
    fn a_fast_symlink_claiming_more_than_its_block_area_yields_the_area() {
        // A size field larger than the area the target lives in bounds the read to the
        // area rather than indexing past it or walking a block map the inode has no
        // blocks for.
        let time = Timestamp::from_secs(1_700_000_000);
        let src = TreeBuilder::new().symlink(
            b"/mtab".to_vec(),
            b"/proc/self/mounts".to_vec(),
            Metadata::new(0o777, time),
        );
        let mut bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let ino = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.lookup_no_follow(b"/mtab").expect("lookup /mtab").0
        };
        let off = inode_offset(&bytes, ino);
        crate::ondisk::put_u32(&mut bytes[off..], 0x04, 100);

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let link = r.inode(ino).unwrap();
        assert_eq!(
            r.read_symlink(&link).unwrap().len(),
            Inode::BLOCK_BYTES,
            "the read is bounded by the block area the target lives in"
        );
    }

    #[test]
    fn an_attribute_block_pointer_past_the_filesystem_is_refused() {
        // A filesystem embedded in a larger disk image has bytes beyond its own block
        // count that a pointer can still reach. `i_file_acl` is checked against the
        // filesystem's block count exactly as a data-block pointer is, so it cannot read
        // a neighbouring partition's bytes back as this inode's attributes.
        let time = Timestamp::from_secs(1_700_000_000);
        let src = TreeBuilder::new()
            .file(b"/f".to_vec(), b"x".to_vec(), Metadata::new(0o644, time))
            .xattr(b"user.blob".to_vec(), vec![0xAB; 300]);
        let mut bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let (ino, blocks_count) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            (
                r.lookup(b"/f").expect("lookup /f").0,
                r.superblock().blocks_count,
            )
        };

        // The neighbour: one block past the filesystem, holding a well-formed attribute
        // block. Parsing it in isolation proves it is readable, so the bounds check is
        // the only thing that can stop the read below.
        let planted = crate::ondisk::Xattr {
            name: b"user.neighbour".to_vec(),
            value: b"from the next partition".to_vec(),
        };
        let neighbour = crate::ondisk::encode_block(std::slice::from_ref(&planted), 4096, false);
        assert_eq!(
            crate::ondisk::parse_block(&neighbour).unwrap(),
            vec![planted],
            "the planted block is a readable attribute block"
        );
        let at = usize::try_from(blocks_count).unwrap() * 4096;
        bytes.resize(at + 4096, 0);
        bytes[at..at + 4096].copy_from_slice(&neighbour);

        // i_file_acl_lo sits at inode offset 0x68.
        let off = inode_offset(&bytes, ino);
        crate::ondisk::put_u32(
            &mut bytes[off..],
            0x68,
            u32::try_from(blocks_count).unwrap(),
        );

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let inode = r.inode(ino).unwrap();
        assert_eq!(inode.file_acl, blocks_count);
        assert!(
            matches!(
                r.xattrs(&inode),
                Err(ReadError::OutOfRange { what: "block", index }) if index == blocks_count
            ),
            "an attribute block outside the filesystem was read: {:?}",
            r.xattrs(&inode)
        );
    }

    #[test]
    fn the_descriptor_stride_ignores_s_desc_size_without_64bit() {
        // `s_desc_size` describes the group descriptor only under `64bit`. Without that
        // feature every descriptor is the 32-byte classic form whatever the word holds,
        // so the same filesystem must read identically however that word is set.
        // Honoring a stale 64 strides past every descriptor after the first, reading
        // group 1's from where group 2's would begin.
        let mut o = opts();
        o.feature.incompat = o.feature.incompat.without(Incompat::SIXTY_FOUR_BIT);
        o.grow = GrowReservation::None;
        let bytes = format(TreeBuilder::new(), 256 * MIB, o)
            .unwrap()
            .into_bytes();

        let pristine = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            assert_eq!(r.desc_size(), GroupDescriptor::SIZE_32);
            assert!(
                r.group_count() > 1,
                "the image must span more than one group for the stride to show"
            );
            (0..r.group_count())
                .map(|g| r.group_descriptor(g).unwrap())
                .collect::<Vec<_>>()
        };

        // s_desc_size sits at superblock offset 0xfe.
        let mut corrupt = bytes.clone();
        put_u16(&mut corrupt[1024..], 0xfe, GroupDescriptor::SIZE_64 as u16);

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        assert_eq!(r.desc_size(), GroupDescriptor::SIZE_32);
        let after: Vec<_> = (0..r.group_count())
            .map(|g| r.group_descriptor(g).unwrap())
            .collect();
        assert_eq!(
            after, pristine,
            "a meaningless s_desc_size moved the descriptors"
        );

        // And under `64bit` the field is what decides: the default profile sets both.
        let wide = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let r = Reader::open(std::io::Cursor::new(wide.as_bytes())).unwrap();
        assert!(r.feature().is_64bit());
        assert_eq!(r.desc_size(), GroupDescriptor::SIZE_64);
    }

    #[test]
    fn a_64bit_superblock_rejects_an_out_of_bounds_desc_size() {
        // Under `64bit` s_desc_size sets the descriptor stride and the width its checksum
        // covers, so the reader holds it to the kernel's bounds: a power of two from
        // `EXT4_MIN_DESC_SIZE_64BIT` (64) up to the block size. A 32-byte value would read
        // a 64-bit table at half its stride; a value past the block size would run each
        // descriptor beyond its block. Both are refused at open. The default profile is
        // `64bit`, and open validates structure before any checksum, so the corruption
        // surfaces as the field error, not a checksum mismatch.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        // s_desc_size sits at superblock offset 0xfe; the superblock starts at byte 1024.
        for bad in [32u16, 8192] {
            let mut corrupt = image.as_bytes().to_vec();
            put_u16(&mut corrupt[1024..], 0xfe, bad);
            assert!(
                matches!(
                    Reader::open(std::io::Cursor::new(&corrupt)),
                    Err(ReadError::Parse(ParseError::InvalidField {
                        field: "s_desc_size",
                        ..
                    }))
                ),
                "a 64bit image with s_desc_size={bad} must be refused at open"
            );
        }
        // The valid 64-byte value the default writes still opens.
        assert!(Reader::open(std::io::Cursor::new(image.as_bytes())).is_ok());
    }

    #[test]
    fn a_corrupted_index_tail_reserved_word_is_caught() {
        // The index checksum covers `dt_reserved` as it lies on disk and stands in four
        // zero bytes only for `dt_checksum` itself. Folding the whole tail as zeros
        // leaves the reserved word uncovered, so a bit flip there passes verification
        // unseen — the one case where the two derivations differ.
        let time = Timestamp::from_secs(1_700_000_000);
        let mut o = opts();
        o.feature.block_size = 1024;
        o.grow = GrowReservation::None;

        let mut src = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, time));
        for i in 0..64u32 {
            let mut name = format!("/d/entry-{i:04}").into_bytes();
            name.resize(b"/d/".len() + 200, b'x');
            src = src.file(name, Vec::new(), Metadata::new(0o644, time));
        }
        let mut bytes = format(src, 64 * MIB, o).unwrap().into_bytes();

        let (root_block, tail) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let (_, dir) = r.lookup(b"/d").expect("the directory is present");
            assert!(
                dir.flags.contains(InodeFlags::INDEX),
                "the directory must be hash-indexed for it to have an index tail"
            );
            r.verify_checksums()
                .expect("it verifies clean to begin with");
            let block = r.data_blocks(&dir).unwrap()[0];
            let raw = r.block(block).unwrap();
            let limit = usize::from(get_u16(&raw, DX_ROOT_COUNT_OFFSET));
            (block, dx_tail_offset(DX_ROOT_COUNT_OFFSET, limit))
        };

        // dt_reserved opens the tail; dt_checksum follows it.
        let at = usize::try_from(root_block).unwrap() * 1024 + tail;
        assert_eq!(bytes[at..at + 4], [0; 4], "the writer leaves it zero");
        bytes[at] = 0xff;

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        assert!(
            matches!(
                r.verify_checksums(),
                Err(ReadError::ChecksumMismatch {
                    object: "directory block",
                    ..
                })
            ),
            "a flipped dt_reserved went unnoticed: {:?}",
            r.verify_checksums()
        );
    }

    #[test]
    fn unsupported_features_are_reported_by_name() {
        // A report that renders a real feature as a bare hexadecimal bit tells a reader
        // nothing to act on. Every bit ext4 defines is named — whether or not this crate
        // models it — and only a bit no ext4 feature claims stays hexadecimal.
        let d = describe_unsupported_incompat(
            Incompat::META_BG.bits() | 0x0000_4000 | 0x0000_8000 | 0x8000_0000,
        );
        for name in ["meta_bg", "large_dir", "inline_data", "0x80000000"] {
            assert!(d.contains(name), "{name} is missing from {d:?}");
        }
        let order: Vec<usize> = ["meta_bg", "large_dir", "inline_data", "0x80000000"]
            .iter()
            .map(|n| d.find(n).unwrap())
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "features are listed in ascending bit order: {d:?}"
        );
    }

    #[test]
    fn every_incompat_bit_is_named_by_exactly_one_table() {
        // Two tables name ext4's `incompat` vocabulary between them: the feature word
        // for what this crate models, and the diagnostic table for the rest. A bit in
        // both would be named twice in one report.
        for (name, bit) in UNMODELLED_INCOMPAT {
            assert_eq!(bit.count_ones(), 1, "{name} names exactly one bit");
            assert!(
                Incompat::from_bits(*bit).names().is_empty(),
                "{name} ({bit:#x}) is named by the feature word too"
            );
            assert_eq!(
                bit & SUPPORTED_INCOMPAT,
                0,
                "{name} ({bit:#x}) is a feature the reader claims to follow"
            );
        }
    }

    #[test]
    fn round_trips_inline_and_block_xattrs() {
        let time = Timestamp::from_secs(1_700_000_000);
        let cap = vec![
            0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let src = TreeBuilder::new()
            .directory(b"/bin".to_vec(), Metadata::new(0o755, time))
            // A small attribute set stays inline in the inode.
            .file(
                b"/bin/ping".to_vec(),
                b"elf".to_vec(),
                Metadata::new(0o755, time),
            )
            .xattr(b"security.capability".to_vec(), cap.clone())
            .xattr(b"user.note".to_vec(), b"hi".to_vec())
            // A large value overflows to an external xattr block.
            .file(b"/big".to_vec(), b"x".to_vec(), Metadata::new(0o644, time))
            .xattr(b"user.blob".to_vec(), vec![0xAB; 300]);
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let tree = walk_tree(&mut r);

        let ping = &tree[&b"/bin/ping".to_vec()];
        assert_eq!(ping.file_acl, 0, "small set stays inline, no acl block");
        let mut got = r.xattrs(ping).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, b"security.capability");
        assert_eq!(got[0].value, cap);
        assert_eq!(got[1].name, b"user.note");

        let big = &tree[&b"/big".to_vec()];
        assert_ne!(big.file_acl, 0, "large value spilled to a block");
        let blob = r.xattrs(big).unwrap();
        assert_eq!(blob.len(), 1);
        assert_eq!(blob[0].name, b"user.blob");
        assert_eq!(blob[0].value, vec![0xAB; 300]);
    }

    #[test]
    fn a_xattr_set_splits_between_the_inode_and_its_block() {
        // `user.huge` alone fills a whole 4096-byte attribute block, so the set only
        // exists on disk because `user.tiny` stays inline: one inode carrying both
        // regions at once, the state a kernel-written inode holds such a set in.
        let time = Timestamp::from_secs(1_700_000_000);
        let huge = vec![0xAA; 4040];
        let tiny = vec![0xBB; 60];
        let src = TreeBuilder::new()
            .file(b"/f".to_vec(), b"x".to_vec(), Metadata::new(0o644, time))
            .xattr(b"user.huge".to_vec(), huge.clone())
            .xattr(b"user.tiny".to_vec(), tiny.clone());
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let tree = walk_tree(&mut r);

        let f = &tree[&b"/f".to_vec()];
        assert_ne!(f.file_acl, 0, "the huge value spilled to a block");
        let inline = parse_inline(&f.inline_xattr).unwrap();
        assert_eq!(inline.len(), 1, "the tiny value stayed inline");
        assert_eq!(inline[0].name, b"user.tiny");
        let mut got = r.xattrs(f).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 2, "both regions read back as one set");
        assert_eq!(got[0].name, b"user.huge");
        assert_eq!(got[0].value, huge);
        assert_eq!(got[1].name, b"user.tiny");
        assert_eq!(got[1].value, tiny);
    }

    #[test]
    fn round_trips_device_fifo_and_socket_nodes() {
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/dev".to_vec(), m(0o755))
            .char_device(b"/dev/null".to_vec(), 1, 3, m(0o666))
            .block_device(b"/dev/sda".to_vec(), 8, 0, m(0o660))
            .fifo(b"/dev/initctl".to_vec(), m(0o600))
            .socket(b"/dev/log".to_vec(), m(0o666));
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let tree = walk_tree(&mut r);

        let null = &tree[&b"/dev/null".to_vec()];
        assert_eq!(null.mode & 0o170000, 0o020000, "char device");
        assert_eq!(null.mode & 0o7777, 0o666);
        assert_eq!(r.device(null), (1, 3));
        assert_eq!(null.blocks, 0, "no data blocks");

        let sda = &tree[&b"/dev/sda".to_vec()];
        assert_eq!(sda.mode & 0o170000, 0o060000, "block device");
        assert_eq!(r.device(sda), (8, 0));

        assert_eq!(
            tree[&b"/dev/initctl".to_vec()].mode & 0o170000,
            0o010000,
            "fifo"
        );
        assert_eq!(
            tree[&b"/dev/log".to_vec()].mode & 0o170000,
            0o140000,
            "socket"
        );
    }

    #[test]
    fn round_trips_distinct_and_fixed_timestamps() {
        let m = Metadata::new(0o644, Timestamp::from_secs(500)).with_times(
            Timestamp::from_secs(100),
            Timestamp::from_secs(200),
            Timestamp::from_secs(300),
        );
        let src = TreeBuilder::new().file(b"/f".to_vec(), b"x".to_vec(), m);
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let root = r.inode(2).unwrap();
        let f_ino = r
            .read_dir(&root)
            .unwrap()
            .iter()
            .find(|e| e.name == b"f")
            .unwrap()
            .inode;
        let f = r.inode(f_ino).unwrap();
        assert_eq!(f.atime, Timestamp::from_secs(100));
        assert_eq!(f.ctime, Timestamp::from_secs(200));
        assert_eq!(f.mtime, Timestamp::from_secs(300));
        assert_eq!(
            f.crtime,
            Timestamp::from_secs(300),
            "crtime derives from mtime"
        );

        // The fixed-time knob overrides every entry time.
        let mut fixed = opts();
        fixed.fixed_time = Some(Timestamp::from_secs(42));
        let src = TreeBuilder::new().file(b"/f".to_vec(), b"x".to_vec(), m);
        let image = format(src, 64 * MIB, fixed).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let root = r.inode(2).unwrap();
        let f_ino = r
            .read_dir(&root)
            .unwrap()
            .iter()
            .find(|e| e.name == b"f")
            .unwrap()
            .inode;
        let f = r.inode(f_ino).unwrap();
        assert_eq!(f.atime, Timestamp::from_secs(42));
        assert_eq!(f.mtime, Timestamp::from_secs(42));
        assert_eq!(f.crtime, Timestamp::from_secs(42));
    }

    #[test]
    fn the_fixed_time_clamp_reaches_the_reserved_structural_inodes() {
        // The clamp forces every inode's four times, including the reserved structural
        // inodes the materializer builds rather than the model — resize (7), journal
        // (8), and orphan (12). Unset, those inodes take the format time; set, they take
        // the clamp. (Teeth: before the fix they took the format time even when clamped.)
        let format_time = Timestamp::from_secs(1_700_000_000);
        let clamp = Timestamp::from_secs(42);
        assert_ne!(
            clamp, format_time,
            "the clamp must differ from the format time"
        );

        let mut fixed = opts();
        fixed.fixed_time = Some(clamp);
        let image = format(TreeBuilder::new(), 64 * MIB, fixed).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        for ino in [7u32, 8, 12] {
            let s = r.inode(ino).unwrap();
            assert_eq!(
                (s.atime, s.ctime, s.mtime, s.crtime),
                (clamp, clamp, clamp, clamp),
                "inode {ino}'s times honor the clamp, not the format time"
            );
        }

        // Unset, the same structural inodes carry the format time.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        for ino in [7u32, 8, 12] {
            assert_eq!(
                r.inode(ino).unwrap().mtime,
                format_time,
                "inode {ino} takes the format time when the clamp is unset"
            );
        }
    }

    #[test]
    fn verifies_metadata_checksums_and_detects_corruption() {
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), m(0o755))
            .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
            .file(b"/big".to_vec(), vec![0x42; 20_000], m(0o600));
        // A multi-group image so descriptors and backups are exercised.
        let bytes = format(src, 512 * MIB, opts()).unwrap().into_bytes();

        // A well-formed image passes its own checksum oracle.
        Reader::open(std::io::Cursor::new(&bytes))
            .unwrap()
            .verify_checksums()
            .unwrap();

        // Corrupting a superblock field the checksum covers is caught.
        let mut corrupt = bytes.clone();
        corrupt[1024 + 0x30] ^= 0xff; // s_wtime
        assert!(matches!(
            Reader::open(std::io::Cursor::new(&corrupt))
                .unwrap()
                .verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "superblock",
                ..
            })
        ));

        // Corrupting the root inode is caught, located by number.
        let root_off = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.group_descriptor(0).unwrap().inode_table as usize * 4096 + 256
        };
        let mut corrupt = bytes.clone();
        corrupt[root_off] ^= 0xff; // a byte of root inode's mode
        assert!(matches!(
            Reader::open(std::io::Cursor::new(&corrupt))
                .unwrap()
                .verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "inode",
                index: 2,
                ..
            })
        ));

        // Corrupting a group descriptor is caught and located by group. Group 1's
        // free-block count is a field the descriptor checksum covers and nothing else
        // reads before the descriptors are verified, so the descriptor's own oracle is
        // what fires. The descriptor table follows the superblock's block at 4 KiB
        // blocks, and `desc_size` is 64 bytes under `64bit`.
        let desc_size = {
            let r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.superblock().desc_size as usize
        };
        assert_eq!(desc_size, 64, "the default feature set sets 64bit");
        let mut corrupt = bytes.clone();
        corrupt[4096 + desc_size + 0x0c] ^= 0xff; // group 1's bg_free_blocks_count_lo
        assert!(matches!(
            Reader::open(std::io::Cursor::new(&corrupt))
                .unwrap()
                .verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "group descriptor",
                index: 1,
                ..
            })
        ));
    }

    #[test]
    fn verifies_bitmap_directory_and_xattr_checksums() {
        // Beyond the superblock, descriptors, and inodes, the oracle covers bitmaps,
        // directory-block tails, and the external attribute block. Each category must
        // stay clean on a well-formed image and fire when its own bytes are corrupted.
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), m(0o755))
            .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
            // A 400-byte value cannot fit inline, so it spills to an external block.
            .file(b"/etc/big".to_vec(), b"x".to_vec(), m(0o644))
            .xattr(b"user.big".to_vec(), vec![0xcd; 400]);
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        // Clean: neither the strict oracle nor the lenient scan finds anything.
        {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.verify_checksums()
                .expect("a well-formed image verifies clean");
            let report = r.scan();
            assert!(
                report.anomalies.is_empty(),
                "a clean image scans clean, got {:?}",
                report.anomalies
            );
        }

        // Locate group 0's block bitmap, the root's first directory block, and the
        // external attribute block of /etc/big.
        let (bitmap_block, dir_block, xattr_block) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let bitmap_block = r.group_descriptor(0).unwrap().block_bitmap;
            let root = r.inode(2).unwrap();
            let dir_block = r.extent_leaves(&root).unwrap()[0].start;
            // /etc/big is the file carrying the external attribute block.
            let mut xattr_block = 0u64;
            for e in r.walk().unwrap() {
                if e.path == b"/etc/big" {
                    xattr_block = e.inode.file_acl;
                }
            }
            assert_ne!(xattr_block, 0, "the file has an external attribute block");
            (bitmap_block, dir_block, xattr_block)
        };
        let bs = 4096u64;
        let corrupt_at = |block: u64, within: u64| {
            let mut c = bytes.clone();
            c[(block * bs + within) as usize] ^= 0xff;
            c
        };

        // A block-bitmap byte the descriptor's checksum covers.
        let c = corrupt_at(bitmap_block, 0);
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(matches!(
            r.verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "block bitmap",
                ..
            })
        ));
        assert!(
            r.scan()
                .anomalies
                .iter()
                .any(|a| a.category == Category::Bitmap),
            "scan reports a Bitmap anomaly"
        );

        // A directory-block byte inside the region the tail checksum covers.
        let c = corrupt_at(dir_block, 40);
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(matches!(
            r.verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "directory block",
                ..
            })
        ));
        assert!(
            r.scan()
                .anomalies
                .iter()
                .any(|a| a.category == Category::Directory),
            "scan reports a Directory anomaly"
        );

        // A byte of the external attribute block, which its h_checksum covers.
        let c = corrupt_at(xattr_block, 32);
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(matches!(
            r.verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "xattr block",
                ..
            })
        ));
        assert!(
            r.scan()
                .anomalies
                .iter()
                .any(|a| a.category == Category::Xattr),
            "scan reports an Xattr anomaly"
        );
    }

    #[test]
    fn verifies_a_two_level_htree_with_interior_index_nodes() {
        // A hash tree deep enough to need interior index nodes has three block roles —
        // root, interior node, and leaf — each with a differently shaped checksum tail.
        // The verifier tells them apart by following the index down from the root, so a
        // whole two-level tree must verify with no false mismatch. A 1024-byte block
        // indexes at most 123 leaves at one level, so a directory spanning more than
        // that many blocks is provably two-level.
        let time = Timestamp::from_secs(1_700_000_000);
        let mut o = opts();
        o.feature.block_size = 1024;
        o.grow = GrowReservation::None;

        // 800 entries with 200-byte names pack four to a leaf, filling roughly 200 leaf
        // blocks — past what a single 1024-byte root indexes, so the writer grows an
        // interior level between the root and the leaves.
        let mut src = TreeBuilder::new().directory(b"/bigdir".to_vec(), Metadata::new(0o755, time));
        for i in 0..800u32 {
            let mut name = format!("/bigdir/entry-{i:04}").into_bytes();
            name.resize(b"/bigdir/".len() + 200, b'x');
            src = src.file(name, Vec::new(), Metadata::new(0o644, time));
        }
        let bytes = format(src, 64 * MIB, o).unwrap().into_bytes();

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let (_, dir) = r.lookup(b"/bigdir").expect("the directory is present");
        assert!(
            dir.flags.contains(InodeFlags::INDEX),
            "an 800-entry directory must be hash-indexed"
        );
        let block_count = dir.size / 1024;
        assert!(
            block_count > 124,
            "a two-level tree spans more than a one-level root's 123 leaves and its \
             root, but this directory is {block_count} blocks — the interior level \
             this test exists to exercise was never grown"
        );

        // The whole tree verifies: the root, both interior nodes, and every leaf.
        r.verify_checksums()
            .expect("a well-formed two-level htree verifies clean");
        assert!(
            r.scan().anomalies.is_empty(),
            "a clean two-level htree scans clean, got {:?}",
            r.scan().anomalies
        );

        // And every name survives the index the checksum pass just walked past.
        let names: std::collections::BTreeSet<Vec<u8>> = r
            .read_dir(&dir)
            .expect("read_dir")
            .into_iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .map(|e| e.name)
            .collect();
        assert_eq!(names.len(), 800, "every name survives the two-level index");
    }

    #[test]
    fn the_orphan_files_blocks_carry_their_magic_and_checksum() {
        // The orphan file is where the kernel records an inode it is deleting, so its
        // blocks are metadata: each closes with the orphan magic word and a checksum over
        // its entries. Both must hold on a fresh image, and corrupting either must be
        // seen — a wrong tail here would surface as corruption at the first deletion.
        let bytes = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        let (first_block, blocks) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let ino = r.superblock().orphan_file_inum;
            assert_eq!(ino, 12, "the orphan file takes the inode past /lost+found");
            let inode = r.inode(ino).unwrap();
            assert_eq!(inode.links_count, 1);
            assert_eq!(
                inode.size,
                32 * 4096,
                "the size heuristic's floor at 64 MiB"
            );
            let leaves = r.extent_leaves(&inode).unwrap();
            (leaves[0].start, u64::from(leaves[0].len))
        };
        assert_eq!(blocks, 32, "the file maps as one contiguous run");

        // Clean: the tails verify, strictly and in the lenient scan.
        {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.verify_checksums().expect("the orphan tails verify");
            assert!(r.scan().anomalies.is_empty());
        }

        let bs = 4096u64;
        let corrupt_at = |offset: u64| {
            let mut c = bytes.clone();
            c[offset as usize] ^= 0xff;
            c
        };

        // The checksum of the last block: a per-block field, so corrupting the final one
        // proves every block is checked, not just the first.
        let last = first_block + blocks - 1;
        let c = corrupt_at((last + 1) * bs - 4);
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(matches!(
            r.verify_checksums(),
            Err(ReadError::ChecksumMismatch {
                object: "orphan block",
                ..
            })
        ));
        assert!(
            r.scan()
                .anomalies
                .iter()
                .any(|a| a.category == Category::Orphan),
            "scan reports an Orphan anomaly"
        );

        // The magic word: a block that has lost it is not an orphan block at all.
        let c = corrupt_at((first_block + 1) * bs - 8);
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(matches!(
            r.verify_checksums(),
            Err(ReadError::BadOrphanFile)
        ));

        // A superblock claiming the feature but naming no inode for the file is
        // malformed, not an empty orphan list: `s_orphan_file_inum` is at 0x280.
        let mut c = bytes.clone();
        c[1024 + 0x280..1024 + 0x284].copy_from_slice(&0u32.to_le_bytes());
        let mut r = Reader::open(std::io::Cursor::new(&c)).unwrap();
        assert!(
            r.scan()
                .anomalies
                .iter()
                .any(|a| a.category == Category::Orphan),
            "a feature with no file behind it is an Orphan anomaly"
        );
    }

    #[test]
    fn a_scan_is_bounded_by_the_bytes_that_exist_not_the_claimed_block_count() {
        // A superblock claiming `2^64 - 1` blocks implies more block groups than a
        // `u32` holds. Every group past the ones the source physically covers has no
        // bitmap block to read, so each would record one "unreadable bitmap" anomaly —
        // billions of them, an allocation driven by a count a bit-flip can set rather
        // than by the bytes that exist. Both of the scan's group loops are capped at
        // the groups the source can hold, so the work and the report stay proportional
        // to the image.
        let bytes = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        let mut corrupt = bytes.clone();
        // s_blocks_count_lo is at superblock offset 0x04 and _hi at 0x150.
        crate::ondisk::put_u32(&mut corrupt[1024 + 0x04..], 0, 0xffff_ffff);
        crate::ondisk::put_u32(&mut corrupt[1024 + 0x150..], 0, 0xffff_ffff);
        let mut r = Reader::open_with(
            std::io::Cursor::new(&corrupt),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let report = r.scan();
        // The image spans two groups' worth of descriptors at most, so the report is a
        // handful of anomalies. The bound is loose on purpose: what it rules out is a
        // report whose length tracks the claimed group count.
        assert!(
            report.anomalies().len() < 64,
            "the scan reported {} anomalies for a 64 MiB image — it is walking the \
             claimed group count, not the source",
            report.anomalies().len()
        );
        // A regression surfaces as this test never returning rather than as a failed
        // assertion: the loop it guards runs four billion times and grows the report as
        // it goes. That is the shape of the fault, so it is the shape of the failure.
    }

    #[test]
    fn verify_checksums_ignores_a_hostile_free_inode_count() {
        // In-use inodes are enumerated from the bitmaps, not from
        // `inodes_count - free_inodes_count`, so a free count set above the inode count
        // — a value that would once have underflowed a subtraction — neither panics nor
        // steers the enumeration.
        let bytes = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        let mut corrupt = bytes.clone();
        // s_free_inodes_count is at superblock offset 0x10; set it above s_inodes_count.
        crate::ondisk::put_u32(&mut corrupt[1024 + 0x10..], 0, 0xffff_ffff);
        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        // It returns (an error or Ok), never panics.
        let _ = r.verify_checksums();
        let _ = r.scan();
    }

    #[test]
    fn open_rejects_a_bad_superblock() {
        let mut bytes = vec![0u8; 4096 * 16];
        // No magic anywhere.
        assert!(matches!(
            Reader::open(std::io::Cursor::new(&bytes)),
            Err(ReadError::Parse(ParseError::BadMagic { .. }))
        ));
        // Truncated image.
        bytes.truncate(512);
        assert!(Reader::open(std::io::Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn multi_group_image_round_trips() {
        let time = Timestamp::from_secs(1_700_000_000);
        let src = TreeBuilder::new().file(
            b"/f".to_vec(),
            b"multi-group".to_vec(),
            Metadata::new(0o644, time),
        );
        let image = format(src, 512 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        assert_eq!(r.superblock().blocks_count, 131072);
        // Descriptors for the backup groups read back with the flex placements.
        let g3 = r.group_descriptor(3).unwrap();
        assert_eq!(g3.block_bitmap, 8);
        assert_eq!(g3.inode_table, 1549);
        let root = r.inode(2).unwrap();
        let f = r
            .read_dir(&root)
            .unwrap()
            .iter()
            .find(|e| e.name == b"f")
            .unwrap()
            .inode;
        let f_inode = r.inode(f).unwrap();
        assert_eq!(r.read_data(&f_inode).unwrap(), b"multi-group");
    }

    #[test]
    fn opens_a_filesystem_at_an_arbitrary_offset() {
        // A filesystem embedded past a leading gap — a partition inside a whole-disk
        // image — reads back identically to a bare one.
        let time = Timestamp::from_secs(1);
        let src = TreeBuilder::new().file(
            b"/hi".to_vec(),
            b"there".to_vec(),
            Metadata::new(0o644, time),
        );
        let image = format(src, 64 * MIB, opts()).unwrap();

        let base = 1_048_576u64; // a 1 MiB partition gap ahead of the filesystem
        let mut padded = vec![0x9au8; base as usize];
        padded.extend_from_slice(image.as_bytes());

        let mut r = Reader::open_with(
            std::io::Cursor::new(&padded),
            &OpenOptions::new().base(base),
        )
        .unwrap();
        assert_eq!(r.policy(), ReadPolicy::Strict);
        let root = r.inode(2).unwrap();
        let names: Vec<_> = r
            .read_dir(&root)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&b"hi".to_vec()));
        let hi = r
            .walk()
            .unwrap()
            .into_iter()
            .find(|e| e.path == b"/hi")
            .unwrap()
            .inode;
        assert_eq!(r.read_data(&hi).unwrap(), b"there");

        // Opening the same buffer at offset zero lands in the gap and is rejected.
        assert!(Reader::open(std::io::Cursor::new(&padded)).is_err());
    }

    #[test]
    fn open_with_refuses_a_base_that_overflows_the_superblock_position() {
        // A `base` near the top of the range leaves no room for the superblock 1024 bytes
        // in. The sum is refused as out of range rather than wrapping to a small seek that
        // would read a non-superblock and mislabel the image.
        let src = std::io::Cursor::new(vec![0u8; 4096]);
        // `Reader` is not `Debug`, so the `Result` is matched rather than unwrapped.
        assert!(matches!(
            Reader::open_with(src, &OpenOptions::new().base(u64::MAX).policy(ReadPolicy::Lenient)),
            Err(ReadError::OutOfRange {
                what: "bytes",
                index
            }) if index == u64::MAX
        ));
    }

    #[test]
    fn errors_classify_as_typed_anomalies() {
        // A missing inode cannot be parsed further: structural, located by number.
        let a = ReadError::NoSuchInode { inode: 7 }.anomaly();
        assert_eq!(a.severity, Severity::Structural);
        assert_eq!(a.category, Category::Inode);
        assert_eq!(a.location.inode, Some(7));

        // A checksum mismatch parses but is self-inconsistent: integrity.
        let cm = ReadError::ChecksumMismatch {
            object: "inode",
            index: 2,
            stored: 1,
            computed: 2,
        }
        .anomaly();
        assert_eq!(cm.severity, Severity::Integrity);
        assert_eq!(cm.category, Category::Inode);
        assert_eq!(cm.location.inode, Some(2));

        // An out-of-range block reference is structural, located by block. With no
        // call-site context an ownerless block reference names no subsystem, so it falls
        // to the structural catch-all; the scan supplies the real owner — the extent
        // tree or the inode — when it walks a mapping (see
        // scan_files_an_out_of_range_extent_against_the_extent_tree).
        let oor = ReadError::OutOfRange {
            what: "block",
            index: 99,
        }
        .anomaly();
        assert_eq!(oor.severity, Severity::Structural);
        assert_eq!(oor.category, Category::Superblock);
        assert_eq!(oor.location.block, Some(99));

        // The strict policy is fatal at conformance and above, and is the default.
        assert!(ReadPolicy::Strict.is_fatal(Severity::Structural));
        assert!(ReadPolicy::Strict.is_fatal(Severity::Integrity));
        assert!(ReadPolicy::Strict.is_fatal(Severity::Conformance));
        assert!(!ReadPolicy::Strict.is_fatal(Severity::Cosmetic));
        assert_eq!(ReadPolicy::default(), ReadPolicy::Strict);
    }

    #[test]
    fn lenient_policy_is_fatal_at_nothing() {
        for sev in [
            Severity::Cosmetic,
            Severity::Conformance,
            Severity::Integrity,
            Severity::Structural,
        ] {
            assert!(!ReadPolicy::Lenient.is_fatal(sev), "{sev:?} under lenient");
        }
        // Strict still draws the line at conformance-and-above, and is the default.
        assert!(ReadPolicy::Strict.is_fatal(Severity::Structural));
        assert!(!ReadPolicy::Strict.is_fatal(Severity::Cosmetic));
        assert_eq!(ReadPolicy::default(), ReadPolicy::Strict);
    }

    #[test]
    fn scans_a_clean_multigroup_image_as_clean() {
        // A populated, multi-group image scans with no anomaly, so no policy finds it
        // fatal. This exercises the whole walk — superblock, every descriptor, every
        // in-use inode and its extent tree, including the journal inode.
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), m(0o755))
            .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
            .file(b"/big".to_vec(), vec![0x42; 200_000], m(0o600));
        let image = format(src, 512 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let report = r.scan();
        assert!(
            report.is_clean(),
            "unexpected anomalies: {:?}",
            report.anomalies()
        );
        assert_eq!(report.worst_severity(), None);
        assert!(!report.has_fatal(ReadPolicy::Strict));
        assert!(!report.has_fatal(ReadPolicy::Lenient));
        assert_eq!(report.to_table(), "no anomalies\n");
        assert!(!report.is_truncated());
        assert_eq!(
            report.to_json(),
            "{\"schema\":1,\"clean\":true,\"count\":0,\"truncated\":false,\"anomalies\":[]}"
        );
    }

    /// A feature profile with the metadata checksums turned off, so a test that edits a
    /// superblock or descriptor field is not also reporting the checksum it invalidated.
    /// The seed serves the checksums, so it comes off with them.
    fn opts_no_csum() -> FormatOptions {
        let mut o = opts();
        o.feature = FeatureSet::DEFAULT
            .with_feature("metadata_csum", false)
            .expect("a known name")
            .with_feature("metadata_csum_seed", false)
            .expect("a known name");
        assert_eq!(o.feature.validate(), Ok(()));
        o
    }

    #[test]
    fn refuses_an_unsupported_incompat_feature_and_reports_it() {
        // The `incompat` word is the one an implementation must refuse when it does not
        // recognize a bit: an unknown extension, or `meta_bg`, whose distributed group
        // descriptors this reader does not follow. A strict open refuses; a lenient scan
        // reports it as a structural anomaly against the superblock.
        let clean = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        // The unmodified default profile is entirely supported, so a strict open accepts
        // it — the refusal below fires on the injected bit, not the profile at large.
        assert!(Reader::open(std::io::Cursor::new(&clean)).is_ok());

        // The `incompat` word is a little-endian u32 at superblock offset 0x60, and the
        // superblock begins 1024 bytes into the image.
        let incompat = 1024 + 0x60;
        for (name, byte, mask, want) in [
            ("meta_bg", 0, 0x10u8, 0x10u32),
            ("unknown high bit", 3, 0x80u8, 0x8000_0000u32),
        ] {
            let mut bytes = clean.clone();
            bytes[incompat + byte] |= mask;

            assert_eq!(
                Reader::open(std::io::Cursor::new(&bytes)).err(),
                Some(ReadError::UnsupportedIncompat { bits: want }),
                "a strict open refuses {name}",
            );

            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap_or_else(|_| panic!("a lenient open accepts {name}"));
            let report = r.scan();
            let found = report
                .anomalies()
                .iter()
                .find(|a| a.category == Category::Superblock && a.severity == Severity::Structural);
            let found = found.unwrap_or_else(|| {
                panic!("scan reports {name} as a structural superblock anomaly: {report:?}")
            });
            assert!(
                found.detail.contains(name) || found.detail.contains("0x80000000"),
                "the anomaly names the feature it found: {}",
                found.detail
            );
            assert!(report.has_fatal(ReadPolicy::Strict));
        }
    }

    #[test]
    fn flags_an_extent_flagged_inode_without_the_extent_feature() {
        // An inode carrying the extent-format flag on a filesystem whose superblock does
        // not enable the extent feature is the incoherence `e2fsck` faults. The mapping
        // mode was chosen by the inode flag alone, so the disagreement went unreported;
        // it is a structural anomaly now. Checksums are off so the edit does not also
        // trip the superblock's own checksum.
        let src = TreeBuilder::new().file(
            b"/hello".to_vec(),
            b"world\n".to_vec(),
            Metadata::new(0o644, Timestamp::from_secs(1_700_000_000)),
        );
        let mut bytes = format(src, 64 * MIB, opts_no_csum()).unwrap().into_bytes();

        // Clear the extent bit (0x40) in the `incompat` word while the inodes keep their
        // extent-format flag, so the two now disagree.
        bytes[1024 + 0x60] &= !0x40;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert!(!r.feature().has_extents());
        let report = r.scan();

        let flagged: Vec<u32> = report
            .anomalies()
            .iter()
            .filter(|a| {
                a.category == Category::Inode
                    && a.severity == Severity::Structural
                    && a.detail.contains("extent format")
            })
            .filter_map(|a| a.location.inode)
            .collect();
        // The root directory and the file are both extent-mapped, so both are flagged;
        // the block-mapped resize inode is not.
        assert!(
            flagged.contains(&ROOT_INO),
            "the root inode is flagged: {report:?}"
        );
        assert!(
            flagged.len() >= 2,
            "every extent-mapped inode is flagged: {flagged:?}"
        );
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    /// Overwrite inode `number` with an extent-mapped inode of `mode` whose inline tree
    /// names `runs` runs of `len` blocks, every one of them mapping the same physical
    /// blocks from `start`, under a declared size of `size` bytes.
    ///
    /// This is the shape a crafted image takes to make one inode's mapping claim far more
    /// than the image holds: 256 bytes of inode naming the same blocks over and over, at
    /// logical offsets a size field says are all in use. Nothing is added to the image —
    /// the blocks it names are blocks that were already there.
    fn craft_extent_inode(
        bytes: &mut [u8],
        number: u32,
        mode: u16,
        runs: u32,
        len: u16,
        start: u64,
        size: u64,
    ) {
        use crate::ondisk::{EXTENT_ENTRY_SIZE, ExtentHeader, ExtentLeaf};

        let mut inode = Inode::empty(256);
        inode.mode = mode;
        inode.links_count = 1;
        inode.flags = InodeFlags::EXTENTS;
        inode.size = size;
        let header = ExtentHeader {
            entries: runs as u16,
            max: runs as u16,
            depth: 0,
            generation: 0,
        };
        inode.block[..EXTENT_ENTRY_SIZE].copy_from_slice(&header.to_bytes());
        for r in 0..runs {
            let leaf = ExtentLeaf {
                block: r * u32::from(len),
                len,
                start,
                initialized: true,
            };
            let off = EXTENT_ENTRY_SIZE * (1 + r as usize);
            inode.block[off..off + EXTENT_ENTRY_SIZE]
                .copy_from_slice(&leaf.to_bytes().expect("a representable run"));
        }
        let at = inode_offset(bytes, number);
        inode
            .write_to(&mut bytes[at..at + 256], 256)
            .expect("write the crafted inode");
    }

    #[test]
    fn a_directory_mapping_one_block_many_times_is_judged_once_per_block() {
        // A directory's logical-to-physical map may name one block from many logical
        // offsets; only a crafted image does, and a scan that judged each offset
        // separately would turn 256 bytes of inode into thousands of findings, each
        // carrying an owned description. The verdict belongs to the block, so it is
        // reached once per block however many offsets name it.
        //
        // The declared size is the largest a directory's size field holds — a million
        // blocks, sixty-four times what the image has — so the map is bounded by the
        // blocks that exist rather than by that claim: a directory has no holes.
        const RUNS: u32 = 4;
        const LEN: u16 = 1000;
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();
        // Inode 3 is a reserved inode the bitmap already marks in use, so the scan reaches
        // it without the bitmap having to be crafted too.
        craft_extent_inode(
            &mut bytes,
            3,
            0o040755,
            RUNS,
            LEN,
            2000,
            u64::from(u32::MAX),
        );

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let report = r.scan();

        // The blocks it names hold no directory tail, so each is one finding — and there
        // are as many findings as there are blocks, not as many as there are offsets.
        let per_block = report
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::Directory && a.location.inode == Some(3))
            .count();
        assert_eq!(
            per_block,
            LEN as usize,
            "one finding per block named, not per logical offset ({} offsets name {LEN} blocks)",
            RUNS as usize * LEN as usize
        );
        assert!(!report.is_truncated(), "this image is fully scanned");
    }

    #[test]
    fn a_report_stops_at_its_cap_and_says_so() {
        // How many findings an image yields is the image's own claim, so a report bounds
        // what it holds: a handful of crafted inodes can name every block in the image,
        // and each block that fails its tail is a finding. The scan stops at the cap and
        // records that it did, rather than growing a report in proportion to what a
        // crafted image asks for.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();
        // The reserved inodes the bitmap already marks in use. Three of them, each naming
        // four thousand of the image's blocks, is more than the cap holds.
        for number in [3u32, 4, 5] {
            craft_extent_inode(
                &mut bytes,
                number,
                0o040755,
                4,
                4000,
                2000,
                u64::from(u32::MAX),
            );
        }

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let report = r.scan();
        assert!(
            report.is_truncated(),
            "a report past the cap says it stopped short"
        );
        assert_eq!(
            report.anomalies().len(),
            ScanReport::MAX_ANOMALIES,
            "a truncated report holds exactly the cap"
        );
        // The truncation reaches every projection: a consumer of any of them must be able
        // to tell a complete report from one that stopped.
        assert!(report.to_json().contains("\"truncated\":true"));
        assert!(report.to_table().contains("report truncated at 10000"));
        assert!(
            report
                .to_sarif(None)
                .contains("\"toolExecutionNotifications\""),
            "SARIF records the short run as a notification about the invocation"
        );
        // The findings still stand: a truncated report is a floor, not a blank verdict.
        assert!(report.has_fatal(ReadPolicy::Strict));

        // And the cap is a knob, not a constant: a caller reading with a gigabyte to
        // spare tightens it and gets a report that says it stopped that much sooner —
        // and says so naming the bound that applied. A notice quoting the default
        // constant would tell a caller who asked for seven that ten thousand were found.
        let mut tight = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new()
                .policy(ReadPolicy::Lenient)
                .limits(Limits::new().max_anomalies(7)),
        )
        .unwrap();
        let short = tight.scan();
        assert!(short.is_truncated());
        assert_eq!(short.anomalies().len(), 7);
        let notice = "report truncated at 7 anomalies; the rest of the image was not scanned";
        assert!(short.to_table().contains(notice), "{}", short.to_table());
        assert!(short.to_sarif(None).contains(notice));

        // A cap of zero stops the scan before it reads a group. The report is empty, and
        // it is *not* clean: an absence of findings from a scan that never looked is not
        // a verdict about the image.
        let mut none = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new()
                .policy(ReadPolicy::Lenient)
                .limits(Limits::new().max_anomalies(0)),
        )
        .unwrap();
        let empty = none.scan();
        assert!(empty.is_truncated());
        assert!(empty.anomalies().is_empty());
        assert!(
            !empty.is_clean(),
            "a truncated report claimed the image was clean"
        );
        assert!(empty.to_json().contains("\"clean\":false"));
        assert!(empty.to_table().contains("report truncated at 0 anomalies"));
    }

    #[test]
    fn a_walk_is_bounded_by_the_names_the_source_has_room_for() {
        // Distinct directory inodes may map the *same* data blocks, so a crafted image can
        // describe an unbounded number of names from a handful of blocks. Every name a
        // well-formed filesystem holds spends at least a dirent's worth of its own blocks,
        // so the source's length bounds the walk without ever reaching a real image.
        let source = TreeBuilder::new()
            .directory(
                b"/a".to_vec(),
                Metadata::new(0o755, Timestamp::from_secs(0)),
            )
            .file(
                b"/a/f".to_vec(),
                b"x".to_vec(),
                Metadata::new(0o644, Timestamp::from_secs(0)),
            );
        let image = format(source, 64 * MIB, opts()).unwrap();
        let bytes = image.into_bytes();

        // At the default limits every name comes back: the structural bound on a 64 MiB
        // image is millions of names, and this tree has three.
        let mut r = Reader::open_with(std::io::Cursor::new(&bytes), &OpenOptions::new()).unwrap();
        let full = r.walk().unwrap();
        assert!(full.len() >= 3, "{full:?}");

        // A caller-set cap refuses rather than truncating: a short list with nothing to
        // say it is short is a silent loss, and a walk is what a caller extracts a tree
        // from.
        let mut capped = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().limits(Limits::new().max_walk_entries(2)),
        )
        .unwrap();
        assert!(matches!(
            capped.walk(),
            Err(ReadError::WalkTooLarge { limit: 2 })
        ));
    }

    #[test]
    fn a_file_read_is_capped_only_where_a_caller_asks() {
        // `read_data` trusts `i_size`, because a sparse file's logical size legitimately
        // exceeds the blocks behind it. A caller reading an image it does not trust caps
        // it explicitly.
        let source = TreeBuilder::new().file(
            b"/f".to_vec(),
            vec![7u8; 8192],
            Metadata::new(0o644, Timestamp::from_secs(0)),
        );
        let image = format(source, 64 * MIB, opts()).unwrap();
        let bytes = image.into_bytes();

        let mut r = Reader::open_with(std::io::Cursor::new(&bytes), &OpenOptions::new()).unwrap();
        let (_, inode) = r.lookup(b"/f").unwrap();
        assert_eq!(r.read_data(&inode).unwrap().len(), 8192);

        // Over the cap the read is refused, and the error carries both numbers a caller
        // acts on. A hundred bytes of an eight-kilobyte file returned as `Ok` would be
        // indistinguishable from a hundred-byte file — the silent loss the walk's own
        // bound exists to avoid, one object down.
        let mut capped = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().limits(Limits::new().max_file_bytes(100)),
        )
        .unwrap();
        let (_, inode) = capped.lookup(b"/f").unwrap();
        assert!(matches!(
            capped.read_data(&inode),
            Err(ReadError::FileTooLarge {
                size: 8192,
                limit: 100
            })
        ));
        // Streaming the same file is bounded the same way: the cap expresses distrust of
        // the declared size, not a memory bound, so it is not escaped by not holding the
        // bytes.
        let mut sink = Vec::new();
        assert!(matches!(
            capped.read_data_to(&inode, &mut sink),
            Err(ReadError::FileTooLarge { .. })
        ));
        assert!(sink.is_empty(), "nothing is written before the refusal");

        // A ranged read is bounded by the buffer the caller supplies, so the cap does not
        // apply to it: this is the way to read part of a file deliberately, and the count
        // it returns is what makes the partial read representable.
        let mut buf = [0u8; 100];
        assert_eq!(capped.read_into(&inode, 0, &mut buf).unwrap(), 100);
        assert_eq!(buf, [7u8; 100]);
    }

    #[test]
    fn a_capped_read_never_maps_the_claim_behind_it() {
        // The cap is asked for by a caller reading an image it does not trust, so the
        // image it has to hold against is the crafted one. A size field claiming sixteen
        // terabytes on a 64 MiB image implies a map of 2^32 logical blocks — eight bytes
        // each, thirty-four gigabytes — so a cap that let the read begin and truncated
        // afterwards would allocate that before returning anything.
        //
        // What proves nothing was mapped is that this completes: the size is checked
        // before a block of map exists.
        const CLAIM: u64 = 1 << 44; // sixteen terabytes, on a 64 MiB image
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();
        craft_extent_inode(&mut bytes, 12, 0o100600, 1, 4, 2000, CLAIM);

        for cap in [0u64, 10, 8192] {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new()
                    .policy(ReadPolicy::Lenient)
                    .limits(Limits::new().max_file_bytes(cap)),
            )
            .unwrap();
            let inode = r.inode(12).unwrap();
            assert!(
                matches!(
                    r.read_data(&inode),
                    Err(ReadError::FileTooLarge { size: CLAIM, .. })
                ),
                "a {CLAIM}-byte claim must be refused under a {cap}-byte cap"
            );
        }

        // And a ranged read of the same inode reads the window it was asked for without
        // mapping the claim: the crafted extent covers logical block 0, so the first
        // block's bytes are readable while everything the claim adds past it is not
        // materialized at all.
        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let inode = r.inode(12).unwrap();
        let mut buf = [0u8; 4096];
        assert_eq!(r.read_into(&inode, 0, &mut buf).unwrap(), 4096);
    }

    #[test]
    fn a_ranged_read_reads_the_window_it_is_given() {
        // The primitive the whole-file forms are built on, over both mappings: a window
        // anywhere in the file, holes filled as zeros, short only at the end of the file.
        // `-O ^extent` is the classic direct/indirect map, where a window deep into the
        // file is reached through the indirect blocks above it.
        for label in ["extent", "block-mapped"] {
            let mut o = opts();
            if label == "block-mapped" {
                o.feature = FeatureSet::EXT2;
            }
            // Long enough to reach single indirection under the classic map (12 direct
            // blocks = 48 KiB at a 4 KiB block), with a recognizable byte per block.
            let mut contents = Vec::new();
            for block in 0..20u8 {
                contents.extend(std::iter::repeat_n(block, 4096));
            }
            let source = TreeBuilder::new().file(
                b"/f".to_vec(),
                contents.clone(),
                Metadata::new(0o644, Timestamp::from_secs(0)),
            );
            let image = format(source, 64 * MIB, o).unwrap();
            let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
            let (_, inode) = r.lookup(b"/f").unwrap();

            // A whole-file read still returns the whole file, however it is now built.
            assert_eq!(
                r.read_data(&inode).unwrap(),
                contents,
                "{label}: whole file"
            );

            // A window crossing a block boundary, and one past the direct blocks.
            for (offset, len) in [
                (0usize, 10usize),
                (4090, 12),
                (65536, 8192),
                (4096 * 19, 4096),
            ] {
                let mut buf = vec![0u8; len];
                let filled = r.read_into(&inode, offset as u64, &mut buf).unwrap();
                assert_eq!(filled, len, "{label}: {len} bytes at {offset}");
                assert_eq!(&buf[..filled], &contents[offset..offset + len]);
            }

            // A read at the end is short rather than an error, and one past the end reads
            // nothing: that is how a caller knows it reached the end rather than a bound.
            let mut buf = vec![0u8; 4096];
            let filled = r
                .read_into(&inode, contents.len() as u64 - 10, &mut buf)
                .unwrap();
            assert_eq!(filled, 10, "{label}: a read at the end is short");
            assert_eq!(
                r.read_into(&inode, contents.len() as u64, &mut buf)
                    .unwrap(),
                0,
                "{label}: a read past the end fills nothing"
            );

            // Streaming yields the same bytes as holding them, which is the property that
            // lets a caller choose by memory rather than by fidelity.
            let mut sink = Vec::new();
            assert_eq!(
                r.read_data_to(&inode, &mut sink).unwrap(),
                contents.len() as u64
            );
            assert_eq!(sink, contents, "{label}: streamed bytes");
        }
    }

    #[test]
    fn a_ranged_read_of_a_sparse_file_reads_holes_as_zeros() {
        // A hole reads as zeros without occupying a block, at any offset and at any level
        // of the classic map — and a windowed read must fill the caller's buffer with them
        // rather than leave whatever it held. The hole here is the whole file: an inode
        // whose size claims blocks its mapping never names.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();
        // A size of four blocks over a one-block extent at logical block 0: blocks 1..4
        // are a hole the tree does not name.
        craft_extent_inode(&mut bytes, 12, 0o100600, 1, 4, 2000, 4 * 4096);
        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let inode = r.inode(12).unwrap();

        let mut buf = vec![0xffu8; 8192];
        let filled = r.read_into(&inode, 4096, &mut buf).unwrap();
        assert_eq!(filled, 8192);
        assert!(
            buf.iter().all(|&b| b == 0),
            "a hole reads as zeros, overwriting the buffer's previous contents"
        );
    }

    #[test]
    fn a_walk_with_visits_every_name_without_gathering_them() {
        // The callback form and the gathering form describe the same tree in the same
        // order; what differs is only whether the entries are held. Comparing the two is
        // what keeps them from drifting.
        let time = Timestamp::from_secs(0);
        let source = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
            .file(
                b"/etc/hostname".to_vec(),
                b"host\n".to_vec(),
                Metadata::new(0o644, time),
            )
            .directory(b"/usr".to_vec(), Metadata::new(0o755, time))
            .file(
                b"/usr/x".to_vec(),
                b"x".to_vec(),
                Metadata::new(0o644, time),
            );
        let image = format(source, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let gathered: Vec<Vec<u8>> = r.walk().unwrap().into_iter().map(|e| e.path).collect();
        let mut streamed = Vec::new();
        // The reader is handed to the callback, so an entry's contents are readable as it
        // is reached — which is what makes a fixed-memory pass over a whole tree possible.
        let mut bytes_seen = 0u64;
        r.walk_with::<ReadError>(|reader, entry| {
            if entry.inode.mode & 0o170000 == 0o100000 {
                bytes_seen += reader.read_data(&entry.inode)?.len() as u64;
            }
            streamed.push(entry.path);
            Ok(())
        })
        .unwrap();
        assert_eq!(streamed, gathered);
        assert_eq!(bytes_seen, 6, "hostname's five bytes and x's one");

        // An error the callback returns stops the walk and comes back unchanged, so a
        // consumer's own failure is never reported as a fault in the image.
        let mut count = 0usize;
        let stopped = r.walk_with::<ReadError>(|_, _| {
            count += 1;
            if count == 2 {
                return Err(ReadError::BadJournal);
            }
            Ok(())
        });
        assert!(matches!(stopped, Err(ReadError::BadJournal)));
        assert_eq!(count, 2, "the walk stops at the failing entry");

        // The entry bound applies to the callback form too, so a hostile image cannot
        // drive an unbounded number of calls.
        let mut capped = Reader::open_with(
            std::io::Cursor::new(image.as_bytes()),
            &OpenOptions::new().limits(Limits::new().max_walk_entries(2)),
        )
        .unwrap();
        assert!(matches!(
            capped.walk_with::<ReadError>(|_, _| Ok(())),
            Err(ReadError::WalkTooLarge { limit: 2 })
        ));
    }

    #[test]
    fn a_named_seed_overrides_the_one_the_image_implies() {
        // An image whose UUID was changed after it was written carries checksums computed
        // from the old seed. Naming that seed is what lets it be verified at all; naming
        // the wrong one makes every checksum fail, which is what proves the override is
        // the value actually used.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let bytes = image.into_bytes();

        let mut own = Reader::open_with(std::io::Cursor::new(&bytes), &OpenOptions::new()).unwrap();
        own.verify_checksums()
            .expect("the image verifies against its own seed");

        let mut wrong = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().csum_seed(0xdead_beef),
        )
        .unwrap();
        assert!(
            matches!(
                wrong.verify_checksums(),
                Err(ReadError::ChecksumMismatch { .. })
            ),
            "a seed the image's checksums were not computed from must not verify"
        );
    }

    #[test]
    fn the_journal_and_orphan_file_are_read_within_the_image_they_claim_to_be_in() {
        // Two structures a scan reaches by name out of the superblock rather than through
        // the inode walk: the journal, of which it reads the first block, and the orphan
        // file, of which it reads every one. Both are regular files, whose size fields
        // reach past thirty-two bits — so a crafted size claims terabytes of blocks, and a
        // reader that materialized a map from that claim would allocate one entry per
        // block claimed before looking at anything.
        //
        // The journal's map is built to the one block wanted; the orphan file's claim is
        // measured against the blocks the image has, and a file that cannot fit is
        // reported malformed. Neither costs memory in proportion to the claim, which is
        // what this test is: it completes.
        const CLAIM: u64 = 1 << 44; // sixteen terabytes, on a 64 MiB image
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();
        craft_extent_inode(&mut bytes, 8, 0o100600, 1, 4, 2000, CLAIM);
        craft_extent_inode(&mut bytes, 12, 0o100600, 1, 4, 2000, CLAIM);

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert_eq!(r.superblock().journal_inum, 8);
        assert_eq!(r.superblock().orphan_file_inum, 12);
        let report = r.scan();

        // The orphan file is reported malformed rather than walked.
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Orphan),
            "the orphan file's claim is faulted: {}",
            report.to_table()
        );
        // The journal's first block is read, and it holds no journal superblock.
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Journal),
            "the journal's first block is judged: {}",
            report.to_table()
        );
        // Reading the journal directly is likewise bounded, and reaches the same verdict.
        assert!(matches!(
            r.journal_superblock(),
            Err(ReadError::Parse(_) | ReadError::BadJournal)
        ));
    }

    #[test]
    fn flags_an_attribute_block_without_the_ext_attr_feature() {
        // `ext_attr` is what says a filesystem holds attributes at all. An inode naming an
        // attribute block on a superblock without it is the incoherence `e2fsck` reports
        // as "i_file_acl for inode N is B, should be zero": the feature word denies the
        // block the pointer claims, so the reader cannot vouch for what that block holds.
        let time = Timestamp::from_secs(1_700_000_000);
        // A value too large for the inline region spills to a block, which is what puts a
        // block number in `i_file_acl`.
        let src = TreeBuilder::new()
            .file(b"/f".to_vec(), b"data".to_vec(), Metadata::new(0o644, time))
            .xattr(b"user.big".to_vec(), vec![0xAB; 2000]);
        let mut bytes = format(src, 64 * MIB, opts_no_csum()).unwrap().into_bytes();

        {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap();
            assert!(r.feature().has_ext_attr());
            assert!(
                r.scan().is_clean(),
                "the image is coherent while the feature stands"
            );
        }

        // Clear `ext_attr` (compat 0x08) while the inode keeps its attribute block.
        bytes[1024 + 0x5c] &= !0x08;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert!(!r.feature().has_ext_attr());
        let report = r.scan();
        let found = report
            .anomalies()
            .iter()
            .find(|a| a.category == Category::Xattr && a.detail.contains("attribute block"))
            .unwrap_or_else(|| panic!("the orphaned attribute block is flagged: {report:?}"));
        assert_eq!(found.severity, Severity::Structural);
        // The anomaly locates both ends of the disagreement: the inode and the block.
        assert!(found.location.inode.is_some() && found.location.block.is_some());
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    #[test]
    fn flags_a_large_regular_file_without_the_large_file_feature() {
        // A regular file of 2 GiB or more is what `large_file` describes, and the resize
        // inode at a 4096-byte block is such a file — 4 GiB of declared classic-map reach.
        // Clearing the feature is the incoherence `e2fsck` reports as "filesystem contains
        // large files, but lacks LARGE_FILE flag in superblock".
        let mut bytes = format(TreeBuilder::new(), 64 * MIB, opts_no_csum())
            .unwrap()
            .into_bytes();

        {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap();
            assert!(r.feature().has_large_file());
            assert!(r.scan().is_clean());
        }

        // Clear `large_file` (ro_compat 0x02, at superblock offset 0x64).
        bytes[1024 + 0x64] &= !0x02;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert!(!r.feature().has_large_file());
        let report = r.scan();
        let found = report
            .anomalies()
            .iter()
            .find(|a| a.detail.contains("regular file"))
            .unwrap_or_else(|| panic!("the large file is flagged: {report:?}"));
        assert_eq!(found.severity, Severity::Conformance);
        assert_eq!(found.category, Category::Inode);
        assert_eq!(
            found.location.inode,
            Some(7),
            "the resize inode is the file that reaches the bound"
        );
        // The directories the image holds are far smaller than the bound, and the bound is
        // on regular files regardless — so exactly one inode is named.
        assert_eq!(
            report
                .anomalies()
                .iter()
                .filter(|a| a.detail.contains("regular file"))
                .count(),
            1
        );
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    #[test]
    fn flags_an_indexed_directory_without_the_dir_index_feature() {
        // A directory carrying the hash-index flag on a superblock without `dir_index` is
        // the incoherence `e2fsck` reports as "inode N has INDEX_FL flag set on filesystem
        // without htree support". The directory still reads linearly, so it is a
        // conformance deviation rather than a structural one.
        let time = Timestamp::from_secs(1_700_000_000);
        let mut src = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, time));
        for i in 0..600u32 {
            let name = format!("/d/entry-{i:04}-padded-out-to-force-an-index").into_bytes();
            src = src.file(name, Vec::new(), Metadata::new(0o644, time));
        }
        let mut bytes = format(src, 64 * MIB, opts_no_csum()).unwrap().into_bytes();

        {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap();
            assert!(r.feature().has_dir_index());
            let (_, dir) = r.lookup(b"/d").expect("the directory");
            assert!(
                dir.flags.contains(InodeFlags::INDEX),
                "the directory is large enough to be indexed"
            );
            assert!(r.scan().is_clean());
        }

        // Clear `dir_index` (compat 0x20) while the directory keeps its index flag.
        bytes[1024 + 0x5c] &= !0x20;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert!(!r.feature().has_dir_index());
        let report = r.scan();
        let found = report
            .anomalies()
            .iter()
            .find(|a| a.detail.contains("hash-indexed"))
            .unwrap_or_else(|| panic!("the unadvertised index is flagged: {report:?}"));
        assert_eq!(found.severity, Severity::Conformance);
        assert_eq!(found.category, Category::Directory);
        assert!(found.location.inode.is_some());
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    #[test]
    fn flags_the_hash_index_flag_on_something_that_is_not_a_directory() {
        // The flag describes how a *directory's* blocks are organized, so on a regular file
        // it means nothing — the incoherence `e2fsck` reports as "inode N has INDEX_FL flag
        // set but is not a directory". It is a different fault from a directory whose flag
        // the feature words deny, and reporting that one here would describe a regular file
        // as a hash-indexed directory.
        let time = Timestamp::from_secs(1_700_000_000);
        let src =
            TreeBuilder::new().file(b"/f".to_vec(), b"data".to_vec(), Metadata::new(0o644, time));
        let mut bytes = format(src, 64 * MIB, opts_no_csum()).unwrap().into_bytes();

        let (number, _) = {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap();
            assert!(r.feature().has_dir_index());
            assert!(r.scan().is_clean());
            r.lookup(b"/f").expect("the file")
        };

        // Set INDEX_FL (0x1000) in the file's `i_flags`, at offset 0x20 of the inode.
        let at = inode_offset(&bytes, number) + 0x20;
        bytes[at + 1] |= 0x10;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let file = r.inode(number).unwrap();
        assert!(file.flags.contains(InodeFlags::INDEX));
        let report = r.scan();
        let found = report
            .anomalies()
            .iter()
            .find(|a| a.detail.contains("not a directory"))
            .unwrap_or_else(|| panic!("the flag on a non-directory is flagged: {report:?}"));
        assert_eq!(found.severity, Severity::Conformance);
        assert_eq!(found.category, Category::Inode);
        assert_eq!(found.location.inode, Some(number));
        // And not the directory rule: the feature stands, and this is not a directory.
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("does not enable the dir_index feature")),
            "a regular file was described as a hash-indexed directory: {report:?}"
        );

        // Clearing `dir_index` (compat 0x20) does not add the directory rule either: that
        // rule is about a directory, and the two faults stay distinct.
        bytes[1024 + 0x5c] &= !0x20;
        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        let report = r.scan();
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("does not enable the dir_index feature")),
            "{report:?}"
        );
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.detail.contains("not a directory"))
        );
    }

    #[test]
    fn the_dirent_bound_is_the_shortest_record_the_format_encodes() {
        // `MIN_DIRENT_LEN` and `min_rec_len` spell the same rule — an eight-byte header
        // plus a name, rounded up to four — in two places, because the bound divides a
        // `u64` and the rule's function is not `const`. Holding them equal is what keeps a
        // change to the header or the alignment from moving one and not the other.
        assert_eq!(MIN_DIRENT_LEN, u64::from(crate::ondisk::min_rec_len(1)));
        // And it really is the floor: a zero-length name is not a record a filesystem
        // holds, and every longer name costs more.
        assert!(MIN_DIRENT_LEN <= u64::from(crate::ondisk::min_rec_len(255)));
    }

    #[test]
    fn flags_metadata_outside_its_group_without_flex_bg() {
        // With `flex_bg` off, each group's bitmaps and inode table must lie within the
        // group. This image is physically a flex one — group 1's metadata is packed into
        // group 0 — so clearing the `flex_bg` bit makes that packing illegal, exactly the
        // corruption `e2fsck` reports as "bitmap for group 1 is not in group". Two groups
        // at 4 KiB blocks, checksums off so the edit stands alone.
        let image = format(TreeBuilder::new(), 256 * MIB, opts_no_csum()).unwrap();
        let mut bytes = image.into_bytes();

        // Flex layout packs the later groups' metadata into group 0, so with flex_bg on
        // the image scans clean: the placement rule does not apply.
        {
            let mut r = Reader::open_with(
                std::io::Cursor::new(&bytes),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap();
            assert!(r.feature().has_flex_bg());
            assert!(
                r.scan().is_clean(),
                "a flex image places metadata legally: {:?}",
                r.scan().anomalies()
            );
        }

        // Clear the flex_bg bit (0x200, bit 9) in the `incompat` word.
        bytes[1024 + 0x60 + 1] &= !0x02;

        let mut r = Reader::open_with(
            std::io::Cursor::new(&bytes),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .unwrap();
        assert!(!r.feature().has_flex_bg());
        let report = r.scan();

        let outside: Vec<&Anomaly> = report
            .anomalies()
            .iter()
            .filter(|a| a.detail.contains("outside the group"))
            .collect();
        assert!(
            !outside.is_empty(),
            "the packed metadata is now out of place: {report:?}"
        );
        // Group 1's block bitmap sits in group 0, so it is named against group 1 and is a
        // structural bitmap anomaly.
        assert!(
            outside.iter().any(|a| {
                a.location.group == Some(1)
                    && a.category == Category::Bitmap
                    && a.severity == Severity::Structural
            }),
            "group 1's bitmap is flagged as outside its group: {report:?}"
        );
        assert!(report.has_fatal(ReadPolicy::Strict));
    }

    #[test]
    fn scan_collects_multiple_anomalies_and_renders_a_table() {
        let time = Timestamp::from_secs(1_700_000_000);
        let src = TreeBuilder::new().file(
            b"/hostname".to_vec(),
            b"ferrosys\n".to_vec(),
            Metadata::new(0o644, time),
        );
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        // Corrupt two independent checksum-covered regions: a superblock field and a
        // byte of the root inode. A fail-fast read stops at the first; the scan
        // reports both.
        let root_off = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            r.group_descriptor(0).unwrap().inode_table as usize * 4096 + 256
        };
        let mut corrupt = bytes.clone();
        corrupt[1024 + 0x30] ^= 0xff; // s_wtime, covered by the superblock checksum
        corrupt[root_off] ^= 0xff; // a byte of the root inode

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();

        // Both corruptions are reported, each an integrity anomaly located to its
        // object; the scan collected rather than stopping at the first.
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Superblock && a.severity == Severity::Integrity)
        );
        assert!(
            report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Inode
                    && a.severity == Severity::Integrity
                    && a.location.inode == Some(2))
        );
        assert!(report.anomalies().len() >= 2);
        assert_eq!(report.worst_severity(), Some(Severity::Integrity));

        // The scan rejects nothing; a strict policy applied to the report would.
        assert!(report.has_fatal(ReadPolicy::Strict));
        assert!(!report.has_fatal(ReadPolicy::Lenient));

        // The table has a header and one row per anomaly, carrying the located inode.
        let table = report.to_table();
        let mut lines = table.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("SEVERITY"));
        assert!(
            header.contains("CATEGORY") && header.contains("LOCATION") && header.contains("DETAIL")
        );
        assert_eq!(lines.count(), report.anomalies().len());
        assert!(table.contains("integrity"));
        assert!(table.contains("inode 2"));
    }

    #[test]
    fn scan_files_an_out_of_range_extent_against_the_extent_tree() {
        // An extent leaf that names a block outside the filesystem is the canonical
        // extent corruption. The anomaly must be filed against the extent tree that
        // named the block, located to the inode and the bad block — not the superblock,
        // which is intact.
        let time = Timestamp::from_secs(1_700_000_000);
        let src =
            TreeBuilder::new().file(b"/f".to_vec(), vec![0x42; 4096], Metadata::new(0o644, time));
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let (ino, inode_off) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let (n, _) = r.lookup(b"/f").expect("lookup /f");
            let isize = r.superblock().inode_size as usize;
            let table = r.group_descriptor(0).unwrap().inode_table as usize;
            (n, table * 4096 + (n as usize - 1) * isize)
        };
        // ee_start_lo sits at inode offset 0x3c: i_block (0x28), past the twelve-byte
        // extent header and the entry's first eight bytes.
        let bogus = 0x00ff_ffffu32; // far past a 64 MiB, 4 KiB-block filesystem
        let mut corrupt = bytes.clone();
        corrupt[inode_off + 0x3c..inode_off + 0x40].copy_from_slice(&bogus.to_le_bytes());

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();
        let extent = report
            .anomalies()
            .iter()
            .find(|a| a.category == Category::ExtentTree)
            .expect("an out-of-range extent is filed against the extent tree");
        assert_eq!(extent.location.inode, Some(ino));
        assert_eq!(extent.location.block, Some(u64::from(bogus)));
        assert_eq!(extent.severity, Severity::Structural);
        // The stray block is not blamed on the superblock, which the scan finds intact.
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Superblock),
            "the out-of-range block was mis-filed against the superblock"
        );
    }

    #[test]
    fn scan_files_an_out_of_range_bitmap_block_against_the_bitmap() {
        // A group descriptor naming a block bitmap outside the filesystem is a bitmap
        // fault, not a superblock one: the out-of-range block reference is filed against
        // the bitmap subsystem the descriptor named it for, located to the group and the
        // stray block. Reverting the scan site to the bare projection files it under the
        // superblock, which is intact.
        let bytes = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        // Group 0's descriptor sits at the start of the descriptor table (block 1 for a
        // 4 KiB-block filesystem with first_data_block 0); its bg_block_bitmap_lo is the
        // descriptor's first field.
        let desc_off = 4096;
        let bogus = 0x00ff_ffffu32; // far past a 64 MiB, 4 KiB-block filesystem
        let mut corrupt = bytes.clone();
        corrupt[desc_off..desc_off + 4].copy_from_slice(&bogus.to_le_bytes());

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();
        let bitmap = report
            .anomalies()
            .iter()
            .find(|a| a.category == Category::Bitmap && a.location.block == Some(u64::from(bogus)))
            .expect("an out-of-range bitmap block is filed against the bitmap");
        assert_eq!(bitmap.location.group, Some(0));
        assert_eq!(bitmap.severity, Severity::Structural);
        // The stray block is not blamed on the superblock. The corrupt descriptor still
        // fails its own checksum — that is a group-descriptor anomaly, correctly typed.
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Superblock),
            "the out-of-range bitmap block was mis-filed against the superblock"
        );
    }

    #[test]
    fn scan_files_an_out_of_range_xattr_block_against_the_attribute_block() {
        // An inode whose external-attribute pointer names a block outside the filesystem
        // is an attribute-block fault, not a superblock one. Reverting the scan site to
        // the bare projection files it under the superblock, which is intact.
        let time = Timestamp::from_secs(1_700_000_000);
        let src = TreeBuilder::new().file(b"/f".to_vec(), Vec::new(), Metadata::new(0o644, time));
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let (ino, inode_off) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let (n, _) = r.lookup(b"/f").expect("lookup /f");
            let isize = r.superblock().inode_size as usize;
            let table = r.group_descriptor(0).unwrap().inode_table as usize;
            (n, table * 4096 + (n as usize - 1) * isize)
        };
        // i_file_acl_lo sits at inode offset 0x68; the high half (0x76) stays zero, so the
        // pointer is the low word alone.
        let bogus = 0x00ff_ffffu32;
        let mut corrupt = bytes.clone();
        corrupt[inode_off + 0x68..inode_off + 0x6c].copy_from_slice(&bogus.to_le_bytes());

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();
        let xattr = report
            .anomalies()
            .iter()
            .find(|a| a.category == Category::Xattr && a.location.block == Some(u64::from(bogus)))
            .expect("an out-of-range xattr block is filed against the attribute block");
        assert_eq!(xattr.location.inode, Some(ino));
        assert!(
            !report
                .anomalies()
                .iter()
                .any(|a| a.category == Category::Superblock),
            "the out-of-range xattr block was mis-filed against the superblock"
        );
    }

    #[test]
    fn scan_collects_both_bitmap_faults_in_one_group() {
        // A group whose block bitmap and inode bitmap both fail their checksum yields two
        // anomalies, not one: scan collects every fault within an object rather than
        // stopping at the first.
        let bytes = format(TreeBuilder::new(), 64 * MIB, opts())
            .unwrap()
            .into_bytes();
        let (block_bmp, inode_bmp) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let d = r.group_descriptor(0).unwrap();
            (d.block_bitmap, d.inode_bitmap)
        };
        // A byte of each bitmap, inside the region the descriptor's checksum covers.
        let mut corrupt = bytes.clone();
        corrupt[block_bmp as usize * 4096] ^= 0xff;
        corrupt[inode_bmp as usize * 4096] ^= 0xff;

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();
        let bitmap_faults = report
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::Bitmap)
            .count();
        assert_eq!(
            bitmap_faults,
            2,
            "both bitmaps of the group fault, so both are reported, got {:?}",
            report.anomalies()
        );
    }

    #[test]
    fn scan_collects_multiple_faults_in_one_directory() {
        // A directory with two corrupt blocks yields two anomalies, not one: scan
        // collects every fault within the directory rather than stopping at the first.
        let time = Timestamp::from_secs(1_700_000_000);
        let mut src = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, time));
        // Enough entries that the directory spans several blocks, so two hold names.
        for i in 0..300u32 {
            src = src.file(
                format!("/d/file-{i:04}").into_bytes(),
                Vec::new(),
                Metadata::new(0o644, time),
            );
        }
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        // The directory's first physical block (its blocks are one contiguous run) and
        // how many it spans. Logical block 0 is the index root; 1 and 2 hold entries.
        let (first, nblocks) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let (_, dir) = r.lookup(b"/d").unwrap();
            let leaves = r.extent_leaves(&dir).unwrap();
            (leaves[0].start, dir.size / 4096)
        };
        assert!(nblocks >= 3, "the directory must span several blocks");
        // A byte inside two entry blocks, within the region each tail checksum covers.
        let mut corrupt = bytes.clone();
        corrupt[(first + 1) as usize * 4096 + 40] ^= 0xff;
        corrupt[(first + 2) as usize * 4096 + 40] ^= 0xff;

        let mut r = Reader::open(std::io::Cursor::new(&corrupt)).unwrap();
        let report = r.scan();
        let dir_faults = report
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::Directory)
            .count();
        assert_eq!(
            dir_faults,
            2,
            "both corrupt directory blocks are reported, got {:?}",
            report.anomalies()
        );
    }

    #[test]
    fn extent_tail_offset_follows_the_declared_capacity() {
        use crate::extent::node_capacity;
        const BS: usize = 4096;
        // A node declaring capacity `eh_max`, its magic and other fields irrelevant to
        // where the tail sits.
        let node = |eh_max: usize| {
            let mut n = vec![0u8; BS];
            put_u16(&mut n, 4, eh_max as u16); // eh_max at offset 4
            n
        };
        // A maximal node: the tail sits at the block-filling offset, exactly where the
        // old block-size derivation put it, so real images are unaffected.
        assert_eq!(
            extent_tail_offset(&node(node_capacity(BS)), BS),
            tail_offset(BS)
        );
        // A node one entry short of full: the tail moves back one entry slot, matching a
        // foreign tool that wrote a node that does not fill its block.
        assert_eq!(
            extent_tail_offset(&node(node_capacity(BS) - 1), BS),
            tail_offset(BS) - EXTENT_ENTRY_SIZE
        );
        // A capacity too large for the block is malformed: fall back to the block-filling
        // offset, which stays in bounds rather than indexing past the node.
        assert_eq!(extent_tail_offset(&node(0xffff), BS), tail_offset(BS));
    }

    #[test]
    fn anomaly_projects_to_json_with_escaping() {
        // Every field renders, the location holds only the coordinates that are set,
        // and the detail string escapes quotes, backslashes, and control characters.
        let a = Anomaly {
            severity: Severity::Structural,
            category: Category::ExtentTree,
            location: Location {
                block: Some(99),
                group: None,
                inode: Some(12),
            },
            detail: "bad \"node\"\n\\path".to_string(),
        };
        let expected = String::from("{\"severity\":\"structural\",\"category\":\"extent tree\",")
            + "\"location\":{\"block\":99,\"inode\":12},"
            + "\"detail\":\"bad \\\"node\\\"\\n\\\\path\"}";
        assert_eq!(a.to_json(), expected);

        // A location with no coordinates renders an empty object.
        let empty = Anomaly {
            severity: Severity::Cosmetic,
            category: Category::Journal,
            location: Location::default(),
            detail: "x".to_string(),
        };
        assert_eq!(
            empty.to_json(),
            "{\"severity\":\"cosmetic\",\"category\":\"journal\",\"location\":{},\"detail\":\"x\"}"
        );
    }

    #[test]
    fn the_scan_document_is_a_versioned_golden_shape() {
        // The emitted JSON is a contract no Rust signature describes: a downstream parser
        // depends on it, and `cargo semver-checks` sees nothing when it changes. So the
        // whole document is pinned here, byte for byte. A diff in this assertion is a
        // change every consumer's parser sees — which is exactly when `schema` must go up
        // and the change must be deliberate.
        let report = ScanReport {
            anomalies: vec![
                Anomaly {
                    severity: Severity::Integrity,
                    category: Category::Inode,
                    location: Location {
                        block: Some(40),
                        group: Some(3),
                        inode: Some(12),
                    },
                    detail: "checksum mismatch".to_string(),
                },
                Anomaly {
                    severity: Severity::Cosmetic,
                    category: Category::Journal,
                    location: Location::default(),
                    detail: "note".to_string(),
                },
            ],
            truncated: false,
            cap: ScanReport::MAX_ANOMALIES,
        };
        assert_eq!(
            report.to_json(),
            "{\"schema\":1,\"clean\":false,\"count\":2,\"truncated\":false,\"anomalies\":[\
             {\"severity\":\"integrity\",\"category\":\"inode\",\
             \"location\":{\"block\":40,\"group\":3,\"inode\":12},\
             \"detail\":\"checksum mismatch\"},\
             {\"severity\":\"cosmetic\",\"category\":\"journal\",\"location\":{},\
             \"detail\":\"note\"}]}"
        );
        assert_eq!(
            report.to_table(),
            "SEVERITY   CATEGORY  LOCATION                   DETAIL\n\
             integrity  inode     group 3 inode 12 block 40  checksum mismatch\n\
             cosmetic   journal   -                          note\n"
        );

        // A clean report is its own shape, and it carries the version too: a consumer
        // that only ever sees sound images must still be able to read the field.
        let clean = ScanReport {
            anomalies: Vec::new(),
            truncated: false,
            cap: ScanReport::MAX_ANOMALIES,
        };
        assert_eq!(
            clean.to_json(),
            "{\"schema\":1,\"clean\":true,\"count\":0,\"truncated\":false,\"anomalies\":[]}"
        );
        assert_eq!(clean.to_table(), "no anomalies\n");
        assert_eq!(SCAN_SCHEMA_VERSION, 1);
    }

    #[test]
    fn report_projects_to_sarif() {
        // A clean report is a well-formed, empty SARIF log: no rules, no results.
        let clean = ScanReport::default();
        assert_eq!(
            clean.to_sarif(None),
            "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
             \"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"ferrosys\",\
             \"rules\":[]}},\"results\":[]}]}"
        );

        // Two anomalies, two categories: one rule apiece, severity maps to the SARIF level,
        // the address becomes a logical location, the image URI a physical one, and the
        // typed value rides in `properties`. The detail escapes like any JSON string.
        let report = ScanReport {
            anomalies: vec![
                Anomaly {
                    severity: Severity::Integrity,
                    category: Category::Inode,
                    location: Location {
                        block: Some(40),
                        group: Some(3),
                        inode: Some(12),
                    },
                    detail: "checksum \"bad\"".to_string(),
                },
                Anomaly {
                    severity: Severity::Cosmetic,
                    category: Category::Journal,
                    location: Location::default(),
                    detail: "note".to_string(),
                },
            ],
            truncated: false,
            cap: ScanReport::MAX_ANOMALIES,
        };
        let expected = String::from(
            "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
             \"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"ferrosys\",\"rules\":[",
        ) + "{\"id\":\"inode\",\"name\":\"inode\",\"shortDescription\":{\"text\":\"inode anomaly\"}},"
            + "{\"id\":\"journal\",\"name\":\"journal\",\"shortDescription\":{\"text\":\"journal anomaly\"}}"
            + "]}},\"results\":["
            + "{\"ruleId\":\"inode\",\"level\":\"error\",\"message\":{\"text\":\"checksum \\\"bad\\\"\"},"
            + "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"disk.img\"}},"
            + "\"logicalLocations\":[{\"fullyQualifiedName\":\"group 3 inode 12 block 40\"}]}],"
            + "\"properties\":{\"severity\":\"integrity\",\"category\":\"inode\",\"block\":40,\"group\":3,\"inode\":12}},"
            + "{\"ruleId\":\"journal\",\"level\":\"note\",\"message\":{\"text\":\"note\"},"
            + "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"disk.img\"}}}],"
            + "\"properties\":{\"severity\":\"cosmetic\",\"category\":\"journal\"}}"
            + "]}]}";
        assert_eq!(report.to_sarif(Some("disk.img")), expected);

        // Without an artifact URI and with no coordinates, a result carries no `locations`.
        let bare = ScanReport {
            anomalies: vec![Anomaly {
                severity: Severity::Conformance,
                category: Category::Superblock,
                location: Location::default(),
                detail: "x".to_string(),
            }],
            truncated: false,
            cap: ScanReport::MAX_ANOMALIES,
        };
        assert!(bare.to_sarif(None).contains(
            "\"ruleId\":\"superblock\",\"level\":\"warning\",\"message\":{\"text\":\"x\"},\
             \"properties\":{\"severity\":\"conformance\",\"category\":\"superblock\"}"
        ));
    }

    #[test]
    fn reader_never_panics_on_mangled_images() {
        // The never-panic contract: opening and every read path return errors on
        // malformed bytes, never crash. A deterministic smoke test over degenerate
        // geometry, truncations, and bit-flips of a valid image; the cargo-fuzz
        // target in fuzz/ is the exhaustive version.
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), m(0o755))
            .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
            .file(b"/big".to_vec(), vec![0x42; 40_000], m(0o600));
        let image = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        fn drive(bytes: &[u8]) {
            if let Ok(mut r) = Reader::open(std::io::Cursor::new(bytes)) {
                let _ = r.walk();
                let _ = r.verify_checksums();
                let _ = r.scan();
            }
            if let Ok(mut r) = Reader::open_with(
                std::io::Cursor::new(bytes),
                &OpenOptions::new().base(512).policy(ReadPolicy::Lenient),
            ) {
                let _ = r.scan();
            }
        }

        // The pristine image drives clean.
        drive(&image);

        // Degenerate geometry that would divide by zero or underflow if unguarded:
        // an enormous inode count, a first data block past the end, and zeroed
        // blocks-per-group and inodes-per-group. Offsets are into the primary
        // superblock at byte 1024.
        for (off, fill) in [
            (0x00usize, 0xffu8), // s_inodes_count enormous
            (0x14, 0xff),        // s_first_data_block past the end
            (0x20, 0x00),        // s_blocks_per_group = 0
            (0x28, 0x00),        // s_inodes_per_group = 0
        ] {
            let mut mangled = image.clone();
            mangled[1024 + off..1024 + off + 4].fill(fill);
            drive(&mangled);
        }

        // Truncations at assorted lengths.
        for len in [0usize, 1, 512, 1023, 1024, 1025, 2048, 4096, 8192, 65_536] {
            drive(&image[..len.min(image.len())]);
        }

        // Deterministic single-byte flips across the metadata region, one image
        // reused (flip, drive, restore) so the sweep stays cheap.
        let mut flip = image.clone();
        let span = flip.len().min(64 * 1024);
        let mut i = 0usize;
        while i < span {
            let orig = flip[i];
            flip[i] ^= 0xff;
            drive(&flip);
            flip[i] = orig;
            i += 251; // a prime stride so flips land on varied field offsets
        }

        // A few fixed non-image patterns.
        drive(&vec![0x00u8; 4096 * 8]);
        drive(&vec![0xffu8; 4096 * 8]);
        let ramp: Vec<u8> = (0..8192u32).map(|k| (k % 256) as u8).collect();
        drive(&ramp);
    }

    #[test]
    fn walk_bounds_a_directory_cycle() {
        // Patch the "b" entry in /a's directory block to point back at the root inode,
        // making the tree cyclic. read_dir does not verify directory-block checksums,
        // so the walk follows the patched entry; the visited-inode bound descends each
        // directory once and returns, where an unbounded walk would recurse to the
        // depth cap and error.
        let time = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, time);
        let src = TreeBuilder::new()
            .directory(b"/a".to_vec(), m(0o755))
            .directory(b"/a/b".to_vec(), m(0o755));
        let mut bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        // The physical byte offset of /a's single directory block.
        let (block_off, block_size) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let root = r.inode(2).unwrap();
            let a_ino = r
                .read_dir(&root)
                .unwrap()
                .into_iter()
                .find(|e| e.name == b"a")
                .unwrap()
                .inode;
            let a_inode = r.inode(a_ino).unwrap();
            let bs = 1024usize << r.superblock().log_block_size;
            let start = r.extent_leaves(&a_inode).unwrap()[0].start;
            (start as usize * bs, bs)
        };

        // Repoint the "b" directory entry at the root inode (2).
        let mut off = block_off;
        let end = block_off + block_size;
        loop {
            let rec_len = u16::from_le_bytes([bytes[off + 4], bytes[off + 5]]) as usize;
            assert!(
                rec_len >= 8 && off + rec_len <= end,
                "walked a valid dir block"
            );
            let name_len = bytes[off + 6] as usize;
            if name_len == 1 && bytes[off + 8] == b'b' {
                bytes[off..off + 4].copy_from_slice(&2u32.to_le_bytes());
                break;
            }
            off += rec_len;
        }

        // The walk terminates (an unbounded one would return the depth-cap error) and
        // yields each directory once; /a/b now resolves to the root and is not
        // descended again.
        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let tree = r.walk().unwrap();
        let paths: Vec<&[u8]> = tree.iter().map(|e| e.path.as_slice()).collect();
        assert!(paths.contains(&b"/a".as_slice()));
        assert!(paths.contains(&b"/a/b".as_slice()));
        assert_eq!(
            paths.iter().filter(|p| **p == b"/a").count(),
            1,
            "the cycle did not multiply entries"
        );
    }

    #[test]
    fn the_walk_names_the_inode_each_path_points_at() {
        // Two names for one file and two files with identical contents are different
        // filesystems, and only the inode number tells them apart: the inodes themselves
        // are byte-identical in the second case. A consumer reconstructing hard links
        // works from the number, so the walk yields it.
        let time = Timestamp::from_secs(1_700_000_000);
        let m = Metadata::new(0o644, time);
        let src = TreeBuilder::new()
            .file(b"/original".to_vec(), b"shared".to_vec(), m)
            .hardlink(b"/link".to_vec(), b"/original".to_vec(), m)
            .file(b"/twin".to_vec(), b"shared".to_vec(), m);
        let image = format(src, 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let by_path: std::collections::BTreeMap<Vec<u8>, u32> = r
            .walk()
            .unwrap()
            .into_iter()
            .map(|e| (e.path, e.number))
            .collect();
        assert_eq!(
            by_path[&b"/link".to_vec()],
            by_path[&b"/original".to_vec()],
            "a hard link is the same inode under a second name"
        );
        assert_ne!(
            by_path[&b"/twin".to_vec()],
            by_path[&b"/original".to_vec()],
            "identical contents are not the same file"
        );

        // The entry's inode is the one its number names, so a consumer need not fetch it
        // again to act on what the walk handed back.
        let entry = r
            .walk()
            .unwrap()
            .into_iter()
            .find(|e| e.path == b"/original")
            .expect("the file is in the tree");
        assert_eq!(r.inode(entry.number).unwrap(), entry.inode);
        assert_eq!(entry.inode.links_count, 2, "the link is counted");
    }

    #[test]
    fn walk_descends_a_tree_nested_past_any_recursion_cap() {
        // A legitimate acyclic tree can nest arbitrarily deep, and the walk must reach
        // the bottom of it. The descent is an explicit stack, not recursion, so depth is
        // bounded by the image rather than a fixed frame count.
        let time = Timestamp::from_secs(1_700_000_000);
        let depth = 200usize;
        let mut src = TreeBuilder::new();
        let mut path = Vec::new();
        for i in 0..depth {
            path.extend_from_slice(format!("/d{i:03}").as_bytes());
            src = src.directory(path.clone(), Metadata::new(0o755, time));
        }
        // A file at the very bottom, so the deepest level carries a name to find.
        let mut leaf = path.clone();
        leaf.extend_from_slice(b"/leaf");
        src = src.file(leaf.clone(), b"deep\n".to_vec(), Metadata::new(0o644, time));
        let bytes = format(src, 64 * MIB, opts()).unwrap().into_bytes();

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let paths: Vec<Vec<u8>> = r
            .walk()
            .expect("a deep tree walks in full")
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            paths.contains(&leaf),
            "the entry {depth} levels down was not reached"
        );
        // The whole chain is present exactly once: the `depth` nested directories plus
        // the leaf, counted apart from the other names an image carries (`/lost+found`).
        let in_chain = paths.iter().filter(|p| p.starts_with(b"/d000")).count();
        assert_eq!(
            in_chain,
            depth + 1,
            "every directory in the chain and the leaf appears exactly once"
        );
        // The chain is present at every level, in depth order.
        for i in 0..depth {
            let mut prefix = Vec::new();
            for j in 0..=i {
                prefix.extend_from_slice(format!("/d{j:03}").as_bytes());
            }
            assert!(
                paths.contains(&prefix),
                "level {i} is missing from the walk"
            );
        }
    }

    /// A merged-`/usr` tree, as every current Linux distribution ships: the directories
    /// live under `/usr` and the classic paths are symbolic links into it.
    fn merged_usr() -> TreeBuilder {
        let t = Timestamp::from_secs(1_700_000_000);
        let m = |mode| Metadata::new(mode, t);
        TreeBuilder::new()
            .directory(b"/usr".to_vec(), m(0o755))
            .directory(b"/usr/lib".to_vec(), m(0o755))
            .directory(b"/usr/lib/modules".to_vec(), m(0o755))
            .file(
                b"/usr/lib/modules/vmlinuz".to_vec(),
                b"not really a kernel".to_vec(),
                m(0o644),
            )
            .directory(b"/etc".to_vec(), m(0o755))
            .file(
                b"/etc/fstab".to_vec(),
                b"/ ext4 defaults\n".to_vec(),
                m(0o644),
            )
            .symlink(b"/lib".to_vec(), b"usr/lib".to_vec(), m(0o777))
            .symlink(
                b"/absolute".to_vec(),
                b"/usr/lib/modules".to_vec(),
                m(0o777),
            )
            // A cycle, and a link to nowhere.
            .symlink(b"/loop_a".to_vec(), b"loop_b".to_vec(), m(0o777))
            .symlink(b"/loop_b".to_vec(), b"loop_a".to_vec(), m(0o777))
            .symlink(b"/dangling".to_vec(), b"nowhere".to_vec(), m(0o777))
    }

    #[test]
    fn lookup_follows_a_symlink_into_merged_usr() {
        let image = format(merged_usr(), 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        // The path that matters: /lib/modules exists only through the link.
        let (through_link, _) = r.lookup(b"/lib/modules").expect("/lib/modules resolves");
        let (direct, _) = r.lookup(b"/usr/lib/modules").expect("/usr/lib/modules");
        assert_eq!(through_link, direct, "the link reaches the same inode");

        // And the file under it reads.
        let (_, inode) = r.lookup(b"/lib/modules/vmlinuz").unwrap();
        assert_eq!(r.read_data(&inode).unwrap(), b"not really a kernel");

        // An absolute target restarts at this filesystem's root, not the host's.
        let (abs, _) = r.lookup(b"/absolute").expect("/absolute resolves");
        assert_eq!(abs, direct);

        // A leading slash is optional, and `.` and empty components are skipped.
        assert_eq!(r.lookup(b"lib/modules").unwrap().0, direct);
        assert_eq!(r.lookup(b"//lib/./modules/").unwrap().0, direct);

        // The root is the root.
        assert_eq!(r.lookup(b"/").unwrap().0, 2);
    }

    #[test]
    fn lookup_no_follow_stops_at_the_link() {
        let image = format(merged_usr(), 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        let (_, link) = r.lookup_no_follow(b"/lib").expect("/lib as a link");
        assert_eq!(link.mode & 0o170000, 0o120000, "it is a symlink");
        assert_eq!(r.read_symlink(&link).unwrap(), b"usr/lib");

        // Following, the same path is the directory it points at.
        let (_, dir) = r.lookup(b"/lib").expect("/lib followed");
        assert_eq!(dir.mode & 0o170000, 0o040000, "it is a directory");

        // A link in a non-final component is followed either way — a path cannot
        // continue through a link without going where it points.
        assert_eq!(
            r.lookup_no_follow(b"/lib/modules").unwrap().0,
            r.lookup(b"/usr/lib/modules").unwrap().0
        );
    }

    #[test]
    fn lookup_bounds_a_symlink_cycle_and_names_what_is_missing() {
        let image = format(merged_usr(), 64 * MIB, opts()).unwrap();
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();

        // A cycle terminates as a loop rather than running forever.
        assert!(matches!(
            r.lookup(b"/loop_a"),
            Err(ReadError::SymlinkLoop { .. })
        ));
        // A link to nothing, and a name that is not there, are both "not found".
        assert!(matches!(
            r.lookup(b"/dangling"),
            Err(ReadError::NotFound { .. })
        ));
        assert!(matches!(
            r.lookup(b"/nope"),
            Err(ReadError::NotFound { .. })
        ));
        // Walking *through* a non-directory is not the same as not finding it.
        assert!(matches!(
            r.lookup(b"/etc/fstab/deeper"),
            Err(ReadError::NotADirectory { .. })
        ));
        // The link itself is still reachable without following it.
        assert!(r.lookup_no_follow(b"/loop_a").is_ok());
    }

    #[test]
    fn a_reserved_inode_without_an_extra_area_verifies_on_its_low_half_alone() {
        // `mke2fs` leaves the reserved inodes at `i_extra_isize = 0`, so they store only
        // `l_i_checksum_lo`. Reproduce that here — set inode 1's extra area to zero and
        // recompute its checksum the way the kernel does — and the verifier must accept
        // it. Comparing a full 32-bit computed value against a stored half rejects seven
        // healthy inodes on every filesystem `mke2fs` ever wrote.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();

        let (table, inode_size, csum) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let table = r.group_descriptor(0).unwrap().inode_table as usize;
            let csum = r.checksummer();
            (table, r.superblock().inode_size as usize, csum)
        };
        let seed = csum.base_seed();
        let off = table * 4096; // inode 1 is the first entry

        // Zero the extra area, so the inode declares none and carries no high half.
        bytes[off + 0x80..off + inode_size].fill(0);
        put_u16(&mut bytes[off..], Inode::CHECKSUM_LO_OFFSET, 0);
        let mut c = csum.crc32c(seed, &1u32.to_le_bytes());
        c = csum.crc32c(c, &0u32.to_le_bytes()); // i_generation
        c = csum.crc32c(c, &bytes[off..off + inode_size]);
        put_u16(&mut bytes[off..], Inode::CHECKSUM_LO_OFFSET, c as u16);

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(
            r.inode(1).unwrap().extra_isize,
            0,
            "the inode declares no extra area"
        );
        let report = r.scan();
        assert!(
            report.is_clean(),
            "an inode storing only its low checksum half was rejected: {:?}",
            report.anomalies()
        );
        r.verify_checksums()
            .expect("and the strict verifier accepts it too");
    }

    #[test]
    fn a_field_this_crate_does_not_model_does_not_break_the_inode_checksum() {
        // The kernel writes `l_i_version` (0x24) on every inode update, and this crate
        // does not model it. A checksum recomputed from a re-serialized `Inode` would
        // zero it and reject every inode of any filesystem that has ever been mounted.
        // Verifying against the inode's own bytes is what makes that a non-event.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).unwrap();
        let mut bytes = image.into_bytes();

        let (table, inode_size, csum) = {
            let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
            let table = r.group_descriptor(0).unwrap().inode_table as usize;
            let csum = r.checksummer();
            (table, r.superblock().inode_size as usize, csum)
        };
        let seed = csum.base_seed();
        // Inode 2, the root.
        let off = table * 4096 + inode_size;

        crate::ondisk::put_u32(&mut bytes[off..], 0x24, 0xdead_beef); // l_i_version
        put_u16(&mut bytes[off..], Inode::CHECKSUM_LO_OFFSET, 0);
        put_u16(&mut bytes[off..], Inode::CHECKSUM_HI_OFFSET, 0);
        let mut c = csum.crc32c(seed, &2u32.to_le_bytes());
        c = csum.crc32c(c, &0u32.to_le_bytes());
        c = csum.crc32c(c, &bytes[off..off + inode_size]);
        put_u16(&mut bytes[off..], Inode::CHECKSUM_LO_OFFSET, c as u16);
        put_u16(
            &mut bytes[off..],
            Inode::CHECKSUM_HI_OFFSET,
            (c >> 16) as u16,
        );

        let mut r = Reader::open(std::io::Cursor::new(&bytes)).unwrap();
        let report = r.scan();
        assert!(
            report.is_clean(),
            "an inode carrying a field this crate does not model was rejected: {:?}",
            report.anomalies()
        );
    }
}
