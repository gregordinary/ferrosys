//! `ferrosys` — pure-Rust, userspace filesystem tooling.
//!
//! The crate creates and reads filesystem images entirely in userspace, over ordinary byte
//! streams, in self-contained, safe Rust. On-disk types serialize through explicit
//! little-endian byte accessors, so the byte layout is spelled out at every field.
//!
//! # Structure
//!
//! The crate root holds what is true of a filesystem whatever family it is, and each family
//! lives in a module of its own behind a feature of its own.
//!
//! **Finding one, and opening it.**
//!
//! - [`detect`](fn@detect) reads an image and reports the [`Filesystem`] family it holds, and
//!   [`detect_with`] does the same at an offset within the source, for a partition or a
//!   region a carver located; [`DetectError`] tells an unreadable source from an
//!   unrecognized one.
//! - [`OpenOptions`], [`ReadPolicy`], and [`Limits`] say where to look, how strictly, and
//!   within what bounds a read may allocate.
// The bullet belongs to the builds that have the item: with no family compiled in there is
// nothing an image could be opened as, so `open` and `FsReader` are not there to link.
#![cfg_attr(
    any(feature = "ext", feature = "fat"),
    doc = " - [`open`](fn@open) detects and hands back the matching family's reader, as an \
[`FsReader`] — an enum of concrete readers rather than a common interface, so a caller that \
has matched its way to one has that family's whole surface."
)]
//!
//! **Describing a tree, and draining one.** A directory tree is not any family's concept, so
//! the vocabulary for one is here and every family consumes it unchanged.
//!
//! - [`Source`], [`SourceEntry`], [`EntryKind`], [`Metadata`], [`FileContent`], [`Xattr`],
//!   and [`Timestamp`] describe what to write; [`TreeBuilder`] and [`LayeredSource`] build
//!   one programmatically.
//! - [`FsTree`] is the other direction, and the one behavioural trait the families share:
//!   walk the names, stat one, stream a file's bytes, resolve a link. It is what lets a sink
//!   drain any family without knowing which.
//!
//! **Saying what was lost, and what was found.**
//!
//! - [`FidelityReport`] names every property a format could not hold and every value a read
//!   had to invent, and [`Synthesis`] is what a read invents them from — with conservative
//!   defaults, because a tree extracted from a format with no permission bits must not land
//!   world-writable because nothing was named. A build that would lose a property fails
//!   until the caller names it in an [`AcceptedLoss`], so nothing is dropped unacknowledged.
//! - [`Finding`] is what a scan reports, carrying a [`Severity`], a byte offset, the
//!   [`Family`] that found it, and that family's own words for the rest. Each family keeps
//!   its own typed taxonomy and projects into this, so there is one document shape and one
//!   severity scale however many families a build carries.
//! - [`printable`](fn@printable) renders a name that came off an image as text a terminal
//!   will not act on, and [`push_json_string`] does the same into a JSON document. Every
//!   message and every finding this crate produces has already been through them; they are
//!   public for a caller whose own output names the same untrusted bytes.
//! - [`crc32c`](fn@crc32c) is the reflected CRC-32C primitive filesystem metadata checksums
//!   are built from.
#![cfg_attr(
    feature = "ext",
    doc = "\n The [`ext`] module implements the ext2/ext3/ext4 family — the \
[`format`](ext::format) writer, the [`Reader`](ext::Reader) opened over any `Read + Seek` \
source, and the byte-exact on-disk structures — and is on by default. Its images are \
byte-reproducible: the UUID, hash seed, and timestamps are inputs, never read from the \
clock or a random source. It re-exports the root vocabulary above, so a caller formatting \
an ext image names one namespace rather than two."
)]
#![cfg_attr(
    feature = "fat",
    doc = "\n The [`fat`] module implements the FAT12/FAT16/FAT32 family — the \
[`format`](fat::format) writer, the [`Reader`](fat::Reader), the \
[`plan_layout`](fat::plan_layout) geometry planner, and the byte-exact on-disk structures \
under [`fat::ondisk`]. Which of the three a volume is follows from its cluster count and \
from nothing else, so the type is derived rather than chosen, and the arithmetic that \
derives it is the format's real contract. Its images are byte-reproducible: the volume \
serial number and the times a directory entry carries are inputs, and the date conversion \
is UTC, so nothing about the machine that wrote an image reaches it. The reader reads any \
conformant volume with one or two allocation tables, whatever wrote it, and takes one input \
no other family has — \
[`ShortNameCharset`](fat::ShortNameCharset), since nothing in a FAT volume records the code \
page its short names are written in and this crate does not guess one."
)]
//!
//! # Features
//!
//! A build takes the filesystem families it names. `ext` is on by default; a build that
//! turns off every family compiles the root substrate and no family code at all, and
//! [`detect`](fn@detect) then recognizes nothing. Granularity is per *family* rather than
//! per format — `ext` is ext2, ext3, and ext4 together, and `fat` is FAT12, FAT16, and
//! FAT32 together, since each set is one lineage sharing its on-disk structures.
//!
//! Cargo unifies features across a dependency graph, so selecting a subset is a property of
//! a leaf application rather than of a library deep in someone's tree: anything else in the
//! build that pulls this crate with a family turns that family on for everyone in it —
//! including the answers [`detect`](fn@detect) then gives.
//!
//! Four more features are off by default, so a build that wants none of them depends only
//! on `thiserror`. Each stands alone and none implies a family — the two ends of a tree are
//! the root's vocabulary, so a source feeds whichever family is being written and a sink
//! drains whichever one was opened:
//!
//! - **`fat`** adds the FAT12/FAT16/FAT32 family. It has no dependencies of its own.
//! - **`tar`** adds the tar/PAX archive source and sink: a filesystem built from an
//!   archive, and one written back out as one. It depends on `tar`.
//! - **`dir`** adds the host-directory source and sink: a filesystem built by walking a
//!   tree on this machine, and one written back out as a tree, with modes, ownership,
//!   times, hard links, special files, and extended attributes. It depends on `rustix`
//!   for the directory, node, ownership and extended-attribute calls the standard library
//!   has no equivalent of, and is present on Linux.
//! - **`serde`** adds `Serialize` to the findings taxonomy, every family's planned geometry,
//!   and the ext feature model, for embedding them in a document of your own. It depends on
//!   `serde`.
// The crate is safe by construction: on-disk types serialize through explicit
// little-endian byte accessors, never transmutes or `zerocopy`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate's README, compiled as a doctest so the example on its front page is the
/// example this crate's API actually accepts. The item exists only while rustdoc is
/// collecting doctests, so it is neither part of the crate nor part of its documentation.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

// ── Generic substrate: the crate root ──
//
// Present regardless of which family backends are enabled. The root exposes only what a
// detector or a scan produces independent of the family that answers it.

// The reflected CRC-32C primitive. The module is pure and has no family dependencies.
mod crc32c;
pub use crc32c::crc32c;

// The little-endian byte accessors every family's on-disk layer serializes through. Two
// families compute them identically with nothing interpreted, which is what makes them a
// shared primitive rather than a shared seam. Compiled where a family is: with none there
// is no on-disk structure to serialize.
#[cfg(any(feature = "ext", feature = "fat"))]
mod bytes;

// Where a materializer's bytes go. Deciding what a byte is belongs to the family; putting
// it at an offset in a seekable destination is the same operation for every one of them,
// so the destination is here and the layout logic stays with the family. Compiled where a
// family is: with none there is nothing to materialize.
#[cfg(any(feature = "ext", feature = "fat"))]
mod sink;

// Rendering bytes that came off an image, an archive, or a host tree as text. Every name
// every family reads is a byte string that may hold whatever a terminal acts on, and a
// message or a finding that interpolates one raw hands those bytes on — so the escaping
// happens where the name enters the text, which is the last point anything can tell it apart
// from the words around it. Both renderings are public because a caller building its own
// output faces the same problem with the same names, and a second implementation of these
// rules is a second place for them to drift.
mod escape;
pub use escape::{printable, push_json_string};

// Image detection and the family selector it returns. `Filesystem` and `DetectError` are
// always present; `detect` dispatches across whichever families are compiled in.
mod detect;
pub use detect::{DetectError, DetectOptions, Filesystem, detect, detect_with};

// A wall-clock instant, and one extended attribute. Both are boundary vocabulary rather
// than storage: how an instant splits across fields and how an attribute's name compresses
// are the family's business, and each family's on-disk layer carries its own conversion.
mod time;
pub use time::Timestamp;
mod xattr;
pub use xattr::Xattr;

// What populates a filesystem. A directory tree is not an ext concept, so the vocabulary
// that describes one lives here and every family consumes it — what a family can
// *represent* of an entry is that family's business, not a reason to give each family a
// source vocabulary of its own.
mod source;
pub use source::{
    EntryKind, FileContent, FileRange, LayeredSource, Metadata, Source, SourceEntry, TreeBuilder,
};

// What a scan found, and what renders it. A family keeps its own typed taxonomy and
// projects into `Finding`, so there is one document shape and one severity scale however
// many families a build carries.
mod finding;
pub use finding::{Coordinate, FINDINGS_SCHEMA_VERSION, Family, Finding, FindingReport, Severity};

// Where a filesystem begins, how strictly it is read, and what one read may allocate — the
// same three settings whatever family answers them.
mod policy;
pub use policy::{Limits, OpenOptions, ReadPolicy};

// Opening an image without naming its family. Compiled only where a family is, since with
// none there is nothing to open an image as — the condition is the disjunction of every
// family feature, so a family added here is a family this reaches.
#[cfg(any(feature = "ext", feature = "fat"))]
mod open;
#[cfg(any(feature = "ext", feature = "fat"))]
pub use open::{FsReader, OpenError, open, open_with};

// What a format could not hold and what a read had to invent, both directions in one
// report, plus the values a read fills a missing field from.
mod fidelity;
pub use fidelity::{AcceptedLoss, Direction, FidelityRecord, FidelityReport, Property, Synthesis};

// The extraction surface: the four operations a sink needs of any family's reader, and the
// one behavioural trait the families share.
mod tree;
pub use tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};

// Room to leave when a filesystem is sized to its contents rather than told a size. What
// every family's search shares is the input and the arithmetic over it; the search itself
// is each family's, because a probe is that family's writer. Compiled where a family is:
// with none there is nothing to size.
#[cfg(any(feature = "ext", feature = "fat"))]
mod sizing;
#[cfg(any(feature = "ext", feature = "fat"))]
pub use sizing::Slack;

// A POSIX access control list, which is the value one extended attribute carries. Like
// `Xattr` itself it is boundary vocabulary: how tightly a family packs one is that family's
// business, and the value is not.
mod acl;
pub use acl::{Acl, AclEntry, AclError, AclQualifier};

// Where a tree comes from and where one goes: an archive at one end, a host directory at the
// other, each in both directions. They are concrete implementations of the root's own
// vocabulary rather than any family's — a sink drains whatever `open` returns, and a source
// feeds whichever family is being written — so they are named here and nowhere else.
#[cfg(feature = "tar")]
mod archive;
#[cfg(feature = "tar")]
pub use archive::{ArchiveError, ArchiveSink, ArchiveSource};
#[cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]
mod host;
#[cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]
pub use host::{DirectorySink, DirectorySource, ExtractReport, HostError};

// ── The ext family: the `ext` module, behind the default-on `ext` feature ──
//
// The family's modules live at the crate root as private modules — so their cross-module
// paths stay `crate::` — and are presented to callers only through [`ext`]. The feature
// model, the checksum seam, and the scan taxonomy are ext concepts: they are reached
// through `ext`, not the crate root.
#[cfg(feature = "ext")]
mod alloc;
#[cfg(feature = "ext")]
mod csum;
#[cfg(feature = "ext")]
mod dir;
#[cfg(feature = "ext")]
mod extent;
#[cfg(feature = "ext")]
mod feature;
#[cfg(feature = "ext")]
mod fit;
#[cfg(feature = "ext")]
mod geometry;
#[cfg(feature = "ext")]
mod hash;
#[cfg(feature = "ext")]
mod identity;
#[cfg(feature = "ext")]
mod journal;
#[cfg(feature = "ext")]
mod materialize;
#[cfg(feature = "ext")]
mod model;
#[cfg(feature = "ext")]
mod ondisk;
#[cfg(feature = "ext")]
mod read;
#[cfg(feature = "ext")]
mod sealed;

#[cfg(feature = "ext")]
pub mod ext;

// ── The FAT family: the `fat` module, behind the off-by-default `fat` feature ──
//
// A family of its own, sharing only the root substrate with ext. Its layers live under the
// module rather than at the crate root, so nothing about a FAT boot sector is reachable
// without naming the family it belongs to.
#[cfg(feature = "fat")]
pub mod fat;
