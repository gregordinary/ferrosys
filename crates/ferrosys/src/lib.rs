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
    any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"),
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
#![cfg_attr(
    feature = "exfat",
    doc = "\n The [`exfat`] module implements the exFAT family — the \
[`format`](exfat::format) writer, the [`plan_layout`](exfat::plan_layout) geometry planner, \
and the byte-exact on-disk structures under [`exfat::ondisk`]. It shares a name with FAT and \
no bytes: a different boot region, a different directory entry format, a different name \
encoding, and an allocation bitmap FAT has no equivalent of. Three of its structures carry a \
checksum and a fourth carries a hash, and every one is recomputed rather than copied. Its \
images are byte-reproducible, and cost one input to be so — the volume serial number, since \
an empty exFAT volume records no time anywhere."
)]
#![cfg_attr(
    feature = "btrfs",
    doc = "\n The [`btrfs`] module implements the btrfs family, over the two layers the format \
has. A [`Volume`](btrfs::Volume) opens one over any `Read + Seek` source and gives the lower \
one: the superblock and every mirror of it the device holds, the chunk map that turns a \
logical address into a place on the device, and a [`Tree`](btrfs::Tree) over any of the \
filesystem's B-trees — searched by the key tuple, iterated in key order, with every block's \
checksum verified as it is read. A [`Reader`](btrfs::Reader) is the filesystem view built on \
that, and [`FormatPlan`](btrfs::FormatPlan) writes one, subvolumes included. Reading a file \
whose bytes are compressed takes the decoder for its algorithm; verifying one takes none, the \
checksums covering the bytes on the volume. The byte-exact on-disk structures are under \
[`btrfs::ondisk`]."
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
//! Nine more features are off by default, so a build that wants none of them depends only
//! on `thiserror`. Each stands alone and none implies a family — the two ends of a tree are
//! the root's vocabulary, so a source feeds whichever family is being written and a sink
//! drains whichever one was opened, and a decoder undoes an encoding whichever family
//! stored a run of bytes in it:
//!
//! - **`fat`** adds the FAT12/FAT16/FAT32 family. It has no dependencies of its own.
//! - **`exfat`** adds the exFAT family, which shares a name with the one above and none of
//!   its structures. It has no dependencies of its own.
//! - **`btrfs`** adds the btrfs family, over a format built out of B-trees and a logical
//!   address space. It has no dependencies of its own.
//! - **`zlib`**, **`lzo`** and **`zstd`** each add a decoder, so that a file whose extents
//!   are stored in that encoding reads as the file rather than as a refusal naming the
//!   algorithm. btrfs is the family here that stores runs that way, and a decoder reaches
//!   bytes only through a family that stores some — name one beside `btrfs`, as
//!   `--features btrfs,zstd`; alone it compiles its dependency and decodes nothing, since
//!   no reachable read stores runs that way. `lzo` takes no dependency, its decoder being
//!   in this crate; the other two depend on `miniz_oxide` and `ruzstd`. None of them is
//!   needed to *verify* a filesystem: the checksums it records cover the bytes it stored,
//!   so a compressed extent is checked without being expanded.
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

// Undoing the encodings a filesystem stores a run of bytes in fewer of them. Here beside
// `crc32c` and for the same reason: an encoding is a property of a run of bytes rather than
// of the format around it, and the same three algorithms appear in more than one filesystem.
// How a format frames them stays with the format. Compiled where a family that stores runs
// this way is; the three decoders inside it are each a feature of their own, so a build with
// that family and none of them still names the encoding it is declining.
#[cfg(feature = "btrfs")]
mod compress;

// The little-endian byte accessors every family's on-disk layer serializes through. Two
// families compute them identically with nothing interpreted, which is what makes them a
// shared primitive rather than a shared seam. Not compiled behind a family: the POSIX ACL
// boundary form is a fixed little-endian record that the family-agnostic substrate parses,
// so a build carrying no family still reads fields out of a buffer.
mod bytes;

// The byte boundary, in both directions. Deciding what a byte is, and finding the structure
// that holds it, belong to the family; seeking to an offset and moving exactly that many
// bytes is the same operation for every one of them, and so is the checked arithmetic that
// names the offset. Both are here and the layout logic stays with the family. This also
// holds what an i/o failure records and the conversion every error type carrying one is
// written by, which is why the module is not compiled behind a family: `DetectError` carries
// one in every build.
mod io;

// Rendering bytes that came off an image, an archive, or a host tree as text. Every name
// every family reads is a byte string that may hold whatever a terminal acts on, and a
// message or a finding that interpolates one raw hands those bytes on — so the escaping
// happens where the name enters the text, which is the last point anything can tell it apart
// from the words around it. Both renderings are public because a caller building its own
// output faces the same problem with the same names, and a second implementation of these
// rules is a second place for them to drift.
mod escape;
pub use escape::{hex, printable, push_json_string};

// Building a JSON document, as against escaping the strings that go into one. Comma
// placement and value formatting are the same rules whatever document is being written, so
// they live here and every document this crate or a consumer emits is built through them —
// the same move `escape` is, one level up from the characters.
pub mod json;

// The depth-first walk every family's reader is driven by: one frontier, one cycle check,
// one set of bounds, with each family supplying what sits on the frontier and how a name's
// children are read. Compiled where a family is, since with none there is no tree to walk.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
mod walk;

// The path resolution every family's reader answers a lookup with: one component loop, one
// ascent on `..`, one hop budget for symbolic links, with each family supplying only how a
// name is found in a directory. Compiled where a family is, for the same reason the walk is.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
mod resolve;

// One shape for a newtype over a field of on-disk flag bits: the set operations every one of
// them needs, so no two of them have different ones. Compiled where a family is, since with
// none there is no on-disk flag word.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
mod flags;

// One table per named choice, generating the word a variant is written as, the list of
// them, and the variant a word means. Every set of choices a caller names goes through it,
// so a vocabulary cannot be spelled twice and drift. `NamedChoice` is public because the
// same three questions are what a consumer's own argument parser asks, and asking them
// generically is what keeps its list of choices from being a second copy of this one.
mod naming;
pub use naming::NamedChoice;

// Image detection and the family selector it returns. `Filesystem` and `DetectError` are
// always present; `detect` dispatches across whichever families are compiled in.
mod detect;
pub use detect::{DetectError, DetectOptions, Filesystem, detect, detect_with};

// What a path is made of, and which of its components a directory can hold. Both questions
// are asked by every family and on both sides of each of them — a source keying entries, a
// model placing them, a reader resolving one, a sink creating one — so both are answered
// here. A second answer that drifted would not fail; it would key two entries apart that the
// model considers one path, or refuse a name where it is read and accept it where it is
// written.
mod path;

// A wall-clock instant, and one extended attribute. Both are boundary vocabulary rather
// than storage: how an instant splits across fields and how an attribute's name compresses
// are the family's business, and each family's on-disk layer carries its own conversion.
//
// The DOS date is where that rule has an exception, and it is here because FAT and exFAT
// carry one encoding rather than two — the same packed words, epoch, and granularity,
// inherited from the same ancestor. Where each format puts those words in an entry stays in
// that family's own layer, so this is compiled only where a family that stores it is.
mod time;
#[cfg(any(feature = "fat", feature = "exfat"))]
pub use time::DosTimestamp;
pub use time::{Civil, Timestamp};
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
pub use finding::{
    Coordinate, Deviation, FINDINGS_SCHEMA_VERSION, Family, Finding, FindingReport, ScanReport,
    Severity,
};

// Where a filesystem begins, how strictly it is read, and what one read may allocate — the
// same three settings whatever family answers them.
mod policy;
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub use policy::MAX_SYMLINK_HOPS;
pub use policy::{Limits, OpenOptions, ReadPolicy};

// Opening an image without naming its family. Compiled only where a family with a *reader*
// is: `FsReader` is an enum of concrete readers, so a build carrying only a family that has
// not got one yet has nothing for it to hold. A family whose reader lands is added to this
// condition in the same change; until then it is named by `detect` and refused by `open`
// through an error variant that exists for exactly as long as something can produce it.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
mod open;
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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

// ── The exFAT family: the `exfat` module, behind the off-by-default `exfat` feature ──
//
// A family of its own, and not a member of the one it shares a name with: the two have a
// different boot region, a different directory entry format, a different name encoding, and
// an allocation model FAT has no equivalent of. Same arrangement as `fat` — the layers live
// under the module, so nothing about an exFAT boot sector is reachable without naming the
// family it belongs to.
#[cfg(feature = "exfat")]
pub mod exfat;

// ── The btrfs family: the `btrfs` module, behind the off-by-default `btrfs` feature ──
//
// Same arrangement again, over a format built differently from all three above: B-trees over
// a logical address space that a chunk tree maps onto the device, with a checksum on every
// metadata block. The layers live under the module, so nothing about a chunk map is reachable
// without naming the family it belongs to.
#[cfg(feature = "btrfs")]
pub mod btrfs;
