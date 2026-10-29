//! The pure model built from a [`Source`](crate::Source) before any byte is written: what every
//! entry of a tree is, the identifier it takes, the names it answers to, and the streams its
//! bytes go in.
//!
//! Everything a populated volume can fail on but the container's room for it happens here, so
//! a caller finds out whether a build works before the destination is touched. The materializer
//! that consumes a model places its streams, turns it into records and writes them; it makes no
//! further decisions about the tree.
//!
//! # What APFS records, and why nothing is lost here
//!
//! An inode carries an owner, a group, a full mode, a link count or child count, a device
//! number, and four times each to the nanosecond; a name is up to 255 UTF-16 code units; an
//! extended attribute is a record of its own. That is every property a [`SourceEntry`]
//! carries, so a tree goes in whole and the fidelity report is empty. What a source states that
//! macOS would not keep is refused rather than written where macOS cannot reach it: an
//! attribute on a device node, and an attribute name that is not UTF-8. The fourth time, an
//! inode's birth, is one a source does not state: it is the modification time where that is not
//! before 1970 and not after the format's instant, and the format's instant otherwise, since
//! macOS refuses to read an inode created before 1970.
//!
//! # What a name may be
//!
//! A name is held to what macOS creates under the release profile's Unicode version (see
//! [`names`]), and to the bytes a directory entry's key holds: no NUL. Two names
//! one directory compares as one, under the volume's kind of name, are refused rather than
//! one of them dropped.
//!
//! # Numbering
//!
//! Identifiers are taken from 16 in a depth-first walk from the root, each directory's entries
//! in the order its records sort: by the hash of the name's compared form, and names under one
//! hash by their bytes. An inode takes the next identifier when the walk meets its first name,
//! and each of its attributes held in a stream the one after that. A file meeting its second
//! name takes, there, an identifier for its first name's sibling record and one for the second
//! name's, and one more for each later name. This is how `hdiutil create -srcfolder` numbers a
//! tree on a volume of the kind it is copied from, which makes the identifiers a function of
//! the tree rather than of the order a source yields it in.
//!
//! # Where attributes go
//!
//! An attribute of up to [`MAX_EMBEDDED_XATTR`] bytes is held in its record, as macOS 15, 26 and
//! 27 hold one set through `setxattr`, and a larger one in a stream of its own. A resource fork
//! is always a stream, as every one macOS wrote is. A symbolic link's target is an attribute the
//! format owns, held in its record.
//!
//! An attribute's name is at most [`MAX_XATTR_NAME`] bytes, the longest `setxattr` sets. At that
//! length a record holding a value of [`MAX_EMBEDDED_XATTR`] bytes fits a node of the file-system
//! tree at every block size, and macOS holds such a value in its record under names of 1, 10 and
//! 120 bytes alike.

use std::collections::{BTreeMap, HashMap};

use crate::Timestamp;
use crate::fidelity::FidelityReport;
use crate::path::canonical_key;
use crate::source::{
    ClassifyError, CompressedFile, Darwin, EntryKind, FileContent, LinkEnd, LinkStep,
    MODE_TYPE_MASK, Metadata, PathFault, SourceEntry, classify_paths, follow_hard_link,
};
use crate::xattr::{Xattr, repeated_name, same_xattrs};

use super::bulk;
use super::decmpfs::{self, Layout};
use super::names::{self, NameFault, UnicodeVersion};
use super::ondisk::{
    DECMPFS_XATTR, RESOURCE_FORK_XATTR, SYMLINK_XATTR, XattrValue, inode_number, xattr_key_size,
};

/// The most bytes of an attribute held in its record; a larger one is a stream.
///
/// macOS 15, 26 and 27 hold an attribute set through `setxattr` in its record at every size
/// from 1 to 3,800 bytes, and in a stream at every size from 3,801 to 4,096 bytes.
pub const MAX_EMBEDDED_XATTR: usize = 3800;

/// Why a compressed file's stored form is refused.
///
/// The form is held to its header: the header names a compression type a read of the volume
/// decodes, the content's length is the file's, and the content is where that type keeps it.
/// The compressed chunks themselves are written as given.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CompressedFault {
    /// The header is shorter than 16 bytes or does not open with `fpmc`.
    #[error("the compression header is not one")]
    NotAHeader,
    /// The header names a compression type no read of the volume decodes.
    #[error("compression type {0} is not one a read of the volume decodes")]
    UnknownType(u32),
    /// The header's content length is not the file's.
    #[error(
        "the compression header gives {declared} bytes of content, where the file holds {held}"
    )]
    #[non_exhaustive]
    LengthDiffers {
        /// The length the header gives.
        declared: u64,
        /// The file's length.
        held: u64,
    },
    /// The type keeps its content in a resource fork, and the form has none.
    #[error("compression type {0} keeps its content in a resource fork, and none is given")]
    ForkMissing(u32),
    /// The type keeps its content after its header, and the form has a resource fork too.
    #[error(
        "compression type {0} keeps its content after its header, and a resource fork is given"
    )]
    ForkGiven(u32),
    /// Content kept after its header is more than one chunk of 64 KiB.
    #[error("content kept after its compression header is {0} bytes, past one chunk of 65536")]
    InlineTooLarge(u64),
    /// The header and the content after it are longer than macOS keeps a compressed file with.
    #[error(
        "a compression attribute of {0} bytes, past the {max} macOS keeps a compressed file with",
        max = decmpfs::MAX_INLINE
    )]
    AttributeTooLong(u64),
}

/// What about `form`, the stored form of a file of `held` bytes, is refused, if anything.
fn compressed_fault(form: &CompressedFile, held: u64) -> Option<CompressedFault> {
    let Some(header) = decmpfs::Header::read_from(&form.header) else {
        return Some(CompressedFault::NotAHeader);
    };
    let Some((layout, _)) = decmpfs::layout(header.method) else {
        return Some(CompressedFault::UnknownType(header.method));
    };
    if header.size != held {
        return Some(CompressedFault::LengthDiffers {
            declared: header.size,
            held,
        });
    }
    match (layout, &form.fork) {
        (Layout::Inline, Some(_)) => Some(CompressedFault::ForkGiven(header.method)),
        (Layout::Inline, None) if decmpfs::chunk_count(held) > 1 => {
            Some(CompressedFault::InlineTooLarge(held))
        }
        (Layout::Inline, None) if form.header.len() as u64 > decmpfs::MAX_INLINE => {
            Some(CompressedFault::AttributeTooLong(form.header.len() as u64))
        }
        (Layout::Offsets | Layout::Resource, None) => {
            Some(CompressedFault::ForkMissing(header.method))
        }
        _ => None,
    }
}

/// The most bytes of a compressed file's header held in its record; a longer one is a stream.
///
/// Every compression header macOS 14 to 27 wrote is held in its record up to 128 bytes and in a
/// stream from 129, 1,206 and 3,176 of them in the images on hand.
pub(crate) const MAX_EMBEDDED_HEADER: usize = 128;

/// The longest target a symbolic link may have, in bytes.
///
/// macOS 15, 26 and 27 create a link at every target length from 1 to 1,023 bytes and hold each
/// target in its record.
pub const MAX_SYMLINK_TARGET: usize = 1023;

/// The largest attribute value a volume holds, in bytes: `setxattr` on macOS 26 sets one of
/// 2,147,483,647 bytes and refuses one a byte longer.
pub const MAX_XATTR_VALUE: u64 = (1 << 31) - 1;

/// The longest attribute name a volume holds, in bytes.
///
/// `setxattr` on macOS 15, 26 and 27 sets a name of 127 bytes and refuses a longer one with
/// `ENAMETOOLONG`. A longer name in a volume's records is no attribute a program can read: macOS
/// lists a name of 128 to 255 bytes and refuses to read it by that name, and past about two
/// thousand bytes `fsck_apfs` finds the tree invalid and macOS lists nothing.
pub const MAX_XATTR_NAME: usize = 127;

// A record holding the longest name and the largest value held in a record fits a node of the
// smallest block size, so no attribute is held in a stream for the length of its name.
const _: () = assert!(
    xattr_key_size(MAX_XATTR_NAME) + XattrValue::HEADER_SIZE + MAX_EMBEDDED_XATTR
        <= bulk::largest_entry(4096)
);

/// The largest device major number Darwin's 32-bit device number holds: eight bits.
const MAX_DEVICE_MAJOR: u32 = 0xFF;

/// The largest device minor number it holds: 24 bits.
const MAX_DEVICE_MINOR: u32 = 0x00FF_FFFF;

/// Something a source states that this volume cannot hold.
///
/// A path in a message is rendered rather than repeated: a source path is a byte string that
/// need not be text and may hold anything a terminal acts on.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A file declared by its length alone, whose bytes the source does not hold. This writer
    /// reads every file's bytes itself.
    #[error(
        "{}: its contents are declared by length alone, and this writer reads every file's bytes",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    ContentsNotHeld {
        /// The file's path.
        path: Vec<u8>,
    },
    /// A path component was `..`, which a source may not use: a path is where an entry goes,
    /// not a traversal to be resolved.
    #[error("path {} has a `..` component", crate::escape::printable(.path))]
    #[non_exhaustive]
    InvalidComponent {
        /// The offending path.
        path: Vec<u8>,
    },
    /// Two entries resolve to the same path.
    #[error("path {} is used by more than one entry", crate::escape::printable(.path))]
    #[non_exhaustive]
    Duplicate {
        /// The duplicated path.
        path: Vec<u8>,
    },
    /// An entry naming the root is not a directory.
    #[error("entry {} names the root but is not a directory", crate::escape::printable(.path))]
    #[non_exhaustive]
    RootNotDirectory {
        /// The offending path.
        path: Vec<u8>,
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
    /// A name is not UTF-8, which macOS refuses in a name.
    #[error("{}: the name is not UTF-8", crate::escape::printable(.path))]
    #[non_exhaustive]
    NameNotUtf8 {
        /// The offending path.
        path: Vec<u8>,
    },
    /// A name holds a NUL, which a directory entry's key ends its name with.
    #[error("{}: the name holds a NUL", crate::escape::printable(.path))]
    #[non_exhaustive]
    NameHoldsNul {
        /// The offending path.
        path: Vec<u8>,
    },
    /// A name is longer than the 255 UTF-16 code units macOS creates.
    #[error(
        "{}: the name is {units} UTF-16 code units, and macOS creates none longer than 255",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    NameTooLong {
        /// The offending path.
        path: Vec<u8>,
        /// How long the name is, in UTF-16 code units.
        units: usize,
    },
    /// A name holds a code point the release profile's Unicode version leaves unassigned, or a
    /// noncharacter, either of which macOS refuses in a name.
    #[error(
        "{}: the name holds U+{code_point:04X}, which macOS refuses in a name under Unicode \
         {}.{}",
        crate::escape::printable(.path),
        .unicode.0,
        .unicode.1
    )]
    #[non_exhaustive]
    NameRefused {
        /// The offending path.
        path: Vec<u8>,
        /// The code point.
        code_point: u32,
        /// The Unicode version the profile holds names to, as its major and minor numbers.
        unicode: (u8, u8),
    },
    /// Two names of one directory are one name on this volume: they differ only in case on a
    /// volume that folds it, or only in how a character is composed.
    #[error(
        "{} and {} are one name on this volume",
        crate::escape::printable(.first),
        crate::escape::printable(.second)
    )]
    #[non_exhaustive]
    NamesCompareEqual {
        /// One of the two paths.
        first: Vec<u8>,
        /// The other.
        second: Vec<u8>,
    },
    /// An entry's `mode` carries file-type bits, which the entry's kind supplies.
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
    /// A device node's number does not fit Darwin's: an 8-bit major and a 24-bit minor.
    #[error(
        "{}: device {major}:{minor} does not fit an 8-bit major and a 24-bit minor",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    DeviceNumberTooLarge {
        /// The offending path.
        path: Vec<u8>,
        /// The major number as given.
        major: u32,
        /// The minor number as given.
        minor: u32,
    },
    /// A symbolic link's target is empty, holds a NUL, or is longer than
    /// [`MAX_SYMLINK_TARGET`] bytes.
    #[error(
        "{}: a link target of {bytes} bytes, empty, or holding a NUL; macOS creates targets of 1 \
         to {MAX_SYMLINK_TARGET} bytes",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    SymlinkTarget {
        /// The link's path.
        path: Vec<u8>,
        /// How long the target is.
        bytes: usize,
    },
    /// An attribute's name is empty, holds a NUL, or is the name the format keeps a symbolic
    /// link's target under.
    #[error(
        "{}: the attribute name {} cannot be stored",
        crate::escape::printable(.path),
        crate::escape::printable(.name)
    )]
    #[non_exhaustive]
    XattrName {
        /// The entry's path.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// An attribute's name is not UTF-8, which macOS neither sets nor passes in a check.
    #[error(
        "{}: the attribute name {} is not UTF-8, which macOS neither sets nor passes in a check",
        crate::escape::printable(.path),
        crate::escape::printable(.name)
    )]
    #[non_exhaustive]
    XattrNameNotUtf8 {
        /// The entry's path.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// A device node carries attributes, which macOS neither lists, reads nor sets on one.
    #[error(
        "{}: a device node carries attributes, which macOS neither lists, reads nor sets on one",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    XattrOnDevice {
        /// The device node's path.
        path: Vec<u8>,
    },
    /// An attribute's name is longer than [`MAX_XATTR_NAME`] bytes.
    #[error(
        "{}: an attribute name of {} bytes, past the {MAX_XATTR_NAME} macOS sets",
        crate::escape::printable(.path),
        .name.len()
    )]
    #[non_exhaustive]
    XattrNameTooLong {
        /// The entry's path.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// An entry states one attribute name twice, and an inode holds one value under each name.
    #[error(
        "{}: the attribute {} is stated more than once",
        crate::escape::printable(.path),
        crate::escape::printable(.name)
    )]
    #[non_exhaustive]
    XattrRepeated {
        /// The entry's path.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// An attribute's value is larger than [`MAX_XATTR_VALUE`] bytes.
    #[error(
        "{}: the attribute {} is {bytes} bytes, and macOS sets none larger than \
         {MAX_XATTR_VALUE}",
        crate::escape::printable(.path),
        crate::escape::printable(.name)
    )]
    #[non_exhaustive]
    XattrTooLarge {
        /// The entry's path.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
        /// How large its value is.
        bytes: u64,
    },
    /// A time is outside what a time in nanoseconds since 1970 holds: before 1677 or after
    /// 2262, or with a fraction of a second of a second or more.
    #[error(
        "{}: a time of {secs} seconds and {nanos} nanoseconds since 1970 is outside what an \
         inode records",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    TimeOutOfRange {
        /// The entry's path.
        path: Vec<u8>,
        /// The time's seconds since 1970.
        secs: i64,
        /// Its nanoseconds.
        nanos: u32,
    },
    /// An entry states a birth time before 1970, which macOS answers a `stat` of with
    /// `EBADMSG` rather than reading. Every later instant is held.
    #[error(
        "{}: a birth time {secs} seconds before 1970 is one macOS will not read",
        crate::escape::printable(.path),
        secs = .secs.unsigned_abs()
    )]
    #[non_exhaustive]
    BirthTimeBeforeEpoch {
        /// The entry's path.
        path: Vec<u8>,
        /// The birth time's seconds since 1970, which are negative.
        secs: i64,
    },
    /// An entry other than a regular file carries a compressed file's stored form.
    #[error(
        "{}: a compressed form on an entry that is not a regular file",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    CompressedNotAFile {
        /// The offending path.
        path: Vec<u8>,
    },
    /// A regular file's compressed form contradicts the file, or is not one a read of the
    /// volume turns into content.
    #[error("{}: {fault}", crate::escape::printable(.path))]
    #[non_exhaustive]
    CompressedForm {
        /// The offending path.
        path: Vec<u8>,
        /// What about the form is refused.
        fault: CompressedFault,
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
    /// A hard link states extended attributes other than its target's: attributes belong to
    /// the object, and a link is a name for it. A link repeating its target's attributes
    /// exactly states nothing new and is accepted.
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
}

/// What one inode is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum InodeKind {
    /// A directory, and its entries in the order its records sort.
    Directory(Vec<Child>),
    /// A regular file: its length, and the stream its bytes go in where it has any.
    File {
        /// Its length in bytes.
        size: u64,
        /// Its data stream's identifier, which is the inode's own, where the file is not
        /// empty.
        stream: Option<u64>,
    },
    /// A symbolic link, and its target.
    Symlink(Vec<u8>),
    /// A device node: whether it is block-special, and Darwin's 32-bit device number.
    Device {
        /// Whether the node is block-special rather than character-special.
        block: bool,
        /// The major number in the high eight bits and the minor in the low 24.
        number: u32,
    },
    /// A named pipe.
    Fifo,
    /// A Unix-domain socket node.
    Socket,
}

impl InodeKind {
    /// The bits of a mode that say what this is.
    pub(crate) const fn mode_bits(&self) -> u16 {
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

    /// The type a directory entry naming this records, as `DT_*` numbers it.
    pub(crate) const fn entry_type(&self) -> u16 {
        match self {
            Self::Fifo => 1,
            Self::Device { block: false, .. } => 2,
            Self::Directory(_) => 4,
            Self::Device { block: true, .. } => 6,
            Self::File { .. } => 8,
            Self::Symlink(_) => 10,
            Self::Socket => 12,
        }
    }
}

/// One entry of a directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Child {
    /// The name, as the source gave it.
    pub(crate) name: Vec<u8>,
    /// The hash its record is keyed by.
    pub(crate) hash: u32,
    /// The inode it names.
    pub(crate) inode: u64,
    /// The type its record carries.
    pub(crate) entry_type: u16,
    /// Its sibling identifier, where the inode it names has more than one name.
    pub(crate) sibling: Option<u64>,
}

/// One name of an inode with more than one: where it is, and the identifier its sibling
/// records are keyed by.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Sibling {
    /// The sibling identifier.
    pub(crate) id: u64,
    /// The directory holding the name.
    pub(crate) parent: u64,
    /// The name.
    pub(crate) name: Vec<u8>,
}

/// An extended attribute, held in its record or in a stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum ModelXattr {
    /// Held in the record.
    Embedded {
        /// The name, as the source gave it.
        name: Vec<u8>,
        /// The value.
        value: Vec<u8>,
        /// The record's flags.
        flags: u16,
    },
    /// Held in the stream with this identifier.
    Stream {
        /// The name, as the source gave it.
        name: Vec<u8>,
        /// The stream's identifier.
        stream: u64,
        /// The record's flags.
        flags: u16,
    },
}

/// One inode of the volume.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Inode {
    /// Its identifier, which is also its private identifier.
    pub(crate) id: u64,
    /// The directory holding its first name.
    pub(crate) parent: u64,
    /// Its first name.
    pub(crate) name: Vec<u8>,
    /// What it is.
    pub(crate) kind: InodeKind,
    /// Ownership, permission bits and three times.
    pub(crate) meta: Metadata,
    /// Its attributes, in the order their records sort: by name, byte for byte.
    pub(crate) xattrs: Vec<ModelXattr>,
    /// How many names it has; one for a directory.
    pub(crate) links: u32,
    /// Its names' sibling records, where it has more than one name.
    pub(crate) siblings: Vec<Sibling>,
    /// Its BSD flags.
    pub(crate) bsd_flags: u32,
    /// Whether it is a file written compressed, as its source's stored form holds it: its
    /// compression header and resource fork among its attributes, and no data stream.
    pub(crate) compressed: bool,
}

/// What a stream holds: a file's bytes, or an attribute's value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum StreamBytes {
    /// A file's content, read when it is placed.
    File(FileContent),
    /// An attribute's value.
    Held(Vec<u8>),
}

/// A run of bytes the volume holds in blocks of their own: a file's data, or an attribute too
/// large for its record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Stream {
    /// The identifier its extents are keyed by.
    pub(crate) id: u64,
    /// The identifier its extent references record as their owner: the file's own for its
    /// data, and the inode's for an attribute.
    pub(crate) owner: u64,
    /// Its length in bytes.
    pub(crate) len: u64,
    /// What it holds.
    pub(crate) bytes: StreamBytes,
    /// The bytes it records as written: the length for a file's data and a resource fork, and
    /// zero for an attribute set through `setxattr`, which every such stream macOS wrote records.
    pub(crate) written: u64,
}

/// How many inodes of each kind the volume counts, the root and private directories not among
/// them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct Counts {
    /// Regular files.
    pub(crate) files: u64,
    /// Directories.
    pub(crate) directories: u64,
    /// Symbolic links.
    pub(crate) symlinks: u64,
    /// Device nodes, named pipes and sockets.
    pub(crate) other: u64,
}

/// A source turned into a volume's inodes.
#[derive(Clone, Debug)]
pub(crate) struct ApfsModel {
    /// The root directory, identifier 2.
    pub(crate) root: Inode,
    /// Every other inode, in identifier order.
    pub(crate) inodes: Vec<Inode>,
    /// Every stream, in the order they are placed: each file's data in inode order, then each
    /// attribute's in identifier order.
    pub(crate) streams: Vec<Stream>,
    /// One past the highest identifier taken.
    pub(crate) next_object_id: u64,
    /// The inodes of each kind.
    pub(crate) counts: Counts,
    /// What the volume could not carry, which is nothing.
    pub(crate) fidelity: FidelityReport,
}

/// Build the model `entries` imply for a volume whose names `fold` case or keep it, held to
/// Unicode `unicode`. `root` is the root directory's metadata where no entry names the root.
/// Identifiers past the root and private directories are numbered from `first`.
///
/// # Errors
///
/// A [`ModelError`] for anything the volume cannot hold.
pub(crate) fn build_model(
    entries: Vec<SourceEntry>,
    fold: bool,
    unicode: UnicodeVersion,
    root: Metadata,
    first: u64,
) -> Result<ApfsModel, ModelError> {
    Builder {
        fold,
        unicode,
        next: first,
        inodes: Vec::new(),
        streams: Vec::new(),
        attribute_streams: Vec::new(),
        counts: Counts::default(),
    }
    .build(entries, root)
}

/// `time` in nanoseconds since 1970, as an inode records it, where it fits.
pub(crate) fn nanos_of(time: Timestamp) -> Option<i64> {
    if !time.has_proper_fraction() {
        return None;
    }
    time.secs
        .checked_mul(i64::from(Timestamp::NANOS_PER_SEC))?
        .checked_add(i64::from(time.nanos))
}

/// What a path holds, decided before anything is numbered.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Class {
    /// A directory.
    Directory,
    /// Something with an inode of its own: a file, a link, a node.
    Object,
    /// A hard link, by the canonical key of what it names.
    Link(Vec<u8>),
}

/// One entry a directory will hold, before anything is numbered.
struct Planned {
    /// The entry's canonical key.
    key: Vec<u8>,
    /// Its name.
    name: Vec<u8>,
    /// The hash its record is keyed by.
    hash: u32,
}

/// A directory the walk has entered: the slot its inode is in, its entries in record order, and
/// how many of them it has reached.
struct Frame {
    slot: Slot,
    entries: Vec<Planned>,
    next: usize,
}

/// Where an inode is: the root, or one of the others by index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    Root,
    At(usize),
}

/// The tree under construction.
struct Builder {
    fold: bool,
    unicode: UnicodeVersion,
    /// The next identifier the walk takes.
    next: u64,
    inodes: Vec<Inode>,
    streams: Vec<Stream>,
    attribute_streams: Vec<Stream>,
    counts: Counts,
}

impl Builder {
    fn build(
        mut self,
        entries: Vec<SourceEntry>,
        root_meta: Metadata,
    ) -> Result<ApfsModel, ModelError> {
        let classes = classify_paths(
            &entries,
            |entry, parts| self.class_of(entry, parts),
            |class| *class == Class::Directory,
        )
        .map_err(|e| match e {
            ClassifyError::Path(PathFault::Traversal, path) => {
                ModelError::InvalidComponent { path }
            }
            ClassifyError::Path(PathFault::Duplicate, path) => ModelError::Duplicate { path },
            ClassifyError::Path(PathFault::RootNotDirectory, path) => {
                ModelError::RootNotDirectory { path }
            }
            ClassifyError::Class(e) => e,
        })?;
        let by_key: HashMap<Vec<u8>, &SourceEntry> = entries
            .iter()
            .map(|entry| (canonical_key(&entry.path), entry))
            .collect();

        // Every entry's directory, each directory's entries in record order, and every pair of
        // names a directory compares as one refused. Entries are met in the source's order, so
        // the error a source with two faults gets is the first's, every time.
        let mut children: BTreeMap<Vec<u8>, Vec<Planned>> = BTreeMap::new();
        for entry in &entries {
            let key = canonical_key(&entry.path);
            if key.is_empty() {
                continue;
            }
            let (parent, name) = match key.iter().rposition(|&b| b == b'/') {
                Some(at) => (key[..at].to_vec(), key[at + 1..].to_vec()),
                None => (Vec::new(), key.clone()),
            };
            if !parent.is_empty() {
                match classes.get(&parent) {
                    None => {
                        return Err(ModelError::ParentMissing {
                            path: entry.path.clone(),
                        });
                    }
                    Some(Class::Directory) => {}
                    Some(_) => {
                        return Err(ModelError::ParentNotDir {
                            path: entry.path.clone(),
                        });
                    }
                }
            }
            let form = names::key(&name, self.fold).expect("a name was held to UTF-8");
            children.entry(parent).or_default().push(Planned {
                key: key.clone(),
                hash: names::hash(&form),
                name,
            });
        }
        for list in children.values_mut() {
            list.sort_by(|a, b| a.hash.cmp(&b.hash).then_with(|| a.name.cmp(&b.name)));
            for run in list.chunk_by(|a, b| a.hash == b.hash) {
                for (i, a) in run.iter().enumerate() {
                    for b in &run[i + 1..] {
                        if names::key(&a.name, self.fold) == names::key(&b.name, self.fold) {
                            return Err(ModelError::NamesCompareEqual {
                                first: by_key[&a.key].path.clone(),
                                second: by_key[&b.key].path.clone(),
                            });
                        }
                    }
                }
            }
        }

        // What each hard link names, at the end of its chain.
        let mut object_of: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for entry in &entries {
            let key = canonical_key(&entry.path);
            let Some(Class::Link(target)) = classes.get(&key) else {
                continue;
            };
            let end = follow_hard_link(target, classes.len(), |at| match classes.get(at) {
                None => LinkStep::Missing,
                Some(Class::Directory) => LinkStep::Directory,
                Some(Class::Object) => LinkStep::File(at.to_vec()),
                Some(Class::Link(next)) => LinkStep::Link(next.clone()),
            });
            let object = match end {
                LinkEnd::File(object) => object,
                LinkEnd::Missing | LinkEnd::Unrepresentable => {
                    return Err(ModelError::HardlinkTargetMissing {
                        path: entry.path.clone(),
                        target: target.clone(),
                    });
                }
                LinkEnd::Directory => {
                    return Err(ModelError::HardlinkTargetIsDirectory {
                        path: entry.path.clone(),
                        target: target.clone(),
                    });
                }
                LinkEnd::Cycle => {
                    return Err(ModelError::HardlinkCycle {
                        path: entry.path.clone(),
                    });
                }
            };
            if !entry.xattrs.is_empty() && !same_xattrs(&entry.xattrs, &by_key[&object].xattrs) {
                return Err(ModelError::LinkCarriesXattrs {
                    path: entry.path.clone(),
                });
            }
            object_of.insert(key, object);
        }

        // The root, whose attributes' streams take the first identifiers the walk does.
        let (root_meta, root_xattrs, root_darwin) = match by_key.get(&Vec::new()) {
            Some(entry) => (entry.meta, entry.xattrs.clone(), entry.darwin.clone()),
            None => (root_meta, Vec::new(), None),
        };
        let root_darwin = root_darwin.as_ref();
        let mut root = Inode {
            id: inode_number::ROOT,
            parent: inode_number::ROOT_PARENT,
            name: b"root".to_vec(),
            kind: InodeKind::Directory(Vec::new()),
            meta: root_meta,
            xattrs: Vec::new(),
            links: 1,
            siblings: Vec::new(),
            bsd_flags: root_darwin.map_or(0, Darwin::stated_flags),
            compressed: false,
        };
        root.xattrs = self.xattrs(inode_number::ROOT, &root_xattrs, false);

        // The walk: each directory's entries in record order, a directory entered as soon as it
        // is met.
        let mut placed: HashMap<Vec<u8>, usize> = HashMap::new();
        // Where each inode's first name is among its directory's entries, by the inode's place,
        // so a second name finds the first without a search of the directory.
        let mut first_entry: Vec<usize> = Vec::new();
        let mut stack = vec![Frame {
            slot: Slot::Root,
            entries: children.remove(&Vec::new()).unwrap_or_default(),
            next: 0,
        }];
        while let Some(frame) = stack.last_mut() {
            let Some(planned) = frame.entries.get(frame.next) else {
                stack.pop();
                continue;
            };
            frame.next += 1;
            let parent_slot = frame.slot;
            let parent_id = match parent_slot {
                Slot::Root => inode_number::ROOT,
                Slot::At(i) => self.inodes[i].id,
            };
            let object = object_of.get(&planned.key).unwrap_or(&planned.key).clone();
            let name = planned.name.clone();
            let hash = planned.hash;
            let key = planned.key.clone();

            let mut new_inode = None;
            let child = if let Some(&at) = placed.get(&object) {
                // Another name for an inode the walk has met: a sibling for its first name if
                // this is its second, then one for this name.
                if self.inodes[at].siblings.is_empty() {
                    let first = self.take();
                    let (first_parent, first_name) =
                        (self.inodes[at].parent, self.inodes[at].name.clone());
                    self.inodes[at].siblings.push(Sibling {
                        id: first,
                        parent: first_parent,
                        name: first_name.clone(),
                    });
                    let entry = self
                        .child_at(&mut root, first_parent, first_entry[at])
                        .expect("an inode's first name is in its directory");
                    debug_assert_eq!(entry.name, first_name);
                    entry.sibling = Some(first);
                }
                let id = self.take();
                self.inodes[at].siblings.push(Sibling {
                    id,
                    parent: parent_id,
                    name: name.clone(),
                });
                self.inodes[at].links += 1;
                Child {
                    name,
                    hash,
                    inode: self.inodes[at].id,
                    entry_type: self.inodes[at].kind.entry_type(),
                    sibling: Some(id),
                }
            } else {
                let entry = by_key[&object];
                let id = self.take();
                let darwin = entry.darwin.as_ref();
                let compressed = darwin.and_then(|d| d.compressed.as_ref());
                let kind = match &entry.kind {
                    EntryKind::Directory => {
                        self.counts.directories += 1;
                        InodeKind::Directory(Vec::new())
                    }
                    EntryKind::File(content) if compressed.is_some() => {
                        // The stored form is the content; the decoded bytes are not written.
                        self.counts.files += 1;
                        InodeKind::File {
                            size: content.len(),
                            stream: None,
                        }
                    }
                    EntryKind::File(content) => {
                        self.counts.files += 1;
                        let size = content.len();
                        let stream = (size > 0).then_some(id);
                        if size > 0 {
                            self.streams.push(Stream {
                                id,
                                owner: id,
                                len: size,
                                bytes: StreamBytes::File(content.clone()),
                                written: size,
                            });
                        }
                        InodeKind::File { size, stream }
                    }
                    EntryKind::Symlink(target) => {
                        self.counts.symlinks += 1;
                        InodeKind::Symlink(target.clone())
                    }
                    EntryKind::CharDevice { major, minor } => {
                        self.counts.other += 1;
                        InodeKind::Device {
                            block: false,
                            number: (major << 24) | minor,
                        }
                    }
                    EntryKind::BlockDevice { major, minor } => {
                        self.counts.other += 1;
                        InodeKind::Device {
                            block: true,
                            number: (major << 24) | minor,
                        }
                    }
                    EntryKind::Fifo => {
                        self.counts.other += 1;
                        InodeKind::Fifo
                    }
                    EntryKind::Socket => {
                        self.counts.other += 1;
                        InodeKind::Socket
                    }
                    EntryKind::HardLink { .. } => {
                        unreachable!("a link's chain ends at an object, never at a link")
                    }
                };
                // A compressed file's stored form joins its attributes, and the flag a read takes
                // its content through the form by is the form's to give: set on a file written
                // compressed and on no other, whatever the source states of it.
                let mut given = entry.xattrs.clone();
                if let Some(form) = compressed {
                    given.push(Xattr {
                        name: DECMPFS_XATTR.to_vec(),
                        value: form.header.clone(),
                    });
                    if let Some(fork) = &form.fork {
                        given.push(Xattr {
                            name: RESOURCE_FORK_XATTR.to_vec(),
                            value: fork.clone(),
                        });
                    }
                }
                let xattrs = self.xattrs(id, &given, compressed.is_some());
                let bsd_flags = darwin.map_or(0, Darwin::stated_flags)
                    | if compressed.is_some() {
                        Darwin::COMPRESSED
                    } else {
                        0
                    };
                let entry_type = kind.entry_type();
                let is_directory = matches!(kind, InodeKind::Directory(_));
                self.inodes.push(Inode {
                    id,
                    parent: parent_id,
                    name: name.clone(),
                    kind,
                    meta: entry.meta,
                    xattrs,
                    links: 1,
                    siblings: Vec::new(),
                    bsd_flags,
                    compressed: compressed.is_some(),
                });
                let at = self.inodes.len() - 1;
                placed.insert(object, at);
                new_inode = Some(at);
                if is_directory {
                    // Entered once this entry is recorded in its parent, below.
                    stack.push(Frame {
                        slot: Slot::At(at),
                        entries: children.remove(&key).unwrap_or_default(),
                        next: 0,
                    });
                }
                Child {
                    name,
                    hash,
                    inode: id,
                    entry_type,
                    sibling: None,
                }
            };
            let directory = match parent_slot {
                Slot::Root => &mut root,
                Slot::At(i) => &mut self.inodes[i],
            };
            let InodeKind::Directory(entries) = &mut directory.kind else {
                unreachable!("only a directory is entered");
            };
            if let Some(at) = new_inode {
                if first_entry.len() <= at {
                    first_entry.resize(at + 1, usize::MAX);
                }
                first_entry[at] = entries.len();
            }
            entries.push(child);
        }

        let mut streams = self.streams;
        self.attribute_streams.sort_by_key(|stream| stream.id);
        streams.extend(self.attribute_streams);
        Ok(ApfsModel {
            root,
            inodes: self.inodes,
            streams,
            next_object_id: self.next,
            counts: self.counts,
            fidelity: FidelityReport::new(),
        })
    }

    /// The next identifier.
    fn take(&mut self) -> u64 {
        let id = self.next;
        self.next += 1;
        id
    }

    /// Entry `index` of directory `parent`.
    fn child_at<'a>(
        &'a mut self,
        root: &'a mut Inode,
        parent: u64,
        index: usize,
    ) -> Option<&'a mut Child> {
        let directory = if parent == inode_number::ROOT {
            root
        } else {
            let at = self.inodes.binary_search_by_key(&parent, |i| i.id).ok()?;
            &mut self.inodes[at]
        };
        let InodeKind::Directory(entries) = &mut directory.kind else {
            return None;
        };
        entries.get_mut(index)
    }

    /// The attributes of inode `id`, in record order, each held in its record or given a
    /// stream and the next identifier.
    fn xattrs(&mut self, id: u64, given: &[Xattr], compressed: bool) -> Vec<ModelXattr> {
        let mut sorted: Vec<&Xattr> = given.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        sorted
            .into_iter()
            .map(|xattr| {
                // A resource fork, and a compressed file's header, are kept as the file system
                // keeps them: a fork always in a stream, a header in its record up to
                // MAX_EMBEDDED_HEADER bytes, each stream recording its length as written.
                let header = compressed && xattr.name == DECMPFS_XATTR;
                let fork = xattr.name == RESOURCE_FORK_XATTR || header;
                let limit = if header {
                    MAX_EMBEDDED_HEADER
                } else {
                    MAX_EMBEDDED_XATTR
                };
                if (header || !fork) && xattr.value.len() <= limit {
                    return ModelXattr::Embedded {
                        name: xattr.name.clone(),
                        value: xattr.value.clone(),
                        flags: super::ondisk::xattr_flags::EMBEDDED,
                    };
                }
                let stream = self.take();
                let len = xattr.value.len() as u64;
                self.attribute_streams.push(Stream {
                    id: stream,
                    owner: id,
                    len,
                    bytes: StreamBytes::Held(xattr.value.clone()),
                    written: if fork { len } else { 0 },
                });
                ModelXattr::Stream {
                    name: xattr.name.clone(),
                    stream,
                    flags: if fork {
                        super::ondisk::xattr_flags::STREAM
                    } else {
                        super::ondisk::xattr_flags::STREAM
                            | super::ondisk::xattr_flags::SET_THROUGH_SETXATTR
                    },
                }
            })
            .collect()
    }

    /// What `entry` holds, refusing what the volume cannot hold whatever it is placed beside.
    fn class_of(&self, entry: &SourceEntry, parts: &[&[u8]]) -> Result<Class, ModelError> {
        let path = || entry.path.clone();
        if let Some(name) = parts.last() {
            if name.contains(&0) {
                return Err(ModelError::NameHoldsNul { path: path() });
            }
            names::check(name, self.unicode).map_err(|fault| match fault {
                NameFault::NotUtf8 => ModelError::NameNotUtf8 { path: path() },
                NameFault::TooLong(units) => ModelError::NameTooLong {
                    path: path(),
                    units,
                },
                NameFault::Unassigned(code_point) | NameFault::Noncharacter(code_point) => {
                    ModelError::NameRefused {
                        path: path(),
                        code_point,
                        unicode: self.unicode,
                    }
                }
            })?;
        }
        let times = [entry.meta.atime, entry.meta.ctime, entry.meta.mtime];
        for time in times.into_iter().chain(entry.meta.btime) {
            if nanos_of(time).is_none() {
                return Err(ModelError::TimeOutOfRange {
                    path: path(),
                    secs: time.secs,
                    nanos: time.nanos,
                });
            }
        }
        if let Some(btime) = entry.meta.btime
            && btime.secs < 0
        {
            return Err(ModelError::BirthTimeBeforeEpoch {
                path: path(),
                secs: btime.secs,
            });
        }
        if entry.meta.mode & MODE_TYPE_MASK != 0 {
            return Err(ModelError::ModeCarriesFileType {
                path: path(),
                mode: entry.meta.mode,
            });
        }
        // macOS answers EPERM to every list, read and write of an attribute on a device node, as
        // root and with the attribute in place (observed, macOS 15, 26 and 27), so one written
        // there is one no reader of the volume on macOS reaches.
        if !entry.xattrs.is_empty()
            && matches!(
                entry.kind,
                EntryKind::CharDevice { .. } | EntryKind::BlockDevice { .. }
            )
        {
            return Err(ModelError::XattrOnDevice { path: path() });
        }
        for xattr in &entry.xattrs {
            let name = &xattr.name;
            if name.is_empty() || name.contains(&0) || name == SYMLINK_XATTR {
                return Err(ModelError::XattrName {
                    path: path(),
                    name: name.clone(),
                });
            }
            // `fsck_apfs -W` fails a volume holding an attribute name that is not UTF-8, and
            // macOS's setxattr refuses one with EINVAL (observed, macOS 15, 26 and 27).
            if std::str::from_utf8(name).is_err() {
                return Err(ModelError::XattrNameNotUtf8 {
                    path: path(),
                    name: name.clone(),
                });
            }
            if name.len() > MAX_XATTR_NAME {
                return Err(ModelError::XattrNameTooLong {
                    path: path(),
                    name: name.clone(),
                });
            }
            if xattr.value.len() as u64 > MAX_XATTR_VALUE {
                return Err(ModelError::XattrTooLarge {
                    path: path(),
                    name: name.clone(),
                    bytes: xattr.value.len() as u64,
                });
            }
        }
        if let Some(name) = repeated_name(&entry.xattrs) {
            return Err(ModelError::XattrRepeated {
                path: path(),
                name: name.to_vec(),
            });
        }
        if let Some(form) = entry.darwin.as_ref().and_then(|d| d.compressed.as_ref()) {
            let EntryKind::File(content) = &entry.kind else {
                return Err(ModelError::CompressedNotAFile { path: path() });
            };
            if let Some(fault) = compressed_fault(form, content.len()) {
                return Err(ModelError::CompressedForm {
                    path: path(),
                    fault,
                });
            }
            for name in [DECMPFS_XATTR, RESOURCE_FORK_XATTR] {
                if entry.xattrs.iter().any(|x| x.name == name) {
                    return Err(ModelError::XattrName {
                        path: path(),
                        name: name.to_vec(),
                    });
                }
            }
            for (name, value) in [
                (DECMPFS_XATTR, Some(&form.header)),
                (RESOURCE_FORK_XATTR, form.fork.as_ref()),
            ] {
                if let Some(value) = value.filter(|v| v.len() as u64 > MAX_XATTR_VALUE) {
                    return Err(ModelError::XattrTooLarge {
                        path: path(),
                        name: name.to_vec(),
                        bytes: value.len() as u64,
                    });
                }
            }
        }
        Ok(match &entry.kind {
            EntryKind::Directory => Class::Directory,
            EntryKind::HardLink { target } => Class::Link(canonical_key(target)),
            EntryKind::File(FileContent::Declared { .. }) => {
                return Err(ModelError::ContentsNotHeld { path: path() });
            }
            EntryKind::Symlink(target) => {
                if target.is_empty() || target.len() > MAX_SYMLINK_TARGET || target.contains(&0) {
                    return Err(ModelError::SymlinkTarget {
                        path: path(),
                        bytes: target.len(),
                    });
                }
                Class::Object
            }
            EntryKind::CharDevice { major, minor } | EntryKind::BlockDevice { major, minor } => {
                if *major > MAX_DEVICE_MAJOR || *minor > MAX_DEVICE_MINOR {
                    return Err(ModelError::DeviceNumberTooLarge {
                        path: path(),
                        major: *major,
                        minor: *minor,
                    });
                }
                Class::Object
            }
            EntryKind::File(_) | EntryKind::Fifo | EntryKind::Socket => Class::Object,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Source, TreeBuilder};

    const FOLDING: bool = true;
    const UNICODE: UnicodeVersion = (17, 0);

    fn meta(mode: u16) -> Metadata {
        Metadata::new(mode, Timestamp::from_secs(1_600_000_000))
    }

    fn model(source: impl Source, fold: bool) -> Result<ApfsModel, ModelError> {
        build_model(
            source.into_entries(),
            fold,
            UNICODE,
            meta(0o755),
            inode_number::FIRST_USER,
        )
    }

    /// The tree `hdiutil create -srcfolder` copied into the `simple` images: twelve files of
    /// fixed sizes, thirty more in one directory, two symbolic links, a hard link, an attribute
    /// held in its record and one held in a stream.
    fn simple() -> Vec<SourceEntry> {
        let sizes: [(&str, usize); 12] = [
            ("top/empty", 0),
            ("top/one", 1),
            ("top/hundred", 100),
            ("top/under", 4095),
            ("top/block", 4096),
            ("top/over", 4097),
            ("top/three", 12288),
            ("top/sub1/sixtyfour", 65536),
            ("top/sub1/mega", (1 << 20) + 3),
            ("top/sub2/deep/a", 10),
            ("top/sub2/deep/b", 20000),
            ("top/sub2/\u{E9}cole", 300),
        ];
        let mut tree = TreeBuilder::new();
        for dir in [
            "top",
            "top/sub1",
            "top/sub2",
            "top/sub2/deep",
            "top/sub2/empty-dir",
        ] {
            tree = tree.directory(format!("/{dir}"), meta(0o755));
        }
        for (path, size) in sizes {
            tree = tree.file(format!("/{path}"), vec![7u8; size], meta(0o644));
        }
        for i in 0..30 {
            tree = tree.file(format!("/top/sub1/n{i:02}"), vec![1u8; 50 * i], meta(0o644));
        }
        let entries = tree
            .symlink("/top/link-rel", "block", meta(0o755))
            .symlink("/top/link-abs", "/nowhere/at/all", meta(0o755))
            .hardlink("/top/sub1/three-again", "/top/three", meta(0o644))
            .into_entries();
        entries
            .into_iter()
            .map(|entry| match entry.path.as_slice() {
                b"/top/block" => entry.with_xattrs(vec![Xattr {
                    name: b"user.small".to_vec(),
                    value: vec![3u8; 16],
                }]),
                b"/top/over" => entry.with_xattrs(vec![Xattr {
                    name: b"user.big".to_vec(),
                    value: vec![4u8; 8000],
                }]),
                _ => entry,
            })
            .collect()
    }

    /// Every name of the model's tree and the inode it names, with each name's sibling
    /// identifier.
    fn named(model: &ApfsModel) -> BTreeMap<Vec<u8>, (u64, Option<u64>)> {
        let mut out = BTreeMap::new();
        let mut todo = vec![(Vec::new(), &model.root)];
        while let Some((path, dir)) = todo.pop() {
            let InodeKind::Directory(children) = &dir.kind else {
                continue;
            };
            for child in children {
                let mut name = path.clone();
                if !name.is_empty() {
                    name.push(b'/');
                }
                name.extend_from_slice(&child.name);
                out.insert(name.clone(), (child.inode, child.sibling));
                if let Some(inode) = model.inodes.iter().find(|i| i.id == child.inode)
                    && (child.sibling.is_none() || inode.name == child.name)
                {
                    todo.push((name, inode));
                }
            }
        }
        out
    }

    #[test]
    fn a_tree_is_numbered_as_hdiutil_numbered_it() {
        // Every identifier of `simple-1` on macOS 26: a depth-first walk in record order, the
        // attribute stream after its inode, and the hard link's two siblings where its second
        // name is met.
        let model = model(simple(), FOLDING).expect("a model");
        let expected: &[(&str, u64)] = &[
            ("top", 16),
            ("top/hundred", 17),
            ("top/empty", 18),
            ("top/link-abs", 19),
            ("top/link-rel", 20),
            ("top/sub1", 21),
            ("top/sub1/n23", 22),
            ("top/sub1/n24", 23),
            ("top/sub1/n12", 24),
            ("top/sub1/n15", 25),
            ("top/sub1/n14", 26),
            ("top/sub1/n13", 27),
            ("top/sub1/n25", 28),
            ("top/sub1/n22", 29),
            ("top/sub1/sixtyfour", 30),
            ("top/sub1/n00", 31),
            ("top/sub1/n07", 32),
            ("top/sub1/n09", 33),
            ("top/sub1/n08", 34),
            ("top/sub1/n06", 35),
            ("top/sub1/n01", 36),
            ("top/sub1/n27", 37),
            ("top/sub1/n18", 38),
            ("top/sub1/n20", 39),
            ("top/sub1/n16", 40),
            ("top/sub1/n29", 41),
            ("top/sub1/n11", 42),
            ("top/sub1/n10", 43),
            ("top/sub1/n17", 44),
            ("top/sub1/n28", 45),
            ("top/sub1/n21", 46),
            ("top/sub1/n26", 47),
            ("top/sub1/n19", 48),
            ("top/sub1/three-again", 49),
            ("top/sub1/mega", 50),
            ("top/sub1/n04", 51),
            ("top/sub1/n03", 52),
            ("top/sub1/n02", 53),
            ("top/sub1/n05", 54),
            ("top/over", 55),
            ("top/three", 49),
            ("top/one", 59),
            ("top/sub2", 60),
            ("top/sub2/deep", 61),
            ("top/sub2/deep/a", 62),
            ("top/sub2/deep/b", 63),
            ("top/sub2/empty-dir", 64),
            ("top/sub2/\u{E9}cole", 65),
            ("top/under", 66),
            ("top/block", 67),
        ];
        let names = named(&model);
        for (path, id) in expected {
            assert_eq!(names[path.as_bytes()].0, *id, "{path}");
        }
        assert_eq!(names.len(), expected.len());
        assert_eq!(names[b"top/sub1/three-again".as_slice()].1, Some(57));
        assert_eq!(names[b"top/three".as_slice()].1, Some(58));
        assert_eq!(model.next_object_id, 68);
        let over = model.inodes.iter().find(|i| i.id == 55).unwrap();
        assert_eq!(
            over.xattrs,
            [ModelXattr::Stream {
                name: b"user.big".to_vec(),
                stream: 56,
                flags: 0x11
            }]
        );
        let three = model.inodes.iter().find(|i| i.id == 49).unwrap();
        assert_eq!(
            (three.parent, three.name.as_slice(), three.links),
            (21, &b"three-again"[..], 2)
        );
        // `simple-1` counts 42 files, 5 directories and 2 symbolic links.
        assert_eq!(
            model.counts,
            Counts {
                files: 42,
                directories: 5,
                symlinks: 2,
                other: 0
            }
        );
    }

    #[test]
    fn two_names_one_directory_compares_as_one_are_refused() {
        let folding = TreeBuilder::new().file("/Read Me", "a", meta(0o644)).file(
            "/read me",
            "b",
            meta(0o644),
        );
        assert!(matches!(
            model(folding.clone(), true),
            Err(ModelError::NamesCompareEqual { .. })
        ));
        assert!(model(folding, false).is_ok());
        let composed = TreeBuilder::new()
            .file("/caf\u{E9}", "a", meta(0o644))
            .file("/cafe\u{301}", "b", meta(0o644));
        assert!(matches!(
            model(composed, false),
            Err(ModelError::NamesCompareEqual { .. })
        ));
    }

    #[test]
    fn a_name_macos_refuses_is_refused() {
        let refused: [(Vec<u8>, &str); 5] = [
            (b"/a\xffb".to_vec(), "NameNotUtf8"),
            (b"/a\0b".to_vec(), "NameHoldsNul"),
            ("/\u{378}".into(), "NameRefused"),
            ("/\u{FDD0}".into(), "NameRefused"),
            (format!("/{}", "\u{20AC}".repeat(256)).into(), "NameTooLong"),
        ];
        for (path, want) in refused {
            let err =
                model(TreeBuilder::new().file(path, "x", meta(0o644)), true).expect_err("refused");
            assert!(format!("{err:?}").starts_with(want), "{err:?}");
        }
    }

    #[test]
    fn a_birth_time_before_1970_is_refused() {
        // macOS will not `stat` an inode created before 1970, so a source stating one names an
        // entry no Mac could read. The modification time is not held to it, as macOS holds
        // none of the other three.
        let before = Timestamp::from_secs(-1);
        for path in ["/f", "/"] {
            let entry = SourceEntry::new(
                path,
                if path == "/" {
                    EntryKind::Directory
                } else {
                    EntryKind::File(b"x".to_vec().into())
                },
                meta(0o755).with_birth_time(before),
            );
            let err = model(vec![entry], true).expect_err("refused");
            assert!(
                matches!(&err, ModelError::BirthTimeBeforeEpoch { secs: -1, path: p } if p == path.as_bytes()),
                "{err:?}"
            );
        }
        let modified = Metadata::new(0o644, before).with_birth_time(Timestamp::from_secs(0));
        model(TreeBuilder::new().file("/f", "x", modified), true).expect("held");
    }

    #[test]
    fn an_attribute_is_held_in_its_record_to_3800_bytes_and_a_resource_fork_never_is() {
        let entry = SourceEntry::new("/f", EntryKind::File(b"x".to_vec().into()), meta(0o644))
            .with_xattrs(vec![
                Xattr {
                    name: b"user.at".to_vec(),
                    value: vec![1; 3800],
                },
                Xattr {
                    name: b"user.past".to_vec(),
                    value: vec![1; 3801],
                },
                Xattr {
                    name: RESOURCE_FORK_XATTR.to_vec(),
                    value: vec![1; 4],
                },
            ]);
        let model = model(vec![entry], true).expect("a model");
        let flags: Vec<(&[u8], bool, u16)> = model.inodes[0]
            .xattrs
            .iter()
            .map(|x| match x {
                ModelXattr::Embedded { name, flags, .. } => (name.as_slice(), true, *flags),
                ModelXattr::Stream { name, flags, .. } => (name.as_slice(), false, *flags),
            })
            .collect();
        assert_eq!(
            flags,
            [
                (RESOURCE_FORK_XATTR, false, 0x1),
                (&b"user.at"[..], true, 0x2),
                (&b"user.past"[..], false, 0x11),
            ]
        );
        let written: Vec<(u64, u64)> = model.streams.iter().map(|s| (s.len, s.written)).collect();
        assert_eq!(written, [(1, 1), (4, 4), (3801, 0)]);
    }

    #[test]
    fn a_firmlink_is_held_in_its_record_at_the_longest_target_a_line_may_give() {
        // macOS 15, 26 and 27 hold every firmlink of their own system volumes in its record,
        // flagged as held there and nothing else.
        use super::super::firmlink::{FIRMLINK_XATTR, Firmlinks, MAX_FIRMLINK_TARGET, mark};
        let target = vec![b'a'; MAX_FIRMLINK_TARGET];
        let mut list = b"/d\t".to_vec();
        list.extend_from_slice(&target);
        list.push(b'\n');
        let links = Firmlinks::parse(&list).expect("a list");
        let mut entries = vec![SourceEntry::new("/d", EntryKind::Directory, meta(0o755))];
        assert_eq!(mark(&mut entries, &links, true).expect("marked"), 1);
        let model = model(entries, true).expect("a model");
        let held: Vec<(&[u8], usize, u16)> = model.inodes[0]
            .xattrs
            .iter()
            .filter_map(|x| match x {
                ModelXattr::Embedded { name, value, flags } => {
                    Some((name.as_slice(), value.len(), *flags))
                }
                ModelXattr::Stream { .. } => None,
            })
            .collect();
        assert_eq!(held, [(FIRMLINK_XATTR, MAX_FIRMLINK_TARGET + 1, 0x2)]);
    }

    #[test]
    fn what_macos_would_not_keep_of_an_attribute_is_refused() {
        // A device node's attributes, which macOS answers EPERM for, and a name that is not
        // UTF-8, which its check fails; a named pipe's attribute and a UTF-8 name are kept.
        let xattr = |name: &[u8]| Xattr {
            name: name.to_vec(),
            value: b"value".to_vec(),
        };
        for (path, kind) in [
            ("/c", EntryKind::CharDevice { major: 1, minor: 3 }),
            ("/b", EntryKind::BlockDevice { major: 1, minor: 4 }),
        ] {
            let entry =
                SourceEntry::new(path, kind, meta(0o644)).with_xattrs(vec![xattr(b"user.a")]);
            let err = model(vec![entry], true).expect_err("refused");
            assert!(
                matches!(&err, ModelError::XattrOnDevice { path: p } if p == path.as_bytes()),
                "{err:?}"
            );
        }
        let entry = SourceEntry::new(
            "/c",
            EntryKind::CharDevice { major: 1, minor: 3 },
            meta(0o644),
        );
        model(vec![entry], true).expect("a device node with no attribute");
        let pipe = SourceEntry::new("/p", EntryKind::Fifo, meta(0o644))
            .with_xattrs(vec![xattr(b"user.a")]);
        model(vec![pipe], true).expect("a named pipe's attribute");
        for name in [&b"user.\xff\xfe"[..], b"user.\xe9t\xe9"] {
            let entry = SourceEntry::new("/f", EntryKind::File(b"f".to_vec().into()), meta(0o644))
                .with_xattrs(vec![xattr(name)]);
            let err = model(vec![entry], true).expect_err("refused");
            assert!(
                matches!(&err, ModelError::XattrNameNotUtf8 { name: n, .. } if n == name),
                "{err:?}"
            );
        }
        let entry = SourceEntry::new("/f", EntryKind::File(b"f".to_vec().into()), meta(0o644))
            .with_xattrs(vec![xattr("user.caf\u{e9}".as_bytes())]);
        model(vec![entry], true).expect("a UTF-8 name");
    }

    #[test]
    fn an_attribute_named_twice_is_refused_whatever_its_values() {
        // Two records under one key are a tree no read accepts, so the name is refused before
        // anything is numbered, on a file and on the root alike.
        let xattr = |name: &str, value: &str| Xattr {
            name: name.into(),
            value: value.into(),
        };
        for path in ["/f", "/"] {
            let kind = || {
                if path == "/" {
                    EntryKind::Directory
                } else {
                    EntryKind::File(b"hello".to_vec().into())
                }
            };
            for second in ["first", "second"] {
                let entry = SourceEntry::new(path, kind(), meta(0o755)).with_xattrs(vec![
                    xattr("user.a", "first"),
                    xattr("user.b", "other"),
                    xattr("user.a", second),
                ]);
                let err = model(vec![entry], true).expect_err("refused");
                assert!(
                    matches!(&err, ModelError::XattrRepeated { path: p, name }
                        if p == path.as_bytes() && name == b"user.a"),
                    "{err:?}"
                );
            }
            let entry = SourceEntry::new(path, kind(), meta(0o755))
                .with_xattrs(vec![xattr("user.a", "first"), xattr("user.b", "first")]);
            model(vec![entry], true).expect("two names");
        }
    }

    /// A compression header of `method` giving `size` bytes, and then `tail`.
    fn header(method: u32, size: u64, tail: &[u8]) -> Vec<u8> {
        let mut header = decmpfs::MAGIC.to_vec();
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        header.extend_from_slice(tail);
        header
    }

    #[test]
    fn a_compressed_form_contradicting_its_file_is_refused_by_what_it_contradicts() {
        let held = 70_000u64;
        let fork = Some(vec![0; 16]);
        let cases: [(CompressedFile, u64, Option<CompressedFault>); 9] = [
            (
                CompressedFile::new(header(10, held, &[]), fork.clone()),
                held,
                None,
            ),
            (
                CompressedFile::new(header(9, 3, &[0xCC, 1, 2, 3]), None),
                3,
                None,
            ),
            (
                CompressedFile::new(b"fpmc".to_vec(), None),
                3,
                Some(CompressedFault::NotAHeader),
            ),
            (
                CompressedFile::new(header(9, 3, &[]).into_iter().rev().collect(), None),
                3,
                Some(CompressedFault::NotAHeader),
            ),
            (
                CompressedFile::new(header(5, 3, &[]), None),
                3,
                Some(CompressedFault::UnknownType(5)),
            ),
            (
                CompressedFile::new(header(10, held - 1, &[]), fork.clone()),
                held,
                Some(CompressedFault::LengthDiffers {
                    declared: held - 1,
                    held,
                }),
            ),
            (
                CompressedFile::new(header(10, held, &[]), None),
                held,
                Some(CompressedFault::ForkMissing(10)),
            ),
            (
                CompressedFile::new(header(9, 3, &[0xCC, 1, 2, 3]), fork),
                3,
                Some(CompressedFault::ForkGiven(9)),
            ),
            (
                CompressedFile::new(header(9, held, &[]), None),
                held,
                Some(CompressedFault::InlineTooLarge(held)),
            ),
        ];
        for (form, len, want) in cases {
            assert_eq!(compressed_fault(&form, len), want, "{form:?}");
            let content = FileContent::from(vec![0u8; len as usize]);
            let entry = SourceEntry::new("/f", EntryKind::File(content), meta(0o644))
                .with_darwin(Darwin::new(0).compressed(form));
            match (model(vec![entry], true), want) {
                (Ok(_), None) => {}
                (Err(ModelError::CompressedForm { fault, .. }), Some(want)) => {
                    assert_eq!(fault, want)
                }
                (other, want) => panic!("{want:?}: {other:?}"),
            }
        }
        // The attribute holding inline content is held to the length macOS keeps one at, the
        // header's sixteen bytes included.
        let at = (decmpfs::MAX_INLINE - 16) as usize;
        let form = |n: usize| CompressedFile::new(header(9, n as u64 - 1, &vec![0xCC; n]), None);
        assert_eq!(compressed_fault(&form(at), at as u64 - 1), None);
        assert_eq!(
            compressed_fault(&form(at + 1), at as u64),
            Some(CompressedFault::AttributeTooLong(decmpfs::MAX_INLINE + 1))
        );
    }
}
