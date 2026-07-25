//! The inode model: a pure, geometry-independent transform from a source's entries
//! into the inode tree the materializer writes.
//!
//! This module decides everything about *what* inodes exist, independent of *where*
//! their blocks land: it assigns inode numbers deterministically in sorted path
//! order, coalesces hard links onto one inode with the right link count, builds each
//! directory's `.`/`..` entries and the parent link accounting they imply, and
//! chooses the fast (inline) or slow (in-block) form for each symlink by its target
//! length. It performs no I/O and never touches a [`Layout`](crate::geometry::Layout).
//!
//! The root directory (inode 2) and `/lost+found` (inode 11) always exist; user
//! entries take inode 11's successors. A source entry whose path names the root
//! supplies the root directory's own mode, ownership, times, and extended attributes;
//! without one the root keeps its `0755` root-owned defaults. An input this profile
//! cannot represent is a typed [`ModelError`], never a dropped or truncated entry.

use std::collections::BTreeMap;

use crate::feature::{FeatureSet, LARGE_FILE_MIN_SIZE};
use crate::ondisk::{
    FileType, Inode, Timestamp, Xattr, has_empty_name, longest_stored_name, split_for_storage,
    xattr_block_len,
};
use crate::source::{EntryKind, FileContent, Metadata, Source, SourceEntry};

/// The widest device major number the on-disk encoding represents (12 bits).
const MAX_DEVICE_MAJOR: u32 = (1 << 12) - 1;
/// The widest device minor number the on-disk encoding represents (20 bits).
const MAX_DEVICE_MINOR: u32 = (1 << 20) - 1;

/// The root directory's inode number.
pub const ROOT_INO: u32 = 2;
/// The `/lost+found` inode number, the first non-reserved inode.
pub const LOST_FOUND_INO: u32 = 11;
/// The lowest inode number a user entry can take: the first past `/lost+found`. A
/// feature that claims an inode of its own at format time — the orphan file does —
/// takes it from here, and [`ModelConfig::first_user_inode`] moves the entries up
/// accordingly.
pub const FIRST_USER_INO: u32 = 12;

/// The size of the inode's inline block area. A symlink target shorter than this is
/// stored inline (a fast symlink), so the longest inline target is one byte less; a
/// target of this length or more is written to a data block.
const FAST_SYMLINK_MAX: usize = 60;

/// The most links ext4 records in an inode's `i_links_count`. A directory whose
/// subdirectory count would exceed this stores `1` instead — the `dir_nlink`
/// sentinel meaning the count is not tracked — and a file cannot hold more
/// hard links than this.
const EXT4_LINK_MAX: u16 = 65000;

/// The file-type bits of a mode (`S_IFMT`), which say what an inode is; the remaining
/// bits are the permission and `setuid`/`setgid`/sticky bits.
const MODE_TYPE_MASK: u16 = 0o170000;

/// An input the model cannot represent.
///
/// A path in a message renders through [`String::from_utf8_lossy`]: an ext4 path is a
/// byte string, which need not be UTF-8, and a message naming the offending path is
/// worth more than one that refuses to guess at a byte. An unrepresentable byte becomes
/// U+FFFD, so the rendering is lossy and the path is still recognizable.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A path resolved to the root where a name was required — a hard link cannot
    /// target the root directory.
    #[error("path is empty or names the root, where a name is required")]
    EmptyPath,
    /// An entry naming the root is not a directory. The root is a directory, so an
    /// entry that would place anything else there is rejected rather than applying its
    /// metadata to a directory it does not describe.
    #[error("entry {} names the root but is not a directory", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    RootNotDirectory {
        /// The offending path.
        path: Vec<u8>,
    },
    /// The configured first user inode names an inode the filesystem reserves, so the
    /// entries would overwrite the root, `/lost+found`, or another reserved inode.
    #[error("the first user inode {given} is below {floor}, the first non-reserved inode")]
    #[non_exhaustive]
    FirstUserInodeReserved {
        /// The configured value.
        given: u32,
        /// The lowest inode a user entry may take.
        floor: u32,
    },
    /// A path component was empty, `.`, `..`, or longer than 255 bytes.
    #[error(
        "path {} has an invalid component {}",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.component)
    )]
    #[non_exhaustive]
    InvalidComponent {
        /// The offending path.
        path: Vec<u8>,
        /// The offending component.
        component: Vec<u8>,
    },
    /// Two entries resolve to the same path. This is a hard error: an input naming one
    /// path twice is rejected rather than resolved by keeping the last entry, so the
    /// filesystem an ambiguous source would produce is never guessed at.
    #[error("path {} is used by more than one entry", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    Duplicate {
        /// The duplicated path.
        path: Vec<u8>,
    },
    /// An entry's parent directory was not declared.
    #[error("path {} has no parent directory", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    ParentMissing {
        /// The path whose parent is absent.
        path: Vec<u8>,
    },
    /// An entry's parent path exists but is not a directory.
    #[error("path {} has a parent that is not a directory", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    ParentNotDir {
        /// The path whose parent is not a directory.
        path: Vec<u8>,
    },
    /// An entry uses a path the filesystem reserves (such as `/lost+found`).
    #[error("path {} is reserved", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    ReservedPath {
        /// The reserved path.
        path: Vec<u8>,
    },
    /// A hard link's target does not exist.
    #[error(
        "hard link {} targets {}, which does not exist",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.target)
    )]
    #[non_exhaustive]
    HardlinkTargetMissing {
        /// The link's path.
        path: Vec<u8>,
        /// The missing target.
        target: Vec<u8>,
    },
    /// A hard link's target is a directory. Every other file type may carry more than
    /// one name; a directory may not, since a second name would make the tree a cycle.
    #[error(
        "hard link {} targets {}, which is a directory",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.target)
    )]
    #[non_exhaustive]
    HardlinkTargetIsDirectory {
        /// The link's path.
        path: Vec<u8>,
        /// The directory target.
        target: Vec<u8>,
    },
    /// A chain of hard links closes on itself, so it names no inode.
    #[error(
        "hard link {} targets {} through a cycle of links",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.target)
    )]
    #[non_exhaustive]
    HardlinkCycle {
        /// The link's path.
        path: Vec<u8>,
        /// The target the chain began with.
        target: Vec<u8>,
    },
    /// A hard link would push its target's link count past what ext4 records.
    #[error(
        "hard link {} targets {}, which already holds the maximum links",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.target)
    )]
    #[non_exhaustive]
    TooManyLinks {
        /// The link's path.
        path: Vec<u8>,
        /// The target at its link limit.
        target: Vec<u8>,
    },
    /// A symlink target is longer than a single block.
    #[error(
        "symlink {} has a target of {len} bytes, more than a block holds",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    SymlinkTargetTooLong {
        /// The symlink's path.
        path: Vec<u8>,
        /// The target length.
        len: usize,
    },
    /// A symlink has an empty target, which points nowhere.
    #[error("symlink {} has an empty target", String::from_utf8_lossy(.path))]
    #[non_exhaustive]
    EmptySymlinkTarget {
        /// The symlink's path.
        path: Vec<u8>,
    },
    /// A symlink target contains an embedded NUL, which the kernel reads as its end.
    #[error(
        "symlink {} has a target containing an embedded NUL",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    SymlinkTargetHasNul {
        /// The symlink's path.
        path: Vec<u8>,
    },
    /// A directory holds more subdirectories than a link count can track without the
    /// `dir_nlink` feature, which the emitted feature set does not carry.
    #[error(
        "directory {} has {subdirs} subdirectories, past the {limit} a link count holds \
         without the dir_nlink feature",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    DirectoryLinkCountOverflow {
        /// The directory's path.
        path: Vec<u8>,
        /// The subdirectory count that overran the limit.
        subdirs: u64,
        /// The most subdirectories representable without `dir_nlink`.
        limit: u16,
    },
    /// A device node's major or minor number exceeds what the on-disk form holds.
    #[error(
        "device {} has out-of-range numbers {major}:{minor}",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    DeviceNumberTooLarge {
        /// The device node's path.
        path: Vec<u8>,
        /// The requested major number.
        major: u32,
        /// The requested minor number.
        minor: u32,
    },
    /// An extended attribute's stored name is longer than 255 bytes.
    #[error(
        "entry {} has an extended attribute name longer than 255 bytes",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    XattrNameTooLong {
        /// The entry's path.
        path: Vec<u8>,
    },
    /// An extended attribute name the on-disk format cannot store as a distinct,
    /// addressable entry: empty (which an index-0 entry turns into the end-of-list
    /// terminator, hiding every attribute after it), carrying an embedded NUL (which the
    /// syscall boundary reads as the name's end), or duplicated within one entry's set
    /// (a state `ext4_xattr_set` cannot produce). It is rejected rather than written
    /// into a set the kernel, `e2fsck`, and this crate's own reader would each misread.
    #[error(
        "entry {} has an invalid extended attribute name ({reason}): {}",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.name)
    )]
    #[non_exhaustive]
    InvalidXattrName {
        /// The entry's path.
        path: Vec<u8>,
        /// The offending attribute name.
        name: Vec<u8>,
        /// Why it cannot be stored: `empty`, `embedded NUL`, or `duplicate`.
        reason: &'static str,
    },
    /// An entry's extended attributes overflow the storage an inode commands: after
    /// filling the inode's inline region, the spilled remainder does not fit the one
    /// xattr block an inode can charge.
    #[error(
        "entry {} has extended attributes spilling {needed} bytes past the inode, more than a block holds",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    XattrsTooLarge {
        /// The entry's path.
        path: Vec<u8>,
        /// Bytes the spilled attributes need in the block.
        needed: usize,
    },
    /// An entry carries extended attributes on a feature set without `ext_attr`, which is
    /// the feature that says a filesystem holds any. Writing them regardless would leave
    /// inodes pointing at an attribute block the feature words deny, which `e2fsck`
    /// faults; dropping them would lose data the source supplied. Neither is done: the
    /// conflict between the attributes and the profile is stated instead.
    #[error(
        "entry {} carries extended attributes, which the feature set cannot hold without \
         ext_attr",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    XattrsWithoutFeature {
        /// The entry's path.
        path: Vec<u8>,
    },
    /// A regular file reaches [`LARGE_FILE_MIN_SIZE`] on a feature set without
    /// `large_file`, the feature that describes a file that large. The kernel sets the
    /// feature when it writes such a file and `e2fsck` faults an image carrying one
    /// without it, so the file is refused rather than written into a filesystem whose
    /// feature words deny it.
    #[error(
        "file {} is {size} bytes, past the {limit} a regular file may reach without the \
         large_file feature",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    FileTooLargeWithoutFeature {
        /// The file's path.
        path: Vec<u8>,
        /// The file's size in bytes.
        size: u64,
        /// The size a regular file must stay under without the feature.
        limit: u64,
    },
    /// An entry carries a timestamp the on-disk format cannot represent: its seconds
    /// lie outside the range an ext4 inode holds, or its nanoseconds are not a valid
    /// sub-second fraction. It is rejected rather than silently wrapped to a different
    /// instant.
    #[error(
        "entry {} has a timestamp of {secs}s + {nanos}ns outside the representable range",
        String::from_utf8_lossy(.path)
    )]
    #[non_exhaustive]
    TimestampOutOfRange {
        /// The entry's path.
        path: Vec<u8>,
        /// The out-of-range seconds value.
        secs: i64,
        /// The nanosecond fraction.
        nanos: u32,
    },
}

/// One entry inside a directory: a name pointing at an inode.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct DirChild {
    /// Entry name.
    pub name: Vec<u8>,
    /// Inode the name points at.
    pub inode: u32,
    /// File type of the named inode.
    pub file_type: FileType,
}

/// What an inode holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Content {
    /// A directory's ordered entries, beginning with `.` and `..`.
    Directory(Vec<DirChild>),
    /// A regular file's contents, in memory or still on the host.
    File(FileContent),
    /// A symlink whose target is stored inline in the inode block area.
    FastSymlink(Vec<u8>),
    /// A symlink whose target is stored in a data block.
    SlowSymlink(Vec<u8>),
    /// A device node; whether it is character- or block-special is carried in the
    /// mode, and the major/minor pair is stored in the inode's block area.
    Device {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// A FIFO or socket: no data and no device number, its type carried in the mode.
    Special,
}

/// A modeled inode: its metadata and its contents, ready for the materializer to
/// place and write.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ModelInode {
    /// Inode number.
    pub number: u32,
    /// Full mode, including the `S_IF*` type bits.
    pub mode: u16,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Link count.
    pub links_count: u16,
    /// Access time.
    pub atime: Timestamp,
    /// Change (status) time.
    pub ctime: Timestamp,
    /// Modification time.
    pub mtime: Timestamp,
    /// Creation time (derived from the modification time; no source records a birth
    /// time).
    pub crtime: Timestamp,
    /// Extended attributes attached to this inode.
    pub xattrs: Vec<Xattr>,
    /// The inode's contents.
    pub content: Content,
}

impl ModelInode {
    /// Whether this inode is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.content, Content::Directory(_))
    }

    /// The file type a directory entry naming this inode records. It follows from the
    /// content, with the mode's type bits distinguishing the two kinds of device node
    /// and a FIFO from a socket.
    fn file_type(&self) -> FileType {
        match self.content {
            Content::Directory(_) => FileType::Dir,
            Content::File(_) => FileType::RegFile,
            Content::FastSymlink(_) | Content::SlowSymlink(_) => FileType::Symlink,
            Content::Device { .. } => match self.mode & MODE_TYPE_MASK {
                0o020000 => FileType::CharDev,
                _ => FileType::BlockDev,
            },
            Content::Special => match self.mode & MODE_TYPE_MASK {
                0o140000 => FileType::Socket,
                _ => FileType::Fifo,
            },
        }
    }
}

/// The complete inode tree: every inode the source implies, plus the always-present
/// root and `/lost+found`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FsModel {
    /// Inodes by number. Numbers are contiguous from [`ROOT_INO`] through
    /// `first_free_inode - 1` once the materializer's reserved inodes fill the gaps.
    pub inodes: BTreeMap<u32, ModelInode>,
    /// The next unused inode number; `first_free_inode - 1` inodes are in use.
    pub first_free_inode: u32,
}

impl FsModel {
    /// Inodes in use: every number below [`first_free_inode`](Self::first_free_inode).
    #[must_use]
    pub fn used_inode_count(&self) -> u32 {
        self.first_free_inode - 1
    }

    /// The root directory inode.
    #[must_use]
    pub fn root(&self) -> &ModelInode {
        &self.inodes[&ROOT_INO]
    }
}

/// Inputs the model needs beyond the source: the block size (which bounds a slow
/// symlink target), the inode size (which fixes the inline extended-attribute
/// region), the default time for the always-present directories, the inode number the
/// source's entries start at, and the feature answers that decide which entries the
/// filesystem can hold at all.
///
/// Build one with [`new`](Self::new), which derives every feature-driven field from one
/// [`FeatureSet`] so they cannot disagree with the image the writer goes on to emit, then
/// set [`fixed_time`](Self::fixed_time) if the format clamps timestamps.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ModelConfig {
    /// Block size in bytes.
    pub block_size: u32,
    /// Inode size in bytes, which fixes the inline extended-attribute region an
    /// entry's attributes may occupy before spilling to a block.
    pub inode_size: u16,
    /// The inode number the first source entry takes. It is [`FIRST_USER_INO`] unless
    /// the feature set claims inodes of its own at format time — the orphan file takes
    /// inode 12 — in which case the entries begin above them. It may not name a
    /// reserved inode.
    pub first_user_inode: u32,
    /// Time recorded on the root and `/lost+found` directories, and the fallback for
    /// any entry when `fixed_time` is set.
    pub default_time: Timestamp,
    /// When set, every inode's four timestamps are forced to this value, overriding
    /// the per-entry times. Makes output byte-reproducible regardless of the
    /// source's timestamps.
    pub fixed_time: Option<Timestamp>,
    /// Whether the feature set permits a directory link count past 65 000
    /// (`dir_nlink`). When it does, an over-limit directory stores the sentinel `1`;
    /// when it does not, such a directory is rejected rather than given a sentinel no
    /// feature backs.
    pub dir_nlink: bool,
    /// Whether the feature set permits extended attributes (`ext_attr`). When it does not,
    /// an entry carrying any is rejected rather than written into a filesystem whose
    /// feature words say it holds none.
    pub ext_attr: bool,
    /// Whether the feature set permits a regular file of [`LARGE_FILE_MIN_SIZE`] or more
    /// (`large_file`). When it does not, a file that large is rejected rather than written
    /// into a filesystem whose feature words say it holds no such file.
    pub large_file: bool,
}

/// The four inode timestamps.
#[derive(Clone, Copy, Debug)]
struct Times {
    atime: Timestamp,
    ctime: Timestamp,
    mtime: Timestamp,
    crtime: Timestamp,
}

impl Times {
    /// Reject any of the four times the on-disk format cannot represent, naming `path`
    /// in the error. Checked once per entry, before the times reach an inode.
    fn validate(&self, path: &[u8]) -> Result<(), ModelError> {
        for t in [self.atime, self.ctime, self.mtime, self.crtime] {
            if !t.is_representable() {
                return Err(ModelError::TimestampOutOfRange {
                    path: path.to_vec(),
                    secs: t.secs,
                    nanos: t.nanos,
                });
            }
        }
        Ok(())
    }
}

impl ModelConfig {
    /// The configuration a `feature` set implies, for a source whose entries start at
    /// `first_user_inode` and whose always-present directories take `default_time`.
    ///
    /// Five of the fields — the block and inode sizes, and the three feature answers —
    /// are properties of the feature set alone, so they are read from it here rather than
    /// supplied one by one. Wiring them by hand is how a model comes to judge a source
    /// against a filesystem the writer is not about to emit: a `dir_nlink` answer that
    /// says yes to a set without the feature, or an `ext_attr` answer that says yes to one
    /// that cannot hold an attribute. There is one derivation, and this is it.
    ///
    /// [`fixed_time`](Self::fixed_time) starts unset — each entry keeps its own times —
    /// and is set afterward by a format that clamps them.
    #[must_use]
    pub fn new(feature: FeatureSet, first_user_inode: u32, default_time: Timestamp) -> Self {
        Self {
            block_size: feature.block_size,
            inode_size: feature.inode_size,
            first_user_inode,
            default_time,
            fixed_time: None,
            dir_nlink: feature.has_dir_nlink(),
            ext_attr: feature.has_ext_attr(),
            large_file: feature.has_large_file(),
        }
    }

    /// Resolve an entry's four timestamps: the fixed time on every field when set,
    /// otherwise the entry's access/change/modification times with the creation time
    /// derived from the modification time.
    fn times(&self, meta: &Metadata) -> Times {
        match self.fixed_time {
            Some(t) => Times {
                atime: t,
                ctime: t,
                mtime: t,
                crtime: t,
            },
            None => Times {
                atime: meta.atime,
                ctime: meta.ctime,
                mtime: meta.mtime,
                crtime: meta.mtime,
            },
        }
    }

    /// The timestamp for the always-present directories: the fixed time when set,
    /// otherwise the default.
    fn base_time(&self) -> Times {
        let t = self.fixed_time.unwrap_or(self.default_time);
        Times {
            atime: t,
            ctime: t,
            mtime: t,
            crtime: t,
        }
    }
}

/// Validate an entry's extended attributes: the feature set must say the filesystem holds
/// attributes at all; each name must be present, free of NUL, and unique within the set;
/// names must fit `e_name_len`; and the set must fit the storage an inode commands — its
/// inline region plus one xattr block, split exactly as the writer will split it. The name
/// rules mirror the non-empty/no-NUL/unique discipline the path components enforce, and
/// for the same reason — a name the on-disk format cannot represent as a distinct,
/// addressable entry is rejected rather than written into a set that would silently lose
/// attributes.
fn validate_xattrs(path: &[u8], xattrs: &[Xattr], config: &ModelConfig) -> Result<(), ModelError> {
    if xattrs.is_empty() {
        return Ok(());
    }
    // `ext_attr` is what says a filesystem carries attributes: the inline region and the
    // external block both belong to it. A set on a profile without the feature is a
    // conflict between the input and the words the image would advertise, so it is named
    // before anything about the attributes themselves.
    if !config.ext_attr {
        return Err(ModelError::XattrsWithoutFeature {
            path: path.to_vec(),
        });
    }
    for (i, x) in xattrs.iter().enumerate() {
        let reason = if has_empty_name(&x.name) {
            // An empty name is the end-of-list terminator under index 0 and an
            // unaddressable entry under any other index.
            Some("empty")
        } else if x.name.contains(&0) {
            Some("embedded NUL")
        } else if xattrs[..i].iter().any(|y| y.name == x.name) {
            Some("duplicate")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(ModelError::InvalidXattrName {
                path: path.to_vec(),
                name: x.name.clone(),
                reason,
            });
        }
    }
    if longest_stored_name(xattrs) > 255 {
        return Err(ModelError::XattrNameTooLong {
            path: path.to_vec(),
        });
    }
    // The attributes that do not fit the inline region spill to the one block an
    // inode can charge; a spill the block cannot hold is the set's hard ceiling.
    let region_len = Inode::inline_xattr_capacity_for(config.inode_size);
    let (_, spilled) = split_for_storage(xattrs, region_len);
    let needed = xattr_block_len(&spilled);
    if !spilled.is_empty() && needed > config.block_size as usize {
        return Err(ModelError::XattrsTooLarge {
            path: path.to_vec(),
            needed,
        });
    }
    Ok(())
}

/// Reject a regular file the feature set cannot describe: one reaching
/// [`LARGE_FILE_MIN_SIZE`] without `large_file`. The bound is on regular files alone —
/// a directory of any size needs no such feature, which is also how `e2fsck` counts
/// them.
fn validate_file_size(path: &[u8], size: u64, config: &ModelConfig) -> Result<(), ModelError> {
    if size >= LARGE_FILE_MIN_SIZE && !config.large_file {
        return Err(ModelError::FileTooLargeWithoutFeature {
            path: path.to_vec(),
            size,
            limit: LARGE_FILE_MIN_SIZE,
        });
    }
    Ok(())
}

/// Whether a path names the filesystem root itself, having no component beyond
/// separators and no-op `.` elements — `/`, `.`, `./`, and the empty path all do. Such
/// an entry describes the root directory rather than something inside it.
fn names_the_root(path: &[u8]) -> bool {
    path.split(|&b| b == b'/')
        .all(|part| part.is_empty() || part == b".")
}

/// Split a path into its meaningful components. A `.` component is a no-op and
/// dropped; `..`, an over-long component, or one containing a NUL is rejected.
fn components(path: &[u8]) -> Result<Vec<Vec<u8>>, ModelError> {
    let mut out = Vec::new();
    for part in path.split(|&b| b == b'/') {
        if part.is_empty() || part == b"." {
            continue; // leading/trailing/repeated slash, or a no-op "." component
        }
        // A NUL cannot appear in a directory entry name, so a component carrying one is
        // rejected rather than written into a dirent the kernel would refuse.
        if part == b".." || part.len() > 255 || part.contains(&0) {
            return Err(ModelError::InvalidComponent {
                path: path.to_vec(),
                component: part.to_vec(),
            });
        }
        out.push(part.to_vec());
    }
    if out.is_empty() {
        return Err(ModelError::EmptyPath);
    }
    Ok(out)
}

/// Join components back into a canonical key for the path map.
fn key(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.join(&b'/')
}

/// One entry, normalized: its components and its parent/name split.
struct Normalized {
    parts: Vec<Vec<u8>>,
    entry: SourceEntry,
}

/// A directory in progress: its collected children and the parent it links back to.
struct DirBuild {
    parent: u32,
    children: Vec<DirChild>,
    /// The directory's path, kept for naming it in a finalization-time error.
    path: Vec<u8>,
}

/// Build the inode model from `source`.
///
/// An entry whose path names the root describes the root directory itself: its mode,
/// ownership, times, and extended attributes are applied to inode 2 rather than
/// creating an inode. At most one entry may name the root, and it must be a directory.
///
/// # Errors
///
/// A [`ModelError`] naming the offending path when an entry cannot be represented:
/// an invalid or duplicate path, a missing or non-directory parent, a reserved
/// path, an unresolvable or directory hard-link target, or an over-long symlink.
pub fn build_model(source: impl Source, config: ModelConfig) -> Result<FsModel, ModelError> {
    let mut inodes: BTreeMap<u32, ModelInode> = BTreeMap::new();
    let mut path_ino: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let mut dirs: BTreeMap<u32, DirBuild> = BTreeMap::new();

    if config.first_user_inode < FIRST_USER_INO {
        return Err(ModelError::FirstUserInodeReserved {
            given: config.first_user_inode,
            floor: FIRST_USER_INO,
        });
    }

    // The format-wide default and fixed times reach the always-present directories, so
    // an unrepresentable one is caught once here rather than per inode.
    config.base_time().validate(b"/")?;

    // Split the source: an entry naming the root describes inode 2, which already
    // exists, while every other entry creates one. The rest are processed in sorted
    // path order, so inode numbering is deterministic and parents precede their
    // children.
    let mut root_entry: Option<SourceEntry> = None;
    let mut normalized: Vec<Normalized> = Vec::new();
    for entry in source.into_entries() {
        if names_the_root(&entry.path) {
            if root_entry.is_some() {
                return Err(ModelError::Duplicate { path: entry.path });
            }
            if !matches!(entry.kind, EntryKind::Directory) {
                return Err(ModelError::RootNotDirectory { path: entry.path });
            }
            root_entry = Some(entry);
            continue;
        }
        let parts = components(&entry.path)?;
        normalized.push(Normalized { parts, entry });
    }
    normalized.sort_by_key(|a| key(&a.parts));

    // Root and lost+found always exist. The root takes the source's root entry when it
    // has one, and the standard 0755 root-owned directory otherwise.
    let root = match &root_entry {
        Some(entry) => {
            let times = config.times(&entry.meta);
            times.validate(&entry.path)?;
            validate_xattrs(&entry.path, &entry.xattrs, &config)?;
            let mut root = dir_inode(
                ROOT_INO,
                0o040000 | entry.meta.mode,
                times,
                entry.xattrs.clone(),
            );
            root.uid = entry.meta.uid;
            root.gid = entry.meta.gid;
            root
        }
        None => dir_inode(ROOT_INO, 0o040755, config.base_time(), Vec::new()),
    };
    inodes.insert(ROOT_INO, root);
    dirs.insert(
        ROOT_INO,
        DirBuild {
            parent: ROOT_INO,
            children: Vec::new(),
            path: b"/".to_vec(),
        },
    );
    path_ino.insert(Vec::new(), ROOT_INO);

    inodes.insert(
        LOST_FOUND_INO,
        dir_inode(LOST_FOUND_INO, 0o040700, config.base_time(), Vec::new()),
    );
    dirs.insert(
        LOST_FOUND_INO,
        DirBuild {
            parent: ROOT_INO,
            children: Vec::new(),
            path: b"/lost+found".to_vec(),
        },
    );
    path_ino.insert(b"lost+found".to_vec(), LOST_FOUND_INO);
    dirs.get_mut(&ROOT_INO)
        .expect("root was just inserted")
        .children
        .push(DirChild {
            name: b"lost+found".to_vec(),
            inode: LOST_FOUND_INO,
            file_type: FileType::Dir,
        });

    // Non-hard-link entries first: they create the inodes hard links later reference.
    let mut next_ino = config.first_user_inode;
    for n in &normalized {
        if matches!(n.entry.kind, EntryKind::HardLink { .. }) {
            continue;
        }
        let path_key = key(&n.parts);
        // `/lost+found` is the filesystem's own directory, so neither it nor anything
        // beneath it may come from the source.
        if n.parts.first().map(Vec::as_slice) == Some(b"lost+found".as_slice()) {
            return Err(ModelError::ReservedPath {
                path: n.entry.path.clone(),
            });
        }
        if path_ino.contains_key(&path_key) {
            return Err(ModelError::Duplicate {
                path: n.entry.path.clone(),
            });
        }
        let (parent_ino, name) = resolve_parent(&n.parts, &path_ino, &dirs, &n.entry.path)?;
        let ino = next_ino;
        next_ino += 1;
        let meta = &n.entry.meta;
        let times = config.times(meta);
        times.validate(&n.entry.path)?;
        validate_xattrs(&n.entry.path, &n.entry.xattrs, &config)?;
        let xattrs = n.entry.xattrs.clone();
        // Every kind but a directory shares this leaf construction; a directory's
        // content and link count are filled in during finalization.
        let leaf = |mode: u16, content: Content| ModelInode {
            number: ino,
            mode,
            uid: meta.uid,
            gid: meta.gid,
            links_count: 1,
            atime: times.atime,
            ctime: times.ctime,
            mtime: times.mtime,
            crtime: times.crtime,
            xattrs: xattrs.clone(),
            content,
        };
        match &n.entry.kind {
            EntryKind::Directory => {
                let mut dir = dir_inode(ino, 0o040000 | meta.mode, times, xattrs.clone());
                dir.uid = meta.uid;
                dir.gid = meta.gid;
                inodes.insert(ino, dir);
                dirs.insert(
                    ino,
                    DirBuild {
                        parent: parent_ino,
                        children: Vec::new(),
                        path: n.entry.path.clone(),
                    },
                );
            }
            EntryKind::File(content) => {
                // The length is known without reading, so a file the feature set cannot
                // describe is refused here — naming its path — whether its bytes are in
                // memory or still on the host.
                validate_file_size(&n.entry.path, content.len(), &config)?;
                inodes.insert(
                    ino,
                    leaf(0o100000 | meta.mode, Content::File(content.clone())),
                );
            }
            EntryKind::Symlink(target) => {
                if target.is_empty() {
                    return Err(ModelError::EmptySymlinkTarget {
                        path: n.entry.path.clone(),
                    });
                }
                // The kernel reads a symlink target as a C string, stopping at the first
                // NUL. A target with an embedded NUL is rejected rather than stored to be
                // silently truncated on read — the same guard a directory component gets.
                if target.contains(&0) {
                    return Err(ModelError::SymlinkTargetHasNul {
                        path: n.entry.path.clone(),
                    });
                }
                // A slow symlink stores its target in a data block that must hold a
                // terminating NUL within the block, so the longest representable target
                // is one byte short of a block. A target of exactly `block_size` bytes
                // would fill the block with no room for the NUL and e2fsck faults it.
                if target.len() >= config.block_size as usize {
                    return Err(ModelError::SymlinkTargetTooLong {
                        path: n.entry.path.clone(),
                        len: target.len(),
                    });
                }
                let content = if target.len() < FAST_SYMLINK_MAX {
                    Content::FastSymlink(target.clone())
                } else {
                    Content::SlowSymlink(target.clone())
                };
                inodes.insert(ino, leaf(0o120777, content));
            }
            EntryKind::CharDevice { major, minor } => {
                check_device(&n.entry.path, *major, *minor)?;
                let content = Content::Device {
                    major: *major,
                    minor: *minor,
                };
                inodes.insert(ino, leaf(0o020000 | meta.mode, content));
            }
            EntryKind::BlockDevice { major, minor } => {
                check_device(&n.entry.path, *major, *minor)?;
                let content = Content::Device {
                    major: *major,
                    minor: *minor,
                };
                inodes.insert(ino, leaf(0o060000 | meta.mode, content));
            }
            EntryKind::Fifo => {
                inodes.insert(ino, leaf(0o010000 | meta.mode, Content::Special));
            }
            EntryKind::Socket => {
                inodes.insert(ino, leaf(0o140000 | meta.mode, Content::Special));
            }
            EntryKind::HardLink { .. } => unreachable!("hard links handled in the second pass"),
        }
        let file_type = inodes[&ino].file_type();
        path_ino.insert(path_key, ino);
        dirs.get_mut(&parent_ino)
            .expect("parent verified to be a directory")
            .children
            .push(DirChild {
                name,
                inode: ino,
                file_type,
            });
    }

    // Hard links: each is another name for an inode the first pass created. Collect
    // them all before resolving any, so a link that targets another link resolves
    // whichever order the two names sort in.
    let mut links: BTreeMap<Vec<u8>, &Normalized> = BTreeMap::new();
    for n in &normalized {
        if !matches!(n.entry.kind, EntryKind::HardLink { .. }) {
            continue;
        }
        let path_key = key(&n.parts);
        if path_ino.contains_key(&path_key) || links.contains_key(&path_key) {
            return Err(ModelError::Duplicate {
                path: n.entry.path.clone(),
            });
        }
        links.insert(path_key, n);
    }
    for (path_key, n) in &links {
        let EntryKind::HardLink { target } = &n.entry.kind else {
            unreachable!("only hard links were collected");
        };
        let target_ino = resolve_link(&n.entry.path, target, &path_ino, &links)?;
        // Every file type but a directory may carry more than one name. A second name
        // for a directory would turn the tree into a cycle, which no kernel permits.
        if inodes[&target_ino].is_dir() {
            return Err(ModelError::HardlinkTargetIsDirectory {
                path: n.entry.path.clone(),
                target: target.clone(),
            });
        }
        let (parent_ino, name) = resolve_parent(&n.parts, &path_ino, &dirs, &n.entry.path)?;
        let target_inode = inodes
            .get_mut(&target_ino)
            .expect("hard-link target verified to exist");
        // An inode's link count is the number of names pointing at it, so it cannot be
        // capped without contradicting the directory entries. Past ext4's limit the
        // link is refused rather than overflowing the 16-bit field.
        if target_inode.links_count >= EXT4_LINK_MAX {
            return Err(ModelError::TooManyLinks {
                path: n.entry.path.clone(),
                target: target.clone(),
            });
        }
        target_inode.links_count += 1;
        let file_type = target_inode.file_type();
        path_ino.insert(path_key.clone(), target_ino);
        dirs.get_mut(&parent_ino)
            .expect("parent verified to be a directory")
            .children
            .push(DirChild {
                name,
                inode: target_ino,
                file_type,
            });
    }

    // Finalize directories: link counts (2 + subdirectories) and the entry list with
    // `.` and `..` ahead of the name-sorted children.
    for (ino, build) in dirs {
        let subdirs = build
            .children
            .iter()
            .filter(|c| c.file_type == FileType::Dir)
            .count();
        let mut children = build.children;
        children.sort_by(|a, b| a.name.cmp(&b.name));
        let mut entries = Vec::with_capacity(children.len() + 2);
        entries.push(DirChild {
            name: b".".to_vec(),
            inode: ino,
            file_type: FileType::Dir,
        });
        entries.push(DirChild {
            name: b"..".to_vec(),
            inode: build.parent,
            file_type: FileType::Dir,
        });
        entries.extend(children);
        // A directory links `.`, its own name in its parent, and each subdirectory's
        // `..`. Past ext4's link limit the count is not tracked and stored as the
        // `dir_nlink` sentinel `1`, exactly as the kernel does, without wrapping the
        // 16-bit field. That sentinel means nothing without the `dir_nlink` feature to
        // back it, and without the feature the kernel cannot even reach this many
        // subdirectories, so an over-limit directory is rejected rather than given a
        // sentinel `e2fsck` would flag as inconsistent.
        let links = 2 + subdirs as u64;
        let links_count = if links > u64::from(EXT4_LINK_MAX) {
            if !config.dir_nlink {
                return Err(ModelError::DirectoryLinkCountOverflow {
                    path: build.path.clone(),
                    subdirs: subdirs as u64,
                    limit: EXT4_LINK_MAX,
                });
            }
            1
        } else {
            links as u16
        };
        let inode = inodes
            .get_mut(&ino)
            .expect("inode inserted for this directory");
        inode.links_count = links_count;
        inode.content = Content::Directory(entries);
    }

    Ok(FsModel {
        inodes,
        first_free_inode: next_ino,
    })
}

/// A directory inode with an empty entry list, filled in during finalization.
fn dir_inode(number: u32, mode: u16, times: Times, xattrs: Vec<Xattr>) -> ModelInode {
    ModelInode {
        number,
        mode,
        uid: 0,
        gid: 0,
        links_count: 2,
        atime: times.atime,
        ctime: times.ctime,
        mtime: times.mtime,
        crtime: times.crtime,
        xattrs,
        content: Content::Directory(Vec::new()),
    }
}

/// Reject a device node whose major or minor number the on-disk form cannot hold.
fn check_device(path: &[u8], major: u32, minor: u32) -> Result<(), ModelError> {
    if major > MAX_DEVICE_MAJOR || minor > MAX_DEVICE_MINOR {
        return Err(ModelError::DeviceNumberTooLarge {
            path: path.to_vec(),
            major,
            minor,
        });
    }
    Ok(())
}

/// Resolve the inode a hard link ultimately names, following any chain of links along
/// the way: a link may target another link, whose target may itself be a link, and the
/// chain ends at the one entry that created an inode.
///
/// `links` holds every hard link in the source, so resolution does not depend on the
/// order the names sort in. A chain that closes on itself names no inode and is
/// rejected; the hop count bounds the walk at the number of links, past which a
/// revisit — and so a cycle — is certain.
fn resolve_link(
    path: &[u8],
    target: &[u8],
    path_ino: &BTreeMap<Vec<u8>, u32>,
    links: &BTreeMap<Vec<u8>, &Normalized>,
) -> Result<u32, ModelError> {
    let mut hop = key(&components(target)?);
    for _ in 0..=links.len() {
        if let Some(&ino) = path_ino.get(&hop) {
            return Ok(ino);
        }
        let next = links
            .get(&hop)
            .ok_or_else(|| ModelError::HardlinkTargetMissing {
                path: path.to_vec(),
                target: target.to_vec(),
            })?;
        let EntryKind::HardLink { target: onward } = &next.entry.kind else {
            unreachable!("only hard links were collected");
        };
        hop = key(&components(onward)?);
    }
    Err(ModelError::HardlinkCycle {
        path: path.to_vec(),
        target: target.to_vec(),
    })
}

/// Resolve an entry's parent inode and its own name, checking the parent exists and
/// is a directory.
fn resolve_parent(
    parts: &[Vec<u8>],
    path_ino: &BTreeMap<Vec<u8>, u32>,
    dirs: &BTreeMap<u32, DirBuild>,
    path: &[u8],
) -> Result<(u32, Vec<u8>), ModelError> {
    let (name, parent_parts) = parts
        .split_last()
        .expect("components() rejects empty paths");
    let parent_ino =
        *path_ino
            .get(&key(parent_parts))
            .ok_or_else(|| ModelError::ParentMissing {
                path: path.to_vec(),
            })?;
    if !dirs.contains_key(&parent_ino) {
        return Err(ModelError::ParentNotDir {
            path: path.to_vec(),
        });
    }
    Ok((parent_ino, name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Metadata, TreeBuilder};

    fn config() -> ModelConfig {
        // The default feature set carries `dir_nlink`, `ext_attr`, and `large_file`, so
        // the derived configuration says yes to all three; a test that needs one of them
        // off overrides that field.
        let cfg = ModelConfig::new(
            FeatureSet::DEFAULT,
            FIRST_USER_INO,
            Timestamp::from_secs(1_700_000_000),
        );
        assert!(cfg.dir_nlink && cfg.ext_attr && cfg.large_file);
        assert_eq!((cfg.block_size, cfg.inode_size), (4096, 256));
        cfg
    }

    fn meta(mode: u16) -> Metadata {
        Metadata::new(mode, Timestamp::from_secs(1_700_000_000))
    }

    fn model(src: TreeBuilder) -> FsModel {
        build_model(src, config()).expect("model")
    }

    #[test]
    fn empty_source_has_root_and_lost_found() {
        let m = model(TreeBuilder::new());
        assert_eq!(m.inodes.len(), 2);
        assert_eq!(m.first_free_inode, FIRST_USER_INO);
        // Root: mode 040755, links 3 (., its entry, and lost+found's ..).
        let root = m.root();
        assert_eq!(root.mode, 0o040755);
        assert_eq!(root.links_count, 3);
        // lost+found: mode 040700, links 2.
        let lf = &m.inodes[&LOST_FOUND_INO];
        assert_eq!(lf.mode, 0o040700);
        assert_eq!(lf.links_count, 2);
    }

    #[test]
    fn an_unrepresentable_entry_timestamp_is_rejected() {
        // A file mtime the on-disk format cannot hold is a typed error, not a silent
        // wrap to a different instant.
        let mut m = Metadata::new(0o644, Timestamp::from_secs(1_700_000_000));
        m.mtime = Timestamp::from_secs(Timestamp::EPOCH_MAX + 1);
        let src = TreeBuilder::new().file(b"/f".to_vec(), b"x".to_vec(), m);
        let err = build_model(src, config()).unwrap_err();
        assert!(
            matches!(err, ModelError::TimestampOutOfRange { secs, .. } if secs == Timestamp::EPOCH_MAX + 1),
            "expected TimestampOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn an_unrepresentable_default_time_is_rejected() {
        // The format-wide default time reaches the always-present directories, so an
        // unrepresentable one fails the build up front.
        let cfg = ModelConfig {
            default_time: Timestamp::from_secs(Timestamp::EPOCH_MIN - 1),
            ..config()
        };
        let err = build_model(TreeBuilder::new(), cfg).unwrap_err();
        assert!(matches!(err, ModelError::TimestampOutOfRange { .. }));
    }

    #[test]
    fn root_entries_begin_with_dot_and_dotdot() {
        let m = model(TreeBuilder::new());
        let Content::Directory(children) = &m.root().content else {
            panic!("root is a directory");
        };
        assert_eq!(children[0].name, b".");
        assert_eq!(children[0].inode, ROOT_INO);
        assert_eq!(children[1].name, b"..");
        assert_eq!(children[1].inode, ROOT_INO, "root's .. points at itself");
        assert_eq!(children[2].name, b"lost+found");
    }

    #[test]
    fn inode_numbers_are_deterministic_in_sorted_path_order() {
        // Added out of order; numbering follows sorted paths, not addition order.
        let m = model(
            TreeBuilder::new()
                .directory(b"/b".to_vec(), meta(0o755))
                .directory(b"/a".to_vec(), meta(0o755))
                .file(b"/a/z".to_vec(), b"z".to_vec(), meta(0o644))
                .file(b"/a/y".to_vec(), b"y".to_vec(), meta(0o644)),
        );
        // Sorted: /a (12), /a/y (13), /a/z (14), /b (15).
        assert_eq!(*m.inodes.keys().max().unwrap(), 15);
        let a = m.inodes.values().find(|i| i.number == 12).unwrap();
        assert!(a.is_dir());
    }

    #[test]
    fn subdirectories_raise_the_parent_link_count() {
        let m = model(
            TreeBuilder::new()
                .directory(b"/a".to_vec(), meta(0o755))
                .directory(b"/a/sub1".to_vec(), meta(0o755))
                .directory(b"/a/sub2".to_vec(), meta(0o755)),
        );
        let a = m.inodes.values().find(|i| matches!(&i.content, Content::Directory(c) if c.iter().any(|e| e.name == b"sub1"))).unwrap();
        // /a: 2 + two subdirectories = 4.
        assert_eq!(a.links_count, 4);
        // Root gained /a as a subdirectory: 2 + lost+found + a = 4.
        assert_eq!(m.root().links_count, 4);
    }

    #[test]
    fn hardlinks_coalesce_onto_one_inode() {
        let m = model(
            TreeBuilder::new()
                .file(b"/a".to_vec(), b"data".to_vec(), meta(0o644))
                .hardlink(b"/b".to_vec(), b"/a".to_vec(), meta(0o644)),
        );
        // Only one file inode exists; it has link count 2.
        let files: Vec<_> = m
            .inodes
            .values()
            .filter(|i| matches!(i.content, Content::File(_)))
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].links_count, 2);
        // Both names point at the same inode.
        let Content::Directory(root) = &m.root().content else {
            unreachable!()
        };
        let a = root.iter().find(|e| e.name == b"a").unwrap().inode;
        let b = root.iter().find(|e| e.name == b"b").unwrap().inode;
        assert_eq!(a, b);
    }

    #[test]
    fn symlink_form_follows_target_length() {
        let short = vec![b'x'; 59];
        let long = vec![b'x'; 60];
        let m = model(
            TreeBuilder::new()
                .symlink(b"/short".to_vec(), short.clone(), meta(0o777))
                .symlink(b"/long".to_vec(), long.clone(), meta(0o777)),
        );
        let s = m
            .inodes
            .values()
            .find(|i| matches!(&i.content, Content::FastSymlink(t) if *t == short));
        let l = m
            .inodes
            .values()
            .find(|i| matches!(&i.content, Content::SlowSymlink(t) if *t == long));
        assert!(s.is_some(), "59-byte target is a fast symlink");
        assert!(l.is_some(), "60-byte target is a slow symlink");
        assert_eq!(s.unwrap().mode, 0o120777);
    }

    #[test]
    fn a_symlink_target_with_an_embedded_nul_is_rejected() {
        // The kernel reads a symlink target as a C string and stops at the first NUL, so
        // an interior NUL would silently truncate the target on read. It is a typed error
        // at model time, the same guard a directory-entry name gets.
        let err = build_model(
            TreeBuilder::new().symlink(b"/link".to_vec(), b"a\0b".to_vec(), meta(0o777)),
            config(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ModelError::SymlinkTargetHasNul { .. }),
            "an embedded NUL must be a typed error, got {err:?}"
        );
    }

    #[test]
    fn a_directory_past_the_link_limit_requires_dir_nlink() {
        // A directory's link count is 2 (`.` and its name in the parent) plus one per
        // subdirectory (its `..`). 64_999 subdirectories reach 65_001, one past
        // EXT4_LINK_MAX, where ext4 stores the `dir_nlink` sentinel `1` — but that sentinel
        // means nothing without the feature, and the kernel could not have created this
        // many subdirectories without it either.
        let build = || {
            let mut b = TreeBuilder::new().directory(b"/d".to_vec(), meta(0o755));
            for i in 0..64_999u32 {
                b = b.directory(format!("/d/{i:05}").into_bytes(), meta(0o755));
            }
            b
        };

        // Without dir_nlink the over-limit directory is refused rather than given a
        // sentinel `e2fsck` would flag as inconsistent.
        let cfg_off = ModelConfig {
            dir_nlink: false,
            ..config()
        };
        let err = build_model(build(), cfg_off).unwrap_err();
        assert!(
            matches!(
                err,
                ModelError::DirectoryLinkCountOverflow { subdirs, limit, .. }
                    if subdirs == 64_999 && limit == 65_000
            ),
            "without dir_nlink the overflow must be a typed error, got {err:?}"
        );

        // With dir_nlink it stores the sentinel `1`, as the kernel does.
        let m = build_model(build(), config()).expect("dir_nlink permits the overflow");
        let d = m
            .inodes
            .values()
            .find(|i| matches!(&i.content, Content::Directory(e) if e.len() > 65_000))
            .expect("the large directory is present");
        assert_eq!(d.links_count, 1, "the dir_nlink sentinel");
    }

    #[test]
    fn ownership_and_mode_are_preserved() {
        let m = model(TreeBuilder::new().file(
            b"/f".to_vec(),
            b"x".to_vec(),
            meta(0o4755).owned_by(1000, 2000),
        ));
        let f = m
            .inodes
            .values()
            .find(|i| matches!(i.content, Content::File(_)))
            .unwrap();
        assert_eq!(f.mode, 0o104755, "setuid bit and perms preserved");
        assert_eq!(f.uid, 1000);
        assert_eq!(f.gid, 2000);
    }

    #[test]
    fn missing_parent_is_rejected() {
        let err = build_model(
            TreeBuilder::new().file(b"/nodir/f".to_vec(), b"x".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::ParentMissing { .. }));
    }

    #[test]
    fn parent_that_is_a_file_is_rejected() {
        let err = build_model(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"x".to_vec(), meta(0o644))
                .file(b"/f/child".to_vec(), b"y".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::ParentNotDir { .. }));
    }

    #[test]
    fn reserved_and_duplicate_and_dotdot_paths_are_rejected() {
        assert!(matches!(
            build_model(
                TreeBuilder::new().directory(b"/lost+found".to_vec(), meta(0o700)),
                config()
            ),
            Err(ModelError::ReservedPath { .. })
        ));
        assert!(matches!(
            build_model(
                TreeBuilder::new()
                    .file(b"/a".to_vec(), b"1".to_vec(), meta(0o644))
                    .file(b"/a".to_vec(), b"2".to_vec(), meta(0o644)),
                config()
            ),
            Err(ModelError::Duplicate { .. })
        ));
        assert!(matches!(
            build_model(
                TreeBuilder::new().file(b"/a/../b".to_vec(), b"x".to_vec(), meta(0o644)),
                config()
            ),
            Err(ModelError::InvalidComponent { .. })
        ));
    }

    #[test]
    fn hardlink_to_a_directory_is_rejected() {
        let err = build_model(
            TreeBuilder::new()
                .directory(b"/d".to_vec(), meta(0o755))
                .hardlink(b"/l".to_vec(), b"/d".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::HardlinkTargetIsDirectory { .. }));
    }

    #[test]
    fn hardlink_resolves_regardless_of_order() {
        // The link sorts before its target; the two-pass build still resolves it.
        let m = model(
            TreeBuilder::new()
                .hardlink(b"/aaa".to_vec(), b"/zzz".to_vec(), meta(0o644))
                .file(b"/zzz".to_vec(), b"data".to_vec(), meta(0o644)),
        );
        let files: Vec<_> = m
            .inodes
            .values()
            .filter(|i| matches!(i.content, Content::File(_)))
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].links_count, 2);
    }

    #[test]
    fn a_hardlink_names_any_kind_but_a_directory() {
        // Every file type but a directory may carry a second name, and the directory
        // entry records the type of the inode it points at, not a regular file.
        let m = model(
            TreeBuilder::new()
                .symlink(b"/sym".to_vec(), b"/target".to_vec(), meta(0o777))
                .hardlink(b"/sym-link".to_vec(), b"/sym".to_vec(), meta(0o777))
                .char_device(b"/null".to_vec(), 1, 3, meta(0o666))
                .hardlink(b"/null-link".to_vec(), b"/null".to_vec(), meta(0o666))
                .fifo(b"/pipe".to_vec(), meta(0o644))
                .hardlink(b"/pipe-link".to_vec(), b"/pipe".to_vec(), meta(0o644)),
        );
        let Content::Directory(root) = &m.root().content else {
            unreachable!()
        };
        let child = |name: &[u8]| root.iter().find(|e| e.name == name).expect("entry");
        for (link, target, file_type) in [
            (&b"/sym-link"[..], &b"/sym"[..], FileType::Symlink),
            (b"/null-link", b"/null", FileType::CharDev),
            (b"/pipe-link", b"/pipe", FileType::Fifo),
        ] {
            let link = child(&link[1..]);
            let target = child(&target[1..]);
            assert_eq!(link.inode, target.inode, "the link shares the inode");
            assert_eq!(link.file_type, file_type);
            assert_eq!(m.inodes[&link.inode].links_count, 2);
        }
    }

    #[test]
    fn a_hardlink_to_a_hardlink_resolves_to_the_inode_beneath_both() {
        // The chain runs backwards through the sort order — /a targets /b, which targets
        // /c — so resolving one link at a time in name order would leave /a unresolved.
        let m = model(
            TreeBuilder::new()
                .hardlink(b"/a".to_vec(), b"/b".to_vec(), meta(0o644))
                .hardlink(b"/b".to_vec(), b"/c".to_vec(), meta(0o644))
                .file(b"/c".to_vec(), b"data".to_vec(), meta(0o644)),
        );
        let files: Vec<_> = m
            .inodes
            .values()
            .filter(|i| matches!(i.content, Content::File(_)))
            .collect();
        assert_eq!(files.len(), 1, "all three names share one inode");
        assert_eq!(files[0].links_count, 3);
    }

    #[test]
    fn a_cycle_of_hardlinks_is_rejected() {
        // Two links naming each other reach no inode; the walk must report the cycle
        // rather than loop.
        let err = build_model(
            TreeBuilder::new()
                .hardlink(b"/a".to_vec(), b"/b".to_vec(), meta(0o644))
                .hardlink(b"/b".to_vec(), b"/a".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ModelError::HardlinkCycle { .. }),
            "expected HardlinkCycle, got {err:?}"
        );
    }

    #[test]
    fn an_empty_nul_or_duplicate_xattr_name_is_rejected() {
        // An empty name serializes to the end-of-list terminator and would hide every
        // attribute after it; a bare namespace prefix has no name past it; a NUL is a
        // false C-string end. Each is refused rather than written into a set that
        // silently drops attributes.
        for (name, reason) in [
            (&b""[..], "empty"),
            (b"user.", "empty"),
            (b"user.a\0b", "embedded NUL"),
        ] {
            let err = build_model(
                TreeBuilder::new()
                    .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                    .xattr(name.to_vec(), b"v".to_vec()),
                config(),
            )
            .unwrap_err();
            assert!(
                matches!(&err, ModelError::InvalidXattrName { reason: r, .. } if *r == reason),
                "name {:?} should be rejected as {reason}, got {err:?}",
                String::from_utf8_lossy(name)
            );
        }

        // A name written twice is a state the kernel cannot produce; the second occurrence
        // is the offending one.
        let err = build_model(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                .xattr(b"user.a".to_vec(), b"1".to_vec())
                .xattr(b"user.a".to_vec(), b"2".to_vec()),
            config(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ModelError::InvalidXattrName {
                    reason: "duplicate",
                    ..
                }
            ),
            "a duplicate xattr name should be rejected, got {err:?}"
        );
    }

    #[test]
    fn a_xattr_set_larger_than_one_block_is_accepted_when_it_splits() {
        // At a 4096-byte block, `user.huge` alone needs the whole block (32-byte
        // header + 20-byte entry + 4040-byte value + 4-byte terminator = 4096), and
        // `user.tiny` fits the 256-byte inode's 88 free inline bytes. Together they
        // exceed one block, and only the split makes the set representable — the
        // same storage a kernel-written inode holds it in.
        let m = build_model(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                .xattr(b"user.huge".to_vec(), vec![0xAA; 4040])
                .xattr(b"user.tiny".to_vec(), vec![0xBB; 60]),
            config(),
        )
        .expect("a set that fits split across the inode and one block");
        let f = m
            .inodes
            .values()
            .find(|i| matches!(i.content, Content::File(_)))
            .unwrap();
        assert_eq!(f.xattrs.len(), 2, "both attributes reach the inode");
    }

    #[test]
    fn a_xattr_spill_no_block_holds_is_rejected() {
        // One more word in the huge value pushes the spilled side past the block:
        // 32 + 20 + align4(4041) + 4 = 4100. The inline attribute is not part of
        // that count — the error names only what the block must hold.
        let err = build_model(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                .xattr(b"user.huge".to_vec(), vec![0xAA; 4041])
                .xattr(b"user.tiny".to_vec(), vec![0xBB; 60]),
            config(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ModelError::XattrsTooLarge { needed: 4100, .. }),
            "the spill alone overflows a block, got {err:?}"
        );
    }

    #[test]
    fn attributes_on_a_profile_without_ext_attr_are_refused() {
        // `ext_attr` is the feature that says a filesystem holds attributes at all. A
        // source carrying one on a profile without it is a conflict between the input and
        // the words the image would advertise: writing the attribute anyway leaves an
        // inode pointing at a block the feature word denies (which `e2fsck` faults), and
        // dropping it silently loses what the source supplied. The conflict is named.
        let cfg = ModelConfig {
            ext_attr: false,
            ..config()
        };
        let src = || {
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                .xattr(b"user.a".to_vec(), b"1".to_vec())
        };
        let err = build_model(src(), cfg).unwrap_err();
        assert!(
            matches!(
                err,
                ModelError::XattrsWithoutFeature { ref path } if path == b"/f"
            ),
            "expected XattrsWithoutFeature naming the entry, got {err:?}"
        );

        // With the feature the same source builds, and a profile without it accepts every
        // entry that carries no attribute.
        build_model(src(), config()).expect("ext_attr holds the same set");
        build_model(
            TreeBuilder::new().file(b"/f".to_vec(), b"data".to_vec(), meta(0o644)),
            cfg,
        )
        .expect("an entry with no attributes needs no feature");
    }

    #[test]
    fn a_regular_file_past_the_large_file_bound_requires_the_feature() {
        // The rule is checked against a size rather than against bytes, so it is exercised
        // here without materializing two gigabytes: the bound is what `e2fsck` applies
        // (`ext2fs_needs_large_file_feature`), and it is inclusive.
        let with = config();
        let without = ModelConfig {
            large_file: false,
            ..config()
        };
        let at = LARGE_FILE_MIN_SIZE;

        assert!(validate_file_size(b"/f", at - 1, &without).is_ok());
        let err = validate_file_size(b"/f", at, &without).unwrap_err();
        assert!(
            matches!(
                err,
                ModelError::FileTooLargeWithoutFeature { size, limit, ref path }
                    if size == LARGE_FILE_MIN_SIZE && limit == LARGE_FILE_MIN_SIZE && path == b"/f"
            ),
            "expected FileTooLargeWithoutFeature naming the file, got {err:?}"
        );
        // The feature is what lifts the bound.
        assert!(validate_file_size(b"/f", at, &with).is_ok());
    }

    #[test]
    fn an_acl_xattr_name_with_an_empty_stored_name_is_accepted() {
        // `system.posix_acl_access` is a whole-name index: its stored name is empty by
        // design and must not be taken for an empty attribute name.
        build_model(
            TreeBuilder::new()
                .file(b"/f".to_vec(), b"data".to_vec(), meta(0o644))
                .xattr(b"system.posix_acl_access".to_vec(), vec![0u8; 4]),
            config(),
        )
        .expect("a whole-name ACL attribute is a valid, non-empty name");
    }

    #[test]
    fn a_root_entry_supplies_the_root_directorys_metadata() {
        // The root already exists, so an entry naming it describes inode 2 rather than
        // adding one: its mode, ownership, and extended attributes are the root's, and
        // the inode numbering is untouched.
        let m = model(
            TreeBuilder::new()
                .root(meta(0o700).owned_by(1000, 2000))
                .xattr(b"user.label".to_vec(), b"rootfs".to_vec())
                .file(b"/f".to_vec(), b"x".to_vec(), meta(0o644)),
        );
        let root = m.root();
        assert_eq!(root.mode, 0o040700);
        assert_eq!((root.uid, root.gid), (1000, 2000));
        assert_eq!(root.xattrs[0].name, b"user.label");
        assert_eq!(root.links_count, 3, "., lost+found's .., and its own");
        assert_eq!(
            m.first_free_inode, 13,
            "the root entry consumed no inode number"
        );
    }

    #[test]
    fn entries_begin_at_the_configured_first_user_inode() {
        // A feature that claims an inode at format time — the orphan file takes 12 —
        // moves the entries up, and the used count still spans every inode below them.
        let cfg = ModelConfig {
            first_user_inode: FIRST_USER_INO + 1,
            ..config()
        };
        let src = TreeBuilder::new().file(b"/f".to_vec(), b"x".to_vec(), meta(0o644));
        let m = build_model(src, cfg).expect("model");
        let f = m
            .inodes
            .values()
            .find(|i| matches!(i.content, Content::File(_)))
            .unwrap();
        assert_eq!(f.number, 13, "the entry sits above the claimed inode");
        assert_eq!(m.first_free_inode, 14);
        assert_eq!(
            m.used_inode_count(),
            13,
            "the claimed inode is counted as in use, though the model never holds it"
        );
    }

    #[test]
    fn a_first_user_inode_inside_the_reserved_range_is_rejected() {
        let cfg = ModelConfig {
            first_user_inode: LOST_FOUND_INO,
            ..config()
        };
        let err = build_model(TreeBuilder::new(), cfg).unwrap_err();
        assert!(matches!(
            err,
            ModelError::FirstUserInodeReserved { given, floor }
                if given == LOST_FOUND_INO && floor == FIRST_USER_INO
        ));
    }

    #[test]
    fn a_root_entry_that_is_not_a_directory_is_rejected() {
        let err = build_model(
            TreeBuilder::new().file(b"/".to_vec(), b"x".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::RootNotDirectory { .. }));
    }

    #[test]
    fn a_second_root_entry_is_a_duplicate() {
        // `.` and `/` name the same directory, so the second is a duplicate — the same
        // rule every other path follows.
        let err = build_model(
            TreeBuilder::new()
                .root(meta(0o755))
                .directory(b".".to_vec(), meta(0o700)),
            config(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::Duplicate { .. }));
    }

    #[test]
    fn an_error_message_names_the_path_as_text() {
        // A path is a byte string, and the message must read as one: the point of naming
        // the offending path is that the caller can find it.
        let err = build_model(
            TreeBuilder::new().file(b"/etc/hostname".to_vec(), b"x".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "path /etc/hostname has no parent directory"
        );

        // A path that is not UTF-8 still names itself, with the bytes it cannot render
        // replaced rather than the whole path withheld.
        let err = build_model(
            TreeBuilder::new().file(b"/\xff\xfe/x".to_vec(), b"x".to_vec(), meta(0o644)),
            config(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "path /\u{fffd}\u{fffd}/x has no parent directory"
        );
    }
}
