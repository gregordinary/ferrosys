//! What populates a filesystem: the [`Source`] trait and a programmatic builder.
//!
//! A source yields a flat list of entries — a path, a kind, and the ownership,
//! mode, and timestamp to record — that the model turns into an inode tree. This
//! module defines that vocabulary and one source, the in-memory [`TreeBuilder`];
//! the archive and host-directory sources are separate, feature-gated
//! implementations of the same trait.
//!
//! A source states what it wants written; whether the current feature profile can
//! represent it is decided when the model consumes it. An input the profile cannot
//! hold — a name over 255 bytes, an unresolvable hard link — becomes a typed error
//! there, never a silently dropped or truncated entry.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::path::canonical_key;
use crate::time::Timestamp;
use crate::xattr::Xattr;

/// A regular file's contents: either bytes in memory, or a range of a file on the host
/// read at the moment it is placed.
///
/// The two coexist in one entry list, deliberately. A source that maps an on-host archive
/// yields handles; a caller that computes an entry's bytes — rewriting one file of a tree
/// it is otherwise passing through — supplies them owned, in the same `Vec<SourceEntry>`.
///
/// # Why this is not just `Vec<u8>`
///
/// A format's peak memory is otherwise the sum of every file it writes, because every
/// file's bytes are built before the first block is placed. A handle defers the bytes
/// until the file is written, so the peak becomes the largest single file rather than the
/// total.
///
/// The [`len`](Self::len) is known without reading, which is what lets the model check a
/// file against the `large_file` feature — and name the offending path — before any bytes
/// are read.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum FileContent {
    /// Bytes held in memory.
    Owned(Vec<u8>),
    /// A range of a file on the host, read when the content is placed.
    Range(FileRange),
}

impl FileContent {
    /// The file's length in bytes, without reading it.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Owned(bytes) => bytes.len() as u64,
            Self::Range(range) => range.len(),
        }
    }

    /// Whether the file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The file's bytes, reading them from the host if they are not already in memory.
    ///
    /// Bytes already held are borrowed, not copied: reading an [`Owned`](Self::Owned)
    /// entry costs nothing, so a caller that reads every entry in turn never holds two
    /// copies of one file. Only a [`Range`](Self::Range) allocates, and only for as long
    /// as the caller keeps what it returned.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the backing file cannot be read — including the case where
    /// it is shorter than the range claims, which means the file changed after the source
    /// that named it was built. An owned entry cannot fail.
    pub fn read(&self) -> std::io::Result<Cow<'_, [u8]>> {
        match self {
            Self::Owned(bytes) => Ok(Cow::Borrowed(bytes)),
            Self::Range(range) => Ok(Cow::Owned(range.read()?)),
        }
    }
}

impl From<Vec<u8>> for FileContent {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Owned(bytes)
    }
}

impl From<FileRange> for FileContent {
    fn from(range: FileRange) -> Self {
        Self::Range(range)
    }
}

// The borrowed forms of a file's bytes, each copied into an owned buffer. A caller writing
// a small file writes it as a literal — `b"ferrosys\n"`, `"#!/bin/sh\n"` — and having to
// spell `.to_vec()` on every one of them is noise that says nothing about the filesystem
// being built. `String` and `&str` are here because a text file is text; the bytes stored
// are the UTF-8 the string already holds, with no re-encoding.
impl From<&[u8]> for FileContent {
    fn from(bytes: &[u8]) -> Self {
        Self::Owned(bytes.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for FileContent {
    fn from(bytes: &[u8; N]) -> Self {
        Self::Owned(bytes.to_vec())
    }
}

impl From<&str> for FileContent {
    fn from(text: &str) -> Self {
        Self::Owned(text.as_bytes().to_vec())
    }
}

impl From<String> for FileContent {
    fn from(text: String) -> Self {
        Self::Owned(text.into_bytes())
    }
}

/// A range of bytes within a file on the host, read at the moment the content is placed.
///
/// The handle is a plain owned value: no lifetime parameter reaches [`SourceEntry`], and a
/// caller may hold, clone, sort, and splice a list of them freely.
///
/// # Two forms, and what each costs
///
/// [`new`](Self::new) carries an open descriptor, shared, so a whole archive's worth of
/// ranges into one file costs one descriptor. [`at_path`](Self::at_path) carries only the
/// path and opens it for each read, which is what lets a source name a range in each of a
/// hundred thousand separate files without holding a descriptor for every one.
///
/// # The file must not change while the source is alive
///
/// The bytes are read when the file is placed, not when the source is built, so an edit in
/// between reaches the image — as wrong bytes rather than as an error, unless the file
/// shrank enough for the read to run short.
///
/// Which edits reach it depends on the form. A held descriptor names an inode: a
/// replacement written to a new file and renamed into place leaves the original inode
/// readable and the format unaffected, and only an **in-place** modification or a
/// truncation of that inode is seen. A path is resolved afresh at each read, so whatever
/// the name resolves to then is what reaches the image.
#[derive(Clone)]
pub struct FileRange {
    /// The open file, when the range was built from one. Shared so a handle is owned
    /// rather than borrowed. `None` for a range named by path alone, which opens `path`
    /// when it is read.
    file: Option<Arc<File>>,
    /// The path the bytes come from: what a range built from a descriptor names for
    /// diagnostics and identity, and what one built by path opens.
    path: Arc<PathBuf>,
    offset: u64,
    len: u64,
}

impl FileRange {
    /// A handle to `len` bytes at `offset` in `file`, which was opened from `path`.
    ///
    /// The path is carried for diagnostics and identity; it is not re-opened, so the
    /// range keeps reading the file this descriptor names even if the path is replaced.
    #[must_use]
    pub fn new(file: Arc<File>, path: impl Into<PathBuf>, offset: u64, len: u64) -> Self {
        Self {
            file: Some(file),
            path: Arc::new(path.into()),
            offset,
            len,
        }
    }

    /// A handle to `len` bytes at `offset` in the file at `path`, opened when the range is
    /// read rather than now.
    ///
    /// This is the form for a source that names ranges in many separate files: it holds no
    /// descriptor, so the number of files it can name is unbounded. The cost is that the
    /// path is resolved at each read, so a file replaced under that name between building
    /// the source and formatting reaches the image.
    #[must_use]
    pub fn at_path(path: impl Into<PathBuf>, offset: u64, len: u64) -> Self {
        Self {
            file: None,
            path: Arc::new(path.into()),
            offset,
            len,
        }
    }

    /// The path the backing file was opened from.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Byte offset of the range within the backing file.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Length of the range in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the range is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read the range's bytes.
    ///
    /// Every failure names the path, the offset, and the length, since that is what a
    /// caller has to act on: the error surfaces through a family's own format error
    /// transparently, so what this message says is the whole of what a person sees. A short read in particular — the file
    /// changed after the source was built — is otherwise indistinguishable from any
    /// other truncation, and names neither the file that changed nor the range that was
    /// lost.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the file cannot be opened or read, or if it is shorter than
    /// the range claims — which is what a file edited after the source was built looks
    /// like.
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        let context = |e: std::io::Error| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "{}: reading {} bytes at offset {}: {e}",
                    crate::escape::printable_path(&self.path),
                    self.len,
                    self.offset
                ),
            )
        };
        let len = usize::try_from(self.len).map_err(|_| {
            std::io::Error::other(format!(
                "{}: {} bytes at offset {} is more than this platform addresses",
                crate::escape::printable_path(&self.path),
                self.len,
                self.offset
            ))
        })?;
        // An independent descriptor, so the read carries its own cursor: a shared one
        // would make two handles into the same file interfere. A range named by path
        // alone opens it here, which is the whole of what it defers.
        let mut handle = match &self.file {
            Some(file) => file.try_clone().map_err(context)?,
            // Opened without following a final symbolic link. A walk records a symlink as a
            // symlink and never reads through one, and this is where that promise would
            // otherwise end: a local writer replacing a staged name with a link between the
            // walk and the placement would put the target's bytes into the image, with no
            // error and nothing in the fidelity report. The "must not change" caveat on a
            // range covers content changing; it does not cover the name becoming a different
            // kind of thing.
            None => open_no_follow(self.path.as_path()).map_err(context)?,
        };
        handle.seek(SeekFrom::Start(self.offset)).map_err(context)?;
        let mut buf = vec![0u8; len];
        handle.read_exact(&mut buf).map_err(context)?;
        Ok(buf)
    }
}

/// Open a regular file by path without following a symbolic link at the end of it.
///
/// `O_NOFOLLOW` is not in the standard library's options, so the raw flag is set through the
/// Unix extension; on a platform with no such flag the plain open is what there is, and the
/// walk that produced the path is the same platform's.
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(o_nofollow())
            .open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

/// `O_NOFOLLOW` for this target.
///
/// Spelled here rather than pulled from a C-binding crate, which this crate does not depend
/// on for one integer, and which is not compiled at all in the feature sets that carry no
/// host directory. The value is part of each kernel's stable syscall interface, and it is
/// one value per architecture rather than one value: Linux's generic definition is
/// `0o400000`, and arm, aarch64, m68k, powerpc and powerpc64 each define `0o100000` in its
/// place, where `0o400000` means `O_LARGEFILE` — a bit the kernel accepts and ignores, so
/// the generic value on one of those is an open that quietly follows the link. The BSDs
/// including macOS use `0x0100`, and the Solaris lineage the Linux generic value.
///
/// A unix target outside those families is a build failure rather than a guess: what a guess
/// costs is a read through a link, silently. The value is proved rather than asserted —
/// `a_link_is_refused_by_the_flag_this_target_defines` opens one on whatever target the suite
/// is running on.
#[cfg(unix)]
const fn o_nofollow() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if cfg!(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "m68k",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )) {
            0o100_000
        } else {
            0o400_000
        }
    }
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        0o400_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x0100
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        compile_error!(
            "no O_NOFOLLOW value is known for this target, and an open that follows a \
             symbolic link would read through a name recorded as a link"
        );
        0
    }
}

impl PartialEq for FileRange {
    /// Two handles are equal when they name the same range of the same path. The open
    /// descriptors are not compared: a path re-opened is the same range by every measure
    /// a caller can act on.
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.offset == other.offset && self.len == other.len
    }
}

impl Eq for FileRange {}

impl std::fmt::Debug for FileRange {
    /// The range, without the descriptor: `FileRange { path, offset, len }`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRange")
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish()
    }
}

/// Ownership, permission bits, and timestamps for one entry.
///
/// The `mode` is the permission and set-user/group/sticky bits only; the file-type
/// bits come from the entry's [`EntryKind`]. Access, change, and modification times
/// are carried independently, matching what ext4 stores and what an archive can
/// supply; the creation time is derived from the modification time by the model,
/// since no archive format records a birth time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Metadata {
    /// Permission and `setuid`/`setgid`/sticky bits (the low twelve bits of the
    /// mode).
    pub mode: u16,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Access time (`atime`).
    pub atime: Timestamp,
    /// Change (status) time (`ctime`).
    pub ctime: Timestamp,
    /// Modification time (`mtime`); also the source of the derived creation time.
    pub mtime: Timestamp,
}

/// The file-type bits of a mode (`S_IFMT`), which [`Metadata::mode`] must not carry: the
/// entry's [`EntryKind`] supplies them. Every model that writes POSIX modes refuses a
/// `mode` with any of these set, so a raw `st_mode` passed through whole is a typed error
/// rather than an inode carrying two file types.
#[cfg(any(feature = "ext", feature = "btrfs"))]
pub(crate) const MODE_TYPE_MASK: u16 = 0o170000;

impl Metadata {
    /// Metadata with the given permission bits, owned by root, whose access,
    /// change, and modification times are all `mtime` — the common case where one
    /// time is known.
    #[must_use]
    pub fn new(mode: u16, mtime: Timestamp) -> Self {
        Self {
            mode,
            uid: 0,
            gid: 0,
            atime: mtime,
            ctime: mtime,
            mtime,
        }
    }

    /// Set the owning user and group.
    #[must_use]
    pub fn owned_by(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Set the access, change, and modification times independently, for a source
    /// that carries all three.
    #[must_use]
    pub fn with_times(mut self, atime: Timestamp, ctime: Timestamp, mtime: Timestamp) -> Self {
        self.atime = atime;
        self.ctime = ctime;
        self.mtime = mtime;
        self
    }
}

/// What an entry is: a regular file, directory, symlink, hard link, device node,
/// FIFO, or socket — the full set of POSIX file types ext4 represents.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum EntryKind {
    /// A directory.
    Directory,
    /// A regular file with the given contents, held in memory or read from the host
    /// when the file is placed.
    File(FileContent),
    /// A symbolic link to the given target path.
    Symlink(Vec<u8>),
    /// A hard link: another name for the entry already present at `target`, which may
    /// be of any kind but a directory, and may itself be a hard link.
    HardLink {
        /// Path of the existing entry this name also points at.
        target: Vec<u8>,
    },
    /// A character-special device node with the given major and minor numbers.
    CharDevice {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// A block-special device node with the given major and minor numbers.
    BlockDevice {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// A named pipe (FIFO).
    Fifo,
    /// A Unix-domain socket node.
    Socket,
}

/// One thing to place in the filesystem: where it goes, what it is, its metadata,
/// and any extended attributes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceEntry {
    /// Path from the filesystem root, e.g. `b"/etc/hostname"`. Leading and repeated
    /// slashes are ignored, as is a `.` component; a `..` component is rejected by the
    /// model. A path naming the root itself (`b"/"`) describes the root directory,
    /// whose metadata and extended attributes the model applies to inode 2.
    pub path: Vec<u8>,
    /// What to place at `path`.
    pub kind: EntryKind,
    /// Ownership, mode, and times.
    pub meta: Metadata,
    /// Extended attributes attached to this entry, each a fully-qualified name and
    /// its value in the boundary form [`Xattr`] describes. Empty for an entry with none.
    pub xattrs: Vec<Xattr>,
}

/// Something that produces the entries to write into a filesystem.
///
/// The model consumes a source once. An archive parser, a walk of a host directory, and
/// the in-memory [`TreeBuilder`] are all sources; the model does not care which.
///
/// # Why the entries are a `Vec` and not an iterator
///
/// Inode numbers are assigned in sorted path order, which is what makes two formats of the
/// same tree byte-identical — so the model sorts the whole list before it places anything.
/// The list is therefore materialized whatever a source hands over, and an iterator would
/// be collected on arrival rather than streamed.
///
/// What that costs is bounded by the entry *count*, not by the bytes: a regular file's
/// contents may be a [`FileContent::Range`], which is a path, an offset, and a length until
/// the file is placed. A tree of a million entries is tens of megabytes of entry records
/// however large the files in it are.
pub trait Source {
    /// Produce the entries, consuming the source.
    fn into_entries(self) -> Vec<SourceEntry>;
}

/// An in-memory, programmatic source: add entries, then hand it to the model.
///
/// Order of addition does not affect the result — the model sorts by path so the
/// inode numbering is deterministic — but a directory's contents are only valid if
/// the directory itself is also added.
#[derive(Clone, Default, Debug)]
pub struct TreeBuilder {
    entries: Vec<SourceEntry>,
}

impl TreeBuilder {
    /// A builder with no entries. The root directory always exists implicitly and
    /// is not added here.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directory at `path`.
    #[must_use]
    pub fn directory(mut self, path: impl Into<Vec<u8>>, meta: Metadata) -> Self {
        self.push(path, EntryKind::Directory, meta);
        self
    }

    /// Set the root directory's own metadata, overriding the `0755` root-owned default.
    ///
    /// The root already exists, so this describes it rather than adding an entry; any
    /// [`xattr`](Self::xattr) that follows attaches to the root. Naming it once is
    /// enough — a second root entry is a duplicate the model rejects.
    #[must_use]
    pub fn root(mut self, meta: Metadata) -> Self {
        self.push(b"/".to_vec(), EntryKind::Directory, meta);
        self
    }

    /// Add a regular file at `path` with `contents`.
    ///
    /// `contents` is anything that converts into a [`FileContent`]: an owned `Vec<u8>` or
    /// `String`, a borrowed `&[u8]`, `&[u8; N]`, or `&str` — each copied into the entry —
    /// or a [`FileRange`], which names bytes on the host and reads them when the file is
    /// placed rather than now.
    #[must_use]
    pub fn file(
        mut self,
        path: impl Into<Vec<u8>>,
        contents: impl Into<FileContent>,
        meta: Metadata,
    ) -> Self {
        self.push(path, EntryKind::File(contents.into()), meta);
        self
    }

    /// Add a symbolic link at `path` pointing at `target`.
    #[must_use]
    pub fn symlink(
        mut self,
        path: impl Into<Vec<u8>>,
        target: impl Into<Vec<u8>>,
        meta: Metadata,
    ) -> Self {
        self.push(path, EntryKind::Symlink(target.into()), meta);
        self
    }

    /// Add a hard link at `path` to the entry already declared at `target`, which may
    /// be of any kind but a directory, and may itself be a hard link.
    ///
    /// The link shares the target's inode, so the two names are one file: the
    /// metadata, extended attributes, and contents are the inode's, and the `meta`
    /// given here is not applied.
    #[must_use]
    pub fn hardlink(
        mut self,
        path: impl Into<Vec<u8>>,
        target: impl Into<Vec<u8>>,
        meta: Metadata,
    ) -> Self {
        self.push(
            path,
            EntryKind::HardLink {
                target: target.into(),
            },
            meta,
        );
        self
    }

    /// Add a character-special device node at `path`.
    #[must_use]
    pub fn char_device(
        mut self,
        path: impl Into<Vec<u8>>,
        major: u32,
        minor: u32,
        meta: Metadata,
    ) -> Self {
        self.push(path, EntryKind::CharDevice { major, minor }, meta);
        self
    }

    /// Add a block-special device node at `path`.
    #[must_use]
    pub fn block_device(
        mut self,
        path: impl Into<Vec<u8>>,
        major: u32,
        minor: u32,
        meta: Metadata,
    ) -> Self {
        self.push(path, EntryKind::BlockDevice { major, minor }, meta);
        self
    }

    /// Add a named pipe (FIFO) at `path`.
    #[must_use]
    pub fn fifo(mut self, path: impl Into<Vec<u8>>, meta: Metadata) -> Self {
        self.push(path, EntryKind::Fifo, meta);
        self
    }

    /// Add a Unix-domain socket node at `path`.
    #[must_use]
    pub fn socket(mut self, path: impl Into<Vec<u8>>, meta: Metadata) -> Self {
        self.push(path, EntryKind::Socket, meta);
        self
    }

    /// Attach an extended attribute to the most recently added entry.
    ///
    /// `name` is the fully-qualified attribute name (e.g. `b"security.capability"`).
    /// If no entry has been added yet, the call has no effect.
    #[must_use]
    pub fn xattr(mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        if let Some(entry) = self.entries.last_mut() {
            entry.xattrs.push(Xattr {
                name: name.into(),
                value: value.into(),
            });
        }
        self
    }

    fn push(&mut self, path: impl Into<Vec<u8>>, kind: EntryKind, meta: Metadata) {
        self.entries.push(SourceEntry {
            path: path.into(),
            kind,
            meta,
            xattrs: Vec::new(),
        });
    }
}

impl Source for TreeBuilder {
    fn into_entries(self) -> Vec<SourceEntry> {
        self.entries
    }
}

/// Several sources composed into one, where a later layer's entry replaces an earlier
/// layer's at the same path.
///
/// This is the shape an image build takes when a base tree is customized: a root
/// filesystem from an archive, then a directory of configuration over it, then a handful
/// of computed files over that. Each layer is a [`Source`] of any kind — they need not be
/// the same kind — and is consumed as it is added.
///
/// # What replacement means
///
/// A path present in more than one layer takes the last layer's entry whole: its kind, its
/// metadata, and its extended attributes, which replace the earlier set rather than merging
/// with it name by name. Paths are compared as the model compares them, so `/etc/hostname`
/// and `//etc//hostname` are one path and the second does replace the first.
///
/// A directory is the case where replacement is not the whole story. Its own entry is
/// replaced like any other, so the last layer decides its mode, ownership, times, and
/// attributes — but its *contents* are separate entries at their own paths, so a directory
/// named by two layers ends up holding the union of what each put in it. That is what makes
/// a configuration layer additive: naming `/etc` again does not empty it.
///
/// Replacing a directory with something that is not one is different: the entries beneath
/// it would have no directory to live in, so they are dropped along with it. A file at
/// `/etc` removes `/etc/hostname` from an earlier layer.
///
/// # What it does not do
///
/// There is no deletion marker. A layer states what is present, so a path an earlier layer
/// placed can be replaced but not removed, and the entry list is always the union of the
/// layers' paths.
///
/// Nothing is validated here. A layer may name a path the model refuses — one holding a
/// `..` element, say — and the refusal comes from the model when the composed list is read,
/// naming the path the caller wrote.
///
/// # Example
///
/// ```
/// use ferrosys::ext::{EntryKind, LayeredSource, Metadata, Source, TreeBuilder, Timestamp};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// let base = TreeBuilder::new()
///     .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
///     .file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), Metadata::new(0o644, time))
///     .file(b"/etc/issue".to_vec(), b"welcome\n".to_vec(), Metadata::new(0o644, time));
/// let overlay = TreeBuilder::new()
///     .file(b"/etc/hostname".to_vec(), b"overlaid\n".to_vec(), Metadata::new(0o600, time));
///
/// let entries = LayeredSource::new().layer(base).layer(overlay).into_entries();
///
/// // Three paths: the overlay replaced one and added none.
/// assert_eq!(entries.len(), 3);
/// let hostname = entries.iter().find(|e| e.path == b"/etc/hostname").unwrap();
/// assert_eq!(hostname.meta.mode, 0o600);
/// assert!(matches!(&hostname.kind, EntryKind::File(c) if c.read().unwrap().as_ref() == b"overlaid\n"));
/// ```
#[derive(Clone, Default, Debug)]
pub struct LayeredSource {
    /// Entries by canonical path, so a later layer's entry replaces an earlier one and the
    /// ordered keys make a subtree a contiguous range.
    entries: BTreeMap<Vec<u8>, SourceEntry>,
}

impl LayeredSource {
    /// A composition with no layers, which yields no entries.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a layer over the ones already added, replacing their entries where the paths
    /// agree.
    ///
    /// The source is consumed here rather than held, so layers of different kinds compose
    /// and each layer's own cost is paid once. Order is the whole contract: the last call
    /// wins.
    #[must_use]
    pub fn layer(mut self, source: impl Source) -> Self {
        for entry in source.into_entries() {
            let key = canonical_key(&entry.path);
            // Something that is not a directory cannot hold the entries an earlier layer
            // put beneath this path, so they go with it. The keys are canonical and
            // ordered, so a subtree is the contiguous range beginning `key/` — and for the
            // root, whose key is empty, that is every other entry.
            if !matches!(entry.kind, EntryKind::Directory) {
                let mut prefix = key.clone();
                if !prefix.is_empty() {
                    prefix.push(b'/');
                }
                let doomed: Vec<Vec<u8>> = self
                    .entries
                    .range(prefix.clone()..)
                    .take_while(|(k, _)| k.starts_with(&prefix))
                    // The path itself is inside its own range when it is the root, whose
                    // prefix is empty. It is being replaced, not dropped.
                    .filter(|(k, _)| **k != key)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in doomed {
                    self.entries.remove(&k);
                }
            }
            self.entries.insert(key, entry);
        }
        self
    }

    /// The number of distinct paths the layers hold between them.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the composition holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Source for LayeredSource {
    /// The composed entries, each path once, carrying the path the layer that won wrote
    /// rather than the canonical form used to compare them — so a model error names what
    /// the caller typed.
    fn into_entries(self) -> Vec<SourceEntry> {
        self.entries.into_values().collect()
    }
}

/// A fault a path has whatever format is being asked to hold it.
#[cfg(any(feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) enum PathFault {
    /// A component was `..`, which a source may not use — a path is where an entry goes, not a
    /// traversal to be resolved.
    Traversal,
    /// Two entries resolve to one path.
    Duplicate,
    /// An entry naming the root is not a directory. The root is a directory, so an entry that
    /// would place anything else there describes a filesystem that cannot exist.
    RootNotDirectory,
}

/// A classification that stopped: at a fault in a path, or at whatever the family decided about
/// what the entry holds.
#[cfg(any(feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) enum ClassifyError<E> {
    /// A fault in a path, with the path as the caller wrote it — so a message names that rather
    /// than the canonical form used to compare it.
    Path(PathFault, Vec<u8>),
    /// The family refused what the entry holds.
    Class(E),
}

/// Decide what every declared path holds, refusing the faults a path has whatever format is
/// being asked to hold it.
///
/// One walk rather than one per family, for the reason the hard-link walk below is one: *which*
/// faults a path can have, and the rule that decides which components it even has, are
/// properties of a source rather than of any format. What each path *holds* is the family's, which is what
/// `class_of` answers — and it is handed the components rather than the path, so a family that
/// bounds a name checks the components this pass already split rather than splitting them again.
///
/// The pass exists because a hard link may name a target that sorts after it: nothing can be
/// placed until every path is known.
#[cfg(any(feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn classify_paths<C, E>(
    entries: &[SourceEntry],
    mut class_of: impl FnMut(&SourceEntry, &[&[u8]]) -> Result<C, E>,
    is_directory: impl Fn(&C) -> bool,
) -> Result<BTreeMap<Vec<u8>, C>, ClassifyError<E>> {
    let mut classes = BTreeMap::new();
    for entry in entries {
        // Split once and key from the same parts, rather than joining a key and taking it apart
        // again: which components a path has is one rule, and asking it twice is two chances to
        // disagree about what this path even is.
        let parts = crate::path::canonical_parts(&entry.path);
        if parts.iter().any(|part| *part == b"..") {
            return Err(ClassifyError::Path(
                PathFault::Traversal,
                entry.path.clone(),
            ));
        }
        let key = parts.join(&b'/');
        if classes.contains_key(&key) {
            return Err(ClassifyError::Path(
                PathFault::Duplicate,
                entry.path.clone(),
            ));
        }
        let class = class_of(entry, &parts).map_err(ClassifyError::Class)?;
        if key.is_empty() && !is_directory(&class) {
            return Err(ClassifyError::Path(
                PathFault::RootNotDirectory,
                entry.path.clone(),
            ));
        }
        classes.insert(key, class);
    }
    Ok(classes)
}

/// What a source declares at one path, as far as following a hard link is concerned.
///
/// The file arm carries whatever the caller needs of the file it found, so a walk that ends at
/// one hands it back rather than leaving the caller to look the path up a second time.
#[cfg(any(feature = "fat", feature = "exfat"))]
pub(crate) enum LinkStep<T> {
    /// A regular file: the chain ends here, with what the caller keeps of it.
    File(T),
    /// A directory, which no filesystem lets a hard link name.
    Directory,
    /// Something the target format cannot hold, so there is nothing left to be a second name
    /// for.
    Unrepresentable,
    /// Another hard link, naming this canonical key.
    Link(Vec<u8>),
    /// Nothing is declared at this path.
    Missing,
}

/// Where a chain of hard links ends.
#[cfg(any(feature = "fat", feature = "exfat"))]
pub(crate) enum LinkEnd<T> {
    /// A file, with what the caller keeps of it.
    File(T),
    /// Something the target format cannot hold.
    Unrepresentable,
    /// A directory.
    Directory,
    /// Nothing at all.
    Missing,
    /// The chain returns to somewhere it has been, so no end of it names a file.
    Cycle,
}

/// Follow the chain of hard links beginning at `target` to whatever is at its end.
///
/// A link may name another link, so this is a walk rather than a lookup — and one that has to
/// terminate on a source that names a cycle. `declared` is how many paths the source declares,
/// which is what bounds it: every step consumes one declared path, so a walk longer than that
/// has come back to somewhere it has been.
///
/// One walk rather than one per family. What a family does with each outcome is its own — the
/// refusals are that family's error taxonomy, and what it keeps of a file is its own value —
/// but *which* outcomes there are, and the bound that makes a cycle terminate rather than hang,
/// are properties of a source and not of any format.
///
/// Nothing here reads a file or resolves a path outside the source: `target` names something
/// the same source declared, which is why a hard link can be written as a second copy at all.
#[cfg(any(feature = "fat", feature = "exfat"))]
pub(crate) fn follow_hard_link<T>(
    target: &[u8],
    declared: usize,
    step: impl Fn(&[u8]) -> LinkStep<T>,
) -> LinkEnd<T> {
    let mut at = canonical_key(target);
    let mut seen = 0usize;
    loop {
        match step(&at) {
            LinkStep::File(found) => return LinkEnd::File(found),
            LinkStep::Directory => return LinkEnd::Directory,
            LinkStep::Unrepresentable => return LinkEnd::Unrepresentable,
            LinkStep::Missing => return LinkEnd::Missing,
            LinkStep::Link(next) => {
                seen += 1;
                if seen > declared {
                    return LinkEnd::Cycle;
                }
                at = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Metadata {
        Metadata::new(0o644, Timestamp::from_secs(1_700_000_000))
    }

    #[test]
    fn builder_collects_entries_in_addition_order() {
        let src = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, meta().mtime))
            .file(b"/etc/hostname".to_vec(), b"host\n".to_vec(), meta())
            .symlink(b"/etc/mtab".to_vec(), b"/proc/mounts".to_vec(), meta());
        let entries = src.into_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, b"/etc");
        assert!(matches!(entries[1].kind, EntryKind::File(_)));
        assert!(matches!(entries[2].kind, EntryKind::Symlink(_)));
    }

    /// The paths a composition yields, in order, as readable strings.
    fn paths(source: LayeredSource) -> Vec<String> {
        source
            .into_entries()
            .into_iter()
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect()
    }

    /// The contents of the regular file at `path`.
    fn contents_at(entries: &[SourceEntry], path: &[u8]) -> Vec<u8> {
        let entry = entries
            .iter()
            .find(|e| e.path == path)
            .expect("path is present");
        match &entry.kind {
            EntryKind::File(c) => c.read().expect("read").into_owned(),
            other => panic!("expected a file, got {other:?}"),
        }
    }

    #[test]
    fn a_later_layer_replaces_an_earlier_entry_whole() {
        let base = TreeBuilder::new()
            .file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), meta())
            .xattr(b"user.from".to_vec(), b"base".to_vec());
        let over = TreeBuilder::new()
            .file(
                b"/etc/hostname".to_vec(),
                b"over\n".to_vec(),
                Metadata::new(0o600, meta().mtime),
            )
            .xattr(b"user.other".to_vec(), b"over".to_vec());

        let entries = LayeredSource::new().layer(base).layer(over).into_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(contents_at(&entries, b"/etc/hostname"), b"over\n");
        assert_eq!(entries[0].meta.mode, 0o600);
        // The attributes are the later layer's set, not the union of the two.
        assert_eq!(entries[0].xattrs.len(), 1);
        assert_eq!(entries[0].xattrs[0].name, b"user.other");
    }

    #[test]
    fn naming_a_directory_again_does_not_empty_it() {
        // What makes a configuration layer additive: the later layer decides the
        // directory's own metadata, and the two layers' contents merge.
        let base = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, meta().mtime))
            .file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), meta());
        let over = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o700, meta().mtime))
            .file(b"/etc/issue".to_vec(), b"over\n".to_vec(), meta());

        let composed = LayeredSource::new().layer(base).layer(over);
        assert_eq!(
            paths(composed.clone()),
            ["/etc", "/etc/hostname", "/etc/issue"]
        );
        let entries = composed.into_entries();
        assert_eq!(entries[0].meta.mode, 0o700, "the later layer's mode");
    }

    #[test]
    fn replacing_a_directory_with_a_file_drops_what_was_beneath_it() {
        let base = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, meta().mtime))
            .file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), meta())
            .directory(b"/etc/ssl".to_vec(), Metadata::new(0o755, meta().mtime))
            .file(b"/etc/ssl/cert".to_vec(), b"pem\n".to_vec(), meta())
            // A sibling whose name shares the replaced path's bytes but not its subtree.
            .file(b"/etcetera".to_vec(), b"kept\n".to_vec(), meta());
        let over = TreeBuilder::new().file(b"/etc".to_vec(), b"now a file\n".to_vec(), meta());

        // Everything under /etc goes with it; /etcetera is not under /etc and stays.
        assert_eq!(
            paths(LayeredSource::new().layer(base).layer(over)),
            ["/etc", "/etcetera"]
        );
    }

    #[test]
    fn a_directory_over_a_file_keeps_the_directory() {
        let base = TreeBuilder::new().file(b"/etc".to_vec(), b"a file\n".to_vec(), meta());
        let over = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, meta().mtime))
            .file(b"/etc/hostname".to_vec(), b"over\n".to_vec(), meta());

        let entries = LayeredSource::new().layer(base).layer(over).into_entries();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0].kind, EntryKind::Directory));
    }

    #[test]
    fn paths_that_spell_one_path_are_one_path() {
        // The model treats these three as one, so layering has to as well: otherwise the
        // replacement silently does not happen and the model sees a duplicate.
        let base = TreeBuilder::new().file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), meta());
        let over = TreeBuilder::new().file(b"//etc//hostname".to_vec(), b"over\n".to_vec(), meta());
        let last = TreeBuilder::new().file(b"etc/./hostname".to_vec(), b"last\n".to_vec(), meta());

        let entries = LayeredSource::new()
            .layer(base)
            .layer(over)
            .layer(last)
            .into_entries();
        assert_eq!(entries.len(), 1, "three spellings of one path");
        // The path is the winning layer's own spelling, so a model error names what the
        // caller wrote rather than a form it never used.
        assert_eq!(entries[0].path, b"etc/./hostname");
        assert_eq!(contents_at(&entries, b"etc/./hostname"), b"last\n");
    }

    #[test]
    fn the_root_is_a_path_like_any_other() {
        let base = TreeBuilder::new()
            .root(Metadata::new(0o755, meta().mtime))
            .file(b"/etc/hostname".to_vec(), b"base\n".to_vec(), meta());
        let over = TreeBuilder::new().root(Metadata::new(0o700, meta().mtime));

        let composed = LayeredSource::new().layer(base).layer(over);
        assert_eq!(paths(composed.clone()), ["/", "/etc/hostname"]);
        assert_eq!(
            composed.into_entries()[0].meta.mode,
            0o700,
            "the later root's mode, and the tree beneath it kept"
        );
    }

    #[test]
    fn a_layer_over_nothing_is_that_layer() {
        let one = TreeBuilder::new().file(b"/a".to_vec(), b"x".to_vec(), meta());
        assert_eq!(paths(LayeredSource::new().layer(one)), ["/a"]);
        assert!(LayeredSource::new().is_empty());
        assert_eq!(LayeredSource::new().len(), 0);
    }

    #[test]
    fn metadata_ownership_builder() {
        let m = Metadata::new(0o600, Timestamp::from_secs(0)).owned_by(1000, 1000);
        assert_eq!(m.uid, 1000);
        assert_eq!(m.gid, 1000);
        assert_eq!(m.mode, 0o600);
    }

    #[test]
    fn hardlink_records_its_target() {
        let src = TreeBuilder::new()
            .file(b"/a".to_vec(), b"x".to_vec(), meta())
            .hardlink(b"/b".to_vec(), b"/a".to_vec(), meta());
        let entries = src.into_entries();
        match &entries[1].kind {
            EntryKind::HardLink { target } => assert_eq!(target, b"/a"),
            other => panic!("expected hardlink, got {other:?}"),
        }
    }

    #[test]
    fn device_fifo_and_socket_kinds_are_recorded() {
        let entries = TreeBuilder::new()
            .char_device(b"/dev/null".to_vec(), 1, 3, meta())
            .block_device(b"/dev/sda".to_vec(), 8, 0, meta())
            .fifo(b"/run/pipe".to_vec(), meta())
            .socket(b"/run/sock".to_vec(), meta())
            .into_entries();
        assert!(matches!(
            entries[0].kind,
            EntryKind::CharDevice { major: 1, minor: 3 }
        ));
        assert!(matches!(
            entries[1].kind,
            EntryKind::BlockDevice { major: 8, minor: 0 }
        ));
        assert!(matches!(entries[2].kind, EntryKind::Fifo));
        assert!(matches!(entries[3].kind, EntryKind::Socket));
    }

    #[test]
    fn xattr_attaches_to_the_most_recent_entry() {
        let entries = TreeBuilder::new()
            .file(b"/bin/ping".to_vec(), b"elf".to_vec(), meta())
            .xattr(b"security.capability".to_vec(), vec![1, 2, 3, 4])
            .xattr(b"user.note".to_vec(), b"hi".to_vec())
            .file(b"/plain".to_vec(), b"x".to_vec(), meta())
            .into_entries();
        assert_eq!(entries[0].xattrs.len(), 2);
        assert_eq!(entries[0].xattrs[0].name, b"security.capability");
        assert!(entries[1].xattrs.is_empty());
    }

    #[test]
    fn xattr_without_a_preceding_entry_is_a_no_op() {
        let entries = TreeBuilder::new()
            .xattr(b"user.orphan".to_vec(), b"v".to_vec())
            .into_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn every_borrowed_form_of_a_files_bytes_converts() {
        // A caller writing a small file writes it as a literal. Each of these is a shape a
        // literal takes, and every one must reach the same owned entry — an argument that
        // has to be spelled `.to_vec()` is a bound that lost a caller nothing but noise.
        let want = EntryKind::File(FileContent::Owned(b"hi".to_vec()));
        let entries = TreeBuilder::new()
            .file(b"/vec".to_vec(), b"hi".to_vec(), meta())
            .file(b"/array".to_vec(), b"hi", meta())
            .file(b"/slice".to_vec(), &b"hi"[..], meta())
            .file(b"/str".to_vec(), "hi", meta())
            .file(b"/string".to_vec(), String::from("hi"), meta())
            .into_entries();
        assert_eq!(entries.len(), 5);
        for entry in &entries {
            assert_eq!(
                entry.kind,
                want,
                "{} converted to something else",
                String::from_utf8_lossy(&entry.path)
            );
        }
    }

    #[test]
    fn reading_owned_contents_borrows_rather_than_copies() {
        // The whole point of holding contents by value is that a format pays for them
        // once. A read that cloned would double the largest file's cost at exactly the
        // moment its blocks are being chunked, which is the peak the type exists to
        // lower. Pointer identity is what proves no copy happened.
        let content = FileContent::Owned(vec![9u8; 64]);
        let FileContent::Owned(held) = &content else {
            unreachable!("the content is owned")
        };
        let read = content.read().expect("an owned read cannot fail");
        assert!(matches!(read, std::borrow::Cow::Borrowed(_)));
        assert!(std::ptr::eq(read.as_ptr(), held.as_ptr()));
    }

    #[test]
    fn a_short_backing_file_names_itself_and_the_range() {
        // A file replaced in place between building the source and formatting is what
        // this error means, and the message is all a caller gets: `FormatError::Io` is
        // transparent, so a bare "failed to fill whole buffer" would name neither the
        // file that changed nor the bytes that went missing.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("shrunk.tar");
        std::fs::write(&path, b"only eight").expect("write the backing file");
        let file = Arc::new(File::open(&path).expect("open the backing file"));

        let range = FileRange::new(Arc::clone(&file), &path, 4, 4096);
        let err = range
            .read()
            .expect_err("a range past the end cannot be read");
        let text = err.to_string();
        assert!(text.contains("shrunk.tar"), "{text}");
        assert!(text.contains("4096"), "{text}");
        assert!(text.contains("offset 4"), "{text}");
        // The kind survives the added context, so a caller can still tell a truncation
        // from a permission failure without matching on the message.
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // A range the file does hold reads its bytes, and reading allocates.
        let content = FileContent::Range(FileRange::new(file, &path, 5, 5));
        let read = content.read().expect("read the range");
        assert!(matches!(read, std::borrow::Cow::Owned(_)));
        assert_eq!(read.as_ref(), b"eight");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_refused_by_the_flag_this_target_defines() {
        // `O_NOFOLLOW` is one number per architecture, and the number that is wrong for the
        // one being built is not a failure the kernel reports: on arm and aarch64 the value
        // Linux's generic headers give is `O_LARGEFILE`, which every open already implies,
        // so the flag is accepted, ignored, and the link followed. Nothing above this reads
        // as broken — the bytes of whatever the link points at simply arrive as the file's.
        //
        // So the flag is exercised rather than trusted: a range named by a path that is a
        // link must fail to read, on whatever target the suite is running on.
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"pointed at\n").expect("write the target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = FileRange::at_path(&link, 0, 11)
            .read()
            .expect_err("a range naming a link reads nothing");
        // That it failed is the whole claim: a flag the kernel ignored is a read that
        // *succeeds*, holding the target's bytes. Which errno says so is the kernel's to
        // choose — Linux reports `ELOOP` and the BSDs `EMLINK` — so the refusal is checked
        // by the path it names rather than by a number that varies with the platform.
        let text = err.to_string();
        assert!(text.contains("link"), "{text}");

        // The same range on the name the link points at reads it, so what the refusal
        // refuses is the link and not the read.
        assert_eq!(
            FileRange::at_path(&target, 0, 11).read().expect("read"),
            b"pointed at\n"
        );
    }

    #[test]
    fn distinct_times_are_preserved() {
        let m = Metadata::new(0o644, Timestamp::from_secs(100)).with_times(
            Timestamp::from_secs(1),
            Timestamp::from_secs(2),
            Timestamp::from_secs(3),
        );
        assert_eq!(m.atime, Timestamp::from_secs(1));
        assert_eq!(m.ctime, Timestamp::from_secs(2));
        assert_eq!(m.mtime, Timestamp::from_secs(3));
    }
}
