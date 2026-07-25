//! What populates a filesystem: the [`Source`] trait and a programmatic builder.
//!
//! A source yields a flat list of entries — a path, a kind, and the ownership,
//! mode, and timestamp to record — that the model turns into an inode tree. This
//! module defines that vocabulary and one source, the in-memory [`TreeBuilder`];
//! an archive source is a separate, feature-gated implementation of the same
//! trait.
//!
//! A source states what it wants written; whether the current feature profile can
//! represent it is decided when the model consumes it. An input the profile cannot
//! hold — a name over 255 bytes, an unresolvable hard link — becomes a typed error
//! there, never a silently dropped or truncated entry.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ondisk::{Timestamp, Xattr};

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
    /// # Errors
    ///
    /// [`std::io::Error`] if the backing file cannot be read — including the case where
    /// it is shorter than the range claims, which means the file changed after the source
    /// that named it was built.
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Owned(bytes) => Ok(bytes.clone()),
            Self::Range(range) => range.read(),
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

/// A range of bytes within a file on the host, held open for the length of a format.
///
/// The handle owns its share of the open file, so an entry carrying one is a plain owned
/// value: no lifetime parameter reaches [`SourceEntry`], and a caller may hold, clone,
/// sort, and splice a list of them freely.
///
/// # The file must not change while the source is alive
///
/// The bytes are read when the file is placed, not when the source is built, so an edit
/// in between reaches the image. Holding the descriptor open narrows this usefully: a
/// replacement written to a new file and renamed into place leaves the original inode
/// readable and the format unaffected. What does reach the image is an **in-place**
/// modification or a truncation of the same inode — and it reaches it as wrong bytes
/// rather than as an error, unless the file shrank enough for the read to run short.
#[derive(Clone)]
pub struct FileRange {
    /// The open file. Shared so a handle is owned rather than borrowed, and so a whole
    /// archive's worth of handles costs one descriptor.
    file: Arc<File>,
    /// The path it was opened from, for diagnostics and identity.
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
            file,
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
    /// # Errors
    ///
    /// [`std::io::Error`] if the file cannot be read, or if it is shorter than the range
    /// claims — which is what a file edited after the source was built looks like.
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        let len = usize::try_from(self.len).map_err(|_| {
            std::io::Error::other(format!(
                "{}: {} bytes at offset {} is more than this platform addresses",
                self.path.display(),
                self.len,
                self.offset
            ))
        })?;
        // An independent descriptor, so the read carries its own cursor: a shared one
        // would make two handles into the same file interfere.
        let mut handle = self.file.try_clone()?;
        handle.seek(SeekFrom::Start(self.offset))?;
        let mut buf = vec![0u8; len];
        handle.read_exact(&mut buf)?;
        Ok(buf)
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
    /// its value. Empty for an entry with none.
    pub xattrs: Vec<Xattr>,
}

/// Something that produces the entries to write into a filesystem.
///
/// The model consumes a source once. An archive parser and the in-memory
/// [`TreeBuilder`] are both sources; the model does not care which.
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
