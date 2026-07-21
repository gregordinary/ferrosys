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

use crate::ondisk::{Timestamp, Xattr};

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
    /// A regular file with the given contents.
    File(Vec<u8>),
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
        contents: impl Into<Vec<u8>>,
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
