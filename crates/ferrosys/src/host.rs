//! The host filesystem, in both directions: [`DirectorySource`] walks a directory tree into
//! the entries a format consumes, and [`DirectorySink`] writes a filesystem's contents back
//! out as a directory tree.
//!
//! This module is the walk in. The write out is [`sink`], and its own documentation covers
//! what it takes to reproduce a tree faithfully — the privileges, the traversal rules, and
//! the one time no host lets a caller set.
//!
//! The walk carries the fidelity an image builder needs: mode bits, ownership, access,
//! change, and modification times to the nanosecond, symlinks, device and FIFO nodes,
//! sockets, hard links, and extended attributes — including a POSIX ACL, which is carried
//! in the version-2 form the syscall boundary speaks and validated on the way through (see
//! [`crate::acl`]).
//!
//! A regular file's contents become a [`FileRange`] naming the file on the host, read only
//! when that file is placed, so a format's peak memory is the largest single file rather
//! than the tree. No descriptor is held between the walk and the format, so the number of
//! files a tree may hold is bounded by nothing this source imposes.
//!
//! # Determinism
//!
//! Entries are sorted by their path inside the image and extended attributes by name, so
//! the same tree walks to the same entry list whatever order the host's directories are
//! read in. Where several names share an inode, the first in that sorted order carries the
//! contents and the rest become hard links to it.
//!
//! The times an entry carries are the host's. A walk reads every directory and every
//! symlink to learn what it holds, and a host that maintains access times records that
//! read, so the access time a walk reports is the one the host held when that entry was
//! reached. Two walks of one tree agree on everything the walk decides; they agree on
//! access and change times where the host holds those still, as a tree read from a
//! `noatime` mount and left unstaged does.
//!
//! [`times_from_modification`](DirectorySource::times_from_modification) is what makes the
//! times the walk's rather than the host's: it puts each entry's modification time in
//! place of its access and change times, so one tree walks to one image however many
//! times it has been read or restaged.
//!
//! # Ownership
//!
//! Each entry records the uid and gid the host file carries.
//! [`owner`](DirectorySource::owner) replaces them throughout, which is what a build
//! running as an ordinary user wants: without it, every file in the image belongs to the
//! user that built it.
//!
//! # The tree must not change while the source is alive
//!
//! Metadata is read during the walk and a regular file's bytes when that file is placed, so
//! an edit in between reaches the image — as wrong bytes rather than as an error, unless
//! the file shrank enough for the read to run short.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

mod sink;

pub use sink::{DirectorySink, ExtractReport};

use crate::acl::Acl;
use crate::escape::{printable, printable_path};
use crate::source::{EntryKind, FileContent, FileRange, Metadata, Source, SourceEntry};
use crate::time::Timestamp;
use crate::xattr::Xattr;

/// A failure walking a host directory tree.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// A path could not be read: opening it, listing it, reading its metadata, reading a
    /// symlink's target, or reading its extended attributes.
    #[error("{}: {source}", printable_path(.path))]
    #[non_exhaustive]
    Io {
        /// The offending path on the host.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// The root of the walk is not a directory.
    #[error("{}: not a directory", printable_path(.path))]
    #[non_exhaustive]
    NotADirectory {
        /// The path the walk was asked to start from.
        path: PathBuf,
    },
    /// A path is of a kind no filesystem entry represents.
    #[error(
        "{}: has a file type that cannot be written to a filesystem",
        printable_path(.path)
    )]
    #[non_exhaustive]
    Unsupported {
        /// The offending path on the host.
        path: PathBuf,
    },
    /// A `system.posix_acl_*` attribute on the host holds bytes that are not a POSIX ACL.
    #[error("{}: has an invalid ACL: {source}", printable_path(.path))]
    #[non_exhaustive]
    Acl {
        /// The offending path on the host.
        path: PathBuf,
        /// The underlying ACL error.
        #[source]
        source: crate::acl::AclError,
    },
    /// A path's extended attributes changed faster than they could be read.
    ///
    /// Reading one means asking the kernel for its size and then for that many bytes, and a
    /// value that grew in between is asked for again. A path whose attributes keep changing
    /// across every attempt is a tree being edited while it is walked, which is a failure of
    /// the tree rather than of the host: what such a walk would record is neither the tree it
    /// started from nor the one it ended at. It is distinct from [`Io`](Self::Io) so a caller
    /// can tell a tree to settle and walk again apart from a fault it can do nothing about.
    #[error(
        "{}: the {} kept changing while it was read, across {attempts} attempts",
        printable_path(.path),
        unstable_subject(.name)
    )]
    #[non_exhaustive]
    UnstableXattrs {
        /// The offending path on the host.
        path: PathBuf,
        /// The attribute whose value kept changing, or `None` when it was the list of names
        /// itself.
        name: Option<Vec<u8>>,
        /// How many times the read was attempted before it was given up on.
        attempts: usize,
    },
    /// The filesystem being written out could not be read.
    #[error(transparent)]
    #[non_exhaustive]
    Read {
        /// The failure the reader reported.
        source: crate::tree::TreeError,
    },
    /// A file's storage yielded fewer bytes than the length the image records for it, so
    /// the file written to the host would be shorter than the tree says.
    ///
    /// A tree that looks complete and is not is the failure an extraction exists to
    /// prevent, so the file is not left behind looking whole: the short entry is a
    /// refusal naming both lengths.
    #[error(
        "{}: the image records {size} bytes and its storage yielded {got}",
        crate::escape::printable(.path)
    )]
    #[non_exhaustive]
    ShortRead {
        /// The entry's path within the image.
        path: Vec<u8>,
        /// The length the image records.
        size: u64,
        /// The bytes its storage yielded.
        got: u64,
    },
    /// The directory an extraction is to write into already holds something.
    ///
    /// An extraction states what the filesystem holds, so a name already in the destination
    /// is an entry that cannot be created — discovered part-way through, with the tree half
    /// written. Refusing before anything is written is the failure a caller can act on.
    #[error("{}: is not empty", printable_path(.path))]
    #[non_exhaustive]
    NotEmpty {
        /// The destination directory.
        path: PathBuf,
    },
    /// The filesystem holds a name no directory on this host can hold.
    ///
    /// A name carrying a separator, a `..`, or a NUL would name a place the destination does
    /// not contain, so it is refused rather than resolved. Nothing a well-formed filesystem
    /// holds reaches this: it is what makes an image an input rather than an instruction.
    #[error(
        "{}: is a name that cannot be written into a directory",
        printable(.path)
    )]
    #[non_exhaustive]
    HostileName {
        /// The offending path inside the filesystem.
        path: Vec<u8>,
    },
    /// An entry arrived before the directory that holds it.
    ///
    /// Every family's walk emits a parent before its children, which is what lets an
    /// extraction hold one open handle per directory on the current path and create each
    /// name through the handle for its own parent. An entry whose parent is not the
    /// directory currently open is a walk that did not keep that order, and writing it
    /// anyway would create it in whichever directory happens to be on top of the stack.
    ///
    /// Nothing in this crate's readers produces it — it is checked rather than assumed
    /// because of what would follow if it were ever wrong.
    #[error(
        "{}: arrived before the directory that holds it, so there is no directory to \
         create it in",
        printable(.path)
    )]
    #[non_exhaustive]
    OutOfOrder {
        /// The path inside the filesystem whose parent was not the directory being written.
        path: Vec<u8>,
    },
    /// More directories are waiting for their metadata than this extraction will hold open
    /// at once.
    ///
    /// A directory whose recorded mode denies its owner search permission keeps its handle
    /// until the walk is over, because applying that mode would close it to the walk still
    /// going on. Which directories those are is the *image's* choice, so an image whose
    /// directories are all `0o600` asks for one open handle per directory in the tree — and
    /// about eleven hundred of them, four or five mebibytes of image, passes the default
    /// `RLIMIT_NOFILE`. What follows is worse than the stop: the deferred directories never
    /// get their mode or their owner, so the tree is left half written, which is the failure
    /// the deferral was introduced to remove.
    ///
    /// So the wait has a ceiling, and reaching it is a typed refusal that leaves the
    /// destination to the caller rather than a descriptor exhaustion part-way through.
    #[error(
        "more than {limit} directories are waiting for their metadata: this filesystem \
         defers a directory whose mode denies its owner search permission, and holds its \
         handle until the walk is over"
    )]
    #[non_exhaustive]
    TooManyDeferredDirectories {
        /// The most directories one extraction defers.
        limit: usize,
    },
    /// This host will not hold this extended attribute on a node of this kind, whatever
    /// privilege the process has.
    ///
    /// The kernel restricts two attributes by the *type* of what they are set on rather than
    /// by who is setting them: a `user.*` attribute is refused on anything that is not a
    /// regular file or a directory, and a default POSIX ACL is refused on anything that is
    /// not a directory. Both come back as the errno a missing privilege uses, and neither is
    /// one — running as root fails identically. A filesystem that records no such rule can
    /// hold either combination perfectly well, so an image carrying one is not malformed;
    /// this host simply has nowhere to put it.
    ///
    /// [`DirectorySink::skip_privileged`] records it as a dropped attribute instead.
    #[error(
        "{}: this host will not hold {} on a node of this kind, whatever privilege the \
         process has",
        printable(.path),
        printable(.name)
    )]
    #[non_exhaustive]
    UnsupportedAttribute {
        /// The entry the attribute belongs to.
        path: Vec<u8>,
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// Reproducing an entry needs a privilege this process does not have.
    #[error("{}: {what}", printable(.path))]
    #[non_exhaustive]
    Unprivileged {
        /// The offending path inside the filesystem.
        path: Vec<u8>,
        /// What could not be done, and what it would take.
        what: &'static str,
    },
    /// An entry records an owner no host id can be set to: a `chown` reads all-ones as
    /// "leave this one alone", so there is no call that sets it.
    #[error(
        "{}: records owner {uid}:{gid}, which cannot be set",
        printable(.path)
    )]
    #[non_exhaustive]
    UnrepresentableOwner {
        /// The offending path inside the filesystem.
        path: Vec<u8>,
        /// The recorded user id.
        uid: u32,
        /// The recorded group id.
        gid: u32,
    },
    /// Two paths in the tree name one directory, which a bind mount produces.
    #[error(
        "{}: is the same directory as {} — walking it again would write that subtree \
         into the image a second time, and a mount of an ancestor would never end",
        printable_path(.path),
        printable_path(.first)
    )]
    #[non_exhaustive]
    RepeatedDirectory {
        /// The second path found for the directory.
        path: PathBuf,
        /// The path the directory was already reached by.
        first: PathBuf,
    },
}

/// What kept changing, for [`HostError::UnstableXattrs`]'s message: one named attribute's
/// value, or the list of names itself.
fn unstable_subject(name: &Option<Vec<u8>>) -> String {
    match name {
        Some(name) => format!("extended attribute {}", printable(name)),
        None => "list of extended attributes".to_string(),
    }
}

/// A [`Source`] that yields the entries walked from a directory on the host.
///
/// The directory itself becomes the filesystem root: its mode, ownership, times, and
/// extended attributes are the root directory's, and everything under it keeps its path
/// relative to it.
///
/// # Example
///
/// ```no_run
/// use ferrosys::{DirectorySource, Timestamp};
/// use ferrosys::ext::{FormatOptions, format_to};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// // A build running as an ordinary user wants the image owned by root, not by itself.
/// let source = DirectorySource::from_path("staging/rootfs")?.owner(0, 0);
/// let mut out = std::fs::File::create("rootfs.img")?;
/// format_to(source, 512 << 20, FormatOptions::new([0x11; 16], time, [0; 16]), &mut out)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DirectorySource {
    entries: Vec<SourceEntry>,
}

impl DirectorySource {
    /// Walk the directory tree at `root` into a source.
    ///
    /// Symlinks are recorded as symlinks and never followed, so a link pointing outside
    /// the tree is written as the link it is — and that holds of what the *format* reads as
    /// well as of what the walk records: a file's bytes are read at placement time, by a
    /// name, and that open does not follow a link either. A local writer replacing a staged
    /// name with a link between the walk and the placement gets an error rather than the
    /// target's bytes in the image. Every directory below `root` is descended,
    /// including one on another mounted filesystem — but each is descended once: two paths
    /// naming a single directory, which a bind mount produces, is
    /// [`HostError::RepeatedDirectory`] rather than a second copy of that subtree in the
    /// image or, where what is mounted is an ancestor, a walk with no end.
    ///
    /// # Errors
    ///
    /// A [`HostError`] if `root` is not a directory, if any path under it cannot be read,
    /// if a stored ACL cannot be translated, or if one directory is reached by two paths.
    pub fn from_path(root: impl AsRef<Path>) -> Result<Self, HostError> {
        let root = root.as_ref();
        // The root is followed if it is itself a symlink — it names the tree to walk, and
        // a link to a directory names one. Everything inside it is read with the link
        // intact.
        let meta = std::fs::metadata(root).map_err(io_at(root))?;
        if !meta.is_dir() {
            return Err(HostError::NotADirectory {
                path: root.to_path_buf(),
            });
        }

        // Which directory each path reached, by the identity the host gives it. Symlinks
        // are never followed, so the one shape that still puts a directory in the tree
        // twice is a bind mount of it elsewhere under `root` — and where what is mounted
        // is an ancestor, the second walk of it finds the mount again, without end. Each
        // directory is entered once and the second path for one is named as the fault,
        // since an image built from that tree would otherwise hold two copies of a
        // subtree the host holds once.
        let mut entered: BTreeMap<(u64, u64), PathBuf> =
            BTreeMap::from([((meta.dev(), meta.ino()), root.to_path_buf())]);
        // The whole tree is collected before any entry is built, so the sort that fixes
        // which name owns a shared inode happens over the complete list.
        let mut found: Vec<(Vec<u8>, PathBuf, std::fs::Metadata)> =
            vec![(b"/".to_vec(), root.to_path_buf(), meta)];
        // An explicit stack rather than recursion: a tree's depth is the host's to choose,
        // and a deep one must not be a stack overflow.
        let mut pending: Vec<(PathBuf, Vec<u8>)> = vec![(root.to_path_buf(), b"/".to_vec())];
        while let Some((host_dir, image_dir)) = pending.pop() {
            for entry in std::fs::read_dir(&host_dir).map_err(io_at(&host_dir))? {
                let entry = entry.map_err(io_at(&host_dir))?;
                let host_path = entry.path();
                let image_path = join(&image_dir, entry.file_name().as_bytes());
                // `DirEntry::metadata` does not follow symlinks, so a link's own metadata
                // is what is recorded and a link to a directory is not descended into.
                let meta = entry.metadata().map_err(io_at(&host_path))?;
                if meta.is_dir() {
                    match entered.entry((meta.dev(), meta.ino())) {
                        Entry::Occupied(first) => {
                            return Err(HostError::RepeatedDirectory {
                                path: host_path,
                                first: first.get().clone(),
                            });
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(host_path.clone());
                        }
                    }
                    pending.push((host_path.clone(), image_path.clone()));
                }
                found.push((image_path, host_path, meta));
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));

        // The first name for an inode, in sorted path order, carries the file; every later
        // name for it is a hard link to that first one. Directories are excluded: their
        // link counts are `.` and their subdirectories' `..`, not several names.
        let mut first_name: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();
        let mut entries = Vec::with_capacity(found.len());
        for (image_path, host_path, meta) in found {
            let mut linked: Option<Vec<u8>> = None;
            if !meta.is_dir() && meta.nlink() > 1 {
                match first_name.entry((meta.dev(), meta.ino())) {
                    Entry::Occupied(held) => linked = Some(held.get().clone()),
                    Entry::Vacant(slot) => {
                        slot.insert(image_path.clone());
                    }
                }
            }
            let kind = match linked {
                Some(target) => EntryKind::HardLink { target },
                None => kind_of(&host_path, &meta)?,
            };
            // A hard link is another name for an inode the first name already described,
            // so it carries neither metadata nor attributes of its own.
            let (meta, xattrs) = if matches!(kind, EntryKind::HardLink { .. }) {
                (metadata_of(&meta), Vec::new())
            } else {
                (metadata_of(&meta), xattrs_of(&host_path)?)
            };
            entries.push(SourceEntry {
                path: image_path,
                kind,
                meta,
                xattrs,
            });
        }
        Ok(Self { entries })
    }

    /// Replace every entry's ownership with `uid` and `gid`.
    ///
    /// A walk records what the host files carry, which for a build running as an ordinary
    /// user is that user's own ids. `owner(0, 0)` is what makes such a build produce the
    /// root-owned image it means to.
    #[must_use]
    pub fn owner(mut self, uid: u32, gid: u32) -> Self {
        for entry in &mut self.entries {
            entry.meta.uid = uid;
            entry.meta.gid = gid;
        }
        self
    }

    /// Replace every entry's access and change times with its own modification time.
    ///
    /// A walk records all three times the host carries, and two of them move under the
    /// host's feet. Reading a file updates its access time, so a build that reads the tree
    /// is itself enough to change what the next walk records; the change time moves
    /// whenever anything sets a mode, an owner, or a link count, which is what staging a
    /// tree does. The modification time moves only when a file's contents do, so it is the
    /// one that describes the tree rather than the history of the machine holding it.
    ///
    /// This makes a walked entry's times what [`Metadata::new`] gives for that entry's
    /// modification time, so one tree walks to one image however many times it has been
    /// read or restaged. It is the clamp for a build that needs reproducible bytes and
    /// keeps per-file modification times; a family's own `fixed_time` is the clamp for one
    /// that forces every inode to a single time instead.
    ///
    /// The creation time is derived from the modification time by the model, so it follows
    /// without being named here.
    #[must_use]
    pub fn times_from_modification(mut self) -> Self {
        for entry in &mut self.entries {
            entry.meta.atime = entry.meta.mtime;
            entry.meta.ctime = entry.meta.mtime;
        }
        self
    }

    /// The number of entries walked, counting the root directory.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the walk produced no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Source for DirectorySource {
    fn into_entries(self) -> Vec<SourceEntry> {
        self.entries
    }
}

/// Attach a path to an I/O failure, so every message names the file it concerns. Both
/// directions use it: a walk names what could not be read, a sink what could not be written.
fn io_at(path: &Path) -> impl Fn(std::io::Error) -> HostError + '_ {
    move |source| HostError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A child's path inside the image: the parent's, a separator, and the name's bytes. The
/// root is `/`, which already ends in the separator.
fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(parent.len() + 1 + name.len());
    path.extend_from_slice(parent);
    if parent != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// What to write at a path, from the file type the host recorded.
fn kind_of(host_path: &Path, meta: &std::fs::Metadata) -> Result<EntryKind, HostError> {
    use std::os::unix::fs::FileTypeExt;

    let file_type = meta.file_type();
    let kind = if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        // The contents are named, not read: the bytes are fetched when the file is
        // placed, so the walk holds neither them nor a descriptor for them.
        EntryKind::File(FileContent::Range(FileRange::at_path(
            host_path,
            0,
            meta.len(),
        )))
    } else if file_type.is_symlink() {
        let target = std::fs::read_link(host_path).map_err(io_at(host_path))?;
        EntryKind::Symlink(target.as_os_str().as_bytes().to_vec())
    } else if file_type.is_char_device() {
        let (major, minor) = device_numbers(meta.rdev());
        EntryKind::CharDevice { major, minor }
    } else if file_type.is_block_device() {
        let (major, minor) = device_numbers(meta.rdev());
        EntryKind::BlockDevice { major, minor }
    } else if file_type.is_fifo() {
        EntryKind::Fifo
    } else if file_type.is_socket() {
        EntryKind::Socket
    } else {
        return Err(HostError::Unsupported {
            path: host_path.to_path_buf(),
        });
    };
    Ok(kind)
}

/// The mode, ownership, and three times a host inode carries.
fn metadata_of(meta: &std::fs::Metadata) -> Metadata {
    // The mode's low twelve bits are the permission and set-user/group/sticky bits; the
    // file-type bits above them are the entry's kind, which is carried separately.
    let mode = (meta.mode() & 0o7777) as u16;
    Metadata::new(mode, time_of(meta.mtime(), meta.mtime_nsec()))
        .owned_by(meta.uid(), meta.gid())
        .with_times(
            time_of(meta.atime(), meta.atime_nsec()),
            time_of(meta.ctime(), meta.ctime_nsec()),
            time_of(meta.mtime(), meta.mtime_nsec()),
        )
}

/// One host timestamp. A nanosecond field outside its range is a value no filesystem
/// produces; it is clamped to the nearest end of that range rather than allowed to reach the
/// on-disk encoding, which holds thirty bits of it.
fn time_of(secs: i64, nanos: i64) -> Timestamp {
    let nanos = nanos.clamp(0, 999_999_999) as u32;
    Timestamp { secs, nanos }
}

/// The major and minor numbers a Linux `dev_t` encodes.
///
/// The two are interleaved: the minor's low eight bits and the major's low twelve sit in
/// the low word, and the high bits of each follow above them.
fn device_numbers(rdev: u64) -> (u32, u32) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Every extended attribute a path carries, sorted by name.
///
/// A POSIX ACL arrives in the version-2 form the syscall boundary speaks, which ext does
/// not store: it is decoded and re-encoded into the compact form, exactly as an ACL
/// arriving in an archive is. Every other attribute is carried through byte for byte.
///
/// A filesystem that does not support extended attributes reports none rather than
/// failing: a tree on such a filesystem simply has no attributes to carry.
fn xattrs_of(host_path: &Path) -> Result<Vec<Xattr>, HostError> {
    let mut xattrs = Vec::new();
    for name in list_xattrs(host_path)? {
        let Some(value) = get_xattr(host_path, &name)? else {
            // The attribute was removed between the listing and the read. It is not
            // carried, which is what the tree now holds.
            continue;
        };
        // An ACL travels in the form the host handed over, which is the form every boundary
        // speaks. It is parsed anyway: a value the kernel cannot mean is worth refusing here,
        // where the path that holds it is still in hand, rather than at whichever family's
        // edge eventually narrows it.
        if name == Acl::ACCESS_NAME || name == Acl::DEFAULT_NAME {
            Acl::decode(&value).map_err(|source| HostError::Acl {
                path: host_path.to_path_buf(),
                source,
            })?;
        }
        xattrs.push(Xattr { name, value });
    }
    // The kernel lists attributes in the order the filesystem holds them, which is not a
    // property of the tree being walked. Sorting makes the entry a function of what the
    // tree has, not of how it is stored.
    xattrs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(xattrs)
}

/// How many times a size query and its read are retried when the value changes underneath
/// them. Each attempt reads the size the kernel reports and immediately asks for that many
/// bytes; a value that keeps changing is a tree being edited during the walk, which the
/// source does not promise to survive.
const XATTR_ATTEMPTS: usize = 4;

/// The names of a path's extended attributes, from the symlink itself rather than from
/// what it points at.
fn list_xattrs(host_path: &Path) -> Result<Vec<Vec<u8>>, HostError> {
    for _ in 0..XATTR_ATTEMPTS {
        // A zero-length buffer asks for the size rather than the value.
        let size = match rustix::fs::llistxattr(host_path, &mut [0u8; 0][..]) {
            Ok(size) => size,
            Err(e) if unsupported(e) => return Ok(Vec::new()),
            Err(e) => return Err(io_at(host_path)(e.into())),
        };
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size];
        match rustix::fs::llistxattr(host_path, &mut buf[..]) {
            Ok(len) => {
                // The list is the names run together, each terminated by a NUL, so the
                // split leaves a trailing empty element that is not a name.
                return Ok(buf[..len]
                    .split(|&b| b == 0)
                    .filter(|name| !name.is_empty())
                    .map(<[u8]>::to_vec)
                    .collect());
            }
            // The set grew between the size query and the read; ask again.
            Err(rustix::io::Errno::RANGE) => continue,
            Err(e) if unsupported(e) => return Ok(Vec::new()),
            Err(e) => return Err(io_at(host_path)(e.into())),
        }
    }
    Err(HostError::UnstableXattrs {
        path: host_path.to_path_buf(),
        name: None,
        attempts: XATTR_ATTEMPTS,
    })
}

/// One extended attribute's value, or `None` if it is gone by the time it is read.
fn get_xattr(host_path: &Path, name: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
    // An attribute name cannot hold a NUL — the kernel's own list is NUL-separated — so
    // this fails only for a name that came from somewhere else.
    let name = CString::new(name).map_err(|_| HostError::Io {
        path: host_path.to_path_buf(),
        source: std::io::Error::other("an extended-attribute name holds a NUL byte"),
    })?;
    for _ in 0..XATTR_ATTEMPTS {
        let size = match rustix::fs::lgetxattr(host_path, &name, &mut [0u8; 0][..]) {
            Ok(size) => size,
            Err(e) if gone(e) => return Ok(None),
            Err(e) if unsupported(e) => return Ok(None),
            Err(e) => return Err(io_at(host_path)(e.into())),
        };
        if size == 0 {
            // An attribute may legitimately have an empty value.
            return Ok(Some(Vec::new()));
        }
        let mut buf = vec![0u8; size];
        match rustix::fs::lgetxattr(host_path, &name, &mut buf[..]) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(Some(buf));
            }
            // The value grew between the size query and the read; ask again.
            Err(rustix::io::Errno::RANGE) => continue,
            Err(e) if gone(e) => return Ok(None),
            Err(e) => return Err(io_at(host_path)(e.into())),
        }
    }
    Err(HostError::UnstableXattrs {
        path: host_path.to_path_buf(),
        name: Some(name.as_bytes().to_vec()),
        attempts: XATTR_ATTEMPTS,
    })
}

/// Whether the failure is the filesystem saying it holds no extended attributes at all.
fn unsupported(e: rustix::io::Errno) -> bool {
    e == rustix::io::Errno::NOTSUP || e == rustix::io::Errno::OPNOTSUPP
}

/// Whether the failure is the attribute no longer being there.
fn gone(e: rustix::io::Errno) -> bool {
    e == rustix::io::Errno::NODATA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_path_joins_under_the_root() {
        assert_eq!(join(b"/", b"etc"), b"/etc");
        assert_eq!(join(b"/etc", b"hostname"), b"/etc/hostname");
        // A name is bytes, not text, and reaches the path as itself.
        assert_eq!(join(b"/", b"od\xffd"), b"/od\xffd");
    }

    #[test]
    fn device_numbers_are_unpacked_from_the_interleaved_encoding() {
        // The encoding splits both numbers: minor's low eight bits, major's low twelve,
        // then the rest of each above. `/dev/null` is 1:3, `/dev/sda` is 8:0.
        assert_eq!(device_numbers((1 << 8) | 3), (1, 3));
        assert_eq!(device_numbers(8 << 8), (8, 0));
        // A minor past eight bits moves into the high field rather than colliding with
        // the major.
        let rdev = ((259u64 & 0xfff) << 8) | (0x1_2345 & 0xff) | ((0x1_2345 & !0xffu64) << 12);
        assert_eq!(device_numbers(rdev), (259, 0x1_2345));
    }

    #[test]
    fn an_out_of_range_nanosecond_field_does_not_reach_the_encoding() {
        // The on-disk form holds thirty bits of nanoseconds, so a value no filesystem
        // produces is clamped rather than truncated into a different time.
        assert_eq!(
            time_of(5, 999_999_999),
            Timestamp {
                secs: 5,
                nanos: 999_999_999,
            }
        );
        assert_eq!(time_of(5, 2_000_000_000).nanos, 999_999_999);
        assert_eq!(time_of(5, -1).nanos, 0);
        // Both ends clamp to the end they overran, however far past it the value is: an
        // over-large field is the last nanosecond of its second and a negative one the
        // first, rather than either wrapping to the other end.
        assert_eq!(time_of(5, i64::from(u32::MAX) + 1).nanos, 999_999_999);
        assert_eq!(time_of(5, i64::MAX).nanos, 999_999_999);
        assert_eq!(time_of(5, i64::MIN).nanos, 0);
    }

    #[test]
    fn a_churning_xattr_names_itself_and_a_churning_list_says_so() {
        // The two shapes the failure takes. The read that gave up is the one thing a caller
        // acting on this has to know, so each says which it was rather than both reporting
        // the path alone.
        let one = HostError::UnstableXattrs {
            path: PathBuf::from("/tree/file"),
            name: Some(b"user.tag".to_vec()),
            attempts: XATTR_ATTEMPTS,
        };
        assert_eq!(
            one.to_string(),
            format!(
                "/tree/file: the extended attribute user.tag kept changing while it was \
                 read, across {XATTR_ATTEMPTS} attempts"
            )
        );

        let all = HostError::UnstableXattrs {
            path: PathBuf::from("/tree/file"),
            name: None,
            attempts: XATTR_ATTEMPTS,
        };
        assert_eq!(
            all.to_string(),
            format!(
                "/tree/file: the list of extended attributes kept changing while it was \
                 read, across {XATTR_ATTEMPTS} attempts"
            )
        );
    }

    /// The paths a walk produced, in the order it produced them.
    fn paths(source: &DirectorySource) -> Vec<String> {
        source
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect()
    }

    /// The entry at one path inside the image.
    fn at<'a>(source: &'a DirectorySource, path: &[u8]) -> &'a SourceEntry {
        source
            .entries
            .iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("{} was not walked", String::from_utf8_lossy(path)))
    }

    #[test]
    fn a_tree_walks_to_the_root_and_everything_under_it_in_path_order() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir(root.join("etc")).expect("etc");
        std::fs::create_dir_all(root.join("var/log")).expect("var/log");
        std::fs::write(root.join("etc/hostname"), b"ferrosys\n").expect("hostname");
        std::os::unix::fs::symlink("/proc/mounts", root.join("etc/mtab")).expect("mtab");

        let source = DirectorySource::from_path(root).expect("walk the tree");
        // Sorted by path, whatever order the host's directories were read in, and the
        // root — the directory the walk started from — is an entry of its own.
        assert_eq!(
            paths(&source),
            [
                "/",
                "/etc",
                "/etc/hostname",
                "/etc/mtab",
                "/var",
                "/var/log"
            ]
        );
        assert_eq!(source.len(), 6);
        assert!(!source.is_empty());

        assert!(matches!(at(&source, b"/").kind, EntryKind::Directory));
        assert!(matches!(
            at(&source, b"/var/log").kind,
            EntryKind::Directory
        ));
        // A symlink is recorded as the link it is, never followed.
        match &at(&source, b"/etc/mtab").kind {
            EntryKind::Symlink(target) => assert_eq!(target, b"/proc/mounts"),
            other => panic!("expected a symlink, got {other:?}"),
        }
    }

    #[test]
    fn a_regular_files_contents_are_named_rather_than_read() {
        // The peak memory of a format is the largest single file only if the walk holds no
        // file's bytes: what it records is where they are.
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("motd"), b"welcome\n").expect("motd");

        let source = DirectorySource::from_path(dir.path()).expect("walk the tree");
        match &at(&source, b"/motd").kind {
            EntryKind::File(FileContent::Range(range)) => {
                assert_eq!(range.len(), 8);
                assert_eq!(range.offset(), 0);
                assert_eq!(range.path(), dir.path().join("motd"));
                assert_eq!(range.read().expect("read the file"), b"welcome\n");
            }
            other => panic!("expected a located file, got {other:?}"),
        }
    }

    #[test]
    fn several_names_for_one_inode_become_hard_links_to_the_first() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::write(root.join("b-original"), b"shared\n").expect("write");
        std::fs::hard_link(root.join("b-original"), root.join("a-link")).expect("hard link");
        std::fs::hard_link(root.join("b-original"), root.join("c-link")).expect("hard link");

        let source = DirectorySource::from_path(root).expect("walk the tree");
        // Sorted path order decides which name carries the file, so the answer does not
        // depend on the order the host listed the directory in.
        assert!(matches!(
            at(&source, b"/a-link").kind,
            EntryKind::File(FileContent::Range(_))
        ));
        for name in [&b"/b-original"[..], b"/c-link"] {
            match &at(&source, name).kind {
                EntryKind::HardLink { target } => assert_eq!(target, b"/a-link"),
                other => panic!(
                    "{} should be a hard link, got {other:?}",
                    String::from_utf8_lossy(name)
                ),
            }
        }
    }

    #[test]
    fn a_directory_is_never_taken_for_a_hard_link() {
        // Every directory has a link count above one — its own `.`, and its parent's entry
        // for it — which is not several names for one inode.
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(dir.path().join("etc")).expect("etc");
        std::fs::create_dir(dir.path().join("etc/ssl")).expect("ssl");

        let source = DirectorySource::from_path(dir.path()).expect("walk the tree");
        for entry in &source.entries {
            assert!(
                matches!(entry.kind, EntryKind::Directory),
                "{} is not a directory",
                String::from_utf8_lossy(&entry.path)
            );
        }
    }

    #[test]
    fn metadata_and_ownership_come_from_the_host_until_owner_replaces_them() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("sh");
        std::fs::write(&file, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).expect("chmod");

        let source = DirectorySource::from_path(dir.path()).expect("walk the tree");
        let entry = at(&source, b"/sh");
        // The permission and set-user bits, without the file-type bits above them.
        assert_eq!(entry.meta.mode, 0o4755);
        // The times are the host's, to the nanosecond, and all three are carried.
        let meta = std::fs::symlink_metadata(&file).expect("stat");
        assert_eq!(entry.meta.mtime, time_of(meta.mtime(), meta.mtime_nsec()));
        assert_eq!(entry.meta.atime, time_of(meta.atime(), meta.atime_nsec()));
        assert_eq!(entry.meta.ctime, time_of(meta.ctime(), meta.ctime_nsec()));
        assert_eq!(entry.meta.uid, meta.uid());

        // A build running as an ordinary user wants the image owned by root instead.
        let owned = DirectorySource::from_path(dir.path())
            .expect("walk the tree")
            .owner(0, 0);
        assert!(
            owned
                .entries
                .iter()
                .all(|e| e.meta.uid == 0 && e.meta.gid == 0)
        );
    }

    #[test]
    fn a_fifo_and_a_socket_are_carried_as_themselves() {
        let dir = tempfile::tempdir().expect("temp dir");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join("pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .expect("make a fifo");
        let _socket =
            std::os::unix::net::UnixListener::bind(dir.path().join("sock")).expect("bind a socket");

        let source = DirectorySource::from_path(dir.path()).expect("walk the tree");
        assert!(matches!(at(&source, b"/pipe").kind, EntryKind::Fifo));
        assert!(matches!(at(&source, b"/sock").kind, EntryKind::Socket));
    }

    #[test]
    fn a_root_that_is_not_a_directory_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").expect("write");
        match DirectorySource::from_path(&file).err() {
            Some(HostError::NotADirectory { path }) => assert_eq!(path, file),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // A path that is not there at all names itself in the failure.
        let missing = dir.path().join("nowhere");
        match DirectorySource::from_path(&missing).err() {
            Some(HostError::Io { path, .. }) => assert_eq!(path, missing),
            other => panic!("expected an I/O failure, got {other:?}"),
        }
    }

    #[test]
    fn extended_attributes_are_carried_in_name_order_and_an_acl_keeps_its_boundary_form() {
        use crate::acl::{AclEntry, AclQualifier};

        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("ping");
        std::fs::write(&file, b"elf").expect("write");

        // The two names are set in the reverse of the order they must come out in.
        let set = |name: &str, value: &[u8]| {
            rustix::fs::lsetxattr(&file, name, value, rustix::fs::XattrFlags::empty())
        };
        if let Err(e) = set("user.note", b"second") {
            // A filesystem without extended attributes cannot carry this test's subject.
            // The skip is reported rather than passing silently.
            eprintln!(
                "SKIPPED: {} holds no extended attributes: {e}",
                file.display()
            );
            return;
        }
        set("security.capability", b"first")
            .or_else(|e| {
                // Only a privileged process may write the security namespace; the ordering
                // this checks does not depend on that one attribute.
                eprintln!("note: security.capability not writable here: {e}");
                Ok::<(), rustix::io::Errno>(())
            })
            .expect("the fallback cannot fail");

        // A stored ACL arrives in the version-2 form the syscall boundary speaks, and the
        // walk carries it in that form: narrowing it is the business of whichever family
        // the entry is eventually written to. It names a user beyond the owner, since an
        // ACL that says no more than the mode bits do is not stored at all.
        let acl = Acl::new(vec![
            AclEntry {
                who: AclQualifier::UserObj,
                perm: Acl::READ | Acl::WRITE | Acl::EXEC,
            },
            AclEntry {
                who: AclQualifier::User(1000),
                perm: Acl::READ | Acl::WRITE,
            },
            AclEntry {
                who: AclQualifier::GroupObj,
                perm: Acl::READ | Acl::EXEC,
            },
            AclEntry {
                who: AclQualifier::Mask,
                perm: Acl::READ | Acl::WRITE | Acl::EXEC,
            },
            AclEntry {
                who: AclQualifier::Other,
                perm: Acl::READ,
            },
        ])
        .expect("a well-formed ACL");
        let v2 = acl.encode();
        let has_acl = set("system.posix_acl_access", &v2).is_ok();

        let source = DirectorySource::from_path(dir.path()).expect("walk the tree");
        let entry = at(&source, b"/ping");
        let names: Vec<&[u8]> = entry.xattrs.iter().map(|x| x.name.as_slice()).collect();
        assert!(
            names.windows(2).all(|w| w[0] < w[1]),
            "the attributes are in name order: {names:?}"
        );
        let note = entry
            .xattrs
            .iter()
            .find(|x| x.name == b"user.note")
            .expect("the attribute set on the file");
        assert_eq!(note.value, b"second");

        if has_acl {
            let stored = entry
                .xattrs
                .iter()
                .find(|x| x.name == Acl::ACCESS_NAME)
                .expect("the ACL set on the file");
            assert_eq!(
                stored.value, v2,
                "the walk carries the form the host handed over"
            );
            // What a family then narrows it to is that family's own test to write; this
            // module has no business naming one.
        } else {
            eprintln!("SKIPPED: {} holds no POSIX ACL", file.display());
        }
    }

    #[test]
    fn every_directory_in_an_ordinary_tree_is_its_own() {
        // The walk-once rule is over the identity the host gives a directory, so distinct
        // directories — including ones under a name shared with a file elsewhere, and an
        // empty one — are each entered on their own.
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/log")).expect("a/log");
        std::fs::create_dir_all(root.join("b/log")).expect("b/log");
        std::fs::create_dir(root.join("empty")).expect("empty");
        std::fs::write(root.join("a/log/messages"), b"\n").expect("messages");

        let source = DirectorySource::from_path(root).expect("walk the tree");
        assert_eq!(
            paths(&source),
            [
                "/",
                "/a",
                "/a/log",
                "/a/log/messages",
                "/b",
                "/b/log",
                "/empty"
            ]
        );
    }

    #[test]
    fn one_directory_under_two_paths_names_both_of_them() {
        // A bind mount is what puts a directory in a tree twice, and making one needs
        // privileges this gate does not have — so what is asserted here is the report,
        // which is the part a caller acts on: it names the path that was refused and the
        // path the directory was already reached by, so the tree can be fixed.
        let said = HostError::RepeatedDirectory {
            path: PathBuf::from("/staging/rootfs/mnt"),
            first: PathBuf::from("/staging/rootfs"),
        }
        .to_string();
        assert!(said.contains("/staging/rootfs/mnt"), "{said}");
        assert!(said.contains("/staging/rootfs"), "{said}");
    }
}
