//! Writing a filesystem's contents back out as a directory tree: the [`DirectorySink`].
//!
//! This is [`DirectorySource`](crate::host::DirectorySource) in the other direction, and the
//! two are a pair — what this writes, that reads, and a tree that makes the round trip
//! describes the same filesystem at both ends.
//!
//! # The image is untrusted
//!
//! A filesystem being read back was written by someone else, and every name in it is an
//! input. Nothing this module writes is reached by resolving a path through the destination
//! tree: each directory is created and then *opened*, and every file, link, and node beneath
//! it is created through that open handle by its single-component name, checked to be one a
//! directory can hold. A name that is not — one holding a separator, a `..`, or a NUL — is
//! refused rather than resolved. So an entry cannot name a place outside the destination,
//! and no directory this writes into is one it did not itself create.
//!
//! One call is spelled as a path, because Linux has no `setxattr` that takes a directory
//! handle before 6.13: an extended attribute on something that cannot be opened — a symbolic
//! link, a device node — is set through `/proc/self/fd/<n>/<name>`, where `<n>` is the held
//! handle to the directory the name is in. The kernel resolves that to the directory the
//! handle already refers to, so the components between the destination and the entry are not
//! walked again and nothing swapped into the tree mid-extraction can redirect the write.
//!
//! Symbolic links are a separate matter, and they are written exactly as the image records
//! them: a link pointing at `/etc/passwd` or at `../../..` is that link, and reproducing it
//! is what an extraction is for. It is safe because nothing here ever follows one — every
//! handle is opened `O_NOFOLLOW` and every attribute is set on the link itself.
//!
//! # What a process may not do
//!
//! Three parts of a tree take privileges: a device node needs `CAP_MKNOD`, setting a file's
//! recorded owner needs `CAP_CHOWN`, and an extended attribute in the `security` or `trusted`
//! namespace is the host's to write rather than an ordinary process's. By default a host that
//! refuses any of them is an error naming the entry, so an extraction that cannot reproduce
//! the tree says so instead of quietly producing a different one.
//! [`skip_privileged`](DirectorySink::skip_privileged) is the opt-in for an unprivileged
//! extraction that wants what it can have: what was left out comes back in the
//! [`ExtractReport`], never in silence.
//!
//! The reserved attributes are not an edge case. A Debian root filesystem carries
//! `security.capability` on the binaries that hold one, and a tree built under SELinux carries
//! `security.selinux` on nearly every inode, so an unprivileged extraction of a real root
//! filesystem meets this before it meets anything else.
//!
//! # What no extraction can carry
//!
//! An inode's change time is the kernel's to set, so a tree written here carries the time it
//! was written rather than the one recorded. Access and modification times are set exactly,
//! to the nanosecond. `/lost+found` is not written: every filesystem makes it for itself, and
//! a tree carrying one would be a tree a format refuses to read back.
//!
//! # Memory
//!
//! A file's bytes are streamed from the filesystem into the destination a window at a time,
//! so extracting a tree far larger than memory costs the working set of one read. What
//! accumulates over the walk is one open handle per directory on the current path — depth,
//! not size — and one path per inode that has more than one name.

use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Gid, Mode, OFlags, Timespec, Timestamps, Uid};

use crate::acl::Acl;
use crate::host::HostError;
use crate::ondisk::{Inode, Timestamp, Xattr};
use crate::read::{ReadError, Reader};

/// `/lost+found`, the one path an extraction must not write: every filesystem makes it for
/// itself, and a source that tries to make it again is refused.
const LOST_FOUND: &[u8] = b"/lost+found";

/// The file-type bits of a mode, and the types they name.
const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFREG: u16 = 0o100000;
const IFLNK: u16 = 0o120000;
const IFCHR: u16 = 0o020000;
const IFBLK: u16 = 0o060000;
const IFIFO: u16 = 0o010000;
const IFSOCK: u16 = 0o140000;

/// The mode a directory is created with, before its children are written.
///
/// A directory whose recorded mode denies its owner write or search permission still has to
/// receive its contents, so it is made writable and made itself once its children are in
/// place. Nothing else may enter it in between: the mode is narrower than most trees record,
/// not wider.
const BUILDING: Mode = Mode::from_bits_retain(0o700);

/// How many bytes of a file move at a time. Large enough that a big file is not a syscall
/// per block, small enough that the buffer is not worth thinking about.
const WINDOW: usize = 1 << 20;

/// What an extraction wrote, and what it left out.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct ExtractReport {
    /// Names written into the destination, not counting the destination directory itself.
    pub written: u64,
    /// The paths not written because this process may not create them, in the image's own
    /// spelling. Empty unless [`skip_privileged`](DirectorySink::skip_privileged) was set —
    /// without it, the first such entry is an error instead.
    pub skipped: Vec<Vec<u8>>,
    /// Whether any entry's recorded ownership could not be applied, so the tree is owned by
    /// the process that wrote it. Only ever true under
    /// [`skip_privileged`](DirectorySink::skip_privileged).
    pub ownership_dropped: bool,
    /// Whether any extended attribute could not be set because this process may not write it,
    /// so an entry carrying one is written without it. `security.capability` on a setuid-free
    /// binary and `security.selinux` on a labelled tree are the ones a root filesystem
    /// carries. Only ever true under [`skip_privileged`](DirectorySink::skip_privileged).
    ///
    /// A flag rather than a list of paths, as
    /// [`ownership_dropped`](Self::ownership_dropped) is: an SELinux-labelled tree carries a
    /// reserved attribute on nearly every inode, and naming each would make what an extraction
    /// holds grow with the size of the tree.
    pub xattrs_dropped: bool,
}

/// Writes a filesystem's contents out as a directory tree on this host.
///
/// The counterpart to [`DirectorySource`](crate::host::DirectorySource): one walks a tree
/// into a filesystem, this writes a filesystem back out as a tree.
///
/// The destination is an existing empty directory, and it becomes the filesystem's root: its
/// mode, ownership, times, and extended attributes are set to the root directory's, and
/// everything the filesystem holds appears beneath it at the path it holds inside the image.
///
/// ```no_run
/// # use ferrosys::ext::{DirectorySink, Reader};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut reader = Reader::open(std::fs::File::open("rootfs.img")?)?;
/// std::fs::create_dir("unpacked")?;
/// let report = DirectorySink::new("unpacked")?.write_tree(&mut reader)?;
/// println!("{} names written", report.written);
/// # Ok(())
/// # }
/// ```
pub struct DirectorySink {
    /// The destination, held open so every write is relative to it and never to a path.
    root: OwnedFd,
    /// What the destination is called, for the failures that name it.
    root_path: PathBuf,
    skip_privileged: bool,
}

impl DirectorySink {
    /// A sink that writes into the directory at `root`, which must exist and be empty.
    ///
    /// Empty, because an extraction states what the filesystem holds: a name already in the
    /// destination would be an entry that cannot be created, discovered part-way through
    /// with the tree half written. Refusing at the start is the failure a caller can act on.
    ///
    /// # Errors
    ///
    /// [`HostError::NotADirectory`] if `root` is not one, [`HostError::NotEmpty`] if it holds
    /// anything, and [`HostError::Io`] if it cannot be opened or listed.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, HostError> {
        let root_path = root.as_ref().to_path_buf();
        let meta = std::fs::metadata(&root_path).map_err(io_at(&root_path))?;
        if !meta.is_dir() {
            return Err(HostError::NotADirectory { path: root_path });
        }
        let mut listing = std::fs::read_dir(&root_path).map_err(io_at(&root_path))?;
        if listing.next().is_some() {
            return Err(HostError::NotEmpty { path: root_path });
        }
        let fd = rustix::fs::open(
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io_at(&root_path)(e.into()))?;
        Ok(Self {
            root: fd,
            root_path,
            skip_privileged: false,
        })
    }

    /// Write what this process may, rather than failing on what it may not.
    ///
    /// A device node needs `CAP_MKNOD`, a recorded owner needs `CAP_CHOWN`, and an extended
    /// attribute in the `security` or `trusted` namespace needs a privilege of its own, so an
    /// extraction running as an ordinary user cannot reproduce a root filesystem exactly.
    /// Without this it says so and stops, which is right when the tree is meant to be
    /// faithful. With it, a node the host refuses to make is left out, the tree is owned by
    /// the process that wrote it, and an attribute the host reserves is not set — and the
    /// [`ExtractReport`] names every path that was skipped and flags each of the other two,
    /// so what the tree is missing is reported rather than assumed.
    #[must_use]
    pub fn skip_privileged(mut self) -> Self {
        self.skip_privileged = true;
        self
    }

    /// Write the filesystem's whole tree into the destination.
    ///
    /// The destination directory takes the filesystem root's own mode, ownership, times, and
    /// extended attributes; `/lost+found` and everything under it is omitted. Every other
    /// name the filesystem holds is written exactly once, with the second and later names for
    /// one inode created as hard links to the first.
    ///
    /// A directory's mode, ownership, and times are applied once its children are in place,
    /// so a directory the image records as read-only is still one its contents could be
    /// written into.
    ///
    /// # Errors
    ///
    /// [`HostError::Read`] if the filesystem cannot be read; [`HostError::Io`] if the
    /// destination cannot be written; [`HostError::HostileName`] if the image holds a name a
    /// directory cannot; [`HostError::Unprivileged`] if the tree needs a privilege this
    /// process does not have and [`skip_privileged`](Self::skip_privileged) was not set; and
    /// [`HostError::Acl`] if a stored POSIX ACL does not decode.
    pub fn write_tree<R: Read + Seek>(
        self,
        reader: &mut Reader<R>,
    ) -> Result<ExtractReport, HostError> {
        let mut state = Extraction {
            sink: &self,
            report: ExtractReport::default(),
            named: HashMap::new(),
            open: Vec::new(),
        };

        // The root has no name, so the walk does not reach it: the destination directory is
        // what carries its mode, ownership, times, and attributes across. It goes on the
        // stack under the empty path, which is what every top-level entry's parent is.
        let root = reader.inode(ROOT_INO)?;
        let xattrs = reader.xattrs(&root)?;
        state.set_xattrs_on_fd(&self.root, &xattrs, b"/")?;
        state.open.push(OpenDir {
            path: Vec::new(),
            fd: rustix::fs::openat(
                &self.root,
                c".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| state.io(b"/", e.into()))?,
            inode: root,
        });

        // Walked entry by entry rather than gathered, so what an extraction holds does not
        // grow with the number of names in the tree. The walk is depth-first with a parent
        // before its children, which is what lets the open handles be a stack.
        reader.walk_with(|reader, entry| {
            if is_lost_found(&entry.path) {
                return Ok(());
            }
            state.write_entry(reader, entry)
        })?;

        // Everything still open is a directory whose children are all written.
        while let Some(dir) = state.open.pop() {
            state.finish_directory(&dir)?;
        }
        Ok(state.report)
    }
}

/// The root directory's inode number.
const ROOT_INO: u32 = 2;

/// A directory that has been created and is still being filled.
struct OpenDir {
    /// Its path inside the image: `/etc`, and empty for the destination itself.
    path: Vec<u8>,
    /// The handle every child of it is created through.
    fd: OwnedFd,
    /// What the image says it is, applied once its children are written.
    inode: Inode,
}

/// One run of [`DirectorySink::write_tree`]: what has been written, and where it is being
/// written to.
struct Extraction<'a> {
    sink: &'a DirectorySink,
    report: ExtractReport,
    /// The first name to reach each inode. A later name for one is a hard link to it.
    named: HashMap<u32, Vec<u8>>,
    /// The directories on the path currently being written, outermost first. The last is the
    /// one the next entry goes into.
    open: Vec<OpenDir>,
}

impl Extraction<'_> {
    /// Write one name.
    fn write_entry<R: Read + Seek>(
        &mut self,
        reader: &mut Reader<R>,
        entry: crate::read::WalkEntry,
    ) -> Result<(), HostError> {
        let (parent, name) = split(&entry.path)?;
        // Every directory deeper than this entry's parent is finished: the walk is
        // depth-first, so nothing will be added to one again.
        while self.open.len() > 1 && self.open[self.open.len() - 1].path != parent {
            let dir = self.open.pop().expect("the loop checked the length");
            self.finish_directory(&dir)?;
        }
        if self.open.last().map(|d| d.path.as_slice()) != Some(parent) {
            // The walk emits a parent before its children, so this is unreachable for a tree
            // the walk produced. It is checked rather than assumed because what follows
            // writes into whatever handle is on top of the stack.
            return Err(HostError::HostileName {
                path: entry.path.clone(),
            });
        }

        let kind = entry.inode.mode & IFMT;
        // A directory has more than one link by construction — its own name and its `.` — so
        // its link count says nothing, and it is never another name for anything.
        if kind != IFDIR
            && let Some(first) = self.named.get(&entry.number)
        {
            let first = first.clone();
            self.link(&first, name, &entry.path)?;
            self.report.written += 1;
            return Ok(());
        }

        // A regular file is the one kind that leaves a handle behind, since writing it is
        // what opened one; its attributes and metadata go through that rather than through
        // its name. Nothing else can be opened without either following it or having an
        // effect of its own.
        let handle = match kind {
            IFDIR => {
                self.make_directory(name, &entry)?;
                None
            }
            IFREG => Some(self.write_file(reader, name, &entry)?),
            IFLNK => {
                let target = reader.read_symlink(&entry.inode)?;
                self.make_symlink(&target, name, &entry)?;
                None
            }
            IFCHR | IFBLK => {
                let (major, minor) = reader.device(&entry.inode);
                let file_type = if kind == IFCHR {
                    FileType::CharacterDevice
                } else {
                    FileType::BlockDevice
                };
                if !self.make_node(file_type, rustix::fs::makedev(major, minor), name, &entry)? {
                    return Ok(());
                }
                None
            }
            IFIFO => {
                if !self.make_node(FileType::Fifo, 0, name, &entry)? {
                    return Ok(());
                }
                None
            }
            IFSOCK => {
                if !self.make_node(FileType::Socket, 0, name, &entry)? {
                    return Ok(());
                }
                None
            }
            _ => {
                return Err(HostError::Unsupported {
                    path: under_root(&self.sink.root_path, &entry.path),
                });
            }
        };

        // Now that the name exists, it is the one a later name for this inode links from.
        // Recorded here rather than before the entry was made, because a node the host
        // refused was skipped: linking to it would fail for want of a name rather than
        // report the privilege that was actually missing. Only an inode the image says has
        // more than one name is held, so what this accumulates is the tree's hard links
        // rather than a path per file in it.
        if kind != IFDIR && entry.inode.links_count > 1 {
            self.named.insert(entry.number, entry.path.clone());
        }

        // A directory's own metadata waits until its children are written; everything else
        // is finished the moment it exists.
        match (kind, &handle) {
            (IFDIR, _) => {}
            (_, Some(fd)) => {
                let xattrs = reader.xattrs(&entry.inode)?;
                self.set_xattrs_on_fd(fd, &xattrs, &entry.path)?;
                self.finish_fd(fd, &entry.inode, &entry.path)?;
            }
            (_, None) => {
                let xattrs = reader.xattrs(&entry.inode)?;
                self.set_xattrs_by_name(name, &xattrs, &entry.path)?;
                self.finish_name(name, &entry.inode, &entry.path, kind == IFLNK)?;
            }
        }
        self.report.written += 1;
        Ok(())
    }

    /// The handle the entry being written goes into.
    fn dir(&self) -> &OwnedFd {
        &self
            .open
            .last()
            .expect("the destination itself is never popped")
            .fd
    }

    /// Create a directory and open it, so its children are written through a handle rather
    /// than through its name.
    fn make_directory(
        &mut self,
        name: &[u8],
        entry: &crate::read::WalkEntry,
    ) -> Result<(), HostError> {
        rustix::fs::mkdirat(self.dir(), name, BUILDING)
            .map_err(|e| self.io(&entry.path, e.into()))?;
        let fd = rustix::fs::openat(
            self.dir(),
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| self.io(&entry.path, e.into()))?;
        self.open.push(OpenDir {
            path: entry.path.clone(),
            fd,
            inode: entry.inode.clone(),
        });
        Ok(())
    }

    /// Set a directory's ownership, mode, and times, now that everything inside it is
    /// written — which is what the wait is for: a directory whose recorded mode denies its
    /// owner write or search permission still had to receive its contents.
    fn finish_directory(&mut self, dir: &OpenDir) -> Result<(), HostError> {
        // The path a failure names: the image path this directory holds, or the destination
        // itself for the root, whose path inside the image is empty.
        let path: &[u8] = if dir.path.is_empty() { b"/" } else { &dir.path };
        self.finish_fd(&dir.fd, &dir.inode, path)
    }

    /// Create a regular file and stream its contents into it, returning the handle its
    /// attributes and metadata are then set through.
    ///
    /// The bytes written are the file's contents as the filesystem reports them, and a hole
    /// reads as zeros — so a sparse file lands in the destination fully allocated, and a tree
    /// holding one occupies more space on the host than it does in the image. What is written
    /// is what a reader of either sees.
    fn write_file<R: Read + Seek>(
        &mut self,
        reader: &mut Reader<R>,
        name: &[u8],
        entry: &crate::read::WalkEntry,
    ) -> Result<OwnedFd, HostError> {
        // `EXCL` is what makes this a file this run created: nothing already at the name is
        // opened, written through, or followed.
        let fd = rustix::fs::openat(
            self.dir(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_retain(0o600),
        )
        .map_err(|e| self.io(&entry.path, e.into()))?;

        let mut out = std::fs::File::from(fd);
        let mut buf = vec![0u8; WINDOW];
        let mut offset = 0u64;
        loop {
            let filled = reader.read_into(&entry.inode, offset, &mut buf)?;
            if filled == 0 {
                break;
            }
            out.write_all(&buf[..filled])
                .map_err(|e| self.io(&entry.path, e))?;
            offset += filled as u64;
        }
        Ok(OwnedFd::from(out))
    }

    /// Create a symbolic link holding exactly the target the image records.
    ///
    /// The target is written as it stands, absolute or `..`-relative or neither: reproducing
    /// the link is the whole point, and nothing here ever resolves one.
    fn make_symlink(
        &mut self,
        target: &[u8],
        name: &[u8],
        entry: &crate::read::WalkEntry,
    ) -> Result<(), HostError> {
        rustix::fs::symlinkat(target, self.dir(), name).map_err(|e| self.io(&entry.path, e.into()))
    }

    /// Create a device node, FIFO, or socket. Reports whether it was created: a node this
    /// process may not make is skipped rather than made under
    /// [`DirectorySink::skip_privileged`].
    ///
    /// A device node is the one of the three that ordinarily needs a privilege, but all
    /// three answer a refusal the same way — a caller that asked for what it could have gets
    /// a report of what it did not, whichever kind of node the host declined.
    fn make_node(
        &mut self,
        file_type: FileType,
        dev: rustix::fs::Dev,
        name: &[u8],
        entry: &crate::read::WalkEntry,
    ) -> Result<bool, HostError> {
        match rustix::fs::mknodat(self.dir(), name, file_type, mode_of(&entry.inode), dev) {
            Ok(()) => Ok(true),
            Err(e) if forbidden(e) => {
                if !self.sink.skip_privileged {
                    return Err(HostError::Unprivileged {
                        path: entry.path.clone(),
                        what: match file_type {
                            FileType::CharacterDevice | FileType::BlockDevice => {
                                "a device node needs CAP_MKNOD to create"
                            }
                            _ => "this host refuses to create a node of this kind",
                        },
                    });
                }
                self.report.skipped.push(entry.path.clone());
                Ok(false)
            }
            Err(e) => Err(self.io(&entry.path, e.into())),
        }
    }

    /// Create another name for a file already written, from the path that first named it.
    ///
    /// The first name's directory is re-opened one component at a time from the destination,
    /// since the walk has usually left it behind by the time a second name for it appears.
    /// Opening it that way rather than joining the path keeps the rule the whole module holds
    /// to: every write goes through a handle to a directory this run created.
    fn link(&mut self, first: &[u8], name: &[u8], path: &[u8]) -> Result<(), HostError> {
        let (first_parent, first_name) = split(first)?;
        let parent = self.open_dir(first_parent, path)?;
        rustix::fs::linkat(&parent, first_name, self.dir(), name, AtFlags::empty())
            .map_err(|e| self.io(path, e.into()))
    }

    /// Open the directory at `path` inside the destination, descending one component at a
    /// time and following nothing. `blame` is the entry a failure is reported against.
    ///
    /// `O_PATH`, because this asks for a handle to traverse from and nothing more. Opening a
    /// directory for reading needs the read bit, and by the time a second name for an inode
    /// appears the first name's directory has been finished and carries the mode the image
    /// records — which a real tree is free to write without read permission. Traversing it
    /// needs only search, which is exactly what `O_PATH` asks for and what `linkat` accepts
    /// of the handle it is given.
    fn open_dir(&self, path: &[u8], blame: &[u8]) -> Result<OwnedFd, HostError> {
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = rustix::fs::openat(&self.sink.root, c".", flags, Mode::empty())
            .map_err(|e| self.io(blame, e.into()))?;
        for component in path.split(|&b| b == b'/') {
            if component.is_empty() {
                continue;
            }
            check_name(component, blame)?;
            fd = rustix::fs::openat(&fd, component, flags, Mode::empty())
                .map_err(|e| self.io(blame, e.into()))?;
        }
        Ok(fd)
    }

    /// Apply ownership, mode, and times to something already open.
    ///
    /// Ownership first: setting an owner clears the set-user and set-group bits, so a mode
    /// applied before it would not survive.
    fn finish_fd(&mut self, fd: &OwnedFd, inode: &Inode, path: &[u8]) -> Result<(), HostError> {
        self.chown_fd(fd, inode, path)?;
        rustix::fs::fchmod(fd, mode_of(inode)).map_err(|e| self.io(path, e.into()))?;
        rustix::fs::futimens(fd, &times_of(inode)).map_err(|e| self.io(path, e.into()))
    }

    /// The same for a name in the current directory, which is what everything that cannot be
    /// opened takes: a symbolic link, a device node, a FIFO, a socket.
    ///
    /// A symbolic link has no mode of its own, and its times and owner are set on the link
    /// rather than on what it points at.
    fn finish_name(
        &mut self,
        name: &[u8],
        inode: &Inode,
        path: &[u8],
        symlink: bool,
    ) -> Result<(), HostError> {
        let flags = if symlink {
            AtFlags::SYMLINK_NOFOLLOW
        } else {
            AtFlags::empty()
        };
        self.chown_at(name, inode, path, flags)?;
        if !symlink {
            // No `SYMLINK_NOFOLLOW` here, and none is needed: Linux has no `fchmodat` that
            // takes it — the call fails outright — and the name being changed is one this
            // run created a moment ago, which is not a symbolic link.
            rustix::fs::chmodat(self.dir(), name, mode_of(inode), AtFlags::empty())
                .map_err(|e| self.io(path, e.into()))?;
        }
        rustix::fs::utimensat(self.dir(), name, &times_of(inode), flags)
            .map_err(|e| self.io(path, e.into()))
    }

    /// Set a name's recorded owner, honouring the skip policy.
    fn chown_at(
        &mut self,
        name: &[u8],
        inode: &Inode,
        path: &[u8],
        flags: AtFlags,
    ) -> Result<(), HostError> {
        let (uid, gid) = owner_of(inode, path)?;
        let result = rustix::fs::chownat(self.dir(), name, Some(uid), Some(gid), flags);
        self.took_ownership(result, path)
    }

    /// The same for something already open, which is every regular file and directory.
    fn chown_fd(&mut self, fd: &OwnedFd, inode: &Inode, path: &[u8]) -> Result<(), HostError> {
        let (uid, gid) = owner_of(inode, path)?;
        let result = rustix::fs::fchown(fd, Some(uid), Some(gid));
        self.took_ownership(result, path)
    }

    /// Judge one ownership call: a refusal is the whole extraction's failure, or a recorded
    /// omission under [`DirectorySink::skip_privileged`].
    fn took_ownership(
        &mut self,
        result: rustix::io::Result<()>,
        path: &[u8],
    ) -> Result<(), HostError> {
        match result {
            Ok(()) => Ok(()),
            Err(e) if forbidden(e) => {
                if !self.sink.skip_privileged {
                    return Err(HostError::Unprivileged {
                        path: path.to_vec(),
                        what: "an owner other than this process's needs CAP_CHOWN to set",
                    });
                }
                self.report.ownership_dropped = true;
                Ok(())
            }
            Err(e) => Err(self.io(path, e.into())),
        }
    }

    /// Set the extended attributes of a name in the current directory.
    ///
    /// This is the path for everything that cannot be opened — a symbolic link most of all,
    /// which cannot be opened without following it. `lsetxattr` does not follow the final
    /// component, so the attributes land on the entry itself rather than on what it may
    /// point at.
    ///
    /// It is the one call here that takes a path rather than a handle, because Linux has no
    /// `setxattr` that takes a directory handle before 6.13. The path names the handle: the
    /// kernel resolves `/proc/self/fd/<n>` to the directory that handle already refers to,
    /// so nothing between the destination and this directory is walked a second time and the
    /// only component resolved from a name is the entry itself.
    fn set_xattrs_by_name(
        &mut self,
        name: &[u8],
        xattrs: &[Xattr],
        path: &[u8],
    ) -> Result<(), HostError> {
        if xattrs.is_empty() {
            return Ok(());
        }
        let at_dir = fd_path(self.dir(), name);
        for xattr in xattrs {
            let value = xattr_value(xattr, path)?;
            let result = rustix::fs::lsetxattr(
                &at_dir,
                &xattr.name[..],
                &value,
                rustix::fs::XattrFlags::empty(),
            );
            self.took_xattr(result, path)?;
        }
        Ok(())
    }

    /// The same through an open handle, which is what a regular file and a directory take.
    fn set_xattrs_on_fd(
        &mut self,
        fd: &OwnedFd,
        xattrs: &[Xattr],
        path: &[u8],
    ) -> Result<(), HostError> {
        for xattr in xattrs {
            let value = xattr_value(xattr, path)?;
            let result =
                rustix::fs::fsetxattr(fd, &xattr.name[..], &value, rustix::fs::XattrFlags::empty());
            self.took_xattr(result, path)?;
        }
        Ok(())
    }

    /// Judge one extended-attribute call, exactly as [`took_ownership`](Self::took_ownership)
    /// judges one ownership call.
    ///
    /// The `security` and `trusted` namespaces are the host's to write, not an ordinary
    /// process's: a root filesystem carries `security.capability` on the binaries that hold
    /// one and `security.selinux` throughout when it is labelled, so an unprivileged
    /// extraction meets a refusal here on trees that are otherwise entirely reproducible.
    fn took_xattr(&mut self, result: rustix::io::Result<()>, path: &[u8]) -> Result<(), HostError> {
        match result {
            Ok(()) => Ok(()),
            Err(e) if forbidden(e) => {
                if !self.sink.skip_privileged {
                    return Err(HostError::Unprivileged {
                        path: path.to_vec(),
                        what: "an extended attribute in the security or trusted namespace \
                               needs privilege to set",
                    });
                }
                self.report.xattrs_dropped = true;
                Ok(())
            }
            Err(e) => Err(self.io(path, e.into())),
        }
    }

    /// An I/O failure against the destination, named by the host path it was writing.
    fn io(&self, path: &[u8], source: std::io::Error) -> HostError {
        HostError::Io {
            path: under_root(&self.sink.root_path, path),
            source,
        }
    }
}

/// Whether a failure is the host declining for want of a privilege.
fn forbidden(e: rustix::io::Errno) -> bool {
    e == rustix::io::Errno::PERM || e == rustix::io::Errno::ACCESS
}

/// A path's parent and its final component, with the component checked to be one a directory
/// can hold.
///
/// `/etc/hostname` is `/etc` and `hostname`; a top-level `/etc` is the empty parent — which
/// is the destination itself — and `etc`.
fn split(path: &[u8]) -> Result<(&[u8], &[u8]), HostError> {
    let cut = path
        .iter()
        .rposition(|&b| b == b'/')
        .ok_or_else(|| HostError::HostileName {
            path: path.to_vec(),
        })?;
    let (parent, name) = (&path[..cut], &path[cut + 1..]);
    check_name(name, path)?;
    Ok((parent, name))
}

/// Refuse a name a directory could not hold, so nothing the image says can reach a place the
/// destination does not contain.
///
/// A separator would traverse, `..` would ascend, `.` would name the directory itself, a NUL
/// would truncate the name a syscall receives, and an empty name is not a name.
fn check_name(name: &[u8], path: &[u8]) -> Result<(), HostError> {
    let ok = !name.is_empty()
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
        && !name.contains(&0);
    if ok {
        return Ok(());
    }
    Err(HostError::HostileName {
        path: path.to_vec(),
    })
}

/// Whether a path is `/lost+found` or something inside it.
fn is_lost_found(path: &[u8]) -> bool {
    path == LOST_FOUND || path.starts_with(b"/lost+found/")
}

/// The path that names `name` inside the directory `dir` refers to, without resolving the
/// directory again.
///
/// `/proc/self/fd/<n>` is the kernel's own name for an open handle: resolving it yields the
/// file that handle refers to, whatever the path it was opened by has since become. Joining a
/// single component onto it therefore reaches exactly what an `*at` call on `dir` would, which
/// is what a call that has no `*at` form needs.
fn fd_path(dir: &OwnedFd, name: &[u8]) -> PathBuf {
    use std::os::fd::AsRawFd;
    let mut path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    path.push(display(name));
    path
}

/// An image path or name as an [`OsStr`](std::ffi::OsStr): the bytes themselves, since a path
/// on this host is bytes too.
fn display(bytes: &[u8]) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(bytes))
}

/// The host path an image path names inside the destination.
///
/// An image path is absolute in the filesystem it came from, and joining an absolute path onto
/// a base discards the base — so the components are pushed one at a time and the destination
/// stays what every path this produces is under. A message naming `/etc/hostname` would say an
/// extraction touched the host's own file; the one that names `<destination>/etc/hostname` says
/// where it actually wrote.
fn under_root(root: &Path, path: &[u8]) -> PathBuf {
    let mut out = root.to_path_buf();
    for component in path.split(|&b| b == b'/') {
        if !component.is_empty() {
            out.push(display(component));
        }
    }
    out
}

/// The permission and set-user/group/sticky bits of a recorded mode.
fn mode_of(inode: &Inode) -> Mode {
    Mode::from_bits_retain(u32::from(inode.mode & 0o7777))
}

/// The owner a recorded inode names, or `None` for one no host id can be set to.
///
/// A `chown` takes `-1` to mean "leave this one alone", so an id of all ones is not an id at
/// all — there is no call that sets it. An image recording one is refused rather than given
/// an owner it does not name.
fn owner_of(inode: &Inode, path: &[u8]) -> Result<(Uid, Gid), HostError> {
    if inode.uid == u32::MAX || inode.gid == u32::MAX {
        return Err(HostError::UnrepresentableOwner {
            path: path.to_vec(),
            uid: inode.uid,
            gid: inode.gid,
        });
    }
    Ok((Uid::from_raw(inode.uid), Gid::from_raw(inode.gid)))
}

/// The two times a host lets a caller set. An inode's change time is the kernel's own, and no
/// extraction can carry it.
fn times_of(inode: &Inode) -> Timestamps {
    Timestamps {
        last_access: timespec(inode.atime),
        last_modification: timespec(inode.mtime),
    }
}

/// One recorded time as the host takes it.
///
/// An inode's fraction is a thirty-bit field, so a filesystem this crate did not write can
/// name more nanoseconds than a second holds — which `utimensat` refuses outright. The excess
/// is carried into the seconds, so the time set is the instant the two fields describe.
fn timespec(t: Timestamp) -> Timespec {
    let carry = i64::from(t.nanos / Timestamp::NANOS_PER_SEC);
    let nanos = t.nanos % Timestamp::NANOS_PER_SEC;
    Timespec {
        tv_sec: t.secs.saturating_add(carry),
        // Bounded below a second by the line above, so it is exact at every width the host
        // spells this field in.
        tv_nsec: nanos as _,
    }
}

/// The value an extended attribute takes on the host.
///
/// A POSIX ACL is stored on disk in ext's compact form, which is not the form the `setxattr`
/// boundary speaks, so it is decoded and written back out in the version-2 form — exactly the
/// inverse of what a walk does on the way in. Every other attribute is bytes, and travels as
/// bytes.
fn xattr_value(xattr: &Xattr, path: &[u8]) -> Result<Vec<u8>, HostError> {
    if xattr.name == Acl::ACCESS_NAME || xattr.name == Acl::DEFAULT_NAME {
        let acl = Acl::decode(&xattr.value).map_err(|source| HostError::Acl {
            path: display(path).to_path_buf(),
            source,
        })?;
        return Ok(acl.encode_xattr_v2());
    }
    Ok(xattr.value.clone())
}

impl From<ReadError> for HostError {
    fn from(source: ReadError) -> Self {
        Self::Read { source }
    }
}

/// Attach a path to an I/O failure, so every message names what could not be written.
fn io_at(path: &Path) -> impl Fn(std::io::Error) -> HostError + '_ {
    move |source| HostError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_path_lands_under_the_destination_rather_than_replacing_it() {
        let root = Path::new("/tmp/unpacked");
        // The case a plain join gets wrong: an absolute argument would discard the base and
        // name the host's own file.
        assert_eq!(
            under_root(root, b"/etc/hostname"),
            root.join("etc/hostname")
        );
        // The root of the image is the destination itself, spelled either way the walk
        // reaches it.
        assert_eq!(under_root(root, b"/"), root);
        assert_eq!(under_root(root, b""), root);
        // Repeated separators name no component, so they add none.
        assert_eq!(under_root(root, b"//var//log"), root.join("var/log"));
    }

    #[test]
    fn a_path_splits_into_the_directory_it_is_in_and_the_name_it_holds() {
        assert_eq!(
            split(b"/etc/hostname").unwrap(),
            (&b"/etc"[..], &b"hostname"[..])
        );
        // A top-level name's parent is the destination itself, which is the empty path.
        assert_eq!(split(b"/etc").unwrap(), (&b""[..], &b"etc"[..]));
    }

    #[test]
    fn a_name_that_could_leave_the_destination_is_refused() {
        // The walk filters these before a path is built, so nothing here reaches a
        // well-formed image. It is checked anyway, because the image is the input and this
        // is the check that makes a name inside the destination the only place a write can
        // land.
        for name in [&b".."[..], b".", b"", b"a/b", b"a\0b"] {
            assert!(
                matches!(check_name(name, b"/x"), Err(HostError::HostileName { .. })),
                "{name:?} must be refused"
            );
        }
        for name in [&b"etc"[..], b"..a", b"a..", b"...", b"\xff\xfe"] {
            assert!(check_name(name, b"/x").is_ok(), "{name:?} is a name");
        }
    }

    #[test]
    fn lost_and_found_is_recognized_with_its_contents() {
        assert!(is_lost_found(b"/lost+found"));
        assert!(is_lost_found(b"/lost+found/17"));
        // A name that merely begins the same way is a different file.
        assert!(!is_lost_found(b"/lost+found-old"));
        assert!(!is_lost_found(b"/etc/lost+found"));
    }
}
