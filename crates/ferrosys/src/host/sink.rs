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
//! That one call is therefore the module's single dependency on `/proc` being mounted. It is
//! reached only for an attribute on a symbolic link or a special node, and where `/proc` is
//! absent — a minimal container is where that happens — it fails as an ordinary I/O error
//! against the entry, naming `ENOENT`. Every other operation goes through a handle and needs
//! nothing mounted.
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
//! not size — one path per inode that has more than one name, and one held handle for each
//! directory the image records without owner-search permission, whose own metadata is applied
//! after the walk rather than as the walk leaves it.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Gid, Mode, OFlags, Timespec, Timestamps, Uid};

use crate::fidelity::{Direction, FidelityReport, Synthesis};
use crate::host::{HostError, io_at};
use crate::source::Metadata;
use crate::time::Timestamp;
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};
use crate::xattr::Xattr;

/// `/lost+found`, the one path an extraction must not write: every filesystem makes it for
/// itself, and a source that tries to make it again is refused.
const LOST_FOUND: &[u8] = b"/lost+found";

/// The mode a directory is created with, before its children are written.
///
/// A directory whose recorded mode denies its owner write or search permission still has to
/// receive its contents, so it is made writable and made itself once its children are in
/// place. Nothing else may enter it in between: the mode is narrower than most trees record,
/// not wider.
const BUILDING: Mode = Mode::from_bits_retain(0o700);

/// The most bytes of a file that move at a time. Large enough that a big file is not a
/// syscall per block, small enough that the buffer is not worth thinking about.
///
/// It is a ceiling rather than the size: a file shorter than this gets a buffer its own size,
/// so a root filesystem of many small files does not allocate and zero a mebibyte per entry
/// to move a few hundred bytes through it.
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
    ///
    /// Named rather than counted, because a device node left out is a specific gap in a
    /// specific tree and a caller acts on which. The list stops at
    /// [`MAX_SKIPPED`](Self::MAX_SKIPPED) names and
    /// [`more_skipped`](Self::more_skipped) says the rest are not there: how many entries a
    /// tree produces is the tree's own claim, and a report's memory is a property of this
    /// crate rather than of what it was pointed at.
    pub skipped: Vec<Vec<u8>>,
    /// Whether more entries were skipped than [`skipped`](Self::skipped) names.
    pub more_skipped: bool,
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
    /// What the source filesystem had no field for, so the tree carries an invented value of.
    ///
    /// A filesystem that records ownership, permission bits, and times reports nothing here,
    /// and [`FidelityReport::is_faithful`] is that claim. One that does not — a format with
    /// no notion of an owner — has those values filled from the [`Synthesis`] the sink was
    /// given, and every entry it happened to is named.
    ///
    /// This is separate from [`skipped`](Self::skipped) and the two flags above, which are
    /// about what *this host* refused. A property the image never held is not something the
    /// host declined to write.
    pub fidelity: FidelityReport,
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
/// # use ferrosys::DirectorySink;
/// # use ferrosys::ext::Reader;
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
    synthesis: Synthesis,
}

impl DirectorySink {
    /// A sink that writes into the directory at `root`, which must exist and be empty.
    ///
    /// Empty, because an extraction states what the filesystem holds: a name already in the
    /// destination would be an entry that cannot be created, discovered part-way through
    /// with the tree half written. Refusing at the start is the failure a caller can act on.
    ///
    /// The name is resolved once. The handle is taken first and both questions — that it is a
    /// directory, and that it is empty — are asked of the handle, so the object this sink
    /// writes into is the same object it accepted. Asking the name twice would leave a window
    /// in which what answered is not what receives the tree.
    ///
    /// # Errors
    ///
    /// [`HostError::NotADirectory`] if `root` is not one, [`HostError::NotEmpty`] if it holds
    /// anything, and [`HostError::Io`] if it cannot be opened or listed.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, HostError> {
        let root_path = root.as_ref().to_path_buf();
        // `O_DIRECTORY` is the "it is a directory" test as well as the open: the kernel
        // answers `ENOTDIR` rather than handing back a descriptor to something else.
        let fd = rustix::fs::open(
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::NOTDIR => HostError::NotADirectory {
                path: root_path.clone(),
            },
            other => io_at(&root_path)(other.into()),
        })?;
        if !is_empty_dir(&fd).map_err(|e| io_at(&root_path)(e.into()))? {
            return Err(HostError::NotEmpty { path: root_path });
        }
        Ok(Self {
            root: fd,
            root_path,
            skip_privileged: false,
            synthesis: Synthesis::new(),
        })
    }

    /// Name what to record for a property the source filesystem has no field for.
    ///
    /// Defaults to [`Synthesis::new`] — owned by root, `0644` for a file and `0755` for a
    /// directory. Ignored entirely by a filesystem that records the property itself, so an
    /// ext image extracts with the ownership and modes it holds whatever is set here.
    ///
    /// The defaults are the conservative ones deliberately: a tree extracted from a format
    /// with no permission bits must not land world-writable because nothing was named.
    #[must_use]
    pub fn synthesis(mut self, synthesis: Synthesis) -> Self {
        self.synthesis = synthesis;
        self
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
    /// one node created as hard links to the first.
    ///
    /// A directory's mode, ownership, and times are applied once its children are in place,
    /// so a directory the image records as read-only is still one its contents could be
    /// written into. One the image records without owner-search permission waits longer
    /// still — until the whole walk is done — because a second name for a hard-linked node
    /// inside it is created by reaching the first, and a directory that cannot be searched
    /// cannot be reached through.
    ///
    /// The source is any [`FsTree`], so the same sink drains whatever `open` hands back.
    /// What a filesystem has no field for is filled from [`synthesis`](Self::synthesis) and
    /// named in the report's [`fidelity`](ExtractReport::fidelity).
    ///
    /// # Errors
    ///
    /// [`HostError::Read`] if the filesystem cannot be read; [`HostError::Io`] if the
    /// destination cannot be written; [`HostError::HostileName`] if the image holds a name a
    /// directory cannot; [`HostError::Unprivileged`] if the tree needs a privilege this
    /// process does not have and [`skip_privileged`](Self::skip_privileged) was not set; and
    /// [`HostError::Acl`] if a stored POSIX ACL does not decode.
    pub fn write_tree<T: FsTree>(self, tree: &mut T) -> Result<ExtractReport, HostError> {
        let mut state = Extraction {
            sink: &self,
            report: ExtractReport::default(),
            named: HashMap::new(),
            open: Vec::new(),
            held: Vec::new(),
        };
        let synthesis = self.synthesis;

        // Walked entry by entry rather than gathered, so what an extraction holds does not
        // grow with the number of names in the tree. The walk is depth-first with a parent
        // before its children, which is what lets the open handles be a stack — and it opens
        // with the root, under the empty path, which is what every top-level entry's parent
        // is.
        tree.walk_tree(|tree, entry| {
            if is_lost_found(&entry.path) {
                return Ok(());
            }
            if entry.path.is_empty() {
                // The root has no name of its own, so the destination directory is what
                // carries its mode, ownership, times, and attributes across. Its own metadata
                // waits, like every directory's, until its children are written.
                let attrs = tree.stat(&entry.node, &synthesis)?;
                state.note_synthesis(&attrs, b"/");
                state.open.push(OpenDir {
                    path: Vec::new(),
                    fd: rustix::fs::openat(
                        &self.root,
                        c".",
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|e| state.io(b"/", e.into()))?,
                    meta: attrs.meta,
                    xattrs: attrs.xattrs,
                });
                return Ok(());
            }
            state.write_entry(tree, entry, &synthesis)
        })?;

        // Everything still open is a directory whose children are all written.
        while let Some(dir) = state.open.pop() {
            state.finish_directory(dir)?;
        }
        // And every directory held back because applying its mode would have closed the tree
        // to the walk that was still going on. Nothing more is written into the destination
        // from here, so there is no name left for a mode to put out of reach.
        for dir in std::mem::take(&mut state.held) {
            state.apply_directory(&dir)?;
        }
        Ok(state.report)
    }
}

/// The most directories one extraction defers to the end of the walk.
///
/// Each one costs an open handle for the rest of the run, and which directories they are is
/// the image's to decide — so this is what stands between a crafted tree and this process's
/// descriptor limit. Two hundred and fifty-six is far past any real root filesystem: a
/// directory reaches the list only by denying its own owner search permission, which is a
/// mode a handful of directories in a tree carry and no ordinary one does.
const MAX_DEFERRED_DIRECTORIES: usize = 256;

/// A directory that has been created and is still being filled.
struct OpenDir {
    /// Its path inside the image: `/etc`, and empty for the destination itself.
    path: Vec<u8>,
    /// The handle every child of it is created through.
    fd: OwnedFd,
    /// What the image says it is, applied once its children are written.
    meta: Metadata,
    /// The extended attributes the image records for it, applied with the rest of its
    /// metadata and in the same order every other node takes.
    xattrs: Vec<Xattr>,
}

impl ExtractReport {
    /// The most skipped paths one report names.
    ///
    /// Past it the names stop and [`more_skipped`](Self::more_skipped) says so. A tree with
    /// more than this many entries a process may not create is one where the *pattern* is
    /// the answer — no privilege at all — rather than a list to work through.
    pub const MAX_SKIPPED: usize = 1024;
}

/// One run of [`DirectorySink::write_tree`]: what has been written, and where it is being
/// written to.
struct Extraction<'a> {
    sink: &'a DirectorySink,
    report: ExtractReport,
    /// The first name to reach each node the walk says has more than one. A later name for
    /// one is a hard link to it.
    named: HashMap<u64, Vec<u8>>,
    /// The directories on the path currently being written, outermost first. The last is the
    /// one the next entry goes into.
    open: Vec<OpenDir>,
    /// The directories whose children are written and whose own metadata is still to apply,
    /// because the mode the image records for them denies their owner search permission.
    /// Drained once the walk is over.
    held: Vec<OpenDir>,
}

impl Extraction<'_> {
    /// Write one name.
    fn write_entry<T: FsTree>(
        &mut self,
        tree: &mut T,
        entry: TreeEntry<T::Node>,
        synthesis: &Synthesis,
    ) -> Result<(), HostError> {
        let (parent, name) = split(&entry.path)?;
        // Every directory deeper than this entry's parent is finished: the walk is
        // depth-first, so nothing will be added to one again.
        while self.open.len() > 1 && self.open[self.open.len() - 1].path != parent {
            let dir = self.open.pop().expect("the loop checked the length");
            self.finish_directory(dir)?;
        }
        if self.open.last().map(|d| d.path.as_slice()) != Some(parent) {
            // The walk emits a parent before its children, so this is unreachable for a tree
            // the walk produced. It is checked rather than assumed because what follows
            // writes into whatever handle is on top of the stack.
            return Err(HostError::OutOfOrder {
                path: entry.path.clone(),
            });
        }

        // A node the walk says is reachable by more than one name is the file the first time
        // it is seen and a hard link every time after.
        if let Some(id) = entry.shared
            && let Some(first) = self.named.get(&id)
        {
            let first = first.clone();
            if self.link(&first, name, &entry.path)? {
                self.report.written += 1;
            }
            return Ok(());
        }

        let attrs = tree.stat(&entry.node, synthesis)?;
        self.note_synthesis(&attrs, &entry.path);

        // A regular file is the one kind that leaves a handle behind, since writing it is
        // what opened one; its attributes and metadata go through that rather than through
        // its name. Nothing else can be opened without either following it or having an
        // effect of its own.
        let handle = match entry.kind {
            NodeKind::Directory => {
                self.make_directory(name, &entry.path, &attrs)?;
                None
            }
            NodeKind::File { size } => Some(self.write_file(tree, name, &entry, size)?),
            NodeKind::Symlink => {
                let target = tree.link_target(&entry.node)?;
                self.make_symlink(&target, name, &entry.path)?;
                None
            }
            NodeKind::CharDevice { major, minor } | NodeKind::BlockDevice { major, minor } => {
                let file_type = if matches!(entry.kind, NodeKind::CharDevice { .. }) {
                    FileType::CharacterDevice
                } else {
                    FileType::BlockDevice
                };
                if !self.make_node(
                    file_type,
                    rustix::fs::makedev(major, minor),
                    name,
                    &entry.path,
                    &attrs,
                )? {
                    return Ok(());
                }
                None
            }
            NodeKind::Fifo => {
                if !self.make_node(FileType::Fifo, 0, name, &entry.path, &attrs)? {
                    return Ok(());
                }
                None
            }
            // Matched exhaustively on purpose: a `NodeKind` a later family adds is a
            // compile error here, which forces a decision about how to write it rather
            // than letting it fall into a wildcard that creates something else.
            NodeKind::Socket => {
                if !self.make_node(FileType::Socket, 0, name, &entry.path, &attrs)? {
                    return Ok(());
                }
                None
            }
        };

        // Now that the name exists, it is the one a later name for this node links from.
        // Recorded here rather than before the entry was made, because a node the host
        // refused was skipped: linking to it would fail for want of a name rather than
        // report the privilege that was actually missing.
        if let Some(id) = entry.shared {
            self.named.insert(id, entry.path.clone());
        }

        // A directory's own metadata waits until its children are written; everything else
        // is finished the moment it exists.
        match (entry.kind, &handle) {
            (NodeKind::Directory, _) => {}
            (_, Some(fd)) => self.finish_fd(fd, &attrs.meta, &attrs.xattrs, &entry.path)?,
            (_, None) => self.finish_name(
                name,
                &attrs.meta,
                &attrs.xattrs,
                &entry.path,
                matches!(entry.kind, NodeKind::Symlink),
            )?,
        }
        self.report.written += 1;
        Ok(())
    }

    /// Record every property the family invented rather than read, so an extraction says
    /// what in the tree was policy rather than the image's.
    fn note_synthesis(&mut self, attrs: &Attributes, path: &[u8]) {
        for property in &attrs.synthesized {
            self.report
                .fidelity
                .record(Direction::Synthesized, path, *property);
        }
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
        path: &[u8],
        attrs: &Attributes,
    ) -> Result<(), HostError> {
        rustix::fs::mkdirat(self.dir(), name, BUILDING).map_err(|e| self.io(path, e.into()))?;
        let fd = rustix::fs::openat(
            self.dir(),
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| self.io(path, e.into()))?;
        self.open.push(OpenDir {
            path: path.to_vec(),
            fd,
            meta: attrs.meta,
            xattrs: attrs.xattrs.clone(),
        });
        Ok(())
    }

    /// A directory whose children are all written: finish it, or hold it back until the walk
    /// is over.
    ///
    /// Applying the recorded mode is what closes a directory, and a mode that denies its
    /// owner search permission closes it to this run as well. That matters once the walk has
    /// left the directory, because a second name for a hard-linked node inside it is created
    /// by traversing to the first — so such a directory keeps [`BUILDING`] and its handle
    /// until the walk is over, by which time there is no name left to reach. It is held by
    /// handle rather than by path, so what finishes it is the object this run created and not
    /// whatever its name resolves to by then.
    ///
    /// One bit decides, and it is the one that matters: every directory a mode leaves
    /// searchable is finished where the walk leaves it, which is what keeps the handles a
    /// walk holds down to the depth of the tree in the trees that have no such directory —
    /// which is nearly all of them.
    fn finish_directory(&mut self, dir: OpenDir) -> Result<(), HostError> {
        if mode_of(&dir.meta).contains(Mode::XUSR) {
            return self.apply_directory(&dir);
        }
        // Which directories wait is the image's choice, so the number of them is too. Past
        // the ceiling the extraction stops as itself rather than running the process out of
        // descriptors — where the drain below would never run, and every deferred directory
        // would be left at `BUILDING` and owned by this process instead of at the mode and
        // owner the image recorded.
        if self.held.len() >= MAX_DEFERRED_DIRECTORIES {
            return Err(HostError::TooManyDeferredDirectories {
                limit: MAX_DEFERRED_DIRECTORIES,
            });
        }
        self.held.push(dir);
        Ok(())
    }

    /// Set a directory's ownership, mode, attributes, and times, now that everything inside
    /// it is written — which is what the wait is for: a directory whose recorded mode denies
    /// its owner write or search permission still had to receive its contents.
    fn apply_directory(&mut self, dir: &OpenDir) -> Result<(), HostError> {
        // The path a failure names: the image path this directory holds, or the destination
        // itself for the root, whose path inside the image is empty.
        let path: &[u8] = if dir.path.is_empty() { b"/" } else { &dir.path };
        self.finish_fd(&dir.fd, &dir.meta, &dir.xattrs, path)
    }

    /// Create a regular file and stream its contents into it, returning the handle its
    /// attributes and metadata are then set through.
    ///
    /// The bytes written are the file's contents as the filesystem reports them, and a hole
    /// reads as zeros — so a sparse file lands in the destination fully allocated, and a tree
    /// holding one occupies more space on the host than it does in the image. What is written
    /// is what a reader of either sees.
    fn write_file<T: FsTree>(
        &mut self,
        tree: &mut T,
        name: &[u8],
        entry: &TreeEntry<T::Node>,
        size: u64,
    ) -> Result<OwnedFd, HostError> {
        // What a tree *writes* is driven entirely by the length the filesystem declares, and
        // a hole reads back as zeros — so an inode claiming terabytes and mapping nothing
        // fills the destination until it runs out of room, from an image of a few kilobytes.
        // The cap a caller set on what a read will return governs that too, checked before
        // the name is created so a refused file leaves nothing behind.
        tree.check_file_size(&entry.path, size)?;
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
        // The window is a ceiling, not the size: most entries in a root filesystem are a few
        // hundred bytes, and a mebibyte allocated and zeroed for each of them is the cost of
        // the tree rather than of the largest file in it.
        let window = usize::try_from(size).unwrap_or(usize::MAX).min(WINDOW);
        let mut buf = vec![0u8; window];
        let mut offset = 0u64;
        // Bounded by the length the walk reported as well as by what the reads yield, so a
        // filesystem that keeps answering cannot write more than it said the file holds.
        while offset < size {
            let want = usize::try_from(size - offset)
                .unwrap_or(usize::MAX)
                .min(window);
            let filled = tree.read_bytes(&entry.node, offset, &mut buf[..want])?;
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
    fn make_symlink(&mut self, target: &[u8], name: &[u8], path: &[u8]) -> Result<(), HostError> {
        rustix::fs::symlinkat(target, self.dir(), name).map_err(|e| self.io(path, e.into()))
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
        path: &[u8],
        attrs: &Attributes,
    ) -> Result<bool, HostError> {
        match rustix::fs::mknodat(self.dir(), name, file_type, mode_of(&attrs.meta), dev) {
            Ok(()) => Ok(true),
            Err(e) if forbidden(e) => {
                if !self.sink.skip_privileged {
                    return Err(HostError::Unprivileged {
                        path: path.to_vec(),
                        what: match file_type {
                            FileType::CharacterDevice | FileType::BlockDevice => {
                                "a device node needs CAP_MKNOD to create"
                            }
                            _ => "this host refuses to create a node of this kind",
                        },
                    });
                }
                self.note_skipped(path);
                Ok(false)
            }
            Err(e) => Err(self.io(path, e.into())),
        }
    }

    /// Create another name for a file already written, from the path that first named it.
    /// Reports whether it was created, as [`make_node`](Self::make_node) does: a link this
    /// host refuses is skipped rather than made under [`DirectorySink::skip_privileged`].
    ///
    /// The first name's directory is re-opened one component at a time from the destination,
    /// since the walk has usually left it behind by the time a second name for it appears.
    /// Opening it that way rather than joining the path keeps the rule the whole module holds
    /// to: every write goes through a handle to a directory this run created. Every directory
    /// along the way is one that can be searched — a mode that would deny it is held back
    /// until the walk is over, which is what [`finish_directory`](Self::finish_directory)
    /// is for.
    ///
    /// A destination filesystem is free to refuse the link itself: one with no notion of a
    /// second name for a node answers `EPERM` however the traversal went, and that is the
    /// host declining what the image asks for exactly as a device node is.
    fn link(&mut self, first: &[u8], name: &[u8], path: &[u8]) -> Result<bool, HostError> {
        let (first_parent, first_name) = split(first)?;
        let parent = self.open_dir(first_parent, path)?;
        match rustix::fs::linkat(&parent, first_name, self.dir(), name, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(e) if forbidden(e) => {
                if !self.sink.skip_privileged {
                    return Err(HostError::Unprivileged {
                        path: path.to_vec(),
                        what: "a second name for a node needs a host that permits a hard link \
                               to it",
                    });
                }
                self.note_skipped(path);
                Ok(false)
            }
            Err(e) => Err(self.io(path, e.into())),
        }
    }

    /// Open the directory at `path` inside the destination, descending one component at a
    /// time and following nothing. `blame` is the entry a failure is reported against.
    ///
    /// `O_PATH`, because this asks for a handle to traverse from and nothing more. Opening a
    /// directory for reading needs the read bit, and by the time a second name for an inode
    /// appears the first name's directory has usually been finished and carries the mode the
    /// image records — which a real tree is free to write without read permission. `O_PATH`
    /// needs no permission on the directory it names, so a mode without the read bit is no
    /// obstacle to holding a handle to it.
    ///
    /// It is no help with the *search* bit, though, which is a separate question: resolving a
    /// name through a directory asks for search on it at the moment of the lookup, whatever
    /// the handle it started from was opened with, and `linkat` asks the same of the
    /// directory holding the name it links from. That is why a directory a mode would leave
    /// unsearchable keeps [`BUILDING`] until the walk is over — see
    /// [`finish_directory`](Self::finish_directory) — so that every directory this descends
    /// through, and the one it links out of, is one it can search.
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

    /// Apply ownership, mode, extended attributes, and times to something already open.
    ///
    /// The order is forced from both ends, and every one of the four calls has to sit where
    /// it does.
    ///
    /// *Ownership first.* Setting an owner clears the set-user and set-group bits, so a mode
    /// applied before it would not survive.
    ///
    /// *Attributes after the mode, not before ownership.* Changing an owner also strips
    /// `security.capability`: the kernel sets `ATTR_KILL_PRIV` on every `chown` of a
    /// non-directory, whether or not the ids actually change, and that is what removes the
    /// attribute. So an attribute written before the `chown` is written and then destroyed,
    /// and this sink would report the extraction faithful. Changing a mode does not do this —
    /// only the mode and change time are touched — but it does rewrite the group entry of a
    /// POSIX access ACL, which is itself an extended attribute, so the attributes must follow
    /// the mode as well. Between the two is the only place both hold.
    ///
    /// *Times last*, because every call above them changes one.
    fn finish_fd(
        &mut self,
        fd: &OwnedFd,
        meta: &Metadata,
        xattrs: &[Xattr],
        path: &[u8],
    ) -> Result<(), HostError> {
        self.chown_fd(fd, meta, path)?;
        rustix::fs::fchmod(fd, mode_of(meta)).map_err(|e| self.io(path, e.into()))?;
        self.set_xattrs_on_fd(fd, xattrs, path)?;
        rustix::fs::futimens(fd, &times_of(meta)).map_err(|e| self.io(path, e.into()))
    }

    /// The same for a name in the current directory, which is what everything that cannot be
    /// opened takes: a symbolic link, a device node, a FIFO, a socket.
    ///
    /// A symbolic link has no mode of its own, and its times and owner are set on the link
    /// rather than on what it points at.
    fn finish_name(
        &mut self,
        name: &[u8],
        meta: &Metadata,
        xattrs: &[Xattr],
        path: &[u8],
        symlink: bool,
    ) -> Result<(), HostError> {
        let flags = if symlink {
            AtFlags::SYMLINK_NOFOLLOW
        } else {
            AtFlags::empty()
        };
        self.chown_at(name, meta, path, flags)?;
        if !symlink {
            // No `SYMLINK_NOFOLLOW` here, and none is needed: Linux has no `fchmodat` that
            // takes it — the call fails outright — and the name being changed is one this
            // run created a moment ago, which is not a symbolic link.
            rustix::fs::chmodat(self.dir(), name, mode_of(meta), AtFlags::empty())
                .map_err(|e| self.io(path, e.into()))?;
        }
        self.set_xattrs_by_name(name, xattrs, path)?;
        rustix::fs::utimensat(self.dir(), name, &times_of(meta), flags)
            .map_err(|e| self.io(path, e.into()))
    }

    /// Set a name's recorded owner, honouring the skip policy.
    fn chown_at(
        &mut self,
        name: &[u8],
        meta: &Metadata,
        path: &[u8],
        flags: AtFlags,
    ) -> Result<(), HostError> {
        let (uid, gid) = owner_of(meta, path)?;
        let result = rustix::fs::chownat(self.dir(), name, Some(uid), Some(gid), flags);
        self.took_ownership(result, path)
    }

    /// The same for something already open, which is every regular file and directory.
    fn chown_fd(&mut self, fd: &OwnedFd, meta: &Metadata, path: &[u8]) -> Result<(), HostError> {
        let (uid, gid) = owner_of(meta, path)?;
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
            let result = rustix::fs::lsetxattr(
                &at_dir,
                &xattr.name[..],
                &xattr.value,
                rustix::fs::XattrFlags::empty(),
            );
            self.took_xattr(result, path, &xattr.name, false)?;
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
            let result = rustix::fs::fsetxattr(
                fd,
                &xattr.name[..],
                &xattr.value,
                rustix::fs::XattrFlags::empty(),
            );
            self.took_xattr(result, path, &xattr.name, true)?;
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
    ///
    /// Two refusals arrive as the same errno and are not that. The kernel restricts a
    /// `user.*` attribute to a regular file or a directory, and a default POSIX ACL to a
    /// directory, by the *type* of what they are set on rather than by who is setting it —
    /// so on a symbolic link or a device node they fail identically for root. Reported as a
    /// missing privilege they would name a namespace the attribute is not in and prescribe a
    /// privilege that would not help, so they are told apart here: `opened` is false exactly
    /// for the kinds the rule applies to, since it is those that cannot be opened.
    fn took_xattr(
        &mut self,
        result: rustix::io::Result<()>,
        path: &[u8],
        name: &[u8],
        opened: bool,
    ) -> Result<(), HostError> {
        match result {
            Ok(()) => Ok(()),
            Err(e) if forbidden(e) => {
                let by_kind = !opened
                    && (name.starts_with(b"user.") || name == crate::acl::Acl::DEFAULT_NAME);
                if !self.sink.skip_privileged {
                    return Err(if by_kind {
                        HostError::UnsupportedAttribute {
                            path: path.to_vec(),
                            name: name.to_vec(),
                        }
                    } else {
                        HostError::Unprivileged {
                            path: path.to_vec(),
                            what: "an extended attribute in the security or trusted namespace \
                                   needs privilege to set",
                        }
                    });
                }
                self.report.xattrs_dropped = true;
                Ok(())
            }
            Err(e) => Err(self.io(path, e.into())),
        }
    }

    /// Record a path this run left out, up to the ceiling the report holds itself to.
    fn note_skipped(&mut self, path: &[u8]) {
        if self.report.skipped.len() < ExtractReport::MAX_SKIPPED {
            self.report.skipped.push(path.to_vec());
        } else {
            self.report.more_skipped = true;
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

/// Whether the directory `fd` refers to holds nothing.
///
/// Listed through the handle rather than through the name it was opened by, so the directory
/// found empty is the one the sink goes on to write into. Every directory holds `.` and `..`
/// and neither is something in it.
///
/// Reading a directory stream from a handle asks for search permission on the directory,
/// which is what every write through that handle asks for as well — so this requires nothing
/// of a destination that the extraction does not already require.
fn is_empty_dir(fd: &OwnedFd) -> rustix::io::Result<bool> {
    for entry in rustix::fs::Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
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
fn mode_of(meta: &Metadata) -> Mode {
    Mode::from_bits_retain(u32::from(meta.mode & 0o7777))
}

/// The owner a recorded inode names, or `None` for one no host id can be set to.
///
/// A `chown` takes `-1` to mean "leave this one alone", so an id of all ones is not an id at
/// all — there is no call that sets it. An image recording one is refused rather than given
/// an owner it does not name.
fn owner_of(meta: &Metadata, path: &[u8]) -> Result<(Uid, Gid), HostError> {
    if meta.uid == u32::MAX || meta.gid == u32::MAX {
        return Err(HostError::UnrepresentableOwner {
            path: path.to_vec(),
            uid: meta.uid,
            gid: meta.gid,
        });
    }
    Ok((Uid::from_raw(meta.uid), Gid::from_raw(meta.gid)))
}

/// The two times a host lets a caller set. An inode's change time is the kernel's own, and no
/// extraction can carry it.
fn times_of(meta: &Metadata) -> Timestamps {
    Timestamps {
        last_access: timespec(meta.atime),
        last_modification: timespec(meta.mtime),
    }
}

/// One recorded time as the host takes it.
///
/// A filesystem's stored fraction need not divide a second — ext4's is a thirty-bit field —
/// so an image this crate did not write can name more nanoseconds than a second holds, which
/// `utimensat` refuses outright. The excess is carried into the seconds, so the time set is
/// the instant the two fields describe.
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

impl From<TreeError> for HostError {
    fn from(source: TreeError) -> Self {
        Self::Read { source }
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
