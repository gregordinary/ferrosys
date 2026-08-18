//! The extraction surface: [`FsTree`], the four things a sink needs of any family's
//! reader.
//!
//! Opening an image hands back that family's own reader, whole, because the families'
//! readers are not interchangeable. Draining one into somewhere else is the exception: a
//! tar archive, a directory tree on this host, and a listing all want the same four things
//! — walk the names, stat one, stream a file's bytes, resolve a link — and none of them
//! wants to know which format is underneath.
//!
//! So this trait is exactly those four, kept to what those consumers call. Anything one
//! family alone can answer stays on that family's concrete reader, where a caller reaches
//! it by matching on what opening an image hands back.
//!
//! # What a stat means when the format has no such field
//!
//! [`stat`](FsTree::stat) hands back a complete [`Attributes`] whatever the family is,
//! because a sink writing a host file needs an owner and a mode and there is no such thing
//! as half of one. A family with no field for a property fills it from the [`Synthesis`]
//! the caller supplied and names the property in
//! [`synthesized`](Attributes::synthesized), so a sink records what was invented without
//! knowing which family invented it.

use crate::fidelity::{Property, Synthesis};
use crate::finding::Family;
use crate::source::Metadata;
use crate::xattr::Xattr;

/// A failure reading a filesystem through the extraction surface.
///
/// The classification is shared: whether the source could not be read at all, whether the
/// filesystem's own bytes are wrong, whether it uses something this build does not follow,
/// and whether a caller's limit stopped the read are the four answers a sink acts on, and
/// they mean the same thing for every family. The family's own message rides along, and a
/// caller that needs the family's *typed* error opens that family's reader directly rather
/// than going through this surface.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError {
    /// The underlying source could not be read or sought.
    ///
    /// The `kind` is [`std::io::Error`]'s own classification, kept beside the message rather
    /// than folded into it because it is what a caller *acts* on: a truncated image
    /// ([`UnexpectedEof`](std::io::ErrorKind::UnexpectedEof)) is a property of what is being
    /// read, while a permission failure
    /// ([`PermissionDenied`](std::io::ErrorKind::PermissionDenied)) is a property of the
    /// environment, and telling them apart should not require matching on text.
    ///
    /// It does not appear in the rendered message, because the message already says it:
    /// `message` is the underlying error rendered by [`std::io::Error`], which opens with the
    /// kind's own description. The field is the machine-readable half of a fact the text
    /// already carries.
    ///
    /// Every error in this crate records an i/o failure this way. They are separate variants
    /// on separate enums because their *other* variants are, and a caller matching on one
    /// should not reach through a wrapper for the two fields it wants.
    #[error("i/o error: {message}")]
    #[non_exhaustive]
    Io {
        /// How the underlying [`std::io::Error`] classified itself.
        kind: std::io::ErrorKind,
        /// The error rendered as text, for a message a person reads.
        message: String,
    },
    /// The filesystem's bytes are not what its format requires: a structure did not parse,
    /// a reference pointed outside the image, or something failed its own checksum.
    #[error("malformed {family} filesystem: {detail}", family = .family.as_str())]
    #[non_exhaustive]
    Malformed {
        /// The family whose reader refused.
        family: Family,
        /// That reader's own message.
        detail: String,
    },
    /// The image uses something this build's reader does not follow, so what it holds
    /// cannot be reported faithfully.
    #[error("unsupported {family} filesystem: {detail}", family = .family.as_str())]
    #[non_exhaustive]
    Unsupported {
        /// The family whose reader refused.
        family: Family,
        /// That reader's own message.
        detail: String,
    },
    /// A read would have exceeded a bound the caller set through
    /// [`Limits`](crate::Limits).
    #[error("{family} read exceeded a limit: {detail}", family = .family.as_str())]
    #[non_exhaustive]
    LimitExceeded {
        /// The family whose reader stopped.
        family: Family,
        /// That reader's own message, naming the bound that applied.
        detail: String,
    },
}

/// What a node in a filesystem tree is, as an extraction sees it.
///
/// This is the read-side mirror of [`EntryKind`](crate::EntryKind), and it differs in one
/// way: there is no hard-link variant. A second name for a node is not a *kind* — the node
/// is still a file — so it is reported through [`TreeEntry::shared`], which says which node
/// two names are both for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum NodeKind {
    /// A directory.
    Directory,
    /// A regular file.
    File {
        /// The file's length in bytes, which is how much
        /// [`read_bytes`](FsTree::read_bytes) will yield.
        size: u64,
    },
    /// A symbolic link, whose target is read with [`link_target`](FsTree::link_target).
    Symlink,
    /// A character-special device node.
    CharDevice {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// A block-special device node.
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

/// One name a walk reached: where it is, what is there, and the family's own handle to it.
///
/// The handle is what the three by-node operations take, so a family hands back whatever it
/// already has — an inode for ext, a directory entry for FAT — and a sink never re-resolves
/// a path it was just given.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TreeEntry<N> {
    /// Absolute path from the filesystem root, `/`-joined, always beginning with `/`.
    /// Empty for the root itself, which is the first entry a walk yields.
    pub path: Vec<u8>,
    /// What is at the path.
    pub kind: NodeKind,
    /// The node's identity, when the family says it may be reached by more than one name.
    ///
    /// Two entries carrying the same value are two names for one node — a hard link — and
    /// a sink writes the second as a link to the first rather than copying the contents.
    /// `None` where the family has no notion of a second name for one node, and where it
    /// has one but this node has only one name, which is what keeps a sink's table down to
    /// the tree's actual links rather than a path per file in it.
    pub shared: Option<u64>,
    /// The family's own handle to the node.
    pub node: N,
}

impl<N> TreeEntry<N> {
    /// An entry at `path` holding `kind`, reached through `node`, with no second name.
    #[must_use]
    pub fn new(path: Vec<u8>, kind: NodeKind, node: N) -> Self {
        Self {
            path,
            kind,
            shared: None,
            node,
        }
    }

    /// Declare that the node may be reached by more than one name, under the identity `id`.
    #[must_use]
    pub fn shared(mut self, id: u64) -> Self {
        self.shared = Some(id);
        self
    }
}

/// Everything a sink records about one node beyond what the walk carried.
///
/// Complete whichever family produced it: a sink writing a host file needs an owner, a
/// mode, and times, and a family with no field for one fills it from the caller's
/// [`Synthesis`] rather than leaving a hole. [`synthesized`](Self::synthesized) is what
/// says which of them that happened to.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Attributes {
    /// Ownership, permission bits, and the three times.
    pub meta: Metadata,
    /// The node's extended attributes, empty for a node with none and for a family that
    /// has no such thing. Each value is in the boundary form [`Xattr`] describes, whatever
    /// the family stored it as.
    pub xattrs: Vec<Xattr>,
    /// The properties in `meta` that the family invented rather than read, because its
    /// format has no field for them. Empty for a family that records everything, which
    /// costs nothing.
    pub synthesized: Vec<Property>,
}

impl Attributes {
    /// Attributes read whole from the filesystem, with nothing invented.
    #[must_use]
    pub fn read(meta: Metadata, xattrs: Vec<Xattr>) -> Self {
        Self {
            meta,
            xattrs,
            synthesized: Vec::new(),
        }
    }

    /// What a [`stat`](FsTree::stat) answers on a family whose whole record of a node is a
    /// read-only bit and two times.
    ///
    /// This is the read-side mirror of
    /// [`LossPolicy::record_losses`](crate::fidelity::LossPolicy), which is the one place
    /// that says what such a format *drops*. The two families in that class lose the same
    /// six properties for the same reason and invent the same four back, so both answers
    /// have one home and neither can gain a clause the other does not.
    ///
    /// `times` is `(access, modification)`, or `None` for a node the format stores no entry
    /// for — the root directory on both families, which therefore has no times at all rather
    /// than invented ones. There is no change time in either format, so the modification time
    /// stands for it: it is the closest thing the volume records, and the alternative is a
    /// value invented out of nothing.
    ///
    /// The read-only bit is the single permission bit either format holds, and it clears the
    /// write bits of whatever mode the caller named. The other eight still came from the
    /// caller and nothing in the volume speaks to them, which is why the mode is named as
    /// invented either way.
    #[cfg(any(feature = "fat", feature = "exfat"))]
    pub(crate) fn from_read_only_bit(
        synthesis: &Synthesis,
        is_dir: bool,
        read_only: bool,
        times: Option<(crate::time::Timestamp, crate::time::Timestamp)>,
    ) -> Self {
        let mut mode = if is_dir {
            synthesis.dir_mode
        } else {
            synthesis.file_mode
        };
        if read_only {
            mode &= !crate::fidelity::WRITE_BITS;
        }
        let zero = crate::time::Timestamp::from_secs(0);
        let (atime, mtime) = times.unwrap_or((zero, zero));
        let mut synthesized = vec![
            Property::Ownership,
            Property::Permissions,
            Property::ChangeTime,
        ];
        if times.is_none() {
            synthesized.push(Property::AccessTime);
            synthesized.push(Property::ModificationTime);
        }
        Self {
            meta: Metadata {
                mode,
                uid: synthesis.uid,
                gid: synthesis.gid,
                atime,
                ctime: mtime,
                mtime,
            },
            xattrs: Vec::new(),
            synthesized,
        }
    }
}

/// The four operations an extraction needs of a filesystem, whichever family it is.
///
/// Implemented by each family's reader. A sink is written once against this and drains an
/// ext4 image, a FAT image, or anything else a later family adds, without a `match` and
/// without knowing what it is draining.
///
/// The trait is deliberately narrow. It is not a general filesystem interface and is not
/// meant to grow into one: a question only one family can answer belongs on that family's
/// concrete reader, which a caller reaches by matching on what opening an image hands
/// back.
pub trait FsTree {
    /// The family's own handle to a node — an inode, a directory entry, whatever it
    /// already holds. A sink treats it as opaque and hands it back unchanged.
    type Node;

    /// Which family this reader is of, which is what a [`TreeError`] it produces names.
    fn family(&self) -> Family;

    /// The cap a read through this reader is held to — the caller's
    /// [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), which defaults to no cap
    /// at all.
    ///
    /// The reader answers rather than the caller because the limits are the ones the
    /// reader was opened under, and a sink draining it never saw them.
    fn max_file_bytes(&self) -> u64;

    /// Walk every name in the tree, calling `visit` for each.
    ///
    /// The root comes first, under the empty path, so a sink that has to apply the root's
    /// own metadata does not need a second way to reach it. After that the order is
    /// depth-first with a parent before its children and siblings in a deterministic order,
    /// which is what lets a sink hold one open handle per directory on the current path
    /// rather than one per directory in the tree.
    ///
    /// The visitor is handed the reader back, so it can stat, read, and resolve while the
    /// walk is in progress and nothing has to be gathered up front. The error type is the
    /// visitor's, so a sink's own failures and the filesystem's stop the walk as
    /// themselves.
    ///
    /// # Errors
    ///
    /// Whatever the visitor returns, and a [`TreeError`] converted into it when the
    /// filesystem cannot be walked.
    fn walk_tree<E, F>(&mut self, visit: F) -> Result<(), E>
    where
        E: From<TreeError>,
        F: FnMut(&mut Self, TreeEntry<Self::Node>) -> Result<(), E>;

    /// Everything recorded about one node: its ownership, mode, and times, and its extended
    /// attributes.
    ///
    /// A property the family's format has no field for is filled from `synthesis` and named
    /// in [`Attributes::synthesized`], so what comes back is always complete and always
    /// says what in it was invented. A family that records a property ignores the
    /// corresponding input.
    ///
    /// # Errors
    ///
    /// A [`TreeError`] if the node's metadata or attributes cannot be read.
    fn stat(&mut self, node: &Self::Node, synthesis: &Synthesis) -> Result<Attributes, TreeError>;

    /// Fill `buf` from `offset` in a regular file, returning how many bytes were placed.
    ///
    /// A short fill means the file ends there. Reading a whole file is a loop over this
    /// rather than one call, which is what keeps a sink's memory the size of its buffer
    /// instead of the size of the largest file in the tree.
    ///
    /// A node that is not a regular file holds no bytes, and this yields none of them: a
    /// directory's storage is its entries and a device node's is a pair of numbers, and
    /// handing either back as file contents would be a block pointer or a device number
    /// read as data. Every implementation answers that way, so a sink that asks gets the
    /// same nothing whichever family it is draining.
    ///
    /// # Errors
    ///
    /// A [`TreeError`] if the file's bytes cannot be read.
    fn read_bytes(
        &mut self,
        node: &Self::Node,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, TreeError>;

    /// A symbolic link's target, exactly as the filesystem records it.
    ///
    /// The target is reproduced as it stands — a link pointing at `/etc/passwd` or at
    /// `../../..` is that link, and reproducing it is what an extraction is for. Nothing
    /// here resolves it.
    ///
    /// # Errors
    ///
    /// A [`TreeError`] if the target cannot be read. Calling it on a node that is not a
    /// symbolic link is a [`TreeError::Malformed`].
    fn link_target(&mut self, node: &Self::Node) -> Result<Vec<u8>, TreeError>;

    /// Refuse a file whose declared length is past the cap this read is held to — the
    /// caller's [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), which defaults to
    /// no cap at all.
    ///
    /// A sink asks so that the cap governs what an *extraction writes*, and not only what a
    /// whole-file read returns. Every sink here streams a file through a fixed buffer, so a
    /// sink's own memory is bounded whatever the file claims — but the bytes it writes are
    /// driven entirely by the size the image declares, and a hole reads back as zeros. An
    /// inode claiming sixteen tebibytes and mapping nothing therefore costs an extraction
    /// sixteen tebibytes of zeros written into the destination, from an image of a hundred
    /// kilobytes, with no setting a caller could reach that prevented it.
    ///
    /// The check is on the declared length and happens before a byte is written, so what a
    /// sink refuses is exactly what a whole-file read of the same node would refuse.
    ///
    /// The rule is one rule and the refusal is one sentence, so this is written here rather
    /// than once per family: what varies between them is the family in the message and the
    /// cap being applied, and both are asked for above.
    ///
    /// # Errors
    ///
    /// [`TreeError::LimitExceeded`] naming the path and the cap.
    // In a build with no family compiled in, [`Family`] has no variants, so `family()`
    // cannot return and everything after it here is unreachable. That build also has no
    // implementor of this trait, which is what makes the body dead rather than wrong. The
    // predicate names every family, so a build carrying any one of them reaches every line
    // here and carries no allowance hiding what the allowance was scoped to expose.
    #[cfg_attr(
        not(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs")),
        allow(unreachable_code, unused_variables)
    )]
    fn check_file_size(&self, path: &[u8], size: u64) -> Result<(), TreeError> {
        let cap = self.max_file_bytes();
        if size > cap {
            return Err(TreeError::LimitExceeded {
                family: self.family(),
                detail: format!(
                    "{}: the file is {size} bytes, more than the {cap}-byte cap this read \
                     is held to",
                    crate::escape::printable(path)
                ),
            });
        }
        Ok(())
    }
}

/// Every failure a walk through [`FsTree::walk_tree`] can have, kept apart until the walk
/// ends.
///
/// A family's walk carries one error type; a walk through this surface has three sources for
/// one — the filesystem's own, a node the shared frame cannot describe, and the visitor's,
/// which is the sink's. Collapsing them at the point they occur would report a sink's failure
/// as a fault in the image, so they ride separately for the length of the walk and are
/// unwrapped at the end.
///
/// `R` is the family's own read error. It is a parameter rather than a fixed type because the
/// conversion that makes `?` work on it — `From<R>` — is what each family writes for itself;
/// a blanket one here would collide with the reflexive `From<T> for T`.
///
/// Compiled where a family is: with none there is no tree to walk.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) enum WalkFail<R, E> {
    /// The filesystem's own failure, which the family's walk produced.
    Read(R),
    /// A node the walk reached that the shared frame cannot describe.
    ///
    /// A property of this surface rather than of any family, which is why every family's
    /// walk handles it. Only the ext family produces one today: an inode's mode nibble can
    /// name no file type, where every FAT node is a directory or a file and both are kinds
    /// the frame has.
    #[cfg_attr(not(feature = "ext"), allow(dead_code))]
    Tree(TreeError),
    /// The visitor's own failure, which is the sink's.
    Visitor(E),
}

#[cfg(test)]
mod tests {
    use super::{NodeKind, TreeEntry};

    #[test]
    fn an_entry_has_no_second_name_until_one_is_declared() {
        let entry = TreeEntry::new(b"/etc/hostname".to_vec(), NodeKind::File { size: 9 }, 12u32);
        assert_eq!(entry.shared, None);
        assert_eq!(entry.node, 12);
        // A node the family says has more than one name carries the identity the names
        // share, which is what lets a sink write the second as a link to the first.
        assert_eq!(entry.shared(12).shared, Some(12));
    }
}
