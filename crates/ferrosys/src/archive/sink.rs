//! Writing a filesystem's contents out as a tar archive: the [`ArchiveSink`].
//!
//! This is [`ArchiveSource`](crate::archive::ArchiveSource) in the other direction, and the
//! two are deliberately a pair — what this writes, that reads, and the round trip
//! reproduces the filesystem it came from.
//!
//! # What the archive carries
//!
//! Everything the filesystem holds that tar can express, and nothing is dropped in silence.
//! Ownership, mode bits, symlinks, hard links, device and FIFO nodes come out in the header;
//! the times (to the nanosecond, and negative where the file predates the epoch), the paths,
//! the ids, the extended attributes, and the POSIX ACLs come out in PAX records, because the
//! header cannot hold them. A socket has no tar entry type at all, so a filesystem holding
//! one is a typed error rather than an archive quietly missing a file.
//!
//! The PAX record is authoritative for every field it carries, and it is always written. The
//! header's own path and link-target fields hold the same value when it fits in them, and
//! are left empty when it does not — so they are either right or absent, never subtly wrong.
//!
//! A record is written in the length-prefixed form the format defines, so its value is
//! delimited by the count and not by the newline that ends the record. A filesystem holding a
//! name with a newline in it therefore round-trips: the length says where the value stops.
//!
//! # Any family, and what that costs a value
//!
//! The source is any [`FsTree`], so the same sink drains whatever `open` hands back. A
//! filesystem that does not record ownership or permission bits has them filled from the
//! [`Synthesis`] the caller named, and every value invented that way is named in the
//! [`FidelityReport`] the write returns — so an archive built from such an image says what
//! in it was the image's and what was policy.
//!
//! # What comes out is what goes back in
//!
//! The archive opens with a `./` member describing the root directory, which is how the
//! root's own metadata survives a round trip, and it omits `/lost+found`, which every
//! filesystem makes for itself and which a formatter refuses to be told to make.
//!
//! # Memory
//!
//! A file's bytes are streamed from the filesystem into the archive, so an archive of a tree
//! far larger than memory costs the working set of one read rather than the size of its
//! largest file. The tree is walked entry by entry for the same reason: nothing accumulates
//! but the hard-link table, which holds one path per node that has more than one name.

use std::collections::HashMap;
use std::io::{Read, Write};

use tar::{Builder, EntryType, Header};

use crate::archive::ArchiveError;
use crate::fidelity::{Direction, FidelityReport, Synthesis};
use crate::time::Timestamp;
use crate::tree::{Attributes, FsTree, NodeKind, TreeEntry, TreeError};

/// `/lost+found`, the one path an archive must not carry: every filesystem makes it for
/// itself, and a formatter refuses a source that tries to make it again.
const LOST_FOUND: &[u8] = b"/lost+found";

/// Writes a filesystem's contents out as a tar archive with PAX extensions.
///
/// The counterpart to [`ArchiveSource`](crate::archive::ArchiveSource): one reads a tree
/// into a filesystem, this writes a filesystem back out as a tree, and an archive that makes
/// the round trip describes the same filesystem at both ends.
///
/// ```no_run
/// # use ferrosys::ArchiveSink;
/// # use ferrosys::ext::Reader;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut reader = Reader::open(std::fs::File::open("rootfs.img")?)?;
/// let out = std::io::BufWriter::new(std::fs::File::create("rootfs.tar")?);
/// let fidelity = ArchiveSink::new(out).write_tree(&mut reader)?;
/// assert!(fidelity.is_faithful());
/// # Ok(())
/// # }
/// ```
pub struct ArchiveSink<W: Write> {
    builder: Builder<W>,
    synthesis: Synthesis,
}

impl<W: Write> ArchiveSink<W> {
    /// A sink that writes its archive to `out`.
    ///
    /// Nothing is buffered here beyond what tar's own framing needs, so a destination that
    /// benefits from buffering should be wrapped in a [`BufWriter`](std::io::BufWriter)
    /// before it is handed over.
    #[must_use]
    pub fn new(out: W) -> Self {
        Self {
            builder: Builder::new(out),
            synthesis: Synthesis::new(),
        }
    }

    /// Name what to record for a property the source filesystem has no field for.
    ///
    /// Defaults to [`Synthesis::new`] — owned by root, `0644` for a file and `0755` for a
    /// directory. Ignored entirely by a filesystem that records the property itself.
    #[must_use]
    pub fn synthesis(mut self, synthesis: Synthesis) -> Self {
        self.synthesis = synthesis;
        self
    }

    /// Write the filesystem's whole tree, then finish the archive.
    ///
    /// The archive's first member is `./`, the root directory, so the root's own metadata
    /// and attributes survive; `/lost+found` and everything under it is omitted. Every other
    /// name the filesystem holds appears exactly once, with the second and later names for
    /// one node written as hard links to the first.
    ///
    /// The returned [`FidelityReport`] names every property the source filesystem had no
    /// field for and the archive therefore carries an invented value of. It is faithful for
    /// a family that records everything.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::Read`] if the filesystem cannot be read; [`ArchiveError::Io`] if the
    /// destination cannot be written; [`ArchiveError::Unrepresentable`] if the filesystem
    /// holds a socket, and [`ArchiveError::XattrNameUnrepresentable`] if an attribute's name
    /// cannot be written to a PAX record.
    pub fn write_tree<T: FsTree>(mut self, tree: &mut T) -> Result<FidelityReport, ArchiveError> {
        // The first name to reach a node is the file; every later name for the same node is
        // another name for it — a hard link — and the archive says so rather than storing
        // the bytes a second time.
        let mut named: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut fidelity = FidelityReport::new();
        let synthesis = self.synthesis;

        // Walked entry by entry rather than gathered, so the memory an archive costs does
        // not grow with the number of names in the tree. The walk reports in this module's
        // own error vocabulary, so a member that cannot be written and a directory that
        // cannot be read both stop it as themselves. The root arrives first, under the empty
        // path, which is what becomes the `./` member.
        tree.walk_tree(|tree, entry| {
            if is_lost_found(&entry.path) {
                return Ok(());
            }
            let member = Member::of(tree, entry, &mut named, &synthesis, &mut fidelity)?;
            self.append(tree, &member)
        })?;

        self.builder.finish().map_err(ArchiveError::Io)?;
        Ok(fidelity)
    }

    /// Append one member: its PAX records, then its header and contents.
    ///
    /// The records go first because that is where they apply — an `x` header describes the
    /// entry that follows it.
    fn append<T: FsTree>(&mut self, tree: &mut T, m: &Member<T::Node>) -> Result<(), ArchiveError> {
        let name = member_name(&m.path, matches!(m.kind, NodeKind::Directory));

        let entry_type = if m.hardlink.is_some() {
            EntryType::Link
        } else {
            match m.kind {
                NodeKind::Directory => EntryType::Directory,
                NodeKind::File { .. } => EntryType::Regular,
                NodeKind::Symlink => EntryType::Symlink,
                NodeKind::CharDevice { .. } => EntryType::Char,
                NodeKind::BlockDevice { .. } => EntryType::Block,
                NodeKind::Fifo => EntryType::Fifo,
                // A socket has no tar entry type at all, and is refused before a member is
                // ever built for it. Matched by name rather than by wildcard so a
                // `NodeKind` a later family adds is a compile error here, which forces a
                // decision about how tar carries it.
                NodeKind::Socket => {
                    return Err(ArchiveError::Unrepresentable {
                        path: m.path.clone(),
                    });
                }
            }
        };
        let target = m.hardlink.as_ref().or(m.symlink.as_ref());
        let meta = &m.attrs.meta;

        // Every field the header cannot hold exactly goes into a PAX record, and the ones it
        // can go into both: the record is authoritative, and every reader that honours it —
        // GNU tar, bsdtar, and this crate's own archive source among them — reads the exact
        // value whatever the header says.
        let mut records: Vec<(String, Vec<u8>)> = vec![
            ("path".to_string(), name.clone()),
            ("atime".to_string(), pax_time(meta.atime).into()),
            ("ctime".to_string(), pax_time(meta.ctime).into()),
            ("mtime".to_string(), pax_time(meta.mtime).into()),
            ("uid".to_string(), meta.uid.to_string().into()),
            ("gid".to_string(), meta.gid.to_string().into()),
        ];
        if let Some(target) = target {
            records.push(("linkpath".to_string(), target.clone()));
        }
        for xattr in &m.attrs.xattrs {
            records.push((pax_xattr_key(&m.path, &xattr.name)?, xattr.value.clone()));
        }
        let borrowed: Vec<(&str, &[u8])> = records
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        self.builder
            .append_pax_extensions(borrowed)
            .map_err(ArchiveError::Io)?;

        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);
        header.set_mode(u32::from(meta.mode & 0o7777));
        header.set_uid(u64::from(meta.uid));
        header.set_gid(u64::from(meta.gid));
        // The header's time is unsigned whole seconds, so a file older than the epoch or one
        // carrying a sub-second time cannot be written there. The PAX record above holds the
        // real value; this is the approximation a reader that ignores it would see.
        header.set_mtime(u64::try_from(meta.mtime.secs).unwrap_or(0));
        if let NodeKind::CharDevice { major, minor } | NodeKind::BlockDevice { major, minor } =
            m.kind
        {
            header.set_device_major(major).map_err(ArchiveError::Io)?;
            header.set_device_minor(minor).map_err(ArchiveError::Io)?;
        }
        // A path or a target that is text and short enough goes into the header as well,
        // where a reader that ignores PAX records finds it. One that is neither — not text,
        // or too long for the field — is left out rather than truncated into a name that is
        // not the file's, or transliterated into a differently-named file. The PAX record
        // above holds it exactly either way, so an empty field here is honestly absent,
        // never subtly wrong.
        if let Ok(text) = std::str::from_utf8(&name) {
            let _ = header.set_path(text);
        }
        if let Some(target) = target
            && let Ok(text) = std::str::from_utf8(target)
        {
            let _ = header.set_link_name(text);
        }

        // A regular file's bytes are streamed out of the filesystem rather than held: the
        // reader fills the archive from the blocks as it goes. Everything else has no body
        // at all — a hard link's contents belong to the node the first name wrote.
        //
        // The size declared is the length the body will actually run to, which is what the
        // walk reported rather than what any size field claims. A header promising more than
        // the body carries is an archive a reader that trusts it mis-frames.
        let size = match m.kind {
            NodeKind::File { size } if m.hardlink.is_none() => size,
            _ => 0,
        };
        // What an archive *writes* is driven entirely by a length the filesystem declares,
        // and a hole reads back as zeros — so an inode claiming terabytes and mapping
        // nothing costs terabytes of members, from an image of a few kilobytes. The cap a
        // caller set on what a read will return governs that too, checked before a byte is
        // written and against the same declared length a whole-file read would have refused.
        tree.check_file_size(&m.path, size)?;
        header.set_size(size);
        header.set_cksum();
        if size == 0 {
            return self
                .builder
                .append(&header, std::io::empty())
                .map_err(ArchiveError::Io);
        }
        let body = NodeData::new(tree, &m.node, size);
        self.builder
            .append(&header, body)
            .map_err(|e| ArchiveError::from_body_io(e, &m.path))
    }
}

/// A regular file's bytes as a [`Read`], filled from the filesystem a window at a time.
///
/// This is what keeps an archive's memory bounded: `tar` copies a body out of a reader, so
/// handing it one that reads through the filesystem means neither side ever holds the file.
struct NodeData<'a, T: FsTree> {
    tree: &'a mut T,
    node: &'a T::Node,
    offset: u64,
    /// The length the header declared, which the body is held to exactly: a filesystem
    /// yielding more than was promised would push the archive's framing out of step with it.
    size: u64,
}

impl<'a, T: FsTree> NodeData<'a, T> {
    fn new(tree: &'a mut T, node: &'a T::Node, size: u64) -> Self {
        Self {
            tree,
            node,
            offset: 0,
            size,
        }
    }
}

impl<T: FsTree> Read for NodeData<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.size.saturating_sub(self.offset);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
        // A read failure of the *filesystem* has to reach the caller through `io::Error`,
        // because that is the only failure a `Read` has. The kind is kept, and the message
        // carries what the reader said, so nothing is lost on the way through.
        let filled = self
            .tree
            .read_bytes(self.node, self.offset, &mut buf[..want])
            .map_err(|e| match e {
                TreeError::Io { kind, message } => std::io::Error::new(kind, message),
                other => std::io::Error::other(other.to_string()),
            })?;
        self.offset += filled as u64;
        Ok(filled)
    }
}

/// One archive member: what the header and its records say, and the node a body comes from.
struct Member<N> {
    /// The path in the filesystem. Empty for the root, which has no name of its own.
    path: Vec<u8>,
    /// What is at the path.
    kind: NodeKind,
    /// The mode, ownership, times, and attributes to record.
    attrs: Attributes,
    /// The member this name is a second name for, when it is a hard link.
    hardlink: Option<Vec<u8>>,
    /// Where a symbolic link points.
    symlink: Option<Vec<u8>>,
    /// The family's handle to the node, for streaming a regular file's bytes.
    node: N,
}

impl<N> Member<N> {
    /// Everything one walk entry contributes to the archive.
    fn of<T: FsTree<Node = N>>(
        tree: &mut T,
        entry: TreeEntry<N>,
        named: &mut HashMap<u64, Vec<u8>>,
        synthesis: &Synthesis,
        fidelity: &mut FidelityReport,
    ) -> Result<Self, ArchiveError> {
        let TreeEntry {
            path,
            kind,
            shared,
            node,
            ..
        } = entry;
        if matches!(kind, NodeKind::Socket) {
            return Err(ArchiveError::Unrepresentable { path });
        }

        // A node the walk says is reachable by more than one name is the file the first time
        // it is seen and a hard link every time after. Only such a node carries an identity,
        // so the table holds the tree's hard links rather than a path per file in it.
        let hardlink = match shared {
            // A hard link's target is a member of this same archive, so it is named the way
            // that member is named.
            Some(id) => match named.get(&id) {
                Some(first) => Some(member_name(first, false)),
                None => {
                    named.insert(id, path.clone());
                    None
                }
            },
            None => None,
        };

        let mut attrs = tree.stat(&node, synthesis)?;
        for property in &attrs.synthesized {
            fidelity.record(Direction::Synthesized, &path, *property);
        }
        // A hard link carries nothing of its own: the contents and the attributes belong to
        // the node, which the name that came first already wrote.
        if hardlink.is_some() {
            attrs.xattrs.clear();
        }

        let symlink = if matches!(kind, NodeKind::Symlink) && hardlink.is_none() {
            Some(tree.link_target(&node)?)
        } else {
            None
        };

        Ok(Self {
            path,
            kind,
            attrs,
            hardlink,
            symlink,
            node,
        })
    }
}

/// Whether a path is `/lost+found` or something inside it.
fn is_lost_found(path: &[u8]) -> bool {
    path == LOST_FOUND || path.starts_with(b"/lost+found/")
}

/// The name a path takes inside an archive: `/etc/hostname` becomes `./etc/hostname`, and
/// the root becomes `./`.
///
/// A relative name is what a tar archive carries and what an extractor unpacks without
/// argument; the archive source maps it back to an absolute path on the way in. A
/// directory's name ends in a slash, as every tar writer marks one.
fn member_name(path: &[u8], directory: bool) -> Vec<u8> {
    let mut name = Vec::with_capacity(path.len() + 2);
    name.push(b'.');
    name.extend_from_slice(path);
    if directory {
        name.push(b'/');
    }
    name
}

/// A timestamp as a PAX record's value: decimal seconds, with a fractional part when the
/// time carries one.
///
/// A negative time floors its seconds and carries the fraction up towards the next
/// second — the same convention the archive source reads back — so
/// `Timestamp { secs: -6, nanos: 750_000_000 }` is written `-5.250000000`, which is the
/// instant it names.
///
/// A filesystem's stored fraction need not divide a second — ext4's is a thirty-bit field —
/// so an image this crate did not write can name more nanoseconds than there are in one.
/// Such a fraction is carried into the seconds before anything is written, so the record
/// names the instant the two fields describe and always holds a nine-digit fraction, rather
/// than a ten-digit one a reader would scale wrongly.
#[must_use]
fn pax_time(t: Timestamp) -> String {
    // Normalize first: every case below assumes a fraction smaller than a second.
    let t = Timestamp {
        secs: t
            .secs
            .saturating_add(i64::from(t.nanos / Timestamp::NANOS_PER_SEC)),
        nanos: t.nanos % Timestamp::NANOS_PER_SEC,
    };
    if t.nanos == 0 {
        return t.secs.to_string();
    }
    if t.secs < 0 {
        let whole = t.secs + 1;
        let frac = Timestamp::NANOS_PER_SEC - t.nanos;
        // A time inside the last second before the epoch has no negative whole part to
        // carry the sign, so the sign is written onto the zero.
        if whole == 0 {
            return format!("-0.{frac:09}");
        }
        return format!("{whole}.{frac:09}");
    }
    format!("{}.{:09}", t.secs, t.nanos)
}

/// The PAX keyword for an extended attribute, `SCHILY.xattr.<name>`.
///
/// A PAX record's keyword is text and cannot hold an `=` (its key/value delimiter) or a
/// newline (its record terminator), so a name carrying either — or one that is not valid
/// UTF-8 — has no faithful spelling. It is refused rather than flattened through U+FFFD or
/// split at a delimiter into a differently-named attribute, which would corrupt the round
/// trip silently. Standard attribute names are ASCII without these bytes.
fn pax_xattr_key(path: &[u8], name: &[u8]) -> Result<String, ArchiveError> {
    match std::str::from_utf8(name) {
        Ok(text) if !text.contains('=') && !text.contains('\n') => {
            Ok(format!("SCHILY.xattr.{text}"))
        }
        _ => Err(ArchiveError::XattrNameUnrepresentable {
            path: path.to_vec(),
            name: name.to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_is_named_relative_to_the_archive_root() {
        assert_eq!(member_name(b"/etc/hostname", false), b"./etc/hostname");
        assert_eq!(member_name(b"/etc", true), b"./etc/");
        // The root has no name of its own, so it is the bare `./` — which is exactly what
        // the archive source reads back as the filesystem root.
        assert_eq!(member_name(b"", true), b"./");
    }

    #[test]
    fn lost_and_found_is_recognized_with_its_contents() {
        assert!(is_lost_found(b"/lost+found"));
        assert!(is_lost_found(b"/lost+found/17"));
        // A name that merely begins the same way is a different file.
        assert!(!is_lost_found(b"/lost+found-old"));
        assert!(!is_lost_found(b"/etc/lost+found"));
    }

    #[test]
    fn a_pax_xattr_key_is_built_for_a_plain_name_and_refused_otherwise() {
        // A standard ASCII name becomes the SCHILY.xattr keyword.
        assert_eq!(
            pax_xattr_key(b"/f", b"user.comment").unwrap(),
            "SCHILY.xattr.user.comment"
        );

        // A name a PAX keyword cannot carry faithfully is a typed error, not a silently
        // corrupted record: an embedded '=' or newline (the record's own delimiters) or a
        // byte that is not valid UTF-8.
        for bad in [&b"user.a=b"[..], b"user.a\nb", b"user.\xff"] {
            assert!(
                matches!(
                    pax_xattr_key(b"/f", bad),
                    Err(ArchiveError::XattrNameUnrepresentable { .. })
                ),
                "name {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_pax_time_is_the_instant_it_names() {
        assert_eq!(pax_time(Timestamp::from_secs(1_700_000_000)), "1700000000");
        assert_eq!(
            pax_time(Timestamp {
                secs: 1_700_000_000,
                nanos: 123_456_789
            }),
            "1700000000.123456789"
        );
        // A negative time stores the floored second and the fraction up to the next one;
        // the decimal form is the instant itself.
        assert_eq!(
            pax_time(Timestamp {
                secs: -6,
                nanos: 750_000_000
            }),
            "-5.250000000"
        );
        // Inside the last second before the epoch there is no negative whole part, so the
        // sign is written onto the zero.
        assert_eq!(
            pax_time(Timestamp {
                secs: -1,
                nanos: 500_000_000
            }),
            "-0.500000000"
        );
        assert_eq!(pax_time(Timestamp::from_secs(-1)), "-1");
    }

    #[test]
    fn a_pax_time_carries_an_over_long_fraction_into_the_seconds() {
        // A filesystem's stored fraction need not divide a second, so an image this crate
        // did not write can name more nanoseconds than a second holds. The record still
        // names the instant the two fields describe, with a nine-digit fraction: writing the
        // raw value would make a ten-digit one, which a reader scales as a tenth of what was
        // meant.
        assert_eq!(
            pax_time(Timestamp {
                secs: 100,
                nanos: 1_073_741_823 // the largest ext4's field holds
            }),
            "101.073741823"
        );
        // The same on the negative side, where the fraction is written as the distance to
        // the next second — the subtraction that an over-long fraction would otherwise
        // take below zero.
        assert_eq!(
            pax_time(Timestamp {
                secs: -6,
                nanos: 1_073_741_823
            }),
            "-4.926258177"
        );
        // A whole number of extra seconds leaves no fraction at all.
        assert_eq!(
            pax_time(Timestamp {
                secs: 10,
                nanos: 2_000_000_000
            }),
            "12"
        );
    }
}
