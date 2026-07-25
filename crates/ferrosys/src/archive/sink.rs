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
//! but the hard-link table, which holds one path per inode that has more than one name.

use std::collections::HashMap;
use std::io::{Read, Seek, Write};

use tar::{Builder, EntryType, Header};

use crate::acl::Acl;
use crate::archive::ArchiveError;
use crate::ondisk::{Inode, Timestamp, Xattr};
use crate::read::{ReadError, Reader, WalkEntry};

/// `/lost+found`, the one path an archive must not carry: every filesystem makes it for
/// itself, and a formatter refuses a source that tries to make it again.
const LOST_FOUND: &[u8] = b"/lost+found";

/// The root directory's inode number.
const ROOT_INO: u32 = 2;

/// The file-type bits of a mode, and the types they name.
const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFREG: u16 = 0o100000;
const IFLNK: u16 = 0o120000;
const IFCHR: u16 = 0o020000;
const IFBLK: u16 = 0o060000;
const IFIFO: u16 = 0o010000;
const IFSOCK: u16 = 0o140000;

/// Writes a filesystem's contents out as a tar archive with PAX extensions.
///
/// The counterpart to [`ArchiveSource`](crate::archive::ArchiveSource): one reads a tree
/// into a filesystem, this writes a filesystem back out as a tree, and an archive that makes
/// the round trip describes the same filesystem at both ends.
///
/// ```no_run
/// # use ferrosys::ext::{ArchiveSink, Reader};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut reader = Reader::open(std::fs::File::open("rootfs.img")?)?;
/// let out = std::io::BufWriter::new(std::fs::File::create("rootfs.tar")?);
/// ArchiveSink::new(out).write_tree(&mut reader)?;
/// # Ok(())
/// # }
/// ```
pub struct ArchiveSink<W: Write> {
    builder: Builder<W>,
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
        }
    }

    /// Write the filesystem's whole tree, then finish the archive.
    ///
    /// The archive's first member is `./`, the root directory, so the root's own metadata
    /// and attributes survive; `/lost+found` and everything under it is omitted. Every other
    /// name the filesystem holds appears exactly once, with the second and later names for
    /// one inode written as hard links to the first.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::Read`] if the filesystem cannot be read; [`ArchiveError::Io`] if the
    /// destination cannot be written; [`ArchiveError::Unrepresentable`] if the filesystem
    /// holds a socket, and [`ArchiveError::XattrNameUnrepresentable`] if an attribute's name
    /// cannot be written to a PAX record.
    pub fn write_tree<R: Read + Seek>(
        mut self,
        reader: &mut Reader<R>,
    ) -> Result<(), ArchiveError> {
        // The root has no name, so the walk does not reach it; the `./` member is what
        // carries its mode, ownership, times, and attributes across.
        let root = reader.inode(ROOT_INO)?;
        let xattrs = reader.xattrs(&root)?;
        self.append(reader, &Member::root(root, xattrs))?;

        // The first name to reach an inode is the file; every later name for the same inode
        // is another name for it — a hard link — and the archive says so rather than storing
        // the bytes a second time.
        let mut named: HashMap<u32, Vec<u8>> = HashMap::new();
        // Walked entry by entry rather than gathered, so the memory an archive costs does
        // not grow with the number of names in the tree. The walk reports in this module's
        // own error vocabulary, so a member that cannot be written and a directory that
        // cannot be read both stop it as themselves.
        reader.walk_with(|reader, entry| {
            if is_lost_found(&entry.path) {
                return Ok(());
            }
            let member = Member::of(reader, entry, &mut named)?;
            self.append(reader, &member)
        })?;

        self.builder.finish().map_err(ArchiveError::Io)
    }

    /// Append one member: its PAX records, then its header and contents.
    ///
    /// The records go first because that is where they apply — an `x` header describes the
    /// entry that follows it.
    fn append<R: Read + Seek>(
        &mut self,
        reader: &mut Reader<R>,
        m: &Member,
    ) -> Result<(), ArchiveError> {
        let kind = m.inode.mode & IFMT;
        let name = member_name(&m.path, kind == IFDIR);

        let entry_type = if m.hardlink.is_some() {
            EntryType::Link
        } else {
            match kind {
                IFDIR => EntryType::Directory,
                IFREG => EntryType::Regular,
                IFLNK => EntryType::Symlink,
                IFCHR => EntryType::Char,
                IFBLK => EntryType::Block,
                IFIFO => EntryType::Fifo,
                // A socket is refused before a member is ever built for it.
                _ => {
                    return Err(ArchiveError::Unrepresentable {
                        path: m.path.clone(),
                    });
                }
            }
        };
        let target = m.hardlink.as_ref().or(m.symlink.as_ref());

        // Every field the header cannot hold exactly goes into a PAX record, and the ones it
        // can go into both: the record is authoritative, and every reader that honours it —
        // GNU tar, bsdtar, and this crate's own archive source among them — reads the exact
        // value whatever the header says.
        let mut records: Vec<(String, Vec<u8>)> = vec![
            ("path".to_string(), name.clone()),
            ("atime".to_string(), pax_time(m.inode.atime).into()),
            ("ctime".to_string(), pax_time(m.inode.ctime).into()),
            ("mtime".to_string(), pax_time(m.inode.mtime).into()),
            ("uid".to_string(), m.inode.uid.to_string().into()),
            ("gid".to_string(), m.inode.gid.to_string().into()),
        ];
        if let Some(target) = target {
            records.push(("linkpath".to_string(), target.clone()));
        }
        for xattr in &m.xattrs {
            records.push((
                pax_xattr_key(&m.path, &xattr.name)?,
                xattr_value(&m.path, xattr)?,
            ));
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
        header.set_mode(u32::from(m.inode.mode & 0o7777));
        header.set_uid(u64::from(m.inode.uid));
        header.set_gid(u64::from(m.inode.gid));
        // The header's time is unsigned whole seconds, so a file older than the epoch or one
        // carrying a sub-second time cannot be written there. The PAX record above holds the
        // real value; this is the approximation a reader that ignores it would see.
        header.set_mtime(u64::try_from(m.inode.mtime.secs).unwrap_or(0));
        if let Some((major, minor)) = m.device {
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
        // size is the inode's, and the reader fills the archive from the blocks as it goes.
        // Everything else has no body at all — a hard link's contents belong to the inode
        // the first name wrote.
        let size = if m.streams_data { m.inode.size } else { 0 };
        header.set_size(size);
        header.set_cksum();
        if size == 0 {
            return self
                .builder
                .append(&header, std::io::empty())
                .map_err(ArchiveError::Io);
        }
        let body = InodeData::new(reader, m.inode.clone());
        self.builder
            .append(&header, body)
            .map_err(|e| ArchiveError::from_body_io(e, &m.path))
    }
}

/// A regular file's bytes as a [`Read`], filled from the filesystem a window at a time.
///
/// This is what keeps an archive's memory bounded: `tar` copies a body out of a reader, so
/// handing it one that reads through the filesystem means neither side ever holds the file.
struct InodeData<'a, R> {
    reader: &'a mut Reader<R>,
    inode: Inode,
    offset: u64,
}

impl<'a, R: Read + Seek> InodeData<'a, R> {
    fn new(reader: &'a mut Reader<R>, inode: Inode) -> Self {
        Self {
            reader,
            inode,
            offset: 0,
        }
    }
}

impl<R: Read + Seek> Read for InodeData<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // A read failure of the *filesystem* has to reach the caller through `io::Error`,
        // because that is the only failure a `Read` has. The kind is kept, and the message
        // carries what the reader said, so nothing is lost on the way through.
        let filled = self
            .reader
            .read_into(&self.inode, self.offset, buf)
            .map_err(|e| match e {
                ReadError::Io { kind, message } => std::io::Error::new(kind, message),
                other => std::io::Error::other(other.to_string()),
            })?;
        self.offset += filled as u64;
        Ok(filled)
    }
}

/// One archive member: what the header and its records say, and whether a body follows.
struct Member {
    /// The path in the filesystem. Empty for the root, which has no name of its own.
    path: Vec<u8>,
    /// The mode, ownership, times, and size to record.
    inode: Inode,
    /// The attributes to carry, in the form an archive holds them.
    xattrs: Vec<Xattr>,
    /// The member this name is a second name for, when it is a hard link.
    hardlink: Option<Vec<u8>>,
    /// Where a symbolic link points.
    symlink: Option<Vec<u8>>,
    /// A device node's major and minor numbers.
    device: Option<(u32, u32)>,
    /// Whether a body follows the header — true only for the first name of a regular file.
    streams_data: bool,
}

impl Member {
    /// The `./` member describing the filesystem root.
    fn root(inode: Inode, xattrs: Vec<Xattr>) -> Self {
        Self {
            path: Vec::new(),
            inode,
            xattrs,
            hardlink: None,
            symlink: None,
            device: None,
            streams_data: false,
        }
    }

    /// Everything one walk entry contributes to the archive.
    fn of<R: Read + Seek>(
        reader: &mut Reader<R>,
        entry: WalkEntry,
        named: &mut HashMap<u32, Vec<u8>>,
    ) -> Result<Self, ArchiveError> {
        let WalkEntry {
            path,
            number,
            inode,
            ..
        } = entry;
        let kind = inode.mode & IFMT;
        if kind == IFSOCK {
            return Err(ArchiveError::Unrepresentable { path });
        }

        // A directory has more than one link by construction — its own name and its `.` — so
        // link counts say nothing about it, and it is never another name for anything.
        let hardlink = if kind == IFDIR {
            None
        } else {
            match named.get(&number) {
                // A hard link's target is a member of this same archive, so it is named the
                // way that member is named.
                Some(first) => Some(member_name(first, false)),
                None => {
                    named.insert(number, path.clone());
                    None
                }
            }
        };
        // A hard link carries nothing of its own: the contents and the attributes belong to
        // the inode, which the name that came first already wrote.
        if hardlink.is_some() {
            return Ok(Self {
                path,
                inode,
                xattrs: Vec::new(),
                hardlink,
                symlink: None,
                device: None,
                streams_data: false,
            });
        }

        let symlink = if kind == IFLNK {
            Some(reader.read_symlink(&inode)?)
        } else {
            None
        };
        let device = if kind == IFCHR || kind == IFBLK {
            Some(reader.device(&inode))
        } else {
            None
        };
        let xattrs = reader.xattrs(&inode)?;

        Ok(Self {
            path,
            inode,
            xattrs,
            hardlink: None,
            symlink,
            device,
            streams_data: kind == IFREG,
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
/// An inode's stored fraction is a thirty-bit field, so a filesystem this crate did not
/// write can name more nanoseconds than there are in a second. Such a fraction is carried
/// into the seconds before anything is written, so the record names the instant the two
/// fields describe and always holds a nine-digit fraction — rather than a ten-digit one a
/// reader would scale wrongly.
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

/// The value an extended attribute takes in an archive.
///
/// A POSIX ACL is stored on disk in ext4's compact form, which is not the form the
/// `getxattr` boundary speaks — and an archive holds what `getxattr` would have given it.
/// So an ACL is decoded and written back out in the version-2 form, which is what GNU tar
/// reads and what the archive source expects on the way back in. Every other attribute is
/// bytes, and travels as bytes.
fn xattr_value(path: &[u8], xattr: &Xattr) -> Result<Vec<u8>, ArchiveError> {
    if xattr.name == Acl::ACCESS_NAME || xattr.name == Acl::DEFAULT_NAME {
        let acl = Acl::decode(&xattr.value).map_err(|source| ArchiveError::Acl {
            path: path.to_vec(),
            source,
        })?;
        return Ok(acl.encode_xattr_v2());
    }
    Ok(xattr.value.clone())
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
        // An inode's fraction is a thirty-bit field, so an image this crate did not write
        // can name more nanoseconds than a second holds. The record still names the
        // instant the two fields describe, with a nine-digit fraction: writing the raw
        // value would make a ten-digit one, which a reader scales as a tenth of what was
        // meant.
        assert_eq!(
            pax_time(Timestamp {
                secs: 100,
                nanos: 1_073_741_823 // the largest the field holds
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
