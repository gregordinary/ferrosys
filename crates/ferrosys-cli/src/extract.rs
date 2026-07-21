//! `ferrosys extract`: read a filesystem's contents back out — as a tar archive, as one
//! file's bytes, or as a listing.
//!
//! # What the archive carries
//!
//! Everything the filesystem holds that tar can express, and nothing is dropped in
//! silence. Ownership, mode bits, symlinks, hard links, device and FIFO nodes come out in
//! the header; the times (to the nanosecond, and negative where the file predates the
//! epoch), the paths, the ids, the extended attributes, and the POSIX ACLs come out in
//! PAX records, because the header cannot hold them. A socket has no tar entry type at
//! all, so an image holding one is a typed error rather than an archive quietly missing a
//! file.
//!
//! The PAX record is authoritative for every field it carries, and it is always written.
//! The header's own path and link-target fields hold the same value when it fits in them,
//! and are left empty when it does not — so they are either right or absent, never subtly
//! wrong.
//!
//! # What comes out is what goes back in
//!
//! The archive opens with a `./` member describing the root directory, which is how the
//! root's own metadata survives a round trip, and it omits `/lost+found`, which every
//! filesystem makes for itself and which a formatter refuses to be told to make. Feeding
//! this archive to `ferrosys format --from-tar` reproduces the filesystem it came from.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};

use ferrosys::ext::ondisk::{Inode, Timestamp, Xattr};
use ferrosys::ext::{Acl, ReadPolicy, Reader, WalkEntry};
use tar::{Builder, EntryType, Header};

use crate::args::{ExtractArgs, ExtractMode, Stream};
use crate::json::Obj;
use crate::{Error, emit, from_read, render};

/// `/lost+found`, the one path an archive must not carry: every filesystem makes it for
/// itself, and a formatter refuses a source that tries to make it again.
const LOST_FOUND: &[u8] = b"/lost+found";

/// The root directory's inode number.
const ROOT_INO: u32 = 2;

/// The file-type bits of a mode.
const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFREG: u16 = 0o100000;
const IFLNK: u16 = 0o120000;
const IFCHR: u16 = 0o020000;
const IFBLK: u16 = 0o060000;
const IFIFO: u16 = 0o010000;
const IFSOCK: u16 = 0o140000;

/// Read the filesystem the arguments name.
pub fn run(args: ExtractArgs) -> Result<(), Error> {
    let image = args.image.display().to_string();
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;
    let mut reader = Reader::open_at(file, args.offset, ReadPolicy::Lenient).map_err(|source| {
        Error::NotExt {
            path: image,
            source,
        }
    })?;

    match args.mode {
        ExtractMode::Cat(path) => cat(&mut reader, &path),
        ExtractMode::List { json } => list(&mut reader, json),
        ExtractMode::ToTar(Stream::Std) => {
            // The archive is the artifact, and it is the only thing on the standard
            // output: no summary, no count, not even on the standard error.
            let stdout = io::stdout();
            let mut out = stdout.lock();
            to_tar(&mut reader, &mut out)?;
            out.flush().map_err(|source| Error::Io {
                what: "standard output".to_string(),
                source,
            })
        }
        ExtractMode::ToTar(Stream::File(path)) => {
            let file = File::create(&path).map_err(|e| Error::io(&path, e))?;
            let mut out = io::BufWriter::new(file);
            to_tar(&mut reader, &mut out)?;
            out.flush().map_err(|e| Error::io(&path, e))
        }
    }
}

/// One archive member, gathered from the filesystem before any of it is written.
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
    /// A regular file's bytes.
    data: Vec<u8>,
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

/// Write the whole tree as a tar archive.
fn to_tar(reader: &mut Reader<File>, out: impl Write) -> Result<(), Error> {
    let entries = reader.walk().map_err(from_read)?;
    let mut builder = Builder::new(out);

    // The root has no name, so the walk does not reach it; the `./` member is what carries
    // its mode, ownership, times, and attributes across.
    let root = reader.inode(ROOT_INO).map_err(from_read)?;
    let root = Member {
        path: Vec::new(),
        xattrs: reader.xattrs(&root).map_err(from_read)?,
        inode: root,
        hardlink: None,
        symlink: None,
        device: None,
        data: Vec::new(),
    };
    append(&mut builder, &root)?;

    // The first name to reach an inode is the file; every later name for the same inode is
    // another name for it — a hard link — and the archive says so rather than storing the
    // bytes a second time.
    let mut named: HashMap<u32, Vec<u8>> = HashMap::new();
    for entry in entries {
        if is_lost_found(&entry.path) {
            continue;
        }
        append(&mut builder, &member(reader, entry, &mut named)?)?;
    }

    builder.finish().map_err(archive_write)
}

/// Gather everything one walk entry contributes to the archive.
fn member(
    reader: &mut Reader<File>,
    entry: WalkEntry,
    named: &mut HashMap<u32, Vec<u8>>,
) -> Result<Member, Error> {
    let WalkEntry {
        path,
        number,
        inode,
    } = entry;
    let kind = inode.mode & IFMT;
    if kind == IFSOCK {
        return Err(Error::Unrepresentable(path));
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
        return Ok(Member {
            path,
            inode,
            xattrs: Vec::new(),
            hardlink,
            symlink: None,
            device: None,
            data: Vec::new(),
        });
    }

    let symlink = if kind == IFLNK {
        Some(reader.read_symlink(&inode).map_err(from_read)?)
    } else {
        None
    };
    let device = if kind == IFCHR || kind == IFBLK {
        Some(reader.device(&inode))
    } else {
        None
    };
    // read_data materializes the file's whole logical size, so extracting a foreign
    // image trusts its `i_size`: a file claiming a very large sparse size allocates in
    // proportion to that claim. inspect's scan reports on such an image without reading
    // its files.
    let data = if kind == IFREG {
        reader.read_data(&inode).map_err(from_read)?
    } else {
        Vec::new()
    };
    let xattrs = reader.xattrs(&inode).map_err(from_read)?;

    Ok(Member {
        path,
        inode,
        xattrs,
        hardlink: None,
        symlink,
        device,
        data,
    })
}

/// Writing the archive failed.
fn archive_write(source: io::Error) -> Error {
    Error::Io {
        what: "the archive".to_string(),
        source,
    }
}

/// Append one member: its PAX records, then its header and contents.
///
/// The records go first because that is where they apply — an `x` header describes the
/// entry that follows it.
fn append(builder: &mut Builder<impl Write>, m: &Member) -> Result<(), Error> {
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
            _ => return Err(Error::Unrepresentable(m.path.clone())),
        }
    };
    let target = m.hardlink.as_ref().or(m.symlink.as_ref());

    // Every field the header cannot hold exactly goes into a PAX record, and the ones it
    // can go into both: the record is authoritative, and every reader that honours it —
    // GNU tar, bsdtar, and this tool's own archive source among them — reads the exact
    // value whatever the header says.
    let mut records: Vec<(String, Vec<u8>)> = vec![
        ("path".to_string(), name.clone()),
        ("atime".to_string(), render::pax_time(m.inode.atime).into()),
        ("ctime".to_string(), render::pax_time(m.inode.ctime).into()),
        ("mtime".to_string(), render::pax_time(m.inode.mtime).into()),
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
    builder
        .append_pax_extensions(borrowed)
        .map_err(archive_write)?;

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
        header.set_device_major(major).map_err(archive_write)?;
        header.set_device_minor(minor).map_err(archive_write)?;
    }
    // A path or a target that is text and short enough goes into the header as well, where
    // a reader that ignores PAX records finds it. One that is neither — not text, or too
    // long for the field — is left out rather than truncated into a name that is not the
    // file's, or transliterated into a differently-named file. The PAX record above holds
    // it exactly either way, so an empty field here is honestly absent, never subtly
    // wrong.
    if let Ok(text) = std::str::from_utf8(&name) {
        let _ = header.set_path(text);
    }
    if let Some(target) = target
        && let Ok(text) = std::str::from_utf8(target)
    {
        let _ = header.set_link_name(text);
    }

    header.set_size(m.data.len() as u64);
    header.set_cksum();
    builder
        .append(&header, m.data.as_slice())
        .map_err(archive_write)
}

/// The PAX keyword for an extended attribute, `SCHILY.xattr.<name>`.
///
/// A PAX record's keyword is text and cannot hold an `=` (its key/value delimiter) or a
/// newline (its record terminator), so a name carrying either — or one that is not valid
/// UTF-8 — has no faithful spelling. It is refused rather than flattened through U+FFFD or
/// split at a delimiter into a differently-named attribute, which would corrupt the round
/// trip silently. Standard attribute names are ASCII without these bytes.
fn pax_xattr_key(path: &[u8], name: &[u8]) -> Result<String, Error> {
    match std::str::from_utf8(name) {
        Ok(text) if !text.contains('=') && !text.contains('\n') => {
            Ok(format!("SCHILY.xattr.{text}"))
        }
        _ => Err(Error::XattrNameUnrepresentable {
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
fn xattr_value(path: &[u8], xattr: &Xattr) -> Result<Vec<u8>, Error> {
    if xattr.name == Acl::ACCESS_NAME || xattr.name == Acl::DEFAULT_NAME {
        let acl = Acl::decode(&xattr.value).map_err(|source| Error::BadAcl {
            path: path.to_vec(),
            source,
        })?;
        return Ok(acl.encode_xattr_v2());
    }
    Ok(xattr.value.clone())
}

/// Write one file's bytes to the standard output, and nothing else.
fn cat(reader: &mut Reader<File>, path: &[u8]) -> Result<(), Error> {
    let (_, inode) = reader.lookup(path).map_err(from_read)?;
    if inode.mode & IFMT != IFREG {
        return Err(Error::NotAFile(path.to_vec()));
    }
    let data = reader.read_data(&inode).map_err(from_read)?;
    emit(&data)
}

/// List the tree: every name the filesystem holds, `/lost+found` included, because a
/// listing describes the filesystem rather than the archive one could make of it.
fn list(reader: &mut Reader<File>, as_json: bool) -> Result<(), Error> {
    let entries = reader.walk().map_err(from_read)?;
    // A symbolic link's target is part of what its name means, so a listing that leaves it
    // out says less than it knows.
    let mut targets: HashMap<usize, Vec<u8>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.inode.mode & IFMT == IFLNK {
            targets.insert(i, reader.read_symlink(&e.inode).map_err(from_read)?);
        }
    }

    let text = if as_json {
        list_json(&entries, &targets)
    } else {
        list_table(&entries, &targets)
    };
    emit(text.as_bytes())
}

/// The listing a person reads: one line per name, in the columns `ls -l` puts them in.
fn list_table(entries: &[WalkEntry], targets: &HashMap<usize, Vec<u8>>) -> String {
    let mut s = String::new();
    for (i, e) in entries.iter().enumerate() {
        s.push_str(&format!(
            "{} {:>3} {:>6} {:>6} {:>10} {} {}",
            render::mode(e.inode.mode),
            e.inode.links_count,
            e.inode.uid,
            e.inode.gid,
            e.inode.size,
            render::iso8601(e.inode.mtime.secs),
            render::printable(&e.path),
        ));
        if let Some(target) = targets.get(&i) {
            s.push_str(" -> ");
            s.push_str(&render::printable(target));
        }
        s.push('\n');
    }
    s
}

/// The listing a machine reads.
fn list_json(entries: &[WalkEntry], targets: &HashMap<usize, Vec<u8>>) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("version", 1);
    let mut a = o.arr("entries");
    for (i, e) in entries.iter().enumerate() {
        let mut j = a.obj();
        j.bytes("path", &e.path);
        j.u64("inode", u64::from(e.number));
        j.str("type", kind_name(e.inode.mode));
        j.u64("mode", u64::from(e.inode.mode & 0o7777));
        j.u64("uid", u64::from(e.inode.uid));
        j.u64("gid", u64::from(e.inode.gid));
        j.u64("links", u64::from(e.inode.links_count));
        j.u64("size", e.inode.size);
        time(&mut j, "atime", e.inode.atime);
        time(&mut j, "ctime", e.inode.ctime);
        time(&mut j, "mtime", e.inode.mtime);
        if let Some(target) = targets.get(&i) {
            j.bytes("target", target);
        }
        j.end();
    }
    a.end();
    o.end();
    out.push('\n');
    out
}

/// A timestamp as two integers: the whole seconds, which reach back past the epoch and so
/// are signed, and the nanoseconds within the second, which do not.
fn time(o: &mut Obj<'_>, key: &str, t: Timestamp) {
    o.i64(key, t.secs);
    o.u64(&format!("{key}_nanos"), u64::from(t.nanos));
}

/// What an inode is, by name.
fn kind_name(mode: u16) -> &'static str {
    match mode & IFMT {
        IFDIR => "directory",
        IFREG => "file",
        IFLNK => "symlink",
        IFCHR => "char_device",
        IFBLK => "block_device",
        IFIFO => "fifo",
        IFSOCK => "socket",
        _ => "unknown",
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
                    Err(Error::XattrNameUnrepresentable { .. })
                ),
                "name {bad:?} must be refused"
            );
        }
    }
}
