//! `ferrosys extract`: read a filesystem's contents back out — as a tar archive, as a
//! directory tree, as one file's bytes, as a listing, or as one path's full metadata.
//!
//! The archive is written by the library's `ArchiveSink` and the tree by its `DirectorySink`,
//! so what each carries — the `./` root member, the omitted `/lost+found`, the PAX times,
//! attributes, and ACLs — is the library's contract rather than this tool's. Feeding what
//! comes out to `ferrosys format --from-tar` or `--from-dir` reproduces the filesystem it
//! came from.
//!
//! A walk can fail part-way — at a socket the archive format cannot carry, an inode that
//! does not read, an ACL that does not decode — and a named destination is created and
//! truncated before the walk starts. `--to-tar FILE --atomic` is for the case where that
//! must not be visible: the archive is written to a sibling temporary file and renamed
//! over the destination once the walk is complete, exactly as `format --atomic` does.
//! `--to-dir` has no such option, because there is no rename that publishes a whole tree at
//! once; what it offers instead is a destination that must start empty, so a failure leaves a
//! partial tree in a directory that held nothing rather than mixed into one that did.
//!
//! # `--to-dir` is Linux's
//!
//! Writing a tree back out sets Linux inode metadata and Linux extended attributes, so the
//! library builds its directory sink on Linux alone. Everything else here — `--to-tar`,
//! `--cat`, `--list`, `--stat` — is the same on every platform, so this module carries the
//! boundary rather than the whole tool: [`to_dir`] is the write on Linux and a typed refusal
//! elsewhere.
//!
//! # Memory
//!
//! Nothing here holds a whole file. `--cat` streams one file's bytes to the standard output
//! and `--to-tar` streams each member's bytes into the archive, so pulling a multi-gigabyte
//! file out of an image costs a working set rather than the file's size. `--list` holds one
//! entry per name, and `--max-file-bytes` is the bound to set on an image whose declared
//! sizes have not earned trust.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::ext::DirectorySink;
use ferrosys::ext::ondisk::{Inode, Timestamp};
use ferrosys::ext::{Acl, ArchiveSink, Limits, OpenOptions, ReadPolicy, Reader, WalkEntry, Xattr};

use crate::args::{ExtractArgs, ExtractMode, Stream};
use crate::dest::Destination;
use crate::json::Obj;
use crate::{Error, emit, from_read, render};

/// The file-type bits of a mode, and the types they name.
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
    let mut limits = Limits::new();
    if let Some(max) = args.max_file_bytes {
        limits = limits.max_file_bytes(max);
    }
    let mut reader = Reader::open_with(
        file,
        &OpenOptions::new()
            .base(args.offset)
            .policy(ReadPolicy::Lenient)
            .limits(limits),
    )
    .map_err(|source| Error::NotExt {
        path: image,
        source,
    })?;

    match args.mode {
        ExtractMode::Cat(path) => cat(&mut reader, &path),
        ExtractMode::Stat { path, json } => stat(&mut reader, &path, json),
        ExtractMode::List { json } => list(&mut reader, json),
        ExtractMode::ToTar(Stream::Std) => {
            // The archive is the artifact, and it is the only thing on the standard
            // output: no summary, no count, not even on the standard error.
            let stdout = io::stdout();
            let mut out = stdout.lock();
            ArchiveSink::new(&mut out).write_tree(&mut reader)?;
            out.flush().map_err(|source| Error::Io {
                what: "standard output".to_string(),
                source,
            })
        }
        ExtractMode::ToTar(Stream::File(path)) => {
            let mut dest = Destination::open(&path, args.atomic)?;
            let mut out = io::BufWriter::new(dest.file());
            ArchiveSink::new(&mut out).write_tree(&mut reader)?;
            out.flush().map_err(|e| Error::io(&path, e))?;
            drop(out);
            dest.commit()
        }
        ExtractMode::ToDir {
            path,
            skip_privileged,
        } => to_dir(&mut reader, &path, skip_privileged),
    }
}

/// Write the whole tree into a directory on this host.
///
/// The directory is made when it is not already there, so a caller names where the tree goes
/// rather than preparing the place first. It must be empty: an extraction states what the
/// filesystem holds, and a name already present would be an entry that could not be created,
/// found part-way through with the tree half written.
///
/// What was written goes to the standard error, as every summary here does — the artifact of
/// this mode is the tree, and it is already on disk.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn to_dir(reader: &mut Reader<File>, path: &Path, skip_privileged: bool) -> Result<(), Error> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    }
    let mut sink = DirectorySink::new(path)?;
    if skip_privileged {
        sink = sink.skip_privileged();
    }
    let report = sink.write_tree(reader)?;

    eprintln!("{:<24}{}", "Names written:", report.written);
    if report.ownership_dropped {
        eprintln!(
            "{:<24}not applied — this process may not set another owner",
            "Ownership:"
        );
    }
    if report.xattrs_dropped {
        eprintln!(
            "{:<24}not applied — this process may not set security or trusted attributes",
            "Attributes:"
        );
    }
    for skipped in &report.skipped {
        eprintln!("{:<24}{}", "Skipped:", render::printable(skipped));
    }
    Ok(())
}

/// The same, on a platform the library builds no directory sink for: a named failure rather
/// than a tree.
///
/// Writing a tree back out sets Linux inode metadata and Linux extended attributes, so the
/// library builds its directory sink on Linux alone. `--to-tar` writes the same contents as
/// an archive anywhere.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn to_dir(_reader: &mut Reader<File>, _path: &Path, _skip: bool) -> Result<(), Error> {
    Err(Error::NoDirectorySink)
}

/// Write one file's bytes to the standard output, and nothing else.
///
/// The bytes are streamed rather than held, so a file larger than memory is written out
/// without ever existing in it.
fn cat(reader: &mut Reader<File>, path: &[u8]) -> Result<(), Error> {
    let (_, inode) = reader.lookup(path).map_err(from_read)?;
    if inode.mode & IFMT != IFREG {
        return Err(Error::NotAFile(path.to_vec()));
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    reader.read_data_to(&inode, &mut out).map_err(from_read)?;
    out.flush().map_err(|source| Error::Io {
        what: "standard output".to_string(),
        source,
    })
}

/// Report everything the filesystem records about one path.
///
/// This is the per-inode view: the metadata a listing carries, plus the extended attributes
/// and decoded POSIX ACLs that only an archive would otherwise show — which for a rootfs is
/// the headline question, since a file's capability set lives in an attribute. A path naming
/// a symlink describes the link itself rather than its target, because a question about a
/// path is a question about that path.
fn stat(reader: &mut Reader<File>, path: &[u8], as_json: bool) -> Result<(), Error> {
    let (number, inode) = reader.lookup_no_follow(path).map_err(from_read)?;
    let xattrs = reader.xattrs(&inode).map_err(from_read)?;
    let target = if inode.mode & IFMT == IFLNK {
        Some(reader.read_symlink(&inode).map_err(from_read)?)
    } else {
        None
    };
    let device = match inode.mode & IFMT {
        IFCHR | IFBLK => Some(reader.device(&inode)),
        _ => None,
    };

    let text = if as_json {
        stat_json(path, number, &inode, &xattrs, target.as_deref(), device)
    } else {
        stat_table(path, number, &inode, &xattrs, target.as_deref(), device)
    };
    emit(text.as_bytes())
}

/// One path's metadata as a person reads it: one field per line, attributes last.
fn stat_table(
    path: &[u8],
    number: u32,
    inode: &Inode,
    xattrs: &[Xattr],
    target: Option<&[u8]>,
    device: Option<(u32, u32)>,
) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        s.push_str(&format!("{k:<24}{v}\n"));
    };
    line("Path:", render::printable(path));
    line("Inode:", number.to_string());
    line("Type:", kind_name(inode.mode).to_string());
    // The mode twice over: octal, which is how a mode is written and read, and the symbolic
    // form a listing shows.
    line(
        "Mode:",
        format!("{:04o} ({})", inode.mode & 0o7777, render::mode(inode.mode)),
    );
    line("Owner:", format!("{}:{}", inode.uid, inode.gid));
    line("Links:", inode.links_count.to_string());
    line("Size:", inode.size.to_string());
    line("Blocks:", inode.blocks.to_string());
    if let Some((major, minor)) = device {
        line("Device:", format!("{major}:{minor}"));
    }
    if let Some(target) = target {
        line("Symlink target:", render::printable(target));
    }
    for (label, t) in [
        ("Accessed:", inode.atime),
        ("Modified:", inode.mtime),
        ("Changed:", inode.ctime),
        ("Created:", inode.crtime),
    ] {
        line(
            label,
            format!("{} ({} ns)", render::iso8601(t.secs), t.nanos),
        );
    }
    for xattr in xattrs {
        // A POSIX ACL is stored in ext's compact form, which is not what a person means by
        // an ACL: it is decoded to `getfacl`'s entry spelling, comma-joined so the value
        // stays on one line of the table. Every other attribute is bytes, shown the way a
        // name is.
        let rendered = acl_text(xattr).unwrap_or_else(|| render::printable(&xattr.value));
        line(
            &format!("Xattr {}:", render::printable(&xattr.name)),
            rendered,
        );
    }
    s
}

/// One path's metadata as a machine reads it, attributes included.
fn stat_json(
    path: &[u8],
    number: u32,
    inode: &Inode,
    xattrs: &[Xattr],
    target: Option<&[u8]>,
    device: Option<(u32, u32)>,
) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("schema", crate::json::SCHEMA_VERSION);
    let mut e = o.obj("entry");
    entry_fields(&mut e, path, number, inode, target);
    e.u64("blocks", inode.blocks);
    time(&mut e, "crtime", inode.crtime);
    if let Some((major, minor)) = device {
        let mut d = e.obj("device");
        d.u64("major", u64::from(major));
        d.u64("minor", u64::from(minor));
        d.end();
    }
    xattr_fields(&mut e, xattrs);
    e.end();
    o.end();
    out.push('\n');
    out
}

/// List the tree: every name the filesystem holds, `/lost+found` included, because a
/// listing describes the filesystem rather than the archive one could make of it.
fn list(reader: &mut Reader<File>, as_json: bool) -> Result<(), Error> {
    let entries = reader.walk().map_err(from_read)?;
    // A symbolic link's target is part of what its name means, so a listing that leaves it
    // out says less than it knows. The attributes are gathered for the JSON listing only:
    // the table has no column for them, and reading a whole tree's attributes to print none
    // of them would be work for nothing.
    let mut targets: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut xattrs: HashMap<usize, Vec<Xattr>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.inode.mode & IFMT == IFLNK {
            targets.insert(i, reader.read_symlink(&e.inode).map_err(from_read)?);
        }
        if as_json {
            let attrs = reader.xattrs(&e.inode).map_err(from_read)?;
            if !attrs.is_empty() {
                xattrs.insert(i, attrs);
            }
        }
    }

    let text = if as_json {
        list_json(&entries, &targets, &xattrs)
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
fn list_json(
    entries: &[WalkEntry],
    targets: &HashMap<usize, Vec<u8>>,
    xattrs: &HashMap<usize, Vec<Xattr>>,
) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("schema", crate::json::SCHEMA_VERSION);
    let mut a = o.arr("entries");
    for (i, e) in entries.iter().enumerate() {
        let mut j = a.obj();
        entry_fields(
            &mut j,
            &e.path,
            e.number,
            &e.inode,
            targets.get(&i).map(Vec::as_slice),
        );
        if let Some(attrs) = xattrs.get(&i) {
            xattr_fields(&mut j, attrs);
        }
        j.end();
    }
    a.end();
    o.end();
    out.push('\n');
    out
}

/// The fields a listing and a stat agree on, written once so the two documents cannot drift.
fn entry_fields(o: &mut Obj<'_>, path: &[u8], number: u32, inode: &Inode, target: Option<&[u8]>) {
    o.bytes("path", path);
    o.u64("inode", u64::from(number));
    o.str("type", kind_name(inode.mode));
    // The permission bits as a number. JSON has no octal literal, so this is decimal — 509
    // is `0o775` — and `mode_octal` beside it carries the spelling a mode is written in.
    o.u64("mode", u64::from(inode.mode & 0o7777));
    o.str("mode_octal", &format!("{:04o}", inode.mode & 0o7777));
    o.u64("uid", u64::from(inode.uid));
    o.u64("gid", u64::from(inode.gid));
    o.u64("links", u64::from(inode.links_count));
    o.u64("size", inode.size);
    time(o, "atime", inode.atime);
    time(o, "ctime", inode.ctime);
    time(o, "mtime", inode.mtime);
    if let Some(target) = target {
        o.bytes("target", target);
    }
}

/// An entry's extended attributes, each as a name, a value, and — for a POSIX ACL — the
/// decoded text form, since the stored bytes are ext's compact encoding rather than anything
/// a consumer would recognize.
fn xattr_fields(o: &mut Obj<'_>, xattrs: &[Xattr]) {
    let mut a = o.arr("xattrs");
    for xattr in xattrs {
        let mut x = a.obj();
        x.bytes("name", &xattr.name);
        x.bytes("value", &xattr.value);
        if let Some(text) = acl_text(xattr) {
            x.str("acl", &text);
        }
        x.end();
    }
    a.end();
}

/// The `getfacl`-style text of an attribute that holds a POSIX ACL, or `None` for any other
/// attribute — and for an ACL attribute whose bytes do not decode, which is reported as the
/// bytes it holds rather than as a failure of the whole listing.
fn acl_text(xattr: &Xattr) -> Option<String> {
    if xattr.name != Acl::ACCESS_NAME && xattr.name != Acl::DEFAULT_NAME {
        return None;
    }
    Acl::decode(&xattr.value).ok().map(|acl| render::acl(&acl))
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
