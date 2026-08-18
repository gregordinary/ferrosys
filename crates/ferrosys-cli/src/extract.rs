//! `ferrosys extract`: read a filesystem's contents back out — as a tar archive, as a
//! directory tree, as one file's bytes, as a listing, or as one path's full metadata.
//!
//! The archive is written by the library's `ArchiveSink` and the tree by its `DirectorySink`,
//! and both are generic over the four operations any family's reader supplies — so what each
//! carries is the library's contract rather than this tool's, and it is the same contract
//! whichever family the image holds. Feeding what comes out to `ferrosys format --from-tar`
//! or `--from-dir` reproduces the filesystem it came from.
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
//! # What a report says when the format records no such thing
//!
//! A listing and a stat describe a name in the vocabulary every family answers: what it is,
//! who owns it, what its mode is, how large it is, and when it was touched. A family with no
//! field for one of those has the value filled in from `--assume-owner` and `--assume-modes`,
//! and every property so filled is named — so a report never states an owner as though the
//! image had recorded one.
//!
//! What is *reported at all* varies with the family, and it varies by omission rather than by
//! invention. A FAT volume has no inode numbers and no second name for a node, so its entries
//! carry no inode and no link count: there is nothing to say, and a zero or a one would be
//! this tool answering a question the format never asked.
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
//! entry per name.
//!
//! What a file's *declared* size costs is a separate question, and the one an image gets to
//! choose. A read of a file writes its declared length, holes reading back as zeros, and
//! nothing structural bounds that length — a sparse file is legitimately larger than the
//! filesystem holding it. So this command caps it whether or not it was asked to: at
//! `--max-file-bytes` where that is given, and at [`SPARSE_HEADROOM`] times the length of the
//! filesystem otherwise. The library defaults to no cap, which is right for a caller that
//! knows what it opened; this tool is most often pointed at an image someone else produced.

mod btrfs;
mod exfat;
mod ext;
mod fat;

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use ferrosys::ArchiveSink;
#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::DirectorySink;
use ferrosys::{
    Attributes, FsReader, FsTree, Limits, NodeKind, OpenOptions, Property, ReadPolicy, Synthesis,
    Timestamp, Xattr,
};

use ferrosys::Acl;

use crate::args::{ExtractArgs, ExtractMode, Stream};
use crate::dest::Destination;
use crate::json::Object;
use crate::{Error, emit, render};

/// One name as this tool reports it, in the vocabulary every family answers.
///
/// The `Option` fields are the whole reason this type exists rather than one family's entry
/// being rendered directly: they are the questions a family may have no answer to, and `None`
/// means the format has no such notion — not that the value is zero.
pub struct Described {
    /// Absolute path from the filesystem root, as the walk reached it.
    pub path: Vec<u8>,
    /// What is at the path, or `None` where the filesystem names a type this vocabulary has
    /// no word for — which a malformed ext inode read leniently can.
    pub kind: Option<NodeKind>,
    /// The length the filesystem records for the node.
    ///
    /// Taken from the family rather than from [`kind`](Self::kind), which carries one only
    /// for a regular file: ext records a length for a directory too, and a report should
    /// show what the image holds rather than what the shared vocabulary happens to carry.
    pub size: u64,
    /// Ownership, mode, times, extended attributes, and what of those was assumed.
    pub attrs: Attributes,
    /// The family's own number for the node, for a family that numbers them.
    pub number: Option<u64>,
    /// How many names reach the node, for a family that counts them.
    pub links: Option<u32>,
    /// A symbolic link's target, for a link.
    pub target: Option<Vec<u8>>,
    /// The blocks the node occupies, for a family that records the count.
    pub blocks: Option<u64>,
    /// The creation time, for a family that records one distinct from the others.
    pub created: Option<Timestamp>,
}

/// How far past the filesystem's own length a file's declared size may reach before the
/// default cap refuses it.
///
/// A file's size is a claim the image makes, and nothing structural bounds it: a sparse
/// file's holes cost no storage, so a well-formed file may be larger than the filesystem
/// holding it and must read back at its full length. That is what an inode claiming sixteen
/// tebibytes and mapping nothing exploits — an extraction writes the declared length, holes
/// reading back as zeros, and fills the destination from an image of a hundred kilobytes.
///
/// So the tool takes the image's own length as the scale and allows a generous multiple of
/// it. A file sixteen times the filesystem that holds it is sparse beyond anything a rootfs
/// carries, and one that large is worth naming: `--max-file-bytes` is how a caller who means
/// it says so.
const SPARSE_HEADROOM: u64 = 16;

/// Read the filesystem the arguments name.
pub fn run(args: ExtractArgs) -> Result<(), Error> {
    let image = args.image.display().to_string();
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;
    // The default is derived rather than absent. The library's own default is no cap, which
    // is right for a caller that knows what it opened; this tool is most often pointed at an
    // image someone else produced, so it starts from what the image could plausibly hold.
    let max_file_bytes = match args.max_file_bytes {
        Some(max) => max,
        None => {
            let len = file
                .metadata()
                .map_err(|e| Error::io(&args.image, e))?
                .len()
                .saturating_sub(args.offset);
            len.saturating_mul(SPARSE_HEADROOM)
        }
    };
    let limits = Limits::new().max_file_bytes(max_file_bytes);
    // Opening goes through the root, so every mode below reaches whichever family the image
    // turns out to hold rather than one this command chose in advance.
    //
    // The strict open is tried first whatever was asked for, and this is the one command
    // where that matters most: extraction writes the image's contents somewhere, so a
    // filesystem carrying a feature this reader does not follow yields output that looks
    // complete and is not. `--strict` makes the refusal the answer. Without it the read
    // falls back to lenient — which is what lets a damaged or unfamiliar image be recovered
    // at all — and the refusal it fell back from is reported rather than dropped, so a run
    // that decided to interpret a deviation says which one.
    let open = |file, policy| {
        ferrosys::open_with(
            file,
            &OpenOptions::new()
                .base(args.offset)
                .policy(policy)
                .limits(limits),
        )
    };
    let reader = match open(file, ReadPolicy::Strict) {
        Ok(reader) => reader,
        Err(source) if args.strict => {
            return Err(Error::NotAFilesystem {
                path: image,
                source,
            });
        }
        Err(refused) => {
            let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;
            let reader =
                open(file, ReadPolicy::Lenient).map_err(|source| Error::NotAFilesystem {
                    path: image.clone(),
                    source,
                })?;
            eprintln!(
                "{}: reading {image} leniently: {refused}",
                crate::args::TOOL
            );
            eprintln!(
                "{}: what it holds is interpreted best-effort; --strict refuses instead",
                crate::args::TOOL
            );
            reader
        }
    };

    let named_the_cap = args.max_file_bytes.is_some();
    let outcome = match reader {
        FsReader::Ext(mut reader) => dispatch(&mut reader, ext::Family, args),
        FsReader::Fat(mut reader) => dispatch(&mut reader, fat::Family, args),
        FsReader::ExFat(mut reader) => dispatch(&mut reader, exfat::Family, args),
        FsReader::Btrfs(mut reader) => dispatch(&mut reader, btrfs::Family, args),
        // A family the library compiled in and this command cannot read back. The binary
        // compiles in every family the library has, so nothing in this workspace reaches it.
        _ => Err(Error::UnsupportedFamily),
    };
    // A bound stopped the read, and the bound in force was this tool's rather than one the
    // invocation named. Saying so is what keeps the default from being a refusal with no way
    // forward: the message the library raises names the cap, and this names where it came
    // from and what raises it.
    if let Err(error) = &outcome
        && !named_the_cap
        && stopped_by_a_limit(error)
    {
        eprintln!(
            "{}: no --max-file-bytes was given, so this run refused any file larger than \
             {max_file_bytes} bytes — {SPARSE_HEADROOM} times the length of the filesystem \
             being read",
            crate::args::TOOL
        );
        eprintln!(
            "{}: a file may legitimately be that sparse — name a larger --max-file-bytes \
             to read one that is",
            crate::args::TOOL
        );
    }
    outcome
}

/// Whether `error` is a read a caller-imposed bound stopped, whichever surface it reached
/// this command through.
///
/// The ways out of an image carry the reader's verdict differently: `--cat` and `--stat`
/// name a path and get one family's own error, while a drained tree goes through the shared
/// extraction surface — as itself for `--list`, wrapped once by an archive, wrapped again by
/// a host tree. What the bound stopped is the same read in all of them.
fn stopped_by_a_limit(error: &Error) -> bool {
    use ferrosys::ext::ReadError as ExtError;

    let through_the_tree = match error {
        // One family's read, reported as itself. FAT's goes through the shared
        // classification on its way here and so lands below.
        Error::Image(
            ExtError::FileTooLarge { .. }
            | ExtError::PathTooLong { .. }
            | ExtError::WalkTooLarge { .. },
        ) => return true,
        Error::Tree(source) => Some(source),
        Error::Archive(ferrosys::ArchiveError::Read(source)) => Some(source),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Error::Host(ferrosys::HostError::Read { source, .. }) => Some(source),
        _ => None,
    };
    matches!(
        through_the_tree,
        Some(ferrosys::TreeError::LimitExceeded { .. })
    )
}

/// What one family answers that the extraction surface does not.
///
/// The four modes that drain a tree are written once against
/// [`FsTree`](ferrosys::FsTree) and need none of this. The three that name a path or list one
/// do: resolving a path and describing a node are questions each family answers out of its
/// own structures, and neither belongs on a trait whose whole point is what a *sink* calls.
/// So they are an inherent method of the same shape on each family and a small implementation
/// of this here, which is the same arrangement the library uses for a question only a
/// concrete reader can answer.
pub trait Describe<R: FsTree> {
    /// Everything reported about one path. A path naming a symbolic link describes the link
    /// itself rather than its target, because a question about a path is a question about
    /// that path.
    fn one(&self, reader: &mut R, path: &[u8], synthesis: &Synthesis) -> Result<Described, Error>;

    /// Everything reported about every name in the tree, in the order a walk reaches them.
    ///
    /// `xattrs` says whether each entry's extended attributes are gathered. Only the JSON
    /// listing shows them, and reading a whole tree's attributes to print none of them is a
    /// read per name for nothing.
    fn all(
        &self,
        reader: &mut R,
        synthesis: &Synthesis,
        xattrs: bool,
    ) -> Result<Vec<Described>, Error>;

    /// Stream one regular file's bytes to `out`.
    fn cat(&self, reader: &mut R, path: &[u8], out: &mut dyn Write) -> Result<(), Error>;
}

/// Carry out the mode the arguments asked for against one family's open reader.
fn dispatch<R, D>(reader: &mut R, family: D, args: ExtractArgs) -> Result<(), Error>
where
    R: FsTree,
    D: Describe<R>,
{
    match args.mode {
        ExtractMode::Cat(path) => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            family.cat(reader, &path, &mut out)?;
            out.flush().map_err(|source| Error::Io {
                what: "standard output".to_string(),
                source,
            })
        }
        ExtractMode::Stat { path, json } => {
            let described = family.one(reader, &path, &args.synthesis)?;
            let text = if json {
                stat_json(&described)
            } else {
                stat_table(&described)
            };
            emit(text.as_bytes())
        }
        ExtractMode::List { json } => {
            let entries = family.all(reader, &args.synthesis, json)?;
            let text = if json {
                list_json(&entries)
            } else {
                list_table(&entries)
            };
            emit(text.as_bytes())
        }
        ExtractMode::ToTar(Stream::Std) => {
            // The archive is the artifact, and it is the only thing on the standard
            // output: no summary, no count, not even on the standard error.
            let stdout = io::stdout();
            let mut out = stdout.lock();
            ArchiveSink::new(&mut out)
                .synthesis(args.synthesis)
                .write_tree(reader)?;
            out.flush().map_err(|source| Error::Io {
                what: "standard output".to_string(),
                source,
            })
        }
        ExtractMode::ToTar(Stream::File(path)) => {
            let mut dest = Destination::open(&path, args.atomic)?;
            let mut out = io::BufWriter::new(dest.file());
            ArchiveSink::new(&mut out)
                .synthesis(args.synthesis)
                .write_tree(reader)?;
            out.flush().map_err(|e| Error::io(&path, e))?;
            drop(out);
            dest.commit()
        }
        ExtractMode::ToDir {
            path,
            skip_privileged,
        } => to_dir(reader, &path, skip_privileged, args.synthesis),
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
fn to_dir<R: FsTree>(
    reader: &mut R,
    path: &Path,
    skip_privileged: bool,
    synthesis: Synthesis,
) -> Result<(), Error> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    }
    let mut sink = DirectorySink::new(path)?.synthesis(synthesis);
    if skip_privileged {
        sink = sink.skip_privileged();
    }
    let report = sink.write_tree(reader)?;

    let mut rows = render::Rows::summary();
    rows.row("Names written:", report.written);
    if report.ownership_dropped {
        rows.row(
            "Ownership:",
            "not applied — this process may not set another owner",
        );
    }
    if report.xattrs_dropped {
        rows.row(
            "Attributes:",
            "not applied — this process may not set security or trusted attributes",
        );
    }
    // What the image never held, as against what this host refused above. An ext filesystem
    // records every property a host file needs, so this says nothing about one; a FAT volume
    // records almost none of them, and this is where it says so.
    for (direction, property, entries) in report.fidelity.summary() {
        rows.row(
            "Assumed:",
            format!(
                "{} ({entries} {})",
                crate::parse::property_name(property),
                if entries == 1 { "entry" } else { "entries" }
            ),
        );
        let _ = direction;
    }
    for skipped in &report.skipped {
        rows.row("Skipped:", render::printable(skipped));
    }
    if report.more_skipped {
        rows.row(
            "Skipped:",
            format!(
                "and more, past the {} this report names",
                ferrosys::ExtractReport::MAX_SKIPPED
            ),
        );
    }
    eprint!("{}", rows.finish());
    Ok(())
}

/// The same, on a platform the library builds no directory sink for: a named failure rather
/// than a tree.
///
/// Writing a tree back out sets Linux inode metadata and Linux extended attributes, so the
/// library builds its directory sink on Linux alone. `--to-tar` writes the same contents as
/// an archive anywhere.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn to_dir<R: FsTree>(
    _reader: &mut R,
    _path: &Path,
    _skip: bool,
    _synthesis: Synthesis,
) -> Result<(), Error> {
    Err(Error::NoDirectorySink)
}

/// One path's metadata as a person reads it: one field per line, attributes last.
fn stat_table(e: &Described) -> String {
    let mut rows = render::Rows::summary();
    let mut line = |k: &str, v: String| rows.row(k, v);
    line("Path:", render::printable(&e.path));
    if let Some(number) = e.number {
        line("Inode:", number.to_string());
    }
    line("Type:", kind_name(e.kind).to_string());
    // The mode twice over: octal, which is how a mode is written and read, and the symbolic
    // form a listing shows.
    line(
        "Mode:",
        format!(
            "{:04o} ({})",
            e.attrs.meta.mode,
            render::mode(e.attrs.meta.mode | file_type_bits(e.kind))
        ),
    );
    line(
        "Owner:",
        format!("{}:{}", e.attrs.meta.uid, e.attrs.meta.gid),
    );
    if let Some(links) = e.links {
        line("Links:", links.to_string());
    }
    line("Size:", e.size.to_string());
    if let Some(blocks) = e.blocks {
        line("Blocks:", blocks.to_string());
    }
    if let Some((major, minor)) = device_of(e.kind) {
        line("Device:", format!("{major}:{minor}"));
    }
    if let Some(target) = &e.target {
        line("Symlink target:", render::printable(target));
    }
    let mut times = vec![
        ("Accessed:", e.attrs.meta.atime),
        ("Modified:", e.attrs.meta.mtime),
        ("Changed:", e.attrs.meta.ctime),
    ];
    if let Some(created) = e.created {
        times.push(("Created:", created));
    }
    for (label, t) in times {
        line(
            label,
            format!("{} ({} ns)", render::iso8601(t.secs), t.nanos),
        );
    }
    for xattr in &e.attrs.xattrs {
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
    // Last, because it qualifies everything above it: whichever of those lines the image did
    // not record and this tool filled in from `--assume-owner` and `--assume-modes`.
    if !e.attrs.synthesized.is_empty() {
        line("Assumed:", property_list(&e.attrs.synthesized));
    }
    rows.finish()
}

/// One path's metadata as a machine reads it, attributes included.
fn stat_json(e: &Described) -> String {
    crate::json::document(|o| {
        let mut j = o.obj("entry");
        entry_fields(&mut j, e);
        if let Some(blocks) = e.blocks {
            j.u64("blocks", blocks);
        }
        if let Some(created) = e.created {
            time(&mut j, "crtime", created);
        }
        if let Some((major, minor)) = device_of(e.kind) {
            let mut d = j.obj("device");
            d.u64("major", u64::from(major));
            d.u64("minor", u64::from(minor));
            d.end();
        }
        xattr_fields(&mut j, &e.attrs.xattrs);
        j.end();
    })
}

/// The listing a person reads: one line per name, in the columns `ls -l` puts them in.
///
/// The link-count column is `-` for a family that does not count them, which keeps the
/// columns in place without printing a count nothing recorded.
fn list_table(entries: &[Described]) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!(
            "{} {:>3} {:>6} {:>6} {:>10} {} {}",
            render::mode(e.attrs.meta.mode | file_type_bits(e.kind)),
            e.links.map_or_else(|| "-".to_string(), |n| n.to_string()),
            e.attrs.meta.uid,
            e.attrs.meta.gid,
            e.size,
            render::iso8601(e.attrs.meta.mtime.secs),
            render::printable(&e.path),
        ));
        if let Some(target) = &e.target {
            s.push_str(" -> ");
            s.push_str(&render::printable(target));
        }
        s.push('\n');
    }
    s
}

/// The listing a machine reads.
fn list_json(entries: &[Described]) -> String {
    crate::json::document(|o| {
        let mut a = o.arr("entries");
        for e in entries {
            let mut j = a.obj();
            entry_fields(&mut j, e);
            if !e.attrs.xattrs.is_empty() {
                xattr_fields(&mut j, &e.attrs.xattrs);
            }
            j.end();
        }
        a.end();
    })
}

/// The fields a listing and a stat agree on, written once so the two documents cannot drift.
///
/// A field a family has no answer for is absent rather than null or zero: a FAT volume has no
/// inode numbers and no link counts, and reporting either would be this tool answering a
/// question the format never asked.
fn entry_fields(o: &mut Object<'_>, e: &Described) {
    o.bytes("path", &e.path);
    if let Some(number) = e.number {
        o.u64("inode", number);
    }
    o.str("type", kind_name(e.kind));
    // The permission bits as a number. JSON has no octal literal, so this is decimal — 509
    // is `0o775` — and `mode_octal` beside it carries the spelling a mode is written in.
    o.u64("mode", u64::from(e.attrs.meta.mode));
    o.str("mode_octal", &format!("{:04o}", e.attrs.meta.mode));
    o.u64("uid", u64::from(e.attrs.meta.uid));
    o.u64("gid", u64::from(e.attrs.meta.gid));
    if let Some(links) = e.links {
        o.u64("links", u64::from(links));
    }
    o.u64("size", e.size);
    time(o, "atime", e.attrs.meta.atime);
    time(o, "ctime", e.attrs.meta.ctime);
    time(o, "mtime", e.attrs.meta.mtime);
    if let Some(target) = &e.target {
        o.bytes("target", target);
    }
    // Always present, empty or not: a consumer must be able to tell "this image recorded
    // every field" from "this document did not say", and an absent array would read as the
    // first when it is neither.
    let names: Vec<&str> = e
        .attrs
        .synthesized
        .iter()
        .map(|p| crate::parse::property_name(*p))
        .collect();
    o.strings("synthesized", &names);
}

/// An entry's extended attributes, each as a name, a value, and — for a POSIX ACL — the
/// decoded text form, since the stored bytes are ext's compact encoding rather than anything
/// a consumer would recognize.
fn xattr_fields(o: &mut Object<'_>, xattrs: &[Xattr]) {
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

/// The properties a read filled in, as one comma-joined phrase for a person to read.
///
/// Named the way `format --accept-loss` names them, which is the tool's one spelling: a
/// property this report shows is one that can be typed back in.
fn property_list(properties: &[Property]) -> String {
    properties
        .iter()
        .map(|p| crate::parse::property_name(*p))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `getfacl`-style text of an attribute that holds a POSIX ACL, or `None` for any other
/// attribute.
///
/// An ACL a read hands back is in the boundary form, and a value that will not parse as one
/// never reaches here: the read itself refuses it, and a scan says which inode holds it.
fn acl_text(xattr: &Xattr) -> Option<String> {
    if xattr.name != Acl::ACCESS_NAME && xattr.name != Acl::DEFAULT_NAME {
        return None;
    }
    Acl::decode(&xattr.value).ok().map(|acl| render::acl(&acl))
}

/// A timestamp as two integers: the whole seconds, which reach back past the epoch and so
/// are signed, and the nanoseconds within the second, which do not.
fn time(o: &mut Object<'_>, key: &str, t: Timestamp) {
    o.i64(key, t.secs);
    o.u64(&format!("{key}_nanos"), u64::from(t.nanos));
}

/// What a node is, by name.
///
/// `unknown` covers both the image naming a type nothing recognizes and a newer library
/// reporting a kind this build has no word for. Neither is a claim about what is there, and
/// neither should be rendered as though it were a file.
fn kind_name(kind: Option<NodeKind>) -> &'static str {
    match kind {
        Some(NodeKind::Directory) => "directory",
        Some(NodeKind::File { .. }) => "file",
        Some(NodeKind::Symlink) => "symlink",
        Some(NodeKind::CharDevice { .. }) => "char_device",
        Some(NodeKind::BlockDevice { .. }) => "block_device",
        Some(NodeKind::Fifo) => "fifo",
        Some(NodeKind::Socket) => "socket",
        _ => "unknown",
    }
}

/// The file-type bits of a mode, which `Metadata` does not carry — it holds permission bits
/// alone — and the symbolic rendering needs.
fn file_type_bits(kind: Option<NodeKind>) -> u16 {
    match kind {
        Some(NodeKind::Directory) => 0o040000,
        Some(NodeKind::File { .. }) => 0o100000,
        Some(NodeKind::Symlink) => 0o120000,
        Some(NodeKind::CharDevice { .. }) => 0o020000,
        Some(NodeKind::BlockDevice { .. }) => 0o060000,
        Some(NodeKind::Fifo) => 0o010000,
        Some(NodeKind::Socket) => 0o140000,
        _ => 0,
    }
}

/// A device node's major and minor numbers, or `None` for anything else.
fn device_of(kind: Option<NodeKind>) -> Option<(u32, u32)> {
    match kind {
        Some(NodeKind::CharDevice { major, minor } | NodeKind::BlockDevice { major, minor }) => {
            Some((major, minor))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrosys::Metadata;

    /// A description carrying just enough to render.
    fn described(kind: NodeKind) -> Described {
        Described {
            path: b"/etc/hostname".to_vec(),
            kind: Some(kind),
            size: match kind {
                NodeKind::File { size } => size,
                _ => 0,
            },
            attrs: Attributes::read(Metadata::new(0o644, Timestamp::from_secs(0)), Vec::new()),
            number: None,
            links: None,
            target: None,
            blocks: None,
            created: None,
        }
    }

    #[test]
    fn a_family_with_no_answer_omits_the_field_rather_than_inventing_one() {
        // The two questions a family may have no answer to. Absent is the report saying
        // nothing; a zero or a one would be it answering.
        let json = list_json(&[described(NodeKind::File { size: 9 })]);
        assert!(!json.contains("\"inode\""), "no inode number was recorded");
        assert!(!json.contains("\"links\""), "no link count was recorded");
        assert!(
            json.contains("\"size\":9"),
            "the length is the family's own"
        );

        // ...and a family that answers them says so in the same fields.
        let mut e = described(NodeKind::File { size: 9 });
        e.number = Some(12);
        e.links = Some(2);
        let json = list_json(&[e]);
        assert!(json.contains("\"inode\":12"));
        assert!(json.contains("\"links\":2"));
    }

    #[test]
    fn what_a_read_invented_is_named_whether_or_not_anything_was() {
        // Always present, so "the image recorded everything" and "this document does not
        // say" are distinguishable. An ext image reports the first.
        let json = list_json(&[described(NodeKind::Directory)]);
        assert!(json.contains("\"synthesized\":[]"));

        let mut e = described(NodeKind::Directory);
        e.attrs.synthesized = vec![Property::Ownership, Property::ChangeTime];
        let json = list_json(&[e]);
        // The spelling is the one `format --accept-loss` reads, so a property a listing
        // names is a property that can be typed straight back into a build.
        assert!(json.contains(r#""synthesized":["ownership","change-time"]"#));
    }

    #[test]
    fn the_symbolic_mode_carries_the_type_the_metadata_does_not() {
        // `Metadata` holds permission bits alone, so the type comes from the kind. Without
        // it every line of a listing would begin with a hyphen.
        let dir = list_table(&[described(NodeKind::Directory)]);
        assert!(dir.starts_with("drw-r--r--"), "got {dir}");
        let file = list_table(&[described(NodeKind::File { size: 9 })]);
        assert!(file.starts_with("-rw-r--r--"), "got {file}");
        // A family with no link count leaves the column in place and prints no number, so
        // the columns after it stay where a reader expects them.
        assert!(dir.starts_with("drw-r--r--   -"), "got {dir}");

        // A family that counts them fills the same column.
        let mut linked = described(NodeKind::File { size: 9 });
        linked.links = Some(2);
        let text = list_table(&[linked]);
        assert!(text.starts_with("-rw-r--r--   2"), "got {text}");
    }

    #[test]
    fn a_report_shows_the_length_the_family_records() {
        // Not the one the shared vocabulary carries, which a regular file alone has: ext
        // records a length for a directory as well, and a listing that zeroed it would be
        // hiding what the image holds.
        let mut e = described(NodeKind::Directory);
        e.size = 4096;
        assert!(list_json(&[e]).contains("\"size\":4096"));
    }
}
