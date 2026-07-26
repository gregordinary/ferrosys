//! `ferrosys format`: write a filesystem into a file.
//!
//! The bytes stream out through the library's `FormatPlan`, which writes only the blocks
//! the filesystem uses, so a file destination stays sparse and an image far larger than
//! memory can be written. A `--from-tar` archive named by path is opened and left on
//! disk, each member read only as its file is placed, so the memory a run needs is the
//! largest single member rather than the whole archive; a `--from-dir` tree is walked for
//! its metadata alone and each file read as it is placed, which is the same bound. An
//! archive arriving on the standard input has nothing to seek back to and is read whole.
//!
//! # The destination is touched last
//!
//! A format writes only the blocks the filesystem uses, so every byte of the destination
//! it does not write must already read as zero — which means creating the file, or
//! truncating one that exists, is part of formatting rather than something done to it
//! afterwards. So the order matters: the archive is parsed, the geometry planned, and the
//! inode model built and checked against it *before* the destination is opened. A run that
//! cannot succeed leaves the file that was there exactly as it was.
//!
//! `--atomic` goes further, for the case where a failure part-way through the writing must
//! not be visible either: the image is written to a sibling temporary file, flushed to
//! disk, and renamed over the destination once it is complete.
//!
//! # `--from-dir` is Linux's
//!
//! Walking a host tree records Linux inode metadata and Linux extended attributes, so the
//! library builds its directory source on Linux alone. Everything else here — an empty
//! filesystem, `--from-tar`, and every geometry option — is the same on every platform, so
//! this module carries the boundary rather than the whole tool: [`from_dir`] is the walk on
//! Linux and a typed refusal elsewhere.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::ext::DirectorySource;
use ferrosys::ext::{
    ArchiveSource, FormatOptions, FormatPlan, Layout, Profile, Reader, Source, TreeBuilder,
};

use crate::args::{Contents, FormatArgs, Stream};
use crate::json::Obj;
use crate::{Error, emit, render};

/// Write the filesystem the arguments describe.
pub fn run(args: FormatArgs) -> Result<(), Error> {
    let options = options(&args);

    // Everything a format can fail at that is not the destination's own I/O happens here:
    // the archive is read and parsed, the geometry is planned, and the inode model is built
    // and checked against it. The destination is not opened until this has succeeded, so a
    // failing run cannot destroy the image already at that path.
    //
    // The source is consumed by value and each kind is a distinct type, so the plan is
    // built once per kind rather than behind a trait object the library would have to
    // accept.
    let plan = match &args.contents {
        None => FormatPlan::new(TreeBuilder::new(), args.size, options)?,
        Some(Contents::Tar(Stream::Std)) => {
            let stdin = std::io::stdin();
            plan(ArchiveSource::from_reader(stdin.lock())?, &args, options)?
        }
        // An archive named by path is opened by the library, which keeps every file's
        // bytes on disk until the file is placed: peak memory is the largest single
        // member rather than the whole archive. A stream on the standard input has no
        // such option — there is nothing to seek back to — so it is read whole.
        Some(Contents::Tar(Stream::File(path))) => {
            plan(ArchiveSource::from_path(path)?, &args, options)?
        }
        // A walked tree names each file rather than reading it, so peak memory here is the
        // largest single file too.
        Some(Contents::Dir(path)) => from_dir(path, &args, options)?,
    };

    // A dry run reports the geometry the plan realizes and stops. The layout is the same
    // value the write would use, so what it reports is exact rather than an estimate — and
    // the destination is never opened at all.
    if args.dry_run {
        return report(&args, plan.layout(), None);
    }

    let mut dest = Destination::open(&args.out, args.atomic)?;
    let layout = plan.write_to(dest.file())?;
    // The filesystem's own account of what it has left, read back from what was just
    // written rather than estimated from the plan: the free counts depend on what the
    // source occupies, and reading them back proves the image opens.
    let usage = Usage::of(dest.written())?;
    dest.commit()?;
    report(&args, &layout, Some(usage))
}

/// Plan a format from one source kind.
fn plan(
    source: impl Source,
    args: &FormatArgs,
    options: FormatOptions,
) -> Result<FormatPlan, Error> {
    Ok(FormatPlan::new(source, args.size, options)?)
}

/// Plan a format from a walked directory tree.
///
/// The ownership override is applied to the walk, since it is what records the host's ids
/// in the first place.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn from_dir(path: &Path, args: &FormatArgs, options: FormatOptions) -> Result<FormatPlan, Error> {
    let mut source = DirectorySource::from_path(path)?;
    if let Some((uid, gid)) = args.owner {
        source = source.owner(uid, gid);
    }
    plan(source, args, options)
}

/// The same, on a platform the library builds no directory source for: a named failure
/// rather than a walk.
///
/// The refusal is the whole of what `--from-dir` does here, and it happens before the
/// destination is opened, like every other planning failure.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn from_dir(
    _path: &Path,
    _args: &FormatArgs,
    _options: FormatOptions,
) -> Result<FormatPlan, Error> {
    Err(Error::NoDirectorySource)
}

/// Report the geometry: the receipt a machine reads on the standard output, or the summary
/// a person reads on the standard error.
///
/// The image itself is the artifact of a format, and it is already on disk. A JSON receipt
/// is an artifact the caller asked for, so it goes to the standard output; the human
/// summary is a diagnostic, so it goes to the standard error.
fn report(args: &FormatArgs, layout: &Layout, usage: Option<Usage>) -> Result<(), Error> {
    if args.json {
        emit(receipt(args, layout, usage).as_bytes())
    } else {
        eprint!("{}", summary(args, layout, usage));
        Ok(())
    }
}

/// What a filesystem has left once it is written: its own free counts, as its superblock
/// records them.
///
/// A format's cost is otherwise invisible — the reserved descriptor blocks, the journal,
/// and the inode tables are all paid before a caller's first file — so these are what say
/// what the geometry left to use.
#[derive(Clone, Copy)]
struct Usage {
    /// Free blocks (`s_free_blocks_count`).
    free_blocks: u64,
    /// Free inodes (`s_free_inodes_count`).
    free_inodes: u32,
}

impl Usage {
    /// Read the counts back from the image at `path`.
    fn of(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|e| Error::io(path, e))?;
        let reader = Reader::open(file).map_err(|source| Error::NotExt {
            path: path.display().to_string(),
            source,
        })?;
        let sb = reader.superblock();
        Ok(Self {
            free_blocks: sb.free_blocks_count,
            free_inodes: sb.free_inodes_count,
        })
    }
}

/// The library options one set of arguments names.
fn options(args: &FormatArgs) -> FormatOptions {
    let mut o = FormatOptions::new(args.uuid, args.time, args.hash_seed);
    o.feature = args.feature;
    o.errors = args.errors;
    o.inodes = args.inodes;
    o.reserved = args.reserved;
    o.volume_name = args.volume_name;
    o.grow = args.grow;
    o.journal = args.journal;
    o.fixed_time = args.fixed_time;
    o.hash_version = args.hash_version;
    o.hash_signedness = args.hash_signedness;
    o
}

/// Where a format's bytes go, and what makes them the destination's.
///
/// Written in place, this is the destination itself. Under `--atomic` it is a sibling
/// temporary file that becomes the destination at [`commit`](Self::commit): the rename is
/// atomic, so a reader of the path sees either the image that was there before or the
/// complete new one, and a run that dies part-way through leaves the old one untouched.
struct Destination {
    /// The path a caller asked for.
    out: PathBuf,
    /// The file being written: `out` itself, or the temporary sibling.
    written: PathBuf,
    file: File,
    /// Whether `written` still has to be renamed over `out`.
    atomic: bool,
}

impl Destination {
    /// Open the destination for `out`, refusing anything but a regular file.
    ///
    /// A format writes only the blocks the filesystem uses and extends the file to its full
    /// size with a single byte at the end, so every byte it does not write must already read
    /// as zero. Creating the file, or truncating one that exists, is what makes that true. A
    /// block device cannot be made true that way: formatting one would leave whatever it
    /// held interleaved with the new filesystem, and the result would pass no checker.
    ///
    /// The kind is checked before the file is opened, so a device is never opened for
    /// writing at all, and again after, from the handle itself, so a path that changed
    /// underneath the first check cannot slip past.
    fn open(out: &Path, atomic: bool) -> Result<Self, Error> {
        let not_regular = || Error::NotARegularFile(out.display().to_string());
        match std::fs::metadata(out) {
            Ok(meta) if !meta.file_type().is_file() => return Err(not_regular()),
            // A path that does not exist yet is about to be a regular file.
            Ok(_) | Err(_) => {}
        }
        // The temporary file is a sibling, because a rename cannot cross filesystems: one
        // in a scratch directory could not become this destination. The process id keeps
        // two runs writing the same destination from writing the same temporary file; it
        // reaches no image byte, so it costs the output's reproducibility nothing.
        let written = if atomic {
            let name = out.file_name().unwrap_or_default();
            let mut temp = name.to_os_string();
            temp.push(format!(".ferrosys-{}.tmp", std::process::id()));
            out.with_file_name(temp)
        } else {
            out.to_path_buf()
        };
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&written)
            .map_err(|e| Error::io(&written, e))?;
        let meta = file.metadata().map_err(|e| Error::io(&written, e))?;
        if !meta.file_type().is_file() {
            return Err(not_regular());
        }
        Ok(Self {
            out: out.to_path_buf(),
            written,
            file,
            atomic,
        })
    }

    /// The handle the image is written through.
    fn file(&mut self) -> &mut File {
        &mut self.file
    }

    /// The file the bytes were written to, for reading them back.
    fn written(&self) -> &Path {
        &self.written
    }

    /// Make the written bytes the destination's.
    ///
    /// Written in place there is nothing to do. Under `--atomic` the file's bytes are
    /// flushed to disk before the rename and the directory entry after it, since a rename
    /// that reached the disk before the bytes it names would leave the destination holding
    /// an image that was never finished — which is the one outcome the option exists to
    /// prevent.
    fn commit(self) -> Result<(), Error> {
        if !self.atomic {
            return Ok(());
        }
        self.file
            .sync_all()
            .map_err(|e| Error::io(&self.written, e))?;
        std::fs::rename(&self.written, &self.out).map_err(|e| Error::io(&self.out, e))?;
        // The directory entry the rename created. A parent that cannot be opened is not a
        // failure of the format — the image is written and in place — so the durability of
        // the entry is best-effort where the bytes' is not.
        if let Some(parent) = self.out.parent().filter(|p| !p.as_os_str().is_empty())
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Drop for Destination {
    /// Remove the temporary file if it never became the destination, so a failed
    /// `--atomic` run leaves nothing behind. A successful `commit` renamed it away, and the
    /// remove then finds nothing to do.
    fn drop(&mut self) {
        if self.atomic {
            let _ = std::fs::remove_file(&self.written);
        }
    }
}

/// The summary a person reads: what was written, and the geometry it took.
fn summary(args: &FormatArgs, layout: &Layout, usage: Option<Usage>) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        s.push_str(&format!("{k:<24}{v}\n"));
    };
    if let Some(label) = render::label(&args.volume_name) {
        line("Filesystem volume name:", label);
    }
    line("Filesystem UUID:", render::uuid(&args.uuid));
    line(
        "Filesystem profile:",
        Profile::of(args.feature).name().to_string(),
    );
    line("Filesystem features:", args.feature.names().join(" "));
    line("Block size:", layout.block_size.to_string());
    line("Inode size:", args.feature.inode_size.to_string());
    line("Block count:", layout.total_blocks.to_string());
    line("Inode count:", layout.total_inodes.to_string());
    // What the geometry left to use, beside what it holds back. A format's overhead is
    // otherwise invisible: the reserved descriptor blocks alone can be a quarter of a small
    // filesystem, and nothing else in this summary would say so.
    if let Some(u) = usage {
        line("Free blocks:", u.free_blocks.to_string());
        line("Free inodes:", u.free_inodes.to_string());
    }
    line("Reserved blocks:", layout.reserved_blocks.to_string());
    line("Blocks per group:", layout.blocks_per_group.to_string());
    line("Inodes per group:", layout.inodes_per_group.to_string());
    line("Block groups:", layout.group_count.to_string());
    line(
        "Reserved GDT blocks:",
        layout.reserved_gdt_blocks.to_string(),
    );
    line(
        "Grows online to:",
        format!("{} blocks", layout.max_grow_blocks),
    );
    line("Filesystem created:", render::iso8601(args.time.secs));
    s
}

/// The receipt a machine reads: the same geometry, as JSON.
fn receipt(args: &FormatArgs, layout: &Layout, usage: Option<Usage>) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("schema", crate::json::SCHEMA_VERSION);
    o.str("uuid", &render::uuid(&args.uuid));
    // The label up to its first NUL, byte-exact: a non-UTF-8 label carries a `_hex` field
    // rather than being flattened through the replacement character.
    let label = &args.volume_name;
    let label_end = label.iter().position(|&b| b == 0).unwrap_or(label.len());
    o.bytes("volume_name", &label[..label_end]);
    o.i64("created", args.time.secs);
    o.str("profile", Profile::of(args.feature).name());
    o.strings("features", &args.feature.names());
    o.u64("block_size", u64::from(layout.block_size));
    o.u64("inode_size", u64::from(args.feature.inode_size));
    o.u64("blocks", layout.total_blocks);
    o.u64("inodes", u64::from(layout.total_inodes));
    // Absent on a dry run, which writes no filesystem to have free counts.
    match usage {
        Some(u) => {
            o.u64("free_blocks", u.free_blocks);
            o.u64("free_inodes", u64::from(u.free_inodes));
        }
        None => {
            o.raw("free_blocks", "null");
            o.raw("free_inodes", "null");
        }
    }
    o.u64("blocks_per_group", u64::from(layout.blocks_per_group));
    o.u64("inodes_per_group", u64::from(layout.inodes_per_group));
    o.u64("groups", u64::from(layout.group_count));
    o.u64("first_data_block", u64::from(layout.first_data_block));
    o.u64("gdt_blocks", u64::from(layout.gdt_blocks));
    o.u64("reserved_gdt_blocks", u64::from(layout.reserved_gdt_blocks));
    o.u64("flex_bg_size", u64::from(layout.flex_bg_size));
    o.u64("max_grow_blocks", layout.max_grow_blocks);
    o.u64("reserved_blocks", layout.reserved_blocks);
    o.bool("written", usage.is_some());
    o.end();
    out.push('\n');
    out
}
