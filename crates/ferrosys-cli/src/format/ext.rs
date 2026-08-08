//! Writing an ext2, ext3, or ext4 filesystem, and reporting the geometry it took.

use std::fs::File;
use std::path::Path;

use ferrosys::ArchiveSource;
#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::DirectorySource;
use ferrosys::ext::{FormatOptions, FormatPlan, Layout, Profile, Reader, Source, TreeBuilder};

use crate::args::{Contents, ExtTarget, FormatArgs, Size, Stream};
use crate::{Error, emit, render};

/// Write the ext filesystem the arguments describe.
pub fn run(args: &FormatArgs, target: &ExtTarget) -> Result<(), Error> {
    let options = options(args, target);

    // Everything a format can fail at that is not the destination's own I/O happens here:
    // the archive is read and parsed, the geometry is planned, and the inode model is built
    // and checked against it. The destination is not opened until this has succeeded, so a
    // failing run cannot destroy the image already at that path.
    //
    // The source is consumed by value and each kind is a distinct type, so the plan is
    // built once per kind rather than behind a trait object the library would have to
    // accept.
    let plan = match &args.contents {
        None => plan(TreeBuilder::new(), args, options)?,
        Some(Contents::Tar(Stream::Std)) => plan(
            ArchiveSource::from_reader(crate::format::bounded_stdin())?,
            args,
            options,
        )?,
        // An archive named by path is opened by the library, which keeps every file's
        // bytes on disk until the file is placed: peak memory is the largest single
        // member rather than the whole archive. A stream on the standard input has no
        // such option — there is nothing to seek back to — so it is read whole.
        Some(Contents::Tar(Stream::File(path))) => {
            plan(ArchiveSource::from_path(path)?, args, options)?
        }
        // A walked tree names each file rather than reading it, so peak memory here is the
        // largest single file too.
        Some(Contents::Dir(path)) => from_dir(path, args, options)?,
    };

    // A dry run reports the geometry the plan realizes and stops. The layout is the same
    // value the write would use, so what it reports is exact rather than an estimate — and
    // the destination is never opened at all.
    if args.dry_run {
        return report(args, target, plan.layout(), None);
    }

    let mut dest = crate::format::open_destination(&args.out, args.atomic)?;
    let layout = plan.write_to(dest.file())?;
    // The filesystem's own account of what it has left, read back from what was just
    // written rather than estimated from the plan: the free counts depend on what the
    // source occupies, and reading them back proves the image opens.
    let usage = Usage::of(dest.written())?;
    dest.commit()?;
    report(args, target, &layout, Some(usage))
}

/// Plan a format from one source kind.
///
/// A named size is planned directly. `--size auto` is a search instead: candidate sizes are
/// planned and the source placed into each until the smallest one that holds it with the
/// requested room to spare is found. Either way what comes back is a plan over the same
/// model, so the search costs no second reading of the source and nothing downstream knows
/// which way the size was arrived at.
fn plan(
    source: impl Source,
    args: &FormatArgs,
    options: FormatOptions,
) -> Result<FormatPlan, Error> {
    Ok(match args.size {
        Size::Bytes(bytes) => FormatPlan::new(source, bytes, options)?,
        Size::Fit(slack) => FormatPlan::fit(source, options, slack)?,
    })
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
fn report(
    args: &FormatArgs,
    target: &ExtTarget,
    layout: &Layout,
    usage: Option<Usage>,
) -> Result<(), Error> {
    if args.json {
        emit(receipt(args, target, layout, usage).as_bytes())
    } else {
        eprint!("{}", summary(args, target, layout, usage));
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
pub struct Usage {
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
fn options(args: &FormatArgs, target: &ExtTarget) -> FormatOptions {
    let mut o = FormatOptions::new(target.uuid, args.time, target.hash_seed);
    o.feature = target.feature;
    o.errors = target.errors;
    o.inodes = target.inodes;
    o.reserved = target.reserved;
    o.volume_name = target.volume_name;
    o.grow = target.grow;
    o.journal = target.journal;
    o.fixed_time = target.fixed_time;
    o.hash_version = target.hash_version;
    o.hash_signedness = target.hash_signedness;
    o
}

/// The summary a person reads: what was written, and the geometry it took.
fn summary(args: &FormatArgs, target: &ExtTarget, layout: &Layout, usage: Option<Usage>) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        s.push_str(&format!("{k:<24}{v}\n"));
    };
    if let Some(label) = render::label(&target.volume_name) {
        line("Filesystem volume name:", label);
    }
    line("Filesystem UUID:", render::uuid(&target.uuid));
    line(
        "Filesystem profile:",
        Profile::of(target.feature).name().to_string(),
    );
    line("Filesystem features:", target.feature.names().join(" "));
    line("Block size:", layout.block_size.to_string());
    line("Inode size:", target.feature.inode_size.to_string());
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
fn receipt(args: &FormatArgs, target: &ExtTarget, layout: &Layout, usage: Option<Usage>) -> String {
    crate::json::document(|o| {
        // The head every family's receipt carries, so a caller reads which filesystem was
        // written from the same two fields whichever one it asked for.
        o.str("family", "ext");
        o.str("variant", Profile::of(target.feature).name());
        o.str("uuid", &render::uuid(&target.uuid));
        // The label up to its first NUL, byte-exact: a non-UTF-8 label carries a `_hex`
        // field rather than being flattened through the replacement character.
        let label = &target.volume_name;
        let label_end = label.iter().position(|&b| b == 0).unwrap_or(label.len());
        o.bytes("volume_name", &label[..label_end]);
        o.i64("created", args.time.secs);
        o.strings("features", &target.feature.names());
        o.u64("block_size", u64::from(layout.block_size));
        o.u64("inode_size", u64::from(target.feature.inode_size));
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
    })
}
