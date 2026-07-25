//! `ferrosys format`: write a filesystem into a file.
//!
//! The bytes stream out through the library's `format_to`, which writes only the blocks
//! the filesystem uses, so a file destination stays sparse and an image far larger than
//! memory can be written. A `--from-tar` archive named by path is opened and left on
//! disk, each member read only as its file is placed, so the memory a run needs is the
//! largest single member rather than the whole archive. An archive arriving on the
//! standard input has nothing to seek back to and is read whole.

use std::fs::{File, OpenOptions};
use std::path::Path;

use ferrosys::ext::{
    ArchiveSource, FormatOptions, Layout, Profile, Source, TreeBuilder, format_to,
};

use crate::args::{FormatArgs, Stream};
use crate::json::Obj;
use crate::{Error, emit, render};

/// Write the filesystem the arguments describe.
pub fn run(args: FormatArgs) -> Result<(), Error> {
    let out = create(&args.out)?;
    let options = options(&args);

    // The source is consumed by value and each kind is a distinct type, so the call is
    // made once per kind rather than behind a trait object the library would have to
    // accept.
    let layout = match &args.from_tar {
        None => write(TreeBuilder::new(), &args, options, &out)?,
        Some(Stream::Std) => {
            let stdin = std::io::stdin();
            let source = ArchiveSource::from_reader(stdin.lock())?;
            write(source, &args, options, &out)?
        }
        // An archive named by path is opened by the library, which keeps every file's
        // bytes on disk until the file is placed: peak memory is the largest single
        // member rather than the whole archive. A stream on the standard input has no
        // such option — there is nothing to seek back to — so it is read whole.
        Some(Stream::File(path)) => {
            let source = ArchiveSource::from_path(path)?;
            write(source, &args, options, &out)?
        }
    };

    // The image itself is the artifact of a format, and it is already on disk. A JSON
    // receipt is an artifact the caller asked for, so it goes to the standard output; the
    // human summary is a diagnostic, so it goes to the standard error.
    if args.json {
        emit(receipt(&args, &layout).as_bytes())
    } else {
        eprint!("{}", summary(&args, &layout));
        Ok(())
    }
}

/// Stream the filesystem out and hand back the geometry it realized.
fn write(
    source: impl Source,
    args: &FormatArgs,
    options: FormatOptions,
    out: &File,
) -> Result<Layout, Error> {
    Ok(format_to(source, args.size, options, out)?)
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

/// Open the destination, refusing anything but a regular file.
///
/// A format writes only the blocks the filesystem uses and extends the file to its full
/// size with a single byte at the end, so every byte it does not write must already read
/// as zero. Creating the file, or truncating one that exists, is what makes that true. A
/// block device cannot be made true that way: formatting one would leave whatever it held
/// interleaved with the new filesystem, and the result would pass no checker.
///
/// The kind is checked before the file is opened, so a device is never opened for writing
/// at all, and again after, from the handle itself, so a path that changed underneath the
/// first check cannot slip past.
fn create(path: &Path) -> Result<File, Error> {
    let not_regular = || Error::NotARegularFile(path.display().to_string());
    match std::fs::metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => return Err(not_regular()),
        // A path that does not exist yet is about to be a regular file.
        Ok(_) | Err(_) => {}
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let meta = file.metadata().map_err(|e| Error::io(path, e))?;
    if !meta.file_type().is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// The summary a person reads: what was written, and the geometry it took.
fn summary(args: &FormatArgs, layout: &Layout) -> String {
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
fn receipt(args: &FormatArgs, layout: &Layout) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("version", 1);
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
    o.u64("blocks_per_group", u64::from(layout.blocks_per_group));
    o.u64("inodes_per_group", u64::from(layout.inodes_per_group));
    o.u64("groups", u64::from(layout.group_count));
    o.u64("first_data_block", u64::from(layout.first_data_block));
    o.u64("gdt_blocks", u64::from(layout.gdt_blocks));
    o.u64("reserved_gdt_blocks", u64::from(layout.reserved_gdt_blocks));
    o.u64("flex_bg_size", u64::from(layout.flex_bg_size));
    o.u64("max_grow_blocks", layout.max_grow_blocks);
    o.u64("reserved_blocks", layout.reserved_blocks);
    o.end();
    out.push('\n');
    out
}
