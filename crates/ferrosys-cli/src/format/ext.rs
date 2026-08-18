//! Writing an ext2, ext3, or ext4 filesystem, and reporting the geometry it took.

use std::fs::File;
use std::path::Path;

use ferrosys::ext::ondisk::unpadded;
use ferrosys::ext::{FormatOptions, FormatPlan, Layout, Profile, Reader};
use ferrosys::{Slack, Source};

use crate::args::{ExtTarget, FormatArgs};
use crate::format::Plan;
use crate::{Error, emit, render};

impl Plan for FormatPlan {
    type Options = FormatOptions;

    const FAMILY: &'static str = "ext";

    fn sized(source: impl Source, bytes: u64, options: FormatOptions) -> Result<Self, Error> {
        Ok(FormatPlan::new(source, bytes, options)?)
    }

    fn fitted(source: impl Source, options: FormatOptions, slack: Slack) -> Result<Self, Error> {
        Ok(FormatPlan::fit(source, options, slack)?)
    }
}

/// Write the ext filesystem the arguments describe.
pub fn run(args: &FormatArgs, target: &ExtTarget) -> Result<(), Error> {
    // Everything a format can fail at that is not the destination's own I/O happens here:
    // the archive is read and parsed, the geometry is planned, and the inode model is built
    // and checked against it. The destination is not opened until this has succeeded, so a
    // failing run cannot destroy the image already at that path.
    let plan: FormatPlan = crate::format::planned(args, options(args, target))?;

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
    let mut o = FormatOptions::new(target.uuid, args.stamp(), target.hash_seed);
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
    let mut rows = render::Rows::summary();
    let mut line = |k: &str, v: String| rows.row(k, v);
    if let Some(label) = render::label(&target.volume_name) {
        line("Filesystem volume name:", label);
    }
    line("Filesystem UUID:", render::uuid(&target.uuid));
    line(
        "Filesystem profile:",
        Profile::of(target.feature).as_str().to_string(),
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
    line("Filesystem created:", render::iso8601(args.stamp().secs));
    rows.finish()
}

/// The receipt a machine reads: the same geometry, as JSON.
fn receipt(args: &FormatArgs, target: &ExtTarget, layout: &Layout, usage: Option<Usage>) -> String {
    crate::json::document(|o| {
        // The head every family's receipt carries, so a caller reads which filesystem was
        // written from the same two fields whichever one it asked for.
        o.str("family", "ext");
        o.str("variant", Profile::of(target.feature).as_str());
        o.str("uuid", &render::uuid(&target.uuid));
        // The label byte-exact: a non-UTF-8 label carries a `_hex` field rather than being
        // flattened through the replacement character, which is what separates this from the
        // human summary's `render::label` above. Both ask the library where the padding
        // starts, so the two can never disagree about where the label ends.
        o.bytes("volume_name", unpadded(&target.volume_name));
        o.i64("created", args.stamp().secs);
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
