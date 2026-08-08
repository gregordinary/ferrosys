//! Writing a FAT12, FAT16, or FAT32 volume, and reporting the geometry and the fidelity it
//! cost.
//!
//! # What a report has that ext's does not
//!
//! A FAT directory entry has no field for an owner, a group, permission bits, a symbolic
//! link, a second name for a file, a device number, or an extended attribute — so a tree
//! carrying any of those does not come back out the way it went in. The plan says so before
//! the destination is opened, and a build that would lose something the caller has not
//! accepted with `--accept-loss` fails there, naming the entry and the property.
//!
//! A loss is a value that does not survive, not a field that does not exist. A root-owned
//! tree of `0644` files and `0755` directories goes in and comes back unchanged, because
//! those are exactly what a read of the image fills in — so it loses nothing and the summary
//! says so.

use std::path::Path;

use ferrosys::ArchiveSource;
#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::DirectorySource;
use ferrosys::fat::{FatLayout, FormatOptions, FormatPlan};
use ferrosys::{FidelityReport, Source, TreeBuilder};

use crate::args::{Contents, FatTarget, FormatArgs, Size, Stream};
use crate::{Error, emit, render};

/// Write the FAT volume the arguments describe.
pub fn run(args: &FormatArgs, target: &FatTarget) -> Result<(), Error> {
    let options = options(args, target);

    // As on the ext side: everything a format can fail at that is not the destination's own
    // I/O happens here, and the destination is not opened until it has succeeded. This
    // family adds a second reason to want the plan as a value — the fidelity report is
    // readable before the write, so what a build will cost is a number to read rather than
    // a surprise to discover.
    let plan = match &args.contents {
        None => build(TreeBuilder::new(), args, options)?,
        Some(Contents::Tar(Stream::Std)) => build(
            ArchiveSource::from_reader(crate::format::bounded_stdin())?,
            args,
            options,
        )?,
        Some(Contents::Tar(Stream::File(path))) => {
            build(ArchiveSource::from_path(path)?, args, options)?
        }
        Some(Contents::Dir(path)) => from_dir(path, args, options)?,
    };

    // Read before the write consumes nothing, so the dry run and the real one report the
    // same number.
    let free = plan.free_clusters();

    if args.dry_run {
        return report(args, target, plan.layout(), free, plan.fidelity(), false);
    }

    let mut dest = crate::format::open_destination(&args.out, args.atomic)?;
    let layout = plan.write_to(dest.file())?;
    dest.commit()?;
    report(args, target, &layout, free, plan.fidelity(), true)
}

/// Plan a format from one source kind.
fn build(
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
#[cfg(any(target_os = "linux", target_os = "android"))]
fn from_dir(path: &Path, args: &FormatArgs, options: FormatOptions) -> Result<FormatPlan, Error> {
    let mut source = DirectorySource::from_path(path)?;
    if let Some((uid, gid)) = args.owner {
        source = source.owner(uid, gid);
    }
    build(source, args, options)
}

/// The same, on a platform the library builds no directory source for.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn from_dir(
    _path: &Path,
    _args: &FormatArgs,
    _options: FormatOptions,
) -> Result<FormatPlan, Error> {
    Err(Error::NoDirectorySource)
}

/// The library options one set of arguments names.
fn options(args: &FormatArgs, target: &FatTarget) -> FormatOptions {
    let mut o = FormatOptions::new(target.volume_id, args.time);
    o.label = target.label;
    o.accepted_loss = target.accepted_loss;
    o.synthesis = target.synthesis;
    o.plan.fat_type = target.request;
    o
}

/// Report the geometry, and what the build cost in fidelity.
fn report(
    args: &FormatArgs,
    target: &FatTarget,
    layout: &FatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
    written: bool,
) -> Result<(), Error> {
    if args.json {
        emit(receipt(args, target, layout, free_clusters, fidelity, written).as_bytes())
    } else {
        eprint!("{}", summary(args, target, layout, free_clusters, fidelity));
        Ok(())
    }
}

/// The summary a person reads.
fn summary(
    args: &FormatArgs,
    target: &FatTarget,
    layout: &FatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        s.push_str(&format!("{k:<24}{v}\n"));
    };
    if let Some(label) = &target.label {
        line("Volume label:", render::printable(trim_label(label)));
    }
    line(
        "Volume serial number:",
        render::volume_serial(target.volume_id),
    );
    line("Filesystem type:", layout.fat_type.as_str().to_string());
    line("Bytes per sector:", layout.bytes_per_sector.to_string());
    line(
        "Sectors per cluster:",
        layout.sectors_per_cluster.to_string(),
    );
    line("Bytes per cluster:", layout.bytes_per_cluster().to_string());
    line("Reserved sectors:", layout.reserved_sectors.to_string());
    line("Allocation tables:", layout.fats.to_string());
    line("Sectors per table:", layout.fat_sectors.to_string());
    line("Root directory entries:", layout.root_entries.to_string());
    line("Total sectors:", layout.total_sectors.to_string());
    line("Clusters:", layout.clusters.to_string());
    // FAT12 and FAT16 record no free count on disk, so for those this is the only place the
    // number is stated at all — and on FAT32 it is what the information sector carries.
    line("Free clusters:", free_clusters.to_string());
    line("Filesystem created:", render::iso8601(args.time.secs));
    // Last, and never omitted: what the volume could not carry is the thing about this
    // family a caller most needs told, and a faithful build says so in one line rather than
    // leaving silence to mean it.
    s.push('\n');
    s.push_str(&fidelity_table(fidelity));
    s
}

/// What the build could not carry, one line per property, in this tool's own spelling.
///
/// Rendered here rather than taken from the library so the words are the ones
/// `--accept-loss` reads: a property this table names is one that can be typed straight back
/// into the command line that produced it.
fn fidelity_table(fidelity: &FidelityReport) -> String {
    let summary = fidelity.summary();
    if summary.is_empty() {
        return "nothing dropped or synthesized\n".to_string();
    }
    let mut s = String::from("DIRECTION  PROPERTY             ENTRIES\n");
    for (direction, property, entries) in summary {
        s.push_str(&format!(
            "{:<11}{:<21}{}\n",
            direction.as_str(),
            crate::parse::property_name(property),
            entries
        ));
    }
    if fidelity.is_truncated() {
        // The counts are complete either way; it is the per-entry records that stopped.
        s.push_str("(more entries than the report stores individually; the counts are whole)\n");
    }
    s
}

/// A volume label without the padding that fills the field it is stored in.
///
/// The stored form is eleven bytes padded with spaces on the right, which is what the volume
/// holds and not what the label is.
fn trim_label(label: &ferrosys::fat::VolumeLabel) -> &[u8] {
    let bytes = label.as_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// The receipt a machine reads.
fn receipt(
    args: &FormatArgs,
    target: &FatTarget,
    layout: &FatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
    written: bool,
) -> String {
    crate::json::document(|o| {
        // The head every family's receipt carries, so a caller reads which filesystem was
        // written from the same two fields whichever one it asked for.
        o.str("family", "fat");
        o.str("variant", layout.fat_type.as_str());
        o.u64("volume_id", u64::from(target.volume_id));
        o.str("volume_serial", &render::volume_serial(target.volume_id));
        match &target.label {
            Some(label) => o.bytes("volume_label", trim_label(label)),
            None => o.raw("volume_label", "null"),
        }
        o.i64("created", args.time.secs);
        o.u64("bytes_per_sector", u64::from(layout.bytes_per_sector));
        o.u64("sectors_per_cluster", u64::from(layout.sectors_per_cluster));
        o.u64("bytes_per_cluster", u64::from(layout.bytes_per_cluster()));
        o.u64("reserved_sectors", u64::from(layout.reserved_sectors));
        o.u64("fats", u64::from(layout.fats));
        o.u64("fat_sectors", u64::from(layout.fat_sectors));
        o.u64("root_entries", u64::from(layout.root_entries));
        o.u64("root_dir_sectors", u64::from(layout.root_dir_sectors));
        o.u64("first_data_sector", u64::from(layout.first_data_sector));
        o.u64("total_sectors", u64::from(layout.total_sectors));
        o.u64("clusters", u64::from(layout.clusters));
        o.u64("free_clusters", u64::from(free_clusters));
        // What the format could not carry, whether or not it carried everything: `faithful`
        // is the one field a caller acts on, and it is always there to be read.
        let mut f = o.obj("fidelity");
        f.bool("faithful", fidelity.is_faithful());
        f.bool("truncated", fidelity.is_truncated());
        let mut a = f.arr("summary");
        for (direction, property, entries) in fidelity.summary() {
            let mut r = a.obj();
            r.str("direction", direction.as_str());
            r.str("property", crate::parse::property_name(property));
            r.u64("entries", entries);
            r.end();
        }
        a.end();
        f.end();
        o.bool("written", written);
    })
}
