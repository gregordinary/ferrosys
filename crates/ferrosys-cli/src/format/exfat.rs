//! Writing an exFAT volume, and reporting the geometry and the fidelity it cost.
//!
//! # What this family's report says that the other two do not
//!
//! An exFAT directory entry set records a name, five attribute bits, three times and two
//! lengths, and has no field for an owner, a group, permission bits, a symbolic link, a
//! second name for a file, a device number, or an extended attribute. So the report is the
//! same shape as FAT's, for the same reason and with the same list — the plan says what a
//! build will cost before the destination is opened, and a build that would lose something
//! the caller has not accepted with `--accept-loss` fails there, naming the entry and the
//! property.
//!
//! A loss is a value that does not survive, not a field that does not exist. A root-owned
//! tree of `0644` files and `0755` directories goes in and comes back unchanged, because
//! those are exactly what a read of the image fills in — so it loses nothing and the summary
//! says so.
//!
//! # No search for a size
//!
//! `--size auto` finds the smallest filesystem that holds the contents by planning candidates
//! and placing into them, and that search is a family's own. This family has none, so the
//! argument parser refuses `--size auto` for it before a source is read. [`Plan::fitted`]'s
//! default is what says so in the type, so a family without a search is one that writes no
//! function rather than one that writes an unreachable one.

use ferrosys::exfat::{ExfatLayout, FormatOptions, FormatPlan, VolumeLabel};
use ferrosys::{FidelityReport, Source};

use crate::args::{ExFatTarget, FormatArgs};
use crate::format::{Plan, Written};
use crate::{Error, emit, render};

impl Plan for FormatPlan {
    type Options = FormatOptions;

    const FAMILY: &'static str = "exfat";

    fn sized(source: impl Source, bytes: u64, options: FormatOptions) -> Result<Self, Error> {
        Ok(FormatPlan::new(source, bytes, options)?)
    }
}

impl Written for FormatPlan {
    type Layout = ExfatLayout;

    fn planned_layout(&self) -> ExfatLayout {
        *self.layout()
    }

    fn write_to(&self, file: &mut std::fs::File) -> Result<ExfatLayout, Error> {
        Ok(FormatPlan::write_to(self, file)?)
    }
}

/// Write the exFAT volume the arguments describe.
pub fn run(args: &FormatArgs, target: &ExFatTarget) -> Result<(), Error> {
    // As in the other two families: everything a format can fail at that is not the
    // destination's own I/O happens here, and the destination is not opened until it has
    // succeeded. The fidelity report is readable off the plan, so what a build will cost is a
    // number to read before it is paid.
    let plan: FormatPlan = crate::format::planned(args, options(target))?;
    // Read before the write consumes nothing, so the dry run and the real one report the same
    // number.
    let free = plan.free_clusters();
    let (layout, written) = crate::format::realize(args, &plan)?;
    report(args, target, &layout, free, plan.fidelity(), written)
}

/// The library options one set of arguments names.
///
/// No instant is among them, and the absence is the format rather than an oversight: an
/// exFAT volume records no time of its own anywhere. The boot region has no field for one and
/// the label entry — which is where the FAT family puts the formatting time — is a character
/// count and a name. Every time on the volume belongs to an entry and comes from the source
/// that named it, which is why the parser refuses `--time` for this family rather than
/// accepting a number the image would not hold.
fn options(target: &ExFatTarget) -> FormatOptions {
    FormatOptions::new(target.volume_serial)
        .label(target.label)
        .accepted_loss(target.accepted_loss)
        .synthesis(target.synthesis)
}

/// Report the geometry, and what the build cost in fidelity.
fn report(
    args: &FormatArgs,
    target: &ExFatTarget,
    layout: &ExfatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
    written: bool,
) -> Result<(), Error> {
    if args.json {
        emit(receipt(target, layout, free_clusters, fidelity, written).as_bytes())
    } else {
        eprint!("{}", summary(target, layout, free_clusters, fidelity));
        Ok(())
    }
}

/// The label as text, or `None` for a volume that carries no name.
///
/// An exFAT label is UTF-16 code units, so what a person reads is the decoding of them —
/// and a label with no units is the unnamed volume rather than an empty name, which is the
/// one distinction a caller acts on.
fn label_text(label: &VolumeLabel) -> Option<String> {
    if label.units().is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(label.units()))
}

/// The summary a person reads.
fn summary(
    target: &ExFatTarget,
    layout: &ExfatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
) -> String {
    let mut rows = render::Rows::summary();
    let mut line = |k: &str, v: String| rows.row(k, v);
    if let Some(label) = label_text(&target.label) {
        line("Volume label:", label);
    }
    line(
        "Volume serial number:",
        render::volume_serial(target.volume_serial),
    );
    line("Filesystem type:", "exfat".to_string());
    line("Bytes per sector:", layout.bytes_per_sector.to_string());
    line(
        "Sectors per cluster:",
        layout.sectors_per_cluster().to_string(),
    );
    line("Bytes per cluster:", layout.bytes_per_cluster.to_string());
    line("Allocation table at sector:", layout.fat_offset.to_string());
    line("Sectors per table:", layout.fat_length.to_string());
    line(
        "Cluster heap at sector:",
        layout.cluster_heap_offset.to_string(),
    );
    line("Total sectors:", layout.volume_length.to_string());
    line("Clusters:", layout.cluster_count.to_string());
    line("Free clusters:", free_clusters.to_string());
    // The three the format itself allocates, which is where a volume's overhead is: nothing
    // else in this summary would say that a fresh volume has already spent clusters, and on a
    // small one the up-case table alone is most of what it spent.
    line(
        "Allocation bitmap at cluster:",
        layout.bitmap_cluster.to_string(),
    );
    line(
        "Up-case table at cluster:",
        layout.upcase_cluster.to_string(),
    );
    line(
        "Root directory at cluster:",
        layout.first_cluster_of_root.to_string(),
    );
    // Last, and never omitted: what the volume could not carry is the thing about this family
    // a caller most needs told, and a faithful build says so in one line rather than leaving
    // silence to mean it.
    rows.blank();
    rows.text(&crate::format::fidelity_table(fidelity));
    rows.finish()
}

/// The receipt a machine reads.
fn receipt(
    target: &ExFatTarget,
    layout: &ExfatLayout,
    free_clusters: u32,
    fidelity: &FidelityReport,
    written: bool,
) -> String {
    crate::json::document(|o| {
        // The head every family's receipt carries, so a caller reads which filesystem was
        // written from the same two fields whichever one it asked for. This family's variant
        // is its family: there is one revision of the format and nothing to sub-classify.
        o.str("family", "exfat");
        o.str("variant", "exfat");
        o.u64("volume_serial_number", u64::from(target.volume_serial));
        o.str(
            "volume_serial",
            &render::volume_serial(target.volume_serial),
        );
        match label_text(&target.label) {
            Some(label) => o.str("volume_label", &label),
            None => o.raw("volume_label", "null"),
        }
        o.u64("bytes_per_sector", u64::from(layout.bytes_per_sector));
        o.u64(
            "sectors_per_cluster",
            u64::from(layout.sectors_per_cluster()),
        );
        o.u64("bytes_per_cluster", u64::from(layout.bytes_per_cluster));
        o.u64("fat_offset", u64::from(layout.fat_offset));
        o.u64("fat_length", u64::from(layout.fat_length));
        o.u64("cluster_heap_offset", u64::from(layout.cluster_heap_offset));
        o.u64("total_sectors", layout.volume_length);
        o.u64("clusters", u64::from(layout.cluster_count));
        o.u64("free_clusters", u64::from(free_clusters));
        o.u64("bitmap_cluster", u64::from(layout.bitmap_cluster));
        o.u64("bitmap_bytes", layout.bitmap_bytes);
        o.u64("upcase_cluster", u64::from(layout.upcase_cluster));
        o.u64("upcase_bytes", layout.upcase_bytes);
        o.u64("root_cluster", u64::from(layout.first_cluster_of_root));
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
