//! Writing a btrfs filesystem, and reporting the geometry it realized.
//!
//! # What this family's report says that the other three do not
//!
//! Chunks and subvolumes. A btrfs is a logical address space with a map onto the device, so
//! where a block group sits and how many copies of it the device carries is the geometry —
//! there is no single "data area" the way a cluster heap or a block-group table is one. And a
//! filesystem may hold more than one tree a mount can land in, so what the summary lists is
//! every subvolume the format was asked for, with the identifier each is known by.
//!
//! # Nothing is lost, and the report says so anyway
//!
//! btrfs represents every property a source states — ownership, modes, symbolic links, second
//! names, device numbers, extended attributes, and four timestamps each to the nanosecond — so
//! a build here drops nothing and the fidelity summary is empty. It is printed regardless, for
//! the reason `--accept-loss` is refused for this family: a caller writing one build step
//! against four families asks all four the same question, and a family that answered by saying
//! nothing would be one whose answer had to be known in advance.
//!
//! # No search for a size
//!
//! `--size auto` finds the smallest filesystem that holds the contents by planning candidates
//! and placing into them, and that search is a family's own. This family has none, so the
//! argument parser refuses `--size auto` for it before a source is read.

use ferrosys::btrfs::ondisk::BlockGroupFlags;
use ferrosys::btrfs::{
    BtrfsLayout, FormatOptions, FormatPlan, NodeSize, PlanRequest, SectorSize, VolumeLabel,
};
use ferrosys::{FidelityReport, Source};

use crate::args::{BtrfsTarget, FormatArgs};
use crate::format::{Plan, Written};
use crate::{Error, emit, render};

impl Plan for FormatPlan {
    type Options = FormatOptions;

    const FAMILY: &'static str = "btrfs";

    fn sized(source: impl Source, bytes: u64, options: FormatOptions) -> Result<Self, Error> {
        Ok(FormatPlan::new(source, bytes, options)?)
    }
}

impl Written for FormatPlan {
    type Layout = BtrfsLayout;

    fn planned_layout(&self) -> BtrfsLayout {
        self.layout().clone()
    }

    fn write_to(&self, file: &mut std::fs::File) -> Result<BtrfsLayout, Error> {
        FormatPlan::write_to(self, file)?;
        Ok(self.layout().clone())
    }
}

/// Write the btrfs filesystem the arguments describe.
pub fn run(args: &FormatArgs, target: &BtrfsTarget) -> Result<(), Error> {
    // As in the other three families: everything a format can fail at that is not the
    // destination's own I/O happens here, and the destination is not opened until it has
    // succeeded.
    let plan: FormatPlan = crate::format::planned(args, options(args, target))?;
    let (layout, written) = crate::format::realize(args, &plan)?;
    report(args, target, &layout, plan.fidelity(), written)
}

/// The library options one set of arguments names.
///
/// Every identifier travels, including the two the format's own tooling has no switch for: a
/// filesystem whose bytes a caller can reproduce is one that states all of them, and a value
/// this tool invented would be a value the caller could not state.
fn options(args: &FormatArgs, target: &BtrfsTarget) -> FormatOptions {
    let mut request = PlanRequest::new(0)
        .metadata_profile(target.metadata_profile)
        .data_profile(target.data_profile)
        .features(target.features.incompat, target.features.compat_ro);
    if let Some(bytes) = target.sector_size {
        request = request.sector_size(SectorSize::Bytes(bytes));
    }
    if let Some(bytes) = target.node_size {
        request = request.node_size(NodeSize::Bytes(bytes));
    }
    let mut options = FormatOptions::new(target.fsid, args.stamp())
        .metadata_uuid(target.metadata_uuid)
        .chunk_tree_uuid(target.chunk_tree_uuid)
        .device_uuid(target.device_uuid)
        .subvolume_uuid(target.subvolume_uuid)
        .label(target.label)
        .plan(request);
    for request in &target.subvolumes {
        options = options.subvolume(request.clone());
    }
    if let Some(path) = &target.default_subvolume {
        options = options.default_subvolume(path.clone());
    }
    options
}

/// Report the geometry the format realized.
fn report(
    args: &FormatArgs,
    target: &BtrfsTarget,
    layout: &BtrfsLayout,
    fidelity: &FidelityReport,
    written: bool,
) -> Result<(), Error> {
    if args.json {
        emit(receipt(args, target, layout, fidelity, written).as_bytes())
    } else {
        eprint!("{}", summary(args, target, layout, fidelity));
        Ok(())
    }
}

/// The label as a person reads it, or that the filesystem carries none.
///
/// A btrfs label is bytes and the field records no encoding, so what is shown is the printable
/// rendering the reader's own reports use rather than a decoding this tool chose.
fn label_text(label: &VolumeLabel) -> Option<String> {
    if label.as_bytes().is_empty() {
        return None;
    }
    Some(render::printable(label.as_bytes()))
}

/// The word the report uses for a block group's contents.
///
/// The flags a chunk carries are a set, and exactly one of the three kinds is in it on every
/// filesystem this writes — mixed block groups being a feature the planner refuses — so one
/// word describes a chunk rather than a list.
fn contents_of(chunk: &ferrosys::btrfs::MappedChunk) -> &'static str {
    if chunk.flags.contains(BlockGroupFlags::SYSTEM) {
        "system"
    } else if chunk.flags.contains(BlockGroupFlags::METADATA) {
        "metadata"
    } else {
        "data"
    }
}

/// The summary a person reads.
fn summary(
    args: &FormatArgs,
    target: &BtrfsTarget,
    layout: &BtrfsLayout,
    fidelity: &FidelityReport,
) -> String {
    let mut rows = render::Rows::summary();
    let mut line = |k: &str, v: String| rows.row(k, v);
    if let Some(label) = label_text(&target.label) {
        line("Label:", label);
    }
    line("Filesystem id:", render::uuid(&target.fsid));
    // Only where it differs from the id above. A filesystem whose two ids are one does not
    // carry the feature that distinguishes them, so a row here would report a state it is
    // not in.
    if let Some(uuid) = target.metadata_uuid {
        line("Metadata id:", render::uuid(&uuid));
    }
    line("Filesystem type:", "btrfs".to_string());
    line("Bytes per sector:", layout.sector_size.to_string());
    line("Bytes per tree block:", layout.node_size.to_string());
    line("Total bytes:", layout.volume_bytes.to_string());
    line(
        "Device bytes allocated:",
        layout.device_bytes_used().to_string(),
    );
    line(
        "Superblock copies:",
        layout.superblock_mirrors.len().to_string(),
    );
    line("Filesystem created:", render::iso8601(args.stamp().secs));
    // The chunks, which is where a btrfs's geometry actually is: a logical address space with
    // a map onto the device, rather than one region per kind of thing.
    rows.blank();
    rows.text("CHUNK      LOGICAL           LENGTH        COPIES\n");
    for chunk in &layout.chunks {
        rows.text(&format!(
            "{:<11}{:<18}{:<14}{}\n",
            contents_of(chunk),
            chunk.logical,
            chunk.length,
            chunk.copies.len()
        ));
    }
    // The subvolumes the format was asked for, which are the trees a mount can land in beside
    // the one every btrfs has.
    if !target.subvolumes.is_empty() {
        rows.blank();
        rows.text("ACCESS     IDENTIFIER                             PATH\n");
        for request in &target.subvolumes {
            // The identifier in full rather than shortened. It is what a caller has to state
            // again to write the same filesystem twice, and a truncated one is a value someone
            // will copy.
            rows.text(&format!(
                "{:<11}{:<38}{}\n",
                if request.read_only {
                    "read-only"
                } else {
                    "writable"
                },
                render::uuid(&request.uuid),
                render::printable(&request.path)
            ));
        }
    }
    if let Some(path) = &target.default_subvolume {
        rows.blank();
        rows.text(&format!(
            "A mount told no subvolume lands on {}.\n",
            render::printable(path)
        ));
    }
    // Last, and never omitted, for the reason every family's is: a build that lost nothing
    // says so in one line rather than leaving silence to mean it.
    rows.blank();
    rows.text(&crate::format::fidelity_table(fidelity));
    rows.finish()
}

/// The receipt a machine reads.
fn receipt(
    args: &FormatArgs,
    target: &BtrfsTarget,
    layout: &BtrfsLayout,
    fidelity: &FidelityReport,
    written: bool,
) -> String {
    crate::json::document(|o| {
        // The head every family's receipt carries, so a caller reads which filesystem was
        // written from the same two fields whichever one it asked for. This family's variant
        // is its family: what varies between two btrfs filesystems is a feature word and a
        // geometry, and neither is a variant to name here.
        o.str("family", "btrfs");
        o.str("variant", "btrfs");
        o.str("fsid", &render::uuid(&target.fsid));
        match target.metadata_uuid {
            Some(uuid) => o.str("metadata_uuid", &render::uuid(&uuid)),
            None => o.raw("metadata_uuid", "null"),
        }
        o.str("chunk_tree_uuid", &render::uuid(&target.chunk_tree_uuid));
        o.str("device_uuid", &render::uuid(&target.device_uuid));
        o.str("subvolume_uuid", &render::uuid(&target.subvolume_uuid));
        // The bytes, and their printable rendering beside them where they are not text: a
        // label the format records no encoding for is one a consumer may need to see exactly.
        if label_text(&target.label).is_some() {
            o.bytes("label", target.label.as_bytes());
        } else {
            o.raw("label", "null");
        }
        o.i64("created", args.stamp().secs);
        o.u64("sector_size", u64::from(layout.sector_size));
        o.u64("node_size", u64::from(layout.node_size));
        o.u64("total_bytes", layout.volume_bytes);
        o.u64("device_bytes_allocated", layout.device_bytes_used());
        o.u64s("superblock_mirrors", &layout.superblock_mirrors);
        let mut chunks = o.arr("chunks");
        for chunk in &layout.chunks {
            let mut c = chunks.obj();
            c.str("contents", contents_of(chunk));
            c.u64("logical", chunk.logical);
            c.u64("length", chunk.length);
            c.u64s("device_offsets", &chunk.copies);
            c.end();
        }
        chunks.end();
        let mut subvolumes = o.arr("subvolumes");
        for request in &target.subvolumes {
            let mut s = subvolumes.obj();
            s.bytes("path", &request.path);
            s.str("uuid", &render::uuid(&request.uuid));
            s.bool("read_only", request.read_only);
            s.end();
        }
        subvolumes.end();
        match &target.default_subvolume {
            Some(path) => o.bytes("default_subvolume", path),
            None => o.raw("default_subvolume", "null"),
        }
        // What the format could not carry, whether or not it carried everything: `faithful` is
        // the one field a caller acts on, and it is always there to be read.
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
