//! Writing an APFS container, and reporting the geometry it realized.
//!
//! # What this family's report says that the others do not
//!
//! Volumes. An APFS container is a pool of blocks with several filesystems in it, each with a
//! name, an identifier and a way of comparing names of its own, so the summary lists every
//! volume the format was asked for in the slot it was given. What the container itself has is
//! a block size, a block count and the blocks its space manager records free once every
//! volume's content is placed. The first volume holds the contents and every other volume is
//! empty but for its root directory.
//!
//! # Nothing is lost, and the report says so anyway
//!
//! A volume holds every property a source states: owners, modes, four times to the
//! nanosecond, hard links, device nodes, pipes, sockets and extended attributes. So the
//! fidelity summary is empty, and it is printed regardless, as every family's is: a caller
//! writing one build step against several families asks each the same question.
//!
//! # A search for a size
//!
//! `--size auto` finds the smallest container that holds the contents with `--slack` left
//! free, by planning candidate sizes and placing the volumes' content into each. The size it
//! settles on is a whole number of blocks, and the destination is that many bytes.

use ferrosys::apfs::{ApfsLayout, Firmlinks, FormatOptions, FormatPlan};
use ferrosys::{Slack, Source};

use crate::args::{ApfsTarget, FormatArgs};
use crate::dest::Reads;
use crate::format::{Plan, Written};
use crate::{Error, emit, render};

impl Plan for FormatPlan {
    type Options = FormatOptions;

    const FAMILY: &'static str = "apfs";

    fn sized(source: impl Source, bytes: u64, options: FormatOptions) -> Result<Self, Error> {
        Ok(FormatPlan::new(source, bytes, options)?)
    }

    fn fitted(source: impl Source, options: FormatOptions, slack: Slack) -> Result<Self, Error> {
        Ok(FormatPlan::fit(source, options, slack)?)
    }
}

impl Written for FormatPlan {
    type Layout = ApfsLayout;

    fn planned_layout(&self) -> ApfsLayout {
        self.layout().clone()
    }

    fn write_to(&self, file: &mut std::fs::File) -> Result<ApfsLayout, Error> {
        FormatPlan::write_to(self, file)?;
        Ok(self.layout().clone())
    }
}

/// Write the APFS container the arguments describe.
pub fn run(args: &FormatArgs, target: &ApfsTarget) -> Result<(), Error> {
    // As in every other family: everything a format can fail at that is not the destination's
    // own I/O happens here, and the destination is not opened until it has succeeded.
    let (options, volume_reads) = options(args, target)?;
    let listed = options
        .volumes
        .iter()
        .filter_map(|volume| volume.firmlinks.as_ref())
        .map(Firmlinks::len)
        .sum();
    let (plan, reads): (FormatPlan, _) = crate::format::planned(args, options)?;
    let reads = reads.and(volume_reads);
    let (layout, written) = crate::format::realize(args, &plan, &reads)?;
    let outcome = Outcome {
        layout: &layout,
        plan: &plan,
        listed,
    };
    if args.json {
        emit(receipt(args, target, &outcome, written).as_bytes())
    } else {
        eprint!("{}", summary(args, target, &outcome));
        Ok(())
    }
}

/// What a format came to: the geometry it realized, the plan it carried out, and how many
/// firmlinks the System volume was given, of which the plan says how many it marked.
struct Outcome<'a> {
    layout: &'a ApfsLayout,
    plan: &'a FormatPlan,
    listed: usize,
}

/// The library options one set of arguments names, and the host files the trees of the
/// volumes after the first read as they are placed.
///
/// Every identifier travels, the container's and each volume's: a container whose bytes a
/// caller can reproduce is one that states all of them, and a value this tool invented would
/// be a value the caller could not state.
fn options(args: &FormatArgs, target: &ApfsTarget) -> Result<(FormatOptions, Reads), Error> {
    let mut requests = target.volumes.clone();
    let mut reads = Reads::default();
    for (slot, dir) in &target.volume_dirs {
        let entries = crate::format::walked(dir, args)?;
        reads = reads.and(crate::format::reads_of(&entries, args)?);
        let request = &mut requests[*slot as usize];
        *request = request.clone().contents(entries);
    }
    if let (Some(path), Some(group)) = (&target.firmlinks, target.volume_group) {
        let text = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        let links = Firmlinks::parse(&text).map_err(|source| Error::Firmlinks {
            path: path.display().to_string(),
            source,
        })?;
        // A slot past the volumes is the library's refusal to name, which it does before
        // anything is placed.
        if let Some(request) = requests.get_mut(group.system as usize) {
            *request = request.clone().firmlinks(links);
        }
    }
    let mut volumes = requests.into_iter();
    let first = volumes
        .next()
        .expect("the parser requires one --volume at least");
    let mut options = FormatOptions::new(target.container_uuid, args.stamp(), first)
        .block_size(target.block_size)
        .profile(target.profile)
        .formatted_by(target.formatted_by);
    for volume in volumes {
        options = options.volume(volume);
    }
    if let Some(group) = target.volume_group {
        options = options.volume_group(group);
    }
    Ok((options, reads))
}

/// The summary a person reads.
fn summary(args: &FormatArgs, target: &ApfsTarget, outcome: &Outcome<'_>) -> String {
    let (layout, bytes) = (outcome.layout, outcome.plan.container_bytes());
    let mut rows = render::Rows::summary();
    let mut line = |k: &str, v: String| rows.row(k, v);
    line("Container id:", render::uuid(&target.container_uuid));
    line("Filesystem type:", "apfs".to_string());
    line("Written as:", target.profile.as_str().to_string());
    line("Bytes:", bytes.to_string());
    line("Block size:", layout.block_size.to_string());
    line("Block count:", layout.block_count.to_string());
    line("Free blocks:", layout.free_blocks().to_string());
    line("Writable blocks:", layout.writable_blocks().to_string());
    line(
        "Volumes:",
        format!("{} of {}", target.volumes.len(), layout.max_volumes),
    );
    line(
        "Formatted by:",
        render::printable(target.formatted_by.as_bytes()),
    );
    line("Container created:", render::iso8601(args.stamp().secs));
    // The volumes, each in its slot, with the identifier in full: it is what a caller has to
    // state again to write the same container twice, and a truncated one is a value someone
    // will copy.
    rows.blank();
    rows.text("SLOT  NAMES             IDENTIFIER                            NAME\n");
    for (slot, volume) in target.volumes.iter().enumerate() {
        rows.text(&format!(
            "{:<6}{:<18}{:<38}{}\n",
            slot,
            volume.names.as_str(),
            render::uuid(&volume.uuid),
            render::printable(volume.name.as_str().as_bytes())
        ));
    }
    // A root snapshot belongs to its volume, so it is named under the table, by its slot.
    for (slot, volume) in target.volumes.iter().enumerate() {
        if let Some(snapshot) = &volume.root_snapshot {
            rows.blank();
            rows.row(
                &format!("Root snapshot {slot}:"),
                format!(
                    "{} {}",
                    render::uuid(&snapshot.uuid()),
                    render::printable(snapshot.name().as_bytes())
                ),
            );
        }
    }
    // The group, by its members' slots and by the identifier it carries, which is its Data
    // volume's own; and how many of the listed firmlinks named a directory the System volume
    // holds, since a line naming none marks nothing.
    if let Some(group) = target.volume_group {
        rows.blank();
        rows.row(
            "Volume group:",
            format!(
                "System in slot {}, Data in slot {}, identified as {}",
                group.system,
                group.data,
                render::uuid(&target.volumes[group.data as usize].uuid)
            ),
        );
        if target.firmlinks.is_some() {
            rows.row(
                "Firmlinks:",
                format!(
                    "{} of {} listed directories",
                    outcome.plan.firmlinked(),
                    outcome.listed
                ),
            );
        }
    }
    // Last, and never omitted, for the reason every family's is: a build that lost nothing
    // says so in one line rather than leaving silence to mean it.
    rows.blank();
    rows.text(&crate::format::fidelity_table(outcome.plan.fidelity()));
    rows.finish()
}

/// The receipt a machine reads.
fn receipt(args: &FormatArgs, target: &ApfsTarget, outcome: &Outcome<'_>, written: bool) -> String {
    let (layout, bytes) = (outcome.layout, outcome.plan.container_bytes());
    crate::json::document(|o| {
        // The head every family's receipt carries. A container has one format and no lineage
        // to spell, so the family is the variant, as `inspect` reports it.
        o.str("family", "apfs");
        o.str("variant", "apfs");
        o.str("container_uuid", &render::uuid(&target.container_uuid));
        o.str("profile", target.profile.as_str());
        o.bytes("formatted_by", target.formatted_by.as_bytes());
        o.i64("created", args.stamp().secs);
        o.u64("bytes", bytes);
        o.u64("block_size", u64::from(layout.block_size));
        o.u64("block_count", layout.block_count);
        o.u64("free_blocks", layout.free_blocks());
        o.u64("writable_blocks", layout.writable_blocks());
        o.u64("max_volumes", u64::from(layout.max_volumes));
        let mut volumes = o.arr("volumes");
        for ((slot, volume), place) in (0u64..).zip(&target.volumes).zip(&layout.newest().volumes) {
            let mut v = volumes.obj();
            v.u64("slot", slot);
            v.bytes("name", volume.name.as_str().as_bytes());
            v.str("uuid", &render::uuid(&volume.uuid));
            v.str("names", volume.names.as_str());
            v.u64("superblock", place.superblock);
            if let Some(snapshot) = &volume.root_snapshot {
                let mut r = v.obj("root_snapshot");
                r.bytes("name", snapshot.name().as_bytes());
                r.str("uuid", &render::uuid(&snapshot.uuid()));
                r.end();
            }
            v.end();
        }
        volumes.end();
        if let Some(group) = target.volume_group {
            let mut g = o.obj("volume_group");
            g.u64("system", u64::from(group.system));
            g.u64("data", u64::from(group.data));
            g.str(
                "uuid",
                &render::uuid(&target.volumes[group.data as usize].uuid),
            );
            if target.firmlinks.is_some() {
                g.u64("firmlinks_listed", outcome.listed as u64);
                g.u64("firmlinks_marked", outcome.plan.firmlinked() as u64);
            }
            g.end();
        }
        crate::format::fidelity_receipt(o, outcome.plan.fidelity());
        o.bool("written", written);
    })
}
