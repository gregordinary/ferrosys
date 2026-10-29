//! The APFS body of an `inspect` report: the container, every volume it lists, and the
//! snapshots of the volume the report reads.
//!
//! Everything here is APFS's own vocabulary — a container, a checkpoint, a volume and its role,
//! a snapshot. The envelope above this module carries the five fields that mean the same thing
//! for every family and knows none of it.
//!
//! # A container of volumes, and a report of one of them
//!
//! A container lists up to a hundred volumes, each a filesystem of its own, so the body has a
//! line for every one — its name, its role and group, its identifier, whether its names fold
//! case, and whether this tool reads it, or, where its superblock could not be read, why — and
//! says which one the scan read. That is the volume
//! `--volume` names, or the one in the container's first slot, and `--snapshot` names one of
//! its snapshots instead of the volume as it is.

use std::fs::File;

use ferrosys::apfs::ondisk::role_name;
use ferrosys::apfs::{BlockZero, NameKind, Reader, Snapshot, UnreadableVolume, VolumeEntry};

use crate::args::InspectArgs;
use crate::inspect::{Dialect, Head, Report};
use crate::{Error, render};

/// Describe the APFS container `reader` is open over, and the volume it reads.
pub fn report(
    mut reader: Reader<File>,
    args: &InspectArgs,
    dialect: Dialect,
) -> Result<Report, Error> {
    super::refuse_groups(
        args,
        "apfs",
        "block groups are how an ext filesystem divides itself, and an APFS container is one \
         pool of blocks its volumes share",
    )?;

    // A scan reads every node of the volume's file-system tree and holds the volume to its
    // own counts. It does not read file data, which APFS carries no checksum over.
    let findings = if args.quick {
        None
    } else {
        Some(reader.scan().to_report())
    };

    let described = Described::of(&mut reader);
    let head = Head {
        family: "apfs",
        // One format with no lineage to spell, so the family is the variant.
        variant: "apfs",
        size: described
            .block_count
            .saturating_mul(u64::from(described.block_size)),
        allocation_unit: u64::from(described.block_size),
        identifier: render::uuid(&described.uuid),
    };
    let body = match dialect {
        Dialect::Table => table(&described),
        Dialect::Json => json(&described),
        Dialect::None => String::new(),
    };
    Ok(Report {
        head,
        findings,
        body,
    })
}

/// Everything the two renderings say, gathered once so they say the same things.
struct Described {
    uuid: [u8; 16],
    block_size: u32,
    block_count: u64,
    /// The transaction of the checkpoint the container is read at.
    xid: u64,
    /// Newer checkpoints opening passed over because a write did not finish them.
    passed_over: usize,
    /// How block zero's copy of the container superblock stands to the live one.
    block_zero: BlockZero,
    features: [(&'static str, u64); 3],
    max_volumes: u32,
    volumes: Vec<VolumeEntry>,
    /// The volumes the container lists whose superblock could not be read.
    unreadable: Vec<UnreadableVolume>,
    /// The slot of the volume the report reads.
    reading: usize,
    /// The snapshot it reads, where it reads one.
    snapshot: Option<Snapshot>,
    /// The snapshots of the volume the report reads, or why its snapshot tree could not be
    /// listed.
    snapshots: Result<Vec<Snapshot>, String>,
}

impl Described {
    fn of(reader: &mut Reader<File>) -> Self {
        let container = reader.container();
        let sb = container.superblock();
        let described = Self {
            uuid: sb.uuid,
            block_size: sb.block_size,
            block_count: sb.block_count,
            xid: container.xid(),
            passed_over: container.passed_over().len(),
            block_zero: container.block_zero(),
            features: [
                ("features", sb.features),
                ("readonly_compatible", sb.readonly_compatible_features),
                ("incompatible", sb.incompatible_features),
            ],
            max_volumes: sb.max_volumes,
            volumes: container.volumes().to_vec(),
            unreadable: container.unreadable_volumes().to_vec(),
            reading: reader.volume().slot,
            snapshot: reader.snapshot().cloned(),
            snapshots: Ok(Vec::new()),
        };
        // Listing what the volume keeps is a read of its snapshot tree, which a damaged one
        // fails. The scan reports that as a finding, and the description says it, so a report
        // made without a scan does not read as a volume with no snapshots.
        let snapshots = reader.snapshots().map_err(|e| e.to_string());
        Self {
            snapshots,
            ..described
        }
    }
}

/// How a volume's names compare: what its incompatible features say about case and
/// normalization.
///
/// The two kinds a format writes are the words `format --volume` takes, from the one table
/// both read. The third, which keeps a name's composition as well as its case, is one this
/// tool reads and does not write, so no option takes its word.
fn names(volume: &VolumeEntry) -> &'static str {
    NameKind::of_volume(&volume.superblock)
        .map_or("case-sensitive, normalization-sensitive", NameKind::as_str)
}

/// A role as the format names it, or its value where the format names none.
fn role(volume: &VolumeEntry) -> String {
    let value = volume.superblock.role;
    role_name(value).map_or_else(|| format!("{value:#x}"), str::to_string)
}

/// A volume's name as a person reads it, or that it has none.
fn volume_name(volume: &VolumeEntry) -> String {
    if volume.name().is_empty() {
        "<none>".to_string()
    } else {
        render::printable(volume.name())
    }
}

/// The description a person reads.
fn table(described: &Described) -> String {
    let mut rows = render::Rows::report();
    let mut line = |k: &str, v: String| rows.row(k, v);

    line("Block count:", described.block_count.to_string());
    line("Block size:", described.block_size.to_string());
    line("Transaction:", described.xid.to_string());
    // Block zero holding an older transaction than the live checkpoint is a container a
    // driver did not unmount cleanly, as a checkpoint a write did not finish is.
    let dirty =
        described.passed_over != 0 || matches!(described.block_zero, BlockZero::Older { .. });
    line("Container state:", render::volume_state(dirty, false));
    line("Block zero:", described.block_zero.to_string());
    for ((_, bits), label) in described.features.iter().zip([
        "Compatible features:",
        "Read-only compatible:",
        "Incompatible features:",
    ]) {
        line(label, format!("{bits:#x}"));
    }
    line(
        "Volumes:",
        format!(
            "{} of {}",
            described.volumes.len() + described.unreadable.len(),
            described.max_volumes
        ),
    );

    // Each slot in its place: one whose superblock could not be read says why, and nothing
    // else is known of it.
    let mut slots: Vec<(usize, Option<&VolumeEntry>)> = described
        .volumes
        .iter()
        .map(|v| (v.slot, Some(v)))
        .chain(described.unreadable.iter().map(|u| (u.slot, None)))
        .collect();
    slots.sort_by_key(|(slot, _)| *slot);
    for (slot, volume) in slots {
        rows.blank();
        let mut line = |k: &str, v: String| rows.row(k, v);
        let Some(volume) = volume else {
            let why = described.unreadable.iter().find(|u| u.slot == slot);
            line(&format!("Volume {slot}:"), "<unreadable>".to_string());
            line(
                "  Read here:",
                format!(
                    "no: {}",
                    why.map(|u| u.error.to_string()).unwrap_or_default()
                ),
            );
            continue;
        };
        let sb = &volume.superblock;
        line(&format!("Volume {}:", volume.slot), volume_name(volume));
        line("  Role:", role(volume));
        // A group is named by the identifier its Data volume carries as its own, so a reader
        // of the report finds the other member by it.
        if sb.volume_group != [0; 16] {
            line("  Volume group:", render::uuid(&sb.volume_group));
        }
        line("  Identifier:", render::uuid(&sb.uuid));
        line("  Names:", names(volume).to_string());
        line(
            "  Features:",
            format!(
                "{:#x}, read-only compatible {:#x}, incompatible {:#x}",
                sb.features, sb.readonly_compatible_features, sb.incompatible_features
            ),
        );
        line(
            "  Holds:",
            format!(
                "{} files, {} directories, {} symbolic links, {} other",
                sb.file_count, sb.directory_count, sb.symlink_count, sb.other_count
            ),
        );
        line("  Snapshots:", sb.snapshot_count.to_string());
        if sb.root_to_xid != 0 {
            line(
                "  Roots from:",
                format!("the snapshot of transaction {}", sb.root_to_xid),
            );
        }
        line("  Blocks allocated:", sb.allocated_blocks.to_string());
        line("  Formatted by:", render::printable(sb.formatted_by.name()));
        line(
            "  Read here:",
            match volume.refusal() {
                None if volume.slot == described.reading => "yes, and reported on".to_string(),
                None => "yes".to_string(),
                Some(why) => format!("no: {why}"),
            },
        );
    }

    let listed: &[Snapshot] = described.snapshots.as_deref().unwrap_or_default();
    if let Err(why) = &described.snapshots {
        rows.blank();
        rows.row("Snapshots:", format!("not listed: {why}"));
    }
    if !listed.is_empty() {
        rows.blank();
        let mut line = |k: &str, v: String| rows.row(k, v);
        for snapshot in listed {
            let mut note = format!(
                "transaction {}, taken {}",
                snapshot.xid,
                render::iso8601(snapshot.created.secs)
            );
            if described
                .snapshot
                .as_ref()
                .is_some_and(|s| s.xid == snapshot.xid)
            {
                note += ", reported on";
            }
            line(
                &format!("Snapshot {}:", render::printable(&snapshot.name)),
                note,
            );
        }
    }
    rows.finish()
}

/// The description a machine reads: the object the envelope splices under `"apfs"`.
fn json(described: &Described) -> String {
    let mut out = String::new();
    let mut apfs = crate::json::Object::new(&mut out);

    let mut c = apfs.obj("container");
    c.u64("block_count", described.block_count);
    c.u64("block_size", u64::from(described.block_size));
    c.u64("transaction", described.xid);
    c.u64("checkpoints_passed_over", described.passed_over as u64);
    c.str("block_zero", &described.block_zero.to_string());
    c.u64("max_volumes", u64::from(described.max_volumes));
    let mut f = c.obj("features");
    for (word, bits) in described.features {
        f.u64(word, bits);
    }
    f.end();
    c.end();

    let mut v = apfs.arr("volumes");
    for volume in &described.volumes {
        let sb = &volume.superblock;
        let mut o = v.obj();
        o.u64("slot", volume.slot as u64);
        o.bytes("name", volume.name());
        o.str("role", &role(volume));
        // A volume in no group, and one rooted at no snapshot, has no field for either, as the
        // table gives no line for either.
        if sb.volume_group != [0; 16] {
            o.str("volume_group", &render::uuid(&sb.volume_group));
        }
        o.str("uuid", &render::uuid(&sb.uuid));
        o.str("names", names(volume));
        o.u64("features", sb.features);
        o.u64(
            "readonly_compatible_features",
            sb.readonly_compatible_features,
        );
        o.u64("incompatible_features", sb.incompatible_features);
        o.u64("files", sb.file_count);
        o.u64("directories", sb.directory_count);
        o.u64("symlinks", sb.symlink_count);
        o.u64("other", sb.other_count);
        o.u64("snapshots", sb.snapshot_count);
        if sb.root_to_xid != 0 {
            o.u64("roots_from_transaction", sb.root_to_xid);
        }
        o.u64("blocks_allocated", sb.allocated_blocks);
        o.bytes("formatted_by", sb.formatted_by.name());
        match volume.refusal() {
            None => o.bool("readable", true),
            Some(why) => {
                o.bool("readable", false);
                o.str("refusal", &why.to_string());
            }
        }
        o.bool("reported_on", volume.slot == described.reading);
        o.end();
    }
    v.end();

    let mut u = apfs.arr("unreadable_volumes");
    for unread in &described.unreadable {
        let mut o = u.obj();
        o.u64("slot", unread.slot as u64);
        o.u64("oid", unread.oid);
        o.str("error", &unread.error.to_string());
        o.end();
    }
    u.end();

    if let Err(why) = &described.snapshots {
        apfs.str("snapshots_not_listed", why);
    }
    let mut s = apfs.arr("snapshots");
    for snapshot in described.snapshots.as_deref().unwrap_or_default() {
        let mut o = s.obj();
        o.bytes("name", &snapshot.name);
        o.u64("transaction", snapshot.xid);
        o.i64("created", snapshot.created.secs);
        if let Some(uuid) = snapshot.uuid {
            o.str("uuid", &render::uuid(&uuid));
        }
        o.bool(
            "reported_on",
            described
                .snapshot
                .as_ref()
                .is_some_and(|r| r.xid == snapshot.xid),
        );
        o.end();
    }
    s.end();

    apfs.end();
    out
}
