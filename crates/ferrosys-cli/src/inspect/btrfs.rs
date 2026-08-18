//! The btrfs body of an `inspect` report: what the superblock says about the volume, what the
//! chunk layer maps it onto, which trees are there, and which subvolumes it holds.
//!
//! Everything here is btrfs's own vocabulary — a logical address, a chunk, a tree root, a
//! subvolume. The envelope above this module carries the five fields that mean the same thing
//! for every family and knows none of it.
//!
//! # Two layers, and the report shows both
//!
//! This is the one family in this tool whose reader stands on something: a logical address
//! space that exists only because a chunk tree maps it onto the device. So the body has a
//! section for each — what the superblock and its copies say, and what the address space
//! underneath is made of — because a volume whose trees all verify and whose chunk map is
//! missing a range is a different report from one where both are sound.
//!
//! # A subvolume is a filesystem inside the filesystem
//!
//! No other family here has anything of the kind, and it is the thing someone points this
//! command at a btrfs to find out: which subvolumes are on it, what they are called, which is
//! the default, and which of them are read-only. So they are a section of their own rather
//! than a count, and each is named by the id a `subvol=` mount option takes.

use std::fs::File;

use ferrosys::btrfs::{Mirror, Reader, Subvolume};

use crate::args::InspectArgs;
use crate::inspect::{Dialect, Head, Report};
use crate::{Error, render};

/// Describe the btrfs filesystem `reader` is open over.
pub fn report(
    mut reader: Reader<File>,
    args: &InspectArgs,
    dialect: Dialect,
) -> Result<Report, Error> {
    // A block group is ext's unit of self-description. btrfs has block *groups* of its own and
    // they are a different thing entirely — an allocation profile over a chunk, not a region of
    // the device that describes itself — so answering `--groups` with them would answer a
    // different question under the same word. Refused rather than passed over, which is the
    // answer both other families give.
    if args.groups {
        return Err(Error::NotForFamily {
            option: "--groups",
            family: "btrfs",
            reason: "block groups are how an ext filesystem divides itself, and a btrfs is \
                     divided by a chunk tree that maps a logical address space onto the device",
        });
    }

    // A scan reads every tree in the filesystem and verifies every metadata block it reaches.
    // It does not read file data: the checksums covering that are per sector over the whole
    // volume, which is a different order of cost and a different question.
    let findings = if args.quick {
        None
    } else {
        Some(reader.scan().to_report())
    };

    let described = Described::of(&mut reader);
    let head = Head {
        family: "btrfs",
        // The family is the finest answer there is: one format with no lineage to spell and no
        // revisions to tell apart, so the family is the variant.
        variant: "btrfs",
        size: described.total_bytes,
        // A sector, which is what this format addresses data in and what one data checksum
        // covers. Its tree blocks are a different size and the body says so.
        allocation_unit: u64::from(described.sector_size),
        identifier: render::uuid(&described.fsid),
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

/// One tree of the filesystem: the name the format gives it and where its root is.
struct TreeLine {
    /// The library's own name for the tree, so a listing and a finding about the same tree call
    /// it the same thing.
    name: String,
    logical: u64,
    level: u8,
}

/// Everything the two renderings say, gathered once so they say the same things.
struct Described {
    fsid: [u8; 16],
    /// The identity that survives the filesystem id being changed, which is what a volume with
    /// the `METADATA_UUID` feature carries and what every tree block is stamped with.
    metadata_id: [u8; 16],
    label: Vec<u8>,
    total_bytes: u64,
    bytes_used: u64,
    sector_size: u32,
    node_size: u32,
    generation: u64,
    /// Every feature the three words advertise, in the words `format -O` reads.
    ///
    /// One list rather than three, for the reason `-O` takes one list: which word a feature
    /// lives in is a property of the feature, and a caller reading a name off this report and
    /// typing it into a format never has to know which.
    features: Vec<&'static str>,
    /// The bits of each word that name no feature this tool knows, in the order the
    /// superblock records the words.
    unknown_features: [(&'static str, u64); 3],
    /// Which of the format's three superblock locations hold what, in the order the format
    /// places them.
    mirrors: Vec<&'static str>,

    /// How many ranges the chunk tree maps, and how much of the address space they cover.
    chunks: usize,
    mapped_bytes: u64,
    trees: Vec<TreeLine>,
    subvolumes: Vec<Subvolume>,
    default_subvolume: u64,
}

impl Described {
    fn of(reader: &mut Reader<File>) -> Self {
        let volume = reader.volume();
        let sb = volume.superblock();
        let map = volume.chunk_map();
        let mirrors = volume
            .mirrors()
            .iter()
            .map(|state| match state {
                Mirror::Present { .. } => "present",
                // Not a fault: the rule the format follows is every copy the device has room
                // for, so a small filesystem has one or two and that is what it should have.
                Mirror::OutsideDevice => "outside the device",
                // A fault, and about the image rather than the filesystem: the device says it
                // is longer than the file in hand.
                Mirror::Truncated => "past the end of the image",
                Mirror::Absent => "absent",
                Mirror::Damaged => "damaged",
                Mirror::Misplaced { .. } => "misplaced",
                // A state a newer library reports and this tool has no word for. Saying so is
                // honest; picking the nearest word would not be.
                _ => "unrecognized",
            })
            .collect();
        // In the order the superblock records the three words, so a reader holding this
        // report beside a dump of the same filesystem meets them in the same order.
        let mut features = sb.compat_flags.names();
        features.extend(sb.compat_ro_flags.names());
        features.extend(sb.incompat_flags.names());
        let described = Self {
            fsid: sb.fsid,
            metadata_id: sb.metadata_id(),
            label: sb.label_bytes().to_vec(),
            total_bytes: sb.total_bytes,
            bytes_used: sb.bytes_used,
            sector_size: sb.sectorsize,
            node_size: sb.nodesize,
            generation: sb.generation,
            features,
            unknown_features: [
                ("compat", sb.compat_flags.unknown_bits()),
                ("compat_ro", sb.compat_ro_flags.unknown_bits()),
                ("incompat", sb.incompat_flags.unknown_bits()),
            ],
            mirrors,
            chunks: map.len(),
            // Summed rather than taken from a field, there being none: the chunk tree records
            // ranges and how much of the address space they cover is what they add up to.
            mapped_bytes: map.chunks().iter().map(|chunk| chunk.length).sum(),
            trees: Vec::new(),
            subvolumes: reader.subvolumes().to_vec(),
            default_subvolume: reader.default_subvolume(),
        };
        Self {
            trees: tree_lines(reader),
            ..described
        }
    }
}

/// Every tree the filesystem records a root for, named as the format names it.
///
/// Read through the volume rather than assumed from the feature words: which trees exist
/// depends on which features are on, and a report that listed the ones a default filesystem has
/// would name trees that are not there.
fn tree_lines(reader: &mut Reader<File>) -> Vec<TreeLine> {
    let Ok(roots) = reader.volume_mut().tree_roots() else {
        // Reaching the roots is what opening the filesystem already did, so a failure here is a
        // filesystem that changed under the command rather than one it never read. The scan is
        // where that is reported; the description says what it has.
        return Vec::new();
    };
    roots
        .iter()
        .map(|root| TreeLine {
            name: ferrosys::btrfs::tree_name(root.objectid),
            logical: root.bytenr,
            level: root.level,
        })
        .collect()
}

/// The label as a person reads it, or that the filesystem carries none.
fn label_text(label: &[u8]) -> String {
    if label.is_empty() {
        "<none>".to_string()
    } else {
        render::printable(label)
    }
}

/// How a subvolume is named in a report: by its own name where it has one, and as the top-level
/// tree where it does not.
///
/// The top-level tree is a subvolume like the others and is the one with no name, because no
/// directory entry names it — it is what a mount reaches with no `subvol=` at all.
fn subvolume_name(name: &[u8]) -> String {
    if name.is_empty() {
        "<top-level>".to_string()
    } else {
        render::printable(name)
    }
}

/// The description a person reads.
fn table(described: &Described) -> String {
    let mut rows = render::Rows::report();
    let mut line = |k: &str, v: String| rows.row(k, v);

    line("Label:", label_text(&described.label));
    line("Metadata identifier:", render::uuid(&described.metadata_id));
    line("Generation:", described.generation.to_string());
    line("Bytes used:", described.bytes_used.to_string());
    line("Sector size:", described.sector_size.to_string());
    line("Tree block size:", described.node_size.to_string());
    // The words `format -O` reads, so a feature named here is one a caller can ask for or
    // clear without translating it first.
    line("Filesystem features:", described.features.join(" "));
    // A feature this tool does not know is never passed over in silence: an image carrying
    // one is not an image it understands, whatever the rest of the line says.
    if described
        .unknown_features
        .iter()
        .any(|(_, bits)| *bits != 0)
    {
        let named: Vec<String> = described
            .unknown_features
            .iter()
            .filter(|(_, bits)| *bits != 0)
            .map(|(word, bits)| format!("{word} {bits:#018x}"))
            .collect();
        line("Unknown feature bits:", named.join(", "));
    }
    line("Superblock copies:", described.mirrors.join(", "));

    // The address space, which is the layer the trees stand on and the one no other family in
    // this tool has.
    rows.blank();
    let mut line = |k: &str, v: String| rows.row(k, v);
    line("Mapped chunks:", described.chunks.to_string());
    line("Mapped bytes:", described.mapped_bytes.to_string());

    rows.blank();
    let mut line = |k: &str, v: String| rows.row(k, v);
    for tree in &described.trees {
        line(
            &format!("{} at:", tree.name),
            format!("{} (level {})", tree.logical, tree.level),
        );
    }

    rows.blank();
    let mut line = |k: &str, v: String| rows.row(k, v);
    for subvolume in &described.subvolumes {
        let mut note = format!("id {}", subvolume.id);
        if subvolume.read_only {
            note += ", read-only";
        }
        if subvolume.id == described.default_subvolume {
            note += ", default";
        }
        line(
            &format!("Subvolume {}:", subvolume_name(&subvolume.name)),
            note,
        );
    }
    rows.finish()
}

/// The description a machine reads: the object the envelope splices under `"btrfs"`.
fn json(described: &Described) -> String {
    let mut out = String::new();
    let mut btrfs = crate::json::Object::new(&mut out);

    let mut s = btrfs.obj("superblock");
    s.bytes("label", &described.label);
    s.str("metadata_uuid", &render::uuid(&described.metadata_id));
    s.u64("generation", described.generation);
    s.u64("total_bytes", described.total_bytes);
    s.u64("bytes_used", described.bytes_used);
    s.u64("sector_size", u64::from(described.sector_size));
    s.u64("node_size", u64::from(described.node_size));
    s.end();

    let mut f = btrfs.obj("features");
    f.strings("named", &described.features);
    // Always reported, zero or not: a consumer that reads this document must be able to tell
    // that a filesystem carries a feature this tool did not understand, and an absent field
    // would read as though there were none.
    let mut u = f.obj("unknown");
    for (word, bits) in described.unknown_features {
        u.u64(word, bits);
    }
    u.end();
    f.end();

    // The copies as a list rather than a count, because which one is damaged is the fact a
    // caller acts on and a count of intact ones is not. In the order the format places them, so
    // an index into this list is a location on the device.
    btrfs.strings("superblock_copies", &described.mirrors);

    let mut c = btrfs.obj("chunks");
    c.u64("mapped_ranges", described.chunks as u64);
    c.u64("mapped_bytes", described.mapped_bytes);
    c.end();

    let mut t = btrfs.arr("trees");
    for tree in &described.trees {
        let mut o = t.obj();
        o.str("name", &tree.name);
        o.u64("logical", tree.logical);
        o.u64("level", u64::from(tree.level));
        o.end();
    }
    t.end();

    let mut v = btrfs.arr("subvolumes");
    for subvolume in &described.subvolumes {
        let mut o = v.obj();
        o.u64("id", subvolume.id);
        o.bytes("name", &subvolume.name);
        o.bool("read_only", subvolume.read_only);
        o.bool("default", subvolume.id == described.default_subvolume);
        o.str("uuid", &render::uuid(&subvolume.uuid));
        o.end();
    }
    v.end();

    btrfs.end();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filesystem_with_no_label_says_so_rather_than_showing_nothing() {
        // An empty label field and a label of spaces are different things, and neither is an
        // absent report line: a report that printed the empty string would read as a label
        // nobody could see rather than as one nobody set.
        assert_eq!(label_text(b""), "<none>");
        assert_eq!(label_text(b"root"), "root");
    }

    #[test]
    fn the_top_level_tree_is_named_rather_than_left_blank() {
        // It is a subvolume like the others and it is the one no directory entry names, so the
        // report says what it is instead of showing an empty cell.
        assert_eq!(subvolume_name(b""), "<top-level>");
        assert_eq!(subvolume_name(b"@home"), "@home");
    }
}
