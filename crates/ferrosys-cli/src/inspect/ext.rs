//! The ext body of an `inspect` report: what an ext2, ext3, or ext4 superblock says about
//! itself, its feature words, and — with `--groups` — each block group's descriptor.
//!
//! Everything here is ext's own vocabulary. The envelope above this module carries the five
//! fields that mean the same thing for every family and knows none of it.

use std::fmt::Write as _;
use std::fs::File;

use ferrosys::ext::ondisk::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, GroupDescriptor, SuperBlock, unpadded,
};
use ferrosys::ext::{FeatureSet, HashSignedness, HashVersion, Incompat, Reader};

use crate::args::InspectArgs;
use crate::inspect::{Dialect, Head, Report};
use crate::{Error, render};

/// Describe the ext filesystem `reader` is open over.
pub fn report(
    mut reader: Reader<File>,
    args: &InspectArgs,
    dialect: Dialect,
) -> Result<Report, Error> {
    // The descriptors `--groups` lists, and whether the listing is all of them.
    //
    // `group_count()` is the superblock's own claim, derived from two fields a crafted image
    // inflates freely, and it reaches `u32::MAX`. So the vector is neither pre-sized from it
    // — reserving for a hostile count would abort the process before a descriptor is read —
    // nor allowed to grow to it: each descriptor listed costs a tuple here and a line in the
    // rendering, so an unbounded loop turns a file occupying nothing into tens of gigabytes
    // of both. `LISTED_GROUPS` is the ceiling, and a listing that reached it says so rather
    // than reading as the whole table.
    //
    // A descriptor the image cannot hold ends the listing rather than the command: an image
    // truncated part-way through its descriptor table has real groups to show, and a run
    // that aborted would show none of them.
    let (groups, complete) = if args.groups {
        let count = reader.group_count().min(LISTED_GROUPS);
        let mut descriptors = Vec::new();
        for g in 0..count {
            match reader.group_descriptor(g) {
                Ok(d) => descriptors.push((g, d)),
                Err(_) => break,
            }
        }
        let complete = descriptors.len() as u64 == u64::from(reader.group_count());
        (descriptors, complete)
    } else {
        (Vec::new(), true)
    };
    // A scan reads every group descriptor, bitmap, inode, and extent tree in the image,
    // so it is the expensive part and the part that reaches a verdict.
    let findings = if args.quick {
        None
    } else {
        Some(reader.scan().to_report())
    };

    let feature = reader.feature();
    // The ext2/ext3/ext4 family the feature words classify to — the reader's own label for
    // the image.
    let profile = reader.profile();
    // The group count the reader derives, already guarded against a degenerate geometry —
    // and the same bound the descriptor listing above iterated, so the count printed can
    // never disagree with the groups shown.
    let group_count = reader.group_count();
    let sb = reader.superblock();

    let head = Head {
        family: "ext",
        variant: profile.as_str(),
        // The filesystem's own extent. Saturating because both operands come from an image
        // read leniently, so a crafted block count must not wrap into a small number that
        // reads as a plausible size.
        size: sb
            .blocks_count
            .saturating_mul(u64::from(feature.block_size)),
        allocation_unit: u64::from(feature.block_size),
        identifier: render::uuid(&sb.uuid),
    };
    let body = match dialect {
        Dialect::Table => table(sb, feature, group_count, &groups, complete),
        Dialect::Json => json(sb, feature, group_count, &groups, complete),
        Dialect::None => String::new(),
    };
    Ok(Report {
        head,
        findings,
        body,
    })
}

/// The inode-table blocks one group takes: its inodes, rounded up to whole blocks.
fn inode_table_blocks(sb: &SuperBlock, feature: FeatureSet) -> u32 {
    let per_block = feature.inodes_per_block();
    if per_block == 0 {
        return 0;
    }
    sb.inodes_per_group.div_ceil(per_block)
}

/// The groups packed into one flex block group, or 1 when the feature is off.
///
/// `None` when `s_log_groups_per_flex` names a shift a 32-bit group count cannot hold (32
/// or more). The field is a byte read verbatim from the image; under the lenient policy a
/// crafted value reaches here, so the shift is bounded rather than left to overflow.
fn flex_bg_size(sb: &SuperBlock, feature: FeatureSet) -> Option<u32> {
    if feature.incompat.contains(Incompat::FLEX_BG) {
        1u32.checked_shl(u32::from(sb.log_groups_per_flex))
    } else {
        Some(1)
    }
}

/// The name of the directory hash a superblock records, or the raw value when it names
/// no hash this tool knows.
fn hash_name(sb: &SuperBlock) -> String {
    match HashVersion::from_u8(sb.def_hash_version) {
        Some(version) => version.to_string(),
        None => format!("unknown ({})", sb.def_hash_version),
    }
}

/// Whether a name's bytes are hashed as signed or unsigned, as `s_flags` records it.
///
/// The library reads the flag and names the answer, as it does for the sibling hash version
/// above: what this report says an image does is then what a read of that image does, and
/// the word it prints is the word `--hash-signedness` accepts.
fn hash_signedness(sb: &SuperBlock) -> &'static str {
    HashSignedness::from_flags(sb.flags).as_str()
}

/// The descriptor flags one group carries, by name.
fn group_flags(desc: &GroupDescriptor) -> Vec<&'static str> {
    let mut out = Vec::new();
    if desc.flags & BG_INODE_UNINIT != 0 {
        out.push("INODE_UNINIT");
    }
    if desc.flags & BG_BLOCK_UNINIT != 0 {
        out.push("BLOCK_UNINIT");
    }
    if desc.flags & BG_INODE_ZEROED != 0 {
        out.push("ITABLE_ZEROED");
    }
    out
}

/// The most block-group descriptors `--groups` lists.
///
/// A million groups is 128 TiB of filesystem at the default geometry, which is past the
/// largest one this crate plans. What the ceiling is really holding back is the other case:
/// a superblock claiming a group count no image behind it could hold, where each descriptor
/// listed costs a tuple and a rendered line and the total is bounded only by the length the
/// file *claims* — which for a sparse one is unrelated to what it occupies.
const LISTED_GROUPS: u32 = 1 << 20;

/// The description a person reads.
fn table(
    sb: &SuperBlock,
    feature: FeatureSet,
    group_count: u32,
    groups: &[(u32, GroupDescriptor)],
    complete: bool,
) -> String {
    let mut rows = render::Rows::report();
    let mut line = |k: &str, v: String| rows.row(k, v);

    let volume = unpadded(&sb.volume_name);
    line(
        "Filesystem volume name:",
        if volume.is_empty() {
            "<none>".to_string()
        } else {
            render::printable(volume)
        },
    );
    line("Filesystem UUID:", render::uuid(&sb.uuid));
    line("Filesystem magic number:", format!("0x{:X}", sb.magic));
    line("Filesystem features:", feature.names().join(" "));
    // A feature this tool does not know is never passed over in silence: an image
    // carrying one is not an image it understands, whatever the rest of the line says.
    let unknown = [
        ("compat", feature.compat.unknown_bits()),
        ("incompat", feature.incompat.unknown_bits()),
        ("ro_compat", feature.ro_compat.unknown_bits()),
    ];
    if unknown.iter().any(|(_, bits)| *bits != 0) {
        let named: Vec<String> = unknown
            .iter()
            .filter(|(_, bits)| *bits != 0)
            .map(|(word, bits)| format!("{word} {bits:#010x}"))
            .collect();
        line("Unknown feature bits:", named.join(", "));
    }
    line(
        "Filesystem state:",
        if sb.state & 1 != 0 {
            "clean".to_string()
        } else {
            "not clean".to_string()
        },
    );
    line(
        "Errors behavior:",
        match sb.errors {
            1 => "Continue".to_string(),
            2 => "Remount read-only".to_string(),
            3 => "Panic".to_string(),
            other => format!("Unknown ({other})"),
        },
    );
    line(
        "Filesystem OS type:",
        match sb.creator_os {
            0 => "Linux".to_string(),
            other => format!("Unknown ({other})"),
        },
    );
    line("Inode count:", sb.inodes_count.to_string());
    line("Block count:", sb.blocks_count.to_string());
    line("Reserved block count:", sb.r_blocks_count.to_string());
    line("Free blocks:", sb.free_blocks_count.to_string());
    line("Free inodes:", sb.free_inodes_count.to_string());
    line("First block:", sb.first_data_block.to_string());
    line("Block size:", feature.block_size.to_string());
    line("Group descriptor size:", feature.desc_size().to_string());
    line("Reserved GDT blocks:", sb.reserved_gdt_blocks.to_string());
    line("Blocks per group:", sb.blocks_per_group.to_string());
    line("Inodes per group:", sb.inodes_per_group.to_string());
    line(
        "Inode blocks per group:",
        inode_table_blocks(sb, feature).to_string(),
    );
    line(
        "Flex block group size:",
        flex_bg_size(sb, feature).map_or_else(
            || {
                format!(
                    "invalid (s_log_groups_per_flex = {})",
                    sb.log_groups_per_flex
                )
            },
            |n| n.to_string(),
        ),
    );
    line("Block groups:", group_count.to_string());
    line("First inode:", sb.first_ino.to_string());
    line("Inode size:", sb.inode_size.to_string());
    if feature.has_journal() {
        line("Journal inode:", sb.journal_inum.to_string());
    }
    if feature.has_orphan_file() {
        line("Orphan file inode:", sb.orphan_file_inum.to_string());
    }
    line("Default directory hash:", hash_name(sb));
    line("Directory Hash Seed:", render::uuid(&sb.hash_seed));
    line(
        "Directory hash signedness:",
        hash_signedness(sb).to_string(),
    );
    if feature.has_metadata_csum() {
        line(
            "Checksum type:",
            match sb.checksum_type {
                1 => "crc32c".to_string(),
                other => format!("unknown ({other})"),
            },
        );
    }
    if feature.has_csum_seed() {
        line("Checksum seed:", format!("{:#010x}", sb.checksum_seed));
    }
    line(
        "Filesystem created:",
        render::iso8601(i64::from(sb.mkfs_time)),
    );
    line("Last write time:", render::iso8601(i64::from(sb.wtime)));

    // The descriptor listing is a column-headed table of its own rather than a run of
    // label-and-value rows, so it is built as text and carried into the report whole.
    if !groups.is_empty() {
        let mut s = String::from(
            "\nGROUP    BLOCK BITMAP  INODE BITMAP  INODE TABLE  FREE BLOCKS  \
             FREE INODES   DIRS  UNUSED  FLAGS\n",
        );
        for (number, d) in groups {
            let _ = writeln!(
                s,
                "{:<7}{:>14}{:>14}{:>13}{:>13}{:>13}{:>7}{:>8}  {}",
                number,
                d.block_bitmap,
                d.inode_bitmap,
                d.inode_table,
                d.free_blocks_count,
                d.free_inodes_count,
                d.used_dirs_count,
                d.itable_unused,
                group_flags(d).join(" ")
            );
        }
        if !complete {
            let _ = writeln!(
                s,
                "\n{} of {group_count} groups listed; the rest were not read",
                groups.len()
            );
        }
        rows.text(&s);
    }
    rows.finish()
}

/// The description a machine reads: the object the envelope splices under `"ext"`.
fn json(
    sb: &SuperBlock,
    feature: FeatureSet,
    group_count: u32,
    groups: &[(u32, GroupDescriptor)],
    complete: bool,
) -> String {
    let mut out = String::new();
    let mut ext = crate::json::Object::new(&mut out);

    let mut s = ext.obj("superblock");
    s.bytes("volume_name", unpadded(&sb.volume_name));
    s.str("uuid", &render::uuid(&sb.uuid));
    s.u64("magic", u64::from(sb.magic));
    s.bool("clean", sb.state & 1 != 0);
    s.u64("errors_behavior", u64::from(sb.errors));
    s.u64("os", u64::from(sb.creator_os));
    s.u64("block_size", u64::from(feature.block_size));
    s.u64("inode_size", u64::from(sb.inode_size));
    s.u64("group_descriptor_size", u64::from(feature.desc_size()));
    s.u64("blocks", sb.blocks_count);
    s.u64("free_blocks", sb.free_blocks_count);
    s.u64("reserved_blocks", sb.r_blocks_count);
    s.u64("inodes", u64::from(sb.inodes_count));
    s.u64("free_inodes", u64::from(sb.free_inodes_count));
    s.u64("first_data_block", u64::from(sb.first_data_block));
    s.u64("blocks_per_group", u64::from(sb.blocks_per_group));
    s.u64("inodes_per_group", u64::from(sb.inodes_per_group));
    s.u64(
        "inode_blocks_per_group",
        u64::from(inode_table_blocks(sb, feature)),
    );
    s.u64("reserved_gdt_blocks", u64::from(sb.reserved_gdt_blocks));
    match flex_bg_size(sb, feature) {
        Some(n) => s.u64("flex_bg_size", u64::from(n)),
        // A shift a 32-bit count cannot hold: null rather than a fabricated size.
        None => s.raw("flex_bg_size", "null"),
    }
    s.u64("groups", u64::from(group_count));
    s.u64("first_inode", u64::from(sb.first_ino));
    s.u64("journal_inode", u64::from(sb.journal_inum));
    s.u64("orphan_file_inode", u64::from(sb.orphan_file_inum));
    s.str("directory_hash", &hash_name(sb));
    s.str("directory_hash_signedness", hash_signedness(sb));
    s.str("directory_hash_seed", &render::hex(&sb.hash_seed));
    s.u64("checksum_type", u64::from(sb.checksum_type));
    s.u64("checksum_seed", u64::from(sb.checksum_seed));
    // Times are seconds since the epoch: an integer a consumer can compare, rather than a
    // rendering it would have to parse. They are signed because ext4's reach back past it.
    s.i64("created", i64::from(sb.mkfs_time));
    s.i64("written", i64::from(sb.wtime));
    s.i64("last_checked", i64::from(sb.lastcheck));
    s.end();

    let mut f = ext.obj("features");
    f.strings("compat", &feature.compat.names());
    f.strings("incompat", &feature.incompat.names());
    f.strings("ro_compat", &feature.ro_compat.names());
    // Always reported, zero or not: a consumer that reads this document must be able to
    // tell that a filesystem carries a feature this tool did not understand, and an absent
    // field would read as though there were none.
    let mut u = f.obj("unknown");
    u.u64("compat", u64::from(feature.compat.unknown_bits()));
    u.u64("incompat", u64::from(feature.incompat.unknown_bits()));
    u.u64("ro_compat", u64::from(feature.ro_compat.unknown_bits()));
    u.end();
    f.end();

    if !groups.is_empty() {
        // Whether the array below is the whole table. A consumer that read a short listing
        // as the complete one would conclude the filesystem has fewer groups than it claims.
        ext.bool("groups_complete", complete);
        let mut a = ext.arr("groups");
        for (number, d) in groups {
            let mut g = a.obj();
            g.u64("group", u64::from(*number));
            g.u64("block_bitmap", d.block_bitmap);
            g.u64("inode_bitmap", d.inode_bitmap);
            g.u64("inode_table", d.inode_table);
            g.u64("free_blocks", u64::from(d.free_blocks_count));
            g.u64("free_inodes", u64::from(d.free_inodes_count));
            g.u64("directories", u64::from(d.used_dirs_count));
            g.u64("unused_inodes", u64::from(d.itable_unused));
            g.strings("flags", &group_flags(d));
            g.end();
        }
        a.end();
    }

    ext.end();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flex_size_bounds_an_out_of_range_shift() {
        // `s_log_groups_per_flex` is a byte read verbatim; under the lenient policy a
        // crafted value reaches this helper. A shift a 32-bit count cannot hold must
        // yield `None` rather than panic (debug) or wrap (release).
        let feature = FeatureSet::default();
        assert!(
            feature.incompat.contains(Incompat::FLEX_BG),
            "the default profile carries flex_bg"
        );
        let mut sb = SuperBlock::default();
        sb.log_groups_per_flex = 4;
        assert_eq!(flex_bg_size(&sb, feature), Some(16));
        sb.log_groups_per_flex = 31;
        assert_eq!(flex_bg_size(&sb, feature), Some(1 << 31));

        for out_of_range in [32u8, 33, 64, 255] {
            sb.log_groups_per_flex = out_of_range;
            assert_eq!(
                flex_bg_size(&sb, feature),
                None,
                "s_log_groups_per_flex = {out_of_range} overflows a u32 shift"
            );
        }
    }

    #[test]
    fn flex_size_is_one_when_the_feature_is_off() {
        // With flex_bg clear the field is meaningless, so the size is one group and the
        // raw exponent is never shifted.
        let feature = FeatureSet::default()
            .with_feature("flex_bg", false)
            .expect("flex_bg is a known feature");
        let mut sb = SuperBlock::default();
        sb.log_groups_per_flex = 40;
        assert_eq!(flex_bg_size(&sb, feature), Some(1));
    }
}
