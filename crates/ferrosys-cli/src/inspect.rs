//! `ferrosys inspect`: report what a filesystem says about itself, and whether it is
//! sound.
//!
//! The report is the run's artifact, so it goes to the standard output — as a table a
//! person reads, or as JSON a machine does.
//!
//! The whole image is scanned unless `--quick` says otherwise. Without a scan, an image
//! that is bad would still be *described*, and described accurately: a superblock says
//! what it says whatever the rest of the image holds. The scan is what turns a
//! description into a verdict.

use std::fmt::Write as _;
use std::fs::File;

use ferrosys::ext::ondisk::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, GroupDescriptor, SuperBlock,
};
use ferrosys::ext::{
    FeatureSet, HashSignedness, HashVersion, Incompat, Profile, ReadPolicy, Reader, ScanReport,
};

use crate::args::InspectArgs;
use crate::json::{Obj, hex};
use crate::{Error, emit, from_read, render};

/// Report on the filesystem the arguments name.
pub fn run(args: InspectArgs) -> Result<(), Error> {
    let path = args.image.display().to_string();
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;

    // The read collects rather than aborts: an image is worth describing even when it is
    // malformed, and what to make of the deviations is the verdict's business, not the
    // reader's. `--fail-on` sets where that verdict's line falls.
    let mut reader = Reader::open_at(file, args.offset, ReadPolicy::Lenient).map_err(|source| {
        Error::NotExt {
            path: path.clone(),
            source,
        }
    })?;

    let groups = if args.groups {
        // `group_count()` is derived from superblock fields a crafted image can inflate to
        // `u32::MAX`, so the descriptor vector is never pre-sized from it: reserving
        // capacity for a hostile count would abort the process before a single descriptor
        // is read. The vector grows as real descriptors are found, and `group_descriptor`
        // returns `OutOfRange` once the table runs past the source, ending the loop.
        let count = reader.group_count();
        let mut descriptors = Vec::new();
        for g in 0..count {
            descriptors.push((g, reader.group_descriptor(g).map_err(from_read)?));
        }
        descriptors
    } else {
        Vec::new()
    };
    // A scan reads every group descriptor, bitmap, inode, and extent tree in the image,
    // so it is the expensive part and the part that reaches a verdict.
    let report = if args.quick {
        None
    } else {
        Some(reader.scan())
    };

    // SARIF is a findings dialect: it projects the scan alone, not the superblock
    // description the table and JSON reports lead with. The parser guarantees a scan ran
    // (--sarif rejects --quick), so a `--sarif` report is always present here.
    //
    // The image is located by a URI reference, not by the path as typed: SARIF's
    // `artifactLocation.uri` is a URI, and a path with a space or a `#` in it is not one.
    if args.sarif {
        let sarif = report
            .as_ref()
            .expect("--sarif requires a scan, enforced at parse time")
            .to_sarif(Some(&render::uri_reference(&args.image)));
        emit(sarif.as_bytes())?;
        emit(b"\n")?;
    } else {
        let feature = reader.feature();
        // The ext2/ext3/ext4 family the feature words classify to — the reader's own
        // label for the image, shown beside the words it is derived from.
        let profile = reader.profile();
        // The group count the reader derives, already guarded against a degenerate
        // geometry — and the same bound the descriptor listing above iterated, so the
        // count printed can never disagree with the groups shown.
        let group_count = reader.group_count();
        let sb = reader.superblock();
        let text = if args.json {
            json(sb, feature, profile, group_count, &groups, report.as_ref())
        } else {
            table(sb, feature, profile, group_count, &groups, report.as_ref())
        };
        emit(text.as_bytes())?;
    }

    // The verdict. A scan that was not run reaches none: `--quick` asked for a
    // description, and a description is what it got.
    if let (Some(report), Some(threshold)) = (&report, args.fail_on)
        && let Some(worst) = report.worst_severity()
        && worst >= threshold
    {
        return Err(Error::Verdict {
            count: report.anomalies().len(),
            worst,
        });
    }
    Ok(())
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

/// A NUL-padded on-disk string, as the bytes before the first NUL.
fn cstr(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// The name of the directory hash a superblock records, or the raw value when it names
/// no hash this tool knows.
fn hash_name(sb: &SuperBlock) -> String {
    match HashVersion::from_u8(sb.def_hash_version) {
        Some(HashVersion::Legacy) => "legacy".to_string(),
        Some(HashVersion::HalfMd4) => "half_md4".to_string(),
        Some(HashVersion::Tea) => "tea".to_string(),
        None => format!("unknown ({})", sb.def_hash_version),
    }
}

/// Whether a name's bytes are hashed as signed or unsigned, as `s_flags` records it.
fn hash_signedness(sb: &SuperBlock) -> &'static str {
    if sb.flags & HashSignedness::SIGNED_FLAG != 0 {
        "signed"
    } else {
        "unsigned"
    }
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

/// The report a person reads.
fn table(
    sb: &SuperBlock,
    feature: FeatureSet,
    profile: Profile,
    group_count: u32,
    groups: &[(u32, GroupDescriptor)],
    report: Option<&ScanReport>,
) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| {
        let _ = writeln!(s, "{k:<28}{v}");
    };

    let volume = cstr(&sb.volume_name);
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
    line("Filesystem profile:", profile.name().to_string());
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

    if !groups.is_empty() {
        s.push('\n');
        s.push_str(
            "GROUP    BLOCK BITMAP  INODE BITMAP  INODE TABLE  FREE BLOCKS  \
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
    }

    if let Some(report) = report {
        s.push('\n');
        s.push_str(&report.to_table());
    }
    s
}

/// The report a machine reads.
fn json(
    sb: &SuperBlock,
    feature: FeatureSet,
    profile: Profile,
    group_count: u32,
    groups: &[(u32, GroupDescriptor)],
    report: Option<&ScanReport>,
) -> String {
    let mut out = String::new();
    let mut o = Obj::new(&mut out);
    o.u64("version", 1);

    let mut s = o.obj("superblock");
    s.bytes("volume_name", cstr(&sb.volume_name));
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
    s.str("directory_hash_seed", &hex(&sb.hash_seed));
    s.u64("checksum_type", u64::from(sb.checksum_type));
    s.u64("checksum_seed", u64::from(sb.checksum_seed));
    // Times are seconds since the epoch: an integer a consumer can compare, rather than a
    // rendering it would have to parse. They are signed because ext4's reach back past it.
    s.i64("created", i64::from(sb.mkfs_time));
    s.i64("written", i64::from(sb.wtime));
    s.i64("last_checked", i64::from(sb.lastcheck));
    s.end();

    let mut f = o.obj("features");
    // The ext2/ext3/ext4 family the words below classify to.
    f.str("profile", profile.name());
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
        let mut a = o.arr("groups");
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

    // The scan's own rendering, spliced in as a value: it is already JSON, and escaping a
    // document that is already JSON would turn it into a string of JSON.
    if let Some(report) = report {
        o.raw("scan", &report.to_json());
    }
    o.end();
    out.push('\n');
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
        let mut sb = SuperBlock {
            log_groups_per_flex: 4,
            ..SuperBlock::default()
        };
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
        let feature = FeatureSet {
            incompat: FeatureSet::default().incompat.without(Incompat::FLEX_BG),
            ..FeatureSet::default()
        };
        let sb = SuperBlock {
            log_groups_per_flex: 40,
            ..SuperBlock::default()
        };
        assert_eq!(flex_bg_size(&sb, feature), Some(1));
    }
}
