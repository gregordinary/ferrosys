//! The FAT body of an `inspect` report: what a FAT12, FAT16, or FAT32 parameter block says
//! about itself, and the two structures only FAT32 has.
//!
//! Everything here is FAT's own vocabulary — a boot sector, a reserved region, a file
//! allocation table, a cluster heap. The envelope above this module carries the five fields
//! that mean the same thing for every family and knows none of it.
//!
//! # The type is derived, and the volume's own claim about it is reported beside it
//!
//! Nothing in a FAT image records which of the three types it is: every driver counts the
//! clusters and compares against two thresholds. The type string in the boot sector is the
//! formatter stating its own conclusion, and nothing keeps it in step with the geometry — so
//! it is reported as what it is, a claim, next to the count the envelope's variant came
//! from. An image whose string disagrees with its geometry is read by its geometry, and this
//! is where that disagreement is visible.

use std::fs::File;

use ferrosys::fat::ondisk::{
    BootSector, BootSectorTail, EXTENDED_BOOT_SIGNATURE, FsInfo, unpadded,
};
use ferrosys::fat::{FatLayout, ReadError, Reader};

use crate::args::InspectArgs;
use crate::inspect::{Dialect, Head, Report};
use crate::{Error, render};

/// Describe the FAT volume `reader` is open over.
pub fn report(
    mut reader: Reader<File>,
    args: &InspectArgs,
    dialect: Dialect,
) -> Result<Report, Error> {
    // A block group is ext's unit of self-description and a FAT volume has nothing of the
    // kind, so the option is refused rather than passed over. A report that quietly omitted
    // the section would read as a volume with no groups in it, which is a different claim
    // from the question not applying.
    if args.groups {
        return Err(Error::NotForFamily {
            option: "--groups",
            family: "fat",
            reason: "block groups are how an ext filesystem divides itself, and a FAT volume \
                     has one flat cluster heap",
        });
    }

    // A scan follows every chain in the volume, compares the allocation tables against each
    // other, and reads every directory, so it is the expensive part and the part that
    // reaches a verdict.
    let findings = if args.quick {
        None
    } else {
        Some(reader.scan().to_report())
    };

    // Both of these read the volume, and both are read leniently like everything else here:
    // a volume whose root directory or information sector cannot be read is still worth
    // describing, and the scan above has already recorded the fault as a finding. Reporting
    // the failure in place says which field could not be read without refusing the report.
    let label = reader.volume_label();
    let info = reader.info_sector();

    let layout = *reader.layout();
    let boot = *reader.boot_sector();
    let volume = match boot.tail {
        BootSectorTail::Fat1216 { volume } | BootSectorTail::Fat32 { volume, .. } => volume,
    };

    let head = Head {
        family: "fat",
        variant: layout.fat_type.as_str(),
        size: layout.total_bytes(),
        allocation_unit: u64::from(layout.bytes_per_cluster()),
        // A FAT volume's identity is its serial number, written the way every tool that
        // shows one writes it: two hex groups of four digits.
        identifier: render::volume_serial(volume.volume_id),
    };
    let body = match dialect {
        Dialect::Table => table(&layout, &boot, label.as_ref(), info.as_ref()),
        Dialect::Json => json(&layout, &boot, label.as_ref(), info.as_ref()),
        Dialect::None => String::new(),
    };
    Ok(Report {
        head,
        findings,
        body,
    })
}

/// The volume label as a person reads it.
///
/// The three answers are distinct and are kept apart: the volume records no label, it
/// records one, and the bytes that would carry it could not be read. Collapsing the third
/// into the first would report a damaged volume as an unnamed one.
fn label_text(label: Result<&Option<Vec<u8>>, &ReadError>) -> String {
    match label {
        Ok(Some(bytes)) => render::printable(bytes),
        Ok(None) => "<none>".to_string(),
        Err(_) => "<unreadable>".to_string(),
    }
}

/// How the file allocation tables are kept, as `BPB_ExtFlags` records it.
///
/// Zero — every copy identical — is what this crate writes and what a checker compares them
/// under. Bit 7 set means only the copy numbered in the low four bits is live, and the
/// others are stale by design rather than by damage.
fn mirroring(ext_flags: u16) -> String {
    if ext_flags & 0x80 == 0 {
        "all copies kept identical".to_string()
    } else {
        format!("copy {} only", ext_flags & 0x0f)
    }
}

/// The description a person reads.
fn table(
    layout: &FatLayout,
    boot: &BootSector,
    label: Result<&Option<Vec<u8>>, &ReadError>,
    info: Result<&Option<FsInfo>, &ReadError>,
) -> String {
    let mut rows = render::Rows::report();
    let mut line = |k: &str, v: String| rows.row(k, v);

    let volume = match boot.tail {
        BootSectorTail::Fat1216 { volume } | BootSectorTail::Fat32 { volume, .. } => volume,
    };

    line("Volume label:", label_text(label));
    line(
        "Volume serial number:",
        render::volume_serial(volume.volume_id),
    );
    // The volume's own claim about its type, beside the count the envelope's variant was
    // derived from. No driver reads it, and a disagreement is visible here alone.
    line("Type string:", render::printable(unpadded(&volume.fs_type)));
    if volume.ext_boot_signature != EXTENDED_BOOT_SIGNATURE {
        // Without it the label, the serial number, and the type string are not fields at
        // all: they are whatever bytes happen to sit there. Legal, and ancient.
        line(
            "Extended boot record:",
            format!(
                "absent (0x{:02x}) — the label, serial number, and type string above are \
                 not recorded",
                volume.ext_boot_signature
            ),
        );
    }
    line("OEM name:", render::printable(unpadded(&boot.oem_name)));
    line("Media descriptor:", format!("0x{:02x}", boot.media));
    line("Bytes per sector:", layout.bytes_per_sector.to_string());
    line(
        "Sectors per cluster:",
        layout.sectors_per_cluster.to_string(),
    );
    line("Bytes per cluster:", layout.bytes_per_cluster().to_string());
    line("Reserved sectors:", layout.reserved_sectors.to_string());
    line("Allocation tables:", layout.fats.to_string());
    line("Sectors per table:", layout.fat_sectors.to_string());
    line(
        "Table entry bits:",
        layout.fat_type.entry_bits().to_string(),
    );
    line("Root directory entries:", layout.root_entries.to_string());
    line(
        "Root directory sectors:",
        layout.root_dir_sectors.to_string(),
    );
    line("First data sector:", layout.first_data_sector.to_string());
    line("Total sectors:", layout.total_sectors.to_string());
    line("Clusters:", layout.clusters.to_string());
    line("Hidden sectors:", boot.hidden_sectors.to_string());

    // The four structures only FAT32 has: a root that is a chain rather than a region, the
    // free-space hint, and the two backups.
    if let (Some(fat32), BootSectorTail::Fat32 { params, .. }) = (layout.fat32, boot.tail) {
        rows.blank();
        let mut line = |k: &str, v: String| rows.row(k, v);
        line("Root directory cluster:", fat32.root_cluster.to_string());
        line("Information sector:", fat32.fs_info_sector.to_string());
        line(
            "Backup boot sector:",
            sector_or_none(fat32.backup_boot_sector),
        );
        line(
            "Backup information sector:",
            sector_or_none(fat32.backup_fs_info_sector),
        );
        line("Table mirroring:", mirroring(params.ext_flags));
        line("Filesystem version:", params.version.to_string());
        // Both counts in the information sector are hints. A driver may update them, ignore
        // them, or leave them stale, so they are labelled as hints rather than reported as
        // the volume's free space — which the allocation table is the authority on.
        match info {
            Ok(Some(info)) => {
                line("Free clusters (hint):", unrecorded_or(info.free_clusters));
                line(
                    "Next free cluster (hint):",
                    unrecorded_or(info.next_free_cluster),
                );
            }
            Ok(None) => {}
            Err(_) => line("Free-space hints:", "<unreadable>".to_string()),
        }
    }
    rows.finish()
}

/// A reserved sector a structure sits in, or `<none>` where the reserved region had no room
/// for it. A volume without a backup boot sector is legal, so this is a shape rather than a
/// fault.
fn sector_or_none(sector: Option<u16>) -> String {
    sector.map_or_else(|| "<none>".to_string(), |n| n.to_string())
}

/// A hint the information sector carries, or `<unrecorded>` where it holds the sentinel that
/// says it does not know — which is a different answer from zero.
fn unrecorded_or(hint: Option<u32>) -> String {
    hint.map_or_else(|| "<unrecorded>".to_string(), |n| n.to_string())
}

/// The description a machine reads: the object the envelope splices under `"fat"`.
fn json(
    layout: &FatLayout,
    boot: &BootSector,
    label: Result<&Option<Vec<u8>>, &ReadError>,
    info: Result<&Option<FsInfo>, &ReadError>,
) -> String {
    let volume = match boot.tail {
        BootSectorTail::Fat1216 { volume } | BootSectorTail::Fat32 { volume, .. } => volume,
    };

    let mut out = String::new();
    let mut fat = crate::json::Object::new(&mut out);

    let mut b = fat.obj("boot");
    match label {
        Ok(Some(bytes)) => b.bytes("volume_label", bytes),
        // No label and an unreadable one are both `null` here and told apart by
        // `volume_label_readable` beside them, so a consumer that only wants the name reads
        // one field and one that must not confuse the two reads both.
        Ok(None) | Err(_) => b.raw("volume_label", "null"),
    }
    b.bool("volume_label_readable", label.is_ok());
    b.u64("volume_serial_number", u64::from(volume.volume_id));
    b.str("volume_serial", &render::volume_serial(volume.volume_id));
    b.bytes("type_string", unpadded(&volume.fs_type));
    b.bool(
        "extended_boot_record",
        volume.ext_boot_signature == EXTENDED_BOOT_SIGNATURE,
    );
    b.u64("drive_number", u64::from(volume.drive_number));
    b.bytes("oem_name", unpadded(&boot.oem_name));
    b.u64("media", u64::from(boot.media));
    b.u64("bytes_per_sector", u64::from(layout.bytes_per_sector));
    b.u64("sectors_per_cluster", u64::from(layout.sectors_per_cluster));
    b.u64("bytes_per_cluster", u64::from(layout.bytes_per_cluster()));
    b.u64("reserved_sectors", u64::from(layout.reserved_sectors));
    b.u64("fats", u64::from(layout.fats));
    b.u64("fat_sectors", u64::from(layout.fat_sectors));
    b.u64("fat_entry_bits", u64::from(layout.fat_type.entry_bits()));
    b.u64("root_entries", u64::from(layout.root_entries));
    b.u64("root_dir_sectors", u64::from(layout.root_dir_sectors));
    b.u64("first_data_sector", u64::from(layout.first_data_sector));
    b.u64("total_sectors", u64::from(layout.total_sectors));
    b.u64("clusters", u64::from(layout.clusters));
    b.u64("hidden_sectors", u64::from(boot.hidden_sectors));
    b.end();

    // Present on exactly the FAT32 volumes, null on the other two — the shape of the volume
    // rather than a field that happens to be missing.
    match (layout.fat32, boot.tail) {
        (Some(f), BootSectorTail::Fat32 { params, .. }) => {
            let mut o = fat.obj("fat32");
            o.u64("root_cluster", u64::from(f.root_cluster));
            o.u64("fs_info_sector", u64::from(f.fs_info_sector));
            match f.backup_boot_sector {
                Some(n) => o.u64("backup_boot_sector", u64::from(n)),
                // Legal: a reserved region with no room for one. Null rather than zero,
                // which is a sector number.
                None => o.raw("backup_boot_sector", "null"),
            }
            match f.backup_fs_info_sector {
                Some(n) => o.u64("backup_fs_info_sector", u64::from(n)),
                None => o.raw("backup_fs_info_sector", "null"),
            }
            o.u64("ext_flags", u64::from(params.ext_flags));
            o.bool("mirrored", params.ext_flags & 0x80 == 0);
            o.u64("version", u64::from(params.version));
            o.end();
        }
        _ => fat.raw("fat32", "null"),
    }

    // Both counts are hints a driver is under no obligation to keep current, and the field
    // says so by name. Null where there is no such sector or it could not be read, told
    // apart by `readable` inside it.
    match info {
        Ok(Some(info)) => {
            let mut o = fat.obj("fsinfo");
            o.bool("readable", true);
            match info.free_clusters {
                Some(n) => o.u64("free_clusters_hint", u64::from(n)),
                None => o.raw("free_clusters_hint", "null"),
            }
            match info.next_free_cluster {
                Some(n) => o.u64("next_free_cluster_hint", u64::from(n)),
                None => o.raw("next_free_cluster_hint", "null"),
            }
            o.end();
        }
        Ok(None) => fat.raw("fsinfo", "null"),
        Err(_) => {
            let mut o = fat.obj("fsinfo");
            o.bool("readable", false);
            o.end();
        }
    }

    fat.end();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirroring_names_which_copies_are_live() {
        // Zero is what this crate writes and what a checker compares the copies under.
        assert_eq!(mirroring(0), "all copies kept identical");
        // Bit 7 set means one copy is live and the rest are stale by design. The low four
        // bits say which, so the report names it rather than saying only that they differ.
        assert_eq!(mirroring(0x80), "copy 0 only");
        assert_eq!(mirroring(0x81), "copy 1 only");
        assert_eq!(mirroring(0x8f), "copy 15 only");
    }

    #[test]
    fn a_label_that_could_not_be_read_is_not_a_volume_without_one() {
        // The three answers are distinct, and the middle one is the whole reason this is not
        // an `Option`: a volume whose root directory is damaged has not told us it is
        // unnamed.
        let named = Some(b"ESP".to_vec());
        assert_eq!(label_text(Ok(&named)), "ESP");
        assert_eq!(label_text(Ok(&None)), "<none>");
        // Taken from the library rather than spelled here: a real failure proves the reader
        // still reports one, where a literal would prove only that this test can write it.
        let unreadable = ReadError::from(std::io::Error::other("the root directory is gone"));
        assert_eq!(label_text(Err(&unreadable)), "<unreadable>");
    }
}
