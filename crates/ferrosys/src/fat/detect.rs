//! Whether an image holds a FAT volume, decided by reading the whole BIOS parameter block
//! and checking it against itself.
//!
//! FAT has no magic. The two bytes at the end of its first sector are the boot signature,
//! which is on every bootable sector ever written — including the master boot record of a
//! disk whose partitions hold something else entirely — so a classifier that trusted it
//! would claim an ext4 disk as FAT. A false positive here is the one detection failure that
//! silently misidentifies a healthy filesystem, and it is worth more care than a magic
//! comparison.
//!
//! So the evidence is the parameter block agreeing with itself: a jump instruction of the
//! right shape, a sector size and a cluster size that are powers of two in the ranges the
//! format defines, a media byte from the defined set, a table count and a reserved count
//! that are possible, a total sector count the source actually holds, and a data region
//! whose size comes out positive. Each is weak; a boot sector that is really an ext4 disk's
//! master boot record fails several.
//!
//! This module is pure apart from reading the one sector it classifies.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use crate::detect::{DetectError, DetectOptions, Filesystem};
use crate::fat::geometry::{FatType, layout_from_boot};
use crate::fat::ondisk::BootSector;
use crate::io::read_exact_at;

/// Whether the FAT family claims the image, and as what.
///
/// `Ok(None)` is "not ours". An I/O failure is the source's rather than the image's and
/// stops detection rather than moving on, since every later probe would fail the same way —
/// but a source too short to hold a boot sector is an answer about the image, so it is
/// "not ours" rather than a failure.
pub(crate) fn claim<R: Read + Seek>(
    mut src: R,
    options: &DetectOptions,
) -> Result<Option<Filesystem>, DetectError> {
    let end = src.seek(SeekFrom::End(0))?;
    let Some(available) = end.checked_sub(options.base) else {
        return Ok(None);
    };
    let sector = match read_exact_at(&mut src, options.base, BootSector::SIZE) {
        Ok(sector) => sector,
        // A source too short to hold a boot sector is an answer about the image rather than
        // a failure of the environment, so the family declines to claim it and detection
        // carries on to the next.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(classify(&sector, available).map(Filesystem::Fat))
}

/// The type a boot sector classifies to, or `None` where the sector is not a FAT volume's.
///
/// The evidence is [`layout_from_boot`], which is the crate's single definition of "these
/// bytes are a FAT volume" and is what the reader opens through as well. Detection needs
/// only the type it arrived at and discards the rest; that the two go through one function
/// is what makes it impossible for detection to claim an image the reader then refuses, or
/// for the reader to open one detection called unrecognized.
///
/// `available` is how many bytes the source holds from the volume's start, which is what
/// makes "the sector count fits" answerable. A volume may be smaller than the region it sits
/// in — a partition is usually larger than its filesystem — so the test is that the count
/// fits, not that it matches.
fn classify(sector: &[u8], available: u64) -> Option<FatType> {
    let boot = BootSector::read_from(sector).ok()?;
    layout_from_boot(&boot, available).ok().map(|l| l.fat_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::geometry::{
        ClusterSize, FatTypeRequest, MAX_CLUSTERS_FAT16, MIN_CLUSTERS_FAT32, PlanRequest,
        ReservedSectors, RootEntries, plan_layout,
    };
    use crate::fat::ondisk::{BootSectorTail, Fat32Params, VolumeInfo};

    /// A boot sector built from a planned layout, which is the only way to get one whose
    /// fields agree with each other.
    fn sector_for(request: &PlanRequest) -> ([u8; BootSector::SIZE], u64) {
        let layout = plan_layout(request).expect("plan");
        let volume = VolumeInfo {
            drive_number: 0x80,
            ext_boot_signature: crate::fat::ondisk::EXTENDED_BOOT_SIGNATURE,
            volume_id: 0x1234_abcd,
            label: VolumeInfo::NO_NAME,
            fs_type: layout.fat_type.label(),
        };
        let tail = match layout.fat32 {
            Some(f) => BootSectorTail::Fat32 {
                params: Fat32Params {
                    fat_sectors: layout.fat_sectors,
                    ext_flags: 0,
                    version: 0,
                    root_cluster: f.root_cluster,
                    fs_info_sector: f.fs_info_sector,
                    backup_boot_sector: f.backup_boot_sector.unwrap_or(0),
                },
                volume,
            },
            None => BootSectorTail::Fat1216 { volume },
        };
        let boot = BootSector {
            jump: [0xEB, 0x3C, 0x90],
            oem_name: *b"ferrosys",
            bytes_per_sector: layout.bytes_per_sector as u16,
            sectors_per_cluster: layout.sectors_per_cluster as u8,
            reserved_sectors: layout.reserved_sectors as u16,
            fats: layout.fats as u8,
            root_entries: layout.root_entries as u16,
            total_sectors_16: u16::try_from(layout.total_sectors).unwrap_or(0),
            media: 0xF8,
            fat_sectors_16: match layout.fat32 {
                Some(_) => 0,
                None => layout.fat_sectors as u16,
            },
            sectors_per_track: 32,
            heads: 2,
            hidden_sectors: 0,
            total_sectors_32: if u16::try_from(layout.total_sectors).is_ok() {
                0
            } else {
                layout.total_sectors
            },
            tail,
        };
        let mut sector = [0u8; BootSector::SIZE];
        boot.write_to(&mut sector).expect("write");
        (sector, layout.total_bytes())
    }

    fn fat12() -> ([u8; BootSector::SIZE], u64) {
        sector_for(
            &PlanRequest::new(4160 * 512)
                .cluster_size(ClusterSize::Sectors(1))
                .reserved_sectors(ReservedSectors::Count(20))
                .root_entries(RootEntries::Count(512)),
        )
    }

    fn fat16() -> ([u8; BootSector::SIZE], u64) {
        sector_for(&PlanRequest::new(64 << 20))
    }

    fn fat32() -> ([u8; BootSector::SIZE], u64) {
        sector_for(&PlanRequest::new(256 << 20).fat_type(FatTypeRequest::Exactly(FatType::Fat32)))
    }

    #[test]
    fn a_planned_volume_of_each_type_is_classified_as_that_type() {
        for (expected, (sector, size)) in [
            (FatType::Fat12, fat12()),
            (FatType::Fat16, fat16()),
            (FatType::Fat32, fat32()),
        ] {
            assert_eq!(
                classify(&sector, size),
                Some(expected),
                "a planned {expected} was not classified as one"
            );
        }
    }

    #[test]
    fn the_boot_signature_alone_is_not_evidence() {
        // The whole reason FAT is classified last and by its whole header: this is what the
        // start of a partitioned disk looks like, and it ends in the same two bytes a FAT
        // volume does.
        let mut mbr = [0u8; BootSector::SIZE];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(classify(&mbr, 1 << 30), None);

        // And a sector that is nothing but the signature and a plausible jump is still not
        // enough, because every other field is zero.
        mbr[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        assert_eq!(classify(&mbr, 1 << 30), None);
    }

    #[test]
    fn every_field_the_classifier_checks_can_refuse_the_image_on_its_own() {
        // Each damage is applied to a volume that classifies cleanly, so a refusal is
        // attributable to the damage rather than to the fixture. A field that could not
        // refuse anything would be a check that does no work.
        let (clean, size) = fat16();
        assert!(classify(&clean, size).is_some());

        /// One field's damage: what it breaks, and how.
        type Damage<'a> = (&'a str, &'a dyn Fn(&mut [u8; BootSector::SIZE]));

        let cases: &[Damage<'_>] = &[
            ("the jump instruction", &|s| s[0] = 0x00),
            ("the jump's trailing no-op", &|s| s[2] = 0x00),
            ("the sector size", &|s| {
                s[11..13].copy_from_slice(&768u16.to_le_bytes())
            }),
            ("a sector size past the format's range", &|s| {
                s[11..13].copy_from_slice(&8192u16.to_le_bytes());
            }),
            ("the cluster size", &|s| s[13] = 3),
            ("a zero cluster size", &|s| s[13] = 0),
            ("the table count", &|s| s[16] = 0),
            ("an implausible table count", &|s| s[16] = 16),
            ("the reserved count", &|s| {
                s[14..16].copy_from_slice(&0u16.to_le_bytes())
            }),
            ("the media byte", &|s| s[21] = 0x42),
            ("the root entry count", &|s| {
                s[17..19].copy_from_slice(&0u16.to_le_bytes())
            }),
            ("the table size", &|s| {
                s[22..24].copy_from_slice(&0u16.to_le_bytes())
            }),
            ("a table that leaves no data region", &|s| {
                s[22..24].copy_from_slice(&u16::MAX.to_le_bytes());
            }),
            ("a table too small to index its own clusters", &|s| {
                s[22..24].copy_from_slice(&1u16.to_le_bytes());
            }),
        ];
        for (what, damage) in cases {
            let mut sector = clean;
            damage(&mut sector);
            assert_eq!(
                classify(&sector, size),
                None,
                "{what} was damaged and the image was still claimed as FAT"
            );
        }
    }

    #[test]
    fn a_volume_larger_than_its_source_is_refused() {
        // A sector count the source cannot hold is the check that stops a plausible-looking
        // header in the middle of some other file from being claimed.
        let (sector, size) = fat16();
        assert!(classify(&sector, size).is_some());
        assert_eq!(classify(&sector, size - 512), None);
        // A source larger than the volume is fine: a partition is usually larger than its
        // filesystem.
        assert!(classify(&sector, size + (1 << 20)).is_some());
    }

    #[test]
    fn an_undersized_fat32_is_classified_as_fat32_and_not_by_its_count() {
        // A FAT32 below its cluster minimum has a count that derives to FAT16, and every
        // mainstream driver reads it as FAT32 all the same, because a zero 16-bit table size
        // is what they test first. Classifying it by the count would name a filesystem
        // nothing sees.
        let (sector, size) = sector_for(
            &PlanRequest::new(8 << 20)
                .cluster_size(ClusterSize::Sectors(1))
                .reserved_sectors(ReservedSectors::Count(32))
                .fat_type(FatTypeRequest::UndersizedFat32),
        );
        let boot = BootSector::read_from(&sector).expect("parse");
        let clusters = (boot.total_sectors()
            - u32::from(boot.reserved_sectors)
            - u32::from(boot.fats) * boot.fat_sectors())
            / u32::from(boot.sectors_per_cluster);
        assert!(
            clusters < crate::fat::MIN_CLUSTERS_FAT32,
            "this fixture is meant to be below the FAT32 minimum"
        );
        assert_eq!(FatType::of_cluster_count(clusters), FatType::Fat16);
        assert_eq!(classify(&sector, size), Some(FatType::Fat32));
    }

    #[test]
    fn the_two_tails_check_each_other() {
        // A FAT32 volume claiming root entries, and a FAT12/16 volume claiming none, are
        // each self-contradictory -- and each is the other shape's strongest check.
        let (mut sector, size) = fat32();
        sector[17..19].copy_from_slice(&512u16.to_le_bytes());
        assert_eq!(classify(&sector, size), None);

        // A FAT32 root cluster that does not exist leaves a driver nowhere to start.
        let (mut sector, size) = fat32();
        sector[44..48].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(classify(&sector, size), None);
        let (mut sector, size) = fat32();
        sector[44..48].copy_from_slice(&50_000_000u32.to_le_bytes());
        assert_eq!(classify(&sector, size), None);
    }

    #[test]
    fn a_source_too_short_to_hold_a_boot_sector_is_not_ours_rather_than_an_error() {
        use std::io::Cursor;
        for len in [0usize, 1, 511] {
            assert_eq!(
                claim(Cursor::new(vec![0u8; len]), &DetectOptions::new()).expect("no i/o error"),
                None
            );
        }
        // And an offset past the end of the source, which is the same answer.
        assert_eq!(
            claim(
                Cursor::new(vec![0u8; 4096]),
                &DetectOptions::new().base(1 << 20)
            )
            .expect("no i/o error"),
            None
        );
    }

    #[test]
    fn a_twelve_or_sixteen_shape_is_never_claimed_as_fat32() {
        // Detection names a family *member*, so naming the wrong one is a false positive of
        // the kind classifying by the whole header is there to prevent. This is the header
        // that could reach it: the 12/16 shape throughout — a non-zero 16-bit table size, a
        // non-zero root entry count — with a cluster count in the band only FAT32 addresses.
        // The count derivation alone would answer FAT32 and the tail says it is not one, so
        // there is no volume here to claim.
        // A sector that classifies cleanly, then rewritten field by field: the size it came
        // with is replaced along with the count, so it is not carried forward.
        let (mut sector, _) = fat16();
        let root_dir_sectors = 512u32 * 32 / 512;
        let overhead = 1 + 512 + root_dir_sectors;
        // The 16-bit table size stays non-zero and grows to hold an entry per cluster at
        // either width, so what refuses this is the derivation and not a table that is too
        // small for it.
        sector[11..13].copy_from_slice(&512u16.to_le_bytes()); // BPB_BytsPerSec
        sector[13] = 1; // BPB_SecPerClus
        sector[14..16].copy_from_slice(&1u16.to_le_bytes()); // BPB_RsvdSecCnt
        sector[16] = 1; // BPB_NumFATs
        sector[17..19].copy_from_slice(&512u16.to_le_bytes()); // BPB_RootEntCnt
        sector[19..21].copy_from_slice(&0u16.to_le_bytes()); // BPB_TotSec16
        sector[22..24].copy_from_slice(&512u16.to_le_bytes()); // BPB_FATSz16

        for (clusters, expected) in [
            (MAX_CLUSTERS_FAT16, Some(FatType::Fat16)),
            (MIN_CLUSTERS_FAT32, None),
        ] {
            let total = overhead + clusters;
            sector[32..36].copy_from_slice(&total.to_le_bytes()); // BPB_TotSec32
            assert_eq!(
                classify(&sector, u64::from(total) * 512),
                expected,
                "{clusters} clusters under a 12/16 tail",
            );
        }
    }

    #[test]
    fn claim_answers_at_the_offset_it_is_given() {
        use std::io::Cursor;
        const BASE: u64 = 1 << 20;
        let (sector, size) = fat16();
        let mut disk = vec![0u8; BASE as usize];
        disk.extend_from_slice(&sector);
        disk.resize(BASE as usize + size as usize, 0);

        assert_eq!(
            claim(Cursor::new(&disk), &DetectOptions::new()).expect("no i/o error"),
            None
        );
        assert_eq!(
            claim(Cursor::new(&disk), &DetectOptions::new().base(BASE)).expect("no i/o error"),
            Some(Filesystem::Fat(FatType::Fat16))
        );
    }
}
