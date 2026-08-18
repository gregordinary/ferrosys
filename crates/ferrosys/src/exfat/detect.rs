//! Whether an image holds an exFAT volume, decided by a magic that is not sufficient on its
//! own and the 53 zero bytes beside it that make it so.
//!
//! exFAT is a tier-1 family: `"EXFAT   "` at offset 3 of sector 0 is a distinctive multi-byte
//! magic at a fixed offset, and a family with one is classified ahead of a family without.
//! What makes this family the exception the tier's rule has to name is that the offset is not
//! exclusively its own — a FAT boot sector keeps `BS_OEMName` there, eight bytes of arbitrary
//! text that no FAT driver reads and no formatter is constrained in. So a FAT volume can
//! spell this magic exactly, and claiming it would mean FAT is never tried, which is the one
//! detection failure ordering exists to prevent.
//!
//! The claim is therefore the magic **and** the 53 bytes at offset 11 that the format
//! requires to be zero — bytes a real FAT parameter block uses for its sector size, its
//! cluster size, and its media descriptor, and cannot leave empty. Both, or the claim is not
//! made. [`MainBootSector::read_from`](crate::exfat::ondisk::MainBootSector::read_from) is
//! where the pair is checked, so it is checked once for the classifier and the reader alike.
//!
//! This module is pure apart from reading the one sector it classifies.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use crate::detect::{DetectError, DetectOptions, Filesystem};
use crate::exfat::geometry::{ExfatLayout, layout_from_boot};
use crate::exfat::ondisk::MainBootSector;
use crate::io::read_exact_at;

/// Whether the exFAT family claims the image.
///
/// `Ok(None)` is "not ours". An I/O failure is the source's rather than the image's and stops
/// detection rather than moving on, since every later probe would fail the same way — but a
/// source too short to hold a boot sector is an answer about the image, so it is "not ours"
/// rather than a failure.
pub(crate) fn claim<R: Read + Seek>(
    mut src: R,
    options: &DetectOptions,
) -> Result<Option<Filesystem>, DetectError> {
    let end = src.seek(SeekFrom::End(0))?;
    let Some(available) = end.checked_sub(options.base) else {
        return Ok(None);
    };
    let sector = match read_exact_at(&mut src, options.base, MainBootSector::SIZE) {
        Ok(sector) => sector,
        // A source too short to hold a boot sector is an answer about the image rather than
        // a failure of the environment, so the family declines to claim it and detection
        // carries on to the next.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(classify(&sector, available).map(|_| Filesystem::ExFat))
}

/// The layout a boot sector classifies to, or `None` where the sector is not an exFAT
/// volume's.
///
/// The evidence is [`layout_from_boot`], which is the crate's single definition of "these
/// bytes are an exFAT volume". Detection needs only that it answered and discards the layout;
/// that the two go through one function is what makes it impossible for detection to claim an
/// image the reader then refuses, or for the reader to open one detection called
/// unrecognized.
///
/// `available` is how many bytes the source holds from the volume's start, which is what
/// makes "the recorded length fits" answerable. A volume may be smaller than the region it
/// sits in — a partition is usually larger than its filesystem — so the test is that the
/// length fits, not that it matches.
fn classify(sector: &[u8], available: u64) -> Option<ExfatLayout> {
    let boot = MainBootSector::read_from(sector).ok()?;
    layout_from_boot(&boot, available).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exfat::geometry::{PlanRequest, plan_layout};
    use crate::exfat::ondisk::{FILE_SYSTEM_NAME, FILE_SYSTEM_REVISION};

    /// A boot sector built from a planned layout, which is the only way to get one whose
    /// fields agree with each other, and how many bytes the volume spans.
    fn sector_for(request: &PlanRequest) -> ([u8; MainBootSector::SIZE], u64) {
        let layout = plan_layout(request).expect("plan");
        let boot = MainBootSector {
            jump_boot: MainBootSector::JUMP_BOOT,
            file_system_name: FILE_SYSTEM_NAME,
            partition_offset: 0,
            volume_length: layout.volume_length,
            fat_offset: layout.fat_offset,
            fat_length: layout.fat_length,
            cluster_heap_offset: layout.cluster_heap_offset,
            cluster_count: layout.cluster_count,
            first_cluster_of_root: layout.first_cluster_of_root,
            volume_serial: 0x1234_5678,
            file_system_revision: FILE_SYSTEM_REVISION,
            volume_flags: 0,
            bytes_per_sector_shift: layout.bytes_per_sector_shift(),
            sectors_per_cluster_shift: layout.sectors_per_cluster_shift(),
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 0,
            boot_code: [0; 390],
        };
        let mut sector = [0u8; MainBootSector::SIZE];
        boot.write_to(&mut sector).expect("write");
        (sector, layout.total_bytes())
    }

    #[test]
    fn a_volume_this_crate_plans_is_one_this_classifier_claims() {
        for request in [
            PlanRequest::new(32 << 20),
            PlanRequest::new(64 << 20).bytes_per_sector(4096),
            PlanRequest::new(512 << 20).cluster_size(crate::exfat::ClusterSize::Bytes(512)),
            PlanRequest::new(8 << 30).cluster_size(crate::exfat::ClusterSize::Bytes(128 << 10)),
        ] {
            let (sector, bytes) = sector_for(&request);
            assert!(
                classify(&sector, bytes).is_some(),
                "the classifier refused a volume the planner produced: {request:?}"
            );
        }
    }

    #[test]
    fn a_fat_boot_sector_spelling_this_magic_is_not_claimed() {
        // The collision the tier's rule has to name, and the reason this family's claim is
        // two conditions rather than one. A FAT volume whose OEM field spells `EXFAT   `
        // classified here would mean FAT is never tried — a healthy filesystem silently
        // misidentified, which is worse than not recognizing it at all.
        let mut fat = [0u8; MainBootSector::SIZE];
        fat[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        fat[3..11].copy_from_slice(&FILE_SYSTEM_NAME);
        fat[11..13].copy_from_slice(&512u16.to_le_bytes()); // BPB_BytsPerSec
        fat[13] = 8; // BPB_SecPerClus
        fat[14..16].copy_from_slice(&32u16.to_le_bytes()); // BPB_RsvdSecCnt
        fat[16] = 2; // BPB_NumFATs
        fat[21] = 0xF8; // BPB_Media
        fat[510..512].copy_from_slice(&0xAA55u16.to_le_bytes());

        assert!(classify(&fat, 512 << 20).is_none());
    }

    #[test]
    fn a_sector_of_zeroes_and_a_sector_of_noise_are_not_claimed() {
        // The 53-byte run is zero in both, so what refuses them is everything else: no
        // magic, no signature, and no geometry that agrees with itself.
        assert!(classify(&[0u8; MainBootSector::SIZE], 512 << 20).is_none());
        let noise: Vec<u8> = (0..MainBootSector::SIZE)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        assert!(classify(&noise, 512 << 20).is_none());
    }

    #[test]
    fn a_volume_larger_than_the_source_holding_it_is_not_claimed() {
        // A volume may be smaller than the region it sits in and never larger, so a recorded
        // length the source cannot hold is a boot sector that does not describe what is
        // there — a truncated image, or a sector that landed somewhere by accident.
        let (sector, bytes) = sector_for(&PlanRequest::new(64 << 20));
        assert!(classify(&sector, bytes).is_some());
        assert!(classify(&sector, bytes - 1).is_none());
        // Larger is fine: a partition is usually larger than its filesystem.
        assert!(classify(&sector, bytes * 4).is_some());
    }

    #[test]
    fn a_short_source_is_not_ours_rather_than_a_failure() {
        // The rule every probe in the ordered list follows: running out of source is an
        // answer about this family, not about every family behind it. Reported as an I/O
        // failure it would end detection, and a one-sector carved fragment is exactly the
        // shape a later probe can still recognize.
        use std::io::Cursor;
        let options = DetectOptions::new();
        assert_eq!(
            claim(Cursor::new(vec![0u8; 100]), &options).expect("not a failure"),
            None
        );
        assert_eq!(
            claim(Cursor::new(Vec::new()), &options).expect("not a failure"),
            None
        );
        // And a base past the end of the source is the same answer.
        assert_eq!(
            claim(
                Cursor::new(vec![0u8; 1024]),
                &DetectOptions::new().base(1 << 30)
            )
            .expect("not a failure"),
            None
        );
    }
}
