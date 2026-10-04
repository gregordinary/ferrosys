//! A filesystem a driver had mounted and did not put down, in every family that records one.
//!
//! Each format keeps the record somewhere of its own — a FAT volume in its boot sector or its
//! table, an exFAT volume in its flags, an ext filesystem in its superblock's state or its
//! journal's recovery flag — and every family says the same thing about it: one finding, at
//! the cosmetic severity, in the same words. The record is the format working rather than
//! failing, so a strict open goes ahead and a verdict drawn at the conformance line passes.
//!
//! The fixtures are images a Linux kernel left behind rather than images with a bit set by
//! hand, because what a kernel actually records is the thing being tested. Each was formatted
//! by the pinned tool for its family, attached to a Linux 7.1 guest, mounted read-write and
//! written to, and the guest was then stopped without unmounting it. Stored without their zero
//! blocks, as [`util::unsparse`] reads them.
#![cfg(all(feature = "ext", feature = "fat", feature = "exfat"))]

mod util;

use std::io::Cursor;

use ferrosys::ext::ondisk::{STATE_CLEAN, STATE_ERRORS};
use ferrosys::fat::ondisk::VOLUME_DIRTY;
use ferrosys::{FindingReport, FsReader, FsTree, ReadPolicy, Severity, TreeError, open};

/// A 4 MiB ext4 at 1 KiB blocks with a journal. The driver wrote six files and a directory,
/// synchronized, then removed one file and wrote another, and the guest stopped.
const EXT4_JOURNAL: &[u8] = include_bytes!("fixtures/ext4-kernel-unclean-journal.sparse");

/// The same filesystem without a journal, written and synchronized, and the guest stopped.
const EXT4: &[u8] = include_bytes!("fixtures/ext4-kernel-unclean.sparse");

/// A 4 MiB ext4 at 1 KiB blocks without a journal, whose file `/seed` had the extent header
/// in its inode zeroed before the guest started. The driver mounted it, met the broken header
/// reading the file, recorded the error, and unmounted the filesystem cleanly.
const EXT4_ERRORS: &[u8] = include_bytes!("fixtures/ext4-kernel-errors.sparse");

/// A 2 MiB FAT12 volume, written and synchronized, and the guest stopped.
const FAT12: &[u8] = include_bytes!("fixtures/fat12-kernel-unclean.sparse");

/// A 16 MiB FAT16 volume, written and synchronized, and the guest stopped.
const FAT16: &[u8] = include_bytes!("fixtures/fat16-kernel-unclean.sparse");

/// A 40 MiB FAT32 volume at one sector a cluster, written and synchronized, and the guest
/// stopped.
const FAT32: &[u8] = include_bytes!("fixtures/fat32-kernel-unclean.sparse");

/// The same FAT32 volume's twin, written and then unmounted cleanly: the control.
const FAT32_UNMOUNTED: &[u8] = include_bytes!("fixtures/fat32-kernel-unmounted.sparse");

/// An 8 MiB exFAT volume, written and synchronized, and the guest stopped.
const EXFAT: &[u8] = include_bytes!("fixtures/exfat-kernel-unclean.sparse");

/// Open `image` strictly, walk its tree, and scan it, in the vocabulary every family shares.
///
/// The open is the default one, so a record of an unclean shutdown that a strict read refused
/// would fail here before anything is asserted.
fn strict_scan(image: &[u8]) -> FindingReport {
    fn walked<T: FsTree>(tree: &mut T) {
        tree.walk_tree::<TreeError, _>(|_, _| Ok(()))
            .expect("the tree walks under the strict policy");
    }
    match open(Cursor::new(image)).expect("a strict open") {
        FsReader::Ext(mut r) => {
            walked(&mut r);
            r.scan().to_report()
        }
        FsReader::Fat(mut r) => {
            walked(&mut r);
            r.scan().to_report()
        }
        FsReader::ExFat(mut r) => {
            walked(&mut r);
            r.scan().to_report()
        }
        other => panic!("{:?} claimed a fixture", other.family()),
    }
}

#[test]
fn every_family_says_a_filesystem_left_mounted_in_the_same_words() {
    let mut said: Vec<(&str, String)> = Vec::new();
    for (label, sparse) in [
        ("ext4 with a journal", EXT4_JOURNAL),
        ("ext4", EXT4),
        ("FAT12", FAT12),
        ("FAT16", FAT16),
        ("FAT32", FAT32),
        ("exFAT", EXFAT),
    ] {
        let report = strict_scan(&util::unsparse(sparse));
        let findings = report.findings();
        assert_eq!(findings.len(), 1, "{label}: {}", report.to_table());
        assert_eq!(findings[0].severity, Severity::Cosmetic, "{label}");
        assert!(
            !report.has_fatal(ReadPolicy::Strict),
            "{label}: a verdict at the conformance line fails it"
        );
        said.push((label, findings[0].detail.clone()));
    }
    let (first, words) = &said[0];
    for (label, detail) in &said {
        assert_eq!(detail, words, "{label} and {first} say it differently");
    }
    // What the record means, not which field held it.
    for field in ["state", "needs_recovery", "VolumeFlags", "entry", "0x"] {
        assert!(!words.contains(field), "the message names {field}: {words}");
    }
}

#[test]
fn a_journal_left_needing_recovery_is_one_unclean_shutdown_and_not_two() {
    // A kernel keeps a journaled filesystem's clean bit set while it is mounted, and records
    // the unclean shutdown as the journal's recovery flag instead. The reader replays the
    // journal, and the scan names the shutdown once.
    let image = util::unsparse(EXT4_JOURNAL);
    let FsReader::Ext(mut reader) = open(Cursor::new(&image)).expect("a strict open") else {
        panic!("the ext family claimed the image")
    };
    assert_eq!(reader.state_on_disk() & STATE_CLEAN, STATE_CLEAN);
    assert!(reader.needs_recovery());
    assert!(
        reader.journal_replay().is_some(),
        "the journal was replayed"
    );
    let report = reader.scan();
    assert_eq!(
        report.anomalies(),
        [ferrosys::ext::ReadError::NotCleanlyUnmounted.anomaly()]
    );

    // Without a journal there is nothing to replay, and the clean bit is what the kernel
    // clears.
    let image = util::unsparse(EXT4);
    let FsReader::Ext(reader) = open(Cursor::new(&image)).expect("a strict open") else {
        panic!("the ext family claimed the image")
    };
    assert_eq!(reader.state_on_disk() & STATE_CLEAN, 0);
    assert!(!reader.needs_recovery());
}

#[test]
fn a_driver_that_found_errors_says_so_beside_the_fault_it_found() {
    let image = util::unsparse(EXT4_ERRORS);
    let FsReader::Ext(mut reader) = open(Cursor::new(&image)).expect("a strict open") else {
        panic!("the ext family claimed the image")
    };
    // Unmounted cleanly, with the error recorded.
    assert_eq!(reader.state_on_disk(), STATE_CLEAN | STATE_ERRORS);
    let report = reader.scan();
    let cosmetic: Vec<_> = report
        .anomalies()
        .iter()
        .filter(|a| a.severity == Severity::Cosmetic)
        .collect();
    assert_eq!(
        cosmetic,
        [&ferrosys::ext::ReadError::ErrorsDetected.anomaly()],
        "the record, and nothing about an unclean shutdown"
    );
    // The fault itself is still there, and reported at its own severity: the record says a
    // driver met one, and the rest of the scan says where.
    assert!(
        report
            .anomalies()
            .iter()
            .any(|a| a.severity == Severity::Structural && a.location.inode == Some(12)),
        "{:?}",
        report.anomalies()
    );
}

#[test]
fn a_fat_volume_left_mounted_by_linux_is_marked_in_its_boot_sector_and_not_its_table() {
    // The specification's record is the clean-shutdown bit of table entry 1. A Linux driver
    // leaves the table alone and sets the boot sector's reserved byte instead, so a reader
    // that looked only at the table would call these volumes clean.
    for (label, sparse) in [("FAT12", FAT12), ("FAT16", FAT16), ("FAT32", FAT32)] {
        let image = util::unsparse(sparse);
        let FsReader::Fat(reader) = open(Cursor::new(&image)).expect("a strict open") else {
            panic!("{label}: the FAT family claimed the image")
        };
        let volume = reader.boot_sector().tail.volume();
        assert_eq!(volume.reserved & VOLUME_DIRTY, VOLUME_DIRTY, "{label}");
        assert!(reader.volume_dirty(), "{label}");
        assert!(!reader.media_failure(), "{label}");
    }

    // The driver marks the primary boot sector and not its backup, so on FAT32 the two copies
    // differ in that bit and nothing else. The bit is a state, reported once above, rather than
    // a backup gone stale.
    let image = util::unsparse(FAT32);
    let backup = 6 * 512;
    let differ: Vec<usize> = (0..512)
        .filter(|&i| image[i] != image[backup + i])
        .collect();
    assert_eq!(
        differ,
        [64 + 1],
        "the copies differ only in the reserved byte"
    );
}

#[test]
fn a_volume_a_linux_driver_unmounted_cleanly_carries_no_record() {
    let image = util::unsparse(FAT32_UNMOUNTED);
    let report = strict_scan(&image);
    assert!(report.is_clean(), "{}", report.to_table());
    let FsReader::Fat(reader) = open(Cursor::new(&image)).expect("a strict open") else {
        panic!("the FAT family claimed the image")
    };
    assert_eq!(reader.boot_sector().tail.volume().reserved, 0);
    assert!(!reader.volume_dirty());
}
