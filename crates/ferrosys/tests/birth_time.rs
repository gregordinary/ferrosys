//! The gate for a birth time: one a source states is written by every family and read back from
//! it, and one no source states reads back as the modification time.
#![cfg(all(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]

use std::collections::BTreeMap;
use std::io::Cursor;

use ferrosys::{
    AcceptedLoss, FsReader, FsTree, Metadata, Source, Synthesis, Timestamp, TreeBuilder, TreeError,
    open,
};

/// The instant every image is formatted at.
const FORMATTED: Timestamp = Timestamp::from_secs(1_700_000_100);

/// The modification time every entry states: an even second, which every family holds whole.
const MODIFIED: Timestamp = Timestamp::from_secs(1_700_000_000);

/// A birth time every family holds whole: an odd second and a fraction in hundredths, which the
/// creation field of a FAT or exFAT entry keeps and its write field would not.
const BORN: Timestamp = Timestamp {
    secs: 1_600_000_001,
    nanos: 230_000_000,
};

/// A directory and a file in it, each stating `born` as its birth time where it is given.
fn tree(born: Option<Timestamp>) -> TreeBuilder {
    let meta = |mode| {
        let meta = Metadata::new(mode, MODIFIED);
        born.map_or(meta, |born| meta.with_birth_time(born))
    };
    TreeBuilder::new().directory("/docs", meta(0o755)).file(
        "/docs/note.txt",
        "a note\n",
        meta(0o644),
    )
}

/// The image every family writes of `source`, by name.
fn images(source: impl Fn() -> TreeBuilder) -> Vec<(&'static str, Vec<u8>)> {
    let ext = ferrosys::ext::FormatOptions::new([0x33; 16], FORMATTED, [0; 16]);
    let mut fat = ferrosys::fat::FormatOptions::new(0x1234_5678, FORMATTED);
    fat.accepted_loss = AcceptedLoss::ALL;
    let mut exfat = ferrosys::exfat::FormatOptions::new(0x1234_5678);
    exfat.accepted_loss = AcceptedLoss::ALL;
    let btrfs = ferrosys::btrfs::FormatOptions::new([0x44; 16], FORMATTED)
        .chunk_tree_uuid([0x45; 16])
        .device_uuid([0x46; 16])
        .subvolume_uuid([0x47; 16]);
    let apfs = ferrosys::apfs::FormatOptions::new(
        [0x11; 16],
        FORMATTED,
        ferrosys::apfs::VolumeRequest::new(
            ferrosys::apfs::VolumeName::new("Born").expect("a name"),
            [0x22; 16],
        ),
    );
    vec![
        (
            "ext",
            ferrosys::ext::format(source(), 32 << 20, ext)
                .expect("ext formats it")
                .into_bytes(),
        ),
        (
            "FAT",
            ferrosys::fat::format(source(), 32 << 20, fat)
                .expect("FAT formats it")
                .into_bytes(),
        ),
        (
            "exFAT",
            ferrosys::exfat::format(source(), 32 << 20, exfat)
                .expect("exFAT formats it")
                .into_bytes(),
        ),
        (
            "btrfs",
            ferrosys::btrfs::format(source(), 256 << 20, btrfs)
                .expect("btrfs formats it")
                .into_bytes(),
        ),
        (
            "APFS",
            ferrosys::apfs::format(source(), 64 << 20, apfs)
                .expect("APFS formats it")
                .into_bytes(),
        ),
    ]
}

/// The birth time a read reports of every entry of the tree, by path.
fn births(image: Vec<u8>) -> BTreeMap<Vec<u8>, Option<Timestamp>> {
    fn walk<T: FsTree>(tree: &mut T) -> BTreeMap<Vec<u8>, Option<Timestamp>> {
        let mut out = BTreeMap::new();
        tree.walk_tree::<TreeError, _>(|tree, entry| {
            let meta = tree.stat(&entry.node, &Synthesis::default())?.meta;
            out.insert(entry.path, meta.btime);
            Ok(())
        })
        .expect("the tree walks");
        out
    }
    match open(Cursor::new(image)).expect("the image opens") {
        FsReader::Ext(mut r) => walk(&mut r),
        FsReader::Fat(mut r) => walk(&mut r),
        FsReader::ExFat(mut r) => walk(&mut r),
        FsReader::Btrfs(mut r) => walk(&mut r),
        FsReader::Apfs(mut r) => walk(&mut r),
        _ => unreachable!("a family this test writes"),
    }
}

/// What a read of each family reports of the two entries' birth times.
fn read_back(source: impl Fn() -> TreeBuilder) -> Vec<(&'static str, [Option<Timestamp>; 2])> {
    images(source)
        .into_iter()
        .map(|(family, image)| {
            let births = births(image);
            let at = |path: &[u8]| {
                *births
                    .get(path)
                    .unwrap_or_else(|| panic!("{family}: {}", String::from_utf8_lossy(path)))
            };
            (family, [at(b"/docs"), at(b"/docs/note.txt")])
        })
        .collect()
}

#[test]
fn a_birth_time_survives_every_family_that_records_one() {
    let read = read_back(|| tree(Some(BORN)));
    assert_eq!(read.len(), 5);
    for (family, births) in read {
        assert_eq!(births, [Some(BORN); 2], "{family}");
    }
}

#[test]
fn a_source_stating_none_reads_back_the_modification_time() {
    // No host walk, archive or built tree states a birth time, and every family writes the
    // modification time in its place, as each did before a source could state one.
    for (family, births) in read_back(|| tree(None)) {
        assert_eq!(births, [Some(MODIFIED); 2], "{family}");
    }
}

#[test]
fn a_birth_time_crosses_from_one_image_to_another() {
    // A tree read from an image states the birth times its format records, so a source made
    // of one carries them into every family it is written to.
    let (_, apfs) = images(|| tree(Some(BORN)))
        .pop()
        .expect("the APFS image is last");
    let source = || {
        let reader = match open(Cursor::new(apfs.clone())).expect("opens") {
            FsReader::Apfs(r) => r,
            _ => unreachable!("an APFS image"),
        };
        ferrosys::ImageSource::read(reader, &Synthesis::default()).expect("reads")
    };
    let written = ferrosys::ext::format(
        source(),
        32 << 20,
        ferrosys::ext::FormatOptions::new([0x33; 16], FORMATTED, [0; 16]),
    )
    .expect("ext formats it")
    .into_bytes();
    assert_eq!(
        births(written)[b"/docs/note.txt".as_slice()],
        Some(BORN),
        "ext"
    );
    let entries = source().into_entries();
    let note = entries
        .iter()
        .find(|e| e.path == b"/docs/note.txt")
        .expect("the file");
    assert_eq!(note.meta.btime, Some(BORN), "the source states it");
}
