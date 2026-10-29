//! The opt-in gate on Apple's restore RAM disk: the container the macOS 26.6.2 restore image
//! carries, read whole and held to what macOS read of it, then written again in the shape a RAM
//! disk root takes and read back.
//!
//! The container is Apple's own. An APFS release older than any the corpus holds made it, and
//! Apple compressed most of its files itself. Apple serves it from its CDN, so
//! `ci/fetch-apple-ramdisk.sh` fetches it into a cache, and nothing of it is committed. The
//! listing is macOS's: `apfs-probes`'s `ramdisk` probe attaches the container read-only on a
//! runner and records every entry as the corpus probe records a volume, and macOS 15, 26 and 27
//! record it byte for byte alike.
//!
//! Run when asked: `FERROSYS_APFS_RAMDISK_LISTING` names the listing, and the gate then fails
//! rather than skips without the container. Both are held to their digests, so the gate fails
//! with either changed in one byte.
#![cfg(all(
    feature = "apfs",
    feature = "zlib",
    feature = "lzvn",
    feature = "lzfse",
    feature = "lzbitmap"
))]

mod apfs_listing;
mod util;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::PathBuf;
use std::process::Command;

use apfs_listing::{Faults, Hashing, compare, hex, json};
use ferrosys::apfs::{
    FormatOptions, NameKind, OpenOptions, Reader, VolumeName, VolumeRequest, format,
};
use ferrosys::{Filesystem, FsTree, ImageSource, Metadata, NodeKind, Synthesis, TreeError};
use sha2::{Digest, Sha256};

/// The digest of macOS's listing of the container, the one every release recorded.
const LISTING_SHA256: &str = "b512e13717f546639037bafe09a70e5462f888e43d9e72fb5068539e2ad176e8";

/// Every entry macOS listed, the root among them, and every regular file it read.
const ENTRIES: usize = 2653;
const FILES: usize = 1351;

/// The container and the listing, where the gate is asked for: `None` where it is not.
fn inputs() -> Option<(PathBuf, PathBuf)> {
    let listing = PathBuf::from(std::env::var_os("FERROSYS_APFS_RAMDISK_LISTING")?);
    let ask = |flag: &str| {
        let out = Command::new("bash")
            .arg(util::ci_dir().join("fetch-apple-ramdisk.sh"))
            .arg(flag)
            .output()
            .expect("run ci/fetch-apple-ramdisk.sh");
        assert!(out.status.success(), "ci/fetch-apple-ramdisk.sh {flag}");
        String::from_utf8(out.stdout)
            .expect("the script answers in text")
            .trim()
            .to_string()
    };
    let image = PathBuf::from(ask("--print-path"));
    let mut digest = Hashing(Sha256::new());
    let mut file = File::open(&image).unwrap_or_else(|e| {
        panic!(
            "the gate requires the container at {}, which ci/fetch-apple-ramdisk.sh fetches: {e}",
            image.display()
        )
    });
    std::io::copy(&mut file, &mut digest).expect("read the container");
    assert_eq!(
        hex(&digest.0.finalize()),
        ask("--print-sha256"),
        "the container"
    );
    let listed = std::fs::read(&listing).expect("read the listing");
    assert_eq!(hex(&Sha256::digest(&listed)), LISTING_SHA256, "the listing");
    Some((image, listing))
}

#[test]
fn apples_restore_ram_disk_reads_as_macos_listed_it() {
    let Some((image, listing)) = inputs() else {
        return;
    };
    let mut file = File::open(&image).expect("open the container");
    assert_eq!(
        ferrosys::detect(&mut file).expect("detect"),
        Filesystem::Apfs
    );

    let mut reader = Reader::open(File::open(&image).expect("open")).expect("opens strictly");
    let scan = reader.scan();
    assert!(
        scan.anomalies().is_empty() && !scan.is_truncated(),
        "a strict scan finds nothing: {:?}",
        scan.anomalies()
    );

    let listing = json(&listing);
    let files = listing["entries"]
        .as_array()
        .expect("an entry list")
        .iter()
        .filter(|e| e.get("sha256").is_some())
        .count();
    let mut faults = Faults::default();
    let entries = compare(&mut reader, &listing, "the restore RAM disk", &mut faults);
    faults.assert_none();
    assert_eq!(
        (entries, files),
        (ENTRIES, FILES),
        "entries walked, files read"
    );
}

/// What one entry of a volume is, as the round trip compares two: everything a source carries
/// of it, each file's content and each compressed form by digest.
#[derive(Debug, PartialEq, Eq)]
struct Held {
    kind: NodeKind,
    meta: Metadata,
    xattrs: Vec<(Vec<u8>, String)>,
    bsd_flags: Option<u32>,
    compressed: Option<(String, Option<String>)>,
    content: Option<String>,
    target: Option<Vec<u8>>,
    shared: bool,
}

/// Every entry `reader` walks, by path.
fn held<R: Read + Seek>(reader: &mut Reader<R>) -> BTreeMap<Vec<u8>, Held> {
    let mut out = BTreeMap::new();
    reader
        .walk_tree::<TreeError, _>(|tree, entry| {
            let attributes = tree.stat(&entry.node, &Synthesis::default())?;
            let mut xattrs: Vec<(Vec<u8>, String)> = attributes
                .xattrs
                .iter()
                .map(|x| (x.name.clone(), hex(&Sha256::digest(&x.value))))
                .collect();
            xattrs.sort();
            let darwin = tree.darwin(&entry.node)?;
            let compressed = darwin
                .as_ref()
                .and_then(|d| d.compressed.as_ref())
                .map(|c| {
                    (
                        hex(&Sha256::digest(&c.header)),
                        c.fork.as_ref().map(|f| hex(&Sha256::digest(f))),
                    )
                });
            let content = match entry.kind {
                NodeKind::File { .. } => {
                    let mut hasher = Hashing(Sha256::new());
                    tree.read_data_to(&entry.node, &mut hasher)
                        .map_err(TreeError::from)?;
                    Some(hex(&hasher.0.finalize()))
                }
                _ => None,
            };
            let target = match entry.kind {
                NodeKind::Symlink => Some(tree.link_target(&entry.node)?),
                _ => None,
            };
            out.insert(
                entry.path.clone(),
                Held {
                    kind: entry.kind,
                    meta: attributes.meta,
                    xattrs,
                    bsd_flags: darwin.as_ref().map(|d| d.bsd_flags),
                    compressed,
                    content,
                    target,
                    shared: entry.shared.is_some(),
                },
            );
            Ok(())
        })
        .expect("the volume walks");
    out
}

/// The shape of a root a RAM disk holds: one volume named `ramdisk`, keeping case and insensitive
/// to normalization, at 4 KiB blocks, the raw container at byte 0, its length a multiple of 4 KiB.
#[test]
fn apples_restore_ram_disk_written_again_as_a_root_reads_back_whole() {
    let Some((image, _)) = inputs() else {
        return;
    };
    let open = || Reader::open(File::open(&image).expect("open")).expect("opens strictly");
    let mut apple = open();
    let want = held(&mut apple);
    let incompatible = apple.superblock().incompatible_features;
    let bytes = File::open(&image)
        .expect("open")
        .metadata()
        .expect("stat")
        .len();

    let source = ImageSource::read(open(), &Synthesis::default()).expect("reads as a source");
    assert!(source.fidelity().is_faithful(), "nothing synthesized");
    let volume = VolumeRequest::new(VolumeName::new("ramdisk").expect("a name"), [0x52; 16])
        .names(NameKind::CaseKeeping);
    let options = FormatOptions::new(
        [0x4d; 16],
        ferrosys::Timestamp::from_secs(1_760_000_000),
        volume,
    );
    let written = format(source, bytes, options)
        .expect("the writer formats it")
        .into_bytes();
    assert_eq!(
        written.len() as u64 % 4096,
        0,
        "a whole number of 4 KiB blocks"
    );

    let mut ours =
        Reader::open_with(Cursor::new(written), &OpenOptions::new()).expect("ours opens strictly");
    assert_eq!(
        ours.superblock().incompatible_features,
        incompatible,
        "the volume's feature word, as Apple's"
    );
    let scan = ours.scan();
    assert!(
        scan.anomalies().is_empty() && !scan.is_truncated(),
        "a strict scan of ours finds nothing: {:?}",
        scan.anomalies()
    );
    let got = held(&mut ours);
    assert_eq!(got.len(), want.len(), "entries");
    let differing: Vec<String> = want
        .iter()
        .filter(|(path, entry)| got.get(*path) != Some(*entry))
        .take(12)
        .map(|(path, entry)| {
            format!(
                "{}:\n  Apple's {entry:?}\n  ours    {:?}",
                String::from_utf8_lossy(path),
                got.get(path)
            )
        })
        .collect();
    assert!(differing.is_empty(), "\n{}", differing.join("\n"));
    let compressed = want.values().filter(|e| e.compressed.is_some()).count();
    eprintln!(
        "the restore RAM disk written again: {} entries, {compressed} compressed files",
        want.len()
    );
}
