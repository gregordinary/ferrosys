//! The APFS foreign-image gate: every container in the corpus macOS made, read whole and held
//! to what macOS reported about it.
//!
//! The corpus is ten containers per macOS release, 14, 15, 26 and 27, made on GitHub's hosted
//! macOS runners by `newfs_apfs`, `diskutil` and Time Machine. Its rows cover every pair of
//! block size (4 to 64 KiB), name kind (case-folding and case-keeping), one volume or two, and
//! snapshots or none, and every volume holds every kind of node, hard links, sparse and large
//! files, attributes from embedded to stream size, and files in each compression type macOS
//! writes. macOS listed each volume entry by entry from a read-only mount, live and at each
//! snapshot, and the image was dumped before and after, so a listing describes exactly the
//! bytes beside it. `ci/fetch-apfs-corpus.sh` holds the corpus to one hashed release.
//!
//! Each volume is opened strictly, scanned, and walked, and every entry is compared with
//! macOS's listing field by field: inode number, mode, owner, group, BSD flags, link count,
//! four times to the nanosecond, device number, symbolic link target, every extended
//! attribute's name, length and digest, compression type and size, a directory's names, and
//! the digest of every byte of every file. The paths the walk reaches are the paths macOS
//! listed. Every inode carries the internal flags the writer gives one of its kind: the flag
//! saying a resource fork is present or the one saying none is, and a compressed file's beside
//! it. Each volume's snapshots are held to `diskutil apfs listSnapshots`, and each snapshot
//! view scans clean as the volume does. The listing also records the compression attribute's
//! own length, which is not compared: the reader reads that attribute as the file's content,
//! every byte of which is compared, and reports no length of it.
//!
//! Beside the corpus are the images of the `clonerefs` probe, one per stage of eight scenes it
//! takes a clone and its source through on each release: the clone written, its source removed,
//! overwritten or emptied, a source written before its clone, clones of clones and of one file
//! twice, clones made after a snapshot and snapshots deleted under them, and a clone of a file
//! kept in its resource fork. Each stage's volume, live and at each snapshot, scans clean, and
//! every file reads back as macOS read it after the stage.
//!
//! Every container of both, formatted by macOS and written to since, still records the sizing
//! [`plan_layout`] gives a container of its block count and block size: the two checkpoint
//! areas, the space manager's chunks, size and arrays, the internal pool and its bitmaps, the
//! free queues' node limits, its volume slots and its ephemeral minimum. That holds the planner
//! at all five block sizes, 32 KiB among them, which no empty container measured has.
//!
//! Where the corpus is absent the gate says so loudly and passes, except under
//! `FERROSYS_REQUIRE_HOST_TOOLS`, where it fails.
#![cfg(all(
    feature = "apfs",
    feature = "zlib",
    feature = "lzfse",
    feature = "lzbitmap"
))]

mod apfs_listing;
mod util;

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use apfs_listing::{Faults, Hashing, compare, hex, json, text};
use ferrosys::apfs::ondisk::{
    CHECKPOINT_AREA_IS_TREE, CheckpointMap, SpaceManager, kind as object_kind,
};
use ferrosys::apfs::{BlockSize, Container, PlanRequest, Reader, plan_layout};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// What the gate compares, in all, over the pinned corpus: every view and every entry, so a
/// gate that compared less is a gate that fails.
const VIEWS: usize = 100;
/// Every entry of every view.
const ENTRIES: usize = 266_583;
/// Every stage image of the `clonerefs` probe, on every release.
const STAGES: usize = 112;

/// The releases the corpus holds, one directory each, and what each must say it is.
const RELEASES: [(&str, &str); 4] = [
    ("corpus-macos-14", "14."),
    ("corpus-macos-15", "15."),
    ("corpus-macos-26", "26."),
    ("corpus-xcode-27", "27."),
];

#[test]
fn every_corpus_volume_reads_as_macos_listed_it() {
    let Some(corpus) = util::apfs_corpus() else {
        return;
    };
    let mut faults = Faults::default();
    let mut views = 0;
    let mut entries = 0;
    for (release, version) in RELEASES {
        let dir = corpus.join(release);
        let index = json(&dir.join("corpus.json"));
        let product = index["macos"]["product_version"]
            .as_str()
            .expect("the index names its macOS");
        assert!(product.starts_with(version), "{release} is macOS {product}");
        let rows = index["rows"].as_array().expect("the index lists its rows");
        assert_eq!(rows.len(), 10, "{release}: the corpus is ten containers");
        for row in rows {
            let name = row["name"].as_str().expect("a row is named");
            assert_eq!(
                row["ok"], true,
                "{release} {name}: the probe passed its own check"
            );
            let image = std::fs::read(dir.join(text(&row["image"]))).expect("read the dump");
            let (dump, digest) = Dump::parse(&image);
            assert_eq!(
                digest,
                text(&row["content_sha256"]),
                "{release} {name}: the dump"
            );
            assert_eq!(
                Some(dump.size),
                row["image_size"].as_u64(),
                "{release} {name}"
            );
            let block_size = row["block_size"].as_u64().expect("a block size");
            let mut container =
                Container::open(dump.clone()).expect("the container opens strictly");
            assert_eq!(
                u64::from(container.block_size()),
                block_size,
                "{release} {name}"
            );
            hold_sizing(&mut container, &format!("{release} {name}"), &mut faults);
            let listed_volumes = row["volume_list"].as_array().map_or(0, Vec::len);
            assert_eq!(
                (
                    container.volumes().len(),
                    container.unreadable_volumes().len()
                ),
                (listed_volumes, 0),
                "{release} {name}: the volumes the container lists"
            );

            for volume in row["volume_list"]
                .as_array()
                .expect("the row lists its volumes")
            {
                let label = format!("macOS {product} {name} {}", text(&volume["name"]));
                let live = dir.join(text(&volume["live"]));
                let mut reader = open(&dump, volume);
                assert_eq!(
                    reader.superblock().is_case_insensitive(),
                    volume["case_sensitive"] == false,
                    "{label}: the name kind"
                );
                let scan = reader.scan();
                for anomaly in scan.anomalies() {
                    faults.add(&label, b"", "scan", &format!("{anomaly:?}"), &"nothing");
                }
                if scan.is_truncated() {
                    faults.add(&label, b"", "scan", &"stopped at its cap", &"a whole scan");
                }
                let listed = json(&live.with_file_name("snapshots.json"));
                compare_snapshots(&mut reader, &listed, &label, &mut faults);
                entries += compare(&mut reader, &json(&live), &label, &mut faults);
                views += 1;

                for snapshot in volume["snapshots"].as_array().expect("a snapshot list") {
                    let at = text(&snapshot["name"]);
                    let label = format!("{label} at {at}");
                    let mut reader = open(&dump, volume)
                        .at_snapshot(at.as_bytes())
                        .expect("the snapshot opens");
                    let scan = reader.scan();
                    for anomaly in scan.anomalies() {
                        faults.add(&label, b"", "scan", &format!("{anomaly:?}"), &"nothing");
                    }
                    let manifest = json(&dir.join(text(&snapshot["manifest"])));
                    entries += compare(&mut reader, &manifest, &label, &mut faults);
                    views += 1;
                }
            }
        }
    }
    eprintln!("APFS corpus: {views} volume views, {entries} entries compared");
    faults.assert_none();
    assert_eq!((views, entries), (VIEWS, ENTRIES), "what the gate compared");
}

/// The releases the `clonerefs` probe ran on, one directory each, and what each must say it is.
const CLONE_RELEASES: [(&str, &str); 4] = [
    ("clonerefs-macos-14", "14."),
    ("clonerefs-macos-15", "15."),
    ("clonerefs-macos-26", "26."),
    ("clonerefs-xcode-27", "27."),
];

/// The stages of the `clonerefs` probe's eight scenes, on each release.
const CLONE_STAGES: usize = 28;

#[test]
fn every_clone_stage_scans_clean_and_reads_as_macos_read_it() {
    let Some(corpus) = util::apfs_corpus() else {
        return;
    };
    let mut faults = Faults::default();
    let mut stages = 0;
    for (release, version) in CLONE_RELEASES {
        let dir = corpus.join(release);
        let sw_vers = std::fs::read_to_string(dir.join("log/sw_vers.out")).expect("sw_vers");
        let product = sw_vers
            .lines()
            .find_map(|line| line.strip_prefix("ProductVersion:"))
            .expect("the run names its macOS")
            .trim();
        assert!(product.starts_with(version), "{release} is macOS {product}");
        let summary = json(&dir.join("summary.json"));
        let summary = summary.as_array().expect("the summary lists the stages");
        assert_eq!(summary.len(), CLONE_STAGES, "{release}: every stage");
        for stage in summary {
            let scene = text(&stage["scene"]);
            let k = stage["stage"].as_u64().expect("a stage number");
            let label = format!("macOS {product} {scene} stage {k}");
            assert_eq!(stage["ok"], true, "{label}: the probe passed its own check");
            let name = format!("{scene}-s{k}");
            let image = std::fs::read(dir.join(format!("images/{name}.bd"))).expect("the dump");
            let (dump, digest) = Dump::parse(&image);
            let info = json(&dir.join(format!("images/{name}.bd.json")));
            assert_eq!(digest, text(&info["content_sha256"]), "{label}: the dump");
            let record = json(&dir.join(format!("scenes/{scene}/s{k}.json")));

            let mut container =
                Container::open(dump.clone()).expect("the container opens strictly");
            hold_sizing(&mut container, &label, &mut faults);
            let volume = container.volumes()[0].clone();
            let mut reader = Reader::over(container, volume).expect("the volume opens strictly");
            for anomaly in reader.scan().anomalies() {
                faults.add(&label, b"", "scan", &format!("{anomaly:?}"), &"nothing");
            }
            for (file, want) in record["files"].as_object().expect("the files macOS read") {
                let path = format!("/{file}");
                let node = reader.lookup(path.as_bytes()).expect("the file");
                if Some(node.inode) != want["ino"].as_u64() {
                    faults.add(&label, path.as_bytes(), "inode", &node.inode, &want["ino"]);
                }
                let mut hasher = Hashing(Sha256::new());
                reader
                    .read_data_to(&node, &mut hasher)
                    .expect("read the file");
                let read = hex(&hasher.0.finalize());
                if read != text(&want["sha256"]) {
                    faults.add(&label, path.as_bytes(), "content", &read, &want["sha256"]);
                }
            }
            let snapshots = reader.snapshots().expect("list the snapshots");
            let read: Vec<(String, u64)> = snapshots
                .iter()
                .map(|s| (String::from_utf8_lossy(&s.name).into_owned(), s.xid))
                .collect();
            let listed: Vec<(String, u64)> = record["snapshots"]
                .as_array()
                .expect("macOS's list")
                .iter()
                .map(|s| {
                    (
                        text(&s["name"]).to_string(),
                        s["xid"].as_u64().expect("a transaction"),
                    )
                })
                .collect();
            assert_eq!(read, listed, "{label}: the snapshots");
            for snapshot in snapshots {
                let at = format!("{label} at {}", String::from_utf8_lossy(&snapshot.name));
                let container =
                    Container::open(dump.clone()).expect("the container opens strictly");
                let volume = container.volumes()[0].clone();
                let mut view = Reader::over(container, volume)
                    .and_then(|reader| reader.at_snapshot(&snapshot.name))
                    .expect("the snapshot opens");
                for anomaly in view.scan().anomalies() {
                    faults.add(&at, b"", "scan", &format!("{anomaly:?}"), &"nothing");
                }
            }
            stages += 1;
        }
    }
    eprintln!("APFS clone stages: {stages} images");
    faults.assert_none();
    assert_eq!(stages, STAGES, "what the gate compared");
}

/// Open the volume a corpus row names, by its slot, and check it is the one named.
/// Hold what a container records of its sizing to what [`plan_layout`] gives a container of
/// its block count and block size.
fn hold_sizing(container: &mut Container<Dump>, label: &str, faults: &mut Faults) {
    let sb = container.superblock().clone();
    let bs = sb.block_size;
    let block_size = match bs {
        4096 => BlockSize::K4,
        8192 => BlockSize::K8,
        16384 => BlockSize::K16,
        32768 => BlockSize::K32,
        65536 => BlockSize::K64,
        other => panic!("{label}: {other} is no block size"),
    };
    let plan =
        plan_layout(&PlanRequest::new(sb.block_count * u64::from(bs)).block_size(block_size))
            .expect("a corpus container's size is one the planner plans");

    // The newest checkpoint's mapping block is the first of the blocks it uses.
    let areas = sb.checkpoint;
    let mut block = vec![0u8; bs as usize];
    container
        .read_blocks(areas.desc_base + u64::from(areas.desc_index), &mut block)
        .expect("read the checkpoint's mapping block");
    let (_, mappings) = CheckpointMap::read_from(&block).expect("a mapping block");
    let mapping = mappings
        .iter()
        .find(|m| m.kind() == object_kind::SPACE_MANAGER)
        .expect("the checkpoint maps its space manager");
    let mut object = vec![0u8; mapping.size as usize];
    container
        .read_blocks(mapping.address, &mut object)
        .expect("read the space manager");
    let sm = SpaceManager::read_from(&object).expect("a space manager");
    let main = &sm.devices[SpaceManager::MAIN];

    let shape = &plan.space_manager;
    let chunks = &plan.chunks;
    for (what, recorded, planned) in [
        (
            "descriptor area",
            (
                areas.desc_base,
                u64::from(areas.desc_blocks & !CHECKPOINT_AREA_IS_TREE),
            ),
            (plan.descriptor_area.start, plan.descriptor_area.count),
        ),
        (
            "data area",
            (
                areas.data_base,
                u64::from(areas.data_blocks & !CHECKPOINT_AREA_IS_TREE),
            ),
            (plan.data_area.start, plan.data_area.count),
        ),
        (
            "chunk-info and address blocks",
            (u64::from(main.cib_count), u64::from(main.cab_count)),
            (chunks.cib_count, chunks.cab_count),
        ),
        (
            "space manager blocks and list",
            (u64::from(mapping.size / bs), u64::from(main.addr_offset)),
            (u64::from(shape.blocks), u64::from(shape.address_offset)),
        ),
        (
            "space manager arrays",
            (
                u64::from(sm.ip_bm_xid_offset),
                u64::from(sm.ip_bm_free_next_offset),
            ),
            (
                u64::from(shape.bitmap_xid_offset),
                u64::from(shape.bitmap_free_list_offset),
            ),
        ),
        (
            "second device's list",
            (
                u64::from(sm.devices[1].addr_offset),
                u64::from(sm.ip_bitmap_offset),
            ),
            (
                u64::from(shape.second_address_offset),
                u64::from(shape.bitmap_slot_offset),
            ),
        ),
        (
            "pool bitmaps",
            (u64::from(sm.ip_bm_size_in_blocks), sm.ip_bm_base),
            (u64::from(plan.pool_bitmaps), plan.pool_bitmap_area.start),
        ),
        (
            "pool-bitmap area and pool",
            (u64::from(sm.ip_bm_block_count), sm.ip_base),
            (plan.pool_bitmap_area.count, plan.pool.start),
        ),
        ("pool blocks", (sm.ip_block_count, 0), (plan.pool.count, 0)),
        (
            "queue node limits",
            (
                u64::from(sm.free_queues[0].tree_node_limit),
                u64::from(sm.free_queues[1].tree_node_limit),
            ),
            (
                u64::from(plan.queue_node_limits.pool),
                u64::from(plan.queue_node_limits.main),
            ),
        ),
        (
            "volume slots and ephemeral minimum",
            (u64::from(sb.max_volumes), sb.ephemeral_info[0] >> 32),
            (
                u64::from(plan.max_volumes),
                u64::from(plan.ephemeral_min_blocks),
            ),
        ),
    ] {
        if recorded != planned {
            faults.0.push(format!(
                "{label}: {what}: the container records {recorded:?}, the plan gives {planned:?}"
            ));
        }
    }
}

fn open(dump: &Dump, volume: &Value) -> Reader<Dump> {
    let container = Container::open(dump.clone()).expect("the container opens strictly");
    let slot = usize::try_from(volume["slot"].as_u64().expect("a slot")).expect("a slot");
    let entry = container
        .volumes()
        .iter()
        .find(|v| v.slot == slot)
        .cloned()
        .expect("the container holds the slot");
    assert_eq!(entry.name(), text(&volume["name"]).as_bytes());
    Reader::over(container, entry).expect("the volume opens strictly")
}

/// Hold a volume's snapshots to what `diskutil apfs listSnapshots` listed: name,
/// transaction, and identifier, in the same order.
fn compare_snapshots(reader: &mut Reader<Dump>, listed: &Value, label: &str, faults: &mut Faults) {
    let read: Vec<(String, u64, String)> = reader
        .snapshots()
        .expect("list the snapshots")
        .into_iter()
        .map(|s| {
            let uuid = s.uuid.map(|u| uuid_text(&u)).unwrap_or_default();
            (String::from_utf8_lossy(&s.name).into_owned(), s.xid, uuid)
        })
        .collect();
    let want: Vec<(String, u64, String)> = listed
        .as_array()
        .expect("a snapshot list")
        .iter()
        .map(|s| {
            (
                text(&s["name"]).to_string(),
                s["xid"].as_u64().expect("a transaction"),
                text(&s["uuid"]).to_string(),
            )
        })
        .collect();
    if read != want {
        faults.add(
            label,
            b"",
            "snapshots",
            &format!("{read:?}"),
            &format!("{want:?}"),
        );
    }
}

/// A container as its block dump holds it: the runs of nonzero blocks at their addresses, and
/// zeros everywhere else, served as a seekable source.
#[derive(Clone)]
struct Dump {
    size: u64,
    /// The first byte of each run and the run's bytes, in address order.
    runs: Arc<Vec<(u64, Vec<u8>)>>,
    pos: u64,
}

impl Dump {
    /// Parse a dump as the corpus stores it, and the digest its index records for it: SHA-256
    /// over each run's header and blocks, the terminating header excluded.
    ///
    /// The layout is an 8-byte magic, the image size as a little-endian `u64` and the block
    /// size as a `u32`, then runs of a first block (`u64`) and a block count (`u32`) followed by
    /// that many blocks, ended by a run whose count is zero.
    fn parse(bytes: &[u8]) -> (Self, String) {
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8"));
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4"));
        assert_eq!(&bytes[..8], b"BLKDUMP1", "a block dump");
        let size = u64_at(8);
        let block = u64::from(u32_at(16));
        let mut at = 20;
        let mut runs = Vec::new();
        let mut digest = Sha256::new();
        loop {
            let first = u64_at(at);
            let count = u64::from(u32_at(at + 8));
            if count == 0 {
                break;
            }
            digest.update(&bytes[at..at + 12]);
            at += 12;
            let len = usize::try_from(count * block).expect("a run fits in memory");
            digest.update(&bytes[at..at + len]);
            runs.push((first * block, bytes[at..at + len].to_vec()));
            at += len;
        }
        let dump = Self {
            size,
            runs: Arc::new(runs),
            pos: 0,
        };
        (dump, hex(&digest.finalize()))
    }
}

impl Read for Dump {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let left = usize::try_from(self.size - self.pos).unwrap_or(usize::MAX);
        let want = buf.len().min(left);
        // The last run starting at or before the position: it holds the position, or a hole
        // runs from its end to the next run's start.
        let next = self.runs.partition_point(|(start, _)| *start <= self.pos);
        let held = next.checked_sub(1).map(|i| &self.runs[i]);
        let n = match held {
            Some((start, data)) if self.pos < start + data.len() as u64 => {
                let from = usize::try_from(self.pos - start).expect("inside a run");
                let n = want.min(data.len() - from);
                buf[..n].copy_from_slice(&data[from..from + n]);
                n
            }
            _ => {
                let end = self.runs.get(next).map_or(self.size, |(start, _)| *start);
                let n = want.min(usize::try_from(end - self.pos).unwrap_or(usize::MAX));
                buf[..n].fill(0);
                n
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Dump {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = pos.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

/// A volume or snapshot identifier as `diskutil` prints it.
fn uuid_text(u: &[u8; 16]) -> String {
    let h = hex(u).to_uppercase();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
