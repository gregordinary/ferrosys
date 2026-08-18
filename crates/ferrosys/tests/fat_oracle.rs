//! The FAT family's oracle tier: `mkfs.fat`, `fsck.fat`, and mtools, and the evidence
//! that their verdicts mean something.
//!
//! An oracle certifies nothing until it has been seen to reject what it should reject,
//! so everything above the `planner` module runs against the pinned foreign tools alone
//! and establishes three things about them:
//!
//! - The baseline repeats itself. `mkfs.fat --invariant` replaces every random and
//!   clock-derived value with a constant, so two runs at identical parameters produce
//!   identical bytes. That is what lets the differential gate be a byte comparison
//!   rather than a filtered field diff.
//! - The type-determination boundaries are where the specification says. The FAT type
//!   is never recorded in an image — every driver computes it from the geometry — so
//!   the boundary arithmetic *is* the format, and the two off-by-ones in it are the
//!   canonical FAT bug. Each boundary is reached exactly and checked against what the
//!   pinned formatter produced.
//! - The checker discriminates. Three hand-made corruptions, each a defect class a
//!   writer can plausibly produce, must be rejected — and the same image before the
//!   corruption must be accepted, so a rejection is attributable to the damage rather
//!   than to the image having been unhealthy all along.
//!
//! The `planner` module is what those three make possible: this crate's own geometry,
//! held field for field against what the baseline produced from the same parameters.
//! It is compiled only where the FAT family is.
//!
//! Every gate here declares the tool it needs and reports a loud skip when it is
//! absent, except where `FERROSYS_REQUIRE_HOST_TOOLS` is set, which is how CI refuses
//! to pass by not consulting an oracle.

mod util;

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use util::{available, fsck_fat_clean, tool};

/// The logical sector size every fixture here uses. It is the only size `mkfs.fat`
/// defaults to and the only one every FAT driver has always supported; the wider range
/// the format permits belongs to the gates that will exercise a writer.
const SECTOR: u64 = 512;

/// Which FAT the cluster count selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

impl FatKind {
    /// The string a conformant formatter writes into `BS_FilSysType`.
    ///
    /// This field is documentation and no driver reads it, which is exactly why it is
    /// useful here: it is the formatter *reporting its own decision*, so comparing it
    /// against the count-derived answer checks two independent derivations against each
    /// other rather than reading one twice.
    fn advertised(self) -> &'static [u8; 8] {
        match self {
            FatKind::Fat12 => b"FAT12   ",
            FatKind::Fat16 => b"FAT16   ",
            FatKind::Fat32 => b"FAT32   ",
        }
    }

    /// The one normative rule: the type follows from the cluster count and from
    /// nothing else. Both boundaries are exclusive below, which is the reading that
    /// prose transcription gets wrong.
    fn of(clusters: u32) -> FatKind {
        if clusters < 4085 {
            FatKind::Fat12
        } else if clusters < 65525 {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        }
    }
}

/// The fields of a BIOS parameter block that the cluster-count computation reads.
#[derive(Debug)]
struct Bpb {
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    fats: u32,
    root_entries: u32,
    total_sectors: u32,
    fat_sectors: u32,
    /// `BPB_FATSz16`, kept separate from the resolved size because zero here is how
    /// every mainstream driver actually recognizes FAT32 — ahead of any cluster
    /// arithmetic.
    fat_sectors_16: u32,
    advertised: [u8; 8],
}

impl Bpb {
    fn parse(sector: &[u8]) -> Bpb {
        let u16_at = |off: usize| u16::from_le_bytes([sector[off], sector[off + 1]]) as u32;
        let u32_at = |off: usize| {
            u32::from_le_bytes([
                sector[off],
                sector[off + 1],
                sector[off + 2],
                sector[off + 3],
            ])
        };
        let fat_sectors_16 = u16_at(22);
        let total_16 = u16_at(19);
        // FAT12/16 place the extended boot record at offset 36 and FAT32 pushes it to
        // 64, so where the type string lives depends on the type -- and a zero
        // `BPB_FATSz16` is what says which.
        let advertised_at = if fat_sectors_16 == 0 { 82 } else { 54 };
        let mut advertised = [0u8; 8];
        advertised.copy_from_slice(&sector[advertised_at..advertised_at + 8]);
        Bpb {
            bytes_per_sector: u16_at(11),
            sectors_per_cluster: sector[13] as u32,
            reserved_sectors: u16_at(14),
            fats: sector[16] as u32,
            root_entries: u16_at(17),
            total_sectors: if total_16 == 0 { u32_at(32) } else { total_16 },
            fat_sectors: if fat_sectors_16 == 0 {
                u32_at(36)
            } else {
                fat_sectors_16
            },
            fat_sectors_16,
            advertised,
        }
    }

    /// The specification's own cluster-count computation, transcribed once.
    ///
    /// A second implementation of this arithmetic will live in the FAT geometry
    /// planner. That is deliberate rather than duplication to be removed: this one is
    /// derived from the specification and checked against the pinned formatter's
    /// output below, so it is what the planner is later held to.
    fn clusters(&self) -> u32 {
        // The specification writes this as an explicit round-up, `((n * 32) + (bps -
        // 1)) / bps`. Spelled with `div_ceil` here because it is the same value and the
        // lint asks for it; the transcription that matters is the one below.
        let root_sectors = (self.root_entries * 32).div_ceil(self.bytes_per_sector);
        let data_sectors = self.total_sectors
            - (self.reserved_sectors + self.fats * self.fat_sectors + root_sectors);
        data_sectors / self.sectors_per_cluster
    }
}

/// One row of the type-determination table: parameters that reach an exact cluster
/// count, and what that count means.
struct Edge {
    /// What this row is for, quoted in a failure so a diff names the boundary rather
    /// than a sector count.
    what: &'static str,
    total_sectors: u64,
    /// Reserved sectors. This is the knob that reaches an exact cluster count: it
    /// moves the data region by one sector, and at one sector per cluster that is one
    /// cluster, which no other parameter offers at this granularity.
    reserved: u32,
    /// Root directory entries, or zero to let the formatter decide -- which it does
    /// only for FAT32, where the field must be zero.
    root_entries: u32,
    /// The type to force with `-F`, where the formatter's own search will not reach
    /// this row unaided.
    force: Option<u32>,
    clusters: u32,
    kind: FatKind,
}

/// Every cluster count at which the derived type changes, and one either side.
///
/// The two counts that are *missing* from the FAT12/16 pair are the subject of
/// [`the_two_ambiguous_cluster_counts_cannot_be_formatted`], and are the reason this
/// table runs 4084 to 4087 rather than 4084 to 4086.
const EDGES: &[Edge] = &[
    Edge {
        what: "one below the largest FAT12",
        total_sectors: 4160,
        reserved: 21,
        root_entries: 512,
        force: None,
        clusters: 4083,
        kind: FatKind::Fat12,
    },
    Edge {
        what: "the largest FAT12",
        total_sectors: 4160,
        reserved: 20,
        root_entries: 512,
        force: None,
        clusters: 4084,
        kind: FatKind::Fat12,
    },
    Edge {
        what: "the smallest FAT16 any formatter will write",
        total_sectors: 4160,
        reserved: 9,
        root_entries: 512,
        force: None,
        clusters: 4087,
        kind: FatKind::Fat16,
    },
    Edge {
        what: "one above the smallest FAT16",
        total_sectors: 4160,
        reserved: 8,
        root_entries: 512,
        force: None,
        clusters: 4088,
        kind: FatKind::Fat16,
    },
    Edge {
        what: "one below the largest FAT16",
        total_sectors: 66080,
        reserved: 13,
        root_entries: 512,
        force: None,
        clusters: 65523,
        kind: FatKind::Fat16,
    },
    Edge {
        what: "the largest FAT16",
        total_sectors: 66080,
        reserved: 12,
        root_entries: 512,
        force: None,
        clusters: 65524,
        kind: FatKind::Fat16,
    },
    Edge {
        what: "the smallest FAT32",
        total_sectors: 66592,
        reserved: 43,
        root_entries: 0,
        force: Some(32),
        clusters: 65525,
        kind: FatKind::Fat32,
    },
    Edge {
        what: "one above the smallest FAT32",
        total_sectors: 66592,
        reserved: 42,
        root_entries: 0,
        force: Some(32),
        clusters: 65526,
        kind: FatKind::Fat32,
    },
];

/// A file of `sectors` times 512 bytes, sparse, ready to be formatted into.
fn blank(sectors: u64) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("create a temporary image");
    file.as_file()
        .set_len(sectors * SECTOR)
        .expect("size the temporary image");
    file
}

/// Format `path` with the pinned baseline, returning what the formatter said.
///
/// `--invariant` is what makes the result reproducible: it replaces the volume
/// identifier and the creation time, the only two values `mkfs.fat` would otherwise
/// draw from the clock and from randomness, with constants. One sector per cluster and
/// two FATs are fixed across every fixture so that the reserved-sector count is the
/// only thing moving.
fn mkfs(path: &Path, edge: &Edge) -> Result<(), String> {
    let mut cmd = tool("mkfs.fat");
    cmd.arg("--invariant")
        .args(["-s", "1", "-f", "2"])
        .args(["-R", &edge.reserved.to_string()]);
    if edge.root_entries != 0 {
        cmd.args(["-r", &edge.root_entries.to_string()]);
    }
    if let Some(bits) = edge.force {
        cmd.args(["-F", &bits.to_string()]);
    }
    let out = cmd.arg(path).output().map_err(|e| format!("spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "mkfs.fat exited {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Build one row's image and hand back both the file and its parsed boot sector.
fn formatted(edge: &Edge) -> (tempfile::NamedTempFile, Bpb) {
    let image = blank(edge.total_sectors);
    mkfs(image.path(), edge).unwrap_or_else(|e| {
        panic!(
            "the baseline could not build {} ({} clusters): {e}",
            edge.what, edge.clusters
        )
    });
    let bpb = Bpb::parse(&read_at(image.path(), 0, SECTOR as usize));
    (image, bpb)
}

fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("open the image");
    file.seek(SeekFrom::Start(offset)).expect("seek the image");
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).expect("read the image");
    buf
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the image for writing");
    file.seek(SeekFrom::Start(offset)).expect("seek the image");
    file.write_all(bytes).expect("write the image");
}

// ---------------------------------------------------------------------------
// The baseline

#[test]
fn the_baseline_formatter_repeats_itself_byte_for_byte() {
    if !available("mkfs.fat") {
        return;
    }
    // The first row is as good as any: what is being checked is the formatter, not the
    // geometry, and a small image makes the comparison cheap.
    let edge = &EDGES[0];
    let first = blank(edge.total_sectors);
    let second = blank(edge.total_sectors);
    mkfs(first.path(), edge).expect("format the first image");
    mkfs(second.path(), edge).expect("format the second image");

    let a = std::fs::read(first.path()).expect("read the first image");
    let b = std::fs::read(second.path()).expect("read the second image");
    assert_eq!(
        a, b,
        "`mkfs.fat --invariant` produced different bytes on two runs at identical \
         parameters, so it is not the byte-equality baseline the differential gate \
         assumes"
    );
}

// ---------------------------------------------------------------------------
// The type-determination boundaries

#[test]
fn every_type_boundary_is_where_the_specification_says() {
    if !available("mkfs.fat") {
        return;
    }
    for edge in EDGES {
        let (_image, bpb) = formatted(edge);

        assert_eq!(
            bpb.clusters(),
            edge.clusters,
            "{}: the parameters no longer reach the cluster count this row exists to \
             test. The boundary has not moved -- these parameters have stopped \
             reaching it, and the row needs new ones. Boot sector: {bpb:?}",
            edge.what
        );
        assert_eq!(
            FatKind::of(bpb.clusters()),
            edge.kind,
            "{}: {} clusters derives the wrong type",
            edge.what,
            edge.clusters
        );
        assert_eq!(
            &bpb.advertised,
            edge.kind.advertised(),
            "{}: the count-derived type and the type the formatter recorded in \
             BS_FilSysType disagree, so one of the two derivations is wrong",
            edge.what
        );
        // The FAT32 recognition every mainstream driver actually performs, checked
        // against the count-derived answer. A driver reaches for this first, so a
        // formatter that got it wrong would produce an image read as the wrong type
        // whatever the cluster count said.
        assert_eq!(
            bpb.fat_sectors_16 == 0,
            edge.kind == FatKind::Fat32,
            "{}: BPB_FATSz16 is zero on exactly the FAT32 images and no others",
            edge.what
        );
    }
}

#[test]
fn the_two_ambiguous_cluster_counts_cannot_be_formatted() {
    if !available("mkfs.fat") {
        return;
    }
    // 4085 and 4086 clusters are the one region where two mainstream drivers read the
    // same image as two different filesystems: the specification and Linux's `vfat`
    // make 4085 the first FAT16, while Windows' `fastfat` reads anything below 4087 as
    // FAT12. The FAT is a packed array whose entry width differs between the two, so
    // the disagreement is not cosmetic -- one of the two readers resolves every chain
    // past the second cluster to nonsense.
    //
    // No formatter will write into that region, and the geometry planner must not
    // either. This asserts the gap is real rather than taking the baseline's word for
    // it, because the planner's refusal is only justified while it is.
    for (reserved, clusters) in [(19, 4085), (10, 4086)] {
        let edge = Edge {
            what: "an ambiguous count",
            total_sectors: 4160,
            reserved,
            root_entries: 512,
            force: None,
            clusters,
            kind: FatKind::Fat16,
        };
        let image = blank(edge.total_sectors);
        let built = mkfs(image.path(), &edge);
        assert!(
            built.is_err(),
            "the baseline formatted a volume at {clusters} clusters, which two \
             mainstream drivers read as different filesystems. Either the gap has \
             been reconsidered upstream or these parameters no longer reach it, and \
             the planner's refusal has to be revisited either way"
        );
    }
}

// ---------------------------------------------------------------------------
// The checker

/// The image the corruption controls damage: a small FAT16 with one file in it, so
/// that there is a cluster chain and a directory entry to break.
///
/// Populated with mtools rather than by hand, so the damage is applied to a tree a
/// foreign implementation wrote and the checker's verdict cannot be an argument with
/// this crate about what a healthy image looks like.
fn populated() -> (tempfile::NamedTempFile, Bpb) {
    let edge = &EDGES[3];
    let (image, bpb) = formatted(edge);

    let payload = tempfile::NamedTempFile::new().expect("create the payload");
    // Four clusters at 512 bytes each, so a chain exists to be looped.
    payload
        .as_file()
        .set_len(4 * SECTOR)
        .expect("size the payload");
    let status = tool("mcopy")
        .arg("-i")
        .arg(image.path())
        .arg(payload.path())
        .arg("::/PAYLOAD.BIN")
        .status()
        .expect("spawn mcopy");
    assert!(status.success(), "mcopy could not populate the image");
    (image, bpb)
}

/// Where a FAT copy begins, in bytes from the start of the image.
fn fat_offset(bpb: &Bpb, copy: u32) -> u64 {
    (bpb.reserved_sectors as u64 + copy as u64 * bpb.fat_sectors as u64) * SECTOR
}

/// Where the fixed-capacity root directory region begins. FAT12 and FAT16 only; on
/// FAT32 the root is an ordinary cluster chain and there is no such region.
fn root_offset(bpb: &Bpb) -> u64 {
    (bpb.reserved_sectors as u64 + bpb.fats as u64 * bpb.fat_sectors as u64) * SECTOR
}

#[test]
fn the_checker_accepts_every_boundary_image() {
    if !available("mkfs.fat") || !available("fsck.fat") {
        return;
    }
    // The control the three rejections below are measured against. Without it, a
    // checker that rejected everything would look like a checker that works.
    for edge in EDGES {
        let (image, _) = formatted(edge);
        fsck_fat_clean(image.path()).unwrap_or_else(|e| {
            panic!(
                "the checker rejected a freshly formatted {}: {e}",
                edge.what
            )
        });
    }
}

#[test]
fn the_checker_rejects_a_fat_copy_that_diverges_from_its_mirror() {
    if !available("mkfs.fat") || !available("fsck.fat") || !available("mcopy") {
        return;
    }
    let (image, bpb) = populated();
    fsck_fat_clean(image.path()).expect("the image is healthy before the damage");

    // A single flipped byte in the second FAT. This is the defect class a writer
    // produces by computing the table once and writing it twice imperfectly, and it is
    // invisible to anything that reads only the first copy -- which is every driver.
    let offset = fat_offset(&bpb, 1) + 8;
    let mut byte = read_at(image.path(), offset, 1);
    byte[0] ^= 0xff;
    write_at(image.path(), offset, &byte);

    let verdict = fsck_fat_clean(image.path());
    assert!(
        verdict.is_err(),
        "the checker accepted an image whose two FATs disagree, so it cannot be \
         trusted to catch a writer that mirrors them badly. It said: {verdict:?}"
    );
}

#[test]
fn the_checker_rejects_a_cluster_chain_that_loops() {
    if !available("mkfs.fat") || !available("fsck.fat") || !available("mcopy") {
        return;
    }
    let (image, bpb) = populated();
    fsck_fat_clean(image.path()).expect("the image is healthy before the damage");

    // Point the second cluster of the payload's chain back at the first, in every copy
    // so that the damage is a loop rather than a disagreement between the copies --
    // otherwise this test would be the previous one wearing a different name. A reader
    // that follows the chain without a bound never terminates, which is why this is a
    // class worth having a control for.
    let entry = 3u32;
    for copy in 0..bpb.fats {
        let offset = fat_offset(&bpb, copy) + u64::from(entry) * 2;
        write_at(image.path(), offset, &2u16.to_le_bytes());
    }

    let verdict = fsck_fat_clean(image.path());
    assert!(
        verdict.is_err(),
        "the checker accepted an image with a circular cluster chain. It said: \
         {verdict:?}"
    );
}

#[test]
fn the_checker_rejects_a_directory_entry_pointing_outside_the_data_region() {
    if !available("mkfs.fat") || !available("fsck.fat") || !available("mcopy") {
        return;
    }
    let (image, bpb) = populated();
    fsck_fat_clean(image.path()).expect("the image is healthy before the damage");

    // The payload's directory entry is the first in the root region: this fixture has
    // no volume label, and the name is a valid 8.3 so no long-name entries precede it.
    let root = root_offset(&bpb);
    let name = read_at(image.path(), root, 11);
    assert_eq!(
        &name, b"PAYLOAD BIN",
        "the first root entry is not the payload, so this test is damaging something \
         other than what it says"
    );

    // A first cluster well past the last one that exists. This is what an allocator
    // off by a region produces, and the reader contract is that it is refused rather
    // than read from wherever the arithmetic lands.
    write_at(image.path(), root + 26, &60000u16.to_le_bytes());

    let verdict = fsck_fat_clean(image.path());
    assert!(
        verdict.is_err(),
        "the checker accepted a directory entry whose first cluster is outside the \
         data region. It said: {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// The foreign reader

/// The cluster counts `minfo` cannot report on, and the reason is worth keeping.
///
/// `minfo` does not merely dump a boot sector: it also prints the `mformat` command
/// line that would recreate the image, and it reaches that by re-deriving the geometry
/// and asserting the derivation converged. For a FAT16 within a few clusters of the
/// FAT12 boundary it does not converge -- mtools' own formatter would have chosen
/// FAT12 at that count -- and the assertion aborts the process.
///
/// So `minfo` is an oracle for images mtools could itself have written, and not a
/// general boot-sector reader. `mdir`, `mcopy`, and `mtype` have no such limit and
/// read every row here, which is why the tree-walking gates are built on those.
const MINFO_CANNOT_READ: &[u32] = &[4087, 4088];

#[test]
fn the_foreign_reader_agrees_with_the_boot_sector() {
    if !available("mkfs.fat") || !available("minfo") {
        return;
    }
    for edge in EDGES {
        let (image, bpb) = formatted(edge);
        let out = tool("minfo")
            .arg("-i")
            .arg(image.path())
            .arg("::")
            .output()
            .expect("spawn minfo");

        // Asserted in both directions, so the limitation stays pinned: a release that
        // fixed it, or widened it, fails here rather than quietly changing what this
        // gate covers.
        let known_limit = MINFO_CANNOT_READ.contains(&edge.clusters);
        assert_eq!(
            out.status.success(),
            !known_limit,
            "{} ({} clusters): minfo {} the image, which is not what this gate has \
             recorded about the geometry it can reconstruct",
            edge.what,
            edge.clusters,
            if known_limit { "read" } else { "refused" }
        );
        if known_limit {
            continue;
        }

        // A second implementation's reading of the same boot sector. mtools rejects an
        // image whose parameters are internally inconsistent, so agreement here is a
        // statement about the whole header rather than about the four fields quoted.
        let said = String::from_utf8_lossy(&out.stdout);
        for expected in [
            format!("sector size: {} bytes", bpb.bytes_per_sector),
            format!("cluster size: {} sectors", bpb.sectors_per_cluster),
            format!("reserved (boot) sectors: {}", bpb.reserved_sectors),
            format!("fats: {}", bpb.fats),
        ] {
            assert!(
                said.contains(&expected),
                "{}: minfo does not report {expected:?}, so it and this crate read \
                 the same boot sector differently. It said:\n{said}",
                edge.what
            );
        }
    }
}

#[test]
fn a_long_name_survives_the_foreign_writer_and_reader() {
    if !available("mkfs.fat") || !available("mcopy") || !available("mdir") {
        return;
    }
    let edge = &EDGES[3];
    let (image, _) = formatted(edge);

    // A name that needs long-name entries to survive at all: it is longer than eight
    // characters, it has spaces, and its case is mixed. If the vendored configuration
    // ever stopped enabling long names, this is what would notice.
    let long = "A Long File Name.txt";
    let body = b"the oracle tier reads what the oracle tier wrote";
    let source = tempfile::Builder::new()
        .prefix("payload")
        .tempdir()
        .expect("create the payload directory");
    let path = source.path().join(long);
    std::fs::write(&path, body).expect("write the payload");

    let status = tool("mcopy")
        .arg("-i")
        .arg(image.path())
        .arg(&path)
        .arg("::/")
        .status()
        .expect("spawn mcopy");
    assert!(status.success(), "mcopy could not write the long name");

    let out = tool("mdir")
        .args(["-/", "-i"])
        .arg(image.path())
        .arg("::")
        .output()
        .expect("spawn mdir");
    assert!(out.status.success(), "mdir refused the image");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains(long),
        "the long name did not survive a write and a read back. mdir said:\n{listing}"
    );
    // The short name the long one is paired with. Every long name has one, a reader
    // has to cope with it, and its numeric tail is the part a writer has to generate
    // deterministically.
    assert!(
        listing.contains("ALONGF~1"),
        "the long name has no numeric-tail short name beside it, so a populated \
         oracle image is not exercising the pairing a reader must handle. mdir \
         said:\n{listing}"
    );

    if !available("mtype") {
        return;
    }
    let out = tool("mtype")
        .arg("-i")
        .arg(image.path())
        .arg(format!("::/{long}"))
        .output()
        .expect("spawn mtype");
    assert!(out.status.success(), "mtype could not read the file back");
    assert_eq!(
        out.stdout, body,
        "the file's contents did not survive the round trip"
    );
}

// ---------------------------------------------------------------------------
// This crate, against the same baseline
//
// Present only where the FAT family is compiled in. Everything above runs against the
// foreign tools alone and needs no family; this is where this crate's own arithmetic and
// its own bytes are held to theirs.

/// The differential gates: what this crate plans and writes, against what the pinned
/// formatter produced from the same parameters.
///
/// There are two, over one parameter set. The **geometry** gate compares field for field:
/// every number in it has two independent derivations, one out of
/// [`plan_layout`](ferrosys::fat::plan_layout) and one read out of a boot sector a foreign
/// implementation wrote and recomputed by [`Bpb::clusters`], which is transcribed from the
/// specification rather than from this crate. The **byte** gate compares whole images, which
/// is available here in a way it never was for ext: `mkfs.fat --invariant` repeats itself
/// exactly, so there is no residual clock field to filter out.
///
/// **The volume compared is the one the baseline used, not the one it was given.**
/// `mkfs.fat` rounds a volume's sector count down to a multiple of `BPB_SecPerTrk` and
/// leaves the remainder unformatted; this crate describes every sector it is given. That
/// divergence is deliberate and is asserted on its own in
/// [`the_planner_describes_the_whole_volume_where_the_baseline_rounds_it_down`], so
/// isolating it here leaves the rest to be compared exactly.
///
/// **Two inputs are lifted out of the baseline's own image before comparing**, because they
/// are inputs rather than decisions: the name the formatter records as its own, and the boot
/// code. This crate writes neither by default — it is not `mkfs.fat`, and the stub is that
/// project's own licensed code — so a gate that did not feed them back would be comparing
/// two formatters' identities rather than their filesystems.
#[cfg(feature = "fat")]
mod differential {
    use super::{Bpb, FatKind, SECTOR, available, read_at, tool};
    use ferrosys::TreeBuilder;
    use ferrosys::fat::{
        BootCode, ClusterSize, FatType, FatTypeRequest, FormatOptions, PlanRequest,
        ReservedSectors, RootEntries, Timestamp, VolumeLabel, format, plan_layout,
    };

    /// The instant the byte gate stamps with: the constant `mkfs.fat --invariant` uses,
    /// truncated to the two-second unit its own directory-entry fields carry.
    ///
    /// The baseline stamps 2015-03-14T09:26:53Z and writes 09:26:52 plus an empty hundredths
    /// field, dropping the odd second because it has nowhere to put it. This crate does have
    /// somewhere — a creation entry's hundredths field — so handing it the same odd instant
    /// would compare a precision the baseline discards rather than the structures. The
    /// divergence is pinned on its own, in the materializer's unit tests.
    const INVARIANT_TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    /// The serial number `mkfs.fat --invariant` writes in place of the one it would
    /// otherwise derive from the moment of formatting.
    const INVARIANT_VOLUME_ID: u32 = 0x1234_abcd;

    /// One parameter set, given to both implementations.
    #[derive(Clone, Copy, Debug)]
    struct Case {
        volume_bytes: u64,
        sector_size: u32,
        cluster: Option<u32>,
        fats: u32,
        reserved: Option<u32>,
        root_entries: Option<u32>,
        force: Option<FatType>,
        /// The volume label, which reaches both the boot sector and an entry in the root
        /// directory — so a case that names one compares a directory entry as well as a
        /// header.
        label: Option<&'static str>,
    }

    impl Case {
        const fn new(volume_bytes: u64) -> Self {
            Self {
                volume_bytes,
                sector_size: 512,
                cluster: None,
                fats: 2,
                reserved: None,
                root_entries: None,
                force: None,
                label: None,
            }
        }

        /// How the case reads in a failure, so a mismatch names parameters rather than a
        /// row number.
        fn describe(&self) -> String {
            format!(
                "{} MiB, {}-byte sectors, cluster {}, {} FATs, reserved {}, root {}, type {}, \
                 label {}",
                self.volume_bytes >> 20,
                self.sector_size,
                self.cluster.map_or("auto".into(), |c| c.to_string()),
                self.fats,
                self.reserved.map_or("auto".into(), |r| r.to_string()),
                self.root_entries.map_or("auto".into(), |r| r.to_string()),
                self.force.map_or("auto", FatType::as_str),
                self.label.unwrap_or("none"),
            )
        }
    }

    /// The type-determination bits `-F` takes.
    fn force_bits(kind: FatType) -> u32 {
        match kind {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 32,
        }
    }

    fn kind_of(bpb: &Bpb) -> FatKind {
        FatKind::of(bpb.clusters())
    }

    fn same_kind(theirs: FatKind, ours: FatType) -> bool {
        matches!(
            (theirs, ours),
            (FatKind::Fat12, FatType::Fat12)
                | (FatKind::Fat16, FatType::Fat16)
                | (FatKind::Fat32, FatType::Fat32)
        )
    }

    /// Format a sparse file of `case.volume_bytes` with the baseline, or say why it would
    /// not. A refusal is an answer about the parameters and not a failure of the gate: the
    /// baseline declines volumes this crate plans, which is a difference between the two
    /// rather than a defect in either.
    fn baseline(case: &Case) -> Result<(tempfile::NamedTempFile, Bpb, Vec<u8>), String> {
        let file = tempfile::NamedTempFile::new().expect("create a temporary image");
        file.as_file()
            .set_len(case.volume_bytes)
            .expect("size the temporary image");
        let mut cmd = tool("mkfs.fat");
        cmd.arg("--invariant")
            .args(["-f", &case.fats.to_string()])
            .args(["-S", &case.sector_size.to_string()]);
        if let Some(c) = case.cluster {
            cmd.args(["-s", &c.to_string()]);
        }
        if let Some(r) = case.reserved {
            cmd.args(["-R", &r.to_string()]);
        }
        if let Some(r) = case.root_entries {
            cmd.args(["-r", &r.to_string()]);
        }
        if let Some(kind) = case.force {
            cmd.args(["-F", &force_bits(kind).to_string()]);
        }
        if let Some(label) = case.label {
            cmd.args(["-n", label]);
        }
        let out = cmd
            .arg(file.path())
            .output()
            .map_err(|e| format!("spawn: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        let sector = read_at(file.path(), 0, case.sector_size.max(SECTOR as u32) as usize);
        let bpb = Bpb::parse(&sector);
        Ok((file, bpb, sector))
    }

    /// The planning request for this case, over the volume the baseline actually used.
    fn request(case: &Case, bpb: &Bpb) -> PlanRequest {
        let used = u64::from(bpb.total_sectors) * u64::from(case.sector_size);
        let mut request = PlanRequest::new(used)
            .bytes_per_sector(case.sector_size)
            .fats(case.fats);
        if let Some(c) = case.cluster {
            request = request.cluster_size(ClusterSize::Sectors(c));
        }
        if let Some(r) = case.reserved {
            request = request.reserved_sectors(ReservedSectors::Count(r));
        }
        if let Some(r) = case.root_entries {
            request = request.root_entries(RootEntries::Count(r));
        }
        if let Some(kind) = case.force {
            // `-F 32` is not this crate's `Exactly(Fat32)`: the baseline treats an explicit
            // request as overriding the cluster minimum and builds a FAT32 far below it,
            // warning rather than refusing. The request that means the same thing here is
            // the acknowledgement, which is why there is one. `-F 12` and `-F 16` have no
            // such exemption in either implementation, because a volume below either of
            // those minimums is read through a table of the wrong entry width rather than
            // merely being non-conformant.
            request = request.fat_type(match kind {
                FatType::Fat32 => FatTypeRequest::UndersizedFat32,
                other => FatTypeRequest::Exactly(other),
            });
        }
        request
    }

    /// Plan the same case with this crate, over the volume the baseline actually used.
    fn ours(case: &Case, bpb: &Bpb) -> ferrosys::fat::FatLayout {
        plan_layout(&request(case, bpb)).unwrap_or_else(|e| {
            panic!(
                "{}: the planner refused what the baseline built: {e}",
                case.describe()
            )
        })
    }

    /// Compare every field of a planned layout against the boot sector the baseline wrote.
    fn agree(case: &Case, bpb: &Bpb, sector: &[u8]) {
        let layout = ours(case, bpb);
        let what = case.describe();
        assert_eq!(
            layout.bytes_per_sector, bpb.bytes_per_sector,
            "{what}: sector size"
        );
        assert_eq!(
            layout.sectors_per_cluster, bpb.sectors_per_cluster,
            "{what}: sectors per cluster"
        );
        assert_eq!(
            layout.reserved_sectors, bpb.reserved_sectors,
            "{what}: reserved sectors"
        );
        assert_eq!(layout.fats, bpb.fats, "{what}: file allocation tables");
        assert_eq!(
            layout.root_entries, bpb.root_entries,
            "{what}: root entries"
        );
        assert_eq!(
            layout.total_sectors, bpb.total_sectors,
            "{what}: total sectors"
        );
        assert_eq!(layout.fat_sectors, bpb.fat_sectors, "{what}: table sectors");
        assert_eq!(
            layout.clusters,
            bpb.clusters(),
            "{what}: cluster count -- the number the type is derived from, so a difference \
             here is a different filesystem and not a different label"
        );
        // The type, by the two rules a driver applies in the order it applies them: a zero
        // 16-bit table size is FAT32 before anything is counted, and the count decides
        // otherwise. They agree on every conformant volume.
        let by_count = kind_of(bpb);
        let recognized = if bpb.fat_sectors_16 == 0 {
            FatKind::Fat32
        } else {
            by_count
        };
        assert!(
            same_kind(recognized, layout.fat_type),
            "{what}: the baseline built a {recognized:?} and this crate planned {}",
            layout.fat_type
        );
        // Where the two rules disagree, the volume is a FAT32 below its cluster minimum and
        // nothing else — the one shape that is read as one thing and counted as another.
        // Pinned so that a disagreement arising anywhere else fails here.
        if recognized != by_count {
            assert_eq!(recognized, FatKind::Fat32, "{what}");
            assert_eq!(case.force, Some(FatType::Fat32), "{what}");
            assert!(
                layout.clusters < ferrosys::fat::MIN_CLUSTERS_FAT32,
                "{what}: the two rules disagreed on a volume that is not undersized"
            );
        }
        // The type string the baseline recorded is its own statement of what it built, and
        // no driver reads it -- which is what makes it a third derivation worth comparing.
        assert_eq!(
            &bpb.advertised,
            &layout.fat_type.label(),
            "{what}: the baseline recorded a different type string than this crate planned"
        );
        // FAT32's placements, where there are any.
        match layout.fat32 {
            Some(f) => {
                assert_eq!(
                    bpb.fat_sectors_16, 0,
                    "{what}: a FAT32 has no 16-bit table size"
                );
                assert_eq!(
                    u32::from_le_bytes(sector[44..48].try_into().unwrap()),
                    f.root_cluster,
                    "{what}: root cluster"
                );
                assert_eq!(
                    u16::from_le_bytes(sector[48..50].try_into().unwrap()),
                    f.fs_info_sector,
                    "{what}: information sector"
                );
                assert_eq!(
                    u16::from_le_bytes(sector[50..52].try_into().unwrap()),
                    f.backup_boot_sector.unwrap_or(0),
                    "{what}: backup boot sector"
                );
            }
            None => assert_ne!(
                bpb.fat_sectors_16, 0,
                "{what}: only a FAT32 has a zero 16-bit table size"
            ),
        }
    }

    /// Run one case, returning whether the baseline built it at all.
    fn compare(case: &Case) -> bool {
        match baseline(case) {
            Ok((_image, bpb, sector)) => {
                agree(case, &bpb, &sector);
                true
            }
            Err(_) => false,
        }
    }

    /// Volumes far enough from every threshold the two implementations key on that the
    /// baseline's rounding cannot move either of them across one.
    ///
    /// The thresholds are the cluster-size table's sector counts and the half-gibibyte at
    /// which convention selects FAT32 outright. Rounding moves a volume by at most one
    /// track, so a size within a track of a threshold could have the two implementations
    /// reading it differently -- which would be a divergence about the rounding rather than
    /// about the geometry, and this gate is about the geometry.
    const SIZES_MIB: &[u64] = &[1, 4, 8, 32, 64, 128, 256, 511, 513, 1024, 2048];

    #[test]
    fn the_planner_reproduces_the_baseline_geometry_at_every_size() {
        if !available("mkfs.fat") {
            return;
        }
        let mut compared = 0;
        for &mib in SIZES_MIB {
            for sector_size in [512u32, 4096] {
                let case = Case {
                    sector_size,
                    ..Case::new(mib << 20)
                };
                if compare(&case) {
                    compared += 1;
                }
            }
        }
        assert!(
            compared >= SIZES_MIB.len(),
            "the sweep compared only {compared} cases, so it is no longer exercising what \
             it claims to -- the baseline is refusing parameters it used to accept"
        );
    }

    #[test]
    fn the_planner_reproduces_the_baseline_geometry_at_every_knob() {
        if !available("mkfs.fat") {
            return;
        }
        let mut compared = 0;
        for &mib in &[8u64, 64, 1024] {
            for cluster in [None, Some(1), Some(2), Some(8)] {
                for fats in [1u32, 2] {
                    for force in [
                        None,
                        Some(FatType::Fat12),
                        Some(FatType::Fat16),
                        Some(FatType::Fat32),
                    ] {
                        let case = Case {
                            cluster,
                            fats,
                            force,
                            // The root region belongs to the smaller two types. The
                            // baseline warns and ignores the count when the result is a
                            // FAT32; this crate refuses it, because a knob that did
                            // nothing is not something a caller should have to discover
                            // from the output. So it is only named where the result
                            // cannot be a FAT32 -- and the refusal itself is pinned by a
                            // unit test rather than left to this sweep to trip over.
                            root_entries: match force {
                                Some(FatType::Fat12 | FatType::Fat16) => Some(224),
                                _ => None,
                            },
                            ..Case::new(mib << 20)
                        };
                        if compare(&case) {
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert!(
            compared >= 24,
            "the knob sweep compared only {compared} cases, which is too few to be \
             exercising the parameters it names"
        );
    }

    #[test]
    fn the_planner_reproduces_the_baseline_at_every_reserved_sector_count() {
        if !available("mkfs.fat") {
            return;
        }
        // The reserved count is the finest knob there is: one sector moves the data region
        // by one sector, which at one sector per cluster is one cluster. Sweeping it walks
        // the cluster count one at a time through the FAT12/FAT16 boundary and past both
        // sides of the range the two drivers dispute, which no coarser knob reaches.
        //
        // It runs at three geometries because the arithmetic under test has terms that only
        // move with the sector size, the cluster size, and the table count. What it does
        // *not* reach is the estimate inside the circular cluster computation: that estimate
        // only seeds a table size, and the count is recomputed from the space the sized table
        // actually left, so an estimate off by one is invisible here unless it also crosses a
        // sector boundary in the table. Injecting such a defect and watching this sweep pass
        // is what established that; the estimate is pinned against a second transcription of
        // the reference formula instead, in the geometry module's own tests.
        for (volume_sectors, cluster) in [(4160u64, 1u32), (66_080, 1), (131_072, 4)] {
            for fats in [1u32, 2] {
                for reserved in 1..=64u32 {
                    let case = Case {
                        cluster: Some(cluster),
                        fats,
                        reserved: Some(reserved),
                        root_entries: Some(512),
                        ..Case::new(volume_sectors * 512)
                    };
                    compare(&case);
                }
            }
        }

        // And the FAT12/FAT16 boundary fixture again, this time reading what the baseline
        // refuses rather than only what it builds.
        let mut compared = 0;
        let mut refused = 0;
        for reserved in 1..=48u32 {
            let case = Case {
                cluster: Some(1),
                reserved: Some(reserved),
                root_entries: Some(512),
                ..Case::new(4160 * 512)
            };
            if compare(&case) {
                compared += 1;
                continue;
            }
            refused += 1;
            // Where the baseline refuses, this crate does not. These are the counts that
            // fall between the two types -- the FAT12 count has passed 4084 and the FAT16
            // count has not reached 4087 -- and the answer is the largest FAT12 no driver
            // disputes, shortening the filesystem by the handful of clusters that separates
            // the two. Asserted against the baseline's own refusal, so the divergence is
            // pinned to where it actually is rather than described.
            let layout = plan_layout(
                &PlanRequest::new(4160 * 512)
                    .cluster_size(ClusterSize::Sectors(1))
                    .reserved_sectors(ReservedSectors::Count(reserved))
                    .root_entries(RootEntries::Count(512)),
            )
            .unwrap_or_else(|e| {
                panic!("{reserved} reserved: the baseline refused it and so did this crate: {e}")
            });
            assert_eq!(layout.fat_type, FatType::Fat12, "{reserved} reserved");
            assert_eq!(
                layout.clusters,
                ferrosys::fat::MAX_CLUSTERS_FAT12,
                "{reserved} reserved: the step down must land on the largest undisputed count"
            );
            assert!(layout.total_sectors < 4160, "{reserved} reserved");
        }
        assert!(
            compared >= 30,
            "only {compared} of 48 reserved counts were comparable"
        );
        assert!(
            refused > 0,
            "the baseline accepted every reserved count in the sweep, so the sweep no \
             longer crosses the range it refuses to write into"
        );
    }

    #[test]
    fn the_planner_describes_the_whole_volume_where_the_baseline_rounds_it_down() {
        if !available("mkfs.fat") {
            return;
        }
        // The one deliberate divergence, asserted in both directions rather than avoided.
        // `mkfs.fat` rounds a volume's sector count down to a multiple of `BPB_SecPerTrk`
        // and leaves the tail unformatted; this crate describes every sector it is given,
        // because a formatter with controlled geometry quietly giving back part of the
        // volume is a surprise no report makes acceptable.
        //
        // A volume one sector past a track boundary is what separates the two.
        let case = Case::new(4161 * 512);
        let (image, bpb, _) = baseline(&case).expect("the baseline builds this");
        let track = u32::from(u16::from_le_bytes(
            read_at(image.path(), 24, 2).try_into().unwrap(),
        ));
        assert!(track > 1, "the baseline recorded no track size to round by");
        assert_eq!(
            bpb.total_sectors,
            4161 / track * track,
            "the baseline no longer rounds the sector count down to a track"
        );

        let layout = plan_layout(&PlanRequest::new(case.volume_bytes)).expect("plan");
        assert_eq!(
            layout.total_sectors, 4161,
            "this crate must describe every sector of the volume it was given"
        );
        assert!(
            layout.total_sectors > bpb.total_sectors,
            "the divergence this case exists to pin has disappeared"
        );

        // And on a volume that is already a whole number of tracks, the two agree -- which
        // is what makes the rounding the whole of the difference.
        let aligned = Case::new(u64::from(4161 / track * track) * 512);
        assert!(compare(&aligned));
    }

    // -----------------------------------------------------------------------
    // The writer, byte for byte

    /// Write the same case with this crate, over the volume the baseline used, with the
    /// baseline's own identity fed back.
    ///
    /// The two fed-back values are the only ones a formatter chooses for itself rather than
    /// deriving: the eight-byte name it records as its own, and the boot code. This crate's
    /// defaults for both are its own, which is the point — so the gate lifts the baseline's
    /// out of the image it just wrote and hands them over, and what remains to compare is
    /// the filesystem.
    fn ours_bytes(case: &Case, bpb: &Bpb, sector: &[u8]) -> Vec<u8> {
        let oem: [u8; 8] = sector[3..11].try_into().expect("eight bytes at offset 3");
        // Where the boot code begins is decided by the tail the sector carries, and a zero
        // 16-bit table size is what says which tail that is.
        let code_at = if bpb.fat_sectors_16 == 0 { 90 } else { 62 };
        let mut options = FormatOptions::new(INVARIANT_VOLUME_ID, INVARIANT_TIME)
            .plan(request(case, bpb))
            .boot_code(BootCode::new(&sector[code_at..510]).expect("a boot sector's worth"));
        options.oem_name = oem;
        if let Some(label) = case.label {
            options = options.label(VolumeLabel::new(label).expect("a valid label"));
        }
        let volume = u64::from(bpb.total_sectors) * u64::from(case.sector_size);
        format(TreeBuilder::new(), volume, options)
            .unwrap_or_else(|e| {
                panic!(
                    "{}: this crate refused what the baseline built: {e}",
                    case.describe()
                )
            })
            .into_bytes()
    }

    /// Hold one case's whole image against the baseline's, reporting where they first part.
    ///
    /// The comparison covers every byte of the filesystem the baseline described. Where its
    /// sector-count rounding left a tail it declined to format, that tail is asserted
    /// untouched rather than compared — this crate would have described it, and the
    /// divergence is pinned on its own in
    /// [`the_planner_describes_the_whole_volume_where_the_baseline_rounds_it_down`].
    fn identical(case: &Case, image: &std::path::Path, bpb: &Bpb, sector: &[u8]) {
        let theirs = std::fs::read(image).expect("read the baseline's image");
        let ours = ours_bytes(case, bpb, sector);
        let what = case.describe();
        assert!(
            ours.len() <= theirs.len(),
            "{what}: this crate wrote {} bytes over a volume of {}",
            ours.len(),
            theirs.len()
        );
        assert!(
            theirs[ours.len()..].iter().all(|&b| b == 0),
            "{what}: the tail the baseline's rounding declined to format is not empty, so \
             the two images are being compared over different filesystems"
        );
        let theirs = &theirs[..ours.len()];
        if ours == theirs {
            return;
        }
        let excused = next_free_hint_offsets(bpb, sector);
        let differing: Vec<usize> = ours
            .iter()
            .zip(theirs.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(off, _)| off)
            .filter(|off| !excused.iter().any(|range| range.contains(off)))
            .collect();
        if differing.is_empty() {
            return;
        }
        let shown: Vec<String> = differing
            .iter()
            .take(16)
            .map(|&off| {
                format!(
                    "{off:#x}: this crate {:#04x}, baseline {:#04x}",
                    ours[off], theirs[off]
                )
            })
            .collect();
        panic!(
            "{what}: {} of {} bytes differ from the baseline's image. First:\n  {}",
            differing.len(),
            ours.len(),
            shown.join("\n  ")
        );
    }

    /// The four bytes of `FSI_Nxt_Free`, in the information sector and in its backup, which
    /// the byte comparison excuses on a FAT32 volume.
    ///
    /// This is the one field the two implementations deliberately disagree on, and
    /// [`the_next_free_hint_is_where_the_two_deliberately_differ`] pins both values. The
    /// exclusion is this narrow on purpose: everything else in both information sectors,
    /// including the free-cluster count beside it, is compared.
    fn next_free_hint_offsets(bpb: &Bpb, boot: &[u8]) -> Vec<std::ops::Range<usize>> {
        if bpb.fat_sectors_16 != 0 {
            // Not a FAT32 volume, so there is no information sector at all.
            return Vec::new();
        }
        const NEXT_FREE_AT: usize = 0x1EC;
        let sector = bpb.bytes_per_sector as usize;
        // `BPB_FSInfo` and `BPB_BkBootSec`, which only a FAT32 boot sector carries.
        let info = usize::from(u16::from_le_bytes([boot[48], boot[49]]));
        let backup = usize::from(u16::from_le_bytes([boot[50], boot[51]]));
        let mut out = vec![{
            let at = info * sector + NEXT_FREE_AT;
            at..at + 4
        }];
        if backup != 0 {
            let at = (backup + info) * sector + NEXT_FREE_AT;
            out.push(at..at + 4);
        }
        out
    }

    #[test]
    fn the_next_free_hint_is_where_the_two_deliberately_differ() {
        // The field says where a driver should begin looking for a free cluster. The
        // baseline writes cluster 2 whatever the volume holds — which on a FAT32 volume is
        // the root directory's own cluster, so a driver has to scan past it. This crate
        // writes the first cluster it did not hand out, which is what the field is for.
        //
        // Pinned in both directions, as the rounding divergence above is: a release of the
        // baseline that started writing the accurate value fails this rather than quietly
        // widening what the byte gate covers.
        if !available("mkfs.fat") {
            return;
        }
        let case = Case {
            force: Some(FatType::Fat32),
            ..Case::new(512 << 20)
        };
        let (image, bpb, sector) = baseline(&case).expect("the baseline builds a 512 MiB FAT32");
        let theirs = std::fs::read(image.path()).expect("read the baseline's image");
        let ours = ours_bytes(&case, &bpb, &sector);
        let info = usize::from(u16::from_le_bytes([sector[48], sector[49]]));
        let at = info * case.sector_size as usize + 0x1EC;
        let read = |bytes: &[u8]| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four"));

        assert_eq!(read(&theirs), 2, "the baseline no longer writes cluster 2");
        // The root directory owns cluster 2 on an empty FAT32 volume, so the first free one
        // is the next.
        assert_eq!(read(&ours), 3);
        // And the free count beside it, which both compute honestly, is compared by the
        // whole-image gate rather than excused — so the exclusion is one field wide.
        let count_at = at - 4;
        assert_eq!(
            theirs[count_at..count_at + 4],
            ours[count_at..count_at + 4],
            "the free cluster count diverged, and only the hint beside it is excused"
        );
    }

    /// Run one case's byte comparison, returning whether the baseline built it at all.
    fn compare_bytes(case: &Case) -> bool {
        match baseline(case) {
            Ok((image, bpb, sector)) => {
                identical(case, image.path(), &bpb, &sector);
                true
            }
            Err(_) => false,
        }
    }

    #[test]
    fn the_writer_is_byte_identical_to_the_baseline_at_every_type() {
        if !available("mkfs.fat") {
            return;
        }
        // Every type, both sector sizes, both table counts, pinned and automatic cluster
        // sizes, and with and without a label — which is what puts a directory entry, and so
        // a date conversion, inside the comparison.
        let mut compared = 0;
        let mut types = std::collections::BTreeSet::new();
        for &mib in SIZES_MIB {
            for sector_size in [512u32, 4096] {
                for fats in [1u32, 2] {
                    for label in [None, Some("FERROSYS")] {
                        let case = Case {
                            sector_size,
                            fats,
                            label,
                            ..Case::new(mib << 20)
                        };
                        if let Ok((image, bpb, sector)) = baseline(&case) {
                            identical(&case, image.path(), &bpb, &sector);
                            types.insert(kind_of(&bpb));
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert!(
            compared >= 40,
            "the sweep compared only {compared} images, so it is no longer exercising what \
             it claims to"
        );
        assert_eq!(
            types.len(),
            3,
            "the sweep did not reach all three FAT types; it reached {types:?}"
        );
    }

    #[test]
    fn the_writer_is_byte_identical_at_every_knob() {
        if !available("mkfs.fat") {
            return;
        }
        let mut compared = 0;
        for &mib in &[8u64, 64, 1024] {
            for cluster in [None, Some(1), Some(2), Some(8)] {
                for force in [
                    None,
                    Some(FatType::Fat12),
                    Some(FatType::Fat16),
                    Some(FatType::Fat32),
                ] {
                    let case = Case {
                        cluster,
                        force,
                        label: Some("KNOBS"),
                        // As in the geometry sweep: the root region belongs to the smaller
                        // two types, and this crate refuses a count for a volume that
                        // reaches FAT32 where the baseline warns and drops it.
                        root_entries: match force {
                            Some(FatType::Fat12 | FatType::Fat16) => Some(224),
                            _ => None,
                        },
                        ..Case::new(mib << 20)
                    };
                    if compare_bytes(&case) {
                        compared += 1;
                    }
                }
            }
        }
        assert!(
            compared >= 20,
            "the knob sweep compared only {compared} images, which is too few to be \
             exercising the parameters it names"
        );
    }

    #[test]
    fn the_writer_is_byte_identical_at_every_reserved_sector_count() {
        if !available("mkfs.fat") {
            return;
        }
        // The finest knob there is: one reserved sector moves the data region by one sector,
        // which at one sector per cluster is one cluster. On the smaller two types it walks
        // the root region and both tables across sector boundaries one at a time; on FAT32 it
        // also walks the backup boot sector and the backup information sector through every
        // placement the reserved region allows, including the counts at which there is no
        // room for one and the write must not happen.
        let mut compared = 0;
        for reserved in 1..=40u32 {
            for (volume_sectors, force, root) in [
                (4160u64, None, Some(512u32)),
                (131_072, Some(FatType::Fat32), None),
            ] {
                let case = Case {
                    cluster: Some(1),
                    reserved: Some(reserved),
                    root_entries: root,
                    force,
                    label: Some("RESERVED"),
                    ..Case::new(volume_sectors * 512)
                };
                if compare_bytes(&case) {
                    compared += 1;
                }
            }
        }
        assert!(
            compared >= 40,
            "only {compared} reserved counts were comparable, which is too few to be walking \
             the placements this sweep names"
        );
    }

    #[test]
    fn the_baselines_larger_allocation_unit_is_where_the_two_writers_part() {
        // The second deliberate divergence, after the sector-count rounding above.
        //
        // `mkfs.fat` will grow the allocation unit to 128 sectors with no byte-count limit,
        // which at a 512-byte sector is 64 KiB — past what the format's own guidance says a
        // driver handles, because more than one widely deployed driver holds a cluster's byte
        // count in sixteen bits. This crate stops at 32 KiB, so on a volume the baseline can
        // only reach a type on by exceeding that, the two have no common answer and this
        // crate refuses rather than writing a cluster a driver truncates.
        //
        // Asserted in both directions, so the divergence stays pinned to where it is: the
        // baseline reaches it, this crate refuses it, and the refusal names the cluster count
        // rather than something vague.
        if !available("mkfs.fat") {
            return;
        }
        let case = Case {
            fats: 1,
            root_entries: Some(224),
            force: Some(FatType::Fat12),
            ..Case::new(128 << 20)
        };
        let (_image, bpb, _) = baseline(&case).expect("the baseline builds this");
        assert!(
            u64::from(bpb.sectors_per_cluster) * u64::from(bpb.bytes_per_sector)
                > u64::from(ferrosys::fat::MAX_BYTES_PER_CLUSTER),
            "the baseline no longer needs an allocation unit past the cap to reach FAT12 here"
        );
        let refused = plan_layout(&request(&case, &bpb));
        assert!(
            matches!(
                refused,
                Err(ferrosys::fat::GeometryError::ClustersAboveMaximum {
                    requested: FatType::Fat12,
                    ..
                })
            ),
            "this crate must refuse a FAT12 it can only reach past the cap, and say why; it \
             said {refused:?}"
        );
    }
}

/// The checker, over images this crate wrote.
///
/// The differential gates above say this crate's bytes are the baseline's bytes. This says
/// an independent implementation agrees they are a filesystem — which is a different
/// question, and the one that still has an answer where the two writers' domains do not
/// overlap.
#[cfg(feature = "fat")]
mod written {
    use super::{EDGES, Edge, SECTOR, available, fsck_fat_clean};
    use ferrosys::TreeBuilder;
    use ferrosys::fat::{
        ClusterSize, FatType, FatTypeRequest, FormatOptions, PlanRequest, ReservedSectors,
        RootEntries, Timestamp, VolumeLabel, format_to,
    };

    /// The instant every image here is stamped with. Any value does; it is an input.
    const TIME: Timestamp = Timestamp::from_secs(1_700_000_000);

    /// Write one boundary row with this crate and hand back the file.
    fn write_edge(edge: &Edge) -> tempfile::NamedTempFile {
        let mut request = PlanRequest::new(0)
            .cluster_size(ClusterSize::Sectors(1))
            .reserved_sectors(ReservedSectors::Count(edge.reserved))
            .fats(2);
        if edge.root_entries != 0 {
            request = request.root_entries(RootEntries::Count(edge.root_entries));
        }
        if edge.force.is_some() {
            // Every forced row in the table is a FAT32 the volume is too small for, which is
            // the request the acknowledgement exists for.
            request = request.fat_type(FatTypeRequest::UndersizedFat32);
        }
        let options = FormatOptions::new(0x1234_abcd, TIME)
            .plan(request)
            .label(VolumeLabel::new("BOUNDARY").expect("a valid label"));

        let file = tempfile::NamedTempFile::new().expect("create a temporary image");
        let plan = format_to(
            TreeBuilder::new(),
            edge.total_sectors * SECTOR,
            options,
            file.as_file(),
        )
        .unwrap_or_else(|e| panic!("{}: this crate refused to write it: {e}", edge.what));
        assert_eq!(
            plan.layout().clusters,
            edge.clusters,
            "{}: the written image does not reach the row's cluster count",
            edge.what
        );
        file
    }

    #[test]
    fn the_checker_accepts_an_image_this_crate_wrote_at_every_type_boundary() {
        if !available("fsck.fat") {
            return;
        }
        for edge in EDGES {
            let image = write_edge(edge);
            let said = fsck_fat_clean(image.path()).unwrap_or_else(|e| {
                panic!(
                    "the checker rejected the {} ({} clusters) this crate wrote: {e}",
                    edge.what, edge.clusters
                )
            });
            // The checker's own count of what the volume holds, which is a second opinion on
            // the geometry rather than a restatement of the boot sector: it walks the table.
            let used = if edge.force.is_some() { 1 } else { 0 };
            assert!(
                said.contains(&format!("{used}/{} clusters", edge.clusters)),
                "{}: the checker counted something other than {used}/{} clusters. It said:\n{said}",
                edge.what,
                edge.clusters
            );
        }
    }

    #[test]
    fn the_checker_accepts_a_volume_below_the_baselines_own_floor() {
        // `mkfs.fat` refuses a volume whose data region is under 32 KiB, in a check its own
        // source calls arbitrary. This crate has no such floor: the floor here is where the
        // reserved sector, the root region, and one table leave nothing behind, and nowhere
        // above it. The checker is what says the smaller volume is still a filesystem —
        // without it, declining to reproduce the baseline's floor would be an assertion
        // about the format rather than a measurement of it.
        if !available("fsck.fat") {
            return;
        }
        let mut smallest = None;
        for sectors in [64u64, 96, 128, 192, 256] {
            let options = FormatOptions::new(0x1234_abcd, TIME).plan(
                PlanRequest::new(0)
                    .cluster_size(ClusterSize::Sectors(1))
                    .root_entries(RootEntries::Count(16))
                    .fats(1),
            );
            let file = tempfile::NamedTempFile::new().expect("create a temporary image");
            let Ok(plan) = format_to(
                TreeBuilder::new(),
                sectors * SECTOR,
                options,
                file.as_file(),
            ) else {
                continue;
            };
            let layout = *plan.layout();
            // Well under the baseline's floor, which is what makes this a measurement of the
            // gap rather than of an ordinary small volume.
            let data_bytes = u64::from(layout.data_sectors()) * u64::from(layout.bytes_per_sector);
            if data_bytes >= 32 * 1024 {
                continue;
            }
            fsck_fat_clean(file.path()).unwrap_or_else(|e| {
                panic!(
                    "the checker rejected a {sectors}-sector volume this crate wrote, whose \
                     data region is {data_bytes} bytes: {e}"
                );
            });
            assert_eq!(layout.fat_type, FatType::Fat12);
            smallest.get_or_insert(sectors);
        }
        assert!(
            smallest.is_some(),
            "no volume in the sweep landed below the baseline's floor, so this gate is no \
             longer measuring the gap it exists for"
        );
    }

    #[test]
    fn the_foreign_reader_finds_the_volume_this_crate_labelled() {
        // mtools reads the image as a plain file, with no mount and no root. An empty volume
        // has one thing in it to find, and finding it exercises the whole path: the boot
        // sector's geometry, the root region's placement, and the directory entry's bytes.
        if !available("mdir") {
            return;
        }
        for edge in EDGES {
            let image = write_edge(edge);
            let out = super::tool("mdir")
                .arg("-i")
                .arg(image.path())
                .arg("::")
                .output()
                .expect("spawn mdir");
            let said = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success(),
                "{}: mdir could not read an image this crate wrote:\n{said}",
                edge.what
            );
            assert!(
                said.contains("is BOUNDARY"),
                "{}: mdir did not find the label this crate wrote. It said:\n{said}",
                edge.what
            );
            assert!(
                said.contains("Volume Serial Number is 1234-ABCD"),
                "{}: mdir read a different serial number than this crate wrote. It said:\n{said}",
                edge.what
            );
            assert!(
                said.contains("No files"),
                "{}: mdir found something in a volume this crate wrote empty. It said:\n{said}",
                edge.what
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A populated volume this crate wrote, against the checker and the foreign reader
//
// `mkfs.fat` does not populate, so there is no differential baseline for a tree — the
// authority for directories, long names, and cluster chains is `fsck.fat`, `mtools`, and
// (in the mount tier) the kernel. These gates are that authority applied: the checker must
// find nothing wrong with the volume, and a foreign reader must find in it exactly the tree
// that was put there. Both halves matter, for the reason the foreign-image gate gives one
// level up: a reader that cannot follow a chain still reports no anomalies about it.

/// The FAT family's own tree gates.
#[cfg(feature = "fat")]
mod populated {
    use super::{available, fsck_fat_clean, tool};
    use ferrosys::fat::{
        FatType, FatTypeRequest, FormatOptions, PlanRequest, Timestamp, VolumeLabel, format_to,
    };
    use ferrosys::{Metadata, TreeBuilder};

    /// The instant every tree here is stamped with: an even second, so nothing under test is
    /// also exercising the two-second rounding the write field applies.
    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    /// One file of the fixture tree: where it goes and what is in it.
    struct Entry {
        path: &'static str,
        bytes: usize,
        /// The 8.3 short name this crate must derive, which is what a driver without
        /// long-name support sees and what `mdir`'s wide listing shows.
        short: &'static str,
    }

    /// The files, chosen so that every naming shape the writer has to handle is in one tree.
    ///
    /// Sizes are small enough that the whole tree fits the FAT12 volume, and varied enough
    /// that a chain of one cluster, a chain of several, and a file owning no cluster at all
    /// are each written.
    const FILES: &[Entry] = &[
        // Already a short name: one directory entry and no long name at all.
        Entry {
            path: "/EFI/BOOT/BOOTX64.EFI",
            bytes: 3000,
            short: "BOOTX64.EFI",
        },
        // Lower case, so the long name is what carries it.
        Entry {
            path: "/readme.txt",
            bytes: 40,
            short: "README.TXT",
        },
        // Long enough to span two long-name entries, with spaces the short name drops.
        // These two shorten to the same eight characters, so the second one placed takes a
        // numeric tail — the part of the derivation a foreign reader can see. Which of them
        // is second is decided by the sort the model applies before it places anything, and
        // a space sorts below a dot, so `Also` takes the plain name.
        Entry {
            path: "/A Long File Name Also.txt",
            bytes: 100,
            short: "ALONGFIL.TXT",
        },
        Entry {
            path: "/A Long File Name.txt",
            bytes: 100,
            short: "ALONGF~1.TXT",
        },
        // Several clusters, so a chain is followed rather than a single entry read.
        Entry {
            path: "/EFI/big.bin",
            bytes: 40_000,
            short: "BIG.BIN",
        },
        // No clusters at all, which the entry records as a zero first cluster.
        Entry {
            path: "/EFI/empty",
            bytes: 0,
            short: "EMPTY",
        },
    ];

    /// The directories the tree needs, deepest last.
    const DIRECTORIES: &[&str] = &["/EFI", "/EFI/BOOT"];

    /// The bytes of the file at `path`, derived from the path so that a file written into
    /// the wrong chain reads back as some other file's contents rather than as zeros.
    fn contents(entry: &Entry) -> Vec<u8> {
        let seed = entry.path.bytes().fold(7u8, |a, b| a.wrapping_add(b));
        (0..entry.bytes)
            .map(|i| seed.wrapping_add((i % 251) as u8))
            .collect()
    }

    /// The fixture tree as a source.
    fn tree() -> TreeBuilder {
        let file = Metadata::new(0o644, TIME);
        let dir = Metadata::new(0o755, TIME);
        let mut source = TreeBuilder::new();
        for path in DIRECTORIES {
            source = source.directory(path.as_bytes().to_vec(), dir);
        }
        for entry in FILES {
            source = source.file(entry.path.as_bytes().to_vec(), contents(entry), file);
        }
        source
    }

    /// Write the fixture tree into a volume of `mib` mebibytes at `request`, and hand back
    /// the file.
    fn write_tree(mib: u64, request: FatTypeRequest) -> tempfile::NamedTempFile {
        let options = FormatOptions::new(0x1234_abcd, TIME)
            .label(VolumeLabel::new("TREE").expect("a valid label"))
            .plan(PlanRequest::new(0).fat_type(request));
        let file = tempfile::NamedTempFile::new().expect("create a temporary image");
        let plan = format_to(tree(), mib << 20, options, file.as_file())
            .unwrap_or_else(|e| panic!("this crate refused to write the tree: {e}"));
        // The tree is root-owned with conventional modes and no links, so the format had
        // nothing to drop — which is what keeps these gates about bytes rather than policy.
        assert!(
            plan.fidelity().is_faithful(),
            "the fixture tree lost something, so these gates are no longer only about the \
             writer: {}",
            plan.fidelity().to_table()
        );
        file
    }

    /// The three volumes, one per type, and what to call each in a failure.
    const VOLUMES: &[(&str, u64, FatType)] = &[
        ("fat12", 2, FatType::Fat12),
        ("fat16", 64, FatType::Fat16),
        ("fat32", 512, FatType::Fat32),
    ];

    #[test]
    fn the_checker_accepts_a_tree_this_crate_wrote_at_every_type() {
        if !available("fsck.fat") {
            return;
        }
        for &(what, mib, kind) in VOLUMES {
            let image = write_tree(mib, FatTypeRequest::Exactly(kind));
            fsck_fat_clean(image.path()).unwrap_or_else(|e| {
                panic!("the checker rejected a populated {what} volume this crate wrote: {e}")
            });
        }
    }

    /// Every path `mdir` finds, in the bare form it lists them — full paths, a directory
    /// marked by a trailing slash — sorted so the comparison is about the tree rather than
    /// about the order a directory happens to be laid out in.
    fn listing(image: &std::path::Path) -> Vec<String> {
        let out = tool("mdir")
            .args(["-/", "-b", "-i"])
            .arg(image)
            .arg("::")
            .output()
            .expect("spawn mdir");
        assert!(
            out.status.success(),
            "mdir refused an image this crate wrote:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut paths: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|line| line.trim_end_matches('/').to_string())
            .filter(|line| !line.is_empty())
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn the_foreign_reader_enumerates_the_tree_this_crate_wrote() {
        if !available("mdir") {
            return;
        }
        let mut want: Vec<String> = DIRECTORIES
            .iter()
            .map(|p| format!("::{p}"))
            .chain(FILES.iter().map(|e| format!("::{}", e.path)))
            .collect();
        want.sort();

        for &(what, mib, kind) in VOLUMES {
            let image = write_tree(mib, FatTypeRequest::Exactly(kind));
            assert_eq!(
                listing(image.path()),
                want,
                "{what}: a second implementation does not find the tree this crate wrote"
            );
        }
    }

    #[test]
    fn the_foreign_reader_reads_back_every_file_this_crate_wrote() {
        if !available("mtype") {
            return;
        }
        // The half the enumeration cannot answer: a directory entry may name the right
        // length and the wrong chain, and a listing would still be exactly right.
        for &(what, mib, kind) in VOLUMES {
            let image = write_tree(mib, FatTypeRequest::Exactly(kind));
            for entry in FILES {
                let out = tool("mtype")
                    .arg("-i")
                    .arg(image.path())
                    .arg(format!("::{}", entry.path))
                    .output()
                    .expect("spawn mtype");
                assert!(
                    out.status.success(),
                    "{what}: mtype could not read {}:\n{}",
                    entry.path,
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(
                    out.stdout,
                    contents(entry),
                    "{what}: {} read back as something else, so its entry names the wrong \
                     chain or its chain holds the wrong bytes",
                    entry.path
                );
            }
        }
    }

    #[test]
    fn the_short_names_this_crate_derives_are_the_ones_a_foreign_reader_shows() {
        if !available("mdir") {
            return;
        }
        // The numeric tail is the part of the derivation that has to be deterministic, and
        // this is where a second implementation says what it sees. `mdir`'s wide listing
        // prints the short name beside the long one.
        let image = write_tree(64, FatTypeRequest::Exactly(FatType::Fat16));
        let out = tool("mdir")
            .args(["-/", "-i"])
            .arg(image.path())
            .arg("::")
            .output()
            .expect("spawn mdir");
        assert!(out.status.success(), "mdir refused the image");
        let said = String::from_utf8_lossy(&out.stdout);
        for entry in FILES {
            let (base, ext) = entry.short.split_once('.').unwrap_or((entry.short, ""));
            // mdir pads the base to eight, separates with a space, and pads the extension to
            // three — so the name is matched as the pair it prints rather than as the dotted
            // form a person writes.
            let shown = format!("{base:<8} {ext:<3}");
            assert!(
                said.contains(&shown),
                "the short name for {} is not {:?} in a foreign reader's listing. mdir \
                 said:\n{said}",
                entry.path,
                entry.short
            );
        }

        // A name that is already a short name gets no long-name entry, and one that is not
        // does. `mdir` prints the long name in a column of its own where there is one, so
        // its absence is the observation — and it is the observation, because the whole
        // reason the writer never uses the case-flag byte is that a name carried only there
        // is one some readers do not show.
        let line = |short: &str| {
            let (base, ext) = short.split_once('.').unwrap_or((short, ""));
            let shown = format!("{base:<8} {ext:<3}");
            said.lines()
                .find(|l| l.starts_with(&shown))
                .unwrap_or_else(|| panic!("no line for {short}. mdir said:\n{said}"))
                .to_string()
        };
        assert!(
            !line("BOOTX64.EFI").contains("BOOTX64.EFI"),
            "a name that is already its own short name was given a long name as well"
        );
        assert!(
            line("README.TXT").ends_with("readme.txt"),
            "the lower-case name was not stored as a long name, so a reader that ignores \
             the reserved case byte would show it as README.TXT"
        );

        // And the label, which shares the root directory with the tree.
        assert!(
            said.contains("Volume in drive : is TREE"),
            "mdir did not find the label beside the tree. It said:\n{said}"
        );
    }

    #[test]
    fn the_read_back_gate_notices_a_file_pointed_at_the_wrong_chain() {
        if !available("mtype") {
            return;
        }
        // The control the gate above is measured against. A directory entry may name the
        // right length and the wrong first cluster, and an enumeration would still be
        // exactly right — so the read-back has to be the thing that catches it, and this is
        // where that claim is tested rather than assumed.
        let options = FormatOptions::new(0x1234_abcd, TIME)
            .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16)));
        let image = tempfile::NamedTempFile::new().expect("create a temporary image");
        let plan = format_to(tree(), 64 << 20, options, image.as_file()).expect("write the tree");
        let layout = plan.layout();

        // The root's first entry is `A Long File Name Also.txt`, preceded by the long-name
        // entries carrying its name. Point it at the chain of the file after it instead.
        let root = u64::from(
            layout
                .root_dir_start_sector()
                .expect("a FAT16 volume has a root region"),
        ) * u64::from(layout.bytes_per_sector);
        let mut entries = super::read_at(image.path(), root, 32 * 16);
        let short = entries
            .chunks_exact(32)
            .position(|e| e.starts_with(b"ALONGFIL"))
            .expect("the short entry is in the first sixteen slots");
        let at = short * 32 + 26;
        let cluster = u16::from_le_bytes([entries[at], entries[at + 1]]);
        entries[at..at + 2].copy_from_slice(&(cluster + 1).to_le_bytes());
        super::write_at(
            image.path(),
            root + (short * 32) as u64 + 26,
            &entries[at..at + 2],
        );

        let damaged = FILES
            .iter()
            .find(|e| e.path == "/A Long File Name Also.txt")
            .expect("the fixture holds the file the short name belongs to");
        let out = tool("mtype")
            .arg("-i")
            .arg(image.path())
            .arg(format!("::{}", damaged.path))
            .output()
            .expect("spawn mtype");
        // Exactly what the gate above asserts, and it must now be false — whether because
        // the read failed or because it returned some other file's bytes.
        assert!(
            !(out.status.success() && out.stdout == contents(damaged)),
            "a file pointed at the wrong cluster read back as its own contents, so the \
             read-back gate cannot tell a correct chain from an incorrect one"
        );
    }

    #[test]
    fn a_tree_that_fills_a_directory_past_one_cluster_is_read_back_whole() {
        if !available("fsck.fat") || !available("mdir") {
            return;
        }
        // A directory long enough to need a chain rather than a single cluster, which is
        // where a writer that placed only the first cluster's worth would stop being caught
        // by any of the gates above.
        let file = Metadata::new(0o644, TIME);
        let mut source =
            TreeBuilder::new().directory(b"/many".to_vec(), Metadata::new(0o755, TIME));
        let count = 300;
        for i in 0..count {
            // A long name each, so every entry costs two slots and the directory is well
            // past one cluster however large a cluster the planner picks.
            source = source.file(
                format!("/many/entry number {i}.dat").into_bytes(),
                format!("{i}").into_bytes(),
                file,
            );
        }
        let options = FormatOptions::new(0x1234_abcd, TIME)
            .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16)));
        let image = tempfile::NamedTempFile::new().expect("create a temporary image");
        format_to(source, 64 << 20, options, image.as_file()).expect("write the tree");

        fsck_fat_clean(image.path())
            .unwrap_or_else(|e| panic!("the checker rejected a multi-cluster directory: {e}"));
        let found = listing(image.path());
        assert_eq!(
            found.len(),
            count + 1,
            "a foreign reader found {} of the {} entries plus the directory holding them",
            found.len(),
            count
        );
    }
}

/// The foreign-image gate, run backwards: an image the baseline built and a foreign tool
/// populated, read by this crate.
///
/// Every other gate here formats with ferrosys and then checks the result, which exercises
/// the reader against exactly one writer's output — its own. That is the shape of setup in
/// which a reader can be wrong about the format in the same direction the writer is and
/// nothing notices. This is the other direction: `mkfs.fat` builds the volume, `mcopy`
/// fills it, and this crate's reader must both find nothing wrong with it *and* read what
/// is in it.
///
/// **Both halves, and the reason is that either alone misses a whole class.** A reader that
/// cannot follow a chain still reports no anomalies about it, so asserting only that the
/// scan is clean would pass a reader that read nothing. And an enumeration can be exactly
/// right while every file's contents come from the wrong cluster, so asserting only the
/// names would pass a reader that resolves them wrongly. The negative controls at the end
/// are what say the gate would notice either.
///
/// [`MATRIX`] is the set of volumes it runs over, and the two shapes no row of it reaches on
/// its own — a root region with no room left and a directory wider than one cluster — have
/// gates of their own, since they are the two ways a FAT directory can end.
#[cfg(feature = "fat")]
mod foreign {
    use super::util::{available, fsck_fat_clean, tool};
    use super::{Bpb, FatKind, read_at};
    use ferrosys::fat::{FatType, OpenOptions, Reader, ShortNameCharset, Storage};
    use ferrosys::{FsTree, NodeKind, ReadPolicy, TreeEntry, TreeError};
    use std::fs::File;
    use std::io::Cursor;
    use std::path::Path;

    /// One volume the baseline is asked to build.
    struct Volume {
        /// What this row is, quoted in every failure so that it names the volume rather
        /// than a sector count.
        what: &'static str,
        bytes_per_sector: u32,
        total_sectors: u64,
        fats: u32,
        /// Root slots to ask for, or zero to leave the count to the formatter — which is
        /// how FAT32 is asked, the field being zero on that type.
        root_entries: u32,
        /// The type to force with `-F`, where the formatter's own search does not reach
        /// the row unaided. FAT12 and FAT16 are left to it, so the type this crate derives
        /// is held against a decision it had no part in.
        force: Option<u32>,
        kind: FatKind,
    }

    impl Volume {
        /// This crate's own name for the row's type.
        fn fat_type(&self) -> FatType {
            match self.kind {
                FatKind::Fat12 => FatType::Fat12,
                FatKind::Fat16 => FatType::Fat16,
                FatKind::Fat32 => FatType::Fat32,
            }
        }

        /// Bytes the volume spans, which is what its image file is sized to.
        fn bytes(&self) -> u64 {
            self.total_sectors * u64::from(self.bytes_per_sector)
        }

        /// Bytes in one allocation unit. Every row is one sector per cluster, which is what
        /// makes this the sector size and what makes the FAT32 rows as large as they are.
        fn bytes_per_cluster(&self) -> u32 {
            self.bytes_per_sector
        }
    }

    /// The matrix: three types, both ends of the sector-size range, and both table counts.
    ///
    /// The rows are a covering array rather than a cross product. Every *pair* of values
    /// across the three dimensions appears in some row, which is six rows where the cross
    /// product is twelve, and the pair is the unit worth covering because what a reader
    /// gets wrong here is arithmetic that multiplies two dimensions together: a table's
    /// span is its sector count times its copies, every region's offset is both, and a
    /// 12-bit entry straddles a sector boundary at a position the sector size decides —
    /// which is a row's size and not only its type, so
    /// [`the_fat12_rows_reach_an_entry_that_straddles_a_sector`] holds the two FAT12 rows
    /// above it.
    ///
    /// 512 and 4096 are the ends of the range the format permits rather than two points
    /// inside it, on the same reasoning that has the boundary table run on exact cluster
    /// counts.
    ///
    /// One sector per cluster throughout, which is also what makes the FAT32 rows the size
    /// they are: 65525 clusters is the floor of that type, so the smallest FAT32 at
    /// 4096-byte sectors describes 261 MiB. The formatter writes the reserved sectors and
    /// the tables and leaves the data region a hole, so it costs a few hundred kilobytes on
    /// disk — and it is why nothing here reads a volume into memory.
    const MATRIX: &[Volume] = &[
        Volume {
            what: "FAT12, 512-byte sectors, one table",
            bytes_per_sector: 512,
            total_sectors: 2048,
            fats: 1,
            root_entries: 512,
            force: None,
            kind: FatKind::Fat12,
        },
        Volume {
            // Sized past the first straddling entry rather than to match its 512-byte
            // counterpart, and held there by
            // `the_fat12_rows_reach_an_entry_that_straddles_a_sector`.
            what: "FAT12, 4096-byte sectors, two tables",
            bytes_per_sector: 4096,
            total_sectors: 3072,
            fats: 2,
            root_entries: 128,
            force: None,
            kind: FatKind::Fat12,
        },
        Volume {
            what: "FAT16, 512-byte sectors, two tables",
            bytes_per_sector: 512,
            total_sectors: 40000,
            fats: 2,
            root_entries: 512,
            force: None,
            kind: FatKind::Fat16,
        },
        Volume {
            what: "FAT16, 4096-byte sectors, one table",
            bytes_per_sector: 4096,
            total_sectors: 20000,
            fats: 1,
            root_entries: 128,
            force: None,
            kind: FatKind::Fat16,
        },
        Volume {
            what: "FAT32, 512-byte sectors, two tables",
            bytes_per_sector: 512,
            total_sectors: 66592,
            fats: 2,
            root_entries: 0,
            force: Some(32),
            kind: FatKind::Fat32,
        },
        Volume {
            what: "FAT32, 4096-byte sectors, one table",
            bytes_per_sector: 4096,
            total_sectors: 66592,
            fats: 1,
            root_entries: 0,
            force: Some(32),
            kind: FatKind::Fat32,
        },
    ];

    /// The row the single-volume gates below run against.
    ///
    /// FAT16 with two tables at 512-byte sectors is the one row that can carry every damage
    /// class at once: a table entry is a plain sixteen-bit cluster number, there is a second
    /// copy for the first to diverge from, and the root is a fixed region whose slots can be
    /// walked without following a chain to reach them.
    const REPRESENTATIVE: &Volume = &MATRIX[2];

    /// The rows the multi-cluster directory gate runs over: one at each sector size.
    ///
    /// A cluster is a sector across the matrix, so the sector size is what decides how many
    /// entries fit in one — and a directory is the one object here whose own contents are
    /// reached by following a chain rather than by arithmetic on the geometry.
    const CHAINED: &[&Volume] = &[&MATRIX[0], &MATRIX[3]];

    /// The rows whose root region is filled to its last slot.
    ///
    /// FAT32 is absent by construction rather than by omission: its root is a cluster chain
    /// like any other directory and grows until the volume is full, so it has no capacity to
    /// reach. The two here are the two types that have one, at both sector sizes, because
    /// the capacity is stated in slots and the region is measured in sectors.
    const FILLED: &[Volume] = &[
        Volume {
            what: "a FAT12 root region filled to its last slot",
            bytes_per_sector: 512,
            total_sectors: 2048,
            fats: 2,
            root_entries: 16,
            force: None,
            kind: FatKind::Fat12,
        },
        Volume {
            what: "a FAT16 root region filled to its last slot, at 4096-byte sectors",
            bytes_per_sector: 4096,
            total_sectors: 20000,
            fats: 1,
            root_entries: 128,
            force: None,
            kind: FatKind::Fat16,
        },
    ];

    /// The bytes of `PAYLOAD.BIN`, the fixture's chain-following case.
    ///
    /// Long enough to span several clusters at every row: a cluster is a sector here, so at
    /// the wide end of the matrix a file has to exceed 4096 bytes before following its chain
    /// is any different from reading one entry. The pattern repeats with period 251, which
    /// shares no factor with any cluster size in the matrix, so a chain followed in the
    /// wrong order reads back as something other than itself.
    fn payload() -> Vec<u8> {
        (0..40960u32).map(|k| (k % 251) as u8).collect()
    }

    /// The tree every case here writes with mtools, as (path, contents).
    ///
    /// Each name is a shape a reader has to handle differently. `README.TXT` is already a
    /// short name and takes no long-name entries at all; `A Long File Name.txt` needs them
    /// and pairs with a numeric-tail short name; `notes.txt` is lower case, which is where
    /// mtools may reach for the reserved case byte this crate never writes and must still
    /// read. The `EFI/BOOT` path is the one a real volume of this family carries; the five
    /// levels below it are depth for its own sake, since a walk that recurses one level less
    /// than it should still returns a tree that looks entirely plausible.
    fn fixture() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("README.TXT", b"already a short name\n".to_vec()),
            (
                "A Long File Name.txt",
                b"a name that needs long-name entries\n".to_vec(),
            ),
            ("notes.txt", b"lower case\n".to_vec()),
            ("EFI/BOOT/BOOTX64.EFI", b"MZ\x90\x00".to_vec()),
            ("A/B/C/D/E/DEEP.TXT", b"five levels down\n".to_vec()),
            ("PAYLOAD.BIN", payload()),
        ]
    }

    /// Every directory the fixture's paths imply, parents before children.
    ///
    /// Derived rather than listed, because it is needed twice — once to create the
    /// directories and once to say what a walk should find — and two lists of the same thing
    /// drift the moment a path is added to one of them.
    fn directories() -> Vec<String> {
        let mut dirs: Vec<String> = Vec::new();
        for (path, _) in fixture() {
            let components: Vec<&str> = path.split('/').collect();
            let mut prefix = String::new();
            // Every component but the last, which is the file itself.
            for part in &components[..components.len() - 1] {
                prefix.push('/');
                prefix.push_str(part);
                if !dirs.contains(&prefix) {
                    dirs.push(prefix.clone());
                }
            }
        }
        dirs
    }

    /// The label every volume here is built with, which is what a real one carries.
    const LABEL: &str = "FERROSYS";

    /// Build one row's volume with the baseline, empty.
    fn built(row: &Volume) -> tempfile::NamedTempFile {
        let image = tempfile::NamedTempFile::new().expect("create a temporary image");
        image
            .as_file()
            .set_len(row.bytes())
            .expect("size the temporary image");
        let mut cmd = tool("mkfs.fat");
        cmd.arg("--invariant")
            .args(["-s", "1"])
            .args(["-n", LABEL])
            .args(["-S", &row.bytes_per_sector.to_string()])
            .args(["-f", &row.fats.to_string()]);
        if row.root_entries != 0 {
            cmd.args(["-r", &row.root_entries.to_string()]);
        }
        if let Some(bits) = row.force {
            cmd.args(["-F", &bits.to_string()]);
        }
        let out = cmd.arg(image.path()).output().expect("spawn mkfs.fat");
        assert!(
            out.status.success(),
            "the baseline could not build {}: {}",
            row.what,
            String::from_utf8_lossy(&out.stderr)
        );
        image
    }

    /// Open a row's image from the file rather than from a copy of it in memory.
    ///
    /// The matrix is what rules the copy out: the widest FAT32 row describes 261 MiB
    /// against a few hundred kilobytes of actual content, and a `Vec` of it would be the
    /// whole 261. Reading through a `File` is the shape a caller uses anyway.
    fn opened(row: &Volume, image: &Path) -> Reader<File> {
        let file = File::open(image).expect("open the image");
        // Strictly, which is itself the assertion: a volume a conformant foreign
        // implementation wrote is one a strict read accepts without argument. A refusal
        // here is either a real difference between the two writers or a rule this crate
        // has stated too narrowly, and both are worth a red gate.
        Reader::open(file)
            .unwrap_or_else(|e| panic!("{}: a strict open refused a baseline image: {e}", row.what))
    }

    /// The cluster count a row actually reaches, which is the formatter's answer to the
    /// parameters rather than this test's arithmetic on them.
    fn clusters_of(row: &Volume) -> u32 {
        let image = built(row);
        opened(row, image.path()).layout().clusters
    }

    /// Build one row's volume with the baseline and fill it with [`fixture`] using mtools.
    fn populated(row: &Volume) -> tempfile::NamedTempFile {
        let image = built(row);

        // The directories first: `mcopy` will not create a path that is not there. One
        // invocation, in the order [`directories`] returns them, since `mmd` creates each in
        // turn and a child cannot be created before its parent.
        let status = tool("mmd")
            .arg("-i")
            .arg(image.path())
            .args(directories().iter().map(|dir| format!("::{dir}")))
            .status()
            .expect("spawn mmd");
        assert!(status.success(), "mmd could not create the fixture's tree");

        let work = tempfile::Builder::new()
            .prefix("fixture")
            .tempdir()
            .expect("create the payload directory");
        for (path, body) in fixture() {
            let name = path.rsplit('/').next().expect("a file name");
            let local = work.path().join(name);
            std::fs::write(&local, &body).expect("write the payload");
            let status = tool("mcopy")
                .arg("-i")
                .arg(image.path())
                .arg(&local)
                .arg(format!("::/{path}"))
                .status()
                .expect("spawn mcopy");
            assert!(status.success(), "mcopy could not write {path}");
        }
        image
    }

    fn bytes_of(path: &Path) -> Vec<u8> {
        std::fs::read(path).expect("read the image")
    }

    fn tools_present() -> bool {
        available("mkfs.fat") && available("mmd") && available("mcopy")
    }

    #[test]
    fn the_reader_finds_nothing_wrong_with_an_image_the_baseline_built() {
        if !tools_present() {
            return;
        }
        for row in MATRIX {
            let image = populated(row);
            let mut reader = opened(row, image.path());
            let layout = *reader.layout();

            // The geometry the row asked for is the geometry that came back. Every one of
            // these is a parameter the formatter was given rather than one it chose, so a
            // mismatch says the reader recovered the volume wrongly and not that the
            // baseline built something else.
            assert_eq!(
                layout.bytes_per_sector, row.bytes_per_sector,
                "{}",
                row.what
            );
            assert_eq!(layout.fats, row.fats, "{}", row.what);
            assert_eq!(layout.root_entries, row.root_entries, "{}", row.what);

            // And the type, against two statements that are not this crate's: the row's own
            // expectation, and `BS_FilSysType` — the field no driver reads, which is the
            // formatter recording the decision it made. Where all three agree, the type was
            // derived from the geometry twice by two implementations.
            let bpb = Bpb::parse(&read_at(image.path(), 0, 512));
            assert_eq!(
                &bpb.advertised,
                row.kind.advertised(),
                "{}: the baseline advertised a type the row does not expect",
                row.what
            );
            assert_eq!(layout.fat_type, row.fat_type(), "{}", row.what);

            reader
                .verify_tables()
                .unwrap_or_else(|e| panic!("{}: {e}", row.what));
            let report = reader.scan();
            assert!(
                report.is_clean(),
                "{}: the scan faulted an image the baseline built and mtools filled:\n{}",
                row.what,
                report.to_report().to_table()
            );
        }
    }

    #[test]
    fn the_reader_reads_what_a_foreign_writer_put_there() {
        if !tools_present() {
            return;
        }
        for row in MATRIX {
            let image = populated(row);
            let mut reader = opened(row, image.path());

            // The enumeration: every path the fixture wrote, and the directories those paths
            // needed, and nothing else.
            let mut paths: Vec<String> = reader
                .walk()
                .unwrap_or_else(|e| panic!("{}: the walk failed: {e}", row.what))
                .into_iter()
                .map(|e| String::from_utf8_lossy(&e.path).into_owned())
                .collect();
            paths.sort();
            let mut expected: Vec<String> = fixture()
                .iter()
                .map(|(p, _)| format!("/{p}"))
                .chain(directories())
                .collect();
            expected.sort();
            assert_eq!(paths, expected, "{}", row.what);

            // And the contents, which is the half an enumeration cannot check: a directory
            // entry may name the right length and the wrong first cluster and the listing
            // would still be exactly right.
            for (path, body) in fixture() {
                let node = reader
                    .lookup(format!("/{path}").as_bytes())
                    .unwrap_or_else(|e| panic!("{}: /{path}: {e}", row.what));
                assert_eq!(u64::from(node.size), body.len() as u64, "{path}");
                assert_eq!(
                    reader.read_data(&node).expect("read"),
                    body,
                    "{}: /{path} read back as something else",
                    row.what
                );
            }
        }
    }

    #[test]
    fn the_short_names_a_foreign_writer_chose_are_read_as_it_wrote_them() {
        if !tools_present() || !available("mdir") {
            return;
        }
        let image = populated(REPRESENTATIVE);
        let mut reader = opened(REPRESENTATIVE, image.path());
        let root = reader.root();
        let entries = reader.read_dir(&root).expect("read the root");
        let by_name = |n: &str| {
            entries
                .iter()
                .find(|e| e.name == n.as_bytes())
                .unwrap_or_else(|| panic!("{n} is absent"))
        };

        // A name that is already its own short name needs no long-name entries, and mtools
        // writes none for it — so the short name and the name are the same eleven bytes.
        let readme = by_name("README.TXT");
        assert_eq!(readme.short_name, b"README.TXT");
        assert!(!readme.has_long_name);

        // A long name pairs with a numeric-tail short name. Which tail mtools chose is its
        // decision and not something this crate reproduces; that there *is* one, and that
        // the reader hands back both, is the property.
        let long = by_name("A Long File Name.txt");
        assert!(long.has_long_name);
        assert_ne!(long.short_name, long.name);
        assert!(
            long.short_name.contains(&b'~'),
            "the foreign writer's short name carries no numeric tail: {}",
            String::from_utf8_lossy(&long.short_name)
        );

        // And what mdir says, which is a second implementation reading the same bytes.
        let out = tool("mdir")
            .args(["-/", "-b", "-i"])
            .arg(image.path())
            .arg("::")
            .output()
            .expect("spawn mdir");
        assert!(out.status.success(), "mdir refused the image");
        let listing = String::from_utf8_lossy(&out.stdout);
        for (path, _) in fixture() {
            assert!(
                listing.contains(&format!("::/{path}")),
                "mdir does not list /{path}:\n{listing}"
            );
        }
    }

    #[test]
    fn a_lower_case_name_reads_the_same_whichever_writer_chose_how_to_store_it() {
        // mtools may store a lower-case 8.3 name in the reserved case byte rather than in
        // long-name entries, which is precisely the ambiguity this crate's writer avoids by
        // never using that byte. Reading is the opposite call: whatever the foreign writer
        // chose, the name it meant is the name that comes back.
        if !tools_present() {
            return;
        }
        for row in MATRIX {
            let image = populated(row);
            let mut reader = opened(row, image.path());
            let node = reader
                .lookup(b"/notes.txt")
                .unwrap_or_else(|e| panic!("{}: {e}", row.what));
            assert_eq!(
                reader.read_data(&node).expect("read"),
                b"lower case\n",
                "{}",
                row.what
            );
        }
    }

    #[test]
    fn the_shared_surface_drains_an_image_no_part_of_this_crate_wrote() {
        // The extraction surface, over a foreign volume: what a sink actually calls, driven
        // through the trait rather than through the family's own reader.
        if !tools_present() {
            return;
        }
        let image = populated(REPRESENTATIVE);
        let mut reader = opened(REPRESENTATIVE, image.path());

        let mut read: Option<Vec<u8>> = None;
        let mut dirs = 0usize;
        reader
            .walk_tree::<TreeError, _>(|tree, entry: TreeEntry<_>| {
                match entry.kind {
                    NodeKind::Directory => dirs += 1,
                    NodeKind::File { size } if entry.path == b"/PAYLOAD.BIN" => {
                        let mut out = Vec::new();
                        let mut buf = [0u8; 97]; // not a divisor of the cluster size
                        let mut offset = 0u64;
                        while offset < size {
                            let filled = tree.read_bytes(&entry.node, offset, &mut buf)?;
                            if filled == 0 {
                                break;
                            }
                            out.extend_from_slice(&buf[..filled]);
                            offset += filled as u64;
                        }
                        read = Some(out);
                    }
                    _ => {}
                }
                Ok(())
            })
            .expect("the walk succeeds");
        // Every directory the fixture implied, and the root, which no path names.
        assert_eq!(dirs, directories().len() + 1);
        assert_eq!(read.expect("/PAYLOAD.BIN was read"), payload());
    }

    /// The controls: each damage is applied to an image the gate above accepts, so a
    /// failure is attributable to the damage rather than to the fixture — and a control
    /// that passes anyway is a gate that would not have noticed the defect it stands for.
    #[test]
    fn each_damage_class_is_observed_failing_the_gate() {
        if !tools_present() {
            return;
        }
        let clean = bytes_of(populated(REPRESENTATIVE).path());
        let layout = {
            let mut reader = Reader::open(Cursor::new(clean.as_slice())).expect("open");
            assert!(reader.scan().is_clean(), "the fixture is not clean");
            *reader.layout()
        };
        let at = |sector: u32| sector as usize * layout.bytes_per_sector as usize;
        let root = at(layout.root_dir_start_sector().expect("a root region"));

        // The root slot of the first file long enough to hold a chain, so a damage that
        // needs one addresses a cluster the foreign writer really allocated rather than a
        // number this test guessed. The 0x0F attribute is a long-name slot, which carries
        // no size and no cluster of its own.
        let multi_cluster_slot = |bytes: &[u8]| -> usize {
            for slot in 0..layout.root_entries as usize {
                let off = root + slot * 32;
                let size = u32::from_le_bytes(bytes[off + 28..off + 32].try_into().unwrap());
                if bytes[off + 11] != 0x0F && size > layout.bytes_per_cluster() {
                    return off;
                }
            }
            panic!("the fixture holds no multi-cluster file in the root");
        };

        /// One damage: what it stands for, and how it is applied.
        type Damage<'a> = (&'a str, &'a dyn Fn(&mut [u8]));
        let cases: &[Damage<'_>] = &[
            // The chain resolves elsewhere: the enumeration stays exactly right and every
            // file's contents come from the wrong place. This is what the read-back half of
            // the gate exists for.
            ("a first cluster moved", &|bytes: &mut [u8]| {
                let off = multi_cluster_slot(bytes);
                let first = u16::from_le_bytes(bytes[off + 26..off + 28].try_into().unwrap());
                bytes[off + 26..off + 28].copy_from_slice(&(first + 1).to_le_bytes());
            }),
            // The mirror, which is what a FAT volume has instead of a checksum.
            ("a table copy diverging", &|bytes: &mut [u8]| {
                let second = at(layout.fat_start_sector(1).expect("two tables"));
                bytes[second + 8] ^= 0xFF;
            }),
            // A chain that never ends, which an unbounded follower would loop on forever.
            // Pointed at itself rather than back at a fixed cluster number: which clusters
            // the foreign writer chose is its decision, and a self-loop is the one form that
            // is a loop whatever it chose.
            ("a chain pointing at itself", &|bytes: &mut [u8]| {
                let off = multi_cluster_slot(bytes);
                let first = u16::from_le_bytes(bytes[off + 26..off + 28].try_into().unwrap());
                for copy in 0..layout.fats {
                    let entry =
                        at(layout.fat_start_sector(copy).expect("a table")) + 2 * first as usize;
                    bytes[entry..entry + 2].copy_from_slice(&first.to_le_bytes());
                }
            }),
        ];

        for (what, damage) in cases {
            let mut bytes = clean.clone();
            damage(&mut bytes);
            let strict = Reader::open(Cursor::new(bytes.as_slice()))
                .and_then(|mut r| r.walk().map(|entries| (r.verify_tables(), entries)));
            let mut lenient = Reader::open_with(
                Cursor::new(bytes.as_slice()),
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .expect("a lenient open still succeeds");
            let scan = lenient.scan();

            let strict_refused = match strict {
                Err(_) => true,
                Ok((tables, entries)) => {
                    tables.is_err()
                        || entries.iter().any(|e| {
                            matches!(e.node.storage, Storage::Chain(_))
                                && lenient.read_data(&e.node).is_err()
                        })
                }
            };
            assert!(
                !scan.is_clean() || strict_refused,
                "{what}: the gate did not notice the damage. The scan said:\n{}",
                scan.to_report().to_table()
            );
        }
    }

    #[test]
    fn a_named_code_page_changes_no_name_a_baseline_image_carries() {
        // Every name mtools wrote here is ASCII, so naming a page must be inert. This is
        // the control on the charset itself: a table applied to bytes below 0x80 would
        // rewrite names the volume records exactly.
        if !tools_present() {
            return;
        }
        let image = populated(REPRESENTATIVE);
        let bytes = bytes_of(image.path());
        let verbatim = {
            let mut r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
            let mut names: Vec<Vec<u8>> = r
                .walk()
                .expect("walk")
                .into_iter()
                .map(|e| e.path)
                .collect();
            names.sort();
            names
        };
        for charset in [
            ShortNameCharset::Cp437,
            ShortNameCharset::Cp850,
            ShortNameCharset::Cp852,
            ShortNameCharset::Cp865,
            ShortNameCharset::Cp866,
        ] {
            let mut r = Reader::open_with(
                Cursor::new(bytes.as_slice()),
                &OpenOptions::new().charset(charset),
            )
            .expect("open");
            let mut names: Vec<Vec<u8>> = r
                .walk()
                .expect("walk")
                .into_iter()
                .map(|e| e.path)
                .collect();
            names.sort();
            assert_eq!(
                names,
                verbatim,
                "{} changed an ASCII name",
                charset.as_str()
            );
        }
    }

    #[test]
    fn the_label_a_foreign_formatter_wrote_is_the_label_this_crate_reads() {
        // A volume label has two homes: an entry in the root carrying the volume-identifier
        // attribute, which is what a driver and `fatlabel` read, and a copy in the boot
        // sector that nothing keeps in step with it. The baseline writes both on every type,
        // so what this asserts is that the two implementations agree on the one that counts
        // — and the enumerations above are what say that entry is not handed back as though
        // it were a file, which is the way a volume label goes wrong.
        if !available("mkfs.fat") {
            return;
        }
        for row in MATRIX {
            let image = built(row);
            let mut reader = opened(row, image.path());
            assert_eq!(
                reader.volume_label().expect("read the label").as_deref(),
                Some(LABEL.as_bytes()),
                "{}: the label the baseline wrote is not the one that came back",
                row.what
            );
        }
    }

    #[test]
    fn the_fat12_rows_reach_an_entry_that_straddles_a_sector() {
        // A claim about the matrix rather than about the reader, and the reason it is
        // asserted is that nothing else would notice it stopping being true. A 12-bit entry
        // occupies a byte and a half, so one entry in every pair of sectors begins in the
        // last byte of one and ends in the first of the next — which is why the reader holds
        // a two-sector window over the table at all. The scan reads every entry of every
        // table looking for clusters nothing reaches, so it crosses those boundaries on any
        // FAT12 volume large enough to have them, and a mis-read straddling entry surfaces
        // as a lost cluster on a volume that has none.
        //
        // "Large enough" is the part that can quietly stop holding: at 4096-byte sectors the
        // first such entry is 2730, so a volume of a few thousand clusters covers this and a
        // volume of two thousand does not, and both look equally like a FAT12 row.
        if !available("mkfs.fat") {
            return;
        }
        for row in MATRIX.iter().filter(|row| row.kind == FatKind::Fat12) {
            // Entry `n` begins at byte `n + n / 2`, so it straddles where that is one below
            // a multiple of the sector size; the lowest such entry is `(2s - 1) / 3`.
            let straddling = (2 * row.bytes_per_sector - 1) / 3;
            let clusters = clusters_of(row);
            assert!(
                clusters + 2 > straddling,
                "{}: {clusters} clusters stops short of entry {straddling}, the first that \
                 straddles a sector at this size — so this row no longer covers the window \
                 the reader keeps over the table",
                row.what
            );
        }
    }

    #[test]
    fn a_subdirectory_wider_than_one_cluster_is_read_to_its_last_entry() {
        // The counterpart of the gate below, and the other half of how a FAT directory can
        // end. A root region stops because the region does; every other directory grows by
        // following its chain, and a reader that reads only the first cluster of one returns
        // a listing that is entirely plausible and short. Nothing above notices, because the
        // fixture's directories each hold a handful of entries.
        if !tools_present() {
            return;
        }
        for row in CHAINED {
            let image = built(row);
            let status = tool("mmd")
                .arg("-i")
                .arg(image.path())
                .arg("::/MANY")
                .status()
                .expect("spawn mmd");
            assert!(status.success(), "{}: mmd could not create /MANY", row.what);

            // Enough entries to reach a third cluster counting `.` and `..`, so the walk has
            // to follow two links rather than one.
            let per_cluster = row.bytes_per_cluster() / 32;
            let names: Vec<String> = (0..2 * per_cluster + 5)
                .map(|entry| format!("E{entry:04}.TXT"))
                .collect();
            let work = tempfile::Builder::new()
                .prefix("chained")
                .tempdir()
                .expect("create the payload directory");
            for name in &names {
                std::fs::write(work.path().join(name), format!("entry {name}\n"))
                    .expect("write the payload");
            }
            let status = tool("mcopy")
                .arg("-i")
                .arg(image.path())
                .args(names.iter().map(|name| work.path().join(name)))
                .arg("::/MANY/")
                .status()
                .expect("spawn mcopy");
            assert!(status.success(), "{}: mcopy could not fill /MANY", row.what);
            fsck_fat_clean(image.path())
                .unwrap_or_else(|e| panic!("{}: the checker faulted /MANY: {e}", row.what));

            let mut reader = opened(row, image.path());
            let dir = reader
                .lookup(b"/MANY")
                .unwrap_or_else(|e| panic!("{}: /MANY: {e}", row.what));
            let mut found: Vec<String> = reader
                .read_dir(&dir)
                .unwrap_or_else(|e| panic!("{}: /MANY would not read: {e}", row.what))
                .into_iter()
                .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
                .collect();
            found.sort();
            // `.` and `..` are entries of the directory and not of the tree, so a reader
            // hands back neither; what is left is exactly what was written.
            let mut expected = names.clone();
            expected.sort();
            assert_eq!(
                found,
                expected,
                "{}: a directory spanning {} clusters did not read to its last entry",
                row.what,
                (names.len() + 2).div_ceil(per_cluster as usize)
            );

            let report = reader.scan();
            assert!(
                report.is_clean(),
                "{}: the scan faulted a directory that merely spans clusters:\n{}",
                row.what,
                report.to_report().to_table()
            );
        }
    }

    #[test]
    fn a_root_region_filled_to_its_last_slot_ends_where_the_region_does() {
        // The one directory shape with no terminator. A FAT12 or FAT16 root has a fixed
        // capacity, so a full one ends because the region ends and not because a slot begins
        // with a zero byte — which makes it where a reader that trusts the terminator alone
        // runs off the end of the region and into whatever follows it.
        if !tools_present() {
            return;
        }
        for row in FILLED {
            let image = built(row);

            // Names that are already their own short names, so each takes exactly one slot
            // and the count of files is the count of slots. A name needing long-name entries
            // would take several, and the region would fill before the fixture ran out.
            //
            // One short of the capacity, because the volume label holds the first slot: the
            // baseline writes it into the root like any other entry, and a full root is
            // therefore the label and one file fewer than the count the field states.
            let work = tempfile::Builder::new()
                .prefix("filled")
                .tempdir()
                .expect("create the payload directory");
            let names: Vec<String> = (0..row.root_entries - 1)
                .map(|slot| format!("F{slot:03}.TXT"))
                .collect();
            for name in &names {
                std::fs::write(work.path().join(name), format!("slot {name}\n"))
                    .expect("write the payload");
            }
            let status = tool("mcopy")
                .arg("-i")
                .arg(image.path())
                .args(names.iter().map(|name| work.path().join(name)))
                .arg("::/")
                .status()
                .expect("spawn mcopy");
            assert!(
                status.success(),
                "{}: mcopy could not fill the root region",
                row.what
            );

            // That the region is genuinely full, said by the tool that filled it. Without
            // this the gate would still pass against a formatter that rounded the capacity
            // up, and would then be testing a root with slots to spare — the ordinary case
            // every other gate here already covers.
            let spare = work.path().join("EXTRA.TXT");
            std::fs::write(&spare, b"one entry too many\n").expect("write the payload");
            let refused = tool("mcopy")
                .arg("-i")
                .arg(image.path())
                .arg(&spare)
                .arg("::/EXTRA.TXT")
                .status()
                .expect("spawn mcopy");
            assert!(
                !refused.success(),
                "{}: the root took one more entry than its stated capacity, so it was never \
                 full and this gate tested nothing",
                row.what
            );

            // And that the foreign checker is content with what filling it produced, so that
            // anything below is attributable to this crate rather than to mtools having
            // written something odd on the way to running out of room.
            fsck_fat_clean(image.path()).unwrap_or_else(|e| {
                panic!("{}: the checker faulted the filled root: {e}", row.what)
            });

            let mut reader = opened(row, image.path());
            assert_eq!(
                reader.layout().root_entries,
                row.root_entries,
                "{}: the formatter gave the root a capacity other than the one asked for",
                row.what
            );
            let root = reader.root();
            let mut found: Vec<String> = reader
                .read_dir(&root)
                .unwrap_or_else(|e| panic!("{}: the root would not read: {e}", row.what))
                .into_iter()
                .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
                .collect();
            found.sort();
            let mut expected = names.clone();
            expected.sort();
            assert_eq!(
                found, expected,
                "{}: the last slot of the region is where the enumeration has to stop",
                row.what
            );

            for name in &names {
                let node = reader
                    .lookup(format!("/{name}").as_bytes())
                    .unwrap_or_else(|e| panic!("{}: /{name}: {e}", row.what));
                assert_eq!(
                    reader.read_data(&node).expect("read"),
                    format!("slot {name}\n").into_bytes(),
                    "{}: /{name} read back as something else",
                    row.what
                );
            }

            let report = reader.scan();
            assert!(
                report.is_clean(),
                "{}: the scan faulted a root region that is merely full:\n{}",
                row.what,
                report.to_report().to_table()
            );
        }
    }
}

/// A volume sized to its contents, against a foreign checker.
///
/// The tier every other one here leaves uncovered. A fitted volume is the *tightest* one
/// this crate writes — the search closes on a size with the sector below it proven not to
/// hold the tree — so it is where an off-by-one in the geometry, the allocation, or the
/// search itself stops being absorbed by slack that happened to be there. On FAT32 the
/// checker also cross-checks the information sector's free count against the table it walks,
/// which is a foreign reading of the exact quantity `Slack` is measured in.
mod fitted {
    use super::{available, fsck_fat_clean};
    use ferrosys::fat::{
        FatType, FatTypeRequest, FormatOptions, FormatPlan, PlanRequest, Timestamp,
    };
    use ferrosys::{Metadata, Slack, TreeBuilder};

    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    /// A tree big enough to need more than one cluster per file at every type under test.
    fn tree(files: usize, each: usize) -> TreeBuilder {
        let mut b = TreeBuilder::new()
            .directory(b"/EFI".to_vec(), Metadata::new(0o755, TIME))
            .directory(b"/EFI/BOOT".to_vec(), Metadata::new(0o755, TIME));
        for i in 0..files {
            b = b.file(
                format!("/EFI/BOOT/part{i:03}.efi").into_bytes(),
                vec![0xC3; each],
                Metadata::new(0o644, TIME),
            );
        }
        b
    }

    #[test]
    fn a_volume_sized_to_its_source_passes_fsck_fat() {
        if !available("fsck.fat") {
            eprintln!("SKIPPED: fsck.fat is not on PATH");
            return;
        }
        let dir = tempfile::tempdir().expect("temp dir");

        for kind in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            for slack in [Slack::None, Slack::Bytes(4 << 20), Slack::Share(2500)] {
                let options = FormatOptions::new(0x1A2B_3C4D, TIME)
                    .accept_all_loss()
                    .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(kind)));

                let plan = FormatPlan::fit(tree(24, 9_000), options, slack)
                    .unwrap_or_else(|e| panic!("{kind:?} with {slack:?} does not fit: {e}"));

                // The size a caller creates is the filesystem's own extent, so the image is
                // exactly as long as the layout says and the checker sees no tail.
                assert_eq!(plan.volume_bytes(), plan.layout().total_bytes());
                let free = plan.free_clusters();
                let clusters = plan.layout().clusters;

                let path = dir
                    .path()
                    .join(format!("{kind:?}-{slack:?}.img").replace(['(', ')'], "_"));
                let volume_bytes = plan.volume_bytes();
                let cluster_bytes = u64::from(plan.layout().bytes_per_cluster());
                let file = std::fs::File::create(&path).expect("create");
                plan.write_to(&file).expect("write");
                drop(file);

                assert_eq!(
                    std::fs::metadata(&path).expect("stat").len(),
                    volume_bytes,
                    "the image on disk is the size the search settled on"
                );
                fsck_fat_clean(&path)
                    .unwrap_or_else(|e| panic!("{kind:?} with {slack:?} is not clean: {e}"));

                // What the slack asked for is what the finished volume has, measured in the
                // unit its own free counter carries.
                let want = match slack {
                    Slack::None => 0,
                    Slack::Bytes(n) => n.div_ceil(cluster_bytes),
                    Slack::Share(h) => u64::from(clusters) * u64::from(h) / 10_000,
                    _ => 0,
                };
                assert!(
                    u64::from(free) >= want,
                    "{kind:?} with {slack:?}: {free} free clusters of {clusters}, wanted {want}"
                );
            }
        }
    }
}
