//! The exFAT family's oracle tier: `mkfs.exfat`, `fsck.exfat`, `tune.exfat`,
//! `dump.exfat`, and `exfatlabel`, and the evidence that their verdicts mean something.
//!
//! The tier was built before any exFAT code existed, which is the order this project works
//! in: an oracle certifies nothing until it has been watched rejecting what it should
//! reject, and a checker first consulted by a writer is a checker whose verdict has never
//! been calibrated. The gates below the divider still run against the pinned foreign tools
//! alone, and they establish four things about them.
//!
//! - **The baseline repeats itself, once one field is pinned.** `mkfs.exfat` has no
//!   invariant switch, and it derives `VolumeSerialNumber` from `CLOCK_REALTIME`. That
//!   is the only value a plain format draws from anywhere but its arguments, so two runs
//!   at identical parameters differ in four bytes of each boot region and in the sector
//!   that checksums each — and `tune.exfat --set-serial`, from the same pinned suite,
//!   rewrites both and recomputes both, which makes the images byte-identical. A
//!   differential gate against this baseline therefore needs no exclusion list.
//!
//! - **The checksums are the ones the format specifies.** Every one an empty volume
//!   carries is recomputed here from the image's own bytes and held against what the
//!   baseline stored, before a line of this crate computes one. That is what turns the
//!   three algorithms from prose into pinned behaviour, including the part of the boot
//!   checksum that is easiest to get wrong and impossible to see: the three offsets it
//!   skips.
//!
//! - **The checker discriminates.** Six corruptions, each a defect class a writer can
//!   plausibly produce, must be rejected — and the same image before the corruption must
//!   be accepted, so a rejection is attributable to the damage rather than to the image
//!   having been unhealthy all along.
//!
//! - **And it has a reach, which is not the same as an opinion.** `fsck.exfat` compares
//!   the on-disk allocation bitmap only against clusters it arrives at by walking a
//!   file. The three residents a format writes — the bitmap, the up-case table, the root
//!   directory — are marked used in the checker's own map without the volume's being
//!   consulted, so an empty volume's bitmap is unchecked in both directions. That is
//!   recorded as a gate rather than as a note, so a later release of the suite that
//!   starts checking is read rather than absorbed.
//!
//! Two of those need a file, and the baseline writes none: an empty exFAT volume holds
//! three primary entries and not one of them carries a set checksum or a name. So the
//! fixture builds a directory entry set by hand and the oracle accepting it is what says
//! the set checksum and the name hash below are right.
//!
//! Reading a record here is deliberately open-coded rather than routed through anything
//! this crate offers, for the reason the FAT tier states: an assertion that reads a field
//! back through the accessor a writer used is an assertion about consistency rather than
//! about bytes, and byte-exactness is the one property this crate cannot afford to check
//! against itself. Where this crate's own arithmetic *is* the thing under test, the gates
//! at the end of this file name it explicitly and hold it against what was read here.
//!
//! Every gate here declares the tool it needs and reports a loud skip when it is absent,
//! except where `FERROSYS_REQUIRE_HOST_TOOLS` is set, which is how CI refuses to pass by
//! not consulting an oracle.

mod util;

use std::io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _};
use std::ops::Range;
use std::path::Path;

use ferrosys::exfat::ondisk::{
    BOOT_CODE_LEN, MainBootSector, RECOMMENDED_UPCASE_BYTES, boot_checksum as crate_boot_checksum,
    entry_set_checksum as crate_set_checksum, name_hash as crate_name_hash,
    upcase_checksum as crate_upcase_checksum,
};
use ferrosys::exfat::{
    ClusterSize, FormatOptions, PlanRequest, VolumeLabel, format_to, plan_layout,
};
use ferrosys::{FsTree, Metadata, Source, Timestamp, TreeBuilder};
use util::{available, fsck_exfat_clean, tool};

// ---------------------------------------------------------------------------
// The matrix

/// One volume the tier builds, and why this family's gates want it.
struct Volume {
    what: &'static str,
    /// The volume's length in bytes. Every image is a sparse file, so a large one costs
    /// what its metadata costs and nothing for the rest.
    bytes: u64,
    /// What `mkfs.exfat` is told beyond the volume label.
    args: &'static [&'static str],
    /// The same instruction, in this crate's own vocabulary. It sits beside `args` rather
    /// than being derived from it so that the correspondence is one a person reads: what the
    /// baseline was told, and what this crate is told to reach the same volume.
    request: PlanRequest,
    /// What the pinned baseline makes of it.
    geometry: Geometry,
}

/// The layout the pinned `mkfs.exfat` derives from a row's arguments.
///
/// Recorded rather than computed, and that is the whole of its value: a number this file
/// derived and then compared against its own derivation would say nothing, while a number
/// written down says what the baseline did on the day it was read. When the pin moves and
/// these move with it, that is a re-baselining to be read beside the version bump rather
/// than absorbed into a green run, which is what pinning the tool is for.
///
/// It is also the table the planner is held to, at the end of this file, and it was read out
/// of the baseline before any of this crate's arithmetic existed — which is what keeps the
/// two independent.
struct Geometry {
    fat_offset: u32,
    fat_length: u32,
    heap_offset: u32,
    cluster_count: u32,
    root_cluster: u32,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    /// The allocation bitmap's first cluster and its length in bytes.
    bitmap: (u32, u64),
    /// The up-case table's first cluster. Its length is the compressed recommended
    /// table's and does not vary, so how many clusters it takes is a property of the
    /// cluster size — which is what moves the root directory's number between rows.
    upcase_cluster: u32,
}

/// The volumes every gate below runs over.
///
/// Sized by what each row *reaches* rather than by how large it is. exFAT addresses a
/// cluster with 32 bits and a sector with 64, so the arithmetic that separates one row
/// from another is the cluster count and the sector size — and a cluster count of a
/// million is reached by half a gigabyte of five-hundred-and-twelve-byte clusters just
/// as well as by a terabyte of megabyte ones, at a four-thousandth of the bytes a gate
/// has to read to compare two of them.
///
/// One row is large in bytes regardless, because a byte offset past four gigabytes is
/// its own arithmetic and no cluster count reaches it.
const VOLUMES: &[Volume] = &[
    Volume {
        what: "the lowest cluster band, where the up-case table spans twelve clusters",
        // Below seven mebibytes convention picks a 512-byte cluster, and the recommended
        // up-case table is twelve of them — so the root directory moves with the table
        // rather than sitting behind a handful of residents. No other row here has a root
        // above five except the million-cluster one, whose root is at 268.
        bytes: 4 * MIB,
        args: &[],
        request: PlanRequest::new(4 * MIB),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 48,
            heap_offset: 4096,
            cluster_count: 4096,
            root_cluster: 15,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            bitmap: (2, 512),
            upcase_cluster: 3,
        },
    },
    Volume {
        what: "the lowest band again, where the bitmap needs a second cluster",
        // Twice the clusters of the row above, so the allocation bitmap is two clusters
        // rather than one and everything behind it moves by one — which is what separates a
        // planner that places the residents in order from one that has memorized an offset.
        bytes: 6 * MIB,
        args: &[],
        request: PlanRequest::new(6 * MIB),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 80,
            heap_offset: 4096,
            cluster_count: 8192,
            root_cluster: 16,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            bitmap: (2, 1024),
            upcase_cluster: 4,
        },
    },
    Volume {
        what: "the smallest volume, at whatever cluster the baseline picks",
        bytes: 32 * MIB,
        args: &[],
        request: PlanRequest::new(32 * MIB),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 62,
            heap_offset: 4096,
            cluster_count: 7680,
            root_cluster: 5,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            bitmap: (2, 960),
            upcase_cluster: 3,
        },
    },
    Volume {
        what: "four-kilobyte clusters, where the up-case table spans two of them",
        bytes: 64 * MIB,
        args: &["-c", "4K"],
        request: PlanRequest::new(64 * MIB).cluster_size(ClusterSize::Bytes(4 << 10)),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 126,
            heap_offset: 4096,
            cluster_count: 15872,
            root_cluster: 5,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            bitmap: (2, 1984),
            upcase_cluster: 3,
        },
    },
    Volume {
        what: "thirty-two-kilobyte clusters, where it fits in one",
        bytes: 512 * MIB,
        args: &["-c", "32K"],
        request: PlanRequest::new(512 * MIB).cluster_size(ClusterSize::Bytes(32 << 10)),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 128,
            heap_offset: 4096,
            cluster_count: 16320,
            root_cluster: 4,
            bytes_per_sector: 512,
            sectors_per_cluster: 64,
            bitmap: (2, 2040),
            upcase_cluster: 3,
        },
    },
    Volume {
        what: "a sector size that is not five hundred and twelve",
        bytes: 64 * MIB,
        args: &["-s", "4096"],
        request: PlanRequest::new(64 * MIB).bytes_per_sector(4096),
        geometry: Geometry {
            // One mebibyte either way, which is what says the boundary alignment is a
            // byte quantity rather than a sector count.
            fat_offset: 256,
            fat_length: 16,
            heap_offset: 512,
            cluster_count: 15872,
            root_cluster: 5,
            bytes_per_sector: 4096,
            sectors_per_cluster: 1,
            bitmap: (2, 1984),
            upcase_cluster: 3,
        },
    },
    Volume {
        what: "a million clusters, so the allocation bitmap spans many of them",
        bytes: 512 * MIB,
        args: &["-s", "512", "-c", "512"],
        request: PlanRequest::new(512 * MIB)
            .bytes_per_sector(512)
            .cluster_size(ClusterSize::Bytes(512)),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 8113,
            heap_offset: 10240,
            cluster_count: 1_038_336,
            root_cluster: 268,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            // Two hundred and fifty-four clusters of it, which is the row's whole point.
            bitmap: (2, 129_792),
            upcase_cluster: 256,
        },
    },
    Volume {
        what: "a volume whose byte offsets pass four gigabytes",
        bytes: 8 * GIB,
        args: &["-c", "128K"],
        request: PlanRequest::new(8 * GIB).cluster_size(ClusterSize::Bytes(128 << 10)),
        geometry: Geometry {
            fat_offset: 2048,
            fat_length: 512,
            heap_offset: 4096,
            cluster_count: 65520,
            root_cluster: 4,
            bytes_per_sector: 512,
            sectors_per_cluster: 256,
            bitmap: (2, 8190),
            upcase_cluster: 3,
        },
    },
];

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The label every fixture carries, so that what `exfatlabel` reads back has a known
/// answer and is not whatever the baseline defaults to.
const LABEL: &str = "FERROSYS";

/// The serial every fixture is normalized to. Any constant does; this one is legible in
/// a hex dump, which is what a person debugging a failing byte comparison is reading.
const PINNED_SERIAL: u32 = 0x1234_5678;

// ---------------------------------------------------------------------------
// The boot sector, read as bytes

/// The fields of the Main Boot Sector every gate here consults.
///
/// Read with explicit little-endian loads at literal offsets, which is what makes an
/// assertion built on them a statement about the image rather than about this file's
/// idea of the image.
#[derive(Debug, Clone, Copy)]
struct Boot {
    volume_length: u64,
    fat_offset: u32,
    fat_length: u32,
    heap_offset: u32,
    cluster_count: u32,
    root_cluster: u32,
    serial: u32,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    fats: u8,
}

impl Boot {
    fn parse(sector: &[u8]) -> Boot {
        let u32_at = |off: usize| {
            u32::from_le_bytes([
                sector[off],
                sector[off + 1],
                sector[off + 2],
                sector[off + 3],
            ])
        };
        let u64_at = |off: usize| (u32_at(off) as u64) | ((u32_at(off + 4) as u64) << 32);
        assert_eq!(
            &sector[3..11],
            b"EXFAT   ",
            "the baseline wrote something that is not an exFAT boot sector"
        );
        Boot {
            volume_length: u64_at(72),
            fat_offset: u32_at(80),
            fat_length: u32_at(84),
            heap_offset: u32_at(88),
            cluster_count: u32_at(92),
            root_cluster: u32_at(96),
            serial: u32_at(100),
            bytes_per_sector: 1 << sector[108],
            sectors_per_cluster: 1 << sector[109],
            fats: sector[110],
        }
    }

    fn cluster_size(&self) -> u64 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// Where cluster `index` begins. The heap's first cluster is numbered two, because
    /// the first two entries of the allocation table are reserved and the numbering is
    /// shared.
    fn cluster_at(&self, index: u32) -> u64 {
        (self.heap_offset as u64 + (index as u64 - 2) * self.sectors_per_cluster)
            * self.bytes_per_sector
    }

    /// Where the allocation table's entry for `cluster` begins.
    fn fat_entry_at(&self, cluster: u32) -> u64 {
        self.fat_offset as u64 * self.bytes_per_sector + cluster as u64 * 4
    }

    /// Where boot region `which` — zero for the main one, one for the backup — begins.
    /// Each is twelve sectors, and the backup follows the main one immediately.
    fn boot_region_at(&self, which: u64) -> u64 {
        which * 12 * self.bytes_per_sector
    }
}

// ---------------------------------------------------------------------------
// The three residents a format writes, read out of the root directory

/// A format-time resident of the cluster heap, and the root directory entry describing
/// it. The allocation bitmap and the up-case table are both of this shape.
#[derive(Debug, Clone, Copy)]
struct Resident {
    /// Byte offset of the 32-byte entry that describes it.
    entry_at: u64,
    start_cluster: u32,
    size: u64,
}

/// What a freshly formatted root directory holds: an entry each for the volume label,
/// the allocation bitmap and the up-case table, one reserved slot, and then nothing.
#[derive(Debug)]
struct Root {
    bitmap: Resident,
    upcase: Resident,
    /// The 32-bit checksum the up-case entry advertises for the table's bytes.
    upcase_checksum: u32,
    label_at: u64,
    /// The label the entry spells, decoded from its UTF-16 units.
    label: String,
    /// The slot the baseline reserves for a volume GUID that was not supplied, if it
    /// wrote one: an `0xA0` entry with its in-use bit cleared, which is `0x20`.
    reserved_at: Option<u64>,
    /// Byte offset of the first slot no entry occupies.
    free_slot: u64,
}

impl Root {
    /// Read the root directory of a freshly formatted volume.
    ///
    /// One cluster, which is asserted rather than assumed: a root that had grown a
    /// second cluster would leave every offset below pointing at the wrong place, and an
    /// allocation table entry is what says so.
    fn read(image: &Path, boot: &Boot) -> Root {
        let chain = u32::from_le_bytes(
            read_at(image, boot.fat_entry_at(boot.root_cluster), 4)
                .try_into()
                .expect("four bytes"),
        );
        assert_eq!(
            chain, 0xFFFF_FFFF,
            "the baseline's root directory is no longer a single cluster, so every \
             offset this tier computes from it is wrong"
        );

        let base = boot.cluster_at(boot.root_cluster);
        let bytes = read_at(image, base, boot.cluster_size() as usize);
        let u32_at =
            |e: &[u8], off: usize| u32::from_le_bytes([e[off], e[off + 1], e[off + 2], e[off + 3]]);
        let u64_at =
            |e: &[u8], off: usize| (u32_at(e, off) as u64) | ((u32_at(e, off + 4) as u64) << 32);

        let (mut bitmap, mut upcase, mut label_at) = (None, None, None);
        let (mut upcase_checksum, mut label) = (0, String::new());
        let (mut reserved_at, mut free_slot) = (None, None);
        for (slot, entry) in bytes.chunks_exact(32).enumerate() {
            let at = base + slot as u64 * 32;
            let resident = || Resident {
                entry_at: at,
                start_cluster: u32_at(entry, 20),
                size: u64_at(entry, 24),
            };
            match entry[0] {
                0x81 => bitmap = Some(resident()),
                0x82 => {
                    upcase_checksum = u32_at(entry, 4);
                    upcase = Some(resident());
                }
                0x83 => {
                    label_at = Some(at);
                    let units = entry[1] as usize;
                    label = String::from_utf16_lossy(
                        &entry[2..2 + units * 2]
                            .chunks_exact(2)
                            .map(|u| u16::from_le_bytes([u[0], u[1]]))
                            .collect::<Vec<_>>(),
                    );
                }
                // A volume GUID entry with its in-use bit cleared. It is not a
                // terminator and the entries this tier needs are on the far side of it,
                // so enumeration steps over it — which is exactly what a reader has to
                // do, and the trap this baseline lays for one that stops at the first
                // entry not in use.
                0x20 => reserved_at = Some(at),
                0x00 => {
                    free_slot = Some(at);
                    break;
                }
                other => panic!("the baseline's root holds an entry of type {other:#04x}"),
            }
        }
        Root {
            bitmap: bitmap.expect("an allocation bitmap entry"),
            upcase: upcase.expect("an up-case table entry"),
            upcase_checksum,
            label_at: label_at.expect("a volume label entry"),
            label,
            reserved_at,
            free_slot: free_slot.expect("an unused slot in the root directory"),
        }
    }
}

// ---------------------------------------------------------------------------
// The checksums, computed here rather than read back

/// The primitive all four of exFAT's checksums are: rotate the accumulator right by one
/// and add the next byte, at whatever width the field is.
///
/// Written once at each width rather than once generically, because the two widths are
/// two constants and a generic over them would be the more elaborate way of writing the
/// same eight characters.
fn rotating_sum32(bytes: &[u8], skip: &[usize]) -> u32 {
    let mut sum = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        sum = ((sum & 1) << 31)
            .wrapping_add(sum >> 1)
            .wrapping_add(*b as u32);
    }
    sum
}

fn rotating_sum16(bytes: &[u8], skip: &[usize]) -> u16 {
    let mut sum = 0u16;
    for (i, b) in bytes.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        sum = ((sum & 1) << 15)
            .wrapping_add(sum >> 1)
            .wrapping_add(*b as u16);
    }
    sum
}

/// The three offsets the boot region's checksum skips: the two bytes of `VolumeFlags`
/// and the one of `PercentInUse`.
///
/// They are skipped rather than summed as zero, so the exclusion moves the answer even
/// on a volume where all three bytes are zero — which is every volume a format produces.
/// A driver rewrites those fields in place while a filesystem is mounted, and the
/// exclusion is what lets it do so without rewriting a checksum.
const BOOT_CHECKSUM_SKIPS: &[usize] = &[106, 107, 112];

/// The boot region's 32-bit checksum, over its first eleven sectors.
fn boot_checksum(region: &[u8]) -> u32 {
    rotating_sum32(region, BOOT_CHECKSUM_SKIPS)
}

/// A directory entry set's 16-bit checksum, over every byte of the set except the two
/// the checksum itself occupies.
fn set_checksum(entries: &[u8]) -> u16 {
    rotating_sum16(entries, &[2, 3])
}

/// A file name's 16-bit hash, over the up-cased name as UTF-16 little-endian bytes.
///
/// The fixture's names are up-case already, so nothing here consults the volume's
/// up-case table. A name that needed it would be testing the table rather than the hash.
fn name_hash(upper_case_name: &str) -> u16 {
    let bytes: Vec<u8> = upper_case_name
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    rotating_sum16(&bytes, &[])
}

// ---------------------------------------------------------------------------
// Running the pinned suite

/// A sparse file of `bytes` bytes, ready to be formatted into.
fn blank(bytes: u64) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("create a temporary image");
    file.as_file()
        .set_len(bytes)
        .expect("size the temporary image");
    file
}

/// Format `path` with the pinned baseline, returning what the formatter said.
///
/// The arguments come in as a slice rather than as a row, because two different matrices
/// call this: [`VOLUMES`], whose rows carry the baseline's arguments verbatim beside this
/// crate's own vocabulary for the same volume, and [`FOREIGN_MATRIX`], whose rows state a
/// sector size and a cluster size and have no ferrosys request to correspond to.
fn mkfs(path: &Path, args: &[&str]) -> Result<String, String> {
    let out = tool("mkfs.exfat")
        .args(["-L", LABEL])
        .args(args)
        .arg(path)
        .output()
        .map_err(|e| format!("spawn mkfs.exfat: {e}"))?;
    let said = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(said)
    } else {
        Err(format!("mkfs.exfat exited {:?}\n{said}", out.status.code()))
    }
}

/// Replace a volume's serial number with `serial`, using the pinned suite's own tool.
///
/// This is what makes the baseline reproducible, and it has to be the suite's tool
/// rather than a patch of our own: the serial is inside the boot checksum, so writing it
/// means recomputing that checksum in both boot regions, and a gate whose baseline was
/// normalized by this crate's arithmetic would be checking that arithmetic against
/// itself.
fn set_serial(path: &Path, serial: u32) {
    let out = tool("tune.exfat")
        .args(["-I", &format!("{serial:#010x}")])
        .arg(path)
        .output()
        .expect("spawn tune.exfat");
    assert!(
        out.status.success(),
        "tune.exfat could not pin the volume serial: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Build one row's image, pin its serial to `serial`, and hand back the file with its
/// boot sector already parsed.
///
/// Formatting a second image is how a gate gets one that differs from another, rather
/// than copying the first: an image here is a sparse file eight gigabytes long with a
/// few hundred kilobytes in it, and a copy is defined over its bytes rather than over
/// what was written, so it fills every hole. On the filesystem preflight mounts to check
/// the gates against a host that records access times, that is the whole of the space
/// there is.
fn formatted_with(volume: &Volume, serial: u32) -> (tempfile::NamedTempFile, Boot) {
    let image = blank(volume.bytes);
    mkfs(image.path(), volume.args)
        .unwrap_or_else(|e| panic!("the baseline could not build {}: {e}", volume.what));
    set_serial(image.path(), serial);
    let boot = Boot::parse(&read_at(image.path(), 0, 512));
    // Read back rather than assumed: every byte comparison below rests on the
    // normalization having happened, and a tool that reported success without writing
    // would leave those gates comparing two clock-derived values and passing whenever
    // the clock had not moved.
    assert_eq!(
        boot.serial, serial,
        "pinning the serial of {} left the field alone",
        volume.what
    );
    (image, boot)
}

/// Build one row's image at the serial every gate here shares.
fn formatted(volume: &Volume) -> (tempfile::NamedTempFile, Boot) {
    formatted_with(volume, PINNED_SERIAL)
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

/// Flip the low bit of the byte at `offset`, and say what it was.
fn flip(path: &Path, offset: u64) {
    let mut byte = read_at(path, offset, 1);
    byte[0] ^= 0x01;
    write_at(path, offset, &byte);
}

/// Every range of bytes in which two images differ, read a chunk at a time.
///
/// The one comparison of two whole images this file has, and the answer to three different
/// questions: whether the baseline repeats itself, whether an image this crate wrote is the
/// baseline's, and where a serial reaches. Each of those is "which bytes differ" with a
/// different pair of images.
///
/// The list is complete rather than capped, because two of those three callers reason over the
/// *whole* of it — one asserts that every region a serial reaches was touched — and a
/// truncated list would satisfy an assertion for the wrong reason.
///
/// Chunked rather than read whole: the matrix reaches eight gigabytes, and a volume that
/// size holds a few hundred kilobytes of metadata in a sparse file — loading either side
/// would turn a comparison of what was written into eight gigabytes of resident pages.
///
/// A chunk is compared as a slice and only walked byte by byte once it is known to differ.
/// This file is built without optimization like every test here, and the difference that makes
/// over nine gigabytes is two seconds against a minute and a quarter. A gate slow enough to be
/// skipped is a gate that does not run.
fn differing_ranges(a: &Path, b: &Path) -> Vec<Range<u64>> {
    const CHUNK: usize = 4 << 20;
    let (mut fa, mut fb) = (
        std::fs::File::open(a).expect("open the first image"),
        std::fs::File::open(b).expect("open the second image"),
    );
    let (len_a, len_b) = (
        fa.metadata().expect("stat the first image").len(),
        fb.metadata().expect("stat the second image").len(),
    );
    assert_eq!(len_a, len_b, "the two images are not the same length");

    let (mut buf_a, mut buf_b) = (vec![0u8; CHUNK], vec![0u8; CHUNK]);
    let mut ranges: Vec<Range<u64>> = Vec::new();
    let mut at = 0u64;
    while at < len_a {
        let want = CHUNK.min((len_a - at) as usize);
        fa.read_exact(&mut buf_a[..want])
            .expect("read the first image");
        fb.read_exact(&mut buf_b[..want])
            .expect("read the second image");
        if buf_a[..want] != buf_b[..want] {
            for (i, (x, y)) in buf_a[..want].iter().zip(&buf_b[..want]).enumerate() {
                if x == y {
                    continue;
                }
                let offset = at + i as u64;
                match ranges.last_mut() {
                    Some(last) if last.end == offset => last.end = offset + 1,
                    _ => ranges.push(offset..offset + 1),
                }
            }
        }
        at += want as u64;
    }
    ranges
}

/// The first few of `ranges` and how many there were, for a failure message.
///
/// A single wrong byte inside a boot region reaches both regions and both checksum sectors,
/// and lands as a couple of hundred ranges — a checksum sector repeats one word, so only some
/// bytes of each repetition change. Printing all of them buries the one thing a person needs,
/// which is where the difference starts. The list itself is not truncated, because two gates
/// reason over the whole of it.
fn summarize(ranges: &[std::ops::Range<u64>]) -> String {
    const SHOWN: usize = 8;
    let head = ranges
        .iter()
        .take(SHOWN)
        .map(|r| format!("{:#x}..{:#x}", r.start, r.end))
        .collect::<Vec<_>>()
        .join(", ");
    if ranges.len() <= SHOWN {
        head
    } else {
        format!("{head}, and {} further ranges", ranges.len() - SHOWN)
    }
}

/// The four places a volume serial reaches: the field itself in each boot region, and
/// the sector that checksums each region.
fn serial_regions(boot: &Boot) -> Vec<Range<u64>> {
    (0..2)
        .flat_map(|region| {
            let base = boot.boot_region_at(region);
            [
                base + 100..base + 104,
                base + 11 * boot.bytes_per_sector..base + 12 * boot.bytes_per_sector,
            ]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The baseline repeats itself

#[test]
fn two_formats_at_the_same_parameters_differ_only_where_the_clock_reaches() {
    if !available("mkfs.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (first, second) = (blank(volume.bytes), blank(volume.bytes));
        mkfs(first.path(), volume.args).expect("the baseline built the first image");
        mkfs(second.path(), volume.args).expect("the baseline built the second image");
        let boot = Boot::parse(&read_at(first.path(), 0, 512));
        let allowed = serial_regions(&boot);

        // A subset rather than an equality, and deliberately: the serial is a function
        // of the clock at nanosecond resolution, so two runs differing in *none* of
        // these bytes is not impossible, only vanishingly unlikely — and a gate that
        // demanded a difference would be one that fails for having been lucky. What the
        // serial reaches when it does change is asserted next, deterministically.
        for range in differing_ranges(first.path(), second.path()) {
            assert!(
                allowed
                    .iter()
                    .any(|a| a.start <= range.start && range.end <= a.end),
                "two formats of {} differ at {range:?}, outside the volume serial and \
                 the boot checksums that cover it. Something else in this baseline is \
                 not reproducible, and a differential gate against it would need to say \
                 what.",
                volume.what
            );
        }
    }
}

#[test]
fn a_serial_change_reaches_the_field_and_the_checksum_over_it_in_both_boot_regions() {
    if !available("mkfs.exfat") || !available("tune.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let (other, _) = formatted_with(volume, !PINNED_SERIAL);

        let changed = differing_ranges(image.path(), other.path());
        for region in serial_regions(&boot) {
            assert!(
                changed
                    .iter()
                    .any(|r| r.start < region.end && region.start < r.end),
                "pinning a different serial on {} left {region:?} untouched, so the \
                 tier is not reaching both boot regions and both checksum sectors",
                volume.what
            );
        }
        let allowed = serial_regions(&boot);
        for range in &changed {
            assert!(
                allowed
                    .iter()
                    .any(|a| a.start <= range.start && range.end <= a.end),
                "pinning a serial on {} also changed {range:?}, which is neither the \
                 field nor a checksum sector",
                volume.what
            );
        }
    }
}

#[test]
fn a_pinned_serial_makes_the_baseline_byte_reproducible() {
    if !available("mkfs.exfat") || !available("tune.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (first, _) = formatted(volume);
        let (second, _) = formatted(volume);
        let differences = differing_ranges(first.path(), second.path());
        assert!(
            differences.is_empty(),
            "two normalized formats of {} differ at {differences:?}. The differential \
             oracle for this family is a whole-image byte comparison only while this \
             holds; if it stops, what changed has to be named here before a gate \
             excludes it.",
            volume.what
        );
    }
}

// ---------------------------------------------------------------------------
// The checksums are the ones the format specifies

#[test]
fn the_boot_checksum_of_each_region_is_the_one_the_specification_computes() {
    if !available("mkfs.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        for region in 0..2 {
            let base = boot.boot_region_at(region);
            let sectors = read_at(image.path(), base, (11 * boot.bytes_per_sector) as usize);
            let computed = boot_checksum(&sectors);
            let stored = u32::from_le_bytes(
                read_at(image.path(), base + 11 * boot.bytes_per_sector, 4)
                    .try_into()
                    .expect("four bytes"),
            );
            assert_eq!(
                computed, stored,
                "boot region {region} of {} carries a checksum this tier cannot \
                 reproduce",
                volume.what
            );

            // The whole sector repeats the value, which is what a reader recovering a
            // damaged region relies on.
            let sector = read_at(
                image.path(),
                base + 11 * boot.bytes_per_sector,
                boot.bytes_per_sector as usize,
            );
            assert!(
                sector.chunks_exact(4).all(|w| w == stored.to_le_bytes()),
                "the checksum sector of boot region {region} of {} does not repeat its \
                 value for the whole sector",
                volume.what
            );
        }
    }
}

#[test]
fn the_boot_checksum_skips_its_three_offsets_rather_than_summing_them_as_zero() {
    if !available("mkfs.exfat") {
        return;
    }
    let (image, boot) = formatted(&VOLUMES[0]);
    let sectors = read_at(image.path(), 0, (11 * boot.bytes_per_sector) as usize);
    for &offset in BOOT_CHECKSUM_SKIPS {
        assert_eq!(
            sectors[offset], 0,
            "offset {offset} of a freshly formatted boot sector is not zero, so this \
             gate is no longer measuring what it claims to"
        );
    }
    assert_ne!(
        boot_checksum(&sectors),
        rotating_sum32(&sectors, &[]),
        "summing the three excluded offsets as the zeroes they are gives the same \
         answer as skipping them, so nothing here would notice an implementation that \
         did not skip them at all"
    );
}

#[test]
fn the_baseline_derives_the_geometry_this_tier_records() {
    if !available("mkfs.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        let want = &volume.geometry;
        let got = [
            ("FatOffset", boot.fat_offset as u64, want.fat_offset as u64),
            ("FatLength", boot.fat_length as u64, want.fat_length as u64),
            (
                "ClusterHeapOffset",
                boot.heap_offset as u64,
                want.heap_offset as u64,
            ),
            (
                "ClusterCount",
                boot.cluster_count as u64,
                want.cluster_count as u64,
            ),
            (
                "FirstClusterOfRootDirectory",
                boot.root_cluster as u64,
                want.root_cluster as u64,
            ),
            (
                "BytesPerSector",
                boot.bytes_per_sector,
                want.bytes_per_sector,
            ),
            (
                "SectorsPerCluster",
                boot.sectors_per_cluster,
                want.sectors_per_cluster,
            ),
            (
                "the allocation bitmap's first cluster",
                root.bitmap.start_cluster as u64,
                want.bitmap.0 as u64,
            ),
            (
                "the allocation bitmap's length",
                root.bitmap.size,
                want.bitmap.1,
            ),
            (
                "the up-case table's first cluster",
                root.upcase.start_cluster as u64,
                want.upcase_cluster as u64,
            ),
        ];
        for (field, measured, recorded) in got {
            assert_eq!(
                measured, recorded,
                "the baseline derives a different {field} for {} than this tier records. \
                 If the pinned version moved, that is a re-baselining and belongs beside \
                 the bump; if it did not, the difference is the finding.",
                volume.what
            );
        }

        // Two relations the recorded numbers must satisfy, checked rather than recorded:
        // a volume is as long as it was made, and its bitmap covers every cluster and no
        // more.
        assert_eq!(
            boot.volume_length * boot.bytes_per_sector,
            volume.bytes,
            "the baseline's {} does not span the file it was given",
            volume.what
        );
        assert_eq!(
            root.bitmap.size,
            boot.cluster_count.div_ceil(8) as u64,
            "the allocation bitmap of {} is not one bit per cluster",
            volume.what
        );
    }
}

#[test]
fn a_directory_ends_at_a_zero_type_byte_and_not_at_a_cleared_in_use_bit() {
    if !available("mkfs.exfat") {
        return;
    }
    // The baseline reserves the root's second slot for a volume GUID nobody supplied,
    // by writing that entry's type with the in-use bit cleared. One such entry cannot
    // hold a file — a set needs three consecutive slots — so it costs nothing and keeps
    // the slot available.
    //
    // What it costs a *reader* is the whole volume. The allocation bitmap and the
    // up-case table are behind it, so a reader that treats the first entry not in use as
    // the end of the directory finds neither, on the very first image any exFAT tool
    // hands it. Pinned here, before there is a reader to get it wrong.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        let reserved = root.reserved_at.unwrap_or_else(|| {
            panic!(
                "the baseline no longer reserves a not-in-use slot on {}, so this gate \
                 is not exercising the enumeration rule it names",
                volume.what
            )
        });
        assert!(
            reserved < root.bitmap.entry_at && reserved < root.upcase.entry_at,
            "the reserved slot on {} is no longer ahead of the two entries a reader \
             must get past it to reach",
            volume.what
        );
        let entry = read_at(image.path(), reserved, 32);
        assert_eq!(
            entry[0] & 0x80,
            0,
            "the reserved slot on {} has its in-use bit set",
            volume.what
        );
        assert!(
            entry[1..].iter().all(|b| *b == 0),
            "the reserved slot on {} carries something beyond its type byte",
            volume.what
        );
    }
}

#[test]
fn the_up_case_table_carries_the_checksum_its_own_bytes_produce() {
    if !available("mkfs.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        let table = read_at(
            image.path(),
            boot.cluster_at(root.upcase.start_cluster),
            root.upcase.size as usize,
        );
        assert_eq!(
            rotating_sum32(&table, &[]),
            root.upcase_checksum,
            "the up-case table of {} does not check out against its own entry",
            volume.what
        );
    }
}

#[test]
fn the_baseline_writes_the_recommended_up_case_table_at_every_geometry() {
    if !available("mkfs.exfat") {
        return;
    }
    // The compressed form of the table the specification recommends, and the checksum
    // its bytes produce. A volume whose case-insensitive lookups are to agree with every
    // other implementation's carries this table and no other, so the value is pinned
    // here rather than derived — a transcription error in a table computed from itself
    // checks out perfectly.
    const RECOMMENDED: u32 = 0xE619_D30D;
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        assert_eq!(
            root.upcase_checksum, RECOMMENDED,
            "the baseline wrote an up-case table this tier does not recognize for {}",
            volume.what
        );
    }
}

// ---------------------------------------------------------------------------
// A file, built by hand, because the baseline writes none

/// Where a hand-built directory entry set landed, and what it points at.
struct Placed {
    /// Byte offset of the set's first entry, the `0x85` file entry.
    file_entry_at: u64,
    /// Byte offset of the `0xC0` stream extension entry.
    stream_entry_at: u64,
    /// The one cluster the file's data occupies.
    cluster: u32,
    /// Byte offset of the allocation bitmap byte holding that cluster's bit, and which
    /// bit it is.
    bitmap_byte_at: u64,
    bitmap_bit: u8,
}

/// Write one file into a freshly formatted volume: a three-entry directory set in the
/// root, one cluster of data, and the allocation bitmap bit that says the cluster is in
/// use.
///
/// The set is correct on the way out. Each control below damages exactly one thing about
/// it and asserts the checker notices, and the undamaged fixture being accepted is what
/// makes each of those attributable to the damage.
///
/// The name is up-case and short enough for one name entry, which keeps the fixture
/// about the checksums rather than about name segmentation — that is the populated
/// writer's problem and it gets its own tier.
fn place_a_file(image: &Path, boot: &Boot, root: &Root, name: &str, data: &[u8]) -> Placed {
    assert!(
        name.len() <= 15
            && name
                .chars()
                .all(|c| c.is_ascii() && !c.is_ascii_lowercase()),
        "the fixture's name must be one entry's worth of up-case ASCII"
    );
    assert!(
        (data.len() as u64) <= boot.cluster_size(),
        "the fixture's data must fit in the one cluster it allocates"
    );

    // The first cluster no bit claims. A fresh volume has the bitmap, the up-case table
    // and the root at the front of the heap and nothing after them, so this is the
    // cluster immediately past them — found rather than assumed, since which clusters
    // those three occupy varies with the cluster size.
    let bitmap = read_at(
        image,
        boot.cluster_at(root.bitmap.start_cluster),
        root.bitmap.size as usize,
    );
    let free = (2..boot.cluster_count + 2)
        .find(|c| bitmap[(*c as usize - 2) / 8] & (1 << ((c - 2) % 8)) == 0)
        .expect("a free cluster");

    let mut file_entry = [0u8; 32];
    file_entry[0] = 0x85;
    file_entry[1] = 2; // two secondary entries follow
    file_entry[4..6].copy_from_slice(&0x0020u16.to_le_bytes()); // archive
    // One instant in all three timestamp fields, so nothing here depends on the clock.
    // 1 January 2020, midnight: the year counts from 1980 in the high seven bits.
    let stamp = ((2020u32 - 1980) << 25) | (1 << 21) | (1 << 16);
    for at in [8, 12, 16] {
        file_entry[at..at + 4].copy_from_slice(&stamp.to_le_bytes());
    }

    let mut stream_entry = [0u8; 32];
    stream_entry[0] = 0xC0;
    // Allocation possible, and no chain in the allocation table: the file is one
    // contiguous run, which is what a fresh sequential writer produces and what this
    // family's writer will declare.
    stream_entry[1] = 0x01 | 0x02;
    stream_entry[3] = name.len() as u8;
    stream_entry[4..6].copy_from_slice(&name_hash(name).to_le_bytes());
    stream_entry[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes()); // valid data
    stream_entry[20..24].copy_from_slice(&free.to_le_bytes());
    stream_entry[24..32].copy_from_slice(&(data.len() as u64).to_le_bytes());

    let mut name_entry = [0u8; 32];
    name_entry[0] = 0xC1;
    for (i, unit) in name.encode_utf16().enumerate() {
        name_entry[2 + i * 2..4 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }

    let mut set = [file_entry, stream_entry, name_entry].concat();
    let checksum = set_checksum(&set);
    set[2..4].copy_from_slice(&checksum.to_le_bytes());
    write_at(image, root.free_slot, &set);

    let mut cluster = vec![0u8; boot.cluster_size() as usize];
    cluster[..data.len()].copy_from_slice(data);
    write_at(image, boot.cluster_at(free), &cluster);

    let (byte, bit) = ((free as usize - 2) / 8, ((free - 2) % 8) as u8);
    let mut claimed = [bitmap[byte]];
    claimed[0] |= 1 << bit;
    let bitmap_byte_at = boot.cluster_at(root.bitmap.start_cluster) + byte as u64;
    write_at(image, bitmap_byte_at, &claimed);

    Placed {
        file_entry_at: root.free_slot,
        stream_entry_at: root.free_slot + 32,
        cluster: free,
        bitmap_byte_at,
        bitmap_bit: bit,
    }
}

/// The name the hand-built fixture carries.
const FIXTURE_NAME: &str = "HELLO.TXT";

/// A volume with one file in it, and everything a control needs to damage it.
fn with_a_file(volume: &Volume) -> (tempfile::NamedTempFile, Boot, Placed) {
    let (image, boot) = formatted(volume);
    let root = Root::read(image.path(), &boot);
    let placed = place_a_file(image.path(), &boot, &root, FIXTURE_NAME, b"ferrosys\n");
    (image, boot, placed)
}

// ---------------------------------------------------------------------------
// The checker discriminates

#[test]
fn the_checker_accepts_the_baseline_across_the_matrix() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, _) = formatted(volume);
        fsck_exfat_clean(image.path())
            .unwrap_or_else(|e| panic!("the checker refused a clean {}: {e}", volume.what));
    }
}

#[test]
fn the_checker_accepts_a_hand_built_directory_entry_set() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // This is what makes the two algorithms above measured rather than transcribed. The
    // baseline writes no set checksum and no name at all, so there is no image to read
    // one out of; a set the checker accepts is the vector.
    for volume in VOLUMES {
        let (image, _, _) = with_a_file(volume);
        let said = fsck_exfat_clean(image.path()).unwrap_or_else(|e| {
            panic!(
                "the checker refused a hand-built file on {}, so the set checksum or \
                 the name hash below is wrong: {e}",
                volume.what
            )
        });
        assert!(
            said.contains("files 1"),
            "the checker did not count the hand-built file on {}. It said:\n{said}",
            volume.what
        );
    }
}

#[test]
fn a_damaged_boot_checksum_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    let (image, boot) = formatted(&VOLUMES[0]);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    flip(image.path(), 11 * boot.bytes_per_sector);
    let refused = fsck_exfat_clean(image.path())
        .expect_err("a boot region whose checksum sector was altered must be refused");
    assert!(
        refused.contains("checksum of boot region"),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn a_serial_written_without_recomputing_the_checksum_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The other half of the exclusion: the three skipped offsets are the only bytes of
    // sector 0 a writer may change without touching the checksum, and the serial four
    // bytes away is not one of them.
    let (image, _) = formatted(&VOLUMES[0]);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    write_at(image.path(), 100, &(!PINNED_SERIAL).to_le_bytes());
    let refused = fsck_exfat_clean(image.path())
        .expect_err("a serial written past its own checksum must be refused");
    assert!(
        refused.contains("checksum of boot region"),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn the_two_fields_a_mounted_driver_rewrites_are_outside_the_checksum() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The reason the exclusion exists, checked as behaviour rather than as arithmetic: a
    // driver marks a volume dirty and updates how full it is while it is mounted, and
    // does so without rewriting either boot region's checksum.
    let (image, _) = formatted(&VOLUMES[0]);
    write_at(image.path(), 106, &0x0002u16.to_le_bytes()); // VolumeFlags: media failure
    write_at(image.path(), 112, &[42]); // PercentInUse
    fsck_exfat_clean(image.path()).expect(
        "changing VolumeFlags and PercentInUse without recomputing the boot checksum \
         must leave the volume acceptable — those three bytes are the exclusion",
    );
}

#[test]
fn a_damaged_up_case_table_checksum_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    let (image, boot) = formatted(&VOLUMES[0]);
    let root = Root::read(image.path(), &boot);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    flip(image.path(), root.upcase.entry_at + 4);
    let refused = fsck_exfat_clean(image.path())
        .expect_err("an up-case table that does not check out must be refused");
    assert!(
        refused.contains("upcase table"),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn a_damaged_directory_set_checksum_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    let (image, _, placed) = with_a_file(&VOLUMES[0]);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    flip(image.path(), placed.file_entry_at + 2);
    let refused = fsck_exfat_clean(image.path())
        .expect_err("a directory entry set that does not check out must be refused");
    assert!(
        refused.contains("checksum"),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn a_name_hash_no_name_produces_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The one field in the set whose damage a reader could survive: the hash is a lookup
    // accelerator, so a wrong one costs no data — it makes a file invisible to a driver
    // that trusts it, which is worse than corruption for being silent. That the checker
    // has an opinion about it at all is what this records.
    let (image, _, placed) = with_a_file(&VOLUMES[0]);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    // Derived from the right answer rather than picked, so the damage is a different
    // value by construction and cannot one day be the same one.
    //
    // The set checksum covers the hash, so it is recomputed over the damaged set: what
    // is being checked is that the checker looks at the hash itself and not only at the
    // checksum that happens to cover it.
    write_at(
        image.path(),
        placed.stream_entry_at + 4,
        &(!name_hash(FIXTURE_NAME)).to_le_bytes(),
    );
    let set = read_at(image.path(), placed.file_entry_at, 96);
    let mut repaired = set.clone();
    repaired[2..4].copy_from_slice(&set_checksum(&set).to_le_bytes());
    write_at(image.path(), placed.file_entry_at, &repaired);

    let refused =
        fsck_exfat_clean(image.path()).expect_err("a name hash no name produces must be refused");
    assert!(
        refused.contains("name hash"),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn a_bitmap_that_calls_a_files_cluster_free_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    let (image, _, placed) = with_a_file(&VOLUMES[0]);
    fsck_exfat_clean(image.path()).expect("the fixture is clean before the damage");

    let mut byte = read_at(image.path(), placed.bitmap_byte_at, 1);
    byte[0] &= !(1 << placed.bitmap_bit);
    write_at(image.path(), placed.bitmap_byte_at, &byte);

    let refused = fsck_exfat_clean(image.path())
        .expect_err("a bitmap disagreeing with a file's own chain must be refused");
    assert!(
        refused.contains(&format!("cluster {:#x} is marked as free", placed.cluster)),
        "the checker refused the image for some other reason:\n{refused}"
    );
}

#[test]
fn the_checker_does_not_reach_the_bitmap_of_an_empty_volume() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The reach of this oracle, recorded as a gate rather than as a note. `fsck.exfat`
    // compares the volume's bitmap only against clusters it arrives at by walking a
    // file: the three residents a format writes are marked used in its own map without
    // the volume's being consulted, and bits set for clusters nothing owns are noticed
    // only on the path that rewrites the bitmap, which a read-only check never takes.
    //
    // So this family's writer deriving the bitmap and the allocation table from one plan
    // is not a convenience — it is the only thing standing behind an empty volume's
    // bitmap, and no gate above will say otherwise. A later release of the suite that
    // starts checking fails here, which is where that should be read.
    let (image, boot) = formatted(&VOLUMES[0]);
    let root = Root::read(image.path(), &boot);
    let at = boot.cluster_at(root.bitmap.start_cluster);

    let mut first = read_at(image.path(), at, 1);
    assert_eq!(
        first[0] & 0x01,
        1,
        "the first heap cluster is not claimed, so this gate is not damaging what it \
         thinks it is"
    );
    first[0] &= !0x01;
    write_at(image.path(), at, &first);
    fsck_exfat_clean(image.path()).expect(
        "the checker now objects to a bitmap that calls the allocation bitmap's own \
         cluster free. That is a stronger checker than this family was designed \
         against, and the note above about where the bitmap's correctness comes from \
         should be revisited rather than this assertion inverted.",
    );

    let (image, boot) = formatted(&VOLUMES[0]);
    let root = Root::read(image.path(), &boot);
    let at = boot.cluster_at(root.bitmap.start_cluster);
    let mut claimed = read_at(image.path(), at, 1);
    claimed[0] = 0xFF;
    write_at(image.path(), at, &claimed);
    fsck_exfat_clean(image.path()).expect(
        "the checker now objects to bits set for clusters nothing owns. Same finding, \
         other direction: revisit the note above rather than inverting this.",
    );
}

// ---------------------------------------------------------------------------
// The other two tools have an opinion of their own

#[test]
fn the_structural_dump_agrees_with_the_boot_sector() {
    if !available("mkfs.exfat") || !available("dump.exfat") {
        return;
    }
    // The `dumpe2fs` of this family, and the tool a later differential gate reads a
    // geometry out of. What it is held to here is the image's own bytes, so a gate built
    // on it is standing on two readings of one volume rather than on one.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let out = tool("dump.exfat")
            .arg(image.path())
            .output()
            .expect("spawn dump.exfat");
        assert!(
            out.status.success(),
            "dump.exfat refused {}: {}",
            volume.what,
            String::from_utf8_lossy(&out.stderr)
        );
        let said = String::from_utf8_lossy(&out.stdout);
        let field = |label: &str| -> String {
            said.lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("dump.exfat printed no {label:?}. It said:\n{said}"))
                .split(':')
                .nth(1)
                .expect("a value after the colon")
                .trim()
                .to_string()
        };
        for (label, want) in [
            ("Volume Length(sectors)", boot.volume_length),
            ("FAT Offset(sector offset)", boot.fat_offset as u64),
            ("FAT Length(sectors)", boot.fat_length as u64),
            (
                "Cluster Heap Offset (sector offset)",
                boot.heap_offset as u64,
            ),
            ("Cluster Count", boot.cluster_count as u64),
            ("Root Cluster (cluster offset)", boot.root_cluster as u64),
            ("Bytes per Sector", boot.bytes_per_sector),
            ("Sectors per Cluster", boot.sectors_per_cluster),
        ] {
            assert_eq!(
                field(label),
                want.to_string(),
                "dump.exfat and the boot sector of {} disagree about {label}",
                volume.what
            );
        }
        assert_eq!(
            field("Volume Serial"),
            format!("{PINNED_SERIAL:#x}"),
            "dump.exfat does not read back the serial this tier pinned on {}",
            volume.what
        );

        // Two of this tool's fields are printed in hexadecimal with no prefix, beside
        // fields that are decimal and fields whose hexadecimal carries one. A reader
        // taking a start cluster of `100` for a hundred is wrong by a hundred and
        // fifty-six, and agrees with itself on every volume small enough for the value
        // to be a single digit — which is four of the six rows here. Pinned against the
        // entries this tier decodes out of the root directory itself.
        let root = Root::read(image.path(), &boot);
        for (label, want) in [
            ("Bitmap start cluster", root.bitmap.start_cluster),
            ("Upcase table start cluster", root.upcase.start_cluster),
        ] {
            let said = field(label);
            assert_eq!(
                u32::from_str_radix(&said, 16).unwrap_or_else(|e| panic!(
                    "dump.exfat printed {said:?} for {label} on {}, which is not \
                     hexadecimal: {e}",
                    volume.what
                )),
                want,
                "dump.exfat and the root directory of {} disagree about {label}",
                volume.what
            );
        }
        for (label, want) in [
            ("Bitmap size", root.bitmap.size),
            ("Upcase table size", root.upcase.size),
        ] {
            assert_eq!(
                field(label),
                want.to_string(),
                "dump.exfat and the root directory of {} disagree about {label}",
                volume.what
            );
        }
        // One allocation table. The two-table variant is a different filesystem wearing
        // this one's boot sector, and every geometry here is computed as though there is
        // one — so the assumption is checked where it is made.
        assert_eq!(
            boot.fats, 1,
            "the baseline built {} with more than one allocation table",
            volume.what
        );
    }
}

#[test]
fn the_label_reader_reads_the_label_the_formatter_wrote() {
    if !available("mkfs.exfat") || !available("exfatlabel") {
        return;
    }
    // Two independent readings of one field, which is the point: the entry this tier
    // decodes out of the root directory by hand, and what the suite's own tool says.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        assert_eq!(
            root.label, LABEL,
            "the volume label entry of {} does not spell what the formatter was told",
            volume.what
        );
        assert!(
            root.label_at < root.free_slot,
            "the volume label entry of {} is not in the root directory",
            volume.what
        );

        let out = tool("exfatlabel")
            .arg(image.path())
            .output()
            .expect("spawn exfatlabel");
        assert!(
            out.status.success(),
            "exfatlabel refused {}: {}",
            volume.what,
            String::from_utf8_lossy(&out.stderr)
        );
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(
            said.lines().any(|l| l.trim() == format!("label: {LABEL}")),
            "exfatlabel did not read back the label written to {}. It said:\n{said}",
            volume.what
        );
    }
}

// ---------------------------------------------------------------------------
// This crate's own arithmetic, held against everything above
//
// Everything before this point runs against the pinned tools alone and would pass with no
// exFAT code in the crate at all. What follows names this crate's functions and holds each
// to what the baseline wrote — which is the whole of what the geometry and the checksums
// can be checked against before a byte of an image is emitted.

/// This crate's reading of a boot sector, over the bytes the baseline produced.
///
/// The tier's own [`Boot::parse`] is beside it deliberately: two readings of one sector,
/// one written to the format's offset table and one written to this crate's, and a gate
/// that compares them is comparing two independent transcriptions rather than a function
/// with itself.
#[test]
fn the_boot_sector_this_crate_parses_is_the_one_the_baseline_wrote() {
    if !available("mkfs.exfat") {
        return;
    }
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let bytes = read_at(image.path(), 0, MainBootSector::SIZE);
        let parsed = MainBootSector::read_from(&bytes)
            .unwrap_or_else(|e| panic!("this crate refused the baseline's {}: {e}", volume.what));

        assert_eq!(parsed.volume_length, boot.volume_length, "{}", volume.what);
        assert_eq!(parsed.fat_offset, boot.fat_offset, "{}", volume.what);
        assert_eq!(parsed.fat_length, boot.fat_length, "{}", volume.what);
        assert_eq!(
            parsed.cluster_heap_offset, boot.heap_offset,
            "{}",
            volume.what
        );
        assert_eq!(parsed.cluster_count, boot.cluster_count, "{}", volume.what);
        assert_eq!(
            parsed.first_cluster_of_root, boot.root_cluster,
            "{}",
            volume.what
        );
        assert_eq!(parsed.volume_serial, boot.serial, "{}", volume.what);
        assert_eq!(
            parsed.bytes_per_sector(),
            Some(boot.bytes_per_sector as u32),
            "{}",
            volume.what
        );
        assert_eq!(
            parsed.bytes_per_cluster(),
            Some((boot.bytes_per_sector * boot.sectors_per_cluster) as u32),
            "{}",
            volume.what
        );
        assert_eq!(parsed.number_of_fats, boot.fats, "{}", volume.what);

        // The fields this crate models and the tier had no reason to read, held to what
        // the format defines rather than to a second reading: a volume the baseline just
        // wrote is clean, is at revision 1.00, and records no partition offset for a file
        // that is not in a partition.
        assert_eq!(parsed.volume_flags, 0, "{}", volume.what);
        assert_eq!(parsed.file_system_revision, 0x0100, "{}", volume.what);
        assert_eq!(parsed.percent_in_use, 0, "{}", volume.what);
        assert_eq!(parsed.partition_offset, 0, "{}", volume.what);

        // And it round-trips: writing what was read back out reproduces the sector byte for
        // byte, which says the reading covered every byte that carries anything. A field
        // this crate did not model would show up here as a difference and nowhere else.
        let mut written = [0u8; MainBootSector::SIZE];
        parsed.write_to(&mut written).expect("write");
        assert_eq!(
            &written[..],
            &bytes[..],
            "re-serializing the boot sector of {} does not reproduce it",
            volume.what
        );
    }
}

#[test]
fn the_planner_derives_the_geometry_the_baseline_derives() {
    if !available("mkfs.exfat") {
        return;
    }
    // The weaker of the two comparisons this family will make, and knowing which one it is
    // matters: this is field by field, and a materializer's is a whole-image byte diff. A
    // field comparison sees only the fields it compares.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        let planned = plan_layout(&volume.request)
            .unwrap_or_else(|e| panic!("the planner refused {}: {e}", volume.what));

        for (field, planned, baseline) in [
            ("VolumeLength", planned.volume_length, boot.volume_length),
            (
                "FatOffset",
                planned.fat_offset as u64,
                boot.fat_offset as u64,
            ),
            (
                "FatLength",
                planned.fat_length as u64,
                boot.fat_length as u64,
            ),
            (
                "ClusterHeapOffset",
                planned.cluster_heap_offset as u64,
                boot.heap_offset as u64,
            ),
            (
                "ClusterCount",
                planned.cluster_count as u64,
                boot.cluster_count as u64,
            ),
            (
                "FirstClusterOfRootDirectory",
                planned.first_cluster_of_root as u64,
                boot.root_cluster as u64,
            ),
            (
                "BytesPerSector",
                planned.bytes_per_sector as u64,
                boot.bytes_per_sector,
            ),
            (
                "SectorsPerCluster",
                planned.sectors_per_cluster() as u64,
                boot.sectors_per_cluster,
            ),
            // The three residents are not in the boot sector at all — the root directory is
            // what records where they are — so these are the columns only a reading of that
            // directory can confirm, and the reason a geometry gate has to open one.
            (
                "the allocation bitmap's first cluster",
                planned.bitmap_cluster as u64,
                root.bitmap.start_cluster as u64,
            ),
            (
                "the allocation bitmap's length",
                planned.bitmap_bytes,
                root.bitmap.size,
            ),
            (
                "the up-case table's first cluster",
                planned.upcase_cluster as u64,
                root.upcase.start_cluster as u64,
            ),
            (
                "the up-case table's length",
                planned.upcase_bytes,
                root.upcase.size,
            ),
        ] {
            assert_eq!(
                planned, baseline,
                "the planner and the baseline disagree about {field} for {}",
                volume.what
            );
        }

        // Where the planner says a cluster begins, against where the baseline actually put
        // one. The two residents are the only clusters an empty volume has content in, so
        // they are the only addresses that can be checked this way — and they are the ones
        // whose arithmetic spans the widest range, the last row's up-case table sitting
        // past four gigabytes.
        for (what, cluster, at) in [
            (
                "the allocation bitmap",
                planned.bitmap_cluster,
                boot.cluster_at(root.bitmap.start_cluster),
            ),
            (
                "the up-case table",
                planned.upcase_cluster,
                boot.cluster_at(root.upcase.start_cluster),
            ),
        ] {
            assert_eq!(
                planned.cluster_start_byte(cluster),
                Some(at),
                "the planner puts {what} of {} somewhere the baseline did not",
                volume.what
            );
        }
    }
}

#[test]
fn the_planner_agrees_with_the_structural_dump_field_by_field() {
    if !available("mkfs.exfat") || !available("dump.exfat") {
        return;
    }
    // A third reading, and the one that is not this project's at all. The gate above holds
    // the planner against bytes this file decoded; this holds it against what the suite's
    // own tool says those bytes mean, so a shared misreading of an offset has somewhere to
    // show up.
    for volume in VOLUMES {
        let (image, _) = formatted(volume);
        let planned = plan_layout(&volume.request).expect("plan");
        let out = tool("dump.exfat")
            .arg(image.path())
            .output()
            .expect("spawn dump.exfat");
        let said = String::from_utf8_lossy(&out.stdout).into_owned();
        let field = |label: &str| -> String {
            said.lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("dump.exfat printed no {label:?}. It said:\n{said}"))
                .split(':')
                .nth(1)
                .expect("a value after the colon")
                .trim()
                .to_string()
        };
        for (label, planned) in [
            ("Volume Length(sectors)", planned.volume_length),
            ("FAT Offset(sector offset)", planned.fat_offset as u64),
            ("FAT Length(sectors)", planned.fat_length as u64),
            (
                "Cluster Heap Offset (sector offset)",
                planned.cluster_heap_offset as u64,
            ),
            ("Cluster Count", planned.cluster_count as u64),
            (
                "Root Cluster (cluster offset)",
                planned.first_cluster_of_root as u64,
            ),
            ("Bytes per Sector", planned.bytes_per_sector as u64),
            ("Sectors per Cluster", planned.sectors_per_cluster() as u64),
            ("Bitmap size", planned.bitmap_bytes),
            ("Upcase table size", planned.upcase_bytes),
        ] {
            assert_eq!(
                field(label),
                planned.to_string(),
                "the planner and dump.exfat disagree about {label} for {}",
                volume.what
            );
        }
        // The two fields this tool prints in hexadecimal with no prefix, read as
        // hexadecimal. A gate that took them for decimal would agree with itself on every
        // volume small enough for the value to be one digit, which is four of these six.
        for (label, planned) in [
            ("Bitmap start cluster", planned.bitmap_cluster),
            ("Upcase table start cluster", planned.upcase_cluster),
        ] {
            let said = field(label);
            assert_eq!(
                u32::from_str_radix(&said, 16).expect("hexadecimal"),
                planned,
                "the planner and dump.exfat disagree about {label} for {}",
                volume.what
            );
        }
    }
}

#[test]
fn the_checksums_this_crate_computes_are_the_ones_the_baseline_stored() {
    if !available("mkfs.exfat") {
        return;
    }
    // The two an empty volume carries. The tier's own implementations above are written to
    // the arithmetic the format states; these are the crate's, and both are held to the
    // value the baseline wrote — so a gate passing means three transcriptions agree rather
    // than one being copied.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);

        for region in 0..2 {
            let base = boot.boot_region_at(region);
            let sectors = read_at(image.path(), base, (11 * boot.bytes_per_sector) as usize);
            let stored = u32::from_le_bytes(
                read_at(image.path(), base + 11 * boot.bytes_per_sector, 4)
                    .try_into()
                    .expect("four bytes"),
            );
            assert_eq!(
                crate_boot_checksum(&sectors),
                stored,
                "this crate's boot checksum for region {region} of {} is not the one the \
                 baseline stored",
                volume.what
            );
        }

        let table = read_at(
            image.path(),
            boot.cluster_at(root.upcase.start_cluster),
            root.upcase.size as usize,
        );
        assert_eq!(
            crate_upcase_checksum(&table),
            root.upcase_checksum,
            "this crate's up-case checksum for {} is not the one the baseline stored",
            volume.what
        );
        // And that value is the recommended table's, which is the constant this crate
        // recognizes the table by rather than deriving from the table's own bytes.
        assert_eq!(
            crate_upcase_checksum(&table),
            ferrosys::exfat::ondisk::RECOMMENDED_UPCASE_CHECKSUM,
            "the baseline wrote a table this crate does not recognize for {}",
            volume.what
        );
        assert_eq!(
            root.upcase.size,
            ferrosys::exfat::ondisk::RECOMMENDED_UPCASE_BYTES,
            "the recommended table's compressed length moved for {}",
            volume.what
        );
    }
}

#[test]
fn a_set_checksum_and_a_name_hash_this_crate_computed_are_ones_the_checker_accepts() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The two the baseline writes none of, so there is no stored value to compare against
    // and the checker's verdict is the vector. The fixture below is the one the controls
    // above damage, rebuilt with this crate's functions in place of this file's: the
    // checker accepting it is what says they agree, and the controls having been observed
    // failing is what says the acceptance means something.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let root = Root::read(image.path(), &boot);
        let placed = place_a_file(image.path(), &boot, &root, FIXTURE_NAME, b"ferrosys\n");

        let name: Vec<u16> = FIXTURE_NAME.encode_utf16().collect();
        let set = read_at(image.path(), placed.file_entry_at, 96);
        assert_eq!(
            crate_name_hash(&name),
            u16::from_le_bytes([set[32 + 4], set[32 + 5]]),
            "this crate's name hash for {FIXTURE_NAME} is not the one the fixture wrote"
        );
        assert_eq!(
            crate_set_checksum(&set),
            u16::from_le_bytes([set[2], set[3]]),
            "this crate's set checksum is not the one the fixture wrote"
        );

        // Written through this crate's functions rather than only compared, so what the
        // checker is asked about is bytes this crate produced.
        let mut rebuilt = set.clone();
        rebuilt[32 + 4..32 + 6].copy_from_slice(&crate_name_hash(&name).to_le_bytes());
        let checksum = crate_set_checksum(&rebuilt).to_le_bytes();
        rebuilt[2..4].copy_from_slice(&checksum);
        write_at(image.path(), placed.file_entry_at, &rebuilt);

        let said = fsck_exfat_clean(image.path()).unwrap_or_else(|e| {
            panic!(
                "the checker refused a directory entry set this crate checksummed on {}: {e}",
                volume.what
            )
        });
        assert!(
            said.contains("files 1"),
            "the checker did not count the file on {}. It said:\n{said}",
            volume.what
        );
    }
}

#[test]
fn detection_answers_this_family_for_every_row_of_the_matrix() {
    if !available("mkfs.exfat") {
        return;
    }
    // Detection over a volume no part of this crate wrote, which is the only kind that says
    // anything: every other gate in this crate reads back what it just produced.
    for volume in VOLUMES {
        let (image, _) = formatted(volume);
        // Only the first sector is read, and the classifier needs to know the source is as
        // long as the volume claims — so the file itself is handed over rather than a
        // buffer, and it is sparse.
        let file = std::fs::File::open(image.path()).expect("open the image");
        assert_eq!(
            ferrosys::detect(file).unwrap_or_else(|e| panic!("{}: {e}", volume.what)),
            ferrosys::Filesystem::ExFat,
            "{}",
            volume.what
        );
    }
}

#[test]
fn a_volume_of_a_neighbouring_family_is_not_answered_as_this_one() {
    if !available("mkfs.exfat") || !available("mkfs.fat") || !available("mke2fs") {
        return;
    }
    // The negative half, built by the neighbouring families' own baselines rather than by
    // this crate's writers — so what is being classified is a foreign volume in both
    // directions. exFAT is tried ahead of FAT, which is exactly why the FAT row matters:
    // a claim made too eagerly here means FAT is never reached.
    let fat = blank(32 * MIB);
    let out = tool("mkfs.fat")
        .args(["-F", "32"])
        .arg(fat.path())
        .output()
        .expect("spawn mkfs.fat");
    assert!(out.status.success(), "mkfs.fat refused to build a fixture");

    let ext = blank(32 * MIB);
    let out = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext4"])
        .arg(ext.path())
        .output()
        .expect("spawn mke2fs");
    assert!(out.status.success(), "mke2fs refused to build a fixture");

    for (what, path) in [("a FAT volume", fat.path()), ("an ext image", ext.path())] {
        let file = std::fs::File::open(path).expect("open the image");
        let answer = ferrosys::detect(file).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_ne!(
            answer,
            ferrosys::Filesystem::ExFat,
            "{what} was classified as exFAT"
        );
    }
}

#[test]
fn a_foreign_volume_reaches_a_reader_through_the_root_without_the_family_being_named() {
    if !available("mkfs.exfat") {
        return;
    }
    // The measurement the staged-arrival error stood in for until there was a reader: an
    // image no part of this crate wrote, opened through the root's own `open`, reaching this
    // family's reader and walking through the surface every family shares. The family is
    // named nowhere in the call — which is the whole of what that seam promises.
    let (image, _) = formatted(&VOLUMES[0]);
    let bytes = std::fs::read(image.path()).expect("read the image");
    let reader = ferrosys::open(Cursor::new(bytes)).expect("open a baseline-written volume");
    assert_eq!(reader.family(), ferrosys::Family::ExFat);

    let ferrosys::FsReader::ExFat(mut tree) = reader else {
        panic!("a volume this baseline wrote is not of this family");
    };
    let mut paths = Vec::new();
    tree.walk_tree::<ferrosys::TreeError, _>(|_, entry| {
        paths.push(entry.path.clone());
        Ok(())
    })
    .expect("walk a baseline-written volume");
    // A freshly formatted volume holds the root and nothing else: the three residents the
    // format allocates are not names in the tree.
    assert_eq!(paths, vec![Vec::<u8>::new()]);
}

// ---------------------------------------------------------------------------
// The images this crate writes, held against the ones the baseline writes
//
// The strongest statement this family makes short of a kernel mounting a volume, and the
// one the gates above exist to make meaningful: a whole-image byte comparison excludes
// nothing, so it sees every field, every reserved run, every byte of padding, and every
// hole. A field-by-field comparison sees only the fields it compares, which is what the
// FAT family paid for twice.

/// Write an empty volume of `volume`'s row with this crate, into a sparse temporary file.
///
/// The boot code comes out of `baseline` rather than out of this crate. Every implementation
/// writes its own stub there and the field is inside the boot region's checksum, so a byte
/// comparison against a baseline that carries one needs the same bytes — and lifting them
/// from the image being compared against is what keeps the *crate* free of another project's
/// machine code while leaving the comparison total.
fn ferrosys_format(volume: &Volume, baseline: &Path, serial: u32) -> tempfile::NamedTempFile {
    ferrosys_format_from(volume, baseline, serial, TreeBuilder::new())
}

/// The same, populated from `source`.
///
/// Held apart from the caller above rather than defaulted, because which of the two a gate uses
/// is the whole of what that gate is about: an empty tree is what the byte comparison against
/// the baseline needs, and a populated one is what the baseline cannot produce at all.
fn ferrosys_format_from(
    volume: &Volume,
    baseline: &Path,
    serial: u32,
    source: impl Source,
) -> tempfile::NamedTempFile {
    let mut boot_code = [0u8; BOOT_CODE_LEN];
    boot_code.copy_from_slice(&read_at(baseline, 120, BOOT_CODE_LEN));

    let image = blank(volume.bytes);
    let options = FormatOptions::new(serial)
        .label(VolumeLabel::new(LABEL).expect("the fixture label fits"))
        .boot_code(boot_code)
        .plan(volume.request);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(image.path())
        .expect("open the image for writing");
    format_to(file, source, volume.bytes, options)
        .unwrap_or_else(|e| panic!("this crate could not build {}: {e}", volume.what));
    image
}

#[test]
fn an_empty_volume_this_crate_writes_is_byte_identical_to_the_baseline() {
    if !available("mkfs.exfat") || !available("tune.exfat") {
        return;
    }
    // Whole-image and unqualified. The two images are the same size, so a difference in
    // length is a difference at an offset like any other, and nothing here is excluded — not
    // the boot code, not the reserved runs, not the padding from the up-case table's end to
    // the end of the cluster it sits in, and not the holes.
    for volume in VOLUMES {
        let (baseline, _) = formatted(volume);
        let ours = ferrosys_format(volume, baseline.path(), PINNED_SERIAL);
        let differences = differing_ranges(baseline.path(), ours.path());
        if let Some(first) = differences.first() {
            // The first offset and both readings of it, because that is what a person
            // debugging this needs: a region of the volume follows from an offset, and "the
            // images differ" does not.
            let at = first.start & !0xF;
            let theirs = read_at(baseline.path(), at, 16);
            let mine = read_at(ours.path(), at, 16);
            panic!(
                "{}: this crate's image differs from the baseline's at {}.\n  \
                 at {at:#x}: baseline {theirs:02x?}\n  at {at:#x}: ferrosys {mine:02x?}",
                volume.what,
                summarize(&differences)
            );
        }
    }
}

#[test]
fn the_checker_is_clean_on_every_volume_this_crate_writes() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // Byte-identity to a baseline the checker accepts already implies this, so what this gate
    // adds is independence from that one: the two would have to fail together for a defect to
    // pass, and they rest on different things — one on the baseline's bytes and one on the
    // checker's opinion. It is also the gate that survives a later re-baselining, when the
    // pin moves and the byte comparison is the thing being re-established.
    for volume in VOLUMES {
        let (baseline, _) = formatted(volume);
        let ours = ferrosys_format(volume, baseline.path(), PINNED_SERIAL);
        let said = fsck_exfat_clean(ours.path()).unwrap_or_else(|e| {
            panic!(
                "the checker refused a volume this crate wrote for {}: {e}",
                volume.what
            )
        });
        assert!(
            said.contains("clean"),
            "the checker did not call {} clean. It said:\n{said}",
            volume.what
        );
    }
}

#[test]
fn the_label_this_crate_wrote_is_the_one_the_suite_reads_back() {
    if !available("mkfs.exfat") || !available("exfatlabel") {
        return;
    }
    // A second implementation's reading of the one field a person names, over a volume this
    // crate wrote. The byte comparison above covers it, and this does not rest on the
    // baseline: `exfatlabel` finds the label by walking the root directory, so a volume whose
    // entries were in the wrong order would answer this differently even where every byte of
    // the entry itself was right.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format(volume, baseline.path(), PINNED_SERIAL);
    let out = tool("exfatlabel")
        .arg(ours.path())
        .output()
        .expect("spawn exfatlabel");
    assert!(out.status.success(), "exfatlabel refused the volume");
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.contains(LABEL),
        "exfatlabel did not read back the label this crate wrote. It said:\n{said}"
    );
}

#[test]
fn a_volume_this_crate_writes_at_another_serial_differs_in_exactly_the_places_the_baseline_does() {
    if !available("mkfs.exfat") || !available("tune.exfat") {
        return;
    }
    // The control on the gate above, and on this crate's reproducibility claim at once. Two
    // baselines at different serials differ in four bytes of each boot region and in the
    // sector that checksums each; two of this crate's images at those same two serials must
    // differ in the same places and nowhere else. A writer that had quietly pinned something
    // else to the serial — a hash seed, an offset — would pass the byte comparison at one
    // serial and fail here.
    let volume = &VOLUMES[0];
    let other = 0x89AB_CDEF;

    let (baseline, _) = formatted(volume);
    let mine = ferrosys_format(volume, baseline.path(), PINNED_SERIAL);
    let theirs = ferrosys_format(volume, baseline.path(), other);

    let (baseline_other, _) = formatted_with(volume, other);
    assert_eq!(
        differing_ranges(mine.path(), theirs.path()),
        differing_ranges(baseline.path(), baseline_other.path()),
        "changing the serial moves a different set of bytes in this crate's images than it \
         does in the baseline's"
    );
}

// ---------------------------------------------------------------------------
// A populated volume, which the baseline cannot produce
//
// Every gate above rests on a differential against `mkfs.exfat`. None of them can reach a
// file, because `mkfs.exfat` writes none: an empty exFAT volume holds a label, a reserved
// slot, a bitmap, and an up-case table, and not one of them is a file set. So the tier's
// shape changes here: it stops being a byte comparison and becomes a checker plus a foreign
// *reader*, asked to find each file by name and say where its bytes are.
//
// Both halves, because a stream extension can carry the right length and the wrong first
// cluster and an enumeration would still be exactly right.

/// The tree every populated gate below writes.
///
/// Chosen so that each entry reaches something no other one does: a name needing more than one
/// name entry, a name with spaces and mixed case, a file spanning several clusters, an empty
/// file that owns none, a subdirectory with something inside it, and a read-only file, which is
/// the one permission bit the format carries.
const TREE: &[Entry] = &[
    Entry::file("/A Long Name With Spaces.dat", 1),
    Entry::dir("/DCIM"),
    Entry::file("/DCIM/IMG_0001.JPG", 9_000),
    Entry::file("/EMPTY.BIN", 0),
    Entry::file("/README.TXT", 6),
];

/// One entry of [`TREE`].
///
/// What each is, is stated rather than inferred from its name. A gate that guessed would guess
/// the same way the builder below guesses, and the two agreeing would be one rule twice rather
/// than a reading of what is on the volume.
struct Entry {
    path: &'static str,
    dir: bool,
    len: usize,
}

impl Entry {
    const fn file(path: &'static str, len: usize) -> Self {
        Self {
            path,
            dir: false,
            len,
        }
    }

    const fn dir(path: &'static str) -> Self {
        Self {
            path,
            dir: true,
            len: 0,
        }
    }
}

/// An instant every field of an entry holds exactly, so no gate below is also asserting a
/// rounding: 2015-03-14T09:26:52Z, an even second with no fraction.
const TREE_TIME: i64 = 1_426_325_212;

/// The bytes `path` holds in [`TREE`], which are a function of the path so that a file found
/// under the wrong name is a file whose contents do not match.
fn tree_contents(path: &str, len: usize) -> Vec<u8> {
    path.bytes().cycle().take(len).collect()
}

/// [`TREE`] as a source, with the read-only file this crate can carry faithfully.
fn tree_source() -> TreeBuilder {
    let time = Timestamp::from_secs(TREE_TIME);
    let mut source = TreeBuilder::new();
    for entry in TREE {
        source = if entry.dir {
            source.directory(entry.path.as_bytes().to_vec(), Metadata::new(0o755, time))
        } else {
            // Read-only on one of them, which is the one permission bit the format carries.
            let mode = if entry.path == "/README.TXT" {
                0o444
            } else {
                0o644
            };
            source.file(
                entry.path.as_bytes().to_vec(),
                tree_contents(entry.path, entry.len),
                Metadata::new(mode, time),
            )
        };
    }
    source
}

/// Everything `dump.exfat` says about the directory tree under `/`, recursively.
fn dump_tree(image: &Path) -> String {
    let out = tool("dump.exfat")
        .args(["-s", "/", "-r"])
        .arg(image)
        .output()
        .expect("spawn dump.exfat");
    assert!(out.status.success(), "dump.exfat refused the volume");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The entry set `dump.exfat` finds at `path`, or `None` where it finds nothing there.
///
/// The exit status is what says which: the tool prints its banner and nothing else for a path
/// it cannot resolve, so a gate reading only the output would take "not found" for an empty
/// answer to a question it did ask.
fn dump_dentry_set(image: &Path, path: &str) -> Option<String> {
    let out = tool("dump.exfat")
        .args(["-d", path])
        .arg(image)
        .output()
        .expect("spawn dump.exfat");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The value `dump.exfat` printed for `label`, as text.
fn dumped(said: &str, label: &str) -> String {
    said.lines()
        .find_map(|line| line.trim().strip_prefix(label)?.split(':').nth(1))
        .unwrap_or_else(|| panic!("dump.exfat printed no {label:?}. It said:\n{said}"))
        .trim()
        .to_string()
}

#[test]
fn the_checker_is_clean_on_every_populated_volume_this_crate_writes() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The hard gate of the populated tier, run at every row of the matrix — so the sector size,
    // the cluster size, and whether the bitmap spans one cluster or many are all varied under
    // it. What it is checking that the empty tier could not: every set checksum, every name
    // hash, and every cluster a file chains through being marked used in the bitmap.
    //
    // That last one is the reason a populated volume is checked at all where an empty one's
    // bitmap is unreachable (see the gate above on what the checker does *not* reach): a file
    // is what gives the checker a cluster to walk to.
    for volume in VOLUMES {
        let (baseline, _) = formatted(volume);
        let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
        let said = fsck_exfat_clean(ours.path()).unwrap_or_else(|e| {
            panic!(
                "the checker refused a populated volume this crate wrote for {}: {e}",
                volume.what
            )
        });
        assert!(
            said.contains("clean"),
            "the checker did not call the populated {} clean. It said:\n{said}",
            volume.what
        );
        // And it counted what went in. `directories` includes the root, which is one more than
        // the tree declares.
        assert!(
            said.contains("directories 2, files 4"),
            "the checker found a different tree on {} than went into it. It said:\n{said}",
            volume.what
        );
    }
}

#[test]
fn the_structural_dump_enumerates_the_tree_that_went_in() {
    if !available("mkfs.exfat") || !available("dump.exfat") {
        return;
    }
    // A second implementation walking the directories this crate wrote and reassembling every
    // name out of the entries behind each stream extension. It is the half a checker does not
    // do: `fsck.exfat` counts files and verifies their checksums without ever saying what any
    // of them is called, so a volume whose names were all mangled identically would be clean.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
    let said = dump_tree(ours.path());

    let found: Vec<&str> = said
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Path:"))
        .map(str::trim)
        .collect();
    let expected: Vec<&str> = TREE.iter().map(|entry| entry.path).collect();
    assert_eq!(
        found, expected,
        "dump.exfat walked a different tree than went in. It said:\n{said}"
    );
}

#[test]
fn a_foreign_reading_of_an_entry_finds_the_bytes_that_went_into_it() {
    if !available("mkfs.exfat") || !available("dump.exfat") {
        return;
    }
    // The other half. An enumeration is right about every name and says nothing about where any
    // of the data is, so this asks the foreign tool for each file's first cluster and length,
    // computes the offset from the boot sector the same tool read, and compares the bytes. A
    // stream extension naming the right length and the wrong cluster passes the gate above and
    // fails this one.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
    let boot = Boot::parse(&read_at(ours.path(), 0, 512));

    for entry in TREE {
        let path = entry.path;
        let said = dump_dentry_set(ours.path(), path)
            .unwrap_or_else(|| panic!("dump.exfat could not resolve {path}"));
        let first: u64 = dumped(&said, "FirstCluster")
            .parse()
            .expect("a cluster number");
        let length: u64 = dumped(&said, "DataLength").parse().expect("a length");
        let valid: u64 = dumped(&said, "ValidDataLength")
            .parse()
            .expect("a valid length");
        assert_eq!(
            valid, length,
            "{path}: a format writes every byte it allocates, so the two lengths are one number"
        );

        if entry.dir {
            // A directory's length is its whole allocation, which the format states as a
            // number of clusters — unlike a file's, which is its bytes. There is nothing here
            // to compare against a source, so what is asserted is the shape.
            assert_eq!(
                length % boot.cluster_size(),
                0,
                "{path}: a whole cluster count"
            );
            assert!(length > 0, "{path}: every directory has a cluster");
            continue;
        }

        assert_eq!(
            length, entry.len as u64,
            "{path}: the length dump.exfat read"
        );
        if entry.len == 0 {
            // An empty file owns no cluster, and the format says so with a zero rather than
            // with a cluster nothing is in.
            assert_eq!(first, 0, "{path}: an empty file owns no cluster");
            continue;
        }
        let at = boot.cluster_at(first as u32);
        assert_eq!(
            read_at(ours.path(), at, entry.len),
            tree_contents(path, entry.len),
            "{path}: the bytes where a foreign reading of the entry says they are"
        );
    }
}

#[test]
fn every_entry_a_populated_volume_carries_says_what_the_source_said() {
    if !available("mkfs.exfat") || !available("dump.exfat") {
        return;
    }
    // The fields a checker has no opinion about and an enumeration does not print: the
    // attribute word, the zone offsets, and the flag that says the allocation table holds no
    // chain for this stream. Each is read back through the foreign tool, which is what makes it
    // an observation rather than a restatement.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());

    for (path, attributes, flags) in [
        // Archive, and a contiguous allocation the table holds no chain for.
        ("/A Long Name With Spaces.dat", "0x0020", "0x03"),
        // Read-only and archive: the one permission bit the format carries.
        ("/README.TXT", "0x0021", "0x03"),
        // An empty file: allocation is possible, and there is none to declare contiguous.
        ("/EMPTY.BIN", "0x0020", "0x01"),
        // A directory, whose own allocation is contiguous like any other.
        ("/DCIM/IMG_0001.JPG", "0x0020", "0x03"),
    ] {
        let said = dump_dentry_set(ours.path(), path).unwrap_or_else(|| {
            panic!("dump.exfat could not resolve {path}");
        });
        assert_eq!(dumped(&said, "FileAttributes"), attributes, "{path}");
        assert_eq!(dumped(&said, "GeneralSecondaryFlags"), flags, "{path}");
        for field in [
            "CreateUtcOffset",
            "LastModifiedUtcOffset",
            "LastAccessedUtcOffset",
        ] {
            assert_eq!(
                dumped(&said, field),
                "128",
                "{path}: {field} — a volume built from instants records that its times are UTC"
            );
        }
    }
}

#[test]
fn the_times_an_entry_records_are_the_instant_the_source_named() {
    if !available("mkfs.exfat") {
        return;
    }
    // Read out of the image rather than out of `dump.exfat`, and that is not a preference.
    // **The tool prints only the low sixteen bits of a timestamp field** — the time word — and
    // discards the date word entirely, so two files a year apart print identically. A gate
    // reading `CreateTimestamp` from it would agree with itself on any two volumes whose times
    // of day matched and would be blind to the whole date. The control below is what says so
    // rather than the comment.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
    let boot = Boot::parse(&read_at(ours.path(), 0, 512));

    // The words 2015-03-14T09:26:52Z packs into, by the field positions the format states
    // rather than by this crate's arithmetic.
    let date = ((2015u32 - 1980) << 9) | (3 << 5) | 14;
    let time = (9u32 << 11) | (26 << 5) | (52 / 2);
    let packed = (date << 16) | time;

    // The root's first file set begins behind the four entries a format writes.
    let set = read_at(ours.path(), boot.cluster_at(boot.root_cluster) + 4 * 32, 32);
    assert_eq!(set[0], 0x85, "the fifth slot of the root is a file entry");
    for (label, at) in [("create", 8), ("modify", 12), ("access", 16)] {
        let field = u32::from_le_bytes([set[at], set[at + 1], set[at + 2], set[at + 3]]);
        assert_eq!(field, packed, "the {label} time");
    }
    // The hundredths and the zone, which the words have no room for.
    assert_eq!(&set[20..25], &[0, 0, 0x80, 0x80, 0x80]);

    if available("dump.exfat") {
        // The control on the paragraph above: what the tool prints is the time word alone.
        let said = dump_dentry_set(ours.path(), "/A Long Name With Spaces.dat")
            .expect("dump.exfat resolves the first entry");
        assert_eq!(
            dumped(&said, "CreateTimestamp"),
            format!("0x{time:08X}"),
            "dump.exfat prints a timestamp's low half, so no gate may read a date from it"
        );
    }
}

#[test]
fn a_damaged_set_checksum_on_a_volume_this_crate_wrote_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The controls above damage a fixture this tier built by hand. This one damages a set the
    // *writer* produced, which is what makes the clean verdict above attributable: a checker
    // that had stopped looking at these volumes for any reason would call both clean.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
    assert!(
        fsck_exfat_clean(ours.path()).is_ok(),
        "the volume must be clean before it is damaged, or a refusal says nothing"
    );

    let boot = Boot::parse(&read_at(ours.path(), 0, 512));
    let at = boot.cluster_at(boot.root_cluster) + 4 * 32;
    let mut sum = read_at(ours.path(), at + 2, 2);
    sum[0] ^= 0xFF;
    write_at(ours.path(), at + 2, &sum);
    assert!(
        fsck_exfat_clean(ours.path()).is_err(),
        "the checker accepted a set whose checksum does not cover it"
    );
}

#[test]
fn a_name_hash_no_name_produces_on_a_volume_this_crate_wrote_is_rejected() {
    if !available("mkfs.exfat") || !available("fsck.exfat") {
        return;
    }
    // The same, one field further in, and the one no checksum covers on its own: the hash is
    // recomputed here over the damage so the set checksum still holds, which is what makes the
    // refusal a statement about the *hash* rather than about the checksum over it. A wrong hash
    // costs no data and makes a file invisible to a driver that trusts it, which is worse than
    // corruption for being silent.
    let volume = &VOLUMES[0];
    let (baseline, _) = formatted(volume);
    let ours = ferrosys_format_from(volume, baseline.path(), PINNED_SERIAL, tree_source());
    assert!(
        fsck_exfat_clean(ours.path()).is_ok(),
        "clean before the damage"
    );

    let boot = Boot::parse(&read_at(ours.path(), 0, 512));
    let set_at = boot.cluster_at(boot.root_cluster) + 4 * 32;
    let slots = usize::from(read_at(ours.path(), set_at, 32)[1]) + 1;
    let mut set = read_at(ours.path(), set_at, slots * 32);

    // The hash lives at offset 4 of the stream extension, which is the second entry.
    set[32 + 4] ^= 0xFF;
    // Recomputed over the damage, so nothing but the hash is wrong.
    set[2] = 0;
    set[3] = 0;
    let sum = crate_set_checksum(&set);
    set[2..4].copy_from_slice(&sum.to_le_bytes());
    write_at(ours.path(), set_at, &set);

    assert!(
        fsck_exfat_clean(ours.path()).is_err(),
        "the checker accepted a name hash no name produces"
    );
}

// ---------------------------------------------------------------------------
// The foreign-image matrix
//
// Everything above populates a volume through this crate. That is the wrong direction for
// a reader: an image whose every layout decision was made here proves only that the two
// halves of one implementation agree. What a reader has to be held to is a volume some
// other implementation laid out.
//
// `exfatprogs` cannot supply one — `mkfs.exfat` writes no files — and this family has no
// mtools. relan/exfat's `libexfat` is the second complete implementation of the format,
// and `ci/exfat-populate.c` is the command line it does not ship: a program that opens an
// image and makes directories and files through that library's own API, with no mount, no
// `/dev/fuse`, no loop device, no kernel, and no root.
//
// The gates here certify the populator before anything depends on it, which is the order
// this project works in. Two things have to be true for it to be worth pinning, and neither
// is self-evident:
//
// - **What it writes is acceptable.** `fsck.exfat` — an oracle already calibrated above —
//   is what says so, and its own count of what it found is what says the tree arrived.
// - **What it writes is not what this crate writes.** A populator that produced exactly
//   the layouts the writer here produces would add nothing a round trip does not already
//   cover. Three layouts are the point: a stream chained through the allocation table,
//   which this writer never emits; a `ValidDataLength` behind its
//   `DataLength`, which a format-time writer cannot produce because it writes everything
//   it allocates; and both of those on a volume alongside a contiguous stream, so the
//   reader meets the two run shapes in one image.
//
// Then this crate's reader is held to what those two foreign implementations produced, over
// a matrix rather than over one volume — and to both halves of it, because either alone
// misses a whole class. A reader that cannot follow a chain still reports no anomalies about
// it, so a clean scan alone would pass a reader that read nothing; and an enumeration can be
// exactly right while every file's contents come from the wrong cluster. The negative
// controls at the end are what say the gate would notice either.

/// Where a row's allocation unit sits in the band the format defines.
///
/// A position rather than a size, because the size is a position and a sector size together:
/// the smallest unit a volume can have is one sector, so the floor of the band is 512 bytes
/// on one row and four kilobytes on another. Pair coverage is over the positions, which is
/// what makes "one sector to the cluster" a value two rows share rather than two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterBand {
    /// One sector to the cluster: the smallest unit the row's sector size allows, and the
    /// densest allocation table and bitmap a volume of a given size can have.
    Floor,
    /// Thirty-two kilobytes, which is what the baseline picks for volumes of ordinary size.
    Middle,
    /// A mebibyte, where a cluster number is shifted eleven places at the small sector size
    /// and eight at the large one.
    High,
}

/// One row of the foreign-image matrix.
///
/// A row states the two dimensions of the volume's geometry and the two properties of the
/// tree put into it. What `mkfs.exfat` is told is derived from the first two rather than
/// written beside them: nothing here formats with ferrosys, so unlike [`Volume`] there is no
/// second vocabulary for a pair of columns to correspond in.
struct ForeignRow {
    /// What this row is, quoted in every failure so that it names the volume rather than a
    /// sector count.
    what: &'static str,
    bytes: u64,
    bytes_per_sector: u32,
    band: ClusterBand,
    /// Whether this row's fixture leaves a stream chained through the allocation table.
    /// Asserted rather than reported: a fixture that stopped reaching a chain would have
    /// stopped covering the run shape this crate's own writer never produces, and that is a
    /// failure and not a change.
    chained: bool,
    /// Whether this row's allocation bitmap spans more than one cluster, which is what makes
    /// the bitmap itself a chain to be followed rather than one cluster to be read.
    wide_bitmap: bool,
}

impl ForeignRow {
    /// The row's allocation unit, in bytes.
    fn bytes_per_cluster(&self) -> u32 {
        match self.band {
            ClusterBand::Floor => self.bytes_per_sector,
            ClusterBand::Middle => 32 << 10,
            ClusterBand::High => 1 << 20,
        }
    }

    /// What the pinned baseline is told to build this row.
    fn args(&self) -> Vec<String> {
        vec![
            "-s".to_string(),
            self.bytes_per_sector.to_string(),
            "-c".to_string(),
            self.bytes_per_cluster().to_string(),
        ]
    }

    /// The length of this row's large files.
    ///
    /// Several clusters at every row, which is the floor a run shape means anything above;
    /// and at the dense end of the matrix two hundred thousand bytes is three hundred and
    /// ninety-one five-hundred-and-twelve-byte clusters, so a chain there is long enough that
    /// following it wrongly lands somewhere visible rather than one cluster out.
    fn big(&self) -> u64 {
        200_000.max(4 * u64::from(self.bytes_per_cluster()))
    }

    /// Whether a byte offset in this row passes what a 32-bit quantity holds.
    fn past_four_gigabytes(&self) -> bool {
        self.bytes > u64::from(u32::MAX)
    }
}

/// The volumes every foreign-image gate runs over.
///
/// **A covering array and not a cross product.** The dimensions are the sector size, where
/// the cluster sits in the band, whether the allocation bitmap spans one cluster or many, and
/// whether the tree carries a chained stream — twenty-four combinations, of which these six
/// carry every *pair*. The pair is the unit worth covering because what a reader gets wrong
/// here is arithmetic that multiplies two dimensions together: every region's byte offset is
/// a sector count times a sector size, a cluster's is that plus a cluster number times a
/// cluster size, and a chain is followed through a table whose entry for a cluster is found
/// by both.
///
/// Sized by what a row reaches rather than by how large it is, which here is the
/// difference between a matrix that runs in seconds and one that does not: the cluster counts
/// below span three orders of magnitude and no image costs more than a few megabytes on disk,
/// because every one of them is a sparse file with only its metadata and its tree written
/// into it.
///
/// **One pair is missing, and it is arithmetic rather than an omission.** The bitmap spans
/// more than one cluster only where the volume holds more than eight bits' worth of clusters
/// per cluster — more than `8 × bytes-per-cluster` of them — so a volume reaching it is larger
/// than `8 × bytes-per-cluster²`. That is two megabytes at 512-byte clusters, eight gigabytes
/// at thirty-two-kilobyte ones, and eight *terabytes* at the megabyte clusters of the last two
/// rows. So (`ClusterBand::High`, a wide bitmap) is not covered, the wide bitmap is carried at
/// the two positions where it is affordable, and
/// [`every_row_of_the_foreign_matrix_reaches_what_it_claims`] names that pair as the only one
/// missing rather than leaving the gap to be inferred: a matrix that quietly stopped at what
/// it could afford would read as coverage.
const FOREIGN_MATRIX: &[ForeignRow] = &[
    ForeignRow {
        what: "one sector to the cluster, at the smallest sector the format defines",
        bytes: 32 * MIB,
        bytes_per_sector: 512,
        band: ClusterBand::Floor,
        chained: true,
        wide_bitmap: true,
    },
    ForeignRow {
        what: "one sector to the cluster, at the largest sector the format defines",
        bytes: 64 * MIB,
        bytes_per_sector: 4096,
        band: ClusterBand::Floor,
        chained: false,
        wide_bitmap: false,
    },
    ForeignRow {
        what: "thirty-two-kilobyte clusters of sixty-four small sectors",
        bytes: 512 * MIB,
        bytes_per_sector: 512,
        band: ClusterBand::Middle,
        chained: true,
        wide_bitmap: false,
    },
    ForeignRow {
        what: "a volume whose byte offsets pass four gigabytes, whose bitmap spans two clusters",
        bytes: 16 * GIB,
        bytes_per_sector: 4096,
        band: ClusterBand::Middle,
        chained: false,
        wide_bitmap: true,
    },
    ForeignRow {
        what: "megabyte clusters of two thousand small sectors",
        bytes: GIB,
        bytes_per_sector: 512,
        band: ClusterBand::High,
        chained: false,
        wide_bitmap: false,
    },
    ForeignRow {
        what: "megabyte clusters at the largest sector the format defines",
        bytes: GIB,
        bytes_per_sector: 4096,
        band: ClusterBand::High,
        chained: true,
        wide_bitmap: false,
    },
];

/// The row the single-volume gates run against.
///
/// The first one, and for two reasons that are one reason: it is the cheapest volume in the
/// matrix and it is the one carrying the most for a control to reach. Its bitmap is a chain,
/// its tree holds a stream the allocation table describes, and its clusters are the smallest
/// the format defines — so a damaged byte is close to everything it could matter to.
const FOREIGN_REPRESENTATIVE: &ForeignRow = &FOREIGN_MATRIX[0];

/// The name that takes more than one `0xC1` entry to spell.
///
/// Thirty UTF-16 units, where an entry holds fifteen, so the set carrying it is a file entry,
/// a stream extension, and two name entries — and a reader that reassembled only the first
/// would hand back a name that looks complete. Mixed case as well, which is what makes its
/// hash a statement about the volume's own up-case table rather than about the bytes of the
/// name.
const FOREIGN_LONG_NAME: &str = "A_Long_Name_For_The_Reader.bin";

/// What the foreign populator is told to build on `row`.
///
/// The order is the whole of the chaining half. `GAP.BIN` is written between two large files
/// and then removed, which leaves a one-cluster hole with an allocated file on each side; the
/// next file written takes the hole first and continues past the far side, and so is chained
/// through the allocation table rather than contiguous. A row that is not a chaining row
/// leaves those three lines out and gets a volume on which every stream is consecutive, which
/// is the other value of that dimension rather than merely its absence — a reader that always
/// walked the table would still be right on every row that has one.
///
/// `SHORT.BIN` is written and then extended without the extension being written, on every
/// row: a valid length behind an allocated one is the one state no format-time writer
/// produces, and it is a property of a file rather than of an allocation, so it is not a
/// dimension of the matrix.
///
/// The label is seven UTF-16 units, inside the eleven the field holds. It is worth saying
/// that this is a constraint the populator does not enforce: `libexfat` writes a longer one's
/// character count into a field that cannot hold the characters, `fsck.exfat` calls the volume
/// clean, and `exfatlabel` then refuses to read it back. A volume like that is a thing a
/// reader will meet and is not what these gates are establishing.
fn foreign_script(row: &ForeignRow) -> String {
    let big = row.big();
    let mut script = String::from("label FOREIGN\nmkdir /DCIM\nmkdir /DCIM/100MEDIA\n");
    script += &format!("write /DCIM/100MEDIA/DEEP.BIN {big} 1\n");
    if row.chained {
        script += &format!("write /GAP.BIN {} 2\n", row.bytes_per_cluster());
    }
    script += &format!("write /DCIM/SECOND.BIN {big} 3\n");
    if row.chained {
        script += "unlink /GAP.BIN\n";
        script += &format!("write /CHAINED.BIN {big} 4\n");
    }
    script += "write /SHORT.BIN 10 5\n";
    script += &format!("grow /SHORT.BIN {big}\n");
    script += &format!("write /{FOREIGN_LONG_NAME} 37 6\n");
    script
}

/// How long one of [`FOREIGN_FILES`] is, on a row whose clusters are its own size.
#[derive(Clone, Copy)]
enum Length {
    /// A fixed count of bytes, smaller than the smallest cluster in the matrix, so the file
    /// is one cluster on every row and its tail is the part of a cluster nothing wrote.
    Bytes(u64),
    /// The row's own [`ForeignRow::big`].
    Big,
}

impl Length {
    fn of(self, row: &ForeignRow) -> u64 {
        match self {
            Length::Bytes(bytes) => bytes,
            Length::Big => row.big(),
        }
    }
}

/// One file [`foreign_script`] leaves behind, and what it is for.
struct ForeignFile {
    /// Where it is, in the syntax a walk spells and `dump.exfat -d` resolves.
    path: &'static str,
    /// `DataLength`: what the file is allocated for.
    len: Length,
    /// `ValidDataLength`: how much of that was written. The two differ on exactly one of
    /// these files, and the bytes past it are undefined rather than zero.
    valid: Length,
    /// The seed its contents were generated from.
    seed: u32,
    /// Whether its stream declares `NoFatChain`.
    contiguous: bool,
    /// Whether only a row that fragments its free space produces this file.
    only_when_chained: bool,
}

/// The files [`foreign_script`] leaves behind.
///
/// Stated rather than parsed out of the script, for the reason [`TREE`] states its own shape:
/// a gate that derived its expectations from the same text the populator read would be one
/// rule written twice, and would agree with itself however the populator behaved.
const FOREIGN_FILES: &[ForeignFile] = &[
    ForeignFile {
        path: "/DCIM/100MEDIA/DEEP.BIN",
        len: Length::Big,
        valid: Length::Big,
        seed: 1,
        contiguous: true,
        only_when_chained: false,
    },
    ForeignFile {
        path: "/DCIM/SECOND.BIN",
        len: Length::Big,
        valid: Length::Big,
        seed: 3,
        contiguous: true,
        only_when_chained: false,
    },
    ForeignFile {
        path: "/CHAINED.BIN",
        len: Length::Big,
        valid: Length::Big,
        seed: 4,
        contiguous: false,
        only_when_chained: true,
    },
    ForeignFile {
        path: "/SHORT.BIN",
        len: Length::Big,
        valid: Length::Bytes(10),
        seed: 5,
        contiguous: true,
        only_when_chained: false,
    },
    ForeignFile {
        path: "/A_Long_Name_For_The_Reader.bin",
        len: Length::Bytes(37),
        valid: Length::Bytes(37),
        seed: 6,
        contiguous: true,
        only_when_chained: false,
    },
];

/// The directories every row's tree carries, parents before children.
///
/// Two levels deep on purpose: a populator that could only fill a root would leave a reader's
/// directory descent untested, and a walk that recurses one level less than it should still
/// returns a tree that looks entirely plausible.
const FOREIGN_DIRECTORIES: &[&str] = &["/DCIM", "/DCIM/100MEDIA"];

/// The files `row`'s tree holds.
fn foreign_files_of(row: &ForeignRow) -> impl Iterator<Item = &'static ForeignFile> {
    let chained = row.chained;
    FOREIGN_FILES
        .iter()
        .filter(move |file| chained || !file.only_when_chained)
}

/// Every path a walk of `row`'s volume should yield, in the order it should yield them.
///
/// Sorted, which is the walk's order and not merely a normalization of it: a walk descends
/// with each directory's children in name order, and every name in the fixture is above `/`
/// in byte order, so sorting whole paths puts a directory immediately ahead of its own
/// subtree.
fn foreign_paths(row: &ForeignRow) -> Vec<String> {
    let mut paths: Vec<String> = FOREIGN_DIRECTORIES
        .iter()
        .map(|dir| (*dir).to_string())
        .chain(foreign_files_of(row).map(|file| file.path.to_string()))
        .collect();
    paths.sort();
    paths
}

/// The `write` command's fill: the little-endian 32-bit counter `j + seed` at offset
/// `4 * j`, with a trailing partial word truncated.
///
/// `ci/exfat-populate.c` writes this and this reads it, in two languages that share
/// nothing. That is the point rather than a duplication to be removed — a generator the
/// gate and the populator both took from one implementation would agree with itself. What
/// makes it a check is that a word names the offset it belongs at, so a reader that lands
/// four bytes out reads a number that says where it actually is.
fn foreign_contents(len: u64, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let word = (i / 4) as u32 + seed;
            (word >> (8 * (i % 4))) as u8
        })
        .collect()
}

/// A directory entry set read out of a foreign volume.
#[derive(Debug)]
struct ForeignSet {
    /// The whole path it was found at, which is what a walk of the same volume spells.
    path: String,
    name: String,
    directory: bool,
    first_cluster: u32,
    len: u64,
    valid: u64,
    /// Bit 1 of `GeneralSecondaryFlags`: the stream's clusters are consecutive and the
    /// allocation table holds nothing for it.
    no_fat_chain: bool,
    /// Where each of the set's 32-byte entries begins in the image, the file entry first.
    ///
    /// Every entry rather than the first: an entry is 32 bytes and a cluster is a multiple of
    /// 32, so a set can straddle a cluster boundary — and the arithmetic that would find its
    /// second entry from its first is arithmetic a control would then be testing against
    /// itself.
    slots: Vec<u64>,
}

/// The clusters a stream occupies, in order.
///
/// The one place this tier decides between the two run shapes, so that reading a stream's
/// bytes and finding where one of its bytes lives are the same walk rather than two.
///
/// `no_fat_chain` decides which: a stream that declares it is contiguous is walked by
/// stepping to the next cluster, and one that does not is walked through the allocation
/// table. The distinction is not cosmetic — the format defines a contiguous stream's table
/// entries as invalid, so a reader that consulted them anyway would be reading whatever the
/// last owner of those entries left behind.
///
/// `len` is what ends a contiguous walk, there being nothing on the medium that does. The
/// root directory has no entry and no length, so it is the one stream walked without one —
/// and it is always chained, which is what makes that possible.
fn foreign_clusters(
    image: &Path,
    boot: &Boot,
    first_cluster: u32,
    no_fat_chain: bool,
    len: Option<u64>,
) -> Vec<u32> {
    assert!(
        len.is_some() || !no_fat_chain,
        "a contiguous stream with no length has no end to walk to"
    );
    let mut out = Vec::new();
    let mut at = first_cluster;
    loop {
        assert!(
            at >= 2 && at < boot.cluster_count + 2,
            "a foreign stream reaches cluster {at}, which is not in the heap"
        );
        out.push(at);
        if len.is_some_and(|len| out.len() as u64 * boot.cluster_size() >= len) {
            break;
        }
        if no_fat_chain {
            at += 1;
            continue;
        }
        let next = u32::from_le_bytes(
            read_at(image, boot.fat_entry_at(at), 4)
                .try_into()
                .expect("four bytes"),
        );
        if next == 0xFFFF_FFFF {
            break;
        }
        at = next;
    }
    out
}

/// The bytes of a stream, read the way the stream itself says to read it.
fn foreign_stream(
    image: &Path,
    boot: &Boot,
    first_cluster: u32,
    no_fat_chain: bool,
    len: Option<u64>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for at in foreign_clusters(image, boot, first_cluster, no_fat_chain, len) {
        out.extend_from_slice(&read_at(
            image,
            boot.cluster_at(at),
            boot.cluster_size() as usize,
        ));
    }
    if let Some(len) = len {
        out.truncate(len as usize);
    }
    out
}

/// Where byte `offset` of a stream lands in the image.
fn foreign_offset(
    image: &Path,
    boot: &Boot,
    first_cluster: u32,
    no_fat_chain: bool,
    offset: u64,
) -> u64 {
    let size = boot.cluster_size();
    let clusters = foreign_clusters(image, boot, first_cluster, no_fat_chain, Some(offset + 1));
    boot.cluster_at(clusters[(offset / size) as usize]) + offset % size
}

/// Every entry set a directory's bytes hold, in the order the volume stores them, each
/// carrying the offset of its entries within those bytes.
///
/// Open-coded against literal offsets, as everything else in this file is, and for the
/// same reason: a gate that read a foreign volume through this crate's own parser would be
/// asking whether the parser agrees with itself.
///
/// A directory ends at a zero type byte. An entry whose in-use bit is clear is stepped
/// over and enumeration continues — the baseline puts one in the root of every volume it
/// formats, ahead of the entries a reader most needs.
fn foreign_directory(bytes: &[u8]) -> Vec<ForeignSet> {
    let u32_at =
        |e: &[u8], off: usize| u32::from_le_bytes([e[off], e[off + 1], e[off + 2], e[off + 3]]);
    let u64_at =
        |e: &[u8], off: usize| (u32_at(e, off) as u64) | ((u32_at(e, off + 4) as u64) << 32);

    let mut sets = Vec::new();
    let mut pending: Option<(ForeignSet, usize)> = None;
    for (slot, entry) in bytes.chunks_exact(32).enumerate() {
        let at = slot as u64 * 32;
        match entry[0] {
            0x00 => break,
            0x85 => {
                // A file entry opens a set; `SecondaryCount` says how many entries follow
                // it, which is what says the set is complete when they have all arrived.
                pending = Some((
                    ForeignSet {
                        path: String::new(),
                        name: String::new(),
                        directory: entry[4] & 0x10 != 0,
                        first_cluster: 0,
                        len: 0,
                        valid: 0,
                        no_fat_chain: false,
                        slots: vec![at],
                    },
                    entry[1] as usize,
                ));
            }
            0xC0 => {
                let (set, _) = pending.as_mut().expect("a stream extension inside a set");
                set.no_fat_chain = entry[1] & 0x02 != 0;
                set.valid = u64_at(entry, 8);
                set.first_cluster = u32_at(entry, 20);
                set.len = u64_at(entry, 24);
                set.slots.push(at);
            }
            0xC1 => {
                let (set, remaining) = pending.as_mut().expect("a name entry inside a set");
                set.name.push_str(&String::from_utf16_lossy(
                    &entry[2..32]
                        .chunks_exact(2)
                        .map(|u| u16::from_le_bytes([u[0], u[1]]))
                        .collect::<Vec<_>>(),
                ));
                set.slots.push(at);
                *remaining = remaining.saturating_sub(1);
            }
            // In use, and not part of a file set: the label, the bitmap, the up-case
            // table. Nothing here reads them, and they are not terminators.
            0x81..=0x83 => continue,
            // Not in use. Stepped over rather than treated as the end of the directory.
            t if t & 0x80 == 0 => continue,
            other => panic!("a foreign directory holds an entry of type {other:#04x}"),
        }
        // A set is finished when its last name entry has arrived. The count includes the
        // stream extension, which is why it is decremented only by the name entries and
        // the stream is what leaves it one short.
        if pending
            .as_ref()
            .is_some_and(|(_, remaining)| *remaining <= 1)
        {
            let (mut set, _) = pending.take().expect("the set being assembled");
            set.name.truncate(set.name.trim_end_matches('\0').len());
            sets.push(set);
        }
    }
    sets
}

/// Read `set`'s valid bytes out of the volume.
///
/// Its `ValidDataLength` and not its `DataLength`: the bytes between the two are allocated
/// and undefined, and a gate that compared them against anything would be asserting
/// something the format does not promise.
fn foreign_bytes(image: &Path, boot: &Boot, set: &ForeignSet) -> Vec<u8> {
    if set.valid == 0 {
        return Vec::new();
    }
    foreign_stream(
        image,
        boot,
        set.first_cluster,
        set.no_fat_chain,
        Some(set.valid),
    )
}

/// The bytes of one entry set, read out of the image slot by slot.
///
/// Concatenated from the slots rather than read as one run, because a set that straddles a
/// cluster boundary is not one run — and the set checksum is over its bytes in order whether
/// or not they are adjacent.
fn foreign_set_bytes(image: &Path, set: &ForeignSet) -> Vec<u8> {
    set.slots
        .iter()
        .flat_map(|at| read_at(image, *at, 32))
        .collect()
}

/// Build one row's image with the baseline.
///
/// No serial pinning, unlike [`formatted`]: nothing here compares two images byte for byte,
/// so the one field the baseline takes from the clock is a field no gate below reads.
fn foreign_formatted(row: &ForeignRow) -> (tempfile::NamedTempFile, Boot) {
    let image = blank(row.bytes);
    let args = row.args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    mkfs(image.path(), &args)
        .unwrap_or_else(|e| panic!("the baseline could not build {}: {e}", row.what));
    let boot = Boot::parse(&read_at(image.path(), 0, 512));
    (image, boot)
}

/// A volume of `row` with its tree in it, laid out entirely by the other implementation.
fn foreign_volume(row: &ForeignRow) -> (tempfile::NamedTempFile, Boot) {
    let (image, boot) = foreign_formatted(row);
    util::exfat_populate(image.path(), &foreign_script(row))
        .unwrap_or_else(|e| panic!("the foreign populator could not fill {}: {e}", row.what));
    (image, boot)
}

/// Every entry set the volume holds, at the path it was found at.
///
/// A descent rather than a listing of the root, because the fixture is two levels deep and
/// the level below the root is where a reader's own descent is exercised.
fn foreign_tree(image: &Path, boot: &Boot) -> Vec<ForeignSet> {
    let mut out: Vec<ForeignSet> = Vec::new();
    // The root is the one directory reached through the boot sector rather than through an
    // entry set, so it has no length and no flag of its own: it is always chained, and it is
    // as long as its chain.
    let mut pending = vec![(String::new(), boot.root_cluster, false, None)];
    while let Some((prefix, first, no_fat_chain, len)) = pending.pop() {
        let bytes = foreign_stream(image, boot, first, no_fat_chain, len);
        for mut set in foreign_directory(&bytes) {
            set.path = format!("{prefix}/{}", set.name);
            for slot in &mut set.slots {
                *slot = foreign_offset(image, boot, first, no_fat_chain, *slot);
            }
            if set.directory {
                pending.push((
                    set.path.clone(),
                    set.first_cluster,
                    set.no_fat_chain,
                    Some(set.len),
                ));
            }
            out.push(set);
        }
    }
    out
}

/// The set at `path`, or a failure that says what the volume did hold.
fn foreign_set<'a>(sets: &'a [ForeignSet], path: &str) -> &'a ForeignSet {
    sets.iter().find(|set| set.path == path).unwrap_or_else(|| {
        let held: Vec<_> = sets.iter().map(|set| set.path.as_str()).collect();
        panic!(
            "the foreign volume holds no {path}. It holds: {}",
            held.join(", ")
        )
    })
}

/// Where the up-case table's bytes begin on a populated volume.
///
/// [`Root::read`] answers the same question and refuses anything but a freshly formatted
/// root, which is what makes it a pin on the baseline's slot order. A populated root holds
/// file entry sets as well, so this one looks for the entry it wants and says nothing about
/// its neighbours.
fn foreign_upcase_at(image: &Path, boot: &Boot) -> u64 {
    let root = foreign_stream(image, boot, boot.root_cluster, false, None);
    for entry in root.chunks_exact(32) {
        if entry[0] == 0x00 {
            break;
        }
        if entry[0] == 0x82 {
            let first = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
            return boot.cluster_at(first);
        }
    }
    panic!("the foreign volume's root holds no up-case table entry")
}

/// A run shape, in the words a failure should spell it in.
fn run_shape(no_fat_chain: bool) -> &'static str {
    if no_fat_chain {
        "contiguous"
    } else {
        "chained"
    }
}

/// Whether every tool a foreign-image gate drives is here.
fn foreign_tools() -> bool {
    available("mkfs.exfat") && available("exfat-populate")
}

// ---------------------------------------------------------------------------
// What the two foreign implementations produced

#[test]
fn the_foreign_populator_builds_volumes_the_checker_accepts() {
    if !foreign_tools() || !available("fsck.exfat") {
        return;
    }
    for row in FOREIGN_MATRIX {
        let (image, _) = foreign_volume(row);
        let said = fsck_exfat_clean(image.path()).unwrap_or_else(|e| {
            panic!(
                "{}: the checker refused a volume the foreign populator filled: {e}",
                row.what
            )
        });
        // The checker's own count, which is a second opinion on what arrived: the root and
        // the fixture's two directories, and the files that survive the script's one removal.
        let want = format!(
            "directories {}, files {}",
            FOREIGN_DIRECTORIES.len() + 1,
            foreign_files_of(row).count()
        );
        assert!(
            said.contains(&want),
            "{}: the checker counted something other than the tree that went in. It wanted \
             \"{want}\" and said:\n{said}",
            row.what
        );
    }
}

#[test]
fn every_row_of_the_foreign_matrix_reaches_what_it_claims() {
    if !foreign_tools() {
        return;
    }
    // A row chosen to span a multi-cluster bitmap and too small to do so looks exactly like
    // coverage, which is how a whole dimension of a matrix goes quietly missing. So every
    // property a row is in the matrix for is read back off the volume that row built.
    for row in FOREIGN_MATRIX {
        let (image, boot) = foreign_volume(row);

        // The two dimensions of the geometry, as the boot sector records them.
        assert_eq!(
            boot.bytes_per_sector,
            u64::from(row.bytes_per_sector),
            "{}",
            row.what
        );
        assert_eq!(
            boot.cluster_size(),
            u64::from(row.bytes_per_cluster()),
            "{}",
            row.what
        );

        // The bitmap's span, in the clusters it is measured in rather than in bytes.
        let bitmap_clusters = u64::from(boot.cluster_count)
            .div_ceil(8)
            .div_ceil(boot.cluster_size());
        assert_eq!(
            bitmap_clusters > 1,
            row.wide_bitmap,
            "{}: the allocation bitmap spans {bitmap_clusters} clusters",
            row.what
        );

        // And the run shape, which is a property of the tree the populator built rather than
        // of the volume the baseline formatted.
        let sets = foreign_tree(image.path(), &boot);
        let chained: Vec<&str> = sets
            .iter()
            .filter(|set| !set.no_fat_chain)
            .map(|set| set.path.as_str())
            .collect();
        assert_eq!(
            !chained.is_empty(),
            row.chained,
            "{}: the streams the allocation table describes are {chained:?}",
            row.what
        );

        // Every file the row's script leaves behind, with the length and the shape it was
        // written to have. This is where a populator that stopped reaching a chained stream,
        // or stopped leaving a written length behind an allocated one, is a failure rather
        // than a change.
        for want in foreign_files_of(row) {
            let got = foreign_set(&sets, want.path);
            assert_eq!(
                got.len,
                want.len.of(row),
                "{}: {} has the wrong DataLength",
                row.what,
                want.path
            );
            assert_eq!(
                got.valid,
                want.valid.of(row),
                "{}: {} has the wrong ValidDataLength",
                row.what,
                want.path
            );
            assert_eq!(
                got.no_fat_chain,
                want.contiguous,
                "{}: {} is {} where this fixture needs it {}",
                row.what,
                want.path,
                run_shape(got.no_fat_chain),
                run_shape(want.contiguous),
            );
        }
    }

    // The matrix as a whole, which is a statement no row makes: every pair of values across
    // the four dimensions appears in some row, less the one pair whose volume would be eight
    // terabytes. A pair missing here that is not that one is a dimension that has quietly
    // stopped varying.
    assert_eq!(
        missing_pairs(),
        vec!["band=High with wide_bitmap=true".to_string()],
        "the covering array no longer covers what it says it covers"
    );

    // And the one row that is large in bytes rather than in clusters, because a byte offset
    // past what a 32-bit quantity holds is its own arithmetic and no cluster count reaches it.
    assert_eq!(
        FOREIGN_MATRIX
            .iter()
            .filter(|row| row.past_four_gigabytes())
            .count(),
        1,
        "the matrix no longer reaches a byte offset past four gigabytes"
    );
}

/// Which pairs of values across [`FOREIGN_MATRIX`]'s four dimensions no row carries.
///
/// The candidate pairs are built from the values the rows actually hold rather than from a
/// list written out here, so a row edited to a value no other row shares widens what has to
/// be covered rather than quietly narrowing it.
fn missing_pairs() -> Vec<String> {
    const DIMENSIONS: [&str; 4] = ["bytes_per_sector", "band", "wide_bitmap", "chained"];
    let value = |row: &ForeignRow, dimension: usize| match dimension {
        0 => row.bytes_per_sector.to_string(),
        1 => format!("{:?}", row.band),
        2 => row.wide_bitmap.to_string(),
        _ => row.chained.to_string(),
    };
    let values = |dimension: usize| {
        let mut seen: Vec<String> = Vec::new();
        for row in FOREIGN_MATRIX {
            let held = value(row, dimension);
            if !seen.contains(&held) {
                seen.push(held);
            }
        }
        seen
    };

    let mut missing = Vec::new();
    for (left, left_name) in DIMENSIONS.iter().enumerate().map(|(i, n)| (i, *n)) {
        for (right, right_name) in DIMENSIONS.iter().enumerate().skip(left + 1) {
            for one in values(left) {
                for other in values(right) {
                    if !FOREIGN_MATRIX
                        .iter()
                        .any(|row| value(row, left) == one && value(row, right) == other)
                    {
                        missing.push(format!("{left_name}={one} with {right_name}={other}"));
                    }
                }
            }
        }
    }
    missing
}

#[test]
fn the_bytes_a_foreign_file_holds_are_the_ones_the_populator_was_told_to_write() {
    if !foreign_tools() {
        return;
    }
    for row in FOREIGN_MATRIX {
        let (image, boot) = foreign_volume(row);
        let sets = foreign_tree(image.path(), &boot);

        for want in foreign_files_of(row) {
            let got = foreign_set(&sets, want.path);
            let read = foreign_bytes(image.path(), &boot, got);
            let expected = foreign_contents(want.valid.of(row), want.seed);
            assert_eq!(
                read.len(),
                expected.len(),
                "{}: {} gave back the wrong number of valid bytes",
                row.what,
                want.path
            );
            let differs = read
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .map(|at| {
                    format!(
                        "first at offset {at}: the volume holds {:#04x} where the pattern is \
                         {:#04x}",
                        read[at], expected[at]
                    )
                });
            assert!(
                differs.is_none(),
                "{}: {} does not hold the pattern the populator was told to write — {}",
                row.what,
                want.path,
                differs.unwrap_or_default()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// This crate's reader, over volumes it did not write
//
// Everything above establishes what the two foreign implementations produced. These hold
// this crate's reader to it — which is the only measurement that says the reader reads
// exFAT rather than reading what this crate's own writer happens to emit. Two directions:
// what the baseline formats, at every row of the matrix, and what the populator fills, at
// every row of the covering array above.
//
// The tree the reader finds is compared against [`FOREIGN_FILES`], which is stated rather
// than read out of the volume — the same discipline the gates above keep. A comparison
// against what the volume said would agree with itself however wrong the volume was.

/// Open `image` with this crate's reader, at the strictness a caller gets by default.
fn open_strict(image: &Path) -> ferrosys::exfat::Reader<std::fs::File> {
    let file = std::fs::File::open(image).expect("open the image");
    ferrosys::exfat::Reader::open(file)
        .unwrap_or_else(|e| panic!("this crate's reader refused a foreign volume: {e}"))
}

/// Open `image` strictly and walk it, keeping only whether anything was refused.
///
/// The two halves are one call because which of them refuses is a property of where the
/// damage is rather than of what the damage is: a boot region and an up-case table are read
/// to open a volume at all, and a directory entry set is read when something walks to it. A
/// control that named the half would be asserting the reader's internal order.
///
/// The `Ok` side is the unit, deliberately: a gate that unwraps the `Err` needs the other
/// side to be printable, and a reader is a source handle and two windows rather than a value
/// anyone wants rendered.
fn strict_read(image: &Path) -> Result<(), ferrosys::exfat::ReadError> {
    let file = std::fs::File::open(image).expect("open the image");
    let mut reader = ferrosys::exfat::Reader::open(file)?;
    reader.walk()?;
    Ok(())
}

/// Build the representative foreign volume, prove a strict read accepts it, let `damage`
/// change one thing about it, and hand back what a strict read then says.
///
/// The reading *before* the damage is what makes the one after it attributable: a refusal
/// from a volume that was never sound says nothing about the byte that was changed. It is
/// the same shape as the corruption controls over the baseline further up this file, one
/// implementation further out.
///
/// Every offset a control needs is taken from the volume before a byte of it changes, which
/// is why the tree is read here rather than inside `damage`: a helper that opened the volume
/// after the damage would fail inside itself, and report as the control's own panic three
/// frames from the assertion it was setting up.
fn foreign_control(
    damage: impl FnOnce(&Path, &Boot, &[ForeignSet]),
) -> (tempfile::NamedTempFile, ferrosys::exfat::ReadError) {
    let (image, boot) = foreign_volume(FOREIGN_REPRESENTATIVE);
    strict_read(image.path()).expect("the fixture is sound before the damage");
    let sets = foreign_tree(image.path(), &boot);
    damage(image.path(), &boot, &sets);
    let refused = strict_read(image.path())
        .expect_err("a strict read accepted a volume one byte of which was changed");
    (image, refused)
}

#[test]
fn the_reader_opens_every_volume_the_baseline_formats_and_finds_nothing_wrong() {
    if !available("mkfs.exfat") || !available("tune.exfat") {
        return;
    }
    // Every row of the matrix, so the sector size, the cluster size, and whether the
    // allocation bitmap spans one cluster or several are all varied against a reader that
    // has never seen any of them. An empty volume is the narrowest case and the one where a
    // reader has nothing to hide behind: what it finds is the three residents the format
    // itself allocates and the root that describes them.
    for volume in VOLUMES {
        let (image, boot) = formatted(volume);
        let mut reader = open_strict(image.path());

        // The geometry, recovered from the same bytes the tier decoded independently.
        let layout = *reader.layout();
        assert_eq!(layout.volume_length, boot.volume_length, "{}", volume.what);
        assert_eq!(layout.cluster_count, boot.cluster_count, "{}", volume.what);
        assert_eq!(
            layout.first_cluster_of_root, boot.root_cluster,
            "{}",
            volume.what
        );
        assert_eq!(
            u64::from(layout.bytes_per_sector),
            boot.bytes_per_sector,
            "{}",
            volume.what
        );

        // The two fields no boot sector records, which only a reading of the root directory
        // recovers — and which the tier's own decode of that directory already pinned.
        assert_eq!(
            layout.upcase_bytes, RECOMMENDED_UPCASE_BYTES,
            "{}: the baseline writes the recommended table",
            volume.what
        );
        assert_eq!(
            layout.bitmap_bytes,
            u64::from(boot.cluster_count).div_ceil(8),
            "{}",
            volume.what
        );

        // The label the baseline was told to write, read back out of a root directory this
        // crate walked itself.
        assert_eq!(
            reader.volume_label(),
            Some(LABEL.as_bytes()),
            "{}",
            volume.what
        );

        // The tree, which is the root and nothing else, and a scan with nothing to say.
        let walked = reader.walk().unwrap_or_else(|e| {
            panic!(
                "{}: this crate's reader could not walk it: {e}",
                volume.what
            )
        });
        assert!(walked.is_empty(), "{}: {walked:?}", volume.what);
        let report = reader.scan();
        assert!(
            report.is_clean(),
            "{}: this crate's reader found fault with a volume the baseline wrote:\n{}",
            volume.what,
            report.to_report().to_table()
        );
    }
}

#[test]
fn the_reader_reads_every_tree_a_foreign_implementation_wrote() {
    if !foreign_tools() {
        return;
    }
    // The measurement this gate exists for. Every byte of these volumes was decided by
    // `mkfs.exfat` and `libexfat`; nothing this crate wrote is in any of them.
    for row in FOREIGN_MATRIX {
        let (image, _) = foreign_volume(row);
        let mut reader = open_strict(image.path());

        let walked: Vec<String> = reader
            .walk()
            .unwrap_or_else(|e| panic!("{}: walk a foreign volume: {e}", row.what))
            .into_iter()
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect();
        assert_eq!(walked, foreign_paths(row), "{}", row.what);
        assert_eq!(reader.volume_label(), Some(&b"FOREIGN"[..]), "{}", row.what);

        for want in foreign_files_of(row) {
            let node = reader
                .lookup(want.path.as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}: {e}", row.what, want.path));
            assert_eq!(node.data_length, want.len.of(row), "{}", want.path);
            assert_eq!(node.valid_data_length, want.valid.of(row), "{}", want.path);

            // The run shape reaches the reader as the shape it is, rather than being
            // flattened into whichever one this crate's own writer emits.
            let contiguous = matches!(node.storage, ferrosys::exfat::Storage::Contiguous(_));
            assert_eq!(
                contiguous,
                want.contiguous,
                "{}: {} came back {}",
                row.what,
                want.path,
                run_shape(contiguous)
            );

            // And the bytes. Past the written length a read yields zeros — the region is
            // allocated and nothing wrote it, so what is on the medium there is whatever it
            // last held, and handing that back would leak it.
            let read = reader
                .read_data(&node)
                .unwrap_or_else(|e| panic!("{}: {}: {e}", row.what, want.path));
            assert_eq!(read.len() as u64, want.len.of(row), "{}", want.path);
            let expected = foreign_contents(want.valid.of(row), want.seed);
            assert_eq!(&read[..expected.len()], &expected[..], "{}", want.path);
            assert!(
                read[expected.len()..].iter().all(|b| *b == 0),
                "{}: {}: the unwritten tail is not zeros",
                row.what,
                want.path
            );
        }
    }
}

#[test]
fn a_foreign_volumes_names_are_resolved_through_the_case_that_volume_defines() {
    if !foreign_tools() {
        return;
    }
    // exFAT compares names case-insensitively through the up-case table the volume carries,
    // so a lookup in the wrong case is the ordinary case rather than an edge of one. This is
    // that fold reaching a volume whose table this crate did not write, through a name
    // two entries long so the fold is over units this reader reassembled.
    let (image, _) = foreign_volume(FOREIGN_REPRESENTATIVE);
    let mut reader = open_strict(image.path());

    assert_eq!(
        reader
            .lookup(b"/dcim/second.bin")
            .expect("a foreign volume's name, in a case nobody wrote it in"),
        reader
            .lookup(b"/DCIM/SECOND.BIN")
            .expect("a foreign volume's name, as it is spelled")
    );

    let shouted = FOREIGN_LONG_NAME.to_ascii_uppercase();
    assert_eq!(
        reader
            .lookup(format!("/{shouted}").as_bytes())
            .expect("the long name, up-cased"),
        reader
            .lookup(format!("/{FOREIGN_LONG_NAME}").as_bytes())
            .expect("the long name, as written")
    );

    // And it is a fold rather than a comparison that has stopped distinguishing anything: a
    // name differing from one that is there by more than its case is not found. Without this
    // the two assertions above are satisfied by a lookup that matches everything.
    assert!(
        matches!(
            reader.lookup(b"/DCIM/SECOND.BIM"),
            Err(ferrosys::exfat::ReadError::NotFound { .. })
        ),
        "a name no entry spells was resolved to one that is there"
    );
}

#[test]
fn the_reader_finds_only_the_remark_a_foreign_volume_earns() {
    if !foreign_tools() || !available("fsck.exfat") {
        return;
    }
    // A volume the checker calls clean must not be a volume this reader calls faulty, and
    // the one thing it has to say about these fixtures is the state a driver left behind: a
    // stream whose written length trails its allocated one. That is reported and is
    // cosmetic, which is exactly what lets the strict opens above succeed.
    for row in FOREIGN_MATRIX {
        let (image, _) = foreign_volume(row);
        fsck_exfat_clean(image.path())
            .unwrap_or_else(|e| panic!("{}: the checker refused the fixture: {e}", row.what));

        let file = std::fs::File::open(image.path()).expect("open the image");
        let mut reader = ferrosys::exfat::Reader::open_with(
            file,
            &ferrosys::OpenOptions::new().policy(ferrosys::ReadPolicy::Lenient),
        )
        .expect("open leniently");
        let report = reader.scan();
        let findings = report.to_report();
        assert!(
            !findings.has_fatal(ferrosys::ReadPolicy::Strict),
            "{}: a volume the checker calls clean carries a fatal finding:\n{}",
            row.what,
            findings.to_table()
        );
        let remarks: Vec<&str> = findings
            .findings()
            .iter()
            .map(|f| f.detail.as_str())
            .collect();
        assert!(
            remarks.iter().any(|d| d.contains("of them written")),
            "{}: the short written length was not reported: {remarks:?}",
            row.what
        );
    }
}

// ---------------------------------------------------------------------------
// The negative controls
//
// One per checksum the format carries, plus the name hash no checksum covers. A reader that
// skipped a checksum would report every volume clean forever, and the gates above are exactly
// the shape that would pass — so each of these damages one field of a volume two foreign
// implementations built and holds this crate's reader to naming it.
//
// Each is paired with `fsck.exfat`, and that pairing is the point rather than a second
// opinion for its own sake: it is what says the damage is damage, and not this reader being
// fussy about something nothing else minds.

#[test]
fn a_damaged_boot_checksum_on_a_foreign_volume_is_refused() {
    if !foreign_tools() {
        return;
    }
    // The OEM parameters sector, which the region's checksum covers and no field of the boot
    // sector names — so what the reader has to notice is the checksum and nothing else. A
    // byte of sector 0 would be seen twice: once by the checksum and once by the comparison
    // against the backup region, which is a second finding rather than a sharper one.
    let (image, refused) = foreign_control(|image, boot, _| {
        flip(image, 9 * boot.bytes_per_sector);
    });
    assert!(
        matches!(
            refused,
            ferrosys::exfat::ReadError::BootChecksumMismatch { sector: 0, .. }
        ),
        "expected the main boot region's checksum to be named, got {refused}"
    );
    if available("fsck.exfat") {
        assert!(
            fsck_exfat_clean(image.path()).is_err(),
            "the checker still calls a volume with a damaged boot checksum clean"
        );
    }
}

#[test]
fn a_damaged_up_case_table_on_a_foreign_volume_is_refused() {
    if !foreign_tools() {
        return;
    }
    // The table every name on the volume is compared and hashed through, which is why its
    // checksum is a refusal rather than a remark: a fold that has silently changed resolves
    // names no driver on that volume resolves, and misses names every driver finds.
    let (image, refused) = foreign_control(|image, boot, _| {
        flip(image, foreign_upcase_at(image, boot) + 64);
    });
    assert!(
        matches!(
            refused,
            ferrosys::exfat::ReadError::UpcaseChecksumMismatch { .. }
        ),
        "expected the up-case table's checksum to be named, got {refused}"
    );
    if available("fsck.exfat") {
        assert!(
            fsck_exfat_clean(image.path()).is_err(),
            "the checker still calls a volume with a damaged up-case table clean"
        );
    }
}

#[test]
fn a_damaged_directory_set_checksum_on_a_foreign_volume_is_refused() {
    if !foreign_tools() {
        return;
    }
    // The low byte of a file's `DataLength`, which is a field a reader believes: the set's
    // checksum is the whole of what stands between a changed length and a read that runs past
    // what was written. Damaging a field rather than a spare byte is what makes the control
    // say that.
    let (image, refused) = foreign_control(|image, _, sets| {
        flip(image, foreign_set(sets, "/DCIM/SECOND.BIN").slots[1] + 24);
    });
    assert!(
        matches!(
            refused,
            ferrosys::exfat::ReadError::SetChecksumMismatch { .. }
        ),
        "expected the entry set's checksum to be named, got {refused}"
    );
    if available("fsck.exfat") {
        assert!(
            fsck_exfat_clean(image.path()).is_err(),
            "the checker still calls a volume with a damaged entry set clean"
        );
    }
}

#[test]
fn a_name_hash_no_name_produces_on_a_foreign_volume_is_refused() {
    if !foreign_tools() {
        return;
    }
    // The set checksum is recomputed over the damage, so nothing else about the set is wrong
    // and what is being observed is the reader looking at the hash rather than at the checksum
    // covering it. Nothing else can: the hash is a lookup accelerator, so a wrong one costs no
    // data and merely makes a file invisible to a driver that trusts the field — which is
    // worse than corruption for being silent.
    let (image, refused) = foreign_control(|image, _, sets| {
        let set = foreign_set(sets, "/DCIM/SECOND.BIN");
        let stored = u16::from_le_bytes(
            read_at(image, set.slots[1] + 4, 2)
                .try_into()
                .expect("two bytes"),
        );
        write_at(image, set.slots[1] + 4, &(!stored).to_le_bytes());
        let recomputed = set_checksum(&foreign_set_bytes(image, set));
        write_at(image, set.slots[0] + 2, &recomputed.to_le_bytes());
    });
    assert!(
        matches!(refused, ferrosys::exfat::ReadError::NameHashMismatch { .. }),
        "expected the name hash to be named, got {refused}"
    );
    if available("fsck.exfat") {
        assert!(
            fsck_exfat_clean(image.path()).is_err(),
            "the checker still calls a volume with a name hash no name produces clean"
        );
    }
}
