//! The btrfs family's oracle tier: `mkfs.btrfs`, `btrfs check`, `btrfs
//! inspect-internal`, `btrfstune`, `btrfs-image`, and `btrfs-corrupt-block`, and the
//! evidence that their verdicts mean something.
//!
//! The tier is built before any btrfs code exists, which is the order this project works
//! in: an oracle certifies nothing until it has been watched rejecting what it should
//! reject, and a checker first consulted by a writer is a checker whose verdict has never
//! been calibrated. Nothing here reads or writes a byte through this crate. What it
//! establishes is five things about the pinned tools, and the family that follows is
//! written against what was observed rather than against what was expected.
//!
//! - **The pin is a release *and* a build.** Every binary prints the release on one line
//!   and the switches it was configured with on the next, so `ci/build-btrfs-progs.sh`'s
//!   flags are asserted rather than described. One switch has no flag behind it and is
//!   named where it is skipped.
//!
//! - **The defaults are measured, not transcribed.** btrfs is the one family here whose
//!   on-disk *defaults* move between upstream releases — this pin turned
//!   `block-group-tree` on and announces it in `mkfs.btrfs`'s own output — so what the
//!   feature words, the block-group profiles, and the geometry are is read out of an
//!   image the pinned tool wrote, at the offsets a later reader will use.
//!
//! - **Each named oracle does what its role says.** Another family's tier once lost an
//!   assumption to a tool listed as a populator that only read volumes out, so every
//!   role is exercised here rather than at the gate that will depend on it:
//!   `mkfs.btrfs -r` fills an image from a directory and keeps what a POSIX tree carries,
//!   `--subvol` makes a real subvolume, `btrfs-image` dumps and restores, and `btrfstune`
//!   changes an identity on a built image.
//!
//! - **The checker discriminates, and it is two checkers.** Five corruptions, each a
//!   defect class a writer can plausibly produce, must be rejected — and the same image
//!   before the corruption must be accepted, so a rejection is attributable to the damage
//!   rather than to the image having been unhealthy all along. One of the five separates
//!   `btrfs check` from `btrfs check --check-data-csum`: a file whose bytes have been
//!   altered is a *clean* filesystem to the first and a broken one to the second, which
//!   is what makes them two gates and not one with a flag.
//!
//! - **And the baseline does not repeat itself.** Two formats at one parameter set differ,
//!   and this file records exactly where — because a differential gate built on the
//!   assumption that they would not is a gate that fails for a reason nobody can read.
//!
//! Reading a field here is deliberately open-coded rather than routed through anything
//! this crate offers, for the reason the FAT and exFAT tiers state: an assertion that
//! reads a field back through the accessor a writer used is an assertion about consistency
//! rather than about bytes, and byte-exactness is the one property this crate cannot
//! afford to check against itself. Here there is a second reason — there is no accessor
//! yet, and these offsets are what the first one will be written from.
//!
//! Every gate here declares the tools it needs and reports a loud skip when one is
//! absent, except where `FERROSYS_REQUIRE_HOST_TOOLS` is set, which is how CI refuses to
//! pass by not consulting an oracle.

mod util;

use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use util::{BTRFS_PROGS_VERSION, available, btrfs_check_clean, tool};

// ---------------------------------------------------------------------------
// The suite

/// Every tool this file runs, and the order a reader meets them in the module docs.
///
/// `btrfs-corrupt-block` is here for presence and not for a version: it has no version
/// flag and prints no banner carrying one, so what holds it to the pin is the directory
/// it resolves to. That is asserted on its own below rather than folded in here, because
/// it is a weaker statement than the other four's and should read as one.
const SUITE: &[&str] = &[
    "mkfs.btrfs",
    "btrfs",
    "btrfstune",
    "btrfs-image",
    "btrfs-corrupt-block",
];

/// Whether every tool the gates need is runnable at the pinned release.
fn suite_ready() -> bool {
    // Every tool is probed before the answer is formed, rather than stopping at the first
    // missing one: `available` is what prints the skip banner, and a machine missing three
    // tools should be told about three rather than installing them one run at a time.
    let found: Vec<bool> = SUITE.iter().map(|name| available(name)).collect();
    found.into_iter().all(|present| present)
}

// ---------------------------------------------------------------------------
// The superblock, at the offsets a reader will be written from
//
// Every value below was read out of an image the pinned `mkfs.btrfs` wrote and held
// against what `btrfs inspect-internal dump-super` said about the same image, which is
// what makes them measurements rather than a transcription of a C structure.

/// Where `btrfs_super_block`'s fields begin, in bytes from the start of the superblock.
mod sb {
    pub const CSUM: usize = 0;
    pub const FSID: usize = 32;
    pub const BYTENR: usize = 48;
    pub const MAGIC: usize = 64;
    pub const GENERATION: usize = 72;
    pub const ROOT: usize = 80;
    pub const CHUNK_ROOT: usize = 88;
    pub const LOG_ROOT: usize = 96;
    pub const TOTAL_BYTES: usize = 112;
    pub const ROOT_DIR_OBJECTID: usize = 128;
    pub const NUM_DEVICES: usize = 136;
    pub const SECTORSIZE: usize = 144;
    pub const NODESIZE: usize = 148;
    pub const SYS_CHUNK_ARRAY_SIZE: usize = 160;
    pub const COMPAT_FLAGS: usize = 172;
    pub const COMPAT_RO_FLAGS: usize = 180;
    pub const INCOMPAT_FLAGS: usize = 188;
    pub const CSUM_TYPE: usize = 196;
    pub const SYS_CHUNK_ARRAY: usize = 811;
}

/// Where `btrfs_header`'s fields begin, in bytes from the start of a tree block. The
/// first four match the superblock's, which is the format's own arrangement and the
/// reason a checksum is computed the same way over both.
mod header {
    pub const CSUM: usize = 0;
    pub const FSID: usize = 32;
    pub const BYTENR: usize = 48;
    pub const FLAGS: usize = 56;
    pub const CHUNK_TREE_UUID: usize = 64;
    pub const GENERATION: usize = 80;
    pub const OWNER: usize = 88;
    pub const NRITEMS: usize = 96;
    /// The last field, one byte wide, and 0 in a leaf. A leaf's item array or a node's
    /// key pointers begin immediately after it — at 101, which no gate here crosses into
    /// and which the reader that does will define for itself.
    pub const LEVEL: usize = 100;
}

/// The first byte the format allocates a tree block at: everything below it is the
/// reserved head, holding the primary superblock and nothing else this tier reads.
const FIRST_TREE_BLOCK: u64 = 1024 * 1024;

/// One superblock is this many bytes wherever it sits.
const SUPER_INFO_SIZE: u64 = 4096;

/// Every location the format defines for a superblock, in bytes from the start of the
/// device.
///
/// **Three, not four.** The first is a fixed offset and the rest are `16 KiB << (12 × n)`,
/// which would go on producing locations forever — 1 PiB is the next one — and the format
/// stops at three. A writer that emitted a fourth would be writing 4096 bytes no reader
/// looks at, and a reader that searched for one would be reading whatever a 1 PiB volume
/// happens to hold there. [`the_format_defines_three_superblock_locations_and_no_fourth`]
/// is what says so from an image rather than from a header.
const MIRRORS: [u64; 3] = [64 * 1024, 64 * 1024 * 1024, 256 * 1024 * 1024 * 1024];

/// What a btrfs superblock and every tree block starts with, once past the checksum.
const MAGIC: &[u8; 8] = b"_BHRfS_M";

/// The feature bits this pin's `mkfs.btrfs` sets with no `-O` argument at all, read from
/// the image rather than from its report of itself.
///
/// `MIXED_BACKREF` (bit 0), `BIG_METADATA` (5), `EXTENDED_IREF` (6), `SKINNY_METADATA`
/// (8), `NO_HOLES` (9).
const DEFAULT_INCOMPAT: u64 = 0x361;

/// The same, for the read-only-compatible word: `FREE_SPACE_TREE` (bit 0),
/// `FREE_SPACE_TREE_VALID` (1), `BLOCK_GROUP_TREE` (3).
///
/// The third is the one that moved. It arrived as an opt-in and became a default in the
/// release before this pin, which is the drift this whole tier exists to measure rather
/// than assume.
const DEFAULT_COMPAT_RO: u64 = 0xb;

// ---------------------------------------------------------------------------
// Scaffolding

/// A directory of scratch images, removed when the gate ends.
struct Lab(tempfile::TempDir);

impl Lab {
    fn new() -> Self {
        Lab(tempfile::tempdir().expect("a scratch directory for the images"))
    }

    /// An empty file of `bytes`, sparse.
    ///
    /// Sparse is what makes the size dimension free: the largest image below claims a
    /// quarter of a terabyte and occupies about five megabytes, because a btrfs of any
    /// size carries about that much metadata and nothing else is ever written.
    fn sparse(&self, name: &str, bytes: u64) -> PathBuf {
        let path = self.0.path().join(name);
        File::create(&path)
            .and_then(|f| f.set_len(bytes))
            .unwrap_or_else(|e| panic!("create a {bytes}-byte sparse file at {path:?}: {e}"));
        path
    }

    /// A file of `bytes` with a btrfs on it, formatted with `args` ahead of the path.
    fn formatted(&self, name: &str, bytes: u64, args: &[&str]) -> PathBuf {
        let path = self.sparse(name, bytes);
        mkfs(&path, args);
        path
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}

/// Format `image`, and hand back everything `mkfs.btrfs` said about what it did.
fn mkfs(image: &Path, args: &[&str]) -> String {
    let out = tool("mkfs.btrfs")
        .args(args)
        .arg(image)
        .output()
        .expect("run mkfs.btrfs");
    let said = said(&out);
    assert!(
        out.status.success(),
        "mkfs.btrfs {args:?} refused {image:?}\n{said}"
    );
    said
}

/// Format `image` expecting a refusal, and hand back what was said about it.
fn mkfs_refuses(image: &Path, args: &[&str]) -> String {
    let out = tool("mkfs.btrfs")
        .args(args)
        .arg(image)
        .output()
        .expect("run mkfs.btrfs");
    let said = said(&out);
    assert!(
        !out.status.success(),
        "mkfs.btrfs {args:?} was expected to refuse {image:?} and did not\n{said}"
    );
    said
}

/// Run one of the suite's readers over `image` and hand back what it printed. A reader
/// that fails is a broken gate rather than a finding about the image, so it panics.
fn inspect(image: &Path, args: &[&str]) -> String {
    let out = tool("btrfs")
        .arg("inspect-internal")
        .args(args)
        .arg(image)
        .output()
        .expect("run btrfs inspect-internal");
    let said = said(&out);
    assert!(
        out.status.success(),
        "btrfs inspect-internal {args:?} failed\n{said}"
    );
    said
}

/// Damage `image` with the suite's own corruptor.
///
/// It is upstream's tool for exactly this and it understands the trees, which is what a
/// gate written before this crate can parse one needs. It writes to the image in place,
/// so every caller works on a copy.
fn corrupt(image: &Path, args: &[&str]) -> String {
    let out = tool("btrfs-corrupt-block")
        .args(args)
        .arg(image)
        .output()
        .expect("run btrfs-corrupt-block");
    let said = said(&out);
    assert!(
        out.status.success(),
        "btrfs-corrupt-block {args:?} failed\n{said}"
    );
    said
}

fn said(out: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The 4096 bytes at `offset`, or `None` where the file does not reach that far.
fn read_super(image: &Path, offset: u64) -> Option<[u8; 4096]> {
    let mut file = File::open(image).expect("open the image");
    if file.metadata().expect("stat the image").len() < offset + SUPER_INFO_SIZE {
        return None;
    }
    file.seek(SeekFrom::Start(offset))
        .expect("seek to the superblock");
    let mut buf = [0u8; 4096];
    file.read_exact(&mut buf).expect("read the superblock");
    Some(buf)
}

/// The primary superblock, which every image these gates build has.
fn primary(image: &Path) -> [u8; 4096] {
    read_super(image, MIRRORS[0]).expect("every image here is larger than 64 KiB")
}

fn u16_at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().expect("two bytes"))
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().expect("eight bytes"))
}

/// Whether a superblock sits at `offset` of `image`, by its magic alone.
fn has_mirror(image: &Path, offset: u64) -> bool {
    read_super(image, offset).is_some_and(|sb| &sb[sb::MAGIC..sb::MAGIC + 8] == MAGIC)
}

/// Flip every bit of one byte at `offset`, in place.
///
/// The whole byte rather than one bit, so that a damaged field is unmistakably damaged
/// wherever the gate points it and no assertion depends on which bit was chosen.
fn flip_byte(image: &Path, offset: u64) {
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(image)
        .expect("open the image for damage");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to the byte");
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).expect("read the byte");
    file.seek(SeekFrom::Start(offset)).expect("seek back");
    file.write_all(&[!byte[0]])
        .expect("write the byte back inverted");
}

/// A copy of `image` under `name`, so a corruption never touches the image a sibling gate
/// is asserting about.
fn copy_of(lab: &Lab, image: &Path, name: &str) -> PathBuf {
    let path = lab.path().join(name);
    fs::copy(image, &path).expect("copy the image");
    path
}

/// The size every gate that is not about size uses: comfortably above the smallest volume
/// this pin will format, and small enough that its two superblocks are the only two.
const ORDINARY: u64 = 1024 * 1024 * 1024;

/// The size the two gates that read a *whole* image into memory use.
///
/// Every image here is sparse, so [`ORDINARY`] costs about five megabytes on disk however
/// large it claims to be — and nothing about that is true of reading one back. Two whole
/// gigabytes resident, in a target that runs its gates in parallel, is a gate that fails on
/// a runner for having been sized against a development machine. This is just above the
/// smallest volume the default profiles accept.
const COMPACT: u64 = 128 * 1024 * 1024;

// ---------------------------------------------------------------------------
// The pin

/// Every tool that can say which release it is says the one the gates are written
/// against.
///
/// `util::available` already fails a run under `FERROSYS_REQUIRE_HOST_TOOLS` when a
/// banner does not match, so this gate exists to make the pin a *named test* rather than
/// a side effect of the first gate that happens to run — and to state the version in one
/// place a person reads when they are wondering what "the baseline" means.
#[test]
fn the_pinned_suite_reports_the_release_the_gates_are_written_against() {
    if !suite_ready() {
        return;
    }
    for name in ["mkfs.btrfs", "btrfstune", "btrfs-image"] {
        let out = tool(name).arg("--version").output().expect("run the tool");
        let banner = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            banner.contains(&format!(
                "{name}, part of btrfs-progs v{BTRFS_PROGS_VERSION}\n"
            )),
            "{name} does not report the pinned release:\n{banner}"
        );
    }
    // The multiplexer is the suite and names no tool ahead of it.
    let out = tool("btrfs").arg("--version").output().expect("run btrfs");
    let banner = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        banner.contains(&format!("btrfs-progs v{BTRFS_PROGS_VERSION}\n")),
        "btrfs does not report the pinned release:\n{banner}"
    );
}

/// The suite was built with the switches `ci/build-btrfs-progs.sh` sets.
///
/// A pinned tarball is half a pin: `mkfs.btrfs` links two compression libraries when it
/// finds them and configure *detects* zoned-device support from the build machine's
/// kernel headers, so an identical source can produce tools that differ by what the
/// machine had installed. This suite reports its own switches on the second line of every
/// version banner, which turns that half of the pin from a comment in a build script into
/// something a gate can fail on.
///
/// `FSVERITY` is deliberately absent from the list. It is the one switch with no configure
/// flag behind it — it follows from whether `linux/fsverity.h` was on the build machine —
/// and asserting it would fail a runner for a header that reaches `btrfs receive` and the
/// help banner and nothing that formats, checks, or dumps. Naming the gap here is the
/// point: a hole a gate explains is a hole, and one nobody wrote down is a phantom bug
/// waiting for a runner with a different distribution.
#[test]
fn the_pinned_suite_reports_the_build_the_pin_describes() {
    if !suite_ready() {
        return;
    }
    let out = tool("btrfs").arg("--version").output().expect("run btrfs");
    let banner = String::from_utf8_lossy(&out.stdout).to_string();
    for switch in [
        "-EXPERIMENTAL",
        "-INJECT",
        "-STATIC",
        "-LZO",
        "-ZSTD",
        "-UDEV",
        "-ZONED",
        "CRYPTO=builtin",
    ] {
        assert!(
            banner.contains(switch),
            "the btrfs-progs on PATH was not built with {switch}; \
             ci/build-btrfs-progs.sh is what sets it:\n{banner}"
        );
    }
}

/// The corruptor came out of the same install as the baseline.
///
/// `btrfs-corrupt-block` has no version flag and prints no banner carrying one, so the
/// probe table in `util` has nothing to match and it is pinned by provenance instead:
/// `ci/build-btrfs-progs.sh` installs it into the same prefix as the four tools that do
/// answer, out of the same build tree, and this is what says the one on PATH is that one.
///
/// It is a weaker check than a banner and it is worth having anyway. Upstream keeps this
/// tool out of its install set — it exists to damage a filesystem — so a copy resolving
/// from anywhere else is somebody's stray build, and a corruption gate driven by a tool
/// nobody can identify proves nothing about the checker beside it.
#[test]
fn the_corruptor_came_out_of_the_same_install_as_the_baseline() {
    if !suite_ready() {
        return;
    }
    let corruptor = which("btrfs-corrupt-block");
    let baseline = which("mkfs.btrfs");
    assert_eq!(
        corruptor.parent(),
        baseline.parent(),
        "btrfs-corrupt-block resolves to {corruptor:?} and mkfs.btrfs to {baseline:?}; \
         the corruptor is held to the pin by the directory it came out of, and these are \
         two installs"
    );
}

/// Where a name on `PATH` resolves to, as a path with no symbolic links left in it.
fn which(name: &str) -> PathBuf {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
        .expect("resolve the tool on PATH");
    let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!found.is_empty(), "{name} is on PATH but did not resolve");
    fs::canonicalize(&found).unwrap_or_else(|e| panic!("canonicalize {found}: {e}"))
}

// ---------------------------------------------------------------------------
// What the pin's defaults actually are

/// The default feature set is the one recorded at the top of this file, read out of the
/// image rather than out of the tool's report of itself.
///
/// This is the measurement the whole tier is here for. ext4's feature profile has been
/// stable for a decade and FAT has no feature words at all; btrfs moves its defaults
/// every few upstream releases, and a writer built against a transcribed table produces a
/// filesystem the pinned checker will not recognize as the one it makes.
#[test]
fn the_baselines_default_feature_set_is_the_one_recorded_here() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = lab.formatted("default.img", ORDINARY, &[]);
    let sb = primary(&image);

    assert_eq!(
        &sb[sb::MAGIC..sb::MAGIC + 8],
        MAGIC,
        "the superblock's magic"
    );
    assert_eq!(
        u64_at(&sb, sb::COMPAT_FLAGS),
        0,
        "no compat feature is set by default"
    );
    assert_eq!(
        u64_at(&sb, sb::INCOMPAT_FLAGS),
        DEFAULT_INCOMPAT,
        "the default incompat word moved; read the new bits out of the pinned headers \
         before changing this constant, because a feature list that names the wrong bit \
         refuses the wrong thing silently"
    );
    assert_eq!(
        u64_at(&sb, sb::COMPAT_RO_FLAGS),
        DEFAULT_COMPAT_RO,
        "the default compat_ro word moved"
    );
    assert_eq!(
        u16_at(&sb, sb::CSUM_TYPE),
        0,
        "crc32c is checksum type 0 and the default"
    );
}

/// The tool's own report of what it did agrees with the image, in the words a person
/// reads.
///
/// Held separately from the bits above because they are two claims: one is what the
/// filesystem *is*, and this is what the baseline *says* — and a later release that
/// changed one without the other would be worth knowing about either way. It is also
/// where the feature *names* are pinned, which is the vocabulary a `-O` argument is
/// written in.
#[test]
fn the_baseline_reports_the_features_and_profiles_it_wrote() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let path = lab.sparse("reported.img", ORDINARY);
    let said = mkfs(&path, &[]);

    for word in [
        "extref",
        "skinny-metadata",
        "no-holes",
        "free-space-tree",
        "block-group-tree",
    ] {
        assert!(
            said.contains(word),
            "mkfs.btrfs no longer reports {word}:\n{said}"
        );
    }
    assert!(
        said.contains("Checksum:           crc32c"),
        "the default checksum:\n{said}"
    );

    // The single-device profile pairing, which has moved between DUP and single more than
    // once upstream and is the other half of what this pin fixes. Data unreplicated,
    // metadata and the system chunk duplicated.
    let profile = |kind: &str| {
        said.lines()
            .find_map(|l| l.trim().strip_prefix(kind))
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_else(|| panic!("mkfs.btrfs reported no {kind} profile:\n{said}"))
    };
    assert_eq!(profile("Data:"), "single", "the default data profile");
    assert_eq!(profile("Metadata:"), "DUP", "the default metadata profile");
    assert_eq!(profile("System:"), "DUP", "the default system profile");
}

/// Every feature word this crate accepts means the bit the pinned baseline moves for it.
///
/// The other half of the vocabulary pin above, and the half that can be wrong silently. That
/// one asserts the baseline still *prints* five words; this asserts that each word this crate
/// takes as input selects the same feature the baseline selects for it — which is the claim a
/// `-O` argument makes, and the one a transcribed table gets wrong by one bit without any
/// gate noticing.
///
/// Measured rather than transcribed, in the only way that settles it: format an image with
/// the word, read the two feature words back out of the superblock, and see which bit moved.
/// A feature the baseline already sets is asked for in the negative instead, since a request
/// for something already present moves nothing.
///
/// **A name the pinned build refuses is skipped and counted, never quietly passed.** Two of
/// this suite's `-O` names are behind build switches `ci/build-btrfs-progs.sh` deliberately
/// does not take, and one needs a geometry this gate does not lay out; a run that reached
/// none of the names would otherwise be a run that checked nothing and said `ok`.
#[test]
fn every_feature_word_this_crate_reads_selects_the_bit_the_baseline_selects() {
    // The vocabulary is what is under test, so it is named; the bits it is held against are
    // read out of the image at literal offsets, as everything else in this file is.
    use ferrosys::btrfs::ondisk::{CompatRoFlags, IncompatFlags};

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();

    // What the tool itself says it takes, rather than a list written here. An alias line
    // names a second spelling of a feature listed elsewhere; this crate gives each feature
    // one name, so the canonical line is the one held against it.
    let offered = tool("mkfs.btrfs")
        .args(["-O", "list-all"])
        .output()
        .expect("run mkfs.btrfs -O list-all");
    let listed = said(&offered);
    let names: Vec<&str> = listed
        .lines()
        // The banner is the one line with no ` - ` description after the name.
        .filter(|line| line.contains(" - "))
        // An alias line says so in its own description: `fst  - free-space-tree alias`.
        .filter(|line| !line.trim_end().ends_with("alias"))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(
        names.len() >= 8,
        "mkfs.btrfs -O list-all offered {} names, which is fewer than any release of it \
         has: the parse above has stopped matching its output\n{listed}",
        names.len()
    );

    let words = |image: &Path| {
        let sb = primary(image);
        (
            u64_at(&sb, sb::INCOMPAT_FLAGS),
            u64_at(&sb, sb::COMPAT_RO_FLAGS),
        )
    };
    let base = lab.formatted("vocabulary-base.img", ORDINARY, &[]);
    let (base_incompat, base_compat_ro) = words(&base);

    let mut checked = Vec::new();
    let mut skipped = Vec::new();
    for (at, name) in names.iter().enumerate() {
        // The baseline is asked first and this crate's table is consulted afterwards, which
        // is the direction that catches a renamed word. Asking this crate first would make a
        // name it no longer resolves look like a feature nothing here implements — a skip —
        // where what it is is the table having drifted from the tool.
        //
        // Which direction to ask in is the one thing that cannot be measured: a feature the
        // baseline already sets moves nothing when asked for again, so it is asked for in
        // the negative. Both attempts are made rather than either being assumed.
        // A fresh image per attempt: `mkfs.btrfs` refuses a device that already carries a
        // filesystem, so formatting twice over one file would report the second form as a
        // feature this build does not offer.
        let attempt = |form: &str, which: &str| {
            let path = lab.sparse(&format!("vocabulary-{at}-{which}.img"), ORDINARY);
            let out = tool("mkfs.btrfs")
                .args(["-O", form])
                .arg(&path)
                .output()
                .expect("run mkfs.btrfs");
            out.status.success().then(|| {
                let (incompat, compat_ro) = words(&path);
                (incompat ^ base_incompat, compat_ro ^ base_compat_ro)
            })
        };
        let negation = format!("^{name}");
        let (positive, negative) = (attempt(name, "on"), attempt(&negation, "off"));
        let (argument, moved) = match (positive, negative) {
            (Some(p), _) if p != (0, 0) => ((*name).to_string(), p),
            (_, Some(n)) if n != (0, 0) => (negation, n),
            // Both directions ran and neither moved a bit, which is conclusive: the tool
            // offers words that are not feature bits at all — `quota` turns on accounting a
            // mount performs and leaves the superblock exactly as it was — and a word that
            // moves no bit is one no feature-word table should hold.
            (Some(_), Some(_)) => {
                assert!(
                    IncompatFlags::from_name(name).is_none()
                        && CompatRoFlags::from_name(name).is_none(),
                    "-O {name} moves no feature bit, and this crate reads it as one"
                );
                skipped.push(format!("{name} (moves no feature bit)"));
                continue;
            }
            // One direction was refused and the other moved nothing, which settles nothing:
            // clearing a bit that was never set succeeds and looks exactly like a word with
            // no bit behind it.
            _ => {
                skipped.push(format!("{name} (this build refuses it)"));
                continue;
            }
        };
        let (moved_incompat, moved_compat_ro) = moved;
        let ours = IncompatFlags::from_name(name)
            .map(|f| (f.bits(), 0))
            .or_else(|| CompatRoFlags::from_name(name).map(|f| (0, f.bits())));
        let Some((want_incompat, want_compat_ro)) = ours else {
            panic!(
                "mkfs.btrfs -O {argument} moved incompat {moved_incompat:#x} and compat_ro \
                 {moved_compat_ro:#x}, and this crate reads no feature by that name"
            );
        };
        // `^no-holes` takes `block-group-tree` with it, the second resting on the first, so
        // what is asserted is that the bit this crate names is among those that moved rather
        // than that it is all of them.
        assert!(
            moved_incompat & want_incompat == want_incompat
                && moved_compat_ro & want_compat_ro == want_compat_ro,
            "mkfs.btrfs -O {argument} moved incompat {moved_incompat:#x} and compat_ro \
             {moved_compat_ro:#x}, and this crate reads {name} as incompat \
             {want_incompat:#x} / compat_ro {want_compat_ro:#x}"
        );
        checked.push(*name);
    }

    // A skip is reported rather than left to be inferred from a count, which is the same
    // rule the tool probes follow: a gate that could not run says so.
    if !skipped.is_empty() {
        eprintln!("  feature words not exercised: {}", skipped.join(", "));
    }
    assert!(
        checked.len() >= 6,
        "only {} of the baseline's {} feature words were exercised: {checked:?}, skipped \
         {skipped:?}",
        checked.len(),
        names.len()
    );
}

/// The default geometry is a 4 KiB sector and a 16 KiB node, and the sector is the page
/// size of the machine `mkfs.btrfs` ran on.
///
/// The second half is what makes this a gate rather than a note. This project's two
/// runners are a self-hosted aarch64 machine and a hosted x86_64 one, and an aarch64
/// kernel is built at 4, 16, or 64 KiB pages — so a baseline built with no `-s` argument
/// can be a *different filesystem* on the two runners. Every gate below names the sector
/// size explicitly for that reason, and this is the one that says why.
#[test]
fn the_baselines_default_geometry_follows_the_page_size_of_the_machine_it_ran_on() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = lab.formatted("geometry.img", ORDINARY, &[]);
    let sb = primary(&image);

    let page = page_size();
    assert_eq!(
        u64::from(u32_at(&sb, sb::SECTORSIZE)),
        page,
        "the default sector size is this machine's page size, and this machine's is {page}"
    );
    assert_eq!(
        u32_at(&sb, sb::NODESIZE),
        16384,
        "the default node size, where the page size does not exceed it"
    );
    assert_eq!(u64_at(&sb, sb::NUM_DEVICES), 1, "one device");
    assert_eq!(
        u64_at(&sb, sb::ROOT_DIR_OBJECTID),
        6,
        "the root tree's directory objectid"
    );
    assert_eq!(
        u64_at(&sb, sb::BYTENR),
        MIRRORS[0],
        "a superblock records where it sits"
    );
    assert_eq!(
        u64_at(&sb, sb::LOG_ROOT),
        0,
        "a freshly formatted volume has no log tree"
    );
    assert_eq!(
        u64_at(&sb, sb::TOTAL_BYTES),
        ORDINARY,
        "the filesystem covers the whole file"
    );
    assert!(
        u64_at(&sb, sb::ROOT) > 0,
        "the root tree has a logical address"
    );
    assert!(
        u64_at(&sb, sb::CHUNK_ROOT) > 0,
        "the chunk tree has a logical address"
    );
    assert!(
        u32_at(&sb, sb::SYS_CHUNK_ARRAY_SIZE) > 0,
        "the bootstrap chunk array is not empty — it is what a reader finds the chunk \
         tree through, and an empty one would leave the volume unopenable"
    );
    assert_eq!(
        &sb[sb::SYS_CHUNK_ARRAY..sb::SYS_CHUNK_ARRAY + 8],
        &256u64.to_le_bytes(),
        "the bootstrap array begins with a key whose objectid is the first chunk-tree one"
    );
}

/// This machine's page size, which decides what a `-s`-less format produces.
fn page_size() -> u64 {
    let out = Command::new("getconf")
        .arg("PAGESIZE")
        .output()
        .expect("ask getconf for the page size");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("getconf printed a page size")
}

/// A sector size larger than this machine's page size is still accepted by the formatter.
///
/// Worth pinning because the family's plan expected the opposite. btrfs couples
/// `sectorsize` to the *kernel's* page size when a volume is mounted, and the natural
/// reading is that the formatter is coupled too — which would make the runners' differing
/// page sizes a limit on what the matrix can contain. It is not: this pin accepts 4 KiB
/// through 64 KiB on a 4 KiB-page machine, and what a mount will accept is a separate
/// question for the tier that boots a kernel.
#[test]
fn the_accepted_sector_sizes_do_not_depend_on_this_machines_page_size() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for sector in [4096u32, 8192, 16384, 32768, 65536] {
        let image = lab.formatted(
            &format!("sector-{sector}.img"),
            ORDINARY,
            &["-s", &sector.to_string(), "-n", "65536"],
        );
        assert_eq!(
            u32_at(&primary(&image), sb::SECTORSIZE),
            sector,
            "a {sector}-byte sector was accepted and recorded"
        );
        btrfs_check_clean(&image, &[])
            .unwrap_or_else(|e| panic!("the checker rejected a {sector}-byte-sector volume: {e}"));
    }
    for sector in [512u32, 1024, 2048] {
        let path = lab.sparse(&format!("small-sector-{sector}.img"), ORDINARY);
        let said = mkfs_refuses(&path, &["-s", &sector.to_string()]);
        assert!(
            said.contains("expected range is [4K, 64K]"),
            "a {sector}-byte sector was refused for a reason this gate does not recognize:\n{said}"
        );
    }
}

/// The node size defaults to the sector size wherever that is the larger of the two, and
/// the format's accepted range is 4 KiB through 64 KiB.
///
/// The default is the part worth having written down: a matrix row that names a sector
/// size and not a node size is a row whose node size moved with it.
#[test]
fn the_node_size_follows_the_sector_size_and_stops_at_sixty_four_kilobytes() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();

    let big_sector = lab.formatted("big-sector.img", ORDINARY, &["-s", "65536"]);
    let sb = primary(&big_sector);
    assert_eq!(u32_at(&sb, sb::SECTORSIZE), 65536);
    assert_eq!(
        u32_at(&sb, sb::NODESIZE),
        65536,
        "with no -n argument the node size follows the larger sector size"
    );

    for node in [4096u32, 8192, 16384, 32768, 65536] {
        let image = lab.formatted(
            &format!("node-{node}.img"),
            ORDINARY,
            &["-s", "4096", "-n", &node.to_string()],
        );
        assert_eq!(u32_at(&primary(&image), sb::NODESIZE), node);
        btrfs_check_clean(&image, &[])
            .unwrap_or_else(|e| panic!("the checker rejected a {node}-byte-node volume: {e}"));
    }
    let path = lab.sparse("node-131072.img", ORDINARY);
    mkfs_refuses(&path, &["-s", "4096", "-n", "131072"]);
}

/// The smallest volume this pin will format, at the default profiles and at the
/// unreplicated ones.
///
/// Two numbers rather than one, because they are two limits — and the refusal names
/// whichever one applies, which is the part worth knowing. 45 MiB is what the format
/// costs at unreplicated profiles; the default duplicated metadata more than doubles it,
/// so a floor read from the format alone is one a default format still refuses.
///
/// Both are asserted at the boundary and against the message, so a planner written from
/// this file refuses what the baseline refuses and for the number the baseline names.
#[test]
fn the_smallest_volume_this_pin_formats_is_the_one_recorded_here() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    const MIB: u64 = 1024 * 1024;

    // The unreplicated pairing pays for one copy of the metadata and reaches the lower
    // floor.
    let single = ["-s", "4096", "-n", "16384", "-m", "single", "-d", "single"];
    mkfs(&lab.sparse("single-45.img", 45 * MIB), &single);
    let said = mkfs_refuses(&lab.sparse("single-44.img", 44 * MIB), &single);
    assert!(
        said.contains(&format!(
            "minimum size for each btrfs device is {}",
            45 * MIB
        )),
        "the unreplicated floor moved:\n{said}"
    );

    // The default pairing duplicates metadata and the system chunk, and says so with a
    // larger number in the same sentence.
    let default = ["-s", "4096", "-n", "16384"];
    mkfs(&lab.sparse("dup-109.img", 109 * MIB), &default);
    let said = mkfs_refuses(&lab.sparse("dup-108.img", 108 * MIB), &default);
    assert!(
        said.contains(&format!(
            "minimum size for each btrfs device is {}",
            109 * MIB
        )),
        "the default-profile floor moved:\n{said}"
    );
}

// ---------------------------------------------------------------------------
// The superblock mirrors

/// A volume carries every superblock location it has room for, and no others.
///
/// This is the family's analogue of the backup superblocks whose absence in another
/// implementation is the reason this project exists, so the rule is "every mirror the
/// device can hold" rather than "as many as seem worth it" — and it is asserted at each
/// threshold rather than at one convenient size.
#[test]
fn a_volume_carries_every_superblock_location_it_has_room_for() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();

    let small = lab.formatted("two-mirrors.img", ORDINARY, &["-s", "4096"]);
    assert!(
        has_mirror(&small, MIRRORS[0]),
        "the primary superblock at 64 KiB"
    );
    assert!(has_mirror(&small, MIRRORS[1]), "the second at 64 MiB");
    assert!(
        !has_mirror(&small, MIRRORS[2]),
        "and no third, the volume being 1 GiB"
    );

    let large = lab.formatted(
        "three-mirrors.img",
        MIRRORS[2] + SUPER_INFO_SIZE,
        &["-s", "4096"],
    );
    assert!(has_mirror(&large, MIRRORS[2]), "the third at 256 GiB");
    assert_eq!(
        u64_at(
            &read_super(&large, MIRRORS[2]).expect("the third mirror is within the file"),
            sb::BYTENR
        ),
        MIRRORS[2],
        "each copy records its own location rather than the primary's, which is what \
         makes a copy found by scanning attributable"
    );
}

/// A mirror is written only where the volume holds all 4096 bytes of it.
///
/// The boundary rather than a comfortable size, because "the device is large enough" has
/// two readings — the mirror *starts* inside the device, or it *ends* inside it — and they
/// differ by exactly one superblock. A volume of precisely 256 GiB has two.
#[test]
fn a_mirror_is_written_only_where_the_volume_holds_all_of_it() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();

    let exact = lab.formatted("exactly-256g.img", MIRRORS[2], &["-s", "4096"]);
    assert!(
        !has_mirror(&exact, MIRRORS[2]),
        "a volume ending where the third mirror begins does not carry it"
    );

    let one_more = lab.formatted(
        "256g-and-a-superblock.img",
        MIRRORS[2] + SUPER_INFO_SIZE,
        &["-s", "4096"],
    );
    assert!(
        has_mirror(&one_more, MIRRORS[2]),
        "and one superblock more does"
    );
}

/// The format defines three superblock locations and no fourth.
///
/// The locations are `16 KiB << (12 × n)` past the first, which is an expression that goes
/// on producing them — 1 PiB is the next — and the format stops at three. A writer built
/// from the arithmetic rather than from the count would put 4096 bytes at 1 PiB that no
/// reader looks at, and a reader built the same way would read whatever a volume that
/// large happens to hold there and take it for a superblock.
///
/// The fixture is a sparse file of a petabyte, which costs about five megabytes and which
/// some filesystems will not create at all: ext4 caps a file well below this. Where the
/// host refuses, the gate says so rather than passing — a claim about a size the host
/// cannot represent is not a claim.
#[test]
fn the_format_defines_three_superblock_locations_and_no_fourth() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    const PEBIBYTE: u64 = 1024 * 1024 * 1024 * 1024 * 1024;

    let path = lab.path().join("petabyte.img");
    let created = File::create(&path).and_then(|f| f.set_len(PEBIBYTE + SUPER_INFO_SIZE));
    if let Err(e) = created {
        eprintln!(
            "\n!!! SKIPPING the fourth-mirror gate: this host will not create a \
             petabyte-long sparse file ({e}) — a filesystem whose maximum file size \
             reaches it, such as tmpfs or btrfs itself, is what runs this gate !!!\n"
        );
        return;
    }
    mkfs(&path, &["-s", "4096"]);

    for (n, offset) in MIRRORS.iter().enumerate() {
        assert!(has_mirror(&path, *offset), "mirror {n} at {offset:#x}");
    }
    assert!(
        !has_mirror(&path, PEBIBYTE),
        "a fourth location would be at 1 PiB, and the format does not define one"
    );
}

// ---------------------------------------------------------------------------
// Each named oracle does what its role says

/// A tree on this machine, for the roles that need one.
///
/// Every property here is one the format carries and a later differential will have to
/// reproduce: a nested directory, an empty one, a file small enough to be stored inside
/// its own metadata, a file large enough not to be, a symbolic link, and a name reached
/// through more than one directory entry. Device nodes are absent and the reason is the
/// project's own posture — creating one needs privileges this project exists not to
/// need — so the baseline's handling of them is a question for a tier that has an image
/// rather than a host tree.
fn source_tree(lab: &Lab) -> PathBuf {
    let root = lab.path().join("source");
    fs::create_dir_all(root.join("dir/nested")).expect("create the nested directory");
    fs::create_dir(root.join("empty")).expect("create the empty directory");
    fs::write(root.join("dir/small.txt"), b"stored inside its own inode\n")
        .expect("write the small file");
    fs::write(
        root.join("large.bin"),
        LARGE_FILE_PATTERN.repeat(LARGE_FILE_REPEATS),
    )
    .expect("write the large file");
    std::os::unix::fs::symlink("dir/small.txt", root.join("link")).expect("create the symlink");
    fs::hard_link(root.join("dir/small.txt"), root.join("second-name.txt"))
        .expect("create the second name");
    root
}

/// A byte pattern that will not occur in a btrfs's own metadata, so that finding it in an
/// image finds file data and nothing else.
const LARGE_FILE_PATTERN: &[u8; 16] = b"ferrosys-data!!\n";

/// Enough repeats to be stored as a regular extent rather than inside the inode, and to
/// cross more than one sector so a damaged one is unambiguous.
const LARGE_FILE_REPEATS: usize = 8192;

/// `mkfs.btrfs -r` fills an image from a directory, and keeps what a POSIX tree carries.
///
/// This is the role the gates below lean on hardest — it is the populated baseline that FAT
/// and exFAT have no equivalent of, and the populated differential is written against it —
/// so it is exercised here rather than at the gate that will depend on it. The exFAT tier
/// is why: a tool listed there as a populator turned out to read volumes out and have no
/// inverse, and that was found well after it was written down.
#[test]
fn the_baseline_fills_an_image_from_a_directory() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "populated.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    btrfs_check_clean(&image, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected a populated baseline: {e}"));

    let fs_tree = inspect(&image, &["dump-tree", "-t", "fs"]);
    for name in [
        "dir",
        "nested",
        "empty",
        "small.txt",
        "large.bin",
        "link",
        "second-name.txt",
    ] {
        assert!(
            fs_tree.contains(&format!("name: {name}")),
            "{name} is in the image:\n{fs_tree}"
        );
    }
    assert!(
        fs_tree.contains("type SYMLINK"),
        "the symbolic link kept its kind"
    );
    assert!(
        fs_tree.contains("links 2"),
        "the second name is a second link to one inode rather than a copy:\n{fs_tree}"
    );
    // Small enough to live in its own metadata, large enough not to: the two extent
    // shapes a reader has to handle, both present in one image.
    assert!(
        fs_tree.contains("inline extent"),
        "the small file is stored inline"
    );
    assert!(
        fs_tree.contains("extent data disk byte"),
        "the large file is stored in an extent"
    );
}

/// The baseline keeps ownership, modes, and extended attributes.
///
/// The three a differential over a populated tree will compare and the three a format
/// that could not hold them would drop silently. Ownership is asserted as what the tree
/// was written with rather than as root's, because these gates run unprivileged and
/// changing it would need what this project exists not to need.
#[test]
fn the_baseline_keeps_ownership_modes_and_extended_attributes() {
    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    let source = lab.path().join("attributed");
    fs::create_dir(&source).expect("create the source directory");
    let file = source.join("file");
    fs::write(&file, b"attributed\n").expect("write the file");
    fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o604))
        .expect("set an unusual mode, so a default cannot pass for it");
    let set = Command::new("setfattr")
        .args(["-n", "user.ferrosys", "-v", "recorded"])
        .arg(&file)
        .status()
        .expect("run setfattr");
    assert!(set.success(), "setfattr refused the source file");

    let image = lab.formatted(
        "attributed.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    let fs_tree = inspect(&image, &["dump-tree", "-t", "fs"]);

    assert!(
        fs_tree.contains("mode 100604"),
        "the file's mode survived:\n{fs_tree}"
    );
    let uid = rustix_free_uid();
    assert!(
        fs_tree.contains(&format!("uid {uid} gid ")),
        "the file's owner survived as the one that wrote the tree:\n{fs_tree}"
    );
    assert!(
        fs_tree.contains("XATTR_ITEM"),
        "the extended attribute survived:\n{fs_tree}"
    );
    assert!(
        fs_tree.contains("user.ferrosys"),
        "and under its own name:\n{fs_tree}"
    );
}

/// This process's user id, without reaching for a dependency the tier does not otherwise
/// have.
fn rustix_free_uid() -> u32 {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .expect("ask id for this user");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("id printed a user id")
}

/// `--subvol` makes a real subvolume, which is more than the plan credited the baseline
/// with.
///
/// A subvolume is a `ROOT_ITEM` in the root tree with an fs tree of its own, plus the
/// `ROOT_REF`/`ROOT_BACKREF` pair that links it to the directory it hangs under. The
/// baseline producing one means a differential over a subvolume layout has something to
/// diff against, rather than the writer's most distinguishing capability having no
/// baseline at all.
#[test]
fn the_baseline_creates_a_subvolume_where_it_is_told_to() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "subvol.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
            // The path is relative to the directory the image is filled from.
            "--subvol",
            "rw:dir",
        ],
    );
    btrfs_check_clean(&image, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected a baseline carrying a subvolume: {e}"));

    let root_tree = inspect(&image, &["dump-tree", "-t", "root"]);
    // 256 is the first free objectid, and a subvolume's root item is keyed by one.
    assert!(
        root_tree.contains("key (256 ROOT_ITEM 0)"),
        "the subvolume's root item:\n{root_tree}"
    );
    assert!(
        root_tree.contains("ROOT_BACKREF"),
        "and its link back to the tree above it"
    );
    assert!(
        root_tree.contains("ROOT_REF"),
        "and the forward half of that pair"
    );

    // The directory the subvolume replaced is now a reference to a root rather than to an
    // inode, which is the one structural difference a reader has to notice when walking
    // across the boundary.
    let fs_tree = inspect(&image, &["dump-tree", "-t", "fs"]);
    assert!(
        fs_tree.contains("location key (256 ROOT_ITEM 0) type DIR"),
        "the entry naming the subvolume points at a root and not at an inode:\n{fs_tree}"
    );
}

/// A second name for a file across a subvolume boundary becomes a copy, silently.
///
/// Not a defect in the baseline — a hard link cannot span two fs trees, and the format is
/// what refuses it — but the *response* is a duplicate rather than a diagnostic, and a
/// differential that puts a link and its target on opposite sides of a boundary would see
/// two files where its source had one. Recording it here is what keeps that from being
/// found as a mismatch nobody can explain.
#[test]
fn a_second_name_across_a_subvolume_boundary_becomes_a_copy() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "split-link.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
            // `second-name.txt` is at the top and its target is under `dir`, so this
            // boundary runs between them.
            "--subvol",
            "rw:dir",
        ],
    );
    btrfs_check_clean(&image, &[]).expect("the image is well-formed either way");

    let fs_tree = inspect(&image, &["dump-tree", "-t", "fs"]);
    assert!(
        !fs_tree.contains("links 2"),
        "the two names are no longer one inode, and nothing said so:\n{fs_tree}"
    );
}

/// `btrfs-image` produces a metadata-only dump, and one that restores to a filesystem the
/// checker accepts.
///
/// Both halves, because the role the plan wants it for is fixtures: a dump that cannot be
/// restored is an archive format rather than an image, and the difference is invisible
/// until something tries to read one back. What it buys is size — the dump below is a
/// fraction of a percent of the volume it came from — which is what makes a large fixture
/// storable.
#[test]
fn the_metadata_dump_restores_to_a_filesystem_the_checker_accepts() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "dumped.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );

    let dump = lab.path().join("dumped.btrfs-image");
    let out = tool("btrfs-image")
        .arg(&image)
        .arg(&dump)
        .output()
        .expect("run btrfs-image");
    assert!(
        out.status.success(),
        "btrfs-image refused the volume\n{}",
        said(&out)
    );

    let dumped = fs::metadata(&dump).expect("stat the dump").len();
    assert!(dumped > 0, "the dump is not empty");
    assert!(
        dumped < ORDINARY / 100,
        "the dump carries metadata alone and should be far smaller than the volume; it is \
         {dumped} bytes of {ORDINARY}"
    );

    let restored = lab.path().join("restored.img");
    let out = tool("btrfs-image")
        .arg("-r")
        .arg(&dump)
        .arg(&restored)
        .output()
        .expect("run btrfs-image -r");
    assert!(
        out.status.success(),
        "btrfs-image could not restore its own dump\n{}",
        said(&out)
    );
    btrfs_check_clean(&restored, &[])
        .unwrap_or_else(|e| panic!("the checker rejected a restored dump: {e}"));

    let tree = inspect(&restored, &["dump-tree", "-t", "fs"]);
    assert!(
        tree.contains("name: large.bin"),
        "the restored image carries the tree"
    );
}

/// `btrfstune` rewrites the identity it names, everywhere that identity is recorded — and
/// leaves alone the one the format also generates.
///
/// The reason this is a gate and not a note is that the suite's tuning tool is where the
/// exFAT family's reproducibility answer came from, and the same move does not close the
/// question here. `-U` rewrites the filesystem id in the superblock and in every tree
/// block header that carries it, and the *chunk tree* id in those same headers is
/// untouched, because `mkfs.btrfs` invents that one too and nothing in the suite sets it.
/// A baseline is therefore not reproducible by tuning it afterwards, which is what the
/// gate below measures directly.
#[test]
fn the_suites_tuning_tool_rewrites_the_identity_it_names_and_not_the_other_one() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = lab.formatted("tuned.img", ORDINARY, &["-s", "4096"]);

    let before = primary(&image);
    let chunk_uuid_before = first_tree_block_chunk_uuid(&image);

    let out = tool("btrfstune")
        .args(["-f", "-U", "12345678-1234-1234-1234-123456789abc"])
        .arg(&image)
        .output()
        .expect("run btrfstune");
    assert!(
        out.status.success(),
        "btrfstune refused the image\n{}",
        said(&out)
    );

    let after = primary(&image);
    assert_ne!(
        &before[sb::FSID..sb::FSID + 16],
        &after[sb::FSID..sb::FSID + 16],
        "the filesystem id changed"
    );
    assert_eq!(
        &after[sb::FSID..sb::FSID + 16],
        &[
            0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc
        ],
        "to the one it was given, in the byte order the format stores a UUID in"
    );
    assert_eq!(
        first_tree_block_chunk_uuid(&image),
        chunk_uuid_before,
        "and the chunk tree's own id, which mkfs.btrfs also invents, is untouched — which \
         is why tuning a baseline afterwards does not make two of them identical"
    );
    btrfs_check_clean(&image, &[])
        .unwrap_or_else(|e| panic!("the checker rejected a tuned image: {e}"));
}

/// The chunk-tree id out of the first tree block, which on every image these gates build
/// begins at 1 MiB — the first byte the format allocates past the reserved head.
///
/// Read by offset rather than by walking the chunk tree, because there is nothing here to
/// walk one with. What makes it sound is that the value is only ever compared against
/// itself, at the same offset, before and after a change.
fn first_tree_block_chunk_uuid(image: &Path) -> [u8; 16] {
    let mut file = File::open(image).expect("open the image");
    file.seek(SeekFrom::Start(
        FIRST_TREE_BLOCK + header::CHUNK_TREE_UUID as u64,
    ))
    .expect("seek to the chunk-tree id");
    let mut uuid = [0u8; 16];
    file.read_exact(&mut uuid).expect("read the chunk-tree id");
    uuid
}

/// Two formats at one parameter set are not byte-identical, and this is where they differ.
///
/// The other two families' baselines *are* reproducible once one field is pinned, which is
/// what lets their differential gates be whole-image byte comparisons with nothing carved
/// out. This one is not, and it is better to know the shape of that now than to discover
/// it as a diff nobody can read.
///
/// What varies is identity and the checksums covering it, not layout: the same blocks are
/// allocated at the same addresses both times. So the divergence is confined to a handful
/// of fields a writer of this crate's own will take as *inputs*, and the differential this
/// family builds lifts them out of the baseline image and hands them back — which is the
/// same move the FAT and exFAT gates make for the bytes their formatters sign their work
/// with.
#[test]
fn two_formats_at_one_parameter_set_differ_only_where_the_baseline_invents_something() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let args = [
        "-s",
        "4096",
        "-n",
        "16384",
        "-U",
        "11111111-2222-3333-4444-555555555555",
        "--device-uuid",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
    ];
    let first = lab.formatted("repeat-a.img", COMPACT, &args);
    let second = lab.formatted("repeat-b.img", COMPACT, &args);

    let a = fs::read(&first).expect("read the first image");
    let b = fs::read(&second).expect("read the second image");
    assert_eq!(a.len(), b.len(), "two formats of one size produce one size");
    assert_ne!(
        a, b,
        "if the baseline has become reproducible, the differential gate this family builds \
         can be a whole-image comparison and this gate is the finding"
    );

    // Nothing in the reserved head differs, the primary superblock included — so the two
    // runs agree on the address of every tree root, the generation they stopped at, and
    // how many bytes they used. That is the strongest single statement here: what varies
    // is *inside* the metadata blocks, not which ones there are.
    let head = FIRST_TREE_BLOCK as usize;
    assert_eq!(
        &a[..head],
        &b[..head],
        "the reserved head, primary superblock and all, is identical between two runs"
    );

    // And inside a block, only its checksum and the chunk-tree id it carries. Every other
    // header field — which block this is, which tree owns it, how many items it holds and
    // at what level — is the same in both, which is the same claim one layer in: the same
    // trees, the same shape, the same addresses.
    const NODE: usize = 16384;
    let mut compared = 0usize;
    for start in (head..a.len() - NODE + 1).step_by(NODE) {
        let (x, y) = (&a[start..start + NODE], &b[start..start + NODE]);
        if x == y {
            continue;
        }
        compared += 1;
        assert_eq!(
            &x[header::FSID..header::FSID + 16],
            &y[header::FSID..header::FSID + 16],
            "the filesystem id, at {start:#x}"
        );
        for (field, at) in [
            ("the block's own logical address", header::BYTENR),
            ("its flags", header::FLAGS),
            ("the generation that wrote it", header::GENERATION),
            ("the tree that owns it", header::OWNER),
        ] {
            assert_eq!(u64_at(x, at), u64_at(y, at), "{field}, at {start:#x}");
        }
        assert_eq!(
            u32_at(x, header::NRITEMS),
            u32_at(y, header::NRITEMS),
            "how many items it holds, at {start:#x}"
        );
        assert_eq!(
            x[header::LEVEL],
            y[header::LEVEL],
            "whether it is a leaf or a node, at {start:#x}"
        );
        assert_ne!(
            &x[header::CHUNK_TREE_UUID..header::GENERATION],
            &y[header::CHUNK_TREE_UUID..header::GENERATION],
            "a block differing at all differs in the chunk-tree id, at {start:#x} — this \
             is the identity mkfs.btrfs invents and no tool in the suite can pin"
        );
        assert_ne!(
            &x[header::CSUM..header::FSID],
            &y[header::CSUM..header::FSID],
            "and therefore in its checksum, at {start:#x}"
        );
    }
    assert!(
        compared > 0,
        "asserted above, restated as the premise of what this loop read"
    );
}

// ---------------------------------------------------------------------------
// The checker discriminates

/// A healthy baseline image is accepted, by both of the checker's questions.
///
/// The control's control: every gate below asserts a rejection, and a rejection means
/// nothing unless the same image before the damage was accepted.
#[test]
fn a_healthy_baseline_image_is_accepted() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "healthy.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    btrfs_check_clean(&image, &[]).expect("the checker accepts a healthy image");
    btrfs_check_clean(&image, &["--check-data-csum"])
        .expect("and accepts it when it reads the data back too");
}

/// A superblock whose checksum no longer covers its contents is rejected.
///
/// The one corruption in this file that needs no tool and no parser: the primary
/// superblock is at a fixed offset and its checksum covers everything after it, so
/// altering any byte past the first thirty-two breaks it. That makes this the control
/// whose vector this repository authored, beside four that upstream's corruptor does.
///
/// It also settles a question a reader has to answer: the second superblock is intact
/// here and the checker refuses the volume anyway rather than falling back to it. Reading
/// a copy is something a caller asks for, not something a reader does quietly.
#[test]
fn a_superblock_whose_checksum_no_longer_covers_it_is_rejected() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let healthy = lab.formatted("sb-healthy.img", ORDINARY, &["-s", "4096"]);
    btrfs_check_clean(&healthy, &[]).expect("the image is healthy before the damage");

    let damaged = copy_of(&lab, &healthy, "sb-damaged.img");
    flip_byte(&damaged, MIRRORS[0] + sb::GENERATION as u64);
    assert_eq!(
        primary(&damaged)[sb::CSUM..sb::CSUM + 32],
        primary(&healthy)[sb::CSUM..sb::CSUM + 32],
        "the checksum itself is untouched, so what the checker objects to is that it no \
         longer covers what follows it rather than that it was altered"
    );
    assert!(
        has_mirror(&damaged, MIRRORS[1]),
        "the second superblock is untouched"
    );

    let refusal = btrfs_check_clean(&damaged, &[])
        .expect_err("the checker must refuse a superblock whose checksum does not cover it");
    assert!(
        refusal.contains("superblock checksum mismatch"),
        "and refuse it for the damage rather than for something else:\n{refusal}"
    );
}

/// A tree block whose checksum no longer covers its contents is rejected.
///
/// The same defect one layer in, and the layer that matters: a writer computes a checksum
/// per tree block, and the reserved head's superblock is the one block whose checksum a
/// writer is least likely to get wrong, having written it last and alone.
#[test]
fn a_tree_block_whose_checksum_no_longer_covers_it_is_rejected() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let healthy = lab.formatted("block-healthy.img", ORDINARY, &["-s", "4096"]);
    btrfs_check_clean(&healthy, &[]).expect("the image is healthy before the damage");

    let damaged = copy_of(&lab, &healthy, "block-damaged.img");
    let leaf = fs_tree_leaf(&damaged);
    corrupt(&damaged, &["-l", &leaf.to_string(), "-b", "64"]);

    let refusal = btrfs_check_clean(&damaged, &[])
        .expect_err("the checker must refuse a tree block whose checksum does not cover it");
    assert!(
        refusal.contains("checksum verify failed"),
        "and refuse it for the damage rather than for something else:\n{refusal}"
    );
}

/// A leaf whose item offsets no longer describe its items is rejected.
///
/// The defect class this family has and the earlier ones do not: a leaf grows an item
/// array forward from its header and the items' data backward from the block's end, so
/// every offset in it is a bound in the opposite direction from the one a reader is
/// walking. Nothing about it is caught by a checksum — the corruptor recomputes one — so a
/// checker that only verified checksums would accept this, which is exactly why it is a
/// control of its own.
#[test]
fn a_leaf_whose_item_offsets_do_not_describe_its_items_is_rejected() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let healthy = lab.formatted("leaf-healthy.img", ORDINARY, &["-s", "4096"]);
    btrfs_check_clean(&healthy, &[]).expect("the image is healthy before the damage");

    let damaged = copy_of(&lab, &healthy, "leaf-damaged.img");
    let leaf = fs_tree_leaf(&damaged);
    corrupt(&damaged, &["-m", &leaf.to_string(), "-f", "shift_items"]);

    let refusal = btrfs_check_clean(&damaged, &[])
        .expect_err("the checker must refuse a leaf whose item offsets do not describe it");
    assert!(
        refusal.contains("unexpected item end"),
        "and refuse it for the damage rather than for something else:\n{refusal}"
    );
}

/// An extent the extent tree no longer records is rejected.
///
/// The accounting half of the format, and the half a from-scratch writer is most likely to
/// get wrong: every allocated extent has a record and a backref saying who holds it, and
/// the records include the ones the extent tree's own blocks occupy. A writer whose
/// reservation and whose accounting disagree produces exactly this, and no checksum
/// anywhere is affected by it.
#[test]
fn an_extent_the_tree_no_longer_records_is_rejected() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let healthy = lab.formatted(
        "extent-healthy.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    btrfs_check_clean(&healthy, &[]).expect("the image is healthy before the damage");

    let damaged = copy_of(&lab, &healthy, "extent-damaged.img");
    let extent = first_data_extent(&damaged);
    corrupt(&damaged, &["-e", "-l", &extent.to_string()]);

    let refusal = btrfs_check_clean(&damaged, &[])
        .expect_err("the checker must refuse an extent nothing accounts for");
    assert!(
        refusal.contains("ref mismatch") || refusal.contains("extent allocation tree"),
        "and refuse it for the damage rather than for something else:\n{refusal}"
    );
}

/// A file whose bytes have been altered is a clean filesystem to one of the checker's
/// questions and a broken one to the other.
///
/// This is what makes `--check-data-csum` a second gate rather than a louder first one,
/// and it is the family's only oracle with no analogue anywhere else in this project:
/// ext4 checksums no data block and neither FAT nor exFAT checksums anything at all. A
/// writer that produced a correct checksum tree for the wrong bytes, or the right bytes
/// under the wrong logical address, passes every other gate here.
///
/// The damage is found by searching the image for the file's own pattern rather than by
/// translating a logical address, which is what keeps the gate from assuming the single-
/// device mapping is the identity — the assumption the family's plan refuses to build a
/// reader on.
#[test]
fn altered_file_bytes_are_caught_by_the_data_checksum_gate_and_by_nothing_else() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let healthy = lab.formatted(
        "csum-healthy.img",
        COMPACT,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    btrfs_check_clean(&healthy, &["--check-data-csum"])
        .expect("the image is healthy before the damage");

    let damaged = copy_of(&lab, &healthy, "csum-damaged.img");
    let bytes = fs::read(&damaged).expect("read the image");
    let at = bytes
        .windows(LARGE_FILE_PATTERN.len())
        .position(|w| w == LARGE_FILE_PATTERN)
        .expect("the large file's bytes are somewhere in the image");
    flip_byte(&damaged, at as u64);

    btrfs_check_clean(&damaged, &[]).expect(
        "the metadata gate must still accept it: nothing about the trees changed, and a \
         checker that started objecting here would stop being a second question",
    );
    let refusal = btrfs_check_clean(&damaged, &["--check-data-csum"])
        .expect_err("the data-checksum gate must refuse it");
    assert!(
        refusal.contains("csum") && refusal.contains("expected csum"),
        "and refuse it for the checksum rather than for something else:\n{refusal}"
    );
}

// ---------------------------------------------------------------------------
// Reading a tree's shape out of the baseline, for the gates that damage one

/// The logical address of a leaf in the image's fs tree.
///
/// Taken from the baseline's own rendering rather than by walking anything, there being
/// nothing here to walk with. `dump-tree` prints one line per node and leaf naming its
/// address, and the first of them for a tree with one leaf is that leaf.
fn fs_tree_leaf(image: &Path) -> u64 {
    let dump = inspect(image, &["dump-tree", "-t", "fs"]);
    dump.lines()
        .find_map(|line| {
            line.strip_prefix("leaf ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no leaf in the fs tree:\n{dump}"))
}

/// The logical address of the first data extent the extent tree records.
///
/// `EXTENT_ITEM` is a data extent and `METADATA_ITEM` is a tree block under this pin's
/// default skinny-metadata, so the key's type is what separates them and the objectid is
/// the address.
fn first_data_extent(image: &Path) -> u64 {
    let dump = inspect(image, &["dump-tree", "-t", "extent"]);
    dump.lines()
        .find_map(|line| {
            let key = line.split("key (").nth(1)?;
            let (objectid, rest) = key.split_once(' ')?;
            rest.starts_with("EXTENT_ITEM")
                .then(|| objectid.parse().ok())?
        })
        .unwrap_or_else(|| panic!("no data extent in the extent tree:\n{dump}"))
}

// ---------------------------------------------------------------------------
// This crate's reader, against the baseline it was written from
//
// Everything above establishes what the tools say. What follows holds the reader to it: the
// same image, read two ways, block for block. The tier is what makes that comparison worth
// making — an oracle nobody has watched reject anything certifies nothing, and these gates
// are the collection on that.

/// Which parameter sets the reader is held to the baseline over.
///
/// A covering set rather than a cross product: each row moves one thing the tree engine
/// actually depends on — how long a block is, how many copies of a chunk there are, which tree
/// the block groups live in, and how a file's holes are recorded — and the populated case
/// below adds the one dimension no option produces, a tree deeper than a single leaf.
#[cfg(feature = "btrfs")]
const READER_MATRIX: &[(&str, &[&str])] = &[
    ("the defaults, whatever this pin makes them", &[]),
    (
        "sixty-four kilobyte blocks",
        &["-s", "65536", "-n", "65536"],
    ),
    ("eight kilobyte sectors", &["-s", "8192"]),
    ("one copy of everything", &["-m", "single", "-d", "single"]),
    (
        "block groups in the extent tree",
        &["-O", "^block-group-tree"],
    ),
    ("holes recorded as extents", &["-O", "^no-holes"]),
    (
        "metadata extents in the wide form",
        &["-O", "^skinny-metadata"],
    ),
];

/// Every tree block the baseline's own rendering names, as address to entry count.
///
/// `dump-tree` prints two lines per block — one naming its count and one naming its flags — so
/// only the first shape is read, and a map keyed by address collapses the repeat that printing
/// a tree per root would otherwise produce.
#[cfg(feature = "btrfs")]
fn oracle_blocks(image: &Path) -> std::collections::BTreeMap<u64, u32> {
    let dump = inspect(image, &["dump-tree"]);
    let mut blocks = std::collections::BTreeMap::new();
    for line in dump.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        // `leaf <addr> items <n> ...` and `node <addr> level <l> items <n> ...`. The second
        // line each block gets names its flags rather than a count, and is skipped by not
        // matching either shape.
        let (at, items) = match words.as_slice() {
            ["leaf", at, "items", items, ..] => (at, items),
            ["node", at, "level", _, "items", items, ..] => (at, items),
            _ => continue,
        };
        let (Ok(at), Ok(items)) = (at.parse(), items.parse()) else {
            continue;
        };
        blocks.insert(at, items);
    }
    assert!(
        !blocks.is_empty(),
        "the baseline's rendering of {image:?} named no tree block at all:\n{dump}"
    );
    blocks
}

/// The same, read through this crate: every block of every tree the volume can reach.
#[cfg(feature = "btrfs")]
fn reader_blocks(image: &Path) -> std::collections::BTreeMap<u64, u32> {
    use ferrosys::btrfs::Volume;

    let mut volume = Volume::open(File::open(image).expect("open the image"))
        .unwrap_or_else(|e| panic!("open {image:?}: {e}"));
    let roots = volume
        .tree_roots()
        .unwrap_or_else(|e| panic!("read the root tree of {image:?}: {e}"));
    let mut blocks = std::collections::BTreeMap::new();
    for root in roots {
        volume
            .tree(root)
            .for_each_block(|block| {
                blocks.insert(block.header().bytenr, block.header().nritems);
                true
            })
            .unwrap_or_else(|e| panic!("walk tree {} of {image:?}: {e}", root.objectid));
    }
    blocks
}

/// The reader reaches every tree the baseline wrote, and agrees about every block of each.
///
/// This is the reader tier's whole claim, stated as one comparison. Reaching a block means
/// translating its logical address through the chunk map and verifying its checksum, so a walk
/// that produces the same table the baseline prints is a walk that did both for every block on
/// the filesystem — including the chunk tree, which is reachable only through the superblock's
/// bootstrap array, and the root tree, which holds no record of itself.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_reaches_every_tree_the_baseline_wrote_and_agrees_block_for_block() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (index, (name, args)) in READER_MATRIX.iter().enumerate() {
        let image = lab.formatted(&format!("matrix-{index}.img"), ORDINARY, args);
        assert_eq!(
            reader_blocks(&image),
            oracle_blocks(&image),
            "reading a filesystem formatted with {name}"
        );
    }
}

/// The same, over a filesystem with a tree deeper than one leaf.
///
/// No format option produces one: what makes a tree grow a level is having enough in it, so
/// the populated baseline is the only way to reach a descent at all — and a descent is where
/// the child pointers, the level check and the seek all live.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_descends_through_the_baselines_own_multi_level_tree() {
    use ferrosys::btrfs::Volume;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = lab.path().join("many");
    fs::create_dir(&source).expect("create the source directory");
    // Enough names that the filesystem tree cannot be one leaf, at either block size.
    for n in 0..2000 {
        fs::write(source.join(format!("entry-{n:04}")), b"x").expect("write a file");
    }
    for (index, (name, args)) in [
        ("sixteen kilobyte blocks", &[][..]),
        ("sixty-four kilobyte blocks", &["-n", "65536"][..]),
    ]
    .iter()
    .enumerate()
    {
        let mut with_source = args.to_vec();
        with_source.extend(["-r", source.to_str().expect("a utf-8 path")]);
        let image = lab.formatted(&format!("deep-{index}.img"), ORDINARY, &with_source);

        assert_eq!(
            reader_blocks(&image),
            oracle_blocks(&image),
            "reading a populated filesystem formatted with {name}"
        );

        // And the tree is genuinely deeper than a leaf, so the comparison above exercised a
        // descent rather than passing because there was nothing to descend through.
        let mut volume = Volume::open(File::open(&image).expect("open")).expect("open the volume");
        let deepest = volume
            .tree_roots()
            .expect("the root tree")
            .iter()
            .map(|root| root.level)
            .max()
            .expect("at least one tree");
        assert!(
            deepest > 0,
            "no tree of the {name} image is deeper than one leaf"
        );
    }
}

/// Where a seek lands is where a walk of the whole tree would have reached.
///
/// Run against the baseline's own trees rather than a forged one, so the keys are the ones a
/// real filesystem produces — every key present is probed, and so is one below and one above
/// each, which is where an off-by-one in the descent's binary search shows.
#[test]
#[cfg(feature = "btrfs")]
fn a_seek_into_the_baselines_own_tree_lands_where_a_walk_would_have_reached() {
    use ferrosys::btrfs::{Volume, ondisk::DiskKey};

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "seek.img",
        ORDINARY,
        &["-r", source.to_str().expect("a utf-8 path")],
    );
    let mut volume = Volume::open(File::open(&image).expect("open")).expect("open the volume");

    for root in volume.tree_roots().expect("the root tree") {
        let mut all = Vec::new();
        volume
            .tree(root)
            .for_each_item(|key, _| {
                all.push(*key);
                true
            })
            .expect("walk the tree");

        let mut probes = vec![DiskKey::MIN];
        for key in &all {
            probes.push(*key);
            probes.push(DiskKey::new(
                key.objectid,
                key.kind,
                key.offset.saturating_sub(1),
            ));
            probes.push(DiskKey::new(
                key.objectid,
                key.kind,
                key.offset.wrapping_add(1),
            ));
        }
        for probe in probes {
            let expected: Vec<DiskKey> = all.iter().copied().filter(|k| *k >= probe).collect();
            let mut got = Vec::new();
            volume
                .tree(root)
                .for_each_item_from(probe, |key, _| {
                    got.push(*key);
                    true
                })
                .expect("seek into the tree");
            assert_eq!(got, expected, "tree {} seeking to {probe:?}", root.objectid);
        }
    }
}

/// The chunk map is the baseline's own, and it is not the identity.
///
/// The second half is what makes the first worth asserting. A reader that returned its input
/// would pass a comparison against a filesystem whose chunks happen to sit where their logical
/// addresses say — and the pinned baseline writes one chunk per image that does not.
#[test]
#[cfg(feature = "btrfs")]
fn the_chunk_map_is_the_baselines_own_and_is_not_the_identity() {
    use ferrosys::btrfs::Volume;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = lab.formatted("chunks.img", ORDINARY, &[]);
    let volume = Volume::open(File::open(&image).expect("open")).expect("open the volume");

    // What the baseline says: one `(logical, length, first stripe offset)` per chunk item.
    let dump = inspect(&image, &["dump-tree", "-t", "chunk"]);
    let mut expected: Vec<(u64, u64, u64)> = Vec::new();
    let mut pending: Option<(u64, u64)> = None;
    for line in dump.lines() {
        let line = line.trim();
        if let Some(rest) = line.split("CHUNK_ITEM ").nth(1) {
            let logical = rest
                .split(')')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("a chunk key with no logical address: {line}"));
            pending = Some((logical, 0));
        } else if let Some(rest) = line.strip_prefix("length ") {
            let length = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("a chunk with no length: {line}"));
            pending = pending.map(|(logical, _)| (logical, length));
        } else if line.starts_with("stripe 0 devid ")
            && let Some((logical, length)) = pending.take()
        {
            let offset = line
                .split("offset ")
                .nth(1)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| panic!("a stripe with no offset: {line}"));
            expected.push((logical, length, offset));
        }
    }
    expected.sort_unstable();
    assert!(
        !expected.is_empty(),
        "no chunk in the baseline's rendering:\n{dump}"
    );

    let found: Vec<(u64, u64, u64)> = volume
        .chunk_map()
        .chunks()
        .iter()
        .map(|chunk| (chunk.logical, chunk.length, chunk.copies[0]))
        .collect();
    assert_eq!(found, expected, "the chunk map against the baseline's own");
    assert!(
        found
            .iter()
            .any(|(logical, _, physical)| logical != physical),
        "every chunk of this image sits where its logical address says, so the comparison \
         would have passed for a reader that translated nothing:\n{found:?}"
    );
}

/// Every copy of the superblock the baseline wrote is one this reader finds, at every
/// threshold the count changes at.
///
/// The reader's side of the mirror-count rule.
/// `a_volume_carries_every_superblock_location_it_has_room_for`
/// above establishes what the baseline writes; this establishes that the reader agrees, which
/// is a different claim — a reader that looked at one location would pass every other gate in
/// this file.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_finds_every_superblock_copy_the_baseline_wrote() {
    use ferrosys::btrfs::{Mirror, Volume};

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    // The first two rows are unreplicated: the count changes at 64 MiB, and the default
    // pairing refuses a volume below 109 MiB, so a volume with exactly one copy is only
    // formattable at `-m single -d single`. The third is far past either limit.
    for (bytes, args, expected) in [
        (MIRRORS[1] - 1, &["-m", "single", "-d", "single"][..], 1),
        (
            MIRRORS[1] + SUPER_INFO_SIZE,
            &["-m", "single", "-d", "single"][..],
            2,
        ),
        (MIRRORS[2] + SUPER_INFO_SIZE, &[][..], 3),
    ] {
        let image = lab.formatted(&format!("mirrors-{bytes}.img"), bytes, args);
        let volume = Volume::open(File::open(&image).expect("open")).expect("open the volume");
        let present = volume
            .mirrors()
            .iter()
            .filter(|m| matches!(m, Mirror::Present { .. }))
            .count();
        assert_eq!(
            present, expected,
            "a {bytes}-byte volume, whose copies the baseline places at {MIRRORS:?}"
        );
        // And the baseline's own count agrees, so neither side is being believed alone.
        let by_magic = MIRRORS.iter().filter(|&&at| has_mirror(&image, at)).count();
        assert_eq!(by_magic, expected, "a {bytes}-byte volume, by magic alone");
    }
}

/// Each of the corruptions the tier watched `btrfs check` reject is one this reader rejects.
///
/// Three of the oracle tier's five, plus a fourth vector that tier did not need: a leaf
/// whose keys have been swapped, which the checker also rejects and which this reader must,
/// since a search over an unsorted tree misses items rather than failing.
///
/// The two of the tier's five that are absent are absent for a stated reason: an extent the
/// extent tree no longer records and a file whose bytes have been altered are both findings
/// about *content*, which this layer does not read — it reaches trees and verifies blocks.
/// Both belong to the gates that read what is in them.
///
/// Every row runs against a copy of an image this reader has just accepted, so a refusal is
/// attributable to the damage rather than to the image having been unreadable all along.
#[test]
#[cfg(feature = "btrfs")]
fn each_corruption_the_checker_rejects_is_one_this_reader_rejects() {
    use ferrosys::btrfs::ReadError;
    use ferrosys::btrfs::ondisk::objectid;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let healthy = lab.formatted(
        "healthy.img",
        COMPACT,
        &["-r", source.to_str().expect("a utf-8 path")],
    );
    // The control: undamaged, this reader reads every block of every tree.
    assert_eq!(reader_blocks(&healthy), oracle_blocks(&healthy));

    let leaf = fs_tree_leaf(&healthy);

    // A tree block whose checksum no longer covers it. The corruptor writes into the block
    // and leaves the checksum alone, which is what makes it this row rather than the next.
    let damaged = copy_of(&lab, &healthy, "csum.img");
    corrupt(&damaged, &["-l", &leaf.to_string(), "-b", "8"]);
    let refusal = read_back(&damaged);
    assert!(
        matches!(
            refusal,
            Err(ReadError::BadChecksum {
                object: "tree block",
                ..
            })
        ),
        "a tree block the corruptor damaged: {refusal:?}"
    );

    // A leaf whose item offsets no longer describe its items. No checksum is affected — the
    // corruptor recomputes it — so what refuses this is the bound on where an item's data may
    // sit, and nothing else.
    let shifted = copy_of(&lab, &healthy, "shift.img");
    corrupt(&shifted, &["-m", &leaf.to_string(), "-f", "shift_items"]);
    let refusal = read_back(&shifted);
    assert!(
        matches!(
            refusal,
            Err(ReadError::BadItem { .. } | ReadError::BadTreeBlock { .. })
        ),
        "a leaf whose items were shifted: {refusal:?}"
    );

    // A leaf whose keys are no longer in order. Re-checksummed like the row above, and
    // refused by the ordering check rather than by any bound: a search over an unsorted tree
    // silently misses items instead of failing, so a reader that only bounded would hand back
    // a wrong answer rather than none.
    //
    // The value is named rather than left to the tool. `--keys` swaps two slots the corruptor
    // picks at random — negative indices among them — so it damages a different leaf every
    // run and sometimes damages none, which is not a control. Rewriting one named key to one
    // named value is the same class of damage and is the same on every run.
    let shuffled = copy_of(&lab, &healthy, "keys.img");
    corrupt(
        &shuffled,
        &[
            "-r",
            &objectid::FS_TREE.to_string(),
            "-K",
            &first_dir_item(&healthy),
            "-f",
            "objectid",
            "--value",
            &objectid::ROOT_TREE.to_string(),
        ],
    );
    assert!(
        btrfs_check_clean(&shuffled, &[]).is_err(),
        "the checker rejects a leaf whose keys are out of order, so this is a control"
    );
    let refusal = read_back(&shuffled);
    assert!(
        matches!(
            refusal,
            Err(ReadError::BadTreeBlock { .. } | ReadError::BadItem { .. })
        ),
        "a leaf whose keys are out of order: {refusal:?}"
    );

    // A superblock whose checksum no longer covers it, in every copy the volume has — with
    // one copy left intact the reader is supposed to read through it, which is the gate after
    // this one.
    let broken = copy_of(&lab, &healthy, "super.img");
    for &at in MIRRORS.iter().filter(|&&at| has_mirror(&broken, at)) {
        flip_byte(&broken, at + sb::GENERATION as u64);
    }
    let refusal = read_back(&broken);
    assert!(
        matches!(
            refusal,
            Err(ReadError::BadChecksum {
                object: "superblock",
                ..
            })
        ),
        "a superblock damaged in every copy: {refusal:?}"
    );
}

/// A damaged copy of the superblock is read through, and said so about.
///
/// The reason the format writes more than one. It needs a volume large enough to have two,
/// which is why it is not a row of the gate above.
#[test]
#[cfg(feature = "btrfs")]
fn a_damaged_copy_of_the_superblock_is_read_through_and_reported() {
    use ferrosys::btrfs::{Mirror, OpenOptions, ReadPolicy, Volume};

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = lab.formatted(
        "two-copies.img",
        MIRRORS[1] + SUPER_INFO_SIZE + ORDINARY,
        &[],
    );
    assert!(
        has_mirror(&image, MIRRORS[1]),
        "this volume has a second copy"
    );
    flip_byte(&image, MIRRORS[0] + sb::GENERATION as u64);

    // Strictly, a copy that does not agree with the live one is a refusal.
    assert!(
        read_back(&image).is_err(),
        "a strict read refuses a damaged copy"
    );

    // Leniently, the filesystem opens through the surviving copy and names the damaged one.
    let mut volume = Volume::open_with(
        File::open(&image).expect("open"),
        OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .expect("the second copy is intact");
    assert_eq!(volume.mirrors()[0], Mirror::Damaged);
    assert!(matches!(volume.mirrors()[1], Mirror::Present { .. }));
    let root = volume.root_tree();
    volume
        .tree(root)
        .count_items()
        .expect("the filesystem reads through the surviving copy");
}

/// The first directory entry of the filesystem tree, as the `objectid,type,offset` triplet the
/// corruptor takes.
///
/// Any key with a key before it in its leaf would do; a directory entry is one every populated
/// filesystem has, and it never sits first in its leaf — the inode item and its name are ahead
/// of it — so rewriting its objectid downward always puts it out of order.
#[cfg(feature = "btrfs")]
fn first_dir_item(image: &Path) -> String {
    use ferrosys::btrfs::ondisk::ItemType;

    let dump = inspect(image, &["dump-tree", "-t", "fs"]);
    dump.lines()
        .find_map(|line| {
            let key = line.split("key (").nth(1)?;
            let mut parts = key.split_whitespace();
            let (objectid, kind, offset) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "DIR_ITEM").then(|| {
                format!(
                    "{objectid},{},{}",
                    ItemType::DIR_ITEM.value(),
                    offset.trim_end_matches(')')
                )
            })
        })
        .unwrap_or_else(|| panic!("no directory entry in the filesystem tree:\n{dump}"))
}

/// Open `image` and walk every tree of it, so a gate asserts on one outcome rather than on
/// whichever of the two steps happened to fail.
#[cfg(feature = "btrfs")]
fn read_back(image: &Path) -> Result<(), ferrosys::btrfs::ReadError> {
    use ferrosys::btrfs::Volume;

    let mut volume = Volume::open(File::open(image).expect("open the image"))?;
    for root in volume.tree_roots()? {
        volume.tree(root).for_each_block(|_| true)?;
    }
    Ok(())
}

/// Every name a walk of `image` reaches, `/`-joined and sorted, with what is at each.
#[cfg(feature = "btrfs")]
fn walked(image: &Path) -> Vec<(String, ferrosys::btrfs::Node)> {
    use ferrosys::btrfs::Reader;

    let mut reader = Reader::open(File::open(image).expect("open the image")).expect("open it");
    let mut out: Vec<(String, ferrosys::btrfs::Node)> = reader
        .walk()
        .expect("walk it")
        .into_iter()
        .map(|entry| {
            (
                String::from_utf8_lossy(&entry.path).into_owned(),
                entry.node,
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The filesystem view, over an image the baseline filled from a directory.
///
/// The tier's other reader gate reads every *block* of every tree, which says the address
/// space and the B-trees are right and says nothing about what the items mean. This is the
/// other half: the names, the modes, the bytes, the link target, the second name for one
/// file, and the checksums the filesystem recorded for its own data — held against the tree
/// this test wrote, on an image `btrfs check --check-data-csum` calls healthy.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_reads_back_the_tree_the_baseline_was_given() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let source = source_tree(&lab);
    let image = lab.formatted(
        "read-back.img",
        ORDINARY,
        &[
            "-s",
            "4096",
            "-r",
            source.to_str().expect("a UTF-8 scratch path"),
        ],
    );
    btrfs_check_clean(&image, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected the fixture: {e}"));

    let reached = walked(&image);
    let names: Vec<&str> = reached.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "",
            "/dir",
            "/dir/nested",
            "/dir/small.txt",
            "/empty",
            "/large.bin",
            "/link",
            "/second-name.txt",
        ],
        "every name the source tree had, and no other"
    );

    use ferrosys::btrfs::Reader;
    let mut reader = Reader::open(File::open(&image).expect("open the image")).expect("open it");

    // A small file lives inside its own record and a large one is addressed by an extent, so
    // the two exercise the two shapes an extent record takes.
    let small = reader.lookup(b"/dir/small.txt").expect("the small file");
    assert_eq!(
        reader.read_data(&small).expect("its bytes"),
        b"stored inside its own inode\n"
    );
    let large = reader.lookup(b"/large.bin").expect("the large file");
    let bytes = reader.read_data(&large).expect("its bytes");
    assert_eq!(bytes, LARGE_FILE_PATTERN.repeat(LARGE_FILE_REPEATS));

    // Reading from the middle of an addressed extent, which is the case the covering-record
    // search exists for: the record is keyed by where it begins and the position is not.
    let mut window = [0u8; 16];
    let at = 4096 + LARGE_FILE_PATTERN.len() as u64 * 3;
    reader
        .read_into(&large, at, &mut window)
        .expect("a read from the middle");
    assert_eq!(&window, LARGE_FILE_PATTERN);

    // The link's target is reproduced as the source wrote it, which is what reading one is;
    // resolving one is the other lookup, and the foreign matrix is where both are held.
    let link = reader.lookup_no_follow(b"/link").expect("the link");
    assert!(link.is_symlink());
    assert_eq!(
        reader.link_target(&link).expect("its target"),
        b"dir/small.txt"
    );

    // Two names for one file, which is a property of the inode rather than of either name.
    let second = reader.lookup(b"/second-name.txt").expect("the second name");
    assert_eq!(second.inode, small.inode);
    assert_eq!(second.item.nlink, 2);

    // And the mode and ownership the source tree carried, which is what makes this a
    // filesystem view rather than a byte comparison.
    assert!(reader.lookup(b"/dir").expect("the directory").is_dir());
    assert_eq!(small.item.mode & 0o170_000, 0o100_000);
    assert_eq!(small.item.uid, nix_uid());

    // Every byte of every file, against the checksums the filesystem recorded for it — the
    // check `btrfs check` makes only with `--check-data-csum`, and the one no other family
    // in this crate can make at all.
    for (path, node) in &reached {
        reader
            .verify_data(node)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
    }

    // Nothing is wrong with it, said by this crate rather than by the checker.
    let report = reader.scan();
    assert!(report.is_clean(), "{:?}", report.anomalies());
}

/// The user this test process runs as, which is the owner `mkfs.btrfs -r` records for every
/// entry it copies.
#[cfg(feature = "btrfs")]
fn nix_uid() -> u32 {
    // Read off a file this process owns rather than through a call: the crate under test has
    // no ownership call outside its `dir` feature, and this tier does not compile it in. What
    // reaches the image is the owner of the *source tree*, which this process created.
    use std::os::unix::fs::MetadataExt as _;
    let here = std::env::current_exe().expect("this test binary has a path");
    fs::metadata(here).expect("it has metadata").uid()
}

// ---------------------------------------------------------------------------
// The foreign-image matrix
//
// The reader gates above run over one image at one parameter set, which proves that this
// reader and this baseline agree about a filesystem — not that the reader handles the
// filesystems the format allows. This is the gate that does: every image here is laid out by
// `mkfs.btrfs` and filled by `mkfs.btrfs -r`, certified healthy by `btrfs check`, and then
// read by this crate, over a matrix that moves everything about a btrfs a reader has to
// follow.
//
// **Both halves, and neither is the other.** A reader that finds nothing wrong with an image
// may have read nothing at all — a clean scan is a claim about anomalies and not about
// contents — and a reader that enumerates every name correctly may be reading each file's
// bytes out of the wrong extent. So one gate holds the tree, the bytes, the modes, the link
// target, the second name, and the attributes against what went in; another says the scan is
// clean and every byte agrees with the checksum the filesystem recorded for it; and the
// controls at the end say both would have noticed.

/// Where a row's tree blocks sit in the band the format defines, as a position rather than a
/// size.
///
/// A node cannot be smaller than the sector it is addressed in, so the smallest node a volume
/// may have is a property of that volume rather than a number: four kilobytes on one row and
/// sixty-four on another. Writing the dimension as a position is what makes "the smallest node
/// this row allows" one value two rows share rather than two values — and it is what keeps the
/// matrix from asking for the combinations the format forbids.
#[cfg(feature = "btrfs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeSize {
    /// The smallest node this row's sector size allows, which is that sector size.
    Floor,
    /// Sixty-four kilobytes, the largest node the format defines.
    Ceiling,
}

/// How many copies of a metadata block a row's volume carries.
#[cfg(feature = "btrfs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// Two, which is what this pin picks for a single device.
    Dup,
    /// One.
    Single,
}

#[cfg(feature = "btrfs")]
impl Profile {
    /// How the baseline's command line spells it.
    fn as_str(self) -> &'static str {
        match self {
            Profile::Dup => "dup",
            Profile::Single => "single",
        }
    }

    /// How the baseline's own rendering of a chunk spells it, which is not the same: one of
    /// the two is an acronym there and a word on the command line.
    fn rendered(self) -> &'static str {
        match self {
            Profile::Dup => "DUP",
            Profile::Single => "single",
        }
    }
}

/// One row of the foreign-image matrix: a volume geometry, a feature set, and two properties
/// of the tree put into it.
#[cfg(feature = "btrfs")]
struct ForeignRow {
    /// What this row is, quoted in every failure so a message names the filesystem rather
    /// than an index.
    what: &'static str,
    /// The volume's addressable unit, in bytes.
    sector: u32,
    node: NodeSize,
    /// How many copies of each metadata block the volume carries.
    metadata: Profile,
    /// Whether the volume has a free-space tree.
    free_space_tree: bool,
    /// Whether its block groups live in a tree of their own rather than in the extent tree,
    /// which is where the format's `BLOCK_GROUP_ITEM` records are found.
    block_group_tree: bool,
    /// Whether a hole in a file is an absence of records rather than a record saying so.
    no_holes: bool,
    /// Whether the tree carries one name so many times that the names cannot fit in a single
    /// `INODE_REF` item and the format's wide form is used instead.
    dense_links: bool,
    /// Whether part of the tree is a subvolume — a second filesystem tree, whose inode numbers
    /// start again from the same value the first one's do.
    subvolume: bool,
}

#[cfg(feature = "btrfs")]
impl ForeignRow {
    /// The row's tree-block size, in bytes.
    fn node_bytes(&self) -> u32 {
        match self.node {
            NodeSize::Floor => self.sector,
            NodeSize::Ceiling => NODE_CEILING,
        }
    }

    /// What the pinned baseline is told to build this row.
    ///
    /// Every feature is stated as a removal from what this pin turns on by itself, because a
    /// removal is what the tool accepts and because it is what makes the row's `-O` list a
    /// list of exactly its differences from the default.
    fn args(&self) -> Vec<String> {
        let mut off: Vec<&str> = Vec::new();
        if !self.free_space_tree {
            off.push("^free-space-tree");
        }
        if !self.block_group_tree {
            off.push("^block-group-tree");
        }
        if !self.no_holes {
            off.push("^no-holes");
        }
        let mut args = vec![
            "-s".to_string(),
            self.sector.to_string(),
            "-n".to_string(),
            self.node_bytes().to_string(),
            "-m".to_string(),
            self.metadata.as_str().to_string(),
            "-d".to_string(),
            "single".to_string(),
        ];
        if !off.is_empty() {
            args.push("-O".to_string());
            args.push(off.join(","));
        }
        if self.subvolume {
            args.push("--subvol".to_string());
            args.push(format!("rw:{SUBVOLUME_DIR}"));
        }
        args
    }

    /// The read-only-compatible feature word this row's volume must end up with.
    ///
    /// Derived from the row rather than transcribed per row, so that a row edited in one
    /// column cannot keep an assertion that belonged to the value it had.
    fn compat_ro(&self) -> u64 {
        let mut word = 0;
        if self.free_space_tree {
            // The tree itself, and the bit saying its contents are current.
            word |= 0b11;
        }
        if self.block_group_tree {
            word |= 0b1000;
        }
        word
    }

    /// The incompatible feature word, the same way.
    ///
    /// Two bits move with the row rather than being the pin's default. `NO_HOLES` is the one
    /// the row asks about directly. `BIG_METADATA` is not asked about at all: it says a tree
    /// block is larger than the four kilobytes the format originally fixed them at, so the row
    /// whose blocks are exactly that size does not carry it, and no option turns it on or off.
    fn incompat(&self) -> u64 {
        let mut word = DEFAULT_INCOMPAT;
        if !self.no_holes {
            word &= !NO_HOLES;
        }
        if self.node_bytes() <= SMALL_METADATA {
            word &= !BIG_METADATA;
        }
        word
    }

    /// How many names this row's densely-linked file is given.
    ///
    /// An `INODE_REF` record is ten bytes and a name, every name for one inode in one
    /// directory shares a single item, and no item may pass what a leaf holds — so the count
    /// that forces the format's wide form is a function of the node size and cannot be a
    /// constant. A handful over the boundary rather than a multiple of it: the point is to
    /// cross it, and every name past the crossing is a directory entry to be written and
    /// walked for nothing.
    fn dense_link_count(&self) -> usize {
        if !self.dense_links {
            return 0;
        }
        self.node_bytes() as usize / (INODE_REF_ENTRY + LINK_NAME_LEN) + DENSE_LINK_SLACK
    }

    /// The length of this row's single-extent file: past the boundary where the baseline stops
    /// storing a file inside its own metadata, and short of where it starts splitting one.
    fn one_extent_len(&self) -> u64 {
        u64::from(self.sector) * 4
    }
}

/// The largest node the format defines, and the value [`NodeSize::Ceiling`] is.
#[cfg(feature = "btrfs")]
const NODE_CEILING: u32 = 64 << 10;

/// The `NO_HOLES` bit of the incompatible feature word.
#[cfg(feature = "btrfs")]
const NO_HOLES: u64 = 1 << 9;

/// Its `BIG_METADATA` bit, which says a tree block is larger than the size the format first
/// fixed them at.
#[cfg(feature = "btrfs")]
const BIG_METADATA: u64 = 1 << 5;

/// The node size that bit distinguishes: at this and below there is nothing big about the
/// metadata, and the baseline leaves the bit clear.
#[cfg(feature = "btrfs")]
const SMALL_METADATA: u32 = 4096;

/// The fixed part of an `INODE_REF` record: a directory index and a name length.
#[cfg(feature = "btrfs")]
const INODE_REF_ENTRY: usize = 10;

/// How far past the boundary a dense row goes.
#[cfg(feature = "btrfs")]
const DENSE_LINK_SLACK: usize = 8;

/// How long each of a dense row's names is, in bytes.
///
/// Long, and that is the point twice over: a long name is fewer names to reach the boundary
/// the wide form sits past, and a name of two hundred bytes is itself a directory entry no
/// short-name assumption survives.
#[cfg(feature = "btrfs")]
const LINK_NAME_LEN: usize = 201;

/// The directory a subvolume row's second tree is rooted at.
#[cfg(feature = "btrfs")]
const SUBVOLUME_DIR: &str = "home";

/// The volumes every foreign-image gate runs over.
///
/// **A covering array and not a cross product.** The dimensions are the sector size, where the
/// node sits in the band the format allows it, how many copies of a metadata block there are,
/// whether there is a free-space tree, whether block groups have a tree of their own, whether
/// holes are recorded as extents, whether one file has more names than a single record holds,
/// and whether part of the tree is a second subvolume. That is three hundred and eighty-four
/// combinations, of which these eight carry every *pair* the format permits.
///
/// The pair is the unit worth covering because what a reader gets wrong here is one thing
/// read through another: an item's position is an offset inside a node whose size is the
/// row's, a block group is found in whichever tree this row keeps them in, a file's bytes are
/// reached through a chunk map whose stripe count is the metadata profile, and an inode number
/// means nothing without the tree it is numbered in.
///
/// **Two pairs are missing, and the format forbids both rather than the matrix omitting
/// them.** A block-group tree requires a free-space tree and requires `no-holes`; asking for
/// it without either leaves a volume that has neither it nor a complaint about it, since the
/// baseline drops the feature with a warning and formats successfully. So
/// (`block_group_tree`, no free-space tree) and (`block_group_tree`, holes as extents) cannot
/// occur, [`the_matrix_covers_every_pair_the_format_allows`] names exactly those two as the
/// gap, and no row asks for one — which is what stops the gate from quietly testing a
/// filesystem other than the one its row describes.
#[cfg(feature = "btrfs")]
const FOREIGN_MATRIX: &[ForeignRow] = &[
    ForeignRow {
        what: "this pin's own defaults, over the smallest tree block the format allows",
        sector: 4096,
        node: NodeSize::Floor,
        metadata: Profile::Dup,
        free_space_tree: true,
        block_group_tree: true,
        no_holes: true,
        dense_links: true,
        subvolume: false,
    },
    ForeignRow {
        what: "holes as extents and block groups in the extent tree, over the largest block",
        sector: 4096,
        node: NodeSize::Ceiling,
        metadata: Profile::Single,
        free_space_tree: false,
        block_group_tree: false,
        no_holes: false,
        dense_links: false,
        subvolume: true,
    },
    ForeignRow {
        what: "a free-space tree without a block-group tree, at sixteen-kilobyte sectors",
        sector: 16384,
        node: NodeSize::Floor,
        metadata: Profile::Dup,
        free_space_tree: true,
        block_group_tree: false,
        no_holes: false,
        dense_links: false,
        subvolume: true,
    },
    ForeignRow {
        what: "one copy of every metadata block, at sixteen-kilobyte sectors",
        sector: 16384,
        node: NodeSize::Ceiling,
        metadata: Profile::Single,
        free_space_tree: true,
        block_group_tree: true,
        no_holes: true,
        dense_links: false,
        subvolume: false,
    },
    ForeignRow {
        what: "neither extra tree, at sixteen-kilobyte sectors",
        sector: 16384,
        node: NodeSize::Ceiling,
        metadata: Profile::Dup,
        free_space_tree: false,
        block_group_tree: false,
        no_holes: false,
        dense_links: true,
        subvolume: false,
    },
    ForeignRow {
        what: "sixty-four-kilobyte sectors, where the smallest node is also the largest",
        sector: 65536,
        node: NodeSize::Floor,
        metadata: Profile::Dup,
        free_space_tree: false,
        block_group_tree: false,
        no_holes: false,
        dense_links: true,
        subvolume: true,
    },
    ForeignRow {
        what: "sixty-four-kilobyte sectors carrying this pin's own feature set",
        sector: 65536,
        node: NodeSize::Floor,
        metadata: Profile::Single,
        free_space_tree: true,
        block_group_tree: true,
        no_holes: true,
        dense_links: false,
        subvolume: true,
    },
    ForeignRow {
        what: "holes as extents at the largest sector and the largest node",
        sector: 65536,
        node: NodeSize::Ceiling,
        metadata: Profile::Single,
        free_space_tree: false,
        block_group_tree: false,
        no_holes: true,
        dense_links: true,
        subvolume: false,
    },
];

/// The row the single-image gates and the negative controls run against.
///
/// The first, because it is the one a damaged byte reaches furthest in: its tree blocks are
/// the smallest the format allows, so its trees are the deepest and most numerous of any row
/// here, it carries every feature this pin turns on by itself, and its densely-linked file
/// puts several hundred names in one directory.
#[cfg(feature = "btrfs")]
const FOREIGN_REPRESENTATIVE: &ForeignRow = &FOREIGN_MATRIX[0];

/// How large each row's volume is.
///
/// Above the smallest this pin will format at either metadata profile, with room for the
/// files below, and sparse — so what it costs on disk is its metadata and its data rather than
/// its size.
#[cfg(feature = "btrfs")]
const FOREIGN_BYTES: u64 = 512 * 1024 * 1024;

/// How long the file that is stored inside its own metadata is.
///
/// Short enough to be inline at every sector size in the matrix: this baseline stores a file
/// inline where it is shorter than the volume's sector, and the smallest sector here is four
/// kilobytes.
#[cfg(feature = "btrfs")]
const INLINE_LEN: u64 = 1000;

/// How long the file the baseline splits into several extents is.
///
/// `mkfs.btrfs -r` writes a regular file in one-mebibyte extents whatever the sector size, and
/// it does not place them consecutively — so three mebibytes is three extents with a jump
/// between them, which is what makes a read from the middle of this file a statement about
/// following extent records rather than about arithmetic on one.
#[cfg(feature = "btrfs")]
const MANY_EXTENT_LEN: u64 = 3 * 1024 * 1024;

/// How far into the many-extent file the windowed read starts.
///
/// Inside the third extent, which is the one no single-extent assumption reaches.
#[cfg(feature = "btrfs")]
const DEEP_READ_AT: u64 = 2 * 1024 * 1024 + 4096;

/// The mode the attributed file carries: unusual enough that no default can pass for it.
#[cfg(feature = "btrfs")]
const ATTRIBUTED_MODE: u32 = 0o604;

/// The extended attribute that file carries, and its value.
#[cfg(feature = "btrfs")]
const XATTR_NAME: &str = "user.ferrosys";
#[cfg(feature = "btrfs")]
const XATTR_VALUE: &str = "recorded";

/// The bytes of a generated file, `len` of them from `offset`.
///
/// Every eight-byte word is a function of its own position in the file, so bytes read from the
/// wrong extent — or from the wrong file, since the seed is per file — say where they came
/// from rather than merely differing from what was expected. Multiplied through an odd
/// constant so that the high bytes of a small offset are not all zero, which is what makes a
/// window of them distinctive enough to find in an image.
#[cfg(feature = "btrfs")]
fn contents(seed: u64, offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let at = offset + i;
            let word = (at & !7).wrapping_mul(0x0100_0000_01b3).wrapping_add(seed);
            word.to_le_bytes()[(at % 8) as usize]
        })
        .collect()
}

/// The seed each generated file's contents are built from.
#[cfg(feature = "btrfs")]
mod seed {
    pub const INLINE: u64 = 0x1111_1111;
    pub const ONE_EXTENT: u64 = 0x2222_2222;
    pub const MANY_EXTENTS: u64 = 0x3333_3333;
    pub const ATTRIBUTED: u64 = 0x4444_4444;
    pub const LINK_TARGET: u64 = 0x5555_5555;
    pub const SUBVOLUME: u64 = 0x6666_6666;
}

/// One name of a densely-linked file, of exactly [`LINK_NAME_LEN`] bytes.
#[cfg(feature = "btrfs")]
fn link_name(index: usize) -> String {
    let lead = "hard-link-";
    let tail = format!("-{index:04}");
    let fill = LINK_NAME_LEN - lead.len() - tail.len();
    format!("{lead}{}{tail}", "n".repeat(fill))
}

/// The tree every row is given, before the row's own additions.
///
/// Every shape a btrfs file takes is here once: a file inside its own metadata, a file of one
/// extent, a file the baseline splits into several, a directory with something in it, a
/// directory with nothing in it, a symbolic link, a second name for a file that already has
/// one, and a file carrying an extended attribute and a mode no default produces.
#[cfg(feature = "btrfs")]
fn build_source(lab: &Lab, row: &ForeignRow) -> PathBuf {
    let root = lab.path().join(format!("source-{}", row.sector));
    let root = unique_dir(root);
    fs::create_dir_all(root.join("dir/nested")).expect("create the nested directory");
    fs::create_dir(root.join("empty")).expect("create the empty directory");
    fs::write(
        root.join("dir/inline.txt"),
        contents(seed::INLINE, 0, INLINE_LEN as usize),
    )
    .expect("write the inline file");
    fs::write(
        root.join("one-extent.bin"),
        contents(seed::ONE_EXTENT, 0, row.one_extent_len() as usize),
    )
    .expect("write the single-extent file");
    fs::write(
        root.join("many-extents.bin"),
        contents(seed::MANY_EXTENTS, 0, MANY_EXTENT_LEN as usize),
    )
    .expect("write the multi-extent file");
    std::os::unix::fs::symlink("dir/inline.txt", root.join("link")).expect("create the symlink");
    // A link naming a *directory*, which is the shape every current distribution's root
    // filesystem has and the one a resolver that stops at links cannot see past: `/bin`,
    // `/lib`, and `/sbin` are all links into `/usr` there, so a reader that could not continue
    // through one would report most of a Fedora root as missing.
    std::os::unix::fs::symlink("dir", root.join("to-dir")).expect("create the link to a directory");
    fs::hard_link(root.join("dir/inline.txt"), root.join("second-name.txt"))
        .expect("create the second name");

    let attributed = root.join("attributed.bin");
    fs::write(
        &attributed,
        contents(seed::ATTRIBUTED, 0, INLINE_LEN as usize),
    )
    .expect("write the attributed file");
    fs::set_permissions(
        &attributed,
        std::os::unix::fs::PermissionsExt::from_mode(ATTRIBUTED_MODE),
    )
    .expect("set the mode");
    let set = Command::new("setfattr")
        .args(["-n", XATTR_NAME, "-v", XATTR_VALUE])
        .arg(&attributed)
        .status()
        .expect("run setfattr");
    assert!(set.success(), "setfattr refused the source file");

    if row.dense_links {
        let links = root.join("links");
        fs::create_dir(&links).expect("create the densely-linked directory");
        let target = links.join("target.bin");
        fs::write(&target, contents(seed::LINK_TARGET, 0, INLINE_LEN as usize))
            .expect("write the link target");
        for index in 0..row.dense_link_count() {
            fs::hard_link(&target, links.join(link_name(index))).expect("create a hard link");
        }
    }

    if row.subvolume {
        let home = root.join(SUBVOLUME_DIR);
        fs::create_dir(&home).expect("create the subvolume's directory");
        fs::write(
            home.join("user.txt"),
            contents(seed::SUBVOLUME, 0, INLINE_LEN as usize),
        )
        .expect("write the file inside the subvolume");
    }
    root
}

/// A directory of `base`'s name that does not exist yet.
///
/// Two rows of the matrix can share a sector size, and a source tree built twice into one
/// place is a tree with the first row's files still in it.
#[cfg(feature = "btrfs")]
fn unique_dir(base: PathBuf) -> PathBuf {
    for suffix in 0.. {
        let candidate = base.with_file_name(format!(
            "{}-{suffix}",
            base.file_name().expect("a name").to_string_lossy()
        ));
        if fs::create_dir(&candidate).is_ok() {
            return candidate;
        }
    }
    unreachable!("the loop returns")
}

/// Every path a walk of `row`'s image must reach, sorted the way a walk's output is.
///
/// Built from the same description [`build_source`] creates the tree from, so a tree that
/// grows a file grows an expectation rather than needing one written twice.
#[cfg(feature = "btrfs")]
fn expected_paths(row: &ForeignRow) -> Vec<String> {
    let mut out = vec![
        String::new(),
        "/attributed.bin".to_string(),
        "/dir".to_string(),
        "/dir/inline.txt".to_string(),
        "/dir/nested".to_string(),
        "/empty".to_string(),
        "/link".to_string(),
        "/many-extents.bin".to_string(),
        "/one-extent.bin".to_string(),
        "/second-name.txt".to_string(),
        "/to-dir".to_string(),
    ];
    if row.dense_links {
        out.push("/links".to_string());
        out.push("/links/target.bin".to_string());
        out.extend((0..row.dense_link_count()).map(|index| format!("/links/{}", link_name(index))));
    }
    if row.subvolume {
        out.push(format!("/{SUBVOLUME_DIR}"));
        out.push(format!("/{SUBVOLUME_DIR}/user.txt"));
    }
    out.sort();
    out
}

/// Build `row`'s image, and have the foreign checker certify it before this crate reads it.
///
/// The certification is half the gate rather than a precondition of it: an image this reader
/// rejects is only a finding about the reader if something else says the image is sound, and
/// `btrfs check --check-data-csum` is the authority that says so — over the data as well as
/// the metadata, which is the one thing this family's checker does that no other family's
/// does.
#[cfg(feature = "btrfs")]
fn foreign_image(lab: &Lab, row: &ForeignRow, name: &str) -> PathBuf {
    let source = build_source(lab, row);
    let mut args = row.args();
    args.push("-r".to_string());
    args.push(source.to_str().expect("a UTF-8 scratch path").to_string());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let image = lab.formatted(name, FOREIGN_BYTES, &borrowed);
    btrfs_check_clean(&image, &["--check-data-csum"]).unwrap_or_else(|e| {
        panic!("the checker rejected the fixture for {:?}: {e}", row.what);
    });
    image
}

/// One row's values, dimension by dimension, for the coverage claim to be computed from.
#[cfg(feature = "btrfs")]
fn dimensions(row: &ForeignRow) -> Vec<(&'static str, String)> {
    vec![
        ("sector", row.sector.to_string()),
        ("node", format!("{:?}", row.node)),
        ("metadata", row.metadata.as_str().to_string()),
        ("free-space-tree", row.free_space_tree.to_string()),
        ("block-group-tree", row.block_group_tree.to_string()),
        ("no-holes", row.no_holes.to_string()),
        ("dense-links", row.dense_links.to_string()),
        ("subvolume", row.subvolume.to_string()),
    ]
}

/// The pairs of values no volume can have, because this format refuses to build one.
///
/// A block-group tree is kept current by a free-space tree and addresses extents that
/// `no-holes` guarantees the shape of, so the baseline turns it off wherever either is
/// missing. It says so and then formats successfully, which is what makes this a pair to
/// name rather than a refusal a gate would notice on its own.
#[cfg(feature = "btrfs")]
const IMPOSSIBLE_PAIRS: &[(&str, &str, &str, &str)] = &[
    ("free-space-tree", "false", "block-group-tree", "true"),
    ("block-group-tree", "true", "no-holes", "false"),
];

/// The matrix carries every pair of values the format permits, and the two it omits are the
/// two the format forbids.
///
/// A covering array is a claim, and a claim that nothing checks stops being true the moment a
/// row is edited: change one column to a value another row already has, and the dimension
/// quietly stops varying while every gate stays green. So the pairs are computed from the rows
/// and held against what is reachable — and the gap is named here rather than inferred from a
/// matrix that stops where it can afford to.
#[test]
#[cfg(feature = "btrfs")]
fn the_matrix_covers_every_pair_the_format_allows() {
    use std::collections::BTreeSet;

    let names: Vec<&'static str> = dimensions(FOREIGN_REPRESENTATIVE)
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    // What each dimension is observed taking, across the rows. Read off the matrix rather
    // than declared, so a dimension that lost a value is a dimension whose pairs go missing.
    let mut values: Vec<BTreeSet<String>> = vec![BTreeSet::new(); names.len()];
    for row in FOREIGN_MATRIX {
        for (at, (_, value)) in dimensions(row).into_iter().enumerate() {
            values[at].insert(value);
        }
    }
    for (at, name) in names.iter().enumerate() {
        assert!(
            values[at].len() >= 2,
            "the matrix has stopped varying `{name}`: every row has {:?}",
            values[at]
        );
    }

    let mut covered: BTreeSet<(usize, usize, String, String)> = BTreeSet::new();
    for row in FOREIGN_MATRIX {
        let cells = dimensions(row);
        for left in 0..cells.len() {
            for right in (left + 1)..cells.len() {
                covered.insert((left, right, cells[left].1.clone(), cells[right].1.clone()));
            }
        }
    }

    let mut missing: Vec<String> = Vec::new();
    for left in 0..names.len() {
        for right in (left + 1)..names.len() {
            for one in &values[left] {
                for other in &values[right] {
                    let pair = (left, right, one.clone(), other.clone());
                    if covered.contains(&pair) {
                        continue;
                    }
                    let impossible = IMPOSSIBLE_PAIRS.iter().any(|(a, av, b, bv)| {
                        (names[left] == *a && one == av && names[right] == *b && other == bv)
                            || (names[left] == *b && one == bv && names[right] == *a && other == av)
                    });
                    if !impossible {
                        missing.push(format!(
                            "{}={one} with {}={other}",
                            names[left], names[right]
                        ));
                    }
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the matrix claims to cover every pair the format allows and does not reach: {missing:#?}"
    );

    // And the other direction: a pair named impossible that some row carries is a note about
    // the format that has stopped being true, which is worse than an uncovered pair because
    // it reads as an explanation.
    for (a, av, b, bv) in IMPOSSIBLE_PAIRS {
        let left = names
            .iter()
            .position(|n| n == a)
            .expect("a named dimension");
        let right = names
            .iter()
            .position(|n| n == b)
            .expect("a named dimension");
        let (left, right, one, other) = if left < right {
            (left, right, (*av).to_string(), (*bv).to_string())
        } else {
            (right, left, (*bv).to_string(), (*av).to_string())
        };
        assert!(
            !covered.contains(&(left, right, one, other)),
            "{a}={av} with {b}={bv} is named as a pair the format forbids, and a row has it"
        );
    }
}

/// Every row of the matrix is the filesystem its row says it is.
///
/// A matrix whose rows are read out of the row rather than out of the image is a matrix that
/// tests whatever the baseline felt like producing. Two of these columns are why: asking for a
/// block-group tree without the features it rests on gets a volume without one and a warning
/// on the standard error, and asking for more names than a record holds gets the wide form
/// only where the node size makes it necessary — so a row that stopped reaching what it
/// describes would go on passing every gate below while covering less.
///
/// Read through the tier's own open-coded accessors and the baseline's own renderings, never
/// through this crate: what is being established is that the image is what the row says, and
/// an image described by the thing under test describes nothing.
#[test]
#[cfg(feature = "btrfs")]
fn every_row_of_the_foreign_matrix_is_the_filesystem_it_claims_to_be() {
    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    for (at, row) in FOREIGN_MATRIX.iter().enumerate() {
        let what = row.what;
        let image = foreign_image(&lab, row, &format!("claims-{at}.img"));
        let sb = primary(&image);

        assert_eq!(
            u32_at(&sb, sb::SECTORSIZE),
            row.sector,
            "{what}: the sector size the row asked for"
        );
        assert_eq!(
            u32_at(&sb, sb::NODESIZE),
            row.node_bytes(),
            "{what}: the node size the row asked for"
        );
        assert_eq!(
            u64_at(&sb, sb::COMPAT_RO_FLAGS),
            row.compat_ro(),
            "{what}: the read-only-compatible features the row asked for"
        );
        assert_eq!(
            u64_at(&sb, sb::INCOMPAT_FLAGS),
            row.incompat(),
            "{what}: the incompatible features the row asked for"
        );

        // How many copies of a metadata block there are is a property of the chunk that holds
        // them, which is where the baseline's own rendering says it.
        let chunks = inspect(&image, &["dump-tree", "-t", "chunk"]);
        let profile = format!("type METADATA|{}", row.metadata.rendered());
        assert!(
            chunks.contains(&profile),
            "{what}: the chunk tree records `{profile}`:\n{chunks}"
        );

        // The wide form of a name record appears exactly where the row says the names outgrew
        // the narrow one, and nowhere else.
        let fs_tree = inspect(&image, &["dump-tree", "-t", "fs"]);
        assert_eq!(
            fs_tree.contains("INODE_EXTREF"),
            row.dense_links,
            "{what}: {} names for one file in one directory {} the record they share",
            row.dense_link_count(),
            if row.dense_links {
                "overflowed"
            } else {
                "did not overflow"
            }
        );

        // And a subvolume row has a second tree, linked to the directory it hangs under.
        let root_tree = inspect(&image, &["dump-tree", "-t", "root"]);
        assert_eq!(
            root_tree.contains("ROOT_BACKREF"),
            row.subvolume,
            "{what}: a second filesystem tree, linked where the row put it:\n{root_tree}"
        );
    }
}

/// This crate reads out of every row of the matrix exactly the tree that went into it.
///
/// The half of the gate that is about *contents*. Every name, every shape a file's bytes take,
/// the target of a link, the second name for a file that has one, the mode and the extended
/// attribute, and — where the row has one — the tree on the other side of a subvolume
/// boundary.
///
/// Each generated file's bytes say where in that file they came from, so a read served out of
/// the wrong extent or out of the neighbouring file fails on what it returned rather than on a
/// length.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_reads_back_every_row_of_the_foreign_matrix() {
    use ferrosys::btrfs::Reader;

    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    for (at, row) in FOREIGN_MATRIX.iter().enumerate() {
        let what = row.what;
        let image = foreign_image(&lab, row, &format!("read-{at}.img"));
        let mut reader =
            Reader::open(File::open(&image).expect("open the image")).expect("open the filesystem");

        let reached: Vec<String> = reader
            .walk()
            .unwrap_or_else(|e| panic!("{what}: walk it: {e}"))
            .into_iter()
            .map(|entry| String::from_utf8_lossy(&entry.path).into_owned())
            .collect();
        let mut sorted = reached.clone();
        sorted.sort();
        assert_eq!(sorted, expected_paths(row), "{what}: the names in the tree");

        // A file stored inside its own metadata, one stored in a single extent, and one the
        // baseline split into three — the three shapes a btrfs file's bytes take.
        let inline = reader.lookup(b"/dir/inline.txt").expect("the inline file");
        assert_eq!(
            reader.read_data(&inline).expect("its bytes"),
            contents(seed::INLINE, 0, INLINE_LEN as usize),
            "{what}: the bytes of the file stored inside its own metadata"
        );
        let one = reader
            .lookup(b"/one-extent.bin")
            .expect("the one-extent file");
        assert_eq!(
            reader.read_data(&one).expect("its bytes"),
            contents(seed::ONE_EXTENT, 0, row.one_extent_len() as usize),
            "{what}: the bytes of the single-extent file"
        );
        let many = reader
            .lookup(b"/many-extents.bin")
            .expect("the many-extent file");
        assert_eq!(
            reader.read_data(&many).expect("its bytes"),
            contents(seed::MANY_EXTENTS, 0, MANY_EXTENT_LEN as usize),
            "{what}: the bytes of the multi-extent file"
        );

        // From the middle of the third extent, which is the read a search for the record at or
        // after a position cannot serve: the record covering a position begins before it.
        let mut window = [0u8; 64];
        reader
            .read_into(&many, DEEP_READ_AT, &mut window)
            .unwrap_or_else(|e| panic!("{what}: a read from inside the third extent: {e}"));
        assert_eq!(
            window.as_slice(),
            contents(seed::MANY_EXTENTS, DEEP_READ_AT, window.len()).as_slice(),
            "{what}: the bytes at {DEEP_READ_AT} of the multi-extent file"
        );

        let link = reader
            .lookup_no_follow(b"/link")
            .expect("the symbolic link");
        assert!(link.is_symlink(), "{what}: the link is one");
        assert_eq!(
            reader.link_target(&link).expect("its target"),
            b"dir/inline.txt",
            "{what}: the link's target, reproduced as it stands"
        );
        // And the same path resolved rather than read reaches what the link names.
        let followed = reader.lookup(b"/link").expect("resolving through the link");
        assert_eq!(
            (followed.tree, followed.inode),
            (inline.tree, inline.inode),
            "{what}: following the link reaches the file it names"
        );
        // A path continuing *through* a link to a directory, which is how a distribution's root
        // filesystem is laid out and the case a resolver that stops at a link cannot serve.
        let across = reader
            .lookup(b"/to-dir/inline.txt")
            .expect("a path through a link to a directory");
        assert_eq!(
            (across.tree, across.inode),
            (inline.tree, inline.inode),
            "{what}: the path through the linked directory reaches the same file"
        );

        // Two names for one file are one inode, which is a property of the inode rather than of
        // either name.
        let second = reader.lookup(b"/second-name.txt").expect("the second name");
        assert_eq!(
            (second.tree, second.inode),
            (inline.tree, inline.inode),
            "{what}: both names reach one inode"
        );
        assert_eq!(
            second.item.nlink, 2,
            "{what}: and the inode says there are two"
        );

        // The mode and the extended attribute, which are what make this a POSIX tree rather
        // than a set of byte streams.
        let attributed = reader
            .lookup(b"/attributed.bin")
            .expect("the attributed file");
        assert_eq!(
            attributed.item.mode & 0o7777,
            ATTRIBUTED_MODE,
            "{what}: the mode the source file carried"
        );
        assert_eq!(
            attributed.item.uid,
            nix_uid(),
            "{what}: the owner the source tree had"
        );
        let xattrs = reader.xattrs(&attributed).expect("its attributes");
        assert_eq!(
            xattrs
                .iter()
                .map(|x| (
                    String::from_utf8_lossy(&x.name).into_owned(),
                    String::from_utf8_lossy(&x.value).into_owned()
                ))
                .collect::<Vec<_>>(),
            vec![(XATTR_NAME.to_string(), XATTR_VALUE.to_string())],
            "{what}: the extended attribute, name and value"
        );

        if row.dense_links {
            let target = reader
                .lookup(b"/links/target.bin")
                .expect("the densely-linked file");
            let names = row.dense_link_count();
            assert_eq!(
                target.item.nlink as usize,
                names + 1,
                "{what}: every name the file was given, plus the one it was created under"
            );
            // Each name reaches the same inode. The point of the row is that the names do not
            // fit in one record, so a reader that read only the first record would resolve the
            // early names and fail on the rest.
            for index in 0..names {
                let path = format!("/links/{}", link_name(index));
                let found = reader
                    .lookup(path.as_bytes())
                    .unwrap_or_else(|e| panic!("{what}: {path}: {e}"));
                assert_eq!(
                    (found.tree, found.inode),
                    (target.tree, target.inode),
                    "{what}: {path} names the file every other name names"
                );
            }
        }

        if row.subvolume {
            let subvolumes = reader.subvolumes();
            assert_eq!(
                subvolumes.len(),
                2,
                "{what}: the top-level tree and the one the row asked for: {subvolumes:?}"
            );
            let named: Vec<String> = subvolumes
                .iter()
                .map(|s| String::from_utf8_lossy(&s.name).into_owned())
                .collect();
            assert!(
                named.iter().any(|n| n == SUBVOLUME_DIR),
                "{what}: the subvolume appears under the name it was given: {named:?}"
            );
            let inside = reader
                .lookup(format!("/{SUBVOLUME_DIR}/user.txt").as_bytes())
                .expect("the file inside the subvolume");
            assert_ne!(
                inside.tree, inline.tree,
                "{what}: a file inside the subvolume is numbered in the subvolume's own tree"
            );
            assert_eq!(
                reader.read_data(&inside).expect("its bytes"),
                contents(seed::SUBVOLUME, 0, INLINE_LEN as usize),
                "{what}: the bytes of the file inside the subvolume"
            );
        }
    }
}

/// This crate finds nothing wrong with any row of the matrix, and says so about the data as
/// well as the metadata.
///
/// The other half of the gate, and it is not implied by the first: a reader can enumerate a
/// tree perfectly and still be handing back bytes the filesystem's own checksums do not cover.
/// `verify_data` is this family's answer to that and it has no analogue in the others — it
/// reads every byte of every file and holds it against the checksum tree, which is the check
/// `btrfs check` makes only when asked and no other family here can make at all.
#[test]
#[cfg(feature = "btrfs")]
fn the_reader_finds_nothing_wrong_with_any_row_of_the_foreign_matrix() {
    use ferrosys::btrfs::Reader;

    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    for (at, row) in FOREIGN_MATRIX.iter().enumerate() {
        let what = row.what;
        let image = foreign_image(&lab, row, &format!("scan-{at}.img"));
        let mut reader =
            Reader::open(File::open(&image).expect("open the image")).expect("open the filesystem");

        let report = reader.scan();
        assert!(
            report.is_clean(),
            "{what}: a filesystem the checker calls healthy: {:?}",
            report.anomalies()
        );

        let tree = reader
            .walk()
            .unwrap_or_else(|e| panic!("{what}: walk it: {e}"))
            .into_iter()
            .map(|entry| {
                (
                    String::from_utf8_lossy(&entry.path).into_owned(),
                    entry.node,
                )
            })
            .collect::<Vec<_>>();
        for (path, node) in &tree {
            reader
                .verify_data(node)
                .unwrap_or_else(|e| panic!("{what}: {path}: {e}"));
        }
    }
}

/// Every row is classified and opened through the crate root, which is the surface a consumer
/// that does not name a family reaches.
///
/// A family reachable only through its own module is a family a caller has to have decided on
/// before opening the image, which is the opposite of what classification is for.
#[test]
#[cfg(feature = "btrfs")]
fn the_root_reaches_every_row_of_the_foreign_matrix() {
    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    for (at, row) in FOREIGN_MATRIX.iter().enumerate() {
        let what = row.what;
        let image = foreign_image(&lab, row, &format!("root-{at}.img"));

        let found = ferrosys::detect(File::open(&image).expect("open the image"));
        assert_eq!(
            found.ok(),
            Some(ferrosys::Filesystem::Btrfs),
            "{what}: classified from its own bytes"
        );

        let opened =
            ferrosys::open(File::open(&image).expect("open the image")).expect("open through root");
        assert!(
            matches!(opened, ferrosys::FsReader::Btrfs(_)),
            "{what}: the root hands back this family's reader"
        );
    }
}

// ---------------------------------------------------------------------------
// What the foreign gate would notice
//
// The gates above pass, which is a claim about this reader only to the degree that they could
// have failed. Each control below is a defect class a reader can plausibly have — bytes that
// were altered under it, bytes that belong to another file, and bytes nothing vouches for —
// applied to the representative row and observed being caught, by the gate that catches it and
// not by the ones that do not.
//
// Two of the three also say something about the oracles, and both are worth having in writing:
// the checker's data pass compares the checksums that are there and does not notice one that
// is gone, and no checker here objects to a file whose bytes verify perfectly and belong to
// something else. Where an oracle is silent, this crate's own check is the only gate, and a
// control is how that stops being an assumption.

/// The length the baseline splits a regular file into, whatever the sector size.
#[cfg(feature = "btrfs")]
const MANY_EXTENT_SPLIT: u64 = 1024 * 1024;

/// The inode `name` has in the image's top-level filesystem tree.
///
/// Read out of the baseline's own rendering rather than through this crate: a control that
/// aims its damage with the thing under test damages whatever that thing believes, which is
/// the one place it must not be consulted. `dump-tree` prints a directory entry's target ahead
/// of its name, so the entry is found by its name and the inode is the last target named
/// before it.
#[cfg(feature = "btrfs")]
fn inode_of(image: &Path, name: &str) -> u64 {
    let dump = inspect(image, &["dump-tree", "-t", "fs"]);
    let mut latest = None;
    for line in dump.lines() {
        if let Some(rest) = line.trim().strip_prefix("location key (")
            && let Some((objectid, kind)) = rest.split_once(' ')
            && kind.starts_with("INODE_ITEM")
        {
            latest = objectid.parse::<u64>().ok();
        }
        if line.trim() == format!("name: {name}") {
            return latest.unwrap_or_else(|| panic!("{name} has an entry with no target:\n{dump}"));
        }
    }
    panic!("no entry named {name}:\n{dump}")
}

/// A file whose bytes were altered under the filesystem is caught by the data check and by
/// nothing else.
///
/// The one corruption class in this family with no analogue anywhere else in this project, and
/// the reader's half of it. What makes it a control rather than a repeat of the tier's is
/// which gate does the catching: a scan reads metadata, so a scan of this image is *clean* and
/// says so honestly, and the file still reads back — with the byte that was changed. Only
/// verifying the data against what the filesystem recorded for it refuses.
#[test]
#[cfg(feature = "btrfs")]
fn altered_bytes_under_a_foreign_image_are_caught_by_verifying_and_not_by_scanning() {
    use ferrosys::btrfs::{ReadError, Reader};

    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    let healthy = foreign_image(&lab, FOREIGN_REPRESENTATIVE, "altered-healthy.img");

    // Located by searching for the file's own bytes, which say which offset of which file they
    // are — so the damage lands where the assertion below expects it without translating a
    // logical address, and without assuming the single-device mapping is the identity.
    let damaged = copy_of(&lab, &healthy, "altered.img");
    let marker = contents(seed::MANY_EXTENTS, DEEP_READ_AT, 32);
    let image_bytes = fs::read(&damaged).expect("read the image");
    let at = image_bytes
        .windows(marker.len())
        .position(|window| window == marker.as_slice())
        .expect("the multi-extent file's own bytes are somewhere in the image");
    flip_byte(&damaged, at as u64);

    // The oracle's verdict, so that what follows is about a filesystem one authority calls
    // sound and another calls damaged rather than about an image nobody vouches for.
    btrfs_check_clean(&damaged, &[]).expect("the metadata gate accepts it: no tree changed");
    btrfs_check_clean(&damaged, &["--check-data-csum"])
        .expect_err("the data gate refuses it, which is what makes this a control");

    let mut reader =
        Reader::open(File::open(&damaged).expect("open the image")).expect("open the filesystem");
    let node = reader
        .lookup(b"/many-extents.bin")
        .expect("the multi-extent file");

    let report = reader.scan();
    assert!(
        report.is_clean(),
        "a scan reads metadata, and no metadata changed: {:?}",
        report.anomalies()
    );

    let read_back = reader.read_data(&node).expect("the file still reads");
    assert_ne!(
        read_back,
        contents(seed::MANY_EXTENTS, 0, MANY_EXTENT_LEN as usize),
        "the altered byte comes back, which is what a reader that verifies nothing hands over"
    );

    let refusal = reader.verify_data(&node);
    assert!(
        matches!(refusal, Err(ReadError::DataChecksum { .. })),
        "verifying the file against what the filesystem recorded for it: {refusal:?}"
    );
}

/// A file extent pointed at another file's bytes is caught by reading the file, and by no
/// checksum at all.
///
/// The defect class the generated fixtures exist for. A checksum covers the bytes **on the
/// volume**, so an extent record aimed at some other correctly-checksummed extent produces a
/// filesystem where every byte verifies and one file's contents are somebody else's: this
/// crate's data verification passes, and the checker objects only through a backref count that
/// has nothing to do with the bytes. What catches it is comparing what came back against what
/// went in — which is why every byte of these fixtures is a function of its own position, and
/// why the matrix asserts contents rather than lengths.
#[test]
#[cfg(feature = "btrfs")]
fn a_file_extent_aimed_at_other_bytes_is_caught_by_what_comes_back_and_by_no_checksum() {
    use ferrosys::btrfs::Reader;

    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    let healthy = foreign_image(&lab, FOREIGN_REPRESENTATIVE, "aimed-healthy.img");

    let inode = inode_of(&healthy, "many-extents.bin");
    let elsewhere = first_data_extent(&healthy);
    let damaged = copy_of(&lab, &healthy, "aimed.img");
    corrupt(
        &damaged,
        &[
            "-i",
            &inode.to_string(),
            "-x",
            &(2 * MANY_EXTENT_SPLIT).to_string(),
            "-f",
            "disk_bytenr",
            "--value",
            &elsewhere.to_string(),
        ],
    );
    // The value is named rather than left to the tool. Without one it writes a number from an
    // unseeded source, which damages a different filesystem every run — and a control that is
    // not the same twice is worse than none, because it passes most of the time.
    btrfs_check_clean(&damaged, &["--check-data-csum"])
        .expect_err("the checker refuses it, on the backref rather than on any checksum");

    let mut reader =
        Reader::open(File::open(&damaged).expect("open the image")).expect("open the filesystem");
    let node = reader
        .lookup(b"/many-extents.bin")
        .expect("the multi-extent file");

    let mut window = [0u8; 64];
    reader
        .read_into(&node, DEEP_READ_AT, &mut window)
        .expect("the file still reads");
    assert_ne!(
        window.as_slice(),
        contents(seed::MANY_EXTENTS, DEEP_READ_AT, window.len()).as_slice(),
        "bytes from elsewhere came back, which the matrix's comparison is what notices"
    );

    reader
        .verify_data(&node)
        .expect("and every one of them verifies, because a checksum covers bytes and not owners");
}

/// A data checksum that is gone is reported here and by no oracle in the suite.
///
/// The checker's data pass compares the checksums it finds against the bytes they cover, so a
/// checksum that has been removed is nothing for it to compare and the filesystem is clean to
/// it. That leaves a file whose bytes nothing vouches for, which is the state a reader must
/// not report as verified — so this crate refuses instead, and this is the gate that says the
/// suite would not have caught it.
#[test]
#[cfg(feature = "btrfs")]
fn a_missing_data_checksum_is_reported_here_and_accepted_by_the_checker() {
    use ferrosys::btrfs::{ReadError, Reader};

    if !suite_ready() || !available("setfattr") {
        return;
    }
    let lab = Lab::new();
    let healthy = foreign_image(&lab, FOREIGN_REPRESENTATIVE, "unvouched-healthy.img");

    let damaged = copy_of(&lab, &healthy, "unvouched.img");
    let extent = first_data_extent(&healthy);
    corrupt(&damaged, &["-C", &extent.to_string()]);

    btrfs_check_clean(&damaged, &["--check-data-csum"]).expect(
        "the checker accepts a filesystem with a checksum missing, which is the finding: its \
         data pass compares what is recorded and says nothing about what is not",
    );

    let mut reader =
        Reader::open(File::open(&damaged).expect("open the image")).expect("open the filesystem");
    let tree = reader.walk().expect("walk it");
    let refusals: Vec<ReadError> = tree
        .iter()
        .filter_map(|entry| reader.verify_data(&entry.node).err())
        .collect();
    assert!(
        refusals
            .iter()
            .any(|e| matches!(e, ReadError::MissingDataChecksum { .. })),
        "a run with no record is a run that did not verify: {refusals:?}"
    );
}

// ---------------------------------------------------------------------------
// The planner, held against the layout the baseline arrives at
//
// The planner is a pure function and its whole claim is that it decides, before a byte is
// written, exactly what the format's own tooling decides while writing. That claim is only
// worth anything against real images, so every gate below formats one, reads the chunk tree out
// of the baseline's own rendering of it, and holds the planned layout against what is there —
// chunk for chunk, copy for copy.
//
// The comparison runs against `dump-tree`'s text rather than against this crate's parser on
// purpose. A differential that reads the baseline's image through the reader this crate ships
// would agree with itself wherever the two share a misunderstanding; the baseline's own words
// about its own image share nothing with either.

/// One chunk as the baseline renders it: where it begins in logical space, how long it is,
/// what it holds and how it is replicated, and where each copy sits on the device.
#[cfg(feature = "btrfs")]
#[derive(PartialEq, Eq, Debug)]
struct ObservedChunk {
    logical: u64,
    length: u64,
    kind: String,
    copies: Vec<u64>,
}

/// Every chunk of `image`, in ascending logical order, read out of `dump-tree`.
#[cfg(feature = "btrfs")]
fn observed_chunks(image: &Path) -> Vec<ObservedChunk> {
    let dump = inspect(image, &["dump-tree", "-t", "chunk"]);
    let mut chunks: Vec<ObservedChunk> = Vec::new();
    for line in dump.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            // `item 1 key (FIRST_CHUNK_TREE CHUNK_ITEM 13631488) itemoff ... itemsize ...`
            [
                "item",
                _,
                "key",
                "(FIRST_CHUNK_TREE",
                "CHUNK_ITEM",
                logical,
                ..,
            ] => {
                let logical = logical
                    .trim_end_matches(')')
                    .parse()
                    .expect("a chunk key's offset is its logical address");
                chunks.push(ObservedChunk {
                    logical,
                    length: 0,
                    kind: String::new(),
                    copies: Vec::new(),
                });
            }
            // `length 8388608 owner 2 stripe_len 65536 type DATA|single`
            ["length", length, "owner", _, "stripe_len", _, "type", kind] => {
                let chunk = chunks.last_mut().expect("a length follows a chunk key");
                chunk.length = length.parse().expect("a chunk length");
                chunk.kind = (*kind).to_owned();
            }
            // `stripe 0 devid 1 offset 13631488`
            ["stripe", _, "devid", _, "offset", offset] => {
                let chunk = chunks.last_mut().expect("a stripe follows a chunk key");
                chunk.copies.push(offset.parse().expect("a stripe offset"));
            }
            _ => {}
        }
    }
    chunks.sort_by_key(|chunk| chunk.logical);
    assert!(
        !chunks.is_empty(),
        "no chunk was read out of {image:?} — the rendering this gate parses has changed"
    );
    chunks
}

/// How the baseline spells a planned chunk's contents and replication, so the two are
/// comparable as text.
#[cfg(feature = "btrfs")]
fn spell(chunk: &ferrosys::btrfs::MappedChunk) -> String {
    use ferrosys::btrfs::ondisk::BlockGroupFlags;

    let kind = if chunk.flags.contains(BlockGroupFlags::DATA) {
        "DATA"
    } else if chunk.flags.contains(BlockGroupFlags::METADATA) {
        "METADATA"
    } else {
        "SYSTEM"
    };
    // The baseline spells the unreplicated profile in lower case and every other one in upper,
    // and the spelling is open-coded here rather than taken from this crate for the reason the
    // whole tier is: an expectation read out of the code under test agrees with it by
    // construction.
    let profile = if chunk.flags.contains(BlockGroupFlags::DUP) {
        "DUP"
    } else {
        "single"
    };
    format!("{kind}|{profile}")
}

/// The parameter set the planner is held against.
///
/// A covering array rather than a cross product: every profile pairing appears, every sector
/// and node size appears, the volume length runs from the smallest the profiles admit to a
/// quarter of a terabyte, and the two feature switches that change which trees exist appear —
/// but the rows are eleven rather than the several hundred crossing them would be. The volume
/// length crosses the fifty-gibibyte threshold in both directions, since that is where a
/// replicated metadata chunk's ceiling steps.
///
/// Every row names its sector size. A row that took the default would be testing a different
/// filesystem on each of this project's two runners, the baseline's default being the page size
/// of the machine it runs on.
#[cfg(feature = "btrfs")]
const PLANNER_MATRIX: &[(&str, u64, &[&str])] = &[
    (
        "the defaults at the smallest volume that takes them",
        109 << 20,
        &["-s", "4096"],
    ),
    ("the defaults", 1 << 30, &["-s", "4096"]),
    (
        "one copy of everything, at its own smallest volume",
        45 << 20,
        &["-s", "4096", "-m", "single", "-d", "single"],
    ),
    (
        "one copy of everything, large",
        17 << 30,
        &["-s", "4096", "-m", "single", "-d", "single"],
    ),
    (
        "replicated data",
        229 << 20,
        &["-s", "4096", "-m", "dup", "-d", "dup"],
    ),
    (
        "replicated data, unreplicated metadata",
        165 << 20,
        &["-s", "4096", "-m", "single", "-d", "dup"],
    ),
    (
        "four kilobyte blocks throughout",
        1 << 30,
        &["-s", "4096", "-n", "4096"],
    ),
    (
        "sixty-four kilobyte blocks throughout",
        8 << 30,
        &["-s", "65536", "-n", "65536"],
    ),
    (
        "at the threshold a metadata chunk's ceiling steps at",
        50 << 30,
        &["-s", "4096"],
    ),
    ("past that threshold", 64 << 30, &["-s", "4096"]),
    (
        "block groups in the extent tree, a quarter of a terabyte",
        256 << 30,
        &["-s", "4096", "-O", "^block-group-tree"],
    ),
];

/// Build the request that describes what a row asked the baseline for.
#[cfg(feature = "btrfs")]
fn request_for(bytes: u64, args: &[&str]) -> ferrosys::btrfs::PlanRequest {
    use ferrosys::btrfs::ondisk::CompatRoFlags;
    use ferrosys::btrfs::{
        DEFAULT_COMPAT_RO, DEFAULT_INCOMPAT, NodeSize, PlanRequest, Profile, SectorSize,
    };

    let value_after = |flag: &str| -> Option<&str> {
        args.iter()
            .position(|arg| *arg == flag)
            .and_then(|at| args.get(at + 1))
            .copied()
    };
    let profile = |flag: &str| match value_after(flag) {
        Some("dup") => Profile::Dup,
        Some("single") => Profile::Single,
        // What the baseline picks where a row names nothing, measured in the oracle tier: data
        // is unreplicated and metadata is replicated on a single device.
        None | Some(_) => {
            if flag == "-d" {
                Profile::Single
            } else {
                Profile::Dup
            }
        }
    };
    let sector: u32 = value_after("-s")
        .expect("every row names its sector size")
        .parse()
        .expect("a sector size");
    // What `-O` removes. The baseline drops `block-group-tree` along with `free-space-tree`
    // rather than refusing the pair — a silent drop this crate's planner refuses — so a row asking
    // for the second describes a filesystem carrying neither, and the request has to say so or
    // it describes a filesystem the baseline did not write.
    let mut compat_ro = DEFAULT_COMPAT_RO;
    if args.contains(&"^block-group-tree") {
        compat_ro = compat_ro.without(CompatRoFlags::BLOCK_GROUP_TREE);
    }
    if args.contains(&"^free-space-tree") {
        compat_ro = CompatRoFlags::NONE;
    }

    let mut request = PlanRequest::new(bytes)
        .sector_size(SectorSize::Bytes(sector))
        .metadata_profile(profile("-m"))
        .data_profile(profile("-d"))
        .features(DEFAULT_INCOMPAT, compat_ro);
    if let Some(node) = value_after("-n") {
        request = request.node_size(NodeSize::Bytes(node.parse().expect("a node size")));
    }
    request
}

/// The planner puts every chunk where the baseline puts it, at every row of the matrix.
///
/// This is the planner tier's whole claim, and it is checked in both address spaces at once: a
/// chunk's logical address advances by its length and its copies advance by its length times
/// their number, so a layout that got the replication right and the arithmetic wrong agrees on
/// one space and not the other.
#[test]
#[cfg(feature = "btrfs")]
fn the_planner_puts_every_chunk_where_the_baseline_puts_it() {
    use ferrosys::btrfs::plan_layout;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, bytes, args) in PLANNER_MATRIX {
        let image = lab.formatted(&format!("plan-{what}.img").replace(' ', "-"), *bytes, args);
        let observed = observed_chunks(&image);

        let layout = plan_layout(&request_for(*bytes, args)).unwrap_or_else(|e| {
            panic!("{what}: the planner refused a volume the baseline took: {e}")
        });

        let planned: Vec<ObservedChunk> = layout
            .chunks
            .iter()
            .map(|chunk| ObservedChunk {
                logical: chunk.logical,
                length: chunk.length,
                kind: spell(chunk),
                copies: chunk.copies.clone(),
            })
            .collect();
        assert_eq!(planned, observed, "{what}: a volume of {bytes} bytes");
    }
}

/// What the planner says the device will have allocated is what the baseline's device record
/// says it did.
///
/// A separate gate from the placement above because it is a separate mistake: a layout can put
/// every chunk in the right place and still misreport what the whole of it consumed, the
/// replicated chunks being the ones that count twice.
#[test]
#[cfg(feature = "btrfs")]
fn the_planner_accounts_for_the_device_the_way_the_baseline_records_it() {
    use ferrosys::btrfs::plan_layout;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, bytes, args) in PLANNER_MATRIX {
        let image = lab.formatted(&format!("used-{what}.img").replace(' ', "-"), *bytes, args);
        let dump = inspect(&image, &["dump-tree", "-t", "chunk"]);
        let recorded: u64 = dump
            .lines()
            .find_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                match words.as_slice() {
                    ["devid", _, "total_bytes", _, "bytes_used", used] => used.parse().ok(),
                    _ => None,
                }
            })
            .expect("the device record names the bytes it has allocated");

        let layout = plan_layout(&request_for(*bytes, args)).expect("the baseline took it");
        assert_eq!(layout.device_bytes_used(), recorded, "{what}");
    }
}

/// The volume the planner refuses is the volume the baseline refuses, to the byte.
///
/// Both numbers come from the same conservative reckoning — every chunk laid down on the way to
/// the finished filesystem, each at the largest length its rule can produce — so agreeing at the
/// boundary is evidence the reckoning is the same one rather than two that happen to be close.
#[test]
#[cfg(feature = "btrfs")]
fn the_planner_refuses_the_volume_the_baseline_refuses() {
    use ferrosys::btrfs::{PlanRequest, Profile, SectorSize, minimum_volume_bytes, plan_layout};

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (metadata, data, flags) in [
        (Profile::Single, Profile::Single, ["single", "single"]),
        (Profile::Dup, Profile::Single, ["dup", "single"]),
        (Profile::Single, Profile::Dup, ["single", "dup"]),
        (Profile::Dup, Profile::Dup, ["dup", "dup"]),
    ] {
        let minimum = minimum_volume_bytes(metadata, data);
        let args = &["-s", "4096", "-m", flags[0], "-d", flags[1]];
        let name = format!("min-{}-{}", flags[0], flags[1]);

        let ok = lab.sparse(&format!("{name}-at.img"), minimum);
        mkfs(&ok, args);
        assert!(
            plan_layout(
                &PlanRequest::new(minimum)
                    .sector_size(SectorSize::Bytes(4096))
                    .metadata_profile(metadata)
                    .data_profile(data)
            )
            .is_ok(),
            "{name}: the baseline formats {minimum} bytes and the planner would not"
        );

        let short = lab.sparse(&format!("{name}-below.img"), minimum - 1);
        mkfs_refuses(&short, args);
        assert!(
            plan_layout(
                &PlanRequest::new(minimum - 1)
                    .sector_size(SectorSize::Bytes(4096))
                    .metadata_profile(metadata)
                    .data_profile(data)
            )
            .is_err(),
            "{name}: the baseline refuses {} bytes and the planner would not",
            minimum - 1
        );
    }
}

/// The feature words the planner derives are the words the baseline writes.
///
/// The one that has to be derived rather than requested is the wide-block bit: the format sets
/// it exactly where a tree block exceeds the four kibibytes it was originally fixed at, so a
/// word written per request would be wrong on the one node size where the bit does not belong
/// and right by transcription everywhere else.
#[test]
#[cfg(feature = "btrfs")]
fn the_planner_derives_the_feature_words_the_baseline_writes() {
    use ferrosys::btrfs::plan_layout;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, node) in [("wide blocks", 16384u32), ("four kilobyte blocks", 4096)] {
        let args = &["-s", "4096", "-n", &node.to_string()[..]];
        let image = lab.formatted(&format!("features-{node}.img"), 1 << 30, args);
        let primary = primary(&image);

        let layout = plan_layout(&request_for(1 << 30, args)).expect("a gibibyte is formattable");
        assert_eq!(
            layout.incompat_flags.bits(),
            u64_at(&primary, sb::INCOMPAT_FLAGS),
            "{what}: the incompatible feature word"
        );
        assert_eq!(
            layout.compat_ro_flags.bits(),
            u64_at(&primary, sb::COMPAT_RO_FLAGS),
            "{what}: the read-only-compatible feature word"
        );
    }
}

/// Every superblock copy the planner lays out is one the baseline wrote, and there are as many.
///
/// The reader already asserts this rule from its own side over a sparse device; this is the
/// other side of the same rule, over images a formatter actually wrote, and the two together
/// are what stop a writer and a reader from disagreeing about which absences are ordinary.
#[test]
#[cfg(feature = "btrfs")]
fn the_planner_lays_out_the_superblock_copies_the_baseline_writes() {
    use ferrosys::btrfs::plan_layout;

    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    // A volume below the second location, one just past it, and one past the third: the counts
    // are one, two, and three, and the smallest is below what replicated metadata fits in.
    for (bytes, args) in [
        (
            60 << 20,
            &["-s", "4096", "-m", "single", "-d", "single"][..],
        ),
        (1 << 30, &["-s", "4096"][..]),
        ((256 << 30) + 4096, &["-s", "4096"][..]),
    ] {
        let image = lab.formatted(&format!("mirrors-{bytes}.img"), bytes, args);
        let layout = plan_layout(&request_for(bytes, args)).expect("the baseline took it");
        let written: Vec<u64> = MIRRORS
            .iter()
            .copied()
            .filter(|&at| has_mirror(&image, at))
            .collect();
        assert_eq!(
            layout.superblock_mirrors, written,
            "a volume of {bytes} bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// The empty-filesystem materializer
//
// The planner's gates above say the layout is the baseline's. These say the *bytes* are a
// filesystem: the pinned checker accepts every one of them, and every record this crate writes
// is the record the baseline writes.
//
// The comparison runs against `dump-tree`'s text for the reason the planner's does — a
// differential read through the reader this crate ships would agree with itself wherever the two
// share a misunderstanding — and it is exact except where a divergence is named below.

/// What a format is asked for, so that nothing in an image comes from a clock or a random
/// source. Each identifier holds a distinct value, so a field written out of the wrong one is
/// visible rather than a coincidence of zeros.
#[cfg(feature = "btrfs")]
fn writer_options() -> ferrosys::btrfs::FormatOptions {
    ferrosys::btrfs::FormatOptions::new(
        [0x11; 16],
        ferrosys::Timestamp {
            secs: 1_786_472_859,
            nanos: 0,
        },
    )
    .chunk_tree_uuid([0x22; 16])
    .device_uuid([0x33; 16])
    .subvolume_uuid([0x44; 16])
}

/// Write an image of `bytes` at the parameters `args` names, in the vocabulary the planner's own
/// matrix uses — so one row describes what the baseline is asked for and what this crate is
/// asked for, and the two cannot drift apart.
#[cfg(feature = "btrfs")]
fn written(lab: &Lab, name: &str, bytes: u64, args: &[&str]) -> PathBuf {
    use ferrosys::btrfs::format_to;

    let path = lab.sparse(name, bytes);
    let file = File::options()
        .write(true)
        .open(&path)
        .expect("open the destination this gate just created");
    format_to(
        file,
        ferrosys::TreeBuilder::new(),
        bytes,
        writer_options().plan(request_for(bytes, args)),
    )
    .unwrap_or_else(|e| panic!("this crate refused a volume the baseline takes: {e}"));
    path
}

/// The pinned checker accepts every filesystem this crate writes.
///
/// The whole parameter set the planner is held against, because a layout being right is not the
/// same claim as the bytes over it being a filesystem: the checker walks the extent tree against
/// every block it can reach, the free-space tree against the block groups, and the root tree
/// against every tree it names.
#[test]
#[cfg(feature = "btrfs")]
fn the_checker_accepts_every_filesystem_this_crate_writes() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, bytes, args) in PLANNER_MATRIX {
        let image = written(
            &lab,
            &format!("w-{what}.img").replace(' ', "-"),
            *bytes,
            args,
        );
        btrfs_check_clean(&image, &[]).unwrap_or_else(|e| {
            panic!("{what}: the checker refused an image this crate wrote\n{e}")
        });
        // The data pass as well. An empty filesystem has no data extent and so no checksum to
        // verify — what this asserts is that the checksum tree it does carry is one the checker
        // reads rather than one it stumbles over.
        btrfs_check_clean(&image, &["--check-data-csum"])
            .unwrap_or_else(|e| panic!("{what}: the data pass refused it\n{e}"));
    }
}

/// The checker rejects an image this crate wrote once one byte of it is altered.
///
/// The negative control the gate above needs. A checker that accepted anything would pass every
/// row of that matrix, and nothing about a green run would say which of the two was true.
#[test]
#[cfg(feature = "btrfs")]
fn the_checker_rejects_a_filesystem_this_crate_wrote_and_something_then_altered() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let image = written(&lab, "control.img", ORDINARY, &["-s", "4096"]);
    btrfs_check_clean(&image, &[])
        .expect("clean before the damage, which is what makes this a control");

    // A byte inside the primary superblock's covered range — the vector the oracle tier's first control
    // uses, authored here because it needs no tool and no parser.
    flip_byte(&image, MIRRORS[0] + 72);
    let refused = btrfs_check_clean(&image, &[]);
    assert!(
        refused.is_err(),
        "the checker accepted an image this gate damaged: {refused:?}"
    );
}

/// This crate spends the tree blocks the baseline spends, at every feature set that changes
/// which trees exist.
///
/// A single number, and the sharpest one about a from-scratch writer there is: a filesystem with
/// a tree too many or a tree too few has a different count, and so does one whose trees came out
/// at a different height. The checker's own summary is where the figure comes from, which is a
/// second opinion rather than this crate's own arithmetic read back.
#[test]
#[cfg(feature = "btrfs")]
fn this_crate_spends_the_tree_blocks_the_baseline_spends() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, extra) in [
        ("every default", &[][..]),
        (
            "block groups in the extent tree",
            &["-O", "^block-group-tree"][..],
        ),
        ("no free-space tree at all", &["-O", "^free-space-tree"][..]),
    ] {
        let mut args = vec!["-s", "4096"];
        args.extend_from_slice(extra);
        let name = what.replace(' ', "-");
        let mine = written(&lab, &format!("u-{name}.img"), ORDINARY, &args);
        let theirs = lab.formatted(&format!("t-{name}.img"), ORDINARY, &args);
        assert_eq!(
            used_bytes(&mine),
            used_bytes(&theirs),
            "{what}: the two filesystems spend different amounts of metadata"
        );
    }
}

/// What the checker reports a filesystem as using, in bytes.
#[cfg(feature = "btrfs")]
fn used_bytes(image: &Path) -> u64 {
    let said = btrfs_check_clean(image, &[]).expect("the checker accepts the image");
    // `found 163840 bytes used, no error found` — the figure is the word after "found" and the
    // line does not end where the phrase does.
    said.split_whitespace()
        .skip_while(|word| *word != "found")
        .nth(1)
        .and_then(|word| word.parse().ok())
        .unwrap_or_else(|| panic!("no used-bytes figure in the checker's summary:\n{said}"))
}

/// Every record this crate writes is the record the baseline writes.
///
/// Tree by tree, record by record, field by field, at every row of the planner's matrix. Three
/// things diverge, each a consequence of writing a filesystem in one transaction rather than in
/// several, and each is replaced by a marker rather than dropped — so a *missing* record still
/// fails, where a comparison that dropped a whole class of line would pass an image that had
/// none of it.
///
/// - **The addresses tree blocks sit at, and the transactions that wrote them.** The baseline
///   commits several transactions on the way to an empty filesystem and frees the blocks each
///   one replaced, so its metadata block group has holes in it and its blocks carry four
///   different generations. Nothing is ever freed here and there is one transaction, so the
///   blocks are consecutive and every generation is the same. Every record keyed by a block
///   address therefore differs, which is every record of the extent tree.
/// - **Where a record sits inside its leaf.** `itemoff` follows from the packing, and the
///   packing differs on any leaf whose records this crate divides differently. What a record
///   *is* is compared through its `itemsize`, which does not.
/// - **The five values the baseline invents**: its filesystem id, device id, chunk tree id,
///   subvolume id, and the instant it formats at. Here they are inputs, which is what makes an
///   image reproducible — the rule every family of this crate holds.
///
/// Two trees are compared by gates of their own below, because both are keyed by a tree block
/// address: the order their records sit in *is* the order the blocks were allocated, so a
/// comparison that marked the addresses and kept the sequence would still be comparing them.
#[test]
#[cfg(feature = "btrfs")]
fn every_record_this_crate_writes_is_the_record_the_baseline_writes() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, bytes, args) in PLANNER_MATRIX {
        let name = what.replace(' ', "-");
        let mine = trees_of(&inspect(
            &written(&lab, &format!("d-{name}.img"), *bytes, args),
            &["dump-tree"],
        ));
        let theirs = trees_of(&inspect(
            &lab.formatted(&format!("b-{name}.img"), *bytes, args),
            &["dump-tree"],
        ));

        assert_eq!(
            mine.keys().collect::<Vec<_>>(),
            theirs.keys().collect::<Vec<_>>(),
            "{what}: the two filesystems do not hold the same trees"
        );
        for (tree, records) in &mine {
            if tree == "free space tree" || tree == "extent tree" {
                continue;
            }
            // A comparison of two empty lists passes and says nothing, so what each tree holds
            // is asserted to be something. The checksum tree of an empty filesystem genuinely
            // holds nothing, which is why it is named rather than covered by a bound.
            assert_eq!(
                records.is_empty(),
                tree == "checksum tree",
                "{what}: the {tree} came out {} records, which is not what it holds",
                records.len()
            );
            assert_eq!(
                records, &theirs[tree],
                "{what}: the {tree} of a {bytes}-byte volume"
            );
        }
    }
}

/// The extent tree records one extent per tree block, and the same ones the baseline records.
///
/// A set rather than a sequence, because the records are keyed by block address and the two
/// filesystems put their blocks at different addresses — so what they must agree on is *which*
/// blocks exist, which tree owns each, and at what height, and not the order those come out in.
///
/// It is the strongest single statement about a from-scratch writer's accounting. A tree block
/// the extent tree does not record is one a driver will allocate over; a record for a block that
/// is not there is a reference to nothing; and a record naming the wrong owner sends a checker
/// looking for a backref in a tree that does not hold one. All three are caught here by a
/// comparison against a filesystem the same tools built.
#[test]
#[cfg(feature = "btrfs")]
fn the_extent_tree_records_the_blocks_the_baselines_does() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    for (what, bytes, args) in PLANNER_MATRIX {
        let name = what.replace(' ', "-");
        let mine = metadata_extents(&written(&lab, &format!("e-{name}.img"), *bytes, args));
        let theirs = metadata_extents(&lab.formatted(&format!("x-{name}.img"), *bytes, args));
        assert_eq!(mine, theirs, "{what}: a volume of {bytes} bytes");
    }
}

/// Every metadata extent of `image`, as `(owning tree, level)`, sorted.
#[cfg(feature = "btrfs")]
fn metadata_extents(image: &Path) -> Vec<(String, u8)> {
    let dump = inspect(image, &["dump-tree", "-t", "extent"]);
    let mut out: Vec<(String, u8)> = Vec::new();
    let mut level = None;
    for line in dump.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            // `tree block skinny level 0`
            ["tree", "block", "skinny", "level", at] => {
                level = Some(at.parse().expect("a tree block level"));
            }
            // `(176 0x3) tree block backref root CHUNK_TREE`
            [_, _, "tree", "block", "backref", "root", owner] => {
                out.push((
                    (*owner).to_owned(),
                    level.take().expect("a level precedes its backref"),
                ));
            }
            _ => {}
        }
    }
    assert!(
        !out.is_empty(),
        "no metadata extent was read out of {image:?}"
    );
    out.sort();
    out
}

/// The free-space tree accounts for the block groups the baseline's does, run for run where the
/// runs can agree.
///
/// The one tree whose record count legitimately differs, and this is where that is stated rather
/// than waved past. A block group written once is filled from its start and has a single run of
/// free space behind what it holds; the baseline's has as many runs as its freed blocks left
/// holes. So what the two must agree on is *which block groups there are* and that every run is
/// inside the one it belongs to — and what they need not agree on is how many runs that is.
#[test]
#[cfg(feature = "btrfs")]
fn the_free_space_tree_covers_the_block_groups_the_baselines_does() {
    if !suite_ready() {
        return;
    }
    let lab = Lab::new();
    let mine = free_space(&written(&lab, "fst-mine.img", ORDINARY, &["-s", "4096"]));
    let theirs = free_space(&lab.formatted("fst-base.img", ORDINARY, &["-s", "4096"]));

    let groups: Vec<(u64, u64)> = mine
        .iter()
        .map(|(start, length, _)| (*start, *length))
        .collect();
    assert_eq!(
        groups,
        theirs
            .iter()
            .map(|(start, length, _)| (*start, *length))
            .collect::<Vec<_>>(),
        "the two filesystems describe different block groups"
    );
    for ((start, length, runs), (_, _, theirs)) in mine.iter().zip(&theirs) {
        assert_eq!(
            *runs, 1,
            "a block group written in one transaction has one free run"
        );
        assert!(
            *theirs >= *runs,
            "the baseline's own free space is at least as fragmented as this crate's"
        );
        assert!(length > &0 && start >= &(1 << 20));
    }
}

/// Each block group of `image`, as `(start, length, free runs)`, out of its free-space tree.
#[cfg(feature = "btrfs")]
fn free_space(image: &Path) -> Vec<(u64, u64, u32)> {
    let dump = inspect(image, &["dump-tree", "-t", "free-space"]);
    let mut out = Vec::new();
    for line in dump.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        // `item 0 key (13631488 FREE_SPACE_INFO 8388608) itemoff ... itemsize 8`
        if let ["item", _, "key", start, "FREE_SPACE_INFO", length, ..] = words.as_slice() {
            out.push((
                start
                    .trim_start_matches('(')
                    .parse()
                    .expect("a block group start"),
                length
                    .trim_end_matches(')')
                    .parse()
                    .expect("a block group length"),
                0,
            ));
        }
        // `free space info extent count 1 flags 0`
        if let ["free", "space", "info", "extent", "count", count, ..] = words.as_slice() {
            out.last_mut().expect("a count follows its key").2 =
                count.parse().expect("a free-run count");
        }
    }
    assert!(
        !out.is_empty(),
        "no free-space record was read out of {image:?}"
    );
    out
}

/// A dump split into its trees, each as the sequence of records it holds.
///
/// **Records rather than blocks.** Which leaf a record sits in is a divergence in its own right —
/// a tree built all at once packs its leaves full where one grown by insertion splits a full
/// block down the middle — so every line describing a *block* is dropped and what is left is the
/// filesystem's content in key order. The heights the two trees came out at are compared anyway,
/// through the `level` every root item carries and the one the superblock records.
#[cfg(feature = "btrfs")]
fn trees_of(dump: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut trees = std::collections::BTreeMap::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in dump.lines() {
        // A tree begins at a line with no indentation naming one: `root tree`, or
        // `extent tree key (EXTENT_TREE ROOT_ITEM 0)`.
        let heading = !line.starts_with(char::is_whitespace)
            && line.split_whitespace().any(|word| word == "tree")
            && !line.starts_with("btrfs-progs");
        if heading {
            if let Some((name, records)) = current.take() {
                trees.insert(name, records);
            }
            let name = line
                .split(" key (")
                .next()
                .unwrap_or(line)
                .trim()
                .to_owned();
            current = Some((name, Vec::new()));
            continue;
        }
        let Some((_, records)) = current.as_mut() else {
            continue;
        };
        if describes_a_block(line) {
            continue;
        }
        records.push(comparable(line));
    }
    if let Some((name, records)) = current {
        trees.insert(name, records);
    }
    assert!(!trees.is_empty(), "no tree was read out of the dump");
    trees
}

/// Whether a line describes the block a record sits in rather than the record.
#[cfg(feature = "btrfs")]
fn describes_a_block(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    matches!(
        words.as_slice(),
        ["leaf", ..]
            | ["node", ..]
            | ["fs", "uuid", ..]
            | ["chunk", "uuid", ..]
            // `key (EXTENT_TREE ROOT_ITEM 0) block 30461952 gen 8` — an internal node's pointer
            // at one of its children, which is a block and not a record.
            | ["key", .., "block", _, "gen", _]
    )
}

/// One line of a dump with each named divergence replaced by a marker and nothing else touched.
#[cfg(feature = "btrfs")]
fn comparable(line: &str) -> String {
    /// The fields whose value is a transaction number or a tree block address.
    const MARKED: &[&str] = &[
        "generation",
        "gen",
        "transid",
        "ctransid",
        "otransid",
        "generation_v2",
        "bytenr",
        "itemoff",
        "leaf",
        "node",
    ];

    let mut out: Vec<String> = Vec::new();
    // `item 0 key (...)` — the index restarts in each leaf, so it says which leaf a record
    // landed in rather than which record it is.
    let line = match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["item", _, rest @ ..] => rest.join(" "),
        _ => line.trim().to_owned(),
    };
    let mut words = line.split_whitespace().peekable();
    let mut mark_next = false;
    while let Some(word) = words.next() {
        if mark_next {
            mark_next = false;
            out.push("N".to_owned());
            continue;
        }
        // `free space 12245 generation 8` on a block's own line, and `free space info extent
        // count` inside the free-space tree, which this never reaches.
        if word == "free" && words.peek() == Some(&"space") {
            words.next();
            words.next();
            out.push("free space N".to_owned());
            continue;
        }
        if MARKED.contains(&word) {
            mark_next = true;
            out.push(word.to_owned());
            continue;
        }
        out.push(if is_identity(word) || is_time(word) {
            "N".to_owned()
        } else {
            marked_key(word)
        });
    }
    out.join(" ")
}

/// A word that is one of the five values the baseline invents, or a rendering of one.
#[cfg(feature = "btrfs")]
fn is_identity(word: &str) -> bool {
    // A UUID as the baseline renders one, and the two halves it splits into for a UUID tree key.
    if word.len() == 36 && word.split('-').map(str::len).eq([8, 4, 4, 4, 12]) {
        return true;
    }
    // Either half of a UUID tree key, which is a UUID split in the middle — and the first of
    // them is at the head of a key, so a leading parenthesis comes with it.
    let bare = word.trim_start_matches('(').trim_end_matches(')');
    matches!(bare.strip_prefix("0x"), Some(hex) if hex.len() == 16)
}

/// A word that is a time, in either rendering the baseline uses.
#[cfg(feature = "btrfs")]
fn is_time(word: &str) -> bool {
    // `1786472859.0`, and the `(2026-08-11` and `14:27:39)` of the reading beside it.
    let digits_and = |word: &str, sep: char| {
        word.split(sep)
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    };
    let bare = word.trim_start_matches('(').trim_end_matches(')');
    (word.contains('.') && digits_and(bare, '.'))
        || (bare.matches('-').count() == 2 && digits_and(bare, '-'))
        || (bare.matches(':').count() == 2 && digits_and(bare, ':'))
}

/// A key whose objectid is a tree block address, marked; anything else unchanged.
///
/// Only the extent tree keys its records by one. A chunk item's key offset is a *logical* address
/// the planner already agrees with the baseline about, so it stays exact.
#[cfg(feature = "btrfs")]
fn marked_key(word: &str) -> String {
    match word.strip_prefix('(') {
        // `(30605312` — a bare number wide enough to be a block address, at the head of a key.
        Some(number) if number.len() >= 7 && number.chars().all(|c| c.is_ascii_digit()) => {
            "(N".to_owned()
        }
        _ => word.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// A populated filesystem this crate wrote

/// The gates that need a tree on the host as well as one in memory.
///
/// `DirectorySource` walks a host directory, which is what lets one tree be handed to this crate
/// and to the baseline — and it is compiled only where a host tree has the properties these
/// gates compare, so the module carries the condition once rather than every gate carrying it.
#[cfg(all(
    feature = "btrfs",
    feature = "dir",
    any(target_os = "linux", target_os = "android")
))]
mod populated {
    use super::*;

    /// A tree this crate is asked to write, and the same tree on the host for the baseline to be
    /// asked to write.
    ///
    /// Built once and used by both, so a row cannot describe two different trees. Everything a
    /// `SourceEntry` carries that a host tree can also carry is in it — a nested directory, an empty
    /// one, a file stored inside its own metadata, one stored in a single extent, one that spans
    /// more than one, a file that is not a whole number of sectors, a symbolic link, a second name
    /// for one inode, an unusual mode, and an extended attribute. What is *not* in it is a device
    /// node, a FIFO, and a socket: creating one on the host needs privileges this project exists not
    /// to need, so those three are covered by the library's own round trip instead.
    fn shared_tree(lab: &Lab) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let root = lab.path().join("shared");
        fs::create_dir_all(root.join("dir/nested")).expect("create the nested directory");
        fs::create_dir(root.join("empty")).expect("create the empty directory");
        fs::write(root.join("dir/small.txt"), b"inside its own metadata\n")
            .expect("the small file");
        fs::write(root.join("one-extent.bin"), vec![0xa5u8; 64 << 10])
            .expect("the one-extent file");
        fs::write(
            root.join("many-extents.bin"),
            vec![0x5au8; (2 << 20) + 4096],
        )
        .expect("the many-extent file");
        fs::write(root.join("ragged.bin"), vec![0x33u8; 5000]).expect("the ragged file");
        // Larger than a data chunk, so both writers append chunks for it, grant extents across
        // the boundaries between them, and restart a checksum record at each discontinuity —
        // the paths content that fits the first chunk never runs. A whole number of mebibytes,
        // so its extent division is the one the two writers agree on.
        fs::write(root.join("spanning.bin"), vec![0x77u8; 20 << 20]).expect("the spanning file");
        std::os::unix::fs::symlink("dir/small.txt", root.join("link")).expect("the symlink");
        fs::hard_link(root.join("dir/small.txt"), root.join("second-name.txt"))
            .expect("the second name");
        fs::set_permissions(root.join("ragged.bin"), PermissionsExt::from_mode(0o604))
            .expect("an unusual mode, so a default cannot pass for it");
        settle_atimes(&root);
        root
    }

    /// Read everything in the tree once, so the access times both producers record are the ones
    /// this pass left behind rather than the ones their own reads move.
    ///
    /// A freshly created file has its access time equal to its modification time, which is
    /// exactly when `relatime` lets a read move it — so a producer that reads the tree after
    /// statting it can leave different whole-second access times for the next producer to stat.
    /// After this pass every access time is at or past the times a read is compared against, and
    /// neither producer's reads move anything.
    fn settle_atimes(root: &Path) {
        for entry in fs::read_dir(root).expect("list the tree") {
            let entry = entry.expect("an entry");
            let kind = entry.file_type().expect("its kind");
            if kind.is_dir() {
                settle_atimes(&entry.path());
            } else if kind.is_symlink() {
                fs::read_link(entry.path()).expect("read the link");
            } else {
                fs::read(entry.path()).expect("read the file");
            }
        }
    }

    /// This crate's image of `source`, at `sector` bytes to a sector and `node` to a tree block.
    fn populated_by_ferrosys(
        lab: &Lab,
        name: &str,
        source: &Path,
        sector: u32,
        node: u32,
    ) -> PathBuf {
        use ferrosys::btrfs::{NodeSize, PlanRequest, SectorSize, format_to};

        let bytes = ORDINARY;
        let path = lab.sparse(name, bytes);
        let file = File::options()
            .write(true)
            .open(&path)
            .expect("open the destination this gate just created");
        let plan = PlanRequest::new(bytes)
            .sector_size(SectorSize::Bytes(sector))
            .node_size(NodeSize::Bytes(node));
        let walked = ferrosys::DirectorySource::from_path(source).expect("walk the shared tree");
        format_to(file, walked, bytes, writer_options().plan(plan))
            .unwrap_or_else(|e| panic!("this crate refused a tree the baseline takes: {e}"));
        path
    }

    /// The checker accepts every populated filesystem this crate writes, with its data pass and
    /// without it.
    ///
    /// Two gates in one run, and the second is the one with no analogue anywhere else in this
    /// project: `btrfs check` alone is clean on a filesystem whose checksum tree covers the wrong
    /// bytes, so a writer that built a correct tree over the wrong data — or the right data under
    /// the wrong logical address — passes everything but `--check-data-csum`.
    #[test]
    fn the_checker_accepts_every_populated_filesystem_this_crate_writes() {
        if !suite_ready() {
            return;
        }
        let lab = Lab::new();
        let source = shared_tree(&lab);
        // The two block sizes a populated image's records depend on: the sector decides which files
        // live inside the metadata and how the checksum tree is keyed, and the node decides how many
        // records a leaf holds and therefore how tall each tree is.
        for (sector, node) in [(4096u32, 16384u32), (4096, 4096), (16384, 16384)] {
            let image = populated_by_ferrosys(
                &lab,
                &format!("pop-{sector}-{node}.img"),
                &source,
                sector,
                node,
            );
            btrfs_check_clean(&image, &[]).unwrap_or_else(|e| {
                panic!("the checker rejected a {sector}/{node} filesystem this crate wrote: {e}")
            });
            btrfs_check_clean(&image, &["--check-data-csum"]).unwrap_or_else(|e| {
                panic!("the data pass rejected a {sector}/{node} filesystem this crate wrote: {e}")
            });
        }
    }

    /// A filesystem this crate populated, altered in a file's own bytes, is rejected by the data
    /// pass and by nothing else.
    ///
    /// The control that makes the gate above a gate. Without it, a run in which every checksum
    /// happened to be ignored would look exactly like a run in which every checksum was right.
    #[test]
    fn altered_bytes_of_a_filesystem_this_crate_wrote_are_caught_only_by_the_data_pass() {
        if !suite_ready() {
            return;
        }
        let lab = Lab::new();
        let source = shared_tree(&lab);
        let image = populated_by_ferrosys(&lab, "control.img", &source, 4096, 16384);
        // Located by searching for the file's own bytes rather than by translating an address, so
        // the control does not assume the single-device mapping is the identity.
        let at = find_pattern(&image, &[0x5au8; 64]).expect("the file's bytes are in the image");
        flip_byte(&image, at);

        btrfs_check_clean(&image, &[]).expect("plain check is clean on altered file bytes");
        assert!(
            btrfs_check_clean(&image, &["--check-data-csum"]).is_err(),
            "the data pass accepted a file whose bytes were altered"
        );
    }

    /// Where `pattern` first occurs in `image`, or [`None`].
    fn find_pattern(image: &Path, pattern: &[u8]) -> Option<u64> {
        let bytes = fs::read(image).expect("read the image");
        bytes
            .windows(pattern.len())
            .position(|window| window == pattern)
            .map(|at| at as u64)
    }

    /// This crate and the baseline, given one tree, write the same filesystem — record for record,
    /// where the two are comparable, and diverging only where this file says.
    ///
    /// The comparison is keyed by **path** rather than by inode number, and that is not a weakening:
    /// the baseline numbers its inodes and orders each directory's sequence in the order the host's
    /// `readdir` happened to return names, which is not a function of the tree at all. So a
    /// record-for-record comparison in the dump's own order would be comparing two orderings of the
    /// host, and the claim worth making — that every object came out with the fields it was given —
    /// is the one made here.
    ///
    /// **The named divergences**, each deliberate and each asserted below rather than
    /// filtered silently:
    ///
    /// - The baseline emits the part of a file that is not a whole mebibyte as a full-sector extent
    ///   and its ragged tail as a second extent of one sector; this crate emits one extent for the
    ///   run, which is fewer records for the same bytes.
    /// - A file long enough to reach the end of a data chunk divides differently there: this
    ///   crate splits the extent that meets the boundary and continues in the next chunk, and
    ///   the baseline's allocator moves to a fresh chunk between whole extents instead. The
    ///   same bytes reach the same file either way, which the path-keyed comparison asserts.
    /// - The baseline writes a symbolic link's target with a trailing byte the inode's own size does
    ///   not count; this crate writes the target and stops, which is what the kernel writes.
    /// - The baseline copies a host directory's `st_blocks` of zero onto every directory including
    ///   the root of a subvolume; this crate charges a subvolume's root directory with the tree
    ///   block its tree is, which is what the same tool writes for a filesystem it creates rather
    ///   than fills.
    /// - Inode numbers, directory sequences, generations, and the five values the baseline invents.
    #[test]
    fn every_object_this_crate_writes_is_the_object_the_baseline_writes() {
        if !suite_ready() {
            return;
        }
        let lab = Lab::new();
        let source = shared_tree(&lab);
        let mine = populated_by_ferrosys(&lab, "mine.img", &source, 4096, 16384);
        let theirs = lab.formatted(
            "theirs.img",
            ORDINARY,
            &[
                "-s",
                "4096",
                "-n",
                "16384",
                "-r",
                source.to_str().expect("a UTF-8 scratch path"),
            ],
        );

        let ours = objects_of(&inspect(&mine, &["dump-tree", "-t", "fs"]));
        let baseline = objects_of(&inspect(&theirs, &["dump-tree", "-t", "fs"]));
        assert_eq!(
            ours.keys().collect::<Vec<_>>(),
            baseline.keys().collect::<Vec<_>>(),
            "the two filesystems do not hold the same names"
        );
        // Nine objects, one of which answers to two names: the tree has ten names in it.
        assert_eq!(ours.len(), 9, "the tree came out {:?}", ours.keys());
        for (name, object) in &ours {
            assert_eq!(
                object, &baseline[name],
                "{name} is not the object the baseline wrote"
            );
        }

        // The divergences, each asserted rather than filtered — a carve-out nobody can see fail is a
        // carve-out that has stopped being true without saying so.
        let ours = inspect(&mine, &["dump-tree", "-t", "fs"]);
        let theirs = inspect(&theirs, &["dump-tree", "-t", "fs"]);

        // Sub-second times. The baseline writes a nanosecond field of zero for every time on every
        // object; this crate writes what the host's file said.
        assert!(
            ours.lines()
                .any(|line| line.trim_start().starts_with("mtime") && !line.contains(".0 ")),
            "this crate kept a time finer than a second:\n{ours}"
        );
        assert!(
            theirs
                .lines()
                .filter(|line| line.trim_start().starts_with("mtime"))
                .all(|line| line.contains(".0 ")),
            "the baseline dropped every sub-second time:\n{theirs}"
        );

        // A birth time. The baseline writes zero and this crate writes the modification time, which
        // is the earliest instant anything states about the object.
        assert!(
            !ours.contains("otime 0.0"),
            "this crate recorded a birth time for every object:\n{ours}"
        );
        assert!(
            theirs.contains("otime 0.0"),
            "the baseline left the birth time unset:\n{theirs}"
        );

        // A symbolic link's stored length. The baseline writes one byte the inode's size does not
        // count; this crate writes the target and stops.
        assert!(
            ours.contains("size 13 nbytes 13"),
            "the link's stored bytes are its target's thirteen:\n{ours}"
        );
        assert!(
            theirs.contains("size 13 nbytes 14"),
            "the baseline stored one byte more than the target:\n{theirs}"
        );

        // How the extents divide. The two counts agree by different routes, and both routes are
        // named divergences: twenty-five shared extents, plus the ragged tail sector the
        // baseline emits as an extent of its own, plus the extent this crate splits where the
        // spanning file meets the end of a data chunk.
        let extents_of = |dump: &str| {
            dump.lines()
                .filter(|line| line.trim_start().starts_with("extent data disk byte"))
                .count()
        };
        assert_eq!(
            (extents_of(&ours), extents_of(&theirs)),
            (26, 26),
            "twenty-five shared extents plus one named divergence on each side"
        );
        // The two divergent extents themselves, so the counts above cannot agree by accident:
        // the baseline's tail sector, and this crate's boundary split — a pair of partial
        // extents whose lengths sum to the whole mebibyte the run would otherwise be.
        assert!(
            theirs.contains("extent data offset 0 nr 4096 ram 4096"),
            "the baseline's ragged tail sector is an extent of its own:\n{theirs}"
        );
        let mut partial: Vec<u64> = ours
            .lines()
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                match words.as_slice() {
                    ["extent", "data", "offset", _, "nr", nr, "ram", _] => nr.parse().ok(),
                    _ => None,
                }
            })
            .filter(|&nr| nr % (1 << 20) != 0)
            .collect();
        partial.sort_unstable();
        assert_eq!(partial.len(), 5, "{partial:?}\n{ours}");
        // The three short runs the tree always has: the many-extent file's whole final sector,
        // the ragged file's one run of two sectors, and the one-extent file entire.
        assert_eq!(&partial[..3], &[4096, 8192, 65536], "{partial:?}");
        assert_eq!(
            partial[3] + partial[4],
            1 << 20,
            "the boundary split is one mebibyte in two parts: {partial:?}\n{ours}"
        );
        assert!(
            ours.contains("extent data offset 0 nr 8192 ram 8192"),
            "the ragged file is one extent of two sectors here:\n{ours}"
        );
    }

    /// The whole-seconds part of a time as the dump renders it: `1786483161.970285660`.
    fn whole_seconds(stamp: &str) -> &str {
        stamp.split('.').next().unwrap_or(stamp)
    }

    /// What one dumped filesystem tree says about each object, keyed by the name it is reached by.
    ///
    /// A name rather than an inode number, for the reason the gate above states. What is kept per
    /// object is the whole inode record but for the fields the divergences name, and the *shape* of
    /// its content: how many bytes are stored inside the metadata and how many bytes of extents it
    /// holds — not how those extents were divided, which is where this crate and the baseline
    /// deliberately differ.
    fn objects_of(dump: &str) -> std::collections::BTreeMap<String, Vec<String>> {
        use std::collections::BTreeMap;

        // First pass: every name each inode answers to, and what the entries say it is. All of
        // them, sorted — a file with two names is one object with two, and keying it by whichever
        // name the dump happened to reach first would key it by an ordering of the host.
        let mut named: BTreeMap<u64, (Vec<String>, String)> = BTreeMap::new();
        let mut location: Option<(u64, String)> = None;
        for line in dump.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                // `location key (261 INODE_ITEM 0) type FILE`
                ["location", "key", target, _, _, "type", kind] => {
                    let inode = target.trim_start_matches('(').parse().unwrap_or(0);
                    location = Some((inode, (*kind).to_owned()));
                }
                ["name:", name] => {
                    if let Some((inode, kind)) = location.take() {
                        let entry = named.entry(inode).or_insert((Vec::new(), kind));
                        // Each name twice in the dump, once under its hash and once under its
                        // sequence, and only one of the two is a name this object *has*.
                        if !entry.0.iter().any(|held| held == name) {
                            entry.0.push((*name).to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
        for (names, _) in named.values_mut() {
            names.sort();
        }

        // Second pass: the inode records themselves, and what each holds.
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut current: Option<u64> = None;
        let mut facts: Vec<String> = Vec::new();
        let mut inline = 0u64;
        let mut extent_bytes = 0u64;
        let flush = |current: &mut Option<u64>,
                     facts: &mut Vec<String>,
                     inline: &mut u64,
                     extent_bytes: &mut u64,
                     out: &mut BTreeMap<String, Vec<String>>| {
            if let Some(inode) = current.take() {
                let Some((names, kind)) = named.get(&inode) else {
                    // The root directory, which no entry names. Its own record diverges by the one
                    // field the doc above names, so comparing it would compare that and nothing else.
                    facts.clear();
                    *inline = 0;
                    *extent_bytes = 0;
                    return;
                };
                let mut about = std::mem::take(facts);
                // The names a directory holds, sorted: this crate numbers a directory's sequence in
                // sorted order and the baseline in the host's `readdir` order, so what the two
                // agree on is which names are there.
                about.sort();
                about.push(format!("entry type {kind}"));
                // How many bytes a file keeps inside its own metadata. Not for a symbolic link: its
                // target is its content and the two writers store a different number of bytes of it,
                // which is one of the named divergences and is asserted on its own.
                if kind != "SYMLINK" {
                    about.push(format!("inline {inline}"));
                }
                about.push(format!("extent bytes {extent_bytes}"));
                out.insert(names.join(" and "), about);
            }
            *inline = 0;
            *extent_bytes = 0;
        };

        for line in dump.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                // `item 0 key (256 INODE_ITEM 0) itemoff 16123 itemsize 160`
                ["item", _, "key", objectid, "INODE_ITEM", ..] => {
                    flush(
                        &mut current,
                        &mut facts,
                        &mut inline,
                        &mut extent_bytes,
                        &mut out,
                    );
                    current = objectid.trim_start_matches('(').parse().ok();
                }
                // `generation 0 transid 0 size 38 nbytes 0` — the size is compared and the two
                // transaction numbers are not.
                ["generation", _, "transid", _, "size", size, "nbytes", _] => {
                    facts.push(format!("size {size}"));
                }
                // `block group 0 mode 100664 links 2 uid 1000 gid 1000 rdev 0`
                [
                    "block",
                    "group",
                    _,
                    "mode",
                    mode,
                    "links",
                    links,
                    "uid",
                    uid,
                    "gid",
                    gid,
                    "rdev",
                    rdev,
                ] => {
                    facts.push(format!(
                        "mode {mode} links {links} uid {uid} gid {gid} rdev {rdev}"
                    ));
                }
                // Whole seconds: the baseline writes a nanosecond field of zero for every time
                // whatever the host's file says, and this crate writes what the host said. That
                // divergence is asserted on its own below rather than compared away here.
                ["atime", stamp, ..] => facts.push(format!("atime {}", whole_seconds(stamp))),
                ["mtime", stamp, ..] => facts.push(format!("mtime {}", whole_seconds(stamp))),
                ["ctime", stamp, ..] => facts.push(format!("ctime {}", whole_seconds(stamp))),
                // `inline extent data size 6 ram_bytes 6 compression 0 (none) encryption 0`
                ["inline", "extent", "data", "size", size, ..] => {
                    inline += size.parse::<u64>().unwrap_or(0);
                }
                // `extent data offset 0 nr 1048576 ram 1048576`
                ["extent", "data", "offset", _, "nr", nr, "ram", _] => {
                    extent_bytes += nr.parse::<u64>().unwrap_or(0);
                }
                // `data hi` — an extended attribute's value, and `name: user.note` two lines above
                // it, which the first pass already keyed. Compared as the pair.
                ["name:", name] if line.starts_with("\t\tname:") => {
                    facts.push(format!("holds a name {name}"));
                }
                _ => {}
            }
        }
        flush(
            &mut current,
            &mut facts,
            &mut inline,
            &mut extent_bytes,
            &mut out,
        );
        out
    }
}

/// The checker accepts a filesystem whose names outgrew the record that holds them.
///
/// The overflow into `INODE_EXTREF` is a shape the library's own round trip proves it *reads*;
/// what only the checker can say is that the pair of records is the pair a driver expects — a
/// backref pass walks every name of every inode against the directory entry naming it, in both
/// directions, and neither form is exempt.
#[test]
#[cfg(feature = "btrfs")]
fn the_checker_accepts_a_filesystem_whose_names_outgrew_one_record() {
    if !suite_ready() {
        return;
    }
    use ferrosys::btrfs::{NodeSize, PlanRequest, format_to};
    use ferrosys::{Metadata, TreeBuilder};

    let lab = Lab::new();
    let time = ferrosys::Timestamp {
        secs: 1_786_472_859,
        nanos: 0,
    };
    let meta = Metadata::new(0o644, time);
    let long = "n".repeat(200);
    let mut source = TreeBuilder::new().file(b"/target".to_vec(), b"linked\n", meta);
    for n in 0..40 {
        source = source.hardlink(
            format!("/{long}{n:04}").into_bytes(),
            b"/target".to_vec(),
            meta,
        );
    }

    // The smallest tree block the format defines, which is what makes forty names an overflow
    // rather than the several hundred a default block holds.
    let path = lab.sparse("dense-links.img", ORDINARY);
    let file = File::options()
        .write(true)
        .open(&path)
        .expect("open the destination this gate just created");
    format_to(
        file,
        source,
        ORDINARY,
        writer_options().plan(PlanRequest::new(ORDINARY).node_size(NodeSize::Bytes(4096))),
    )
    .unwrap_or_else(|e| panic!("this crate refused a densely linked tree: {e}"));

    btrfs_check_clean(&path, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected a densely linked filesystem: {e}"));

    let fs_tree = inspect(&path, &["dump-tree", "-t", "fs"]);
    assert!(
        fs_tree.contains("INODE_EXTREF"),
        "the names outgrew one record:\n{fs_tree}"
    );
    assert!(
        fs_tree.contains("links 41"),
        "one file with forty-one names:\n{fs_tree}"
    );
}

/// A subvolume this crate writes is one the baseline's own tooling recognizes.
///
/// `btrfs check`'s root-reference pass is the gate: it walks every `ROOT_REF` against the
/// `ROOT_BACKREF` that should mirror it and against the directory entry in the parent tree that
/// should name it, so a subvolume linked from one end only is rejected. `btrfs subvolume list`
/// is what says the same filesystem reads back as the layout it was asked for.
#[test]
#[cfg(feature = "btrfs")]
fn the_subvolume_layout_this_crate_writes_is_the_one_the_baseline_reads_back() {
    if !suite_ready() {
        return;
    }
    use ferrosys::btrfs::{SubvolumeRequest, format_to};
    use ferrosys::{Metadata, TreeBuilder};

    let lab = Lab::new();
    let time = ferrosys::Timestamp {
        secs: 1_786_472_859,
        nanos: 0,
    };
    let source = TreeBuilder::new()
        .directory(b"/@".to_vec(), Metadata::new(0o755, time))
        .file(
            b"/@/hostname".to_vec(),
            "ferrosys\n",
            Metadata::new(0o644, time),
        )
        .directory(b"/@home".to_vec(), Metadata::new(0o755, time))
        .file(
            b"/@home/profile".to_vec(),
            "shell\n",
            Metadata::new(0o644, time),
        );

    let path = lab.sparse("subvolumes.img", ORDINARY);
    let file = File::options()
        .write(true)
        .open(&path)
        .expect("open the destination this gate just created");
    format_to(
        file,
        source,
        ORDINARY,
        writer_options()
            // The identifiers descend where the subvolumes ascend. That is the ordinary case — a
            // caller states an identifier and nothing relates it to the order a tree is walked in
            // — and it is what makes the UUID tree's record order differ from its producer's. A
            // pair chosen the other way round would have this gate passing over a tree whose
            // keys descend, which every driver reads by binary search.
            .subvolume(SubvolumeRequest::new(b"/@".to_vec(), [0x66; 16]))
            .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x55; 16]))
            .default_subvolume(b"/@".to_vec()),
    )
    .unwrap_or_else(|e| panic!("this crate refused a subvolume layout: {e}"));

    btrfs_check_clean(&path, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected a filesystem with subvolumes: {e}"));

    // Each subvolume linked from both ends, which is what the checker's root-reference pass
    // above walked — and what a filesystem linked from one end only would have failed on.
    let root_tree = inspect(&path, &["dump-tree", "-t", "root"]);
    for name in ["@", "@home"] {
        for shape in ["root ref key", "root backref key"] {
            assert!(
                root_tree.contains(&format!("{shape} dirid 256 sequence")),
                "{name} is linked as a {shape}:\n{root_tree}"
            );
        }
        assert!(
            root_tree.contains(&format!("name {name}")),
            "{name} is named in the root tree:\n{root_tree}"
        );
    }

    // The bit that says a mount told no subvolume does not land on the top-level tree, and the
    // entry that says which one it lands on instead. Both, because either alone is a filesystem
    // that says one thing and does another.
    let sb = primary(&path);
    assert_ne!(
        u64::from_le_bytes(sb[188..196].try_into().expect("eight bytes")) & (1 << 1),
        0,
        "the default-subvolume feature bit is set"
    );
    assert!(
        root_tree.contains("location key (256 ROOT_ITEM 0)"),
        "the default entry names the subvolume that was asked for:\n{root_tree}"
    );
}

/// A filesystem this crate writes with a name and with two identifiers is one the pinned
/// checker opens.
///
/// Both are things nothing else in this tier reaches, and both are inside what the superblock's
/// checksum covers — so a value written into the wrong field produces an image that verifies
/// perfectly and that the format's own tooling refuses. That is the class of fault only an
/// oracle finds: this crate's reader would have to make the same mistake twice to notice, and
/// on the device identifier it did.
#[test]
#[cfg(feature = "btrfs")]
fn a_name_and_a_second_identifier_reach_the_image_the_way_the_baseline_reads_them() {
    if !suite_ready() {
        return;
    }
    use ferrosys::TreeBuilder;
    use ferrosys::btrfs::{VolumeLabel, format_to};

    let lab = Lab::new();
    let label = VolumeLabel::new("ferrosys-root").expect("a label the field holds");
    let metadata_uuid = [0x77; 16];

    let path = lab.sparse("named.img", ORDINARY);
    let file = File::options()
        .write(true)
        .open(&path)
        .expect("open the destination this gate just created");
    format_to(
        file,
        TreeBuilder::new(),
        ORDINARY,
        writer_options()
            .label(label)
            .metadata_uuid(Some(metadata_uuid)),
    )
    .unwrap_or_else(|e| panic!("this crate refused a named filesystem: {e}"));

    // The checker is what says the two identifiers are in the fields the format puts them in.
    // It refuses to open a filesystem whose device record names the wrong one, which is what
    // makes this a gate rather than a rendering comparison.
    btrfs_check_clean(&path, &["--check-data-csum"])
        .unwrap_or_else(|e| panic!("the checker rejected a named filesystem: {e}"));

    let dumped = inspect(&path, &["dump-super"]);
    for (field, value) in [
        ("label", "ferrosys-root".to_string()),
        ("metadata_uuid", uuid_text(&metadata_uuid)),
        ("dev_item.fsid", uuid_text(&metadata_uuid)),
    ] {
        let read = dumped
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string());
        assert_eq!(
            read.as_deref(),
            Some(value.as_str()),
            "{field} in the baseline's own reading:\n{dumped}"
        );
    }
    // The visible id is still the visible id, which is the whole point of there being two.
    assert!(
        dumped.contains(&uuid_text(&[0x11; 16])),
        "the id a person sees is unchanged:\n{dumped}"
    );
}

/// A 16-byte identifier in the dashed form every btrfs tool prints.
#[cfg(feature = "btrfs")]
fn uuid_text(uuid: &[u8; 16]) -> String {
    let hex = |range: std::ops::Range<usize>| {
        uuid[range]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}
