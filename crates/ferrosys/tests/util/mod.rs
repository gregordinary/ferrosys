//! Helpers shared by every test target that shells out to a foreign implementation.
//!
//! Each file under `tests/` compiles as its own crate, so shared code has to live in
//! a module they all include — without one, every target grows its own copy of these
//! helpers and the copies drift apart in what they report and what they pin. This
//! module is the single copy: how a host tool is probed, how it is invoked, and how
//! a checker's verdict is read.
//!
//! Six upstreams are pinned here, one per family of gate: `e2fsprogs` for ext,
//! `dosfstools` for FAT's formatter and checker, `mtools` for reading and populating a
//! FAT image without a mount, `exfatprogs` for exFAT, relan/exfat's `libexfat` for
//! the one role `exfatprogs` has no tool for — filling a volume — and `btrfs-progs` for
//! btrfs. Every one of them decides whether an image this crate wrote is acceptable, or
//! what an image it must read looks like, so every one is held to an exact version — an
//! upstream that changed its mind between releases would otherwise turn a distribution
//! upgrade into a phantom regression here.
//!
//! `ferrosys-cli/tests/cli.rs` carries its own aligned versions of these helpers,
//! because a crate's packaged tests cannot include a file from a sibling crate's
//! directory. A behavioral change here belongs there too, and the reverse. What is aligned
//! is every rule and not merely the names: the version *marker*, the pinned-tool table with
//! its per-tool probe arguments, the vendored configurations, and the checkers that hand
//! back what the checker said.
//!
//! The copy there carries the subset that crate's gates consult — `e2fsprogs` and
//! `fsck.fat`, not mtools — and the rules are the ones here, so a helper it does not need is
//! absent rather than different.

// Each test target uses its own subset of these helpers; the ones it does not call
// would otherwise fail the dead-code lint in that target alone.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The `e2fsprogs` release the ext gates are written against: the version CI builds
/// from source, and the one whose observed behavior pinned every expected value in
/// these tests. `ci/build-e2fsprogs.sh` builds exactly this version.
pub const E2FSPROGS_VERSION: &str = "1.47.0";

/// The `dosfstools` release the FAT gates are written against, supplying `mkfs.fat`
/// as the byte-equality baseline and `fsck.fat` as the checker.
/// `ci/build-dosfstools.sh` builds exactly this version.
pub const DOSFSTOOLS_VERSION: &str = "4.2";

/// The `mtools` release the FAT gates are written against. `mkfs.fat` cannot populate
/// an image, so mtools is what puts a tree into one and what reads a tree back out of
/// one — this family's counterpart to `debugfs`. `ci/build-mtools.sh` builds exactly
/// this version.
pub const MTOOLS_VERSION: &str = "4.0.49";

/// The `exfatprogs` release the exFAT gates are written against, supplying
/// `mkfs.exfat` as the geometry baseline, `fsck.exfat` as the checker, `tune.exfat` as
/// what pins a volume serial so two formats compare byte for byte, and `dump.exfat`
/// and `exfatlabel` as second readings of what a format wrote.
/// `ci/build-exfatprogs.sh` builds exactly this version.
pub const EXFATPROGS_VERSION: &str = "1.4.2";

/// The relan/exfat release `exfat-populate` is linked against. That project is the
/// second complete implementation of the format, and its `libexfat` is what puts a tree
/// into an exFAT volume — the role `exfatprogs` has no tool for and this family has no
/// mtools for. `ci/build-exfat-populate.sh` builds exactly this version, and the binary
/// it installs reports the library release rather than one of its own.
pub const RELAN_EXFAT_VERSION: &str = "1.4.0";

/// The `btrfs-progs` release the btrfs gates are written against, supplying
/// `mkfs.btrfs` as the baseline — including the `-r` form that fills an image from a
/// directory — `btrfs check` as the hard checker, `btrfs inspect-internal` as the
/// item-level rendering of what a format wrote, `btrfstune` as the suite's own answer to
/// changing a built image's identity, `btrfs-image` as the metadata-only dump, and
/// `btrfs-corrupt-block` as what damages a structure so the checker can be watched
/// rejecting it. `ci/build-btrfs-progs.sh` builds exactly this version.
///
/// The pin decides more here than in the other families. btrfs moves its on-disk
/// *defaults* between releases — this one turned `block-group-tree` on by default and
/// announces it in `mkfs.btrfs`'s own output — so what a gate compares against is a
/// release rather than a format.
pub const BTRFS_PROGS_VERSION: &str = "7.1";

/// A suite whose tools are held to an exact version, and how each of them says so.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    E2fsprogs,
    Dosfstools,
    Mtools,
    Exfatprogs,
    RelanExfat,
    BtrfsProgs,
}

impl Suite {
    fn version(self) -> &'static str {
        match self {
            Suite::E2fsprogs => E2FSPROGS_VERSION,
            Suite::Dosfstools => DOSFSTOOLS_VERSION,
            Suite::Mtools => MTOOLS_VERSION,
            Suite::Exfatprogs => EXFATPROGS_VERSION,
            Suite::RelanExfat => RELAN_EXFAT_VERSION,
            Suite::BtrfsProgs => BTRFS_PROGS_VERSION,
        }
    }

    /// What `name`'s version banner must contain when it is the pinned release.
    ///
    /// A substring rather than a parse, because the four suites agree on nothing
    /// beyond printing a version somewhere: `e2fsprogs` writes
    /// `mke2fs 1.47.0 (5-Feb-2023)`, `dosfstools` writes `mkfs.fat 4.2 (2021-01-31)`,
    /// and mtools writes `mcopy (GNU mtools) 4.0.49`. The trailing character on the
    /// first two is what keeps `4.2` from also matching a hypothetical `4.2.1`.
    ///
    /// `exfatprogs` is the one that does not name the tool at all: every binary in it
    /// prints `exfatprogs version : 1.4.2 (2026-06-15)`, so `name` has nothing to
    /// contribute and a banner cannot say which tool produced it. What establishes that
    /// a tool is present is that running it worked; the banner establishes only which
    /// release it came from.
    ///
    /// `exfat-populate` is the one binary here this project compiles itself, and what it
    /// reports is the *library* release it was linked against — which is the pin that
    /// decides what a volume it fills looks like. Its own source is in this repository
    /// and has no version of its own to drift from.
    ///
    /// `btrfs-progs` names the tool ahead of the suite in every binary but the
    /// multiplexer, which *is* the suite and prints its release alone. It is also the one
    /// suite whose line ends at the version, so the terminator has to be the end of the
    /// line: upstream ships point releases — `v6.16.1` beside `v6.16` — and a bare
    /// `btrfs-progs v7.1` is a prefix of `btrfs-progs v7.1.1`.
    fn marker(self, name: &str) -> String {
        let version = self.version();
        match self {
            Suite::E2fsprogs => format!("{name} {version} "),
            Suite::Dosfstools => format!("{name} {version} ("),
            Suite::Mtools => format!("{name} (GNU mtools) {version}"),
            Suite::Exfatprogs => format!("exfatprogs version : {version} ("),
            Suite::RelanExfat => format!("{name} (relan/exfat) {version}"),
            Suite::BtrfsProgs if name == "btrfs" => format!("btrfs-progs v{version}\n"),
            Suite::BtrfsProgs => format!("{name}, part of btrfs-progs v{version}\n"),
        }
    }
}

/// Every tool a gate consults that ships in a pinned suite, with the arguments that
/// make it print its version banner. Anything absent from this table (`tar`,
/// `python3`, `qemu-system-aarch64`, `btrfs-corrupt-block`) is probed for existence
/// alone and has no pin here.
///
/// `btrfs-corrupt-block` is the one absence that is not an unpinned tool: it ships in a
/// pinned suite and has no version flag or banner of any kind, so there is nothing for
/// this table to match. What holds it to the pin is where the binary came from, and
/// `btrfs_oracle.rs` is where that is asserted, because the answer is one family's
/// rather than a rule for every suite.
///
/// The probe arguments differ per tool because the tools do. `e2fsprogs` answers `-V`
/// throughout. In `dosfstools` only `fatlabel` has a version flag: `mkfs.fat` prints
/// its banner as the last line of `--help`, and `fsck.fat` prints one only when it
/// starts a check, so it is pointed at a device it will fail on and the banner it
/// prints first is the answer. Every mtools name is one binary reading its own
/// `argv[0]`, so they all answer `--version` identically. Every `exfatprogs` binary
/// takes `-V`, and `fsck.exfat` is the one that prints its banner and then exits
/// non-zero for want of a device — which is read here rather than its status, the same
/// way `resize2fs` and `fsck.fat` are.
const PINNED: &[(&str, Suite, &[&str])] = &[
    ("debugfs", Suite::E2fsprogs, &["-V"]),
    ("dumpe2fs", Suite::E2fsprogs, &["-V"]),
    ("e2fsck", Suite::E2fsprogs, &["-V"]),
    ("e2image", Suite::E2fsprogs, &["-V"]),
    ("mke2fs", Suite::E2fsprogs, &["-V"]),
    ("resize2fs", Suite::E2fsprogs, &["-V"]),
    ("tune2fs", Suite::E2fsprogs, &["-V"]),
    ("mkfs.fat", Suite::Dosfstools, &["--help"]),
    ("fsck.fat", Suite::Dosfstools, &["-n", "/dev/null"]),
    ("fatlabel", Suite::Dosfstools, &["--version"]),
    ("mcopy", Suite::Mtools, &["--version"]),
    ("mdir", Suite::Mtools, &["--version"]),
    ("mmd", Suite::Mtools, &["--version"]),
    ("minfo", Suite::Mtools, &["--version"]),
    ("mtype", Suite::Mtools, &["--version"]),
    ("mkfs.exfat", Suite::Exfatprogs, &["-V"]),
    ("fsck.exfat", Suite::Exfatprogs, &["-V"]),
    ("tune.exfat", Suite::Exfatprogs, &["-V"]),
    ("dump.exfat", Suite::Exfatprogs, &["-V"]),
    ("exfatlabel", Suite::Exfatprogs, &["-V"]),
    ("exfat-populate", Suite::RelanExfat, &["--version"]),
    ("mkfs.btrfs", Suite::BtrfsProgs, &["--version"]),
    ("btrfs", Suite::BtrfsProgs, &["--version"]),
    ("btrfstune", Suite::BtrfsProgs, &["--version"]),
    ("btrfs-image", Suite::BtrfsProgs, &["--version"]),
];

fn pinned(name: &str) -> Option<(Suite, &'static [&'static str])> {
    PINNED
        .iter()
        .find(|(tool, _, _)| *tool == name)
        .map(|(_, suite, probe)| (*suite, *probe))
}

/// A host-tool invocation with its environment pinned.
///
/// `LC_ALL=C`, because the gates read tool output — `dumpe2fs` field names, `e2fsck`
/// verdict text, `mdir` listings — and a translated message would fail them for
/// reasons that have nothing to do with the image.
///
/// Two suites additionally get a vendored configuration file, so that what a gate
/// observes is what this project pins rather than what the host distribution happens
/// to be set up for: `mke2fs` gets `ci/mke2fs.conf`, and mtools gets
/// `ci/mtools.conf`. Routing every call site through here is what makes those pins
/// universal.
///
/// Two tools additionally get `TZ=UTC`, for the same reason at two levels of the
/// format. A FAT directory entry stores local time with no zone, so mtools converts on
/// the way in and on the way out; an exFAT entry stores local time *and* the offset it
/// was local to, so `exfat-populate` records the machine's zone in a byte a gate then
/// reads back. Leaving either to the host would make an image's bytes, and a listing's
/// text, depend on where the machine thinks it is.
pub fn tool(name: &str) -> Command {
    let mut cmd = Command::new(name);
    cmd.env("LC_ALL", "C");
    if name == "mke2fs" {
        cmd.env("MKE2FS_CONFIG", mke2fs_config());
    }
    if pinned(name).is_some_and(|(suite, _)| suite == Suite::Mtools) {
        cmd.env("MTOOLSRC", mtools_config());
        cmd.env("TZ", "UTC");
    }
    if pinned(name).is_some_and(|(suite, _)| suite == Suite::RelanExfat) {
        cmd.env("TZ", "UTC");
    }
    cmd
}

/// The vendored `mke2fs.conf`. Every `mke2fs` image is built under it (via [`tool`]),
/// so what the gates compare against is the feature set this project pins rather than
/// the host distribution's defaults.
pub fn mke2fs_config() -> PathBuf {
    ci_dir().join("mke2fs.conf")
}

/// The vendored `mtools.conf`. mtools reads the host's configuration before whatever
/// `MTOOLSRC` names, and the later file wins, so pointing at this one is what makes a
/// machine's own settings unable to change what a gate observes.
pub fn mtools_config() -> PathBuf {
    ci_dir().join("mtools.conf")
}

fn ci_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci")
}

/// Whether `name` is runnable, printing a loud skip banner when it is not.
///
/// A gate that needs a foreign implementation and does not get one has verified
/// nothing, so where the gates are expected to run (CI sets
/// `FERROSYS_REQUIRE_HOST_TOOLS`) a missing tool fails the run outright rather than
/// passing in silence.
///
/// A tool from a pinned suite is also held to that suite's version: under
/// `FERROSYS_REQUIRE_HOST_TOOLS` a different version is a hard failure — the run
/// would otherwise claim an oracle it did not consult — and elsewhere it is reported
/// once per gate, so a local divergence from CI reads as what it is.
pub fn available(name: &str) -> bool {
    // An unpinned tool is asked `-V` and judged on whether anything came back at all.
    let (suite, args) = pinned(name).unwrap_or((Suite::E2fsprogs, &["-V"]));

    // Presence, not success. An exit status says nothing useful here: `-V` is not
    // every tool's version flag, and `fsck.fat` is deliberately pointed at a device it
    // will fail on. Any output means the binary exists and ran, which is the question;
    // the arguments only have to make it exit promptly rather than block on input.
    let Ok(probe) = tool(name).args(args).output() else {
        return missing(name);
    };
    let banner = format!(
        "{}{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    if banner.is_empty() && !probe.status.success() {
        return missing(name);
    }
    if pinned(name).is_some() {
        check_version(name, suite, &banner);
    }
    true
}

/// Report a tool that is not there, and decide whether that ends the run.
fn missing(name: &str) -> bool {
    assert!(
        std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
        "host-tool gate requires `{name}` but it was not found on PATH"
    );
    eprintln!(
        "\n!!! SKIPPING host-tool gate: `{name}` not found on PATH — \
         correctness was NOT verified against the foreign implementation !!!\n"
    );
    false
}

/// Hold a pinned tool's version banner to the release its suite is pinned at.
fn check_version(name: &str, suite: Suite, banner: &str) {
    if banner.contains(&suite.marker(name)) {
        return;
    }
    let version = suite.version();
    assert!(
        std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
        "the gates pin `{name}` at {version} as their oracle, but the one on PATH \
         does not report it. It answered:\n{banner}"
    );
    eprintln!(
        "note: `{name}` is not the {version} the gates are written against — a \
         divergence may not reproduce under CI's pinned oracle"
    );
}

/// Run `e2fsck -fn`: the ground truth that a filesystem is healthy, so that anything
/// the reader objects to is the reader's fault — and, run over an image this crate
/// wrote, the foreign verdict on the writer. The error carries everything the checker
/// said, both streams labeled.
pub fn e2fsck_clean(path: &Path) -> Result<(), String> {
    let out = tool("e2fsck")
        .args(["-f", "-n"])
        .arg(path)
        .output()
        .map_err(|e| format!("spawn e2fsck: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "e2fsck exited {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Run `fsck.fat -n`: the FAT family's counterpart to [`e2fsck_clean`], and the same
/// contract. `-n` answers no to every repair, so the image is never modified and the
/// exit status is a verdict rather than a report of what was fixed.
///
/// The `Ok` case carries what the checker said. A FAT checker's summary line is a
/// count of files and used clusters, which is a second opinion on what an image
/// contains and is worth having where a gate wants to assert it; a caller that does
/// not can ignore it.
pub fn fsck_fat_clean(path: &Path) -> Result<String, String> {
    let out = tool("fsck.fat")
        .arg("-n")
        .arg(path)
        .output()
        .map_err(|e| format!("spawn fsck.fat: {e}"))?;
    let said = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(said)
    } else {
        Err(format!("fsck.fat exited {:?}\n{said}", out.status.code()))
    }
}

/// Run `fsck.exfat -n`: the exFAT family's counterpart to [`e2fsck_clean`], and the
/// same contract. `-n` answers no to every repair, so the image is never modified and
/// the exit status is a verdict rather than a report of what was fixed.
///
/// The `Ok` case carries what the checker said, for the reason [`fsck_fat_clean`]'s
/// does: the summary line counts the directories and files it found, which is a second
/// opinion on what an image contains.
///
/// Every damage a gate here inflicts is answered with status 4, "errors left
/// uncorrected", because `-n` corrects nothing. The distinction that matters is
/// between zero and everything else, so the status is reported rather than matched:
/// 8 is an operation error and 16 a command line this crate got wrong, and reading
/// either as "the image is bad" would turn a broken gate into a finding.
pub fn fsck_exfat_clean(path: &Path) -> Result<String, String> {
    let out = tool("fsck.exfat")
        .arg("-n")
        .arg(path)
        .output()
        .map_err(|e| format!("spawn fsck.exfat: {e}"))?;
    let said = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(said)
    } else {
        Err(format!("fsck.exfat exited {:?}\n{said}", out.status.code()))
    }
}

/// Run `btrfs check`: the btrfs family's counterpart to [`e2fsck_clean`], and the same
/// contract. It repairs nothing unless asked to with `--repair`, so the exit status is a
/// verdict rather than a report of what was fixed and the image is never modified.
///
/// `extra` is what the caller adds ahead of the image — `--check-data-csum` reads every
/// data extent back and verifies it against the checksum tree, which is a second question
/// about the same image and the one gate no other family here has an analogue for.
///
/// The `Ok` case carries what the checker said, for the reason [`fsck_fat_clean`]'s does:
/// the summary counts the bytes it found in each tree, which is a second opinion on what
/// an image contains.
pub fn btrfs_check_clean(path: &Path, extra: &[&str]) -> Result<String, String> {
    let out = tool("btrfs")
        .arg("check")
        .args(extra)
        .arg(path)
        .output()
        .map_err(|e| format!("spawn btrfs check: {e}"))?;
    let said = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(said)
    } else {
        Err(format!(
            "btrfs check exited {:?}\n{said}",
            out.status.code()
        ))
    }
}

/// Run `exfat-populate` over `image`, driving it with `script`.
///
/// This is the exFAT family's counterpart to `mcopy`: what puts a tree into a volume
/// this crate did not write, so a reader can be asked to read an image whose every
/// layout decision belongs to another implementation. `exfatprogs` has no tool for it —
/// a `mkfs.exfat` volume holds a label, a reserved slot, a bitmap, and an up-case table,
/// and never a file — so the second implementation of the format is what fills one.
///
/// The script's grammar is documented in `ci/exfat-populate.c`. It is handed over on
/// standard input rather than through a file, so a gate's tree is written where the gate
/// reads it and there is no temporary path to clean up.
///
/// The error carries everything the program said, which is where `libexfat`'s own
/// diagnostics come out.
pub fn exfat_populate(image: &Path, script: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = tool("exfat-populate")
        .arg(image)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn exfat-populate: {e}"))?;
    child
        .stdin
        .take()
        .expect("the child was spawned with a piped standard input")
        .write_all(script.as_bytes())
        .map_err(|e| format!("write the script to exfat-populate: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait for exfat-populate: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "exfat-populate exited {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}
