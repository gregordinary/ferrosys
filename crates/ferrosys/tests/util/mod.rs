//! Helpers shared by every test target that shells out to a foreign implementation.
//!
//! Each file under `tests/` compiles as its own crate, so shared code has to live in
//! a module they all include — without one, every target grows its own copy of these
//! helpers and the copies drift apart in what they report and what they pin. This
//! module is the single copy: how a host tool is probed, how it is invoked, and how
//! a checker's verdict is read.
//!
//! Three suites are pinned here, one per family of gate: `e2fsprogs` for ext,
//! `dosfstools` for FAT's formatter and checker, and `mtools` for reading and
//! populating a FAT image without a mount. Every one of them decides whether an image
//! this crate wrote is acceptable, so every one is held to an exact version — a
//! checker that changed its mind between releases would otherwise turn a distribution
//! upgrade into a phantom regression here.
//!
//! `ferrosys-cli/tests/cli.rs` carries its own aligned versions of these helpers,
//! because a crate's packaged tests cannot include a file from a sibling crate's
//! directory. A behavioral change here belongs there too.

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

/// A suite whose tools are held to an exact version, and how each of them says so.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    E2fsprogs,
    Dosfstools,
    Mtools,
}

impl Suite {
    fn version(self) -> &'static str {
        match self {
            Suite::E2fsprogs => E2FSPROGS_VERSION,
            Suite::Dosfstools => DOSFSTOOLS_VERSION,
            Suite::Mtools => MTOOLS_VERSION,
        }
    }

    /// What `name`'s version banner must contain when it is the pinned release.
    ///
    /// A substring rather than a parse, because the three suites agree on nothing
    /// beyond printing their name and their version somewhere: `e2fsprogs` writes
    /// `mke2fs 1.47.0 (5-Feb-2023)`, `dosfstools` writes `mkfs.fat 4.2 (2021-01-31)`,
    /// and mtools writes `mcopy (GNU mtools) 4.0.49`. The trailing character on the
    /// first two is what keeps `4.2` from also matching a hypothetical `4.2.1`.
    fn marker(self, name: &str) -> String {
        let version = self.version();
        match self {
            Suite::E2fsprogs => format!("{name} {version} "),
            Suite::Dosfstools => format!("{name} {version} ("),
            Suite::Mtools => format!("{name} (GNU mtools) {version}"),
        }
    }
}

/// Every tool a gate consults that ships in a pinned suite, with the arguments that
/// make it print its version banner. Anything absent from this table (`tar`,
/// `python3`, `qemu-system-aarch64`) is probed for existence alone and has no pin.
///
/// The probe arguments differ per tool because the tools do. `e2fsprogs` answers `-V`
/// throughout. In `dosfstools` only `fatlabel` has a version flag: `mkfs.fat` prints
/// its banner as the last line of `--help`, and `fsck.fat` prints one only when it
/// starts a check, so it is pointed at a device it will fail on and the banner it
/// prints first is the answer. Every mtools name is one binary reading its own
/// `argv[0]`, so they all answer `--version` identically.
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
/// mtools also gets `TZ=UTC`. A FAT directory entry stores local time with no zone,
/// so mtools converts on the way in and on the way out; leaving that to the host's
/// zone would make an image's bytes, and a listing's text, depend on where the
/// machine thinks it is.
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
