//! Helpers shared by every test target that shells out to the `e2fsprogs` oracles.
//!
//! Each file under `tests/` compiles as its own crate, so shared code has to live in
//! a module they all include — without one, every target grows its own copy of these
//! helpers and the copies drift apart in what they report and what they pin. This
//! module is the single copy: how a host tool is probed, how it is invoked, and how
//! `e2fsck`'s verdict is read.
//!
//! `ferrosys-cli/tests/cli.rs` carries its own aligned versions of these helpers,
//! because a crate's packaged tests cannot include a file from a sibling crate's
//! directory. A behavioral change here belongs there too.

// Each test target uses its own subset of these helpers; the ones it does not call
// would otherwise fail the dead-code lint in that target alone.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The `e2fsprogs` release the gates are written against: the version CI builds from
/// source, and the one whose observed behavior pinned every expected value in these
/// tests. `ci/build-e2fsprogs.sh` builds exactly this version.
pub const E2FSPROGS_VERSION: &str = "1.47.0";

/// The tools that ship in `e2fsprogs` and so are held to [`E2FSPROGS_VERSION`].
/// Anything else (`tar`, `python3`, `qemu-system-aarch64`) has no version pin.
const E2FSPROGS_TOOLS: &[&str] = &[
    "debugfs",
    "dumpe2fs",
    "e2fsck",
    "e2image",
    "mke2fs",
    "resize2fs",
    "tune2fs",
];

/// A host-tool invocation with its environment pinned.
///
/// `LC_ALL=C`, because the gates read tool output — `dumpe2fs` field names, `e2fsck`
/// verdict text — and a translated message would fail them for reasons that have
/// nothing to do with the image. `mke2fs` additionally gets the vendored
/// configuration, so the feature set an oracle image carries is the project's, not
/// whatever the host distribution enables; routing every call site through here is
/// what makes that pin universal.
pub fn tool(name: &str) -> Command {
    let mut cmd = Command::new(name);
    cmd.env("LC_ALL", "C");
    if name == "mke2fs" {
        cmd.env("MKE2FS_CONFIG", mke2fs_config());
    }
    cmd
}

/// The vendored `mke2fs.conf`. Every `mke2fs` image is built under it (via [`tool`]),
/// so what the gates compare against is the feature set this project pins rather than
/// the host distribution's defaults.
pub fn mke2fs_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/mke2fs.conf")
}

/// Whether `name` is runnable, printing a loud skip banner when it is not.
///
/// A gate that needs a foreign implementation and does not get one has verified
/// nothing, so where the gates are expected to run (CI sets
/// `FERROSYS_REQUIRE_HOST_TOOLS`) a missing tool fails the run outright rather than
/// passing in silence.
///
/// An `e2fsprogs` tool is also held to [`E2FSPROGS_VERSION`]: under
/// `FERROSYS_REQUIRE_HOST_TOOLS` a different version is a hard failure — the run
/// would otherwise claim an oracle it did not consult — and elsewhere it is reported
/// once per gate, so a local divergence from CI reads as what it is.
pub fn available(name: &str) -> bool {
    // The probe only asks whether the binary exists and runs, so any output — a
    // version line, or a complaint that `-V` is not its flag — counts as present; the
    // flag just has to make the tool exit promptly rather than block on input. `-V`
    // is the e2fsprogs version flag, and the tools that spell it `--version` instead
    // answer `-V` with a prompt exit all the same.
    let probe = tool(name).arg("-V").output();
    let ok = probe
        .as_ref()
        .map(|o| o.status.success() || !o.stderr.is_empty() || !o.stdout.is_empty())
        .unwrap_or(false);
    if !ok {
        assert!(
            std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
            "host-tool gate requires `{name}` but it was not found on PATH"
        );
        eprintln!(
            "\n!!! SKIPPING host-tool gate: `{name}` not found on PATH — \
             correctness was NOT verified against the foreign implementation !!!\n"
        );
        return false;
    }
    if E2FSPROGS_TOOLS.contains(&name) {
        check_version(name, &probe.expect("probed above"));
    }
    true
}

/// Hold an `e2fsprogs` tool's `-V` banner to the pinned oracle version.
fn check_version(name: &str, probe: &Output) {
    // The banner is "<name> 1.47.0 (5-Feb-2023)", on stderr for the whole family; the
    // version is the token after the tool's own name.
    let banner = format!(
        "{}{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    let version = banner
        .split_whitespace()
        .skip_while(|t| *t != name)
        .nth(1)
        .unwrap_or("unknown");
    if version == E2FSPROGS_VERSION {
        return;
    }
    assert!(
        std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
        "the gates pin e2fsprogs {E2FSPROGS_VERSION} as their oracle, \
         but `{name}` reports {version}"
    );
    eprintln!(
        "note: `{name}` is version {version}, not the {E2FSPROGS_VERSION} the gates are \
         written against — a divergence may not reproduce under CI's pinned oracle"
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
