//! End-to-end gates for the `ferrosys` binary: it is run as a process, over real files,
//! and judged by what it wrote and the code it exited with.
//!
//! Where a gate needs a host tool — `e2fsck` to check an image, `dumpe2fs` to say what is
//! in it, GNU `tar` to read our archive, `python3` to parse our JSON — it declares the
//! tool and fails loudly when it is missing rather than passing in silence. The whole
//! point of these gates is that a foreign implementation agrees with us, so a gate that
//! quietly skipped the foreign half would be worse than no gate at all.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The binary under test, built by cargo before the test runs.
const FERROSYS: &str = env!("CARGO_BIN_EXE_ferrosys");

const UUID: &str = "f0e17055-0000-4000-8000-000000000000";
const TIME: &str = "1700000000";

// The host-tool helpers below — `tool`, `available`, the version pin, the checkers — mirror
// `ferrosys/tests/util/mod.rs`, function for function and rule for rule. They are a copy
// rather than an include because a crate's packaged tests cannot include a file from a
// sibling crate's directory; a behavioral change here belongs there too, and the reverse.

/// The `e2fsprogs` release the ext gates are written against: the version CI builds from
/// source, and the one whose observed behavior pinned every expected value in these tests.
const E2FSPROGS_VERSION: &str = "1.47.0";

/// The `dosfstools` release the FAT gates are written against, supplying `fsck.fat` as the
/// checker for the volumes they write.
const DOSFSTOOLS_VERSION: &str = "4.2";

/// The `exfatprogs` release the exFAT gates are written against, supplying `fsck.exfat` as
/// the checker for the volumes they write and `mkfs.exfat` as the formatter for the one
/// volume here that this tool did not write.
const EXFATPROGS_VERSION: &str = "1.4.2";

/// The relan/exfat release `exfat-populate` is linked against — the second complete
/// implementation of exFAT, and what puts a tree into a volume this tool had no hand in.
const RELAN_EXFAT_VERSION: &str = "1.4.0";

/// The `btrfs-progs` release the btrfs gate is written against, supplying `mkfs.btrfs` —
/// which both lays out the filesystem and fills it from a directory, so this family's foreign
/// fixture needs one tool where exFAT's needs two.
///
/// This family's binary is read-only, so there is no volume here it wrote and nothing for a
/// checker to accept: every btrfs the tool is pointed at is one it had no hand in.
const BTRFS_PROGS_VERSION: &str = "7.1";

/// A suite whose tools are held to an exact version, and how each of them says so.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    E2fsprogs,
    Dosfstools,
    Exfatprogs,
    RelanExfat,
    BtrfsProgs,
}

impl Suite {
    fn version(self) -> &'static str {
        match self {
            Suite::E2fsprogs => E2FSPROGS_VERSION,
            Suite::Dosfstools => DOSFSTOOLS_VERSION,
            Suite::Exfatprogs => EXFATPROGS_VERSION,
            Suite::RelanExfat => RELAN_EXFAT_VERSION,
            Suite::BtrfsProgs => BTRFS_PROGS_VERSION,
        }
    }

    /// What `name`'s version banner must contain when it is the pinned release.
    ///
    /// A substring rather than a parse, because the suites agree on nothing beyond printing
    /// their name and their version somewhere: `e2fsprogs` writes `mke2fs 1.47.0 (5-Feb-2023)`
    /// and `dosfstools` writes `fsck.fat 4.2 (2021-01-31)`. The trailing character is what
    /// keeps `4.2` from also matching a hypothetical `4.2.1`.
    fn marker(self, name: &str) -> String {
        let version = self.version();
        match self {
            Suite::E2fsprogs => format!("{name} {version} "),
            Suite::Dosfstools => format!("{name} {version} ("),
            // `exfatprogs` names itself and not the binary: every tool in it prints
            // `exfatprogs version : 1.4.2 (…)`, so there is no tool name to match on.
            Suite::Exfatprogs => format!("exfatprogs version : {version} ("),
            // The populator reports the library release it was linked against, since that is
            // what decides how a volume comes out. Its own source is in this tree.
            Suite::RelanExfat => format!("{name} (relan/exfat) {version}"),
            // `btrfs-progs` names the tool ahead of the suite, so the banner carries both.
            Suite::BtrfsProgs => format!("{name}, part of btrfs-progs v{version}\n"),
        }
    }
}

/// Every tool a gate consults that ships in a pinned suite, with the arguments that make it
/// print its version banner. Anything absent from this table (`tar`, `python3`, `getfattr`)
/// is probed for existence alone and has no pin.
///
/// The probe arguments differ per tool because the tools do. `e2fsprogs` answers `-V`
/// throughout; `fsck.fat` prints a banner only when it starts a check, so it is pointed at a
/// device it will fail on and the banner it prints first is the answer.
const PINNED: &[(&str, Suite, &[&str])] = &[
    ("debugfs", Suite::E2fsprogs, &["-V"]),
    ("dumpe2fs", Suite::E2fsprogs, &["-V"]),
    ("e2fsck", Suite::E2fsprogs, &["-V"]),
    ("mke2fs", Suite::E2fsprogs, &["-V"]),
    ("resize2fs", Suite::E2fsprogs, &["-V"]),
    ("fsck.fat", Suite::Dosfstools, &["-n", "/dev/null"]),
    ("mkfs.exfat", Suite::Exfatprogs, &["-V"]),
    ("fsck.exfat", Suite::Exfatprogs, &["-V"]),
    ("exfat-populate", Suite::RelanExfat, &["--version"]),
    ("mkfs.btrfs", Suite::BtrfsProgs, &["--version"]),
];

fn pinned(name: &str) -> Option<(Suite, &'static [&'static str])> {
    PINNED
        .iter()
        .find(|(tool, _, _)| *tool == name)
        .map(|(_, suite, probe)| (*suite, *probe))
}

/// A host-tool invocation with its environment pinned.
///
/// `LC_ALL=C`, because the gates read tool output — `dumpe2fs` field names, `tar` listings —
/// and a translated message would fail them for reasons that have nothing to do with the
/// image. `mke2fs` additionally gets the vendored configuration, so the feature set an oracle
/// image carries is the project's, not whatever the host distribution enables.
fn tool(name: &str) -> Command {
    let mut cmd = Command::new(name);
    cmd.env("LC_ALL", "C");
    if name == "mke2fs" {
        cmd.env("MKE2FS_CONFIG", mke2fs_config());
    }
    cmd
}

/// The vendored `mke2fs.conf`, applied at every `mke2fs` call site via [`tool`].
fn mke2fs_config() -> PathBuf {
    ci_dir().join("mke2fs.conf")
}

fn ci_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci")
}

/// Whether `name` is runnable, printing a loud skip banner when it is not.
///
/// A gate that needs a foreign implementation and does not get one has verified nothing, so
/// where the gates are expected to run (CI sets `FERROSYS_REQUIRE_HOST_TOOLS`) a missing tool
/// fails the run outright rather than passing in silence.
///
/// A tool from a pinned suite is also held to that suite's version: under
/// `FERROSYS_REQUIRE_HOST_TOOLS` a different version is a hard failure — the run would
/// otherwise claim an oracle it did not consult — and elsewhere it is reported once per gate,
/// so a local divergence from CI reads as what it is.
fn available(name: &str) -> bool {
    // An unpinned tool is asked `-V` and judged on whether anything came back at all.
    let (suite, args) = pinned(name).unwrap_or((Suite::E2fsprogs, &["-V"]));

    // Presence, not success. An exit status says nothing useful here: `-V` is not every
    // tool's version flag, and `fsck.fat` is deliberately pointed at a device it will fail
    // on. Any output means the binary exists and ran, which is the question; the arguments
    // only have to make it exit promptly rather than block on input.
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

/// The exit codes the tool contracts to, mirroring `e2fsck`'s.
const OK: i32 = 0;
const IMAGE_BAD: i32 = 4;
const OPERATIONAL: i32 = 8;
const USAGE: i32 = 16;

/// Run the tool and hand back everything it produced.
fn run(args: &[&str]) -> Output {
    Command::new(FERROSYS)
        .args(args)
        .output()
        .expect("the binary runs")
}

/// Run the tool, feeding `input` to its standard input.
fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(FERROSYS)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input)
        .expect("write the input");
    child.wait_with_output().expect("the binary finishes")
}

/// The exit code a run reported.
fn code(out: &Output) -> i32 {
    out.status.code().expect("the process exited normally")
}

/// A run that must succeed, with its standard output.
fn ok(args: &[&str]) -> Vec<u8> {
    let out = run(args);
    assert_eq!(
        code(&out),
        OK,
        "`ferrosys {}` failed:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// A scratch directory that lives as long as the test.
fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("a scratch directory")
}

/// The path to a file in the scratch directory, as the tool takes it.
fn at(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

/// Format an image of `size` from `archive`, if one is given.
fn format(image: &Path, size: &str, archive: Option<&Path>) -> Output {
    let image = image.to_str().expect("a text path");
    let mut args = vec![
        "format", "--size", size, "--uuid", UUID, "--time", TIME, image,
    ];
    let archive = archive.map(|a| a.to_str().expect("a text path").to_string());
    if let Some(a) = &archive {
        args.insert(1, "--from-tar");
        args.insert(2, a);
    }
    run(&args)
}

/// A tar archive carrying the whole fidelity list: ownership and modes, times to the
/// nanosecond, a fast and a slow symlink, a hard link, device and FIFO nodes, extended
/// attributes inline and in a block, POSIX ACLs, and a directory large enough that the
/// filesystem must index it by hash rather than scan it.
fn fidelity_archive() -> Vec<u8> {
    use tar::{Builder, EntryType, Header};

    let mut b = Builder::new(Vec::new());

    // A directory, a file in it, and the modes and owners that must survive.
    let push = |b: &mut Builder<Vec<u8>>,
                records: Vec<(&str, Vec<u8>)>,
                kind: EntryType,
                path: &str,
                mode: u32,
                uid: u64,
                gid: u64,
                link: Option<&str>,
                device: Option<(u32, u32)>,
                data: &[u8]| {
        let mut recs: Vec<(String, Vec<u8>)> = records
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        recs.push(("path".to_string(), path.as_bytes().to_vec()));
        if let Some(l) = link {
            recs.push(("linkpath".to_string(), l.as_bytes().to_vec()));
        }
        let borrowed: Vec<(&str, &[u8])> = recs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        b.append_pax_extensions(borrowed).expect("pax records");

        let mut h = Header::new_ustar();
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_uid(uid);
        h.set_gid(gid);
        h.set_mtime(1_700_000_000);
        // The ustar header holds 100 bytes of path and of link target. A value longer
        // than that is left out of the header, exactly as the tool itself leaves it out:
        // the PAX record above carries it, and every reader that honours PAX — GNU tar,
        // bsdtar, and the archive source under test — reads it from there.
        let _ = h.set_path(path);
        if let Some(l) = link {
            let _ = h.set_link_name(l);
        }
        if let Some((major, minor)) = device {
            h.set_device_major(major).expect("a major number");
            h.set_device_minor(minor).expect("a minor number");
        }
        h.set_size(data.len() as u64);
        h.set_cksum();
        b.append(&h, data).expect("append");
    };

    // The archive's own root member: the filesystem root's mode and ownership.
    push(
        &mut b,
        vec![],
        EntryType::Directory,
        "./",
        0o755,
        0,
        0,
        None,
        None,
        &[],
    );
    push(
        &mut b,
        vec![],
        EntryType::Directory,
        "./etc/",
        0o755,
        0,
        0,
        None,
        None,
        &[],
    );
    // A file with a sub-second time and a non-root owner, carrying an inline attribute.
    push(
        &mut b,
        vec![
            ("mtime", b"1700000000.123456789".to_vec()),
            ("atime", b"1600000000".to_vec()),
            ("ctime", b"1650000000".to_vec()),
            ("SCHILY.xattr.user.note", b"hello".to_vec()),
        ],
        EntryType::Regular,
        "./etc/hostname",
        0o644,
        1000,
        1000,
        None,
        None,
        b"ferrosys\n",
    );
    // A value too large for the inode spills into an external attribute block.
    push(
        &mut b,
        vec![("SCHILY.xattr.user.big", vec![0xcd; 400])],
        EntryType::Regular,
        "./etc/big",
        0o600,
        0,
        0,
        None,
        None,
        &vec![b'x'; 5000],
    );
    // A directory carrying both a POSIX access ACL and a default one, in the version-2
    // form `getxattr` returns — which is what an archiver copies into an archive.
    push(
        &mut b,
        vec![
            ("SCHILY.xattr.system.posix_acl_access", acl_v2_access()),
            ("SCHILY.xattr.system.posix_acl_default", acl_v2_default()),
        ],
        EntryType::Directory,
        "./home/",
        0o750,
        1000,
        1000,
        None,
        None,
        &[],
    );
    // A fast symlink (inline in the inode) and a slow one (in a block).
    push(
        &mut b,
        vec![],
        EntryType::Symlink,
        "./etc/mtab",
        0o777,
        0,
        0,
        Some("/proc/self/mounts"),
        None,
        &[],
    );
    let long_target = "/".to_string() + &"p".repeat(120);
    push(
        &mut b,
        vec![],
        EntryType::Symlink,
        "./etc/long",
        0o777,
        0,
        0,
        Some(&long_target),
        None,
        &[],
    );
    // A hard link: a second name for a file already in the archive.
    push(
        &mut b,
        vec![],
        EntryType::Link,
        "./etc/hostname.link",
        0o644,
        1000,
        1000,
        Some("./etc/hostname"),
        None,
        &[],
    );
    // Device and FIFO nodes.
    push(
        &mut b,
        vec![],
        EntryType::Directory,
        "./dev/",
        0o755,
        0,
        0,
        None,
        None,
        &[],
    );
    push(
        &mut b,
        vec![],
        EntryType::Char,
        "./dev/null",
        0o666,
        0,
        0,
        None,
        Some((1, 3)),
        &[],
    );
    push(
        &mut b,
        vec![],
        EntryType::Block,
        "./dev/sda",
        0o660,
        0,
        6,
        None,
        Some((8, 0)),
        &[],
    );
    push(
        &mut b,
        vec![],
        EntryType::Fifo,
        "./dev/initctl",
        0o600,
        0,
        0,
        None,
        None,
        &[],
    );
    // A directory of more than a thousand names, which no linear directory holds: the
    // filesystem must index it by hash, and reading it back must walk that index.
    push(
        &mut b,
        vec![],
        EntryType::Directory,
        "./many/",
        0o755,
        0,
        0,
        None,
        None,
        &[],
    );
    for i in 0..1200 {
        push(
            &mut b,
            vec![],
            EntryType::Regular,
            &format!("./many/file-{i:05}"),
            0o644,
            0,
            0,
            None,
            None,
            format!("{i}").as_bytes(),
        );
    }

    b.into_inner().expect("finish the archive")
}

/// The version-2 `posix_acl_xattr` bytes for an access ACL naming a user: owner rwx, user
/// 1000 rw-, owning group r-x, mask rwx, other r--.
fn acl_v2_access() -> Vec<u8> {
    vec![
        0x02, 0x00, 0x00, 0x00, // a_version = 2
        0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
        0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw-
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
        0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
        0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
    ]
}

/// The version-2 bytes for a minimal default ACL, which only a directory may carry.
fn acl_v2_default() -> Vec<u8> {
    vec![
        0x02, 0x00, 0x00, 0x00, // a_version = 2
        0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
        0x20, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r-x
    ]
}

/// Write the fidelity archive into the scratch directory.
fn write_archive(dir: &tempfile::TempDir) -> PathBuf {
    let path = at(dir, "source.tar");
    std::fs::write(&path, fidelity_archive()).expect("write the archive");
    path
}

// ---------------------------------------------------------------------------
// format
// ---------------------------------------------------------------------------

#[test]
fn a_formatted_image_checks_clean_and_is_reproducible() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    let out = format(&image, "64M", None);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    // The summary is a diagnostic, so it goes to the standard error: the artifact of a
    // format is the image, and the standard output stays clear for one the caller asked
    // for.
    assert!(out.stdout.is_empty(), "nothing goes to the standard output");
    assert!(String::from_utf8_lossy(&out.stderr).contains("Filesystem UUID:"));

    // The same inputs write the same bytes. Nothing in the tool reads the clock or a
    // random source, so this holds without a flag asking for it.
    let again = at(&dir, "again.img");
    assert_eq!(code(&format(&again, "64M", None)), OK);
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&again).expect("read"),
        "two formats from the same inputs wrote different bytes"
    );

    if !available("e2fsck") {
        return;
    }
    e2fsck_clean(&image);
}

#[test]
fn an_image_built_from_an_archive_checks_clean() {
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    let out = format(&image, "128M", Some(&archive));
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    if !available("e2fsck") {
        return;
    }
    e2fsck_clean(&image);
}

/// Assert `e2fsck -fn` finds nothing to fault, reporting both streams labeled.
fn e2fsck_clean(image: &Path) {
    if let Err(report) = checked(tool("e2fsck").args(["-f", "-n"]).arg(image), "e2fsck") {
        panic!("e2fsck faulted the image\n{report}");
    }
}

/// Run a checker and hand back what it said, or the whole of its complaint when it refused.
///
/// The `Ok` case carries the checker's own summary, which is a second opinion on what an
/// image contains and is worth asserting on where a gate wants it. This is the shape
/// `ferrosys/tests/util/mod.rs` uses, so a gate written against one harness reads the same
/// against the other.
fn checked(cmd: &mut Command, name: &str) -> Result<String, String> {
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }
    Err(format!(
        "{name} exited {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    ))
}

// Walking a tree records Linux inode metadata and Linux extended attributes, so the
// library builds its directory source on Linux alone and `--from-dir` is carried out
// there. The gate below this one is the other half of that contract.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn an_image_built_from_a_directory_holds_what_the_tree_held() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch();
    let tree = at(&dir, "staging");
    std::fs::create_dir(&tree).expect("staging");
    std::fs::create_dir(tree.join("etc")).expect("etc");
    std::fs::write(tree.join("etc/hostname"), b"ferrosys\n").expect("hostname");
    let init = tree.join("etc/init");
    std::fs::write(&init, b"#!/bin/sh\n").expect("init");
    std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::os::unix::fs::symlink("/proc/self/mounts", tree.join("etc/mtab")).expect("mtab");

    let image = at(&dir, "fs.img");
    let out = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--from-dir",
        tree.to_str().expect("a text path"),
        // A test run does not run as root, so without this the image would be owned by
        // whoever ran it.
        "--owner",
        "0:0",
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    let image = image.to_str().expect("a text path");
    // The contents are the tree's.
    assert_eq!(
        ok(&["extract", image, "--cat", "/etc/hostname"]),
        b"ferrosys\n"
    );
    // The mode survived, and the ownership override reached the inode.
    let stat = String::from_utf8(ok(&["extract", image, "--stat", "/etc/init", "--json"]))
        .expect("the report is text");
    assert!(stat.contains("\"mode_octal\":\"0755\""), "{stat}");
    assert!(stat.contains("\"uid\":0"), "{stat}");
    assert!(stat.contains("\"gid\":0"), "{stat}");
    // A symlink is the link it is, not what it points at.
    let stat = String::from_utf8(ok(&["extract", image, "--stat", "/etc/mtab", "--json"]))
        .expect("the report is text");
    assert!(stat.contains("\"target\":\"/proc/self/mounts\""), "{stat}");

    if available("e2fsck") {
        e2fsck_clean(Path::new(image));
    }
}

// The round trip in the tool's own terms: a tree in, an image, and the tree back out.
// Both halves are Linux's, since walking and writing a tree both touch Linux inode
// metadata and Linux extended attributes.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn a_tree_survives_a_round_trip_through_an_image() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = scratch();
    let tree = at(&dir, "staging");
    std::fs::create_dir_all(tree.join("etc")).expect("etc");
    std::fs::create_dir_all(tree.join("var/empty")).expect("var/empty");
    std::fs::write(tree.join("etc/hostname"), b"ferrosys\n").expect("hostname");
    let init = tree.join("etc/init");
    std::fs::write(&init, b"#!/bin/sh\nexec /sbin/init\n").expect("init");
    std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    std::fs::hard_link(&init, tree.join("etc/init-alias")).expect("hard link");
    std::os::unix::fs::symlink("/proc/self/mounts", tree.join("etc/mtab")).expect("mtab");

    // No --owner: the tree is this process's, so writing it back needs no privilege, and
    // what is being checked is fidelity rather than ownership.
    let image = at(&dir, "fs.img");
    let out = run(&[
        "format",
        "--size",
        "auto",
        "--slack",
        "10%",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--from-dir",
        tree.to_str().expect("a text path"),
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    // The destination is made by the tool, so a caller names where the tree goes rather
    // than preparing the place first.
    let unpacked = at(&dir, "unpacked");
    let out = run(&[
        "extract",
        image.to_str().expect("a text path"),
        "--to-dir",
        unpacked.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    let summary = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(summary.contains("Names written:"), "{summary}");

    // The tree that came back is the tree that went in: names, contents, modes, and the
    // sharing a hard link expresses.
    let names = |root: &Path| {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read") {
                let path = entry.expect("entry").path();
                if std::fs::symlink_metadata(&path).expect("stat").is_dir() {
                    pending.push(path.clone());
                }
                found.push(
                    path.strip_prefix(root)
                        .expect("under the root")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        found.sort();
        found
    };
    assert_eq!(names(&tree), names(&unpacked));
    assert_eq!(
        std::fs::read(unpacked.join("etc/init")).expect("read"),
        b"#!/bin/sh\nexec /sbin/init\n"
    );
    let mode = std::fs::symlink_metadata(unpacked.join("etc/init"))
        .expect("stat")
        .mode();
    assert_eq!(mode & 0o7777, 0o750);
    assert_eq!(
        std::fs::read_link(unpacked.join("etc/mtab")).expect("read the link"),
        Path::new("/proc/self/mounts")
    );
    assert_eq!(
        std::fs::symlink_metadata(unpacked.join("etc/init"))
            .expect("stat")
            .ino(),
        std::fs::symlink_metadata(unpacked.join("etc/init-alias"))
            .expect("stat")
            .ino(),
        "the two names did not come back as one file"
    );
    // Nothing the filesystem makes for itself is written into the tree.
    assert!(!unpacked.join("lost+found").exists());

    // And the tree that came back builds the same image the first one did, which is the
    // round trip closing: --from-dir over the extraction, byte for byte.
    let again = at(&dir, "again.img");
    let out = run(&[
        "format",
        "--size",
        "auto",
        "--slack",
        "10%",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--from-dir",
        unpacked.to_str().expect("a text path"),
        again.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    // A destination that already holds something is refused, and the tree that is there
    // is left alone.
    let out = run(&[
        "extract",
        image.to_str().expect("a text path"),
        "--to-dir",
        unpacked.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), OPERATIONAL);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not empty"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    if available("e2fsck") {
        e2fsck_clean(&image);
        e2fsck_clean(&again);
    }
}

// The other half: where there is no directory source, `--from-dir` says so and the
// destination is left alone, the same as every other planning failure.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn from_dir_is_refused_where_there_is_no_directory_source() {
    let dir = scratch();
    let tree = at(&dir, "staging");
    std::fs::create_dir(&tree).expect("staging");

    let image = at(&dir, "fs.img");
    let out = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--from-dir",
        tree.to_str().expect("a text path"),
        image.to_str().expect("a text path"),
    ]);
    // Not a usage error: the command line is understood, and the tool cannot carry it out.
    assert_eq!(
        code(&out),
        OPERATIONAL,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--from-dir"), "{said}");
    assert!(said.contains("--from-tar"), "{said}");
    // The refusal happens while planning, so nothing was created at the destination.
    assert!(!image.exists(), "the destination was created anyway");
}

#[test]
fn format_writes_the_selected_base_profile() {
    // `-t` makes ext2 and ext3 first-class on the command line: one flag seeds the base
    // feature set, the image checks clean, and `inspect` reads the profile back as the one
    // that was asked for. The whole ext lineage the writer emits is reachable this way.
    let dir = scratch();
    for profile in ["ext2", "ext3", "ext4"] {
        let image = at(&dir, &format!("{profile}.img"));
        let path = image.to_str().expect("a text path");
        let out = run(&[
            "format", "-t", profile, "--size", "64M", "--uuid", UUID, "--time", TIME, path,
        ]);
        assert_eq!(
            code(&out),
            OK,
            "format -t {profile} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The realized profile is in the format summary and read back by inspect alike.
        let summary = fields(&String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            summary["Filesystem profile"], profile,
            "the format summary names the profile it wrote"
        );
        let report = fields(&String::from_utf8_lossy(&ok(&["inspect", path])));
        assert_eq!(
            report["Filesystem family"], "ext",
            "inspect names the family in the report's head"
        );
        assert_eq!(
            report["Filesystem variant"], profile,
            "inspect labels the {profile} image as {profile}"
        );

        if available("e2fsck") {
            e2fsck_clean(&image);
        }
    }
}

#[test]
fn format_refuses_a_destination_that_is_not_a_regular_file() {
    // A format writes only the blocks the filesystem uses, so every byte it does not
    // write must already read as zero. A directory is not a regular file, and neither is
    // a device; the tool refuses both rather than writing a filesystem into whatever was
    // already there.
    let dir = scratch();
    let out = format(dir.path(), "64M", None);
    assert_eq!(code(&out), OPERATIONAL);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a regular file"),
        "the refusal says why: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_failed_format_leaves_the_destination_exactly_as_it_was() {
    // The destination must read as zero where the filesystem does not write, so creating or
    // truncating it is part of formatting. That makes the *order* load-bearing: a run that
    // truncated first and then failed on its source would destroy an image while writing no
    // filesystem — and re-running a format line with one option edited, over the image you
    // already have, is exactly how that happens.
    let dir = scratch();
    let image = at(&dir, "keep.img");
    assert_eq!(code(&format(&image, "16M", None)), OK);
    let sound = std::fs::read(&image).expect("read the image that must survive");

    // Every failure mode that is not the destination's own I/O, one per line of defence:
    // a source that does not parse, a geometry too small to hold its own metadata, a
    // feature set that contradicts itself, and a size below the journal's minimum.
    let bad_archive = at(&dir, "bad.tar");
    std::fs::write(&bad_archive, b"not a tar, just bytes").expect("write");
    let failures: [Vec<&str>; 4] = [
        vec!["--from-tar", bad_archive.to_str().unwrap()],
        vec!["--size", "4M", "--grow", "8T"],
        vec!["-O", "metadata_csum_seed,^metadata_csum"],
        vec!["--size", "4M"],
    ];
    for extra in failures {
        let mut args = vec!["format", "--size", "16M", "--uuid", UUID, "--time", TIME];
        args.extend_from_slice(&extra);
        let path = image.to_str().unwrap().to_string();
        args.push(&path);
        let out = run(&args);
        assert_ne!(code(&out), OK, "{extra:?} must fail");
        assert_eq!(
            std::fs::read(&image).expect("the destination still exists"),
            sound,
            "{extra:?} changed the destination of a format that wrote no filesystem"
        );
    }
}

#[test]
fn atomic_publishes_the_image_only_once_it_is_whole() {
    // The opt-in guarantee is that the destination holds either the image that was there
    // before or the whole new one. What can be tested without killing the process
    // mid-write is the two halves that make it true: a successful run leaves the new image
    // in place and no temporary file beside it, and a failing one leaves neither a changed
    // destination nor a stray temporary.
    let dir = scratch();
    let image = at(&dir, "atomic.img");
    let out = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--atomic",
        image.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        std::fs::metadata(&image)
            .expect("the image is in place")
            .len(),
        16 << 20
    );
    // Byte-identical to the in-place write: how the bytes reach the destination is not
    // allowed to change what they are.
    let in_place = at(&dir, "in-place.img");
    assert_eq!(code(&format(&in_place, "16M", None)), OK);
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&in_place).expect("read")
    );
    assert!(
        temp_siblings(dir.path()).is_empty(),
        "no temporary left behind"
    );

    // A failing atomic run cleans up after itself, and the destination is untouched.
    let bad_archive = at(&dir, "bad.tar");
    std::fs::write(&bad_archive, b"not a tar").expect("write");
    let out = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--atomic",
        "--from-tar",
        bad_archive.to_str().unwrap(),
        image.to_str().unwrap(),
    ]);
    assert_ne!(code(&out), OK);
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&in_place).expect("read"),
        "a failed atomic run changed the destination"
    );
    assert!(
        temp_siblings(dir.path()).is_empty(),
        "no temporary left behind"
    );
}

/// The temporary files `--atomic` writes through, by name, so a gate can assert there are
/// none.
fn temp_siblings(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read the scratch directory")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".ferrosys-") && n.ends_with(".tmp"))
        .collect()
}

#[test]
fn a_dry_run_reports_the_geometry_and_writes_nothing() {
    // The safe way to discover what a format would cost: the layout reported is the same
    // value the write would use, so it is exact — and the destination is never opened, so
    // a dry run over an image you already have cannot touch it.
    let dir = scratch();
    let image = at(&dir, "never-written.img");
    let out = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--dry-run",
        image.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!image.exists(), "a dry run created the destination");
    let report = fields(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(report["Block count"], "4096");
    // The reservation is what a dry run is worth reading for: it is the one cost nothing
    // else in the summary would show.
    assert_eq!(report["Reserved GDT blocks"], "64");

    // And the geometry it reported is the geometry a real format then realizes.
    let real = at(&dir, "real.img");
    let written = run(&[
        "format",
        "--size",
        "16M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        real.to_str().unwrap(),
    ]);
    assert_eq!(code(&written), OK);
    let after = fields(&String::from_utf8_lossy(&written.stderr));
    for key in [
        "Block count",
        "Inode count",
        "Reserved GDT blocks",
        "Grows online to",
    ] {
        assert_eq!(
            report[key], after[key],
            "{key} differs between the dry run and the write"
        );
    }
    // What only a written filesystem can report: what it has left.
    assert!(
        !report.contains_key("Free blocks"),
        "a dry run has no free count to report"
    );
    assert_eq!(after["Free blocks"], "2710");
}

#[test]
fn an_auto_size_fits_the_contents_and_slack_leaves_room_in_it() {
    let dir = scratch();
    let archive = write_archive(&dir);

    // Sized to the archive rather than to a number the caller guessed.
    let fitted = at(&dir, "fitted.img");
    let out = run(&[
        "format",
        "--size",
        "auto",
        "--from-tar",
        archive.to_str().unwrap(),
        "--uuid",
        UUID,
        "--time",
        TIME,
        fitted.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    let tight = fields(&String::from_utf8_lossy(&out.stderr));
    let blocks: u64 = tight["Block count"].parse().expect("a block count");
    let free: u64 = tight["Free blocks"].parse().expect("a free count");
    // The image on disk is the size the search settled on, and nothing was rounded into
    // it afterwards.
    let block_size: u64 = tight["Block size"].parse().expect("a block size");
    assert_eq!(
        std::fs::metadata(&fitted).expect("the image exists").len(),
        blocks * block_size
    );

    // The same contents with a fifth of the filesystem left free: a larger filesystem, and
    // one whose own free count says so.
    let roomy = at(&dir, "roomy.img");
    let out = run(&[
        "format",
        "--size",
        "auto",
        "--slack",
        "20%",
        "--from-tar",
        archive.to_str().unwrap(),
        "--uuid",
        UUID,
        "--time",
        TIME,
        roomy.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    let loose = fields(&String::from_utf8_lossy(&out.stderr));
    let roomy_blocks: u64 = loose["Block count"].parse().expect("a block count");
    let roomy_free: u64 = loose["Free blocks"].parse().expect("a free count");
    assert!(
        roomy_blocks > blocks,
        "{roomy_blocks} blocks with slack is not larger than {blocks} without"
    );
    // A fifth of the filesystem, as the share is measured: whole blocks, rounded down.
    assert!(
        roomy_free >= roomy_blocks / 5,
        "{roomy_free} of {roomy_blocks} blocks free is under the fifth that was asked for"
    );
    assert!(free < roomy_free);

    // A named size and --slack together is a usage error, not a silently ignored option.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--slack",
        "20%",
        "--uuid",
        UUID,
        "--time",
        TIME,
        at(&dir, "never.img").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(!at(&dir, "never.img").exists());

    if !available("e2fsck") {
        return;
    }
    // The tightest filesystem this tool writes, judged by something that is not this tool.
    e2fsck_clean(&fitted);
    e2fsck_clean(&roomy);
}

#[test]
fn a_small_filesystem_formats_at_the_defaults() {
    // The growth reservation is bounded by the filesystem it is reserved from, so `Max` —
    // the default — cannot be the reason a small image fails to format. Filling the resize
    // inode's whole map costs more blocks than any of these sizes has to spare, so each of
    // them is a size the share bound is what makes formattable.
    let dir = scratch();
    for (size, profile, reserved) in [
        ("1M", "ext2", "4"),
        ("4M", "ext2", "16"),
        ("8M", "ext4", "32"),
        ("16M", "ext4", "64"),
    ] {
        let image = at(&dir, &format!("small-{size}.img"));
        let out = run(&[
            "format",
            "--size",
            size,
            "-t",
            profile,
            "--uuid",
            UUID,
            "--time",
            TIME,
            image.to_str().unwrap(),
        ]);
        assert_eq!(
            code(&out),
            OK,
            "{size} {profile} must format at the defaults: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report = fields(&String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            report["Reserved GDT blocks"], reserved,
            "{size} reservation"
        );
        if available("e2fsck") {
            e2fsck_clean(&image);
        }
    }

    // Below the journal's own minimum an ext4 filesystem still cannot be built — that is a
    // journal's 1024 blocks, not the reservation — and the failure says so and names the
    // way out. This is the message a first-time user gets, so it is worth pinning.
    let image = at(&dir, "too-small.img");
    let out = run(&[
        "format",
        "--size",
        "4M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        image.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OPERATIONAL);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no room for a journal"), "{stderr}");
    assert!(
        stderr.contains("hint:"),
        "the failure names the option to change: {stderr}"
    );
    assert!(stderr.contains("-t ext2"), "{stderr}");
    assert!(stderr.contains("-O ^has_journal,^orphan_file"), "{stderr}");

    // Both spellings the hint offers are run, because a hint that names a flag
    // combination the tool then refuses sends the caller from one error to another.
    // `-O ^has_journal` alone is such a combination — the default profile carries
    // `orphan_file`, which requires a journal — so the hint names the pair.
    for way_out in [vec!["-t", "ext2"], vec!["-O", "^has_journal,^orphan_file"]] {
        let image = at(&dir, "way-out.img");
        let mut args = vec!["format", "--size", "4M", "--uuid", UUID, "--time", TIME];
        args.extend_from_slice(&way_out);
        args.push(image.to_str().unwrap());
        let out = run(&args);
        assert_eq!(
            code(&out),
            OK,
            "the hint's `{}` builds a filesystem: {}",
            way_out.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn format_takes_its_time_from_the_environment_when_the_option_is_absent() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    let out = Command::new(FERROSYS)
        .args(["format", "--size", "64M", "--uuid", UUID])
        .arg(&image)
        .env("SOURCE_DATE_EPOCH", TIME)
        .output()
        .expect("the binary runs");
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    // And it is the same image the option would have written: one input, two ways in.
    let explicit = at(&dir, "explicit.img");
    assert_eq!(code(&format(&explicit, "64M", None)), OK);
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&explicit).expect("read")
    );

    // With neither, the tool has no clock to fall back on, and says so.
    let neither = at(&dir, "neither.img");
    let out = Command::new(FERROSYS)
        .args(["format", "--size", "64M", "--uuid", UUID])
        .arg(&neither)
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .expect("the binary runs");
    assert_eq!(code(&out), USAGE);
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

/// The `KEY: value` pairs a `dumpe2fs -h`-shaped report prints, by key.
fn fields(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[test]
fn inspect_agrees_with_dumpe2fs_field_by_field() {
    // This is what earns the claim that the tool reimplements `dumpe2fs`'s inspection
    // natively: not that it prints something, but that what it prints is what e2fsprogs
    // prints, field by field, about the same image.
    if !available("dumpe2fs") {
        return;
    }
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);

    let ours = fields(&String::from_utf8_lossy(&ok(&[
        "inspect",
        image.to_str().expect("a text path"),
    ])));
    let theirs = tool("dumpe2fs")
        .arg("-h")
        .arg(&image)
        .output()
        .expect("spawn dumpe2fs");
    let theirs = fields(&String::from_utf8_lossy(&theirs.stdout));

    // Every field both tools name must agree. A field one of them does not print (their
    // "Fragment size", our "Block groups") is not a disagreement.
    let shared = [
        "Filesystem volume name",
        "Filesystem UUID",
        "Filesystem magic number",
        "Filesystem state",
        "Errors behavior",
        "Filesystem OS type",
        "Inode count",
        "Block count",
        "Reserved block count",
        "Free blocks",
        "Free inodes",
        "First block",
        "Block size",
        "Group descriptor size",
        "Reserved GDT blocks",
        "Blocks per group",
        "Inodes per group",
        "Inode blocks per group",
        "Flex block group size",
        "First inode",
        "Inode size",
        "Journal inode",
        "Orphan file inode",
        "Default directory hash",
        "Directory Hash Seed",
        "Checksum type",
        "Checksum seed",
    ];
    for key in shared {
        let ours = ours
            .get(key)
            .unwrap_or_else(|| panic!("inspect prints {key}"));
        let theirs = theirs
            .get(key)
            .unwrap_or_else(|| panic!("dumpe2fs prints {key}"));
        assert_eq!(ours, theirs, "the two tools disagree about {key}");
    }

    // The feature line is compared as a set: both print the same names, and the order
    // they print them in says nothing about whether the same features are present.
    let sorted = |s: &str| {
        let mut v: Vec<&str> = s.split_whitespace().collect();
        v.sort_unstable();
        v.join(" ")
    };
    let f = "Filesystem features";
    assert_eq!(
        sorted(&ours[f]),
        sorted(&theirs[f]),
        "the two tools disagree about which features the image carries"
    );
}

#[test]
fn format_applies_the_label_inode_and_reserved_options() {
    let dir = scratch();
    let image = at(&dir, "labelled.img");
    let path = image.to_str().expect("a text path");
    // 256 MiB is two whole groups, so `--inodes 5000` and `--reserved-percent 1.5` have
    // exact, checkable outcomes.
    let out = run(&[
        "format",
        "--size",
        "256M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--label",
        "rootfs",
        "--inodes",
        "5000",
        "--reserved-percent",
        "1.5",
        path,
    ]);
    assert_eq!(
        code(&out),
        OK,
        "format failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report = fields(&String::from_utf8_lossy(&ok(&["inspect", path])));
    assert_eq!(report["Filesystem volume name"], "rootfs");
    // The writer emits ext4, and inspect labels it as the variant its feature words
    // classify to, in the report's family-neutral head.
    assert_eq!(report["Filesystem family"], "ext");
    assert_eq!(report["Filesystem variant"], "ext4");
    // 5000 spread across two groups, each rounded up to fill its inode-table blocks.
    assert_eq!(report["Inode count"], "5024");
    // floor(65536 blocks * 1.5%), computed exactly, no floating point.
    assert_eq!(report["Reserved block count"], "983");
}

#[test]
fn format_refuses_an_over_long_label_and_an_out_of_range_percent() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    let path = image.to_str().expect("a text path");

    // Seventeen bytes of label is one too many: a usage error, caught before any file is
    // opened, so nothing is written.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--label",
        "0123456789abcdefX",
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(!image.exists(), "a refused format writes nothing");

    // A reserved percentage past the 50% ceiling is refused the same way.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--reserved-percent",
        "60",
        path,
    ]);
    assert_eq!(code(&out), USAGE);
}

#[test]
fn inspect_reports_every_group_and_scans_by_default() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    // Large enough to have several groups, so the group table has something to say.
    assert_eq!(code(&format(&image, "512M", None)), OK);

    let text = String::from_utf8(ok(&[
        "inspect",
        "--groups",
        image.to_str().expect("a text path"),
    ]))
    .expect("the report is text");
    assert!(text.contains("GROUP"), "the group table has a header");
    // Four groups at 32768 blocks each, and each one named.
    for group in 0..4 {
        assert!(
            text.lines().any(|l| l.starts_with(&format!("{group} "))),
            "group {group} is in the table"
        );
    }
    // The scan ran, and found nothing.
    assert!(text.contains("no findings"));
}

#[test]
fn inspect_groups_survives_a_hostile_group_count() {
    // A crafted superblock can claim ~4 billion block groups (`blocks_count` maxed,
    // `blocks_per_group` of one). The group listing must not pre-size a vector from that
    // count: reserving capacity for it would ask for hundreds of gigabytes and abort the
    // process before a single descriptor was read. The descriptor loop grows as real
    // descriptors are found, is bounded above whatever the count claims, and stops where the
    // image runs out — a clean image-bad exit, not a crash.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    // Small on purpose: the loop reads descriptors until it runs off the end of the
    // image, so the image's size, not the claimed group count, bounds the work.
    assert_eq!(code(&format(&image, "16M", None)), OK);

    let mut bytes = std::fs::read(&image).expect("read the image");
    // The primary superblock sits at byte 1024. `s_blocks_count_lo` is at 0x04 and
    // `s_blocks_per_group` at 0x20, both little-endian u32.
    bytes[1024 + 0x04..1024 + 0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[1024 + 0x20..1024 + 0x24].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(&image, &bytes).expect("write the image");

    let out = run(&["inspect", "--groups", image.to_str().expect("a text path")]);
    // An aborted (signal-killed) process has no exit code, so reading one at all is half
    // the assertion: the preallocation crash would fail here.
    let exit = out
        .status
        .code()
        .expect("the process exited rather than aborting");
    assert_eq!(
        exit,
        IMAGE_BAD,
        "a hostile group count is a bad image, not a crash:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn one_bad_image_extracts_to_the_same_exit_code_whichever_destination_it_is_given() {
    // The exit code says what kind of failure it was, and the kind cannot depend on where
    // the output was going: one image that cannot be read is a bad filesystem through
    // `--to-tar` and must be a bad filesystem through `--to-dir` too. A caller reading 8
    // from one and 4 from the other would conclude the run was the tool's fault in one case
    // and the image's in the other, about the same bytes.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "16M", None)), OK);

    // The root inode's type, rewritten to a regular file: the superblock still parses, and
    // the tree cannot be walked because its root is not a directory. `i_mode` opens the
    // inode, little-endian, so the high byte carries the type bits.
    let bad = at(&dir, "bad.img");
    let mut bytes = std::fs::read(&image).expect("read");
    let root_inode = inode_table_offset(&bytes) + 256;
    bytes[root_inode + 1] = 0x81;
    std::fs::write(&bad, &bytes).expect("write");
    let path = bad.to_str().expect("a text path");

    let tar = at(&dir, "out.tar");
    let to_tar = run(&[
        "extract",
        path,
        "--to-tar",
        tar.to_str().expect("a text path"),
    ]);
    let out = at(&dir, "unpacked");
    let to_dir = run(&[
        "extract",
        path,
        "--to-dir",
        out.to_str().expect("a text path"),
    ]);

    assert_eq!(
        code(&to_tar),
        IMAGE_BAD,
        "--to-tar:\n{}",
        String::from_utf8_lossy(&to_tar.stderr)
    );
    assert_eq!(
        code(&to_dir),
        code(&to_tar),
        "--to-dir reports a different kind of failure about the same image:\n{}",
        String::from_utf8_lossy(&to_dir.stderr)
    );
}

#[test]
fn inspect_groups_is_bounded_by_more_than_the_length_the_image_claims() {
    // The other half of the same hostile count, and the one a bound on the *image* does not
    // catch: a file that claims 32 GiB and occupies nothing. Every descriptor offset lands
    // inside the claimed length, so every read succeeds, and a loop bounded only by that
    // gathers tens of gigabytes of tuples and renders a string of the same order — from a
    // file taking up no disk blocks at all.
    //
    // So the listing has a ceiling of its own, and a run that reaches it says the listing is
    // short rather than passing it off as the whole table.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "16M", None)), OK);

    let mut bytes = std::fs::read(&image).expect("read the image");
    bytes[1024 + 0x04..1024 + 0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[1024 + 0x20..1024 + 0x24].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(&image, &bytes).expect("write the image");
    // Sparse: the length is a claim, and the file still occupies what it did.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .expect("open the image")
        .set_len(32 << 30)
        .expect("claim 32 GiB");

    // `--quick` so the scan is not what this measures: the group listing is.
    let out = run(&[
        "inspect",
        "--groups",
        "--quick",
        image.to_str().expect("a text path"),
    ]);
    assert!(
        out.status.code().is_some(),
        "the process exited rather than aborting"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("groups listed; the rest were not read"),
        "a listing that stopped short says so:\n{stdout}"
    );
}

#[test]
fn inspect_json_parses_as_json() {
    // Validated by a real parser, not by one we wrote: our own JSON writer agreeing with
    // our own JSON reader would prove nothing.
    if !available("python3") {
        return;
    }
    let dir = scratch();
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "64M", None)), OK);
    let json = ok(&[
        "inspect",
        "--json",
        "--groups",
        image.to_str().expect("a text path"),
    ]);

    // The judge parses with a foreign implementation and then checks *values*, not key
    // presence: the fields a consumer reads must equal what the format was given (the
    // UUID, the time, the 64 MiB of 4 KiB blocks) or what the profile pins (the
    // feature lists, a clean scan, and the unknown-feature words, which must be
    // reported as zero rather than omitted — an absent field would read as though an
    // image carrying a foreign feature carried none).
    let judge = r#"
import json, sys
doc = json.load(sys.stdin)
# Every document this tool emits names its shape with the same field, so a consumer
# reads one key wherever it looks.
assert doc["schema"] == 2, doc["schema"]
assert "version" not in doc, "the envelope field is `schema` in every document"
# The head means the same thing whatever family answered, so a consumer that reads only
# these five fields and the findings never learns what a group descriptor is.
assert doc["family"] == "ext", doc["family"]
assert doc["variant"] == "ext4", doc["variant"]
assert doc["size"] == 64 * 1024 * 1024, doc["size"]
assert doc["allocation_unit"] == 4096, doc["allocation_unit"]
assert doc["identifier"] == "f0e17055-0000-4000-8000-000000000000", doc["identifier"]
assert doc["findings"]["clean"] is True, doc["findings"]
assert doc["findings"]["findings"] == [], doc["findings"]
assert doc["findings"]["schema"] == 2, doc["findings"]
# The body is entirely ext's own, and a later family adds one beside it.
ext = doc["ext"]
sb = ext["superblock"]
assert sb["uuid"] == doc["identifier"], sb["uuid"]
assert sb["block_size"] == 4096, sb["block_size"]
assert sb["blocks"] * sb["block_size"] == doc["size"], sb["blocks"]
assert sb["created"] == 1700000000, sb["created"]
feats = ext["features"]
assert "has_journal" in feats["compat"], feats["compat"]
assert "extent" in feats["incompat"], feats["incompat"]
# The family's own label lives in the head as `variant`, not twice.
assert "profile" not in feats, feats
assert feats["unknown"] == {"compat": 0, "incompat": 0, "ro_compat": 0}, feats["unknown"]
groups = ext["groups"]
assert len(groups) == 1 and groups[0]["group"] == 0, groups
assert groups[0]["free_inodes"] == sb["free_inodes"], groups
"#;
    let mut child = tool("python3")
        .args(["-c", judge])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&json)
        .expect("write the document");
    let out = child.wait_with_output().expect("python3 finishes");
    assert!(
        out.status.success(),
        "python3 rejected the document or its values:\n{}\n{}",
        String::from_utf8_lossy(&json),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// exit codes
// ---------------------------------------------------------------------------

#[test]
fn the_four_exit_codes_are_reachable_and_distinct() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "64M", None)), OK);
    let path = image.to_str().expect("a text path");

    // 0: a filesystem was read, and it is sound.
    assert_eq!(code(&run(&["inspect", path])), OK);

    // 4: a filesystem was read, and it is bad. Flip a bit in the root inode's mode so the
    // image parses — a superblock is still a superblock — but is self-inconsistent.
    let bad = at(&dir, "bad.img");
    let mut bytes = std::fs::read(&image).expect("read");
    let root_inode = inode_table_offset(&bytes) + 256; // inode 2 is the second entry
    bytes[root_inode] ^= 0xff;
    std::fs::write(&bad, &bytes).expect("write");
    let out = run(&["inspect", bad.to_str().expect("a text path")]);
    assert_eq!(
        code(&out),
        IMAGE_BAD,
        "a corrupted image is bad, not merely described:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The report still came out — a bad filesystem is described *and* faulted.
    assert!(!out.stdout.is_empty());

    // 8: the bytes are not a filesystem at all, so there is no opinion to form.
    let blob = at(&dir, "blob.img");
    std::fs::write(&blob, vec![0x5a; 64 * 1024]).expect("write");
    assert_eq!(
        code(&run(&["inspect", blob.to_str().expect("a text path")])),
        OPERATIONAL
    );

    // 16: the command line could not be understood.
    assert_eq!(code(&run(&["inspect", "--nonesuch", path])), USAGE);
    assert_eq!(code(&run(&["frobnicate"])), USAGE);
    assert_eq!(code(&run(&[])), USAGE);
}

#[test]
fn a_filesystem_another_formatter_wrote_is_not_thereby_bad() {
    // `inspect` answers "is this filesystem sound", not "did I write this". A filesystem
    // `mke2fs` made is not ours, and it is not broken — so it must inspect clean and exit
    // 0. This is the gate that keeps the default verdict threshold honest: `conformance`,
    // the threshold below the default, means *valid ext4 but not the form this tool
    // writes*, and defaulting to it would fault every healthy filesystem from every other
    // formatter.
    if !available("mke2fs") {
        return;
    }
    let dir = scratch();
    for kind in ["ext4", "ext3", "ext2"] {
        let image = at(&dir, &format!("{kind}.img"));
        std::fs::write(&image, vec![0u8; 32 << 20]).expect("make the file");
        let made = tool("mke2fs")
            .args(["-q", "-t", kind])
            .arg(&image)
            .output()
            .expect("spawn mke2fs");
        assert!(
            made.status.success(),
            "mke2fs could not make an {kind} filesystem: {}",
            String::from_utf8_lossy(&made.stderr)
        );

        let out = run(&["inspect", image.to_str().expect("a text path")]);
        assert_eq!(
            code(&out),
            OK,
            "a healthy {kind} filesystem from mke2fs was reported bad:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // And it was really read, not merely opened: the report describes it.
        let report = String::from_utf8_lossy(&out.stdout);
        assert!(
            report.contains("Block count:") && report.contains("no findings"),
            "the {kind} filesystem was scanned:\n{report}"
        );
    }
}

#[test]
fn a_bad_image_is_only_bad_at_the_severity_asked_for() {
    let dir = scratch();
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "64M", None)), OK);
    let bad = at(&dir, "bad.img");
    let mut bytes = std::fs::read(&image).expect("read");
    let root_inode = inode_table_offset(&bytes) + 256;
    bytes[root_inode] ^= 0xff;
    std::fs::write(&bad, &bytes).expect("write");
    let path = bad.to_str().expect("a text path");

    // The default threshold faults it...
    assert_eq!(code(&run(&["inspect", path])), IMAGE_BAD);
    // ...and `never` reports the same findings without reaching a verdict, which is what
    // a caller who wants the report and not the judgement asks for.
    let out = run(&["inspect", "--fail-on", "never", path]);
    assert_eq!(code(&out), OK);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("integrity")
            || String::from_utf8_lossy(&out.stdout).contains("structural"),
        "the findings are still reported"
    );
    // A scan that never ran reaches no verdict either.
    assert_eq!(code(&run(&["inspect", "--quick", path])), OK);
}

/// The byte offset of group 0's inode table, read out of the image's own superblock and
/// first group descriptor.
///
/// The test corrupts an inode, so it has to find one; doing that by hand rather than
/// through the reader keeps the gate honest about what it broke.
fn inode_table_offset(bytes: &[u8]) -> usize {
    let u32_at = |off: usize| {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize
    };
    // The primary superblock is 1024 bytes in; the descriptor table follows the block it
    // sits in. At a 4096-byte block size that is block 1.
    let block_size = 1024usize << u32_at(1024 + 0x18);
    let gdt = block_size; // first_data_block is 0 at 4096 bytes, so the table is block 1
    // bg_inode_table_lo is at offset 8 of the descriptor.
    u32_at(gdt + 8) * block_size
}

// ---------------------------------------------------------------------------
// extract
// ---------------------------------------------------------------------------

#[test]
fn a_tar_survives_a_round_trip_through_a_filesystem() {
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(
        code(&format(&image, "128M", Some(&archive))),
        OK,
        "the archive formats"
    );

    // Out again, and back in: the second image must be the first one, byte for byte. That
    // is the round trip closing — every name, mode, owner, time, link, device, attribute,
    // and ACL survived, because a single lost bit would move a byte.
    let out_tar = at(&dir, "out.tar");
    assert_eq!(
        code(&run(&[
            "extract",
            image.to_str().expect("a text path"),
            "--to-tar",
            out_tar.to_str().expect("a text path"),
        ])),
        OK
    );

    // Before comparing the two images, prove the hard things are actually in the archive.
    // A byte-identical round trip is symmetric: a field dropped on the way out and never
    // looked for on the way back in would leave both images equal and the gate green,
    // having verified nothing about it. These are the positive controls that keep it
    // honest.
    let tar_bytes = std::fs::read(&out_tar).expect("read the archive");
    let contains = |needle: &[u8]| tar_bytes.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(b"SCHILY.xattr.system.posix_acl_access"),
        "the archive carries the access ACL"
    );
    assert!(
        contains(b"SCHILY.xattr.system.posix_acl_default"),
        "the archive carries the default ACL"
    );
    // And it carries it in the version-2 form the syscall boundary speaks — the bytes
    // `getxattr` would have returned — not ext4's compact on-disk form, which GNU tar and
    // our own archive source both reject.
    assert!(
        contains(&acl_v2_access()),
        "the ACL travels in the version-2 form, not ext4's on-disk form"
    );
    assert!(
        contains(b"SCHILY.xattr.user.big"),
        "the archive carries the attribute that spilled into a block"
    );
    assert!(
        contains(b"./etc/hostname.link"),
        "the archive carries the hard link"
    );
    assert!(
        contains(b"1700000000.123456789"),
        "the archive carries the sub-second time the header cannot hold"
    );

    // The hash-indexed directory came back whole. Reading it means walking the hash tree,
    // which no linear scan would have found the way through.
    let listing = String::from_utf8(ok(&[
        "extract",
        image.to_str().expect("a text path"),
        "--list",
    ]))
    .expect("text");
    let many = listing
        .lines()
        .filter(|l| l.contains("/many/file-"))
        .count();
    assert_eq!(
        many, 1200,
        "every name in the hash-indexed directory is read back"
    );

    let again = at(&dir, "again.img");
    let out = format(&again, "128M", Some(&out_tar));
    assert_eq!(
        code(&out),
        OK,
        "the archive we wrote is one we can read back:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&again).expect("read"),
        "the filesystem did not survive the round trip through our own archive"
    );

    if !available("e2fsck") {
        return;
    }
    e2fsck_clean(&again);
}

#[test]
fn gnu_tar_reads_the_archive_we_write() {
    // Round-tripping through our own reader proves nothing about interoperability: it
    // would pass just as well if we had invented a private archive format. A foreign tar
    // reading it is what makes it a tar.
    if !available("tar") {
        return;
    }
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);
    let out_tar = at(&dir, "out.tar");
    assert_eq!(
        code(&run(&[
            "extract",
            image.to_str().expect("a text path"),
            "--to-tar",
            out_tar.to_str().expect("a text path"),
        ])),
        OK
    );

    // GNU tar lists it without complaint. The `x` header our PAX records travel in carries
    // an empty name field, and this is where a foreign tool gets to object to that.
    let out = tool("tar")
        .args(["--xattrs", "-tvf"])
        .arg(&out_tar)
        .output()
        .expect("spawn tar");
    let listing = String::from_utf8_lossy(&out.stdout);
    let complaints = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && complaints.is_empty(),
        "GNU tar objected to our archive:\n{complaints}"
    );
    for name in ["./etc/hostname", "./dev/null", "./etc/mtab"] {
        assert!(listing.contains(name), "GNU tar lists {name}:\n{listing}");
    }
    // It sees the kinds, not just the names: a device is a device, a link is a link.
    // The mode is required *and* one of the two spellings tar uses for the numbers — the
    // parentheses matter, since `&&` binding tighter than `||` would let any listing
    // containing "1, 3" pass without the mode ever being checked.
    assert!(
        listing.contains("crw-rw-rw-") && (listing.contains("1,3") || listing.contains("1, 3")),
        "GNU tar sees the device node:\n{listing}"
    );

    // And it unpacks: the mode and the extended attribute survive into a real directory.
    let unpacked = at(&dir, "unpacked");
    std::fs::create_dir(&unpacked).expect("make the directory");
    let out = tool("tar")
        .args(["--xattrs", "--xattrs-include=*", "-xf"])
        .arg(&out_tar)
        .arg("-C")
        .arg(&unpacked)
        .arg("./etc/hostname")
        .output()
        .expect("spawn tar");
    assert!(
        out.status.success(),
        "GNU tar could not unpack our archive:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hostname = unpacked.join("etc/hostname");
    assert_eq!(
        std::fs::read(&hostname).expect("read the unpacked file"),
        b"ferrosys\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&hostname)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "the mode survived into a real file");
    }
    // The user attribute survived, as GNU tar itself reports it. `getfattr`'s absence is
    // loud under the require-env, not a silent skip: an unrun check must never read as a
    // pass it did not earn.
    if available("getfattr") {
        let out = tool("getfattr")
            .args(["-n", "user.note", "--only-values"])
            .arg(&hostname)
            .output()
            .expect("spawn getfattr");
        assert!(
            out.status.success(),
            "getfattr could not read the attribute:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"hello");
    }
}

#[test]
fn extract_writes_one_artifact_and_nothing_else() {
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);
    let path = image.to_str().expect("a text path");

    // `--cat` is the file's bytes, and nothing else at all.
    let out = run(&["extract", path, "--cat", "/etc/hostname"]);
    assert_eq!(code(&out), OK);
    assert_eq!(out.stdout, b"ferrosys\n");
    assert!(out.stderr.is_empty());

    // A `..` component is an ascent, which is what reaches a file through the relative links
    // that ascend on a real root filesystem. At the root there is nothing to ascend to, so a
    // run of them stays there rather than naming anything on the machine reading the image.
    for path_in_image in [
        "/etc/../etc/hostname",
        "/../etc/hostname",
        "/etc/../../../etc/hostname",
    ] {
        assert_eq!(
            ok(&["extract", path, "--cat", path_in_image]),
            b"ferrosys\n",
            "{path_in_image}"
        );
    }

    // A path the filesystem does not have is an operational failure, not a bad image: the
    // filesystem is fine, the request was not.
    let out = run(&["extract", path, "--cat", "/nowhere"]);
    assert_eq!(code(&out), OPERATIONAL);
    assert!(out.stdout.is_empty(), "no bytes are written for no file");

    // The listing names every file, with its mode, owner, and target.
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    assert!(listing.contains("/etc/hostname"));
    assert!(listing.contains("lrwxrwxrwx"), "a symlink reads as one");
    assert!(
        listing.contains("/etc/mtab -> /proc/self/mounts"),
        "a link says where it points"
    );
    assert!(listing.contains("crw-rw-rw-"), "a device reads as one");
    assert!(
        listing.contains("/lost+found"),
        "a listing describes the filesystem, and /lost+found is in it"
    );
}

#[test]
fn stat_reports_one_path_with_its_attributes_and_acls() {
    // The forensic question — what is this file's mode, and what is in its attributes — is
    // one `--stat` answers for a single path, without writing a whole archive and unpacking
    // it. The attributes and the decoded ACLs are the part no other output carries.
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);
    let path = image.to_str().expect("a text path");

    let report =
        String::from_utf8(ok(&["extract", path, "--stat", "/etc/hostname"])).expect("text");
    let stat = fields(&report);
    assert_eq!(stat["Type"], "file");
    // The mode in both spellings: octal, which is how a mode is written, and symbolic.
    assert_eq!(stat["Mode"], "0644 (-rw-r--r--)");
    assert_eq!(stat["Owner"], "1000:1000");
    assert_eq!(stat["Size"], "9");
    // The attribute is the point of the command.
    assert_eq!(stat["Xattr user.note"], "hello");
    // And the sub-second time the archive carried survives into the report.
    assert!(
        stat["Modified"].contains("123456789 ns"),
        "{}",
        stat["Modified"]
    );

    // An ACL comes back as bytes no person reads: it is decoded to the text `getfacl`
    // prints, or it is not really reported at all.
    let report = String::from_utf8(ok(&["extract", path, "--stat", "/home"])).expect("text");
    let stat = fields(&report);
    assert_eq!(stat["Type"], "directory");
    let acl = &stat["Xattr system.posix_acl_access"];
    assert!(acl.contains("user:1000:rw-"), "{acl}");
    assert!(acl.contains("mask::rwx"), "{acl}");
    assert!(
        stat.contains_key("Xattr system.posix_acl_default"),
        "a directory's default ACL is reported too"
    );

    // A path naming a symlink describes the link, not what it points at: a question about a
    // path is a question about that path.
    let report = String::from_utf8(ok(&["extract", path, "--stat", "/etc/mtab"])).expect("text");
    let stat = fields(&report);
    assert_eq!(stat["Type"], "symlink");
    assert_eq!(stat["Symlink target"], "/proc/self/mounts");

    // A path the filesystem does not have is an operational failure, as `--cat`'s is.
    let out = run(&["extract", path, "--stat", "/nowhere"]);
    assert_eq!(code(&out), OPERATIONAL);
    assert!(out.stdout.is_empty());
}

#[test]
fn the_json_documents_carry_attributes_and_both_spellings_of_a_mode() {
    // A machine reading the listing needs the attributes, which for the forensic use are
    // the headline field. And a mode in JSON has to be decimal, since JSON
    // has no octal literal — so the octal spelling is carried beside it rather than left for
    // the reader to convert and get wrong.
    if !available("python3") {
        return;
    }
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);
    let path = image.to_str().expect("a text path");

    let judge = r#"
import json, sys
doc = json.load(sys.stdin)
assert doc["schema"] == 2, doc["schema"]
by_path = {e["path"]: e for e in doc["entries"]}
h = by_path["/etc/hostname"]
assert h["mode"] == 0o644 and h["mode_octal"] == "0644", h
assert h["uid"] == 1000 and h["type"] == "file", h
# The attribute a listing never carried.
names = {x["name"]: x for x in h["xattrs"]}
assert names["user.note"]["value"] == "hello", names
# An ACL comes with the decoded text beside its stored bytes: the bytes are ext's compact
# form, which no consumer of this document would otherwise be able to read.
home = by_path["/home"]
acls = {x["name"]: x for x in home["xattrs"]}
acl = acls["system.posix_acl_access"]
assert "user:1000:rw-" in acl["acl"], acl
assert acl["value_hex"], acl
# An entry with no attributes carries no xattrs key rather than an empty one.
assert "xattrs" not in by_path["/etc"], by_path["/etc"]
"#;
    let listing = ok(&["extract", path, "--list", "--json"]);
    assert_json(judge, &listing);

    // The same fields, for one path, out of --stat --json.
    let stat_judge = r#"
import json, sys
doc = json.load(sys.stdin)
assert doc["schema"] == 2, doc["schema"]
e = doc["entry"]
assert e["path"] == "/etc/hostname" and e["mode_octal"] == "0644", e
assert e["crtime"] == e["mtime"], e
assert {x["name"] for x in e["xattrs"]} == {"user.note"}, e
"#;
    let stat = ok(&["extract", path, "--stat", "/etc/hostname", "--json"]);
    assert_json(stat_judge, &stat);
}

/// Judge a JSON document with a `python3` program, which fails the gate by assertion.
fn assert_json(program: &str, document: &[u8]) {
    let mut child = tool("python3")
        .args(["-c", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(document)
        .expect("write the document");
    let out = child.wait_with_output().expect("python3 finishes");
    assert!(
        out.status.success(),
        "python3 rejected the document or its values:\n{}\n{}",
        String::from_utf8_lossy(document),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_read_is_bounded_by_the_cap_it_is_given() {
    // `--cat` on a hostile image would allocate whatever `i_size` claims, so the library's
    // bound is reachable from the command line. Over the cap the read is refused,
    // because a truncated file returned as a success is the failure that matters: a caller
    // would write an incomplete file and see nothing wrong.
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);
    let path = image.to_str().expect("a text path");

    // /etc/big is 5000 bytes in the fidelity archive.
    let out = run(&[
        "extract",
        path,
        "--max-file-bytes",
        "1K",
        "--cat",
        "/etc/big",
    ]);
    assert_ne!(code(&out), OK, "a file over the cap must not be written");
    assert!(
        out.stdout.is_empty(),
        "no bytes are written before the refusal"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("5000"),
        "the message names the size: {stderr}"
    );
    assert!(stderr.contains("1024"), "and the cap: {stderr}");

    // Under the cap the same file reads whole, so the bound is a bound and not a break.
    let out = run(&[
        "extract",
        path,
        "--max-file-bytes",
        "8K",
        "--cat",
        "/etc/big",
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout.len(), 5000);
}

#[test]
fn a_read_is_bounded_even_when_no_cap_is_given() {
    // The scenario the cap exists for was the out-of-the-box behavior: an inode declaring a
    // size nothing structural bounds, and an extraction writing that many bytes because a
    // hole reads back as zeros. The library's default is no cap, which is right for a caller
    // that knows what it opened; this tool is most often pointed at an image someone else
    // produced, so it derives one from the image's own length.
    if !available("debugfs") || !available("e2fsck") {
        return;
    }
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "16M", Some(&archive))), OK);
    let path = image.to_str().expect("a text path");

    // A terabyte declared by a sixteen-mebibyte image: legal on its face, since a sparse
    // file's holes cost no storage, and past sixteen times what the image holds. `debugfs`
    // recomputes the inode's checksum as the kernel would, so the image is still sound —
    // which is the point, since a refusal that only fires on a damaged image would prove
    // nothing about this one.
    let out = tool("debugfs")
        .args(["-w", "-R", "sif /etc/big size 1099511627776"])
        .arg(&image)
        .output()
        .expect("spawn debugfs");
    assert!(out.status.success(), "debugfs did not run");

    let out = run(&["extract", path, "--cat", "/etc/big"]);
    assert_ne!(
        code(&out),
        OK,
        "a file whose declared size dwarfs the image must not be written out by default"
    );
    assert!(
        out.stdout.is_empty(),
        "no bytes are written before the refusal"
    );
    // And the message says where the cap came from, so a run stopped by a default the
    // invocation did not name has somewhere to go.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--max-file-bytes"),
        "the refusal names what raises the cap: {stderr}"
    );
}

#[test]
fn detect_says_what_an_image_is_and_where() {
    // The question a carving pipeline asks. It is deliberately not `inspect`: the answer is
    // one word, and an image that is recognizably ext still classifies even where a strict
    // read would refuse it.
    let dir = scratch();
    for profile in ["ext2", "ext3", "ext4"] {
        let image = at(&dir, &format!("{profile}.img"));
        let out = run(&[
            "format",
            "--size",
            "64M",
            "-t",
            profile,
            "--uuid",
            UUID,
            "--time",
            TIME,
            image.to_str().unwrap(),
        ]);
        assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
        let answer = ok(&["detect", image.to_str().unwrap()]);
        assert_eq!(
            String::from_utf8_lossy(&answer).trim(),
            profile,
            "detect names the family the feature words classify to"
        );
    }

    // A filesystem inside a larger image is found where it is, and not where it is not.
    let ext4 = at(&dir, "ext4.img");
    let disk = at(&dir, "disk.img");
    let mut bytes = vec![0u8; 1 << 20];
    bytes.extend_from_slice(&std::fs::read(&ext4).expect("read"));
    std::fs::write(&disk, &bytes).expect("write the disk image");
    let answer = ok(&["detect", "--offset", "1M", disk.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&answer).trim(), "ext4");

    let out = run(&["detect", disk.to_str().unwrap()]);
    assert_eq!(code(&out), OPERATIONAL, "nothing is at offset zero");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "unrecognized",
        "the negative answer is still the run's artifact"
    );
}

#[test]
fn a_pipe_carries_the_filesystem_from_one_run_to_the_next() {
    // The tar goes out on the standard output and back in on the standard input, with no
    // file in between — and it is still the same filesystem.
    let dir = scratch();
    let archive = write_archive(&dir);
    let image = at(&dir, "fs.img");
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);

    let tar = ok(&[
        "extract",
        image.to_str().expect("a text path"),
        "--to-tar",
        "-",
    ]);
    let piped = at(&dir, "piped.img");
    let out = run_with_stdin(
        &[
            "format",
            "--size",
            "128M",
            "--uuid",
            UUID,
            "--time",
            TIME,
            "--from-tar",
            "-",
            piped.to_str().expect("a text path"),
        ],
        &tar,
    );
    assert_eq!(
        code(&out),
        OK,
        "the piped archive formats:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&image).expect("read"),
        std::fs::read(&piped).expect("read"),
        "the filesystem did not survive the pipe"
    );
}

#[test]
fn a_socket_is_a_typed_error_rather_than_a_missing_file() {
    // tar has no entry type for a socket. Extracting one would have to drop it, and a
    // filesystem that comes back missing a file is worse than one that will not come back
    // at all — so the tool refuses, by name.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    build_image_with_socket(&image);
    let out = run(&[
        "extract",
        image.to_str().expect("a text path"),
        "--to-tar",
        "-",
    ]);
    assert_eq!(code(&out), OPERATIONAL);
    let complaint = String::from_utf8_lossy(&out.stderr);
    assert!(
        complaint.contains("/run/sock") && complaint.contains("socket"),
        "the refusal names the file and why: {complaint}"
    );
}

#[test]
fn atomic_leaves_the_destination_alone_when_the_walk_fails() {
    // A walk fails part-way, and a named destination is created and truncated before it
    // starts — so without `--atomic` the archive that was already there is gone, replaced
    // by the fragment written up to the refusal. The socket image is the reliable way to
    // fail mid-walk; what is being pinned is the destination's contents, not the refusal.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    build_image_with_socket(&image);
    let path = image.to_str().expect("a text path");

    let out_tar = at(&dir, "existing.tar");
    let previous = b"the archive that was already there";
    std::fs::write(&out_tar, previous).expect("seed the destination");
    let dest = out_tar.to_str().expect("a text path");

    let out = run(&["extract", path, "--to-tar", dest, "--atomic"]);
    assert_eq!(code(&out), OPERATIONAL);
    assert_eq!(
        std::fs::read(&out_tar).expect("the destination still exists"),
        previous,
        "an atomic extract that failed left the destination untouched"
    );
    // And no temporary file survives the failure.
    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read the scratch directory")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.contains(".ferrosys-"))
        .collect();
    assert!(
        strays.is_empty(),
        "a temporary file was left behind: {strays:?}"
    );

    // The same walk without `--atomic` writes in place, which is what the option exists
    // to opt out of: the destination is truncated before the walk reaches the socket.
    let out = run(&["extract", path, "--to-tar", dest]);
    assert_eq!(code(&out), OPERATIONAL);
    assert_ne!(
        std::fs::read(&out_tar).expect("the destination still exists"),
        previous,
        "written in place, a failed walk does replace what was there"
    );
}

/// A filesystem holding a socket, which no archive can express — built through the
/// library, since no archive could describe it to `format --from-tar` either.
fn build_image_with_socket(path: &Path) {
    use ferrosys::ext::Timestamp;
    use ferrosys::ext::{FormatOptions, GrowReservation, Metadata, TreeBuilder, format_to};

    let time = Timestamp::from_secs(1_700_000_000);
    let source = TreeBuilder::new()
        .directory(b"/run".to_vec(), Metadata::new(0o755, time))
        .socket(b"/run/sock".to_vec(), Metadata::new(0o666, time));
    let mut options = FormatOptions::new([0x11; 16], time, [0u8; 16]);
    options.grow = GrowReservation::UpTo(1 << 30);
    let file = std::fs::File::create(path).expect("create the image");
    format_to(source, 64 << 20, options, &file).expect("format");
}

// ---------------------------------------------------------------------------
// offset
// ---------------------------------------------------------------------------

#[test]
fn a_filesystem_inside_a_larger_image_is_read_at_its_offset() {
    // A partition inside a whole-disk image: the filesystem does not begin at byte zero,
    // and every read has to be relative to where it does begin.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    let archive = write_archive(&dir);
    assert_eq!(code(&format(&image, "128M", Some(&archive))), OK);

    const OFFSET: usize = 1 << 20; // a megabyte in, where a partition table would leave it
    let disk = at(&dir, "disk.img");
    let mut bytes = vec![0x00; OFFSET];
    bytes.extend_from_slice(&std::fs::read(&image).expect("read"));
    std::fs::write(&disk, &bytes).expect("write");
    let path = disk.to_str().expect("a text path");

    // Without the offset the bytes at the front are not a filesystem, and the tool says so
    // rather than guessing.
    assert_eq!(code(&run(&["inspect", path])), OPERATIONAL);

    // With it, the filesystem is there, sound, and readable.
    let report = String::from_utf8(ok(&["inspect", "--offset", "1M", path])).expect("text");
    assert!(report.contains(UUID));
    assert!(report.contains("no findings"));
    assert_eq!(
        ok(&["extract", "--offset", "1M", path, "--cat", "/etc/hostname"]),
        b"ferrosys\n"
    );
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

#[test]
fn help_is_an_artifact_and_a_usage_error_is_not() {
    // Asking for help is a run that succeeded, and the help is what it produced.
    let out = run(&["--help"]);
    assert_eq!(code(&out), OK);
    assert!(String::from_utf8_lossy(&out.stdout).contains("usage:"));
    assert!(out.stderr.is_empty());

    for topic in ["format", "inspect", "extract"] {
        let out = run(&[topic, "--help"]);
        assert_eq!(code(&out), OK);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(topic), "the {topic} help names {topic}");
    }

    // The `--from-tar` memory cost is documented where a user meets it, not left to be
    // discovered on a large archive.
    let out = run(&["format", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("memory"),
        "format's help says what --from-tar costs in memory"
    );

    // A usage error is a failure: it goes to the standard error, and the standard output
    // stays empty, so a pipe never receives half a usage message where an artifact should
    // have been.
    let out = run(&["inspect", "--nonesuch", "x.img"]);
    assert_eq!(code(&out), USAGE);
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn inspect_sarif_is_valid_sarif_a_foreign_parser_accepts() {
    // The SARIF projection exists so a CI system can ingest a scan. That claim is only
    // worth anything if a real JSON parser accepts the document *and* the document is
    // internally consistent: every result's `ruleId` has to name a rule the run
    // declares, or an ingesting tool drops the finding. Both are checked here by
    // python3, not by a reader of our own.
    if !available("python3") {
        return;
    }
    let dir = scratch();
    // The image is deliberately at an awkward path: SARIF locates an artifact by a URI
    // reference, and a path is not one. This name carries every character the URI grammar
    // treats specially — a space (not allowed in a URI at all), `#` (a fragment), `?` (a
    // query), `%` (the escape itself), a backslash, and a multi-byte character — so the
    // judge's decode-compare has something to catch.
    let image = at(&dir, "a b#c?d%e\\f\u{e9}.img");
    assert_eq!(code(&format(&image, "64M", None)), OK);

    // A clean image projects an empty findings list — exercised first, since an empty
    // `results` array is the shape most likely to be malformed.
    let clean = ok(&["inspect", "--sarif", image.to_str().expect("a text path")]);
    check_sarif(&clean, image.to_str().expect("a text path"), 0);

    // Corrupting a superblock field the checksum covers gives the scan something to
    // report, so the result objects themselves are projected and validated. `s_wtime`
    // at offset 0x30 is covered by the superblock checksum and read by nothing that
    // would fail earlier.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("reopen the image");
        f.seek(SeekFrom::Start(1024 + 0x30))
            .expect("seek to s_wtime");
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).expect("read s_wtime");
        byte[0] ^= 0xff;
        f.seek(SeekFrom::Start(1024 + 0x30)).expect("seek back");
        f.write_all(&byte).expect("corrupt s_wtime");
    }

    // A faulted image exits `IMAGE_BAD`, so the document comes off a failing run.
    let out = run(&["inspect", "--sarif", image.to_str().expect("a text path")]);
    assert_eq!(
        code(&out),
        IMAGE_BAD,
        "a corrupted superblock is a bad image:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    check_sarif(&out.stdout, image.to_str().expect("a text path"), 1);
}

/// Judge a SARIF document with `python3`: it must parse, carry the 2.1.0 envelope this
/// tool writes, name at least `min_results` findings, and — the part a substring check
/// cannot see — every result must reference a declared rule, carry a SARIF-legal level,
/// and locate itself in the image `artifact` names.
///
/// The location is judged as a URI, which is what SARIF asks for and what a path is not:
/// the string has to be spelled in the characters RFC 3986 allows, and it has to
/// percent-decode back to the exact path the run was given. Checking the decode rather
/// than the encoding keeps the judge from restating our own escaping rule back at us — any
/// correct encoding passes, and a path passed through raw fails on the first space.
fn check_sarif(document: &[u8], artifact: &str, min_results: usize) {
    let script = r#"
import json, os, re, sys, urllib.parse
doc = json.load(sys.stdin)
artifact, min_results = sys.argv[1], int(sys.argv[2])
# A rooted path names a file on this host, so it is located by an absolute `file://` URI;
# anything else stays the relative reference the invocation named.
expected = os.fsencode(("file://" + artifact) if artifact.startswith("/") else artifact)
# RFC 3986 3.2: a URI reference is spelled in unreserved and reserved characters and
# percent-escapes, and nothing else. A space, a backslash, or a raw non-ASCII byte is
# outside the grammar however permissive the reader.
uri_grammar = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
assert doc["version"] == "2.1.0", doc["version"]
assert doc["$schema"].endswith("sarif-2.1.0.json"), doc["$schema"]
runs = doc["runs"]
assert len(runs) == 1, len(runs)
driver = runs[0]["tool"]["driver"]
assert driver["name"] == "ferrosys", driver["name"]
declared = {r["id"] for r in driver["rules"]}
for r in driver["rules"]:
    assert r["name"] and r["shortDescription"]["text"], r
results = runs[0]["results"]
assert len(results) >= min_results, f"{len(results)} results, wanted >= {min_results}"
for r in results:
    # A result naming an undeclared rule is silently dropped by an ingesting tool.
    assert r["ruleId"] in declared, f'{r["ruleId"]} not in {declared}'
    assert r["level"] in ("error", "warning", "note", "none"), r["level"]
    assert isinstance(r["message"]["text"], str) and r["message"]["text"], r
    uris = [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for loc in r.get("locations", [])
        if "physicalLocation" in loc
    ]
    assert len(uris) == 1, f"one artifact location per result, got {uris}"
    assert uri_grammar.fullmatch(uris[0]), f"not a URI reference: {uris[0]!r}"
    decoded = urllib.parse.unquote_to_bytes(uris[0])
    assert decoded == expected, f"{decoded!r} != {expected!r}"
print("ok")
"#;
    let mut child = tool("python3")
        .args(["-c", script, artifact, &min_results.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(document)
        .expect("write the document");
    let out = child.wait_with_output().expect("python3 finishes");
    assert!(
        out.status.success(),
        "python3 rejected the SARIF document:\n{}\n{}",
        String::from_utf8_lossy(document),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn identity_rewrites_what_an_image_is_known_by() {
    let dir = scratch();
    let image = at(&dir, "id.img");
    // 512 MiB puts backups in groups 1 and 3, so the run covers the copies, not the
    // primary alone.
    assert_eq!(code(&format(&image, "512M", None)), OK);
    let path = image.to_str().expect("a text path");

    let out = ok(&[
        "identity",
        "--uuid",
        "5a5a1122-3344-4566-8788-99aabbccddee",
        "--label",
        "relabelled",
        path,
    ]);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("3 superblock copies written"), "{text}");
    assert!(text.contains("journal superblock updated"), "{text}");

    // Read back through the tool's own reader, so the assertion is about the image rather
    // than about what the rewrite reported.
    let report = String::from_utf8_lossy(&ok(&["inspect", "--json", path])).into_owned();
    assert!(
        report.contains("5a5a1122-3344-4566-8788-99aabbccddee"),
        "the new UUID is not in the report:\n{report}"
    );
    assert!(report.contains("relabelled"), "the new label:\n{report}");

    if available("e2fsck") {
        e2fsck_clean(&image);
    }
}

#[test]
fn identity_calls_a_sound_foreign_volume_what_it_is_not_a_bad_filesystem() {
    // `identity` rewrites ext fields, and pointed at a sound volume of another family the
    // verdict must be the one every verb gives a request it cannot carry out — exit 8 —
    // not "a filesystem was read and it is bad", which would send a CI step hunting for
    // damage in a volume that has none. The refusal names what the image holds, in the
    // word `detect` prints for it.
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    assert_eq!(code(&format_esp(&image, &tree)), OK);
    let path = image.to_str().expect("a text path");

    let out = run(&["identity", "--label", "x", path]);
    assert_eq!(code(&out), OPERATIONAL);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("fat32"), "{said}");
    assert!(said.contains("ext"), "{said}");

    // And the volume is untouched: a refusal writes nothing.
    let word = ok(&["detect", path]);
    assert_eq!(String::from_utf8_lossy(&word), "fat32\n");
}

#[test]
fn identity_reports_json_and_refuses_a_run_that_would_write_nothing() {
    let dir = scratch();
    let image = at(&dir, "id.img");
    assert_eq!(code(&format(&image, "64M", None)), OK);
    let path = image.to_str().expect("a text path");

    let out = ok(&["identity", "--label", "tagged", "--json", path]);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("\"superblocks\":1"), "{text}");
    assert!(text.contains("\"checksum_seed_set\":false"), "{text}");
    // A label change moves no UUID, so the log has nothing to record.
    assert!(text.contains("\"journal_superblock\":false"), "{text}");

    // Naming no change is a command line that meant to say something.
    let out = run(&["identity", path]);
    assert_eq!(code(&out), USAGE);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--uuid, --label, or --set-checksum-seed"),
        "{err}"
    );

    // A label past the field is refused before the image is opened.
    let out = run(&[
        "identity",
        "--label",
        "far too long to be a volume label",
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("the maximum is 16"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn identity_refuses_a_uuid_that_seeds_the_checksums_and_leaves_the_image_alone() {
    let dir = scratch();
    let image = at(&dir, "seeded.img");
    // metadata_csum without metadata_csum_seed: the checksums are seeded from the UUID.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "-O",
        "^metadata_csum_seed",
        image.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    let path = image.to_str().expect("a text path");
    let before = std::fs::read(&image).expect("read the image");

    let out = run(&[
        "identity",
        "--uuid",
        "11111111-2222-3333-4444-555555555555",
        path,
    ]);
    assert_eq!(code(&out), OPERATIONAL, "the request cannot be carried out");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalidate every metadata checksum"), "{err}");
    assert_eq!(
        std::fs::read(&image).expect("read the image"),
        before,
        "a refused rewrite wrote nothing"
    );

    // The way through, which the message names.
    let out = ok(&[
        "identity",
        "--uuid",
        "11111111-2222-3333-4444-555555555555",
        "--set-checksum-seed",
        path,
    ]);
    assert!(
        String::from_utf8_lossy(&out).contains("metadata_csum_seed set"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    if available("e2fsck") {
        e2fsck_clean(&image);
    }
}

// -- the FAT family -------------------------------------------------------------------
//
// The binary compiles in every family the library has, so an image of any of them is one
// this tool identifies, describes, and reads back. These gates are the second family's
// half of that claim, and `fsck.fat` is the foreign judge for the images they write —
// the same contract `e2fsck_clean` carries above.

/// Whether `fsck.fat` is runnable and is the pinned version.
///
/// It is in [`PINNED`] like every other checker, so this is [`available`] under its own name
/// rather than a second probe with its own rules.
fn fsck_fat_available() -> bool {
    available("fsck.fat")
}

/// Check a FAT image with `fsck.fat -n`, which answers no to every repair — so the image is
/// never modified and the exit status is a verdict rather than a report of what was fixed.
fn fsck_fat_clean(image: &Path) {
    if let Err(report) = checked(tool("fsck.fat").arg("-n").arg(image), "fsck.fat") {
        panic!("fsck.fat faulted the image\n{report}");
    }
}

/// A serial number in the form the tool prints and reads.
const SERIAL: &str = "1A2B-3C4D";

/// Build the ESP-shaped tree the FAT gates format: a boot payload under `/EFI/BOOT`, and
/// a file at the root.
///
/// Every mode is what a read of a FAT image fills in — `0755` for a directory and `0644`
/// for a file — so nothing about them is lost. The times are the host's, and those are
/// what the gates accept the loss of.
fn esp_tree(dir: &tempfile::TempDir) -> PathBuf {
    let root = dir.path().join("tree");
    std::fs::create_dir_all(root.join("EFI/BOOT")).expect("make the tree");
    std::fs::write(root.join("EFI/BOOT/BOOTX64.EFI"), b"MZ payload").expect("write the payload");
    std::fs::write(root.join("readme.txt"), b"hello\n").expect("write the file");
    let paths = [
        root.clone(),
        root.join("EFI"),
        root.join("EFI/BOOT"),
        root.join("EFI/BOOT/BOOTX64.EFI"),
        root.join("readme.txt"),
    ];
    for path in &paths {
        let mode = if path.is_dir() { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .expect("set the mode");
    }
    // The two losses this tree exists to exercise are stated here rather than left to the
    // host to supply.
    //
    // A change time is lost only where it differs from the modification time, and the
    // difference `set_permissions` leaves behind is however much of it the kernel's
    // timestamp granularity records. On a kernel with fine-grained change times that is
    // tens of microseconds and the loss is reported; on one without, the chmod lands in the
    // same tick as the write, the two times are equal to the nanosecond, and this tree
    // loses nothing at all -- so a build that must refuse succeeds and a report that must
    // name the change time does not. Naming the modification time outright puts it years
    // before the change time on any kernel.
    //
    // The second it names is odd, which FAT's two-second field cannot hold, so the
    // precision is lost as deliberately as the change time is. It sits one second past
    // `TIME`, the instant the volume itself is stamped with.
    for path in &paths {
        let status = std::process::Command::new("touch")
            .args(["-d", "@1700000001"])
            .arg(path)
            .status()
            .expect("run touch");
        assert!(
            status.success(),
            "set the modification time on {}",
            path.display()
        );
    }
    root
}

/// Format the ESP tree as a FAT32 volume, accepting the two losses a host tree always
/// takes: the change time, which the format has no field for, and the precision of the
/// times it does record.
fn format_esp(image: &Path, tree: &Path) -> Output {
    run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "fat32",
        "--volume-id",
        SERIAL,
        "--time",
        TIME,
        "--label",
        "ESP",
        "--owner",
        "0:0",
        "--accept-loss",
        "change-time,time-precision",
        "--from-dir",
        tree.to_str().expect("a text path"),
        image.to_str().expect("a text path"),
    ])
}

#[test]
fn an_auto_size_fits_a_fat_volume_and_slack_leaves_room_in_it() {
    let dir = scratch();
    let tree = esp_tree(&dir);

    let fit = |image: &Path, slack: Option<&str>| {
        let mut argv = vec![
            "format",
            "--size",
            "auto",
            "-t",
            "fat32",
            "--volume-id",
            SERIAL,
            "--time",
            TIME,
            "--owner",
            "0:0",
            "--accept-loss",
            "change-time,time-precision",
            "--from-dir",
            tree.to_str().expect("a text path"),
        ];
        if let Some(pct) = slack {
            argv.extend(["--slack", pct]);
        }
        argv.push(image.to_str().expect("a text path"));
        let out = run(&argv);
        assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
        fields(&String::from_utf8_lossy(&out.stderr))
    };

    // Sized to the tree rather than to a number the caller guessed.
    let tight_img = at(&dir, "tight.img");
    let tight = fit(&tight_img, None);
    let sectors: u64 = tight["Total sectors"].parse().expect("a sector count");
    let sector: u64 = tight["Bytes per sector"].parse().expect("a sector size");
    let clusters: u64 = tight["Clusters"].parse().expect("a cluster count");
    let free: u64 = tight["Free clusters"].parse().expect("a free count");

    // The image on disk is the size the search settled on, and a fitted volume is exactly
    // its own filesystem: nothing was rounded into it afterwards and nothing left over.
    assert_eq!(
        std::fs::metadata(&tight_img)
            .expect("the image exists")
            .len(),
        sectors * sector
    );

    // A small tree lands on FAT32's own floor — the type needs 65525 clusters whatever it
    // holds — so it is already almost entirely free, and a share cannot make it grow.
    assert_eq!(clusters, 65_525, "the smallest FAT32 there is");
    assert!(free > clusters - 1_000, "and nearly all of it is free");

    // Room named in bytes is what does make it grow, because it is a claim the floor does
    // not already satisfy.
    let roomy_img = at(&dir, "roomy.img");
    let roomy = fit(&roomy_img, Some("200M"));
    let roomy_clusters: u64 = roomy["Clusters"].parse().expect("a cluster count");
    let roomy_free: u64 = roomy["Free clusters"].parse().expect("a free count");
    assert!(
        roomy_clusters > clusters,
        "asking for room produces a larger volume: {roomy_clusters} against {clusters}"
    );
    let roomy_cluster_bytes: u64 = roomy["Bytes per cluster"].parse().expect("a cluster size");
    assert!(
        roomy_free * roomy_cluster_bytes >= 200 << 20,
        "200 MiB is free: {roomy_free} clusters of {roomy_cluster_bytes}"
    );
    assert!(free < roomy_free, "and the tight one leaves less");

    // Both are volumes a foreign checker accepts. A fitted volume is the tightest one this
    // tool writes, which is where an off-by-one in the search would show.
    if fsck_fat_available() {
        fsck_fat_clean(&tight_img);
        fsck_fat_clean(&roomy_img);
    }
}

#[test]
fn a_fat_volume_the_tool_wrote_is_one_a_foreign_checker_accepts() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    let out = format_esp(&image, &tree);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    // The summary names what the volume could not carry, in the words `--accept-loss`
    // reads — so a property the report shows is one that can be typed back in.
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("change-time"), "{said}");
    assert!(said.contains("Volume serial number:   1A2B-3C4D"), "{said}");
    // The label as it was given, not as the eleven-byte field pads it.
    assert!(said.contains("Volume label:           ESP\n"), "{said}");

    if fsck_fat_available() {
        fsck_fat_clean(&image);
    }
}

#[test]
fn a_fat_volume_is_detected_described_and_read_back_by_the_binary() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    assert_eq!(code(&format_esp(&image, &tree)), OK);
    let path = image.to_str().expect("a text path");

    // `detect` names the type, not just the family: the word a caller acts on, and the
    // same word `-t` takes. Answering `unrecognized` here is the failure this whole
    // command exists to end.
    assert_eq!(ok(&["detect", path]), b"fat32\n");

    // `inspect` describes it through the same envelope an ext image gets: a head that
    // means the same thing for both, then this family's own body.
    let report = String::from_utf8(ok(&["inspect", path])).expect("text");
    assert!(
        report.contains("Filesystem family:          fat"),
        "{report}"
    );
    assert!(
        report.contains("Filesystem variant:         fat32"),
        "{report}"
    );
    assert!(
        report.contains("Filesystem identifier:      1A2B-3C4D"),
        "{report}"
    );
    // The body is FAT's own vocabulary, and none of ext's.
    assert!(report.contains("Bytes per cluster:"), "{report}");
    assert!(report.contains("Allocation tables:"), "{report}");
    assert!(!report.contains("Block groups:"), "{report}");

    // ...and the whole image was scanned, so this is a verdict rather than a description.
    assert!(report.contains("no findings"), "{report}");

    // `extract` reads the tree back out through the shared extraction surface.
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    for name in ["/EFI", "/EFI/BOOT", "/EFI/BOOT/BOOTX64.EFI", "/readme.txt"] {
        assert!(listing.contains(name), "{name} is missing from\n{listing}");
    }
    assert_eq!(ok(&["extract", path, "--cat", "/readme.txt"]), b"hello\n");
}

#[test]
fn a_fat_report_omits_what_the_format_has_no_answer_for() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    assert_eq!(code(&format_esp(&image, &tree)), OK);
    let path = image.to_str().expect("a text path");

    let json =
        String::from_utf8(ok(&["extract", path, "--stat", "/readme.txt", "--json"])).expect("text");
    // FAT has no inode numbers and no second name for a node. The fields are absent
    // rather than null or zero: a zero would be this tool answering a question the format
    // never asked.
    assert!(!json.contains("\"inode\""), "{json}");
    assert!(!json.contains("\"links\""), "{json}");
    // What the report *did* fill in is named, in the spelling `--accept-loss` reads.
    assert!(json.contains("\"synthesized\":["), "{json}");
    assert!(json.contains("\"ownership\""), "{json}");
    assert!(json.contains("\"change-time\""), "{json}");

    // The same two fields are present on an ext image, and its synthesized list is empty:
    // an ext inode records every property a report names.
    let ext_image = at(&dir, "ext.img");
    assert_eq!(code(&format(&ext_image, "64M", None)), OK);
    let json = String::from_utf8(ok(&[
        "extract",
        ext_image.to_str().unwrap(),
        "--stat",
        "/",
        "--json",
    ]))
    .expect("text");
    assert!(json.contains("\"inode\":2"), "{json}");
    assert!(json.contains("\"links\":"), "{json}");
    assert!(json.contains("\"synthesized\":[]"), "{json}");
}

#[test]
fn an_option_of_one_family_is_refused_for_another_rather_than_ignored() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let path = image.to_str().expect("a text path");

    // A journal is ext's, and a FAT volume has none. Refused by name: a run that was
    // handed a volume built differently from the one it asked for would never know.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "fat32",
        "--volume-id",
        SERIAL,
        "--time",
        TIME,
        "--journal",
        "4096",
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--journal"), "{said}");
    assert!(said.contains("ext family"), "{said}");
    assert!(!image.exists(), "a refused line wrote nothing");

    // ...and the reporting side of the same rule: a block group is how an ext filesystem
    // divides itself, so `--groups` on a FAT volume is a question with no answer.
    let tree = esp_tree(&dir);
    assert_eq!(code(&format_esp(&image, &tree)), OK);
    let out = run(&["inspect", "--groups", path]);
    assert_eq!(code(&out), OPERATIONAL);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--groups does not apply"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_fat_build_refuses_what_it_would_lose_until_it_is_told_it_may() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    let path = image.to_str().expect("a text path");
    let tree_path = tree.to_str().expect("a text path");

    // The same line without `--accept-loss`: the host tree's change times have nowhere to
    // go, and the build says so rather than dropping them.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "fat32",
        "--volume-id",
        SERIAL,
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--from-dir",
        tree_path,
        path,
    ]);
    assert_eq!(code(&out), OPERATIONAL);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("change time"), "{said}");
    assert!(!image.exists(), "a refused build wrote nothing");

    // A symbolic link is a loss of a different kind, and accepting the times does not
    // accept it: the acknowledgement names properties for exactly this reason.
    std::os::unix::fs::symlink("readme.txt", tree.join("link")).expect("make a symlink");
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "fat32",
        "--volume-id",
        SERIAL,
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--accept-loss",
        "change-time,time-precision",
        "--from-dir",
        tree_path,
        path,
    ]);
    assert_eq!(code(&out), OPERATIONAL);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("/link"), "{said}");

    // Naming that one too is what lets it through, and the link is simply not there.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "fat32",
        "--volume-id",
        SERIAL,
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--accept-loss",
        "change-time,time-precision,kind",
        "--from-dir",
        tree_path,
        path,
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    assert!(!listing.contains("/link"), "{listing}");
}

// -- the exFAT family -----------------------------------------------------------------
//
// The third family's half of the same claim, and the one place these gates go further than
// the two above: one of them runs the shipping binary over a volume *no part of this
// workspace wrote*. The FAT family's gap here is what makes that worth a gate of its own —
// the library could read a volume the binary answered `unrecognized` for, and every test
// used images the tool could also write, so nothing noticed. A foreign image through the
// command is the check that would have.

/// The volume serial the exFAT gates write, in the form the tool prints and reads.
const EXFAT_SERIAL: &str = "5E71-A10C";

/// Check an exFAT volume with `fsck.exfat -n`, which answers no to every repair — so the
/// image is never modified and the exit status is a verdict rather than a report of what was
/// fixed.
fn fsck_exfat_clean(image: &Path) {
    if let Err(report) = checked(tool("fsck.exfat").arg("-n").arg(image), "fsck.exfat") {
        panic!("fsck.exfat faulted the image\n{report}");
    }
}

/// Format the ESP tree as an exFAT volume, accepting the two losses a host tree always takes.
///
/// The same two the FAT gates accept, which is worth stating because the reason has narrowed
/// and not gone: exFAT keeps a creation and a modification time to ten milliseconds, so the
/// odd second `esp_tree` sets survives in both of those exactly — and its *access* time is
/// two-second granular like FAT's, with no hundredths field beside it, so the precision is
/// still lost on that one. The change time has nowhere to go in either format.
fn format_exfat(image: &Path, tree: &Path) -> Output {
    run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "exfat",
        "--volume-serial",
        EXFAT_SERIAL,
        "--label",
        "ESP",
        "--owner",
        "0:0",
        "--accept-loss",
        "change-time,time-precision",
        "--from-dir",
        tree.to_str().expect("a text path"),
        image.to_str().expect("a text path"),
    ])
}

#[test]
fn an_exfat_volume_the_tool_wrote_is_one_a_foreign_checker_accepts() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    let out = format_exfat(&image, &tree);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    // The summary names what the volume could not carry, in the words `--accept-loss` reads —
    // so a property the report shows is one that can be typed back in.
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("change-time"), "{said}");
    assert!(said.contains("time-precision"), "{said}");
    assert!(said.contains("Volume serial number:   5E71-A10C"), "{said}");
    assert!(said.contains("Volume label:           ESP\n"), "{said}");
    // The three the format allocates before a caller's first file, which no other family's
    // summary has a line for.
    assert!(said.contains("Up-case table at cluster:"), "{said}");

    if available("fsck.exfat") {
        fsck_exfat_clean(&image);
    }
}

#[test]
fn exfat_refuses_the_time_flag_it_has_no_field_for() {
    // An exFAT volume records no instant of its own anywhere, so `--time` here would be
    // an accepted flag that changes nothing — which reads as one that worked. It is
    // refused by name, exactly as any other option of a family that was not named is,
    // and the command line without it is complete.
    let dir = scratch();
    let image = at(&dir, "timed.img");
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "exfat",
        "--volume-serial",
        EXFAT_SERIAL,
        "--time",
        TIME,
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--time") && said.contains("exfat"), "{said}");
    assert!(!image.exists(), "a refused line wrote nothing");
}

#[test]
fn an_exfat_volume_is_detected_described_and_read_back_by_the_binary() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    assert_eq!(code(&format_exfat(&image, &tree)), OK);
    let path = image.to_str().expect("a text path");

    // One word, and it is the family's: this format has one revision and every volume records
    // it, so there is no finer answer to give. It is the same word `-t` takes.
    assert_eq!(ok(&["detect", path]), b"exfat\n");

    // `inspect` describes it through the same envelope the other two get: a head that means
    // the same thing for all three, then this family's own body.
    let report = String::from_utf8(ok(&["inspect", path])).expect("text");
    assert!(
        report.contains("Filesystem family:          exfat"),
        "{report}"
    );
    assert!(
        report.contains("Filesystem variant:         exfat"),
        "{report}"
    );
    assert!(
        report.contains("Filesystem identifier:      5E71-A10C"),
        "{report}"
    );
    // The body is exFAT's own vocabulary, and none of either neighbour's: no block groups,
    // and no second allocation table to count.
    assert!(report.contains("Up-case table at cluster:"), "{report}");
    assert!(report.contains("Volume state:"), "{report}");
    assert!(!report.contains("Block groups:"), "{report}");
    assert!(!report.contains("Allocation tables:"), "{report}");
    // ...and the whole image was scanned, so this is a verdict rather than a description.
    assert!(report.contains("no findings"), "{report}");

    // `extract` reads the tree back out through the shared extraction surface. The names come
    // back in the case they went in — this format stores one name and stores it whole.
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    for name in ["/EFI", "/EFI/BOOT", "/EFI/BOOT/BOOTX64.EFI", "/readme.txt"] {
        assert!(listing.contains(name), "{name} is missing from\n{listing}");
    }
    assert_eq!(ok(&["extract", path, "--cat", "/readme.txt"]), b"hello\n");
}

#[test]
fn a_volume_nothing_here_wrote_is_read_by_the_shipping_binary() {
    // The measurement this family's CLI half exists for, and the one the FAT family had no
    // gate for. Every byte of this volume was decided by `mkfs.exfat` and by relan/exfat's
    // `libexfat`; the binary has to identify it, describe it, and read what is in it.
    if !available("mkfs.exfat") || !available("exfat-populate") {
        return;
    }
    let dir = scratch();
    let image = at(&dir, "foreign.img");
    std::fs::File::create(&image)
        .expect("create the image")
        .set_len(64 << 20)
        .expect("size the image");
    let out = tool("mkfs.exfat")
        .args(["-L", "FOREIGN"])
        .arg(&image)
        .output()
        .expect("spawn mkfs.exfat");
    assert!(
        out.status.success(),
        "the baseline could not build the volume: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A tree with a name longer than one entry spells and a file large enough to span several
    // clusters, so what the binary reads back is a reassembled name and a followed run rather
    // than one entry and one cluster.
    let script = "mkdir /DCIM\nwrite /DCIM/A_Long_Name_For_The_Reader.bin 200000 1\n";
    let mut child = tool("exfat-populate")
        .arg(&image)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn exfat-populate");
    child
        .stdin
        .as_mut()
        .expect("the populator's standard input")
        .write_all(script.as_bytes())
        .expect("write the script");
    let filled = child.wait_with_output().expect("wait for exfat-populate");
    assert!(
        filled.status.success(),
        "the foreign populator could not fill the volume: {}",
        String::from_utf8_lossy(&filled.stderr)
    );

    let path = image.to_str().expect("a text path");
    assert_eq!(ok(&["detect", path]), b"exfat\n");

    let report = String::from_utf8(ok(&["inspect", path])).expect("text");
    assert!(
        report.contains("Filesystem family:          exfat"),
        "{report}"
    );
    // A volume a conformant foreign implementation wrote is one this tool finds nothing wrong
    // with. A finding here is either a real difference between two writers or a rule this
    // crate has stated too narrowly, and both are worth a red gate.
    assert!(report.contains("no findings"), "{report}");

    // And the contents, which is the half a clean scan does not cover: a reader that read
    // nothing would report no anomalies either.
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    assert!(
        listing.contains("/DCIM/A_Long_Name_For_The_Reader.bin"),
        "{listing}"
    );
    let bytes = ok(&[
        "extract",
        path,
        "--cat",
        "/DCIM/A_Long_Name_For_The_Reader.bin",
    ]);
    assert_eq!(bytes.len(), 200_000, "the whole file came back");
    // The populator's fill is a little-endian counter naming the offset each word belongs at,
    // so a read that landed four bytes out reads back a number that says where it really is.
    let word = u32::from_le_bytes(bytes[4000..4004].try_into().expect("four bytes"));
    assert_eq!(word, 1000 + 1, "the bytes came from the right offset");
}

#[test]
fn a_size_this_family_cannot_search_for_is_refused_before_anything_is_read() {
    let dir = scratch();
    let image = at(&dir, "esp.img");

    // `--size auto` plans candidate sizes and places the contents into each, and that search
    // is a family's own. This one has none, so the refusal comes from the command line rather
    // than from a plan — which is what keeps a whole tree from being walked to say so.
    //
    // The source is a directory that is not there, and that is the assertion: a run that
    // reached the planning stage would fail on the missing tree instead, so the message being
    // about the size is what says nothing was read. Without it the refusal could equally come
    // from the plan, which spells the same words on purpose.
    let out = run(&[
        "format",
        "--size",
        "auto",
        "-t",
        "exfat",
        "--volume-serial",
        EXFAT_SERIAL,
        "--accept-loss",
        "change-time,time-precision",
        "--from-dir",
        dir.path()
            .join("no-such-tree")
            .to_str()
            .expect("a text path"),
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--size auto"), "{said}");
    assert!(said.contains("exfat"), "{said}");
    assert!(!image.exists(), "a refused line wrote nothing");
}

#[test]
fn an_option_belongs_to_a_family_or_to_the_class_that_shares_it() {
    let dir = scratch();
    let image = at(&dir, "out.img");
    let path = image.to_str().expect("a text path");

    // Each family names its own identity, and neither of the other two flags reaches this one.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "exfat",
        "--volume-id",
        SERIAL,
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--volume-id"), "{said}");
    assert!(said.contains("fat family"), "{said}");

    // ...and the reverse, so neither direction is the one that happens to work.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--uuid",
        UUID,
        "--volume-serial",
        EXFAT_SERIAL,
        "--time",
        TIME,
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--volume-serial"), "{said}");
    assert!(said.contains("exfat family"), "{said}");

    // But `--accept-loss` belongs to a *class* rather than to a family: the two formats that
    // record a name, a few attribute bits and some times lose the same six properties for the
    // same reason, so the option reaches both and is refused only for the third.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "--uuid",
        UUID,
        "--time",
        TIME,
        "--accept-loss",
        "all",
        path,
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--accept-loss"), "{said}");
    assert!(said.contains("the fat and exfat families"), "{said}");
    assert!(!image.exists(), "a refused line wrote nothing");
}

/// A path that descends through a regular file is the caller's error, on every family.
///
/// The exit-code contract draws the 4-versus-8 line at "a filesystem was read, and it is
/// bad", so a typo'd path must answer 8 with the path in the message whichever family
/// answers — a gate keyed on 4 must never receive a corruption verdict from a caller's typo.
#[test]
fn a_path_through_a_file_is_the_callers_error_whichever_family_answers() {
    let dir = scratch();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).expect("make the tree");
    std::fs::write(tree.join("hello.txt"), b"hello\n").expect("the file");
    // Modes the FAT and exFAT read-back reports for every entry, so the format loses
    // nothing this test is not about.
    std::fs::set_permissions(&tree, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the directory's mode");
    std::fs::set_permissions(
        tree.join("hello.txt"),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .expect("the file's mode");
    let tree = tree.to_str().expect("a text path");

    let families: [(&str, Vec<&str>); 4] = [
        ("ext4", vec!["--uuid", UUID, "--time", TIME]),
        (
            "fat32",
            vec![
                "--volume-id",
                SERIAL,
                "--time",
                TIME,
                "--accept-loss",
                "change-time,time-precision",
            ],
        ),
        (
            "exfat",
            vec![
                "--volume-serial",
                EXFAT_SERIAL,
                "--accept-loss",
                "change-time,time-precision",
            ],
        ),
        // The one family whose smallest default-profile volume is past sixty-four mebibytes.
        (
            "btrfs",
            vec!["--fsid", FSID, "--time", TIME, "--size", "128M"],
        ),
    ];
    for (family, identity) in families {
        let image = at(&dir, &format!("{family}.img"));
        let path = image.to_str().expect("a text path");
        let mut args = vec!["format", "-t", family, "--owner", "0:0", "--from-dir", tree];
        if family != "btrfs" {
            args.extend_from_slice(&["--size", "64M"]);
        }
        args.extend_from_slice(&identity);
        args.push(path);
        let out = run(&args);
        assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

        let out = run(&["extract", path, "--cat", "/hello.txt/x"]);
        assert_eq!(
            code(&out),
            OPERATIONAL,
            "{family}: a typo'd path is not a verdict about the image:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(
            said.contains("no such path in the filesystem: /hello.txt/x"),
            "{family}: what reaches the caller is the path it typed: {said}"
        );
    }
}

#[test]
fn an_exfat_label_is_text_and_a_lookup_is_case_insensitive() {
    let dir = scratch();
    let image = at(&dir, "esp.img");
    let tree = esp_tree(&dir);
    let path = image.to_str().expect("a text path");
    assert_eq!(code(&format_exfat(&image, &tree)), OK);

    // The volume's own up-case table is what a lookup folds through, so a path in a case
    // nobody wrote reaches the entry a driver reading the same volume would reach.
    assert_eq!(ok(&["extract", path, "--cat", "/README.TXT"]), b"hello\n");
    assert_eq!(ok(&["extract", path, "--cat", "/readme.txt"]), b"hello\n");

    // A label of twelve code units is one the eleven-unit field cannot hold, and it is refused
    // rather than truncated into a name no reader spells the way it was typed.
    let out = run(&[
        "format",
        "--size",
        "64M",
        "-t",
        "exfat",
        "--volume-serial",
        EXFAT_SERIAL,
        "--label",
        "TWELVE CHARS",
        at(&dir, "labelled.img").to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--label"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// -- the btrfs family -----------------------------------------------------------------
//
// The fourth family, and the one whose two halves shipped a release apart: the reading gates
// below came first and every fixture in them is a filesystem `mkfs.btrfs` built and filled,
// which is the case the exFAT gates had to construct deliberately and the one that matters
// most — a library that reads an image the shipping binary answers `unrecognized` for is a
// library nobody can point at anything. The writing gates follow, and what they add is the
// other direction: an image this tool laid out, put in front of the checker that has no hand
// in it.

/// How large the btrfs fixture is.
///
/// Above the smallest this pin will format at its default metadata profile, and sparse, so what
/// it costs is its metadata and the file put into it.
const BTRFS_BYTES: u64 = 512 << 20;

/// A btrfs nothing in this workspace wrote, filled from a tree nothing in this workspace reads.
///
/// One tool does both halves, which is this family's difference from exFAT's fixture: `mkfs.btrfs
/// -r` lays the filesystem out and copies a directory into it, and `--subvol` makes part of that
/// directory a filesystem tree of its own — so the fixture reaches a structure no other family
/// here has, without a second implementation being involved.
fn foreign_btrfs(dir: &tempfile::TempDir) -> PathBuf {
    let tree = dir.path().join("btrfs-tree");
    std::fs::create_dir_all(tree.join("etc")).expect("make the tree");
    std::fs::create_dir(tree.join("home")).expect("make the subvolume's directory");
    std::fs::write(tree.join("etc/hostname"), b"hello\n").expect("write the file");
    std::fs::write(tree.join("home/note.txt"), b"inside\n").expect("write the file");
    // A link naming a directory, which is how every current distribution's root filesystem is
    // laid out: `/bin`, `/lib`, and `/sbin` are links into `/usr`, so a path resolved through
    // one is the ordinary case rather than an edge of it.
    std::os::unix::fs::symlink("etc", tree.join("to-etc")).expect("link to a directory");

    let image = at(dir, "foreign-btrfs.img");
    std::fs::File::create(&image)
        .expect("create the image")
        .set_len(BTRFS_BYTES)
        .expect("size the image");
    let out = tool("mkfs.btrfs")
        .args([
            "-q", "-f", "-s", "4096", "-L", "FOREIGN", "--subvol", "rw:home", "-r",
        ])
        .arg(&tree)
        .arg(&image)
        .output()
        .expect("spawn mkfs.btrfs");
    assert!(
        out.status.success(),
        "the baseline could not build the filesystem: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    image
}

#[test]
fn a_btrfs_nothing_here_wrote_is_detected_described_and_read_back_by_the_binary() {
    if !available("mkfs.btrfs") {
        return;
    }
    let dir = scratch();
    let image = foreign_btrfs(&dir);
    let path = image.to_str().expect("a text path");

    // One word, and it is the family's: this format has one revision, no lineage to spell, and
    // nothing finer to sub-classify into.
    assert_eq!(ok(&["detect", path]), b"btrfs\n");

    let report = String::from_utf8(ok(&["inspect", path])).expect("text");
    assert!(
        report.contains("Filesystem family:          btrfs"),
        "{report}"
    );
    assert!(
        report.contains("Filesystem variant:         btrfs"),
        "{report}"
    );
    assert!(
        report.contains("Label:                      FOREIGN"),
        "{report}"
    );
    // The body is this family's own vocabulary and none of the other three's: a tree block is
    // not a block group, and a chunk map is a layer no other family in this tool has.
    assert!(report.contains("Tree block size:"), "{report}");
    assert!(report.contains("Mapped chunks:"), "{report}");
    assert!(report.contains("FS_TREE at:"), "{report}");
    assert!(!report.contains("Block groups:"), "{report}");
    assert!(!report.contains("Allocation tables:"), "{report}");
    // Every superblock copy the volume has room for, said one by one rather than counted: which
    // copy is damaged is what a person acts on.
    assert!(
        report.contains("Superblock copies:          present"),
        "{report}"
    );
    // The subvolumes, which is the thing someone points this command at a btrfs to find out.
    // The top-level tree is one of them and is the one no directory entry names.
    assert!(report.contains("Subvolume <top-level>:"), "{report}");
    assert!(report.contains("Subvolume home:"), "{report}");
    // A filesystem a conformant foreign implementation wrote is one this tool finds nothing
    // wrong with. A finding here is either a real difference between two writers or a rule this
    // crate has stated too narrowly, and both are worth a red gate.
    assert!(report.contains("no findings"), "{report}");

    // And the contents, which is the half a clean scan does not cover: a reader that read
    // nothing would report no anomalies either. The walk crosses the subvolume boundary, so
    // what comes back is the filesystem rather than one of its trees.
    let listing = String::from_utf8(ok(&["extract", path, "--list"])).expect("text");
    for name in ["/etc/hostname", "/home", "/home/note.txt", "/to-etc -> etc"] {
        assert!(listing.contains(name), "{name} is missing from\n{listing}");
    }
    assert_eq!(ok(&["extract", path, "--cat", "/etc/hostname"]), b"hello\n");
    assert_eq!(
        ok(&["extract", path, "--cat", "/home/note.txt"]),
        b"inside\n"
    );
    // A path continuing through a link to a directory, which is the resolution a distribution's
    // root filesystem needs on nearly every absolute path in it.
    assert_eq!(
        ok(&["extract", path, "--cat", "/to-etc/hostname"]),
        b"hello\n"
    );
    // And an ascent, on a filesystem this tool did not write: back out of one directory and
    // down into another, which is the other half of what a relative link on a real root
    // filesystem needs.
    assert_eq!(
        ok(&["extract", path, "--cat", "/home/../etc/hostname"]),
        b"hello\n"
    );
}

// -- the btrfs family, written --------------------------------------------------------
//
// What the gates above establish is that this tool reads a filesystem it had no hand in.
// These are the other direction, and the authority runs the other way with it: the checker
// that built none of these images is what says each one is a filesystem, and this tool's own
// reader is what says the tree inside it is the tree that went in. Neither claim alone is
// enough — a checker accepts an empty filesystem happily, and a reader agreeing with the
// writer it was built beside proves only that the two share a misunderstanding.

/// How large the images these gates write are.
///
/// Well past the smallest this pin formats at the default profile pairing, and sparse, so what
/// one costs is its metadata and whatever went into it.
const BTRFS_WRITTEN_BYTES: &str = "1G";

/// The filesystem id every image here is written with, in the dashed form the tool prints.
const FSID: &str = "5f2ac1de-0000-4000-8000-000000000001";

/// Assert `btrfs check` finds nothing to fault, with its data pass as well.
///
/// Both passes, because they are two checkers rather than one loud one: a file whose bytes
/// have been altered is a clean filesystem to the first and a fault to the second, so an image
/// that has only met the first has not been asked about its data at all.
fn btrfs_check_clean(image: &Path) {
    for extra in [&[][..], &["--check-data-csum"][..]] {
        let mut cmd = tool("btrfs");
        cmd.args(["check", "--readonly"]).args(extra).arg(image);
        if let Err(report) = checked(&mut cmd, "btrfs check") {
            panic!("btrfs check faulted an image this tool wrote\n{report}");
        }
    }
}

/// A source tree with one of everything the round trip below asserts on.
///
/// Small, and each entry is a distinct claim: a nested directory, a file whose bytes are past
/// what a leaf holds so it becomes an addressed extent, a file small enough to live inside the
/// metadata, a symbolic link, and a second name for a file. Two directories at the root, which
/// is what lets the subvolume gate make one a tree of its own and leave the other where it is.
fn btrfs_source(dir: &tempfile::TempDir) -> PathBuf {
    let root = dir.path().join("btrfs-source");
    std::fs::create_dir_all(root.join("system/etc")).expect("make the tree");
    std::fs::create_dir_all(root.join("people/user")).expect("make the tree");
    std::fs::write(root.join("system/etc/hostname"), b"ferrosys\n").expect("write the file");
    // Every byte a function of its own position, so a read that returned another file's
    // correctly-checksummed bytes is caught by the contents rather than by the length.
    let large: Vec<u8> = (0..300_000u32).map(|at| (at % 251) as u8).collect();
    std::fs::write(root.join("people/user/blob.bin"), &large).expect("write the file");
    std::os::unix::fs::symlink("etc/hostname", root.join("system/name")).expect("link to a file");
    std::fs::hard_link(
        root.join("system/etc/hostname"),
        root.join("system/etc/hostname.also"),
    )
    .expect("a second name for one file");
    root
}

#[test]
fn a_btrfs_this_tool_wrote_is_a_filesystem_the_checker_accepts_and_reads_back_as_it_went_in() {
    if !available("mkfs.btrfs") {
        return;
    }
    let dir = scratch();
    let source = btrfs_source(&dir);
    let image = at(&dir, "written.img");
    let path = image.to_str().expect("a text path");

    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "--label",
        "ferrosys",
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--from-dir",
        source.to_str().expect("a text path"),
        path,
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));

    // The authority that had no hand in it.
    btrfs_check_clean(&image);

    // And this tool's own reader over the same image, which is the half a checker cannot make:
    // a filesystem with the wrong bytes under the right checksums passes `check` and fails here.
    assert_eq!(ok(&["detect", path]), b"btrfs\n");
    let report = String::from_utf8_lossy(&ok(&["inspect", path])).into_owned();
    assert!(
        report.contains("Filesystem family:          btrfs"),
        "{report}"
    );
    assert!(
        report.contains(FSID),
        "the id it was written with: {report}"
    );
    assert!(report.contains("ferrosys"), "the label: {report}");
    assert!(report.contains("no findings"), "{report}");

    assert_eq!(
        ok(&["extract", path, "--cat", "/system/etc/hostname"]),
        b"ferrosys\n"
    );
    // Through the symbolic link, and through it to the file it names.
    assert_eq!(
        ok(&["extract", path, "--cat", "/system/name"]),
        b"ferrosys\n"
    );
    // The second name for one file is the same file.
    assert_eq!(
        ok(&["extract", path, "--cat", "/system/etc/hostname.also"]),
        b"ferrosys\n"
    );
    // And the file whose bytes are past what a leaf holds comes back as what went in, byte for
    // byte, which is what says the extents were addressed rather than merely counted.
    let large: Vec<u8> = (0..300_000u32).map(|at| (at % 251) as u8).collect();
    assert_eq!(
        ok(&["extract", path, "--cat", "/people/user/blob.bin"]),
        large
    );
}

/// A feature named on the command line reaches the superblock, and the filesystem it produces
/// is one the checker still accepts.
///
/// The case worth writing the option for: `block-group-tree` is a default of this pin and a
/// kernel older than 6.1 cannot mount a filesystem carrying it, so clearing it is how a caller
/// writes an image for an older kernel. What is asserted is the whole path — the word is
/// parsed in btrfs's vocabulary, the planner writes the word it selected, `inspect` prints the
/// same word back, and an authority that had no hand in any of it calls the result sound.
#[test]
fn a_feature_named_on_the_command_line_reaches_the_filesystem_and_is_read_back_by_its_name() {
    if !available("mkfs.btrfs") {
        return;
    }
    let dir = scratch();
    let source = btrfs_source(&dir);
    let image = at(&dir, "features.img");
    let path = image.to_str().expect("a text path");

    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "-O",
        "^block-group-tree",
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--from-dir",
        source.to_str().expect("a text path"),
        path,
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    btrfs_check_clean(&image);

    let report = String::from_utf8_lossy(&ok(&["inspect", path])).into_owned();
    let features = report
        .lines()
        .find_map(|line| line.trim().strip_prefix("Filesystem features:"))
        .map(str::trim)
        .unwrap_or_else(|| panic!("inspect reported no feature line\n{report}"));
    assert!(
        !features.split(' ').any(|word| word == "block-group-tree"),
        "the feature the command line cleared is still there: {features}"
    );
    // The rest of the baseline is untouched, which is what says one name moved one feature.
    for word in ["free-space-tree", "no-holes", "skinny-metadata", "extref"] {
        assert!(
            features.split(' ').any(|have| have == word),
            "{word} is missing from {features}"
        );
    }

    // A word of another family's vocabulary is refused rather than ignored, so a command line
    // that asked for something this filesystem has no concept of does not quietly succeed.
    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "-O",
        "has_journal",
        "--time",
        TIME,
        at(&dir, "refused.img").to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("not a feature name of the btrfs family"),
        "{err}"
    );
}

#[test]
fn subvolumes_are_written_where_the_command_line_put_them_and_the_checker_takes_them() {
    if !available("mkfs.btrfs") {
        return;
    }
    let dir = scratch();
    let source = btrfs_source(&dir);
    let image = at(&dir, "subvolumes.img");
    let path = image.to_str().expect("a text path");

    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "--subvol",
        "5f2ac1de-0000-4000-8000-0000000000a1:/system",
        "--subvol",
        "ro:5f2ac1de-0000-4000-8000-0000000000a2:/people",
        "--default-subvol",
        "/system",
        "--time",
        TIME,
        "--owner",
        "0:0",
        "--from-dir",
        source.to_str().expect("a text path"),
        path,
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    btrfs_check_clean(&image);

    // The checker's root-reference pass is what says the linkage between a subvolume and the
    // directory it hangs under is sound, and it runs above. What this adds is that the trees
    // are the ones asked for: two beside the one every btrfs has, one of them read-only, and a
    // mount told no subvolume landing on the first.
    let report = String::from_utf8_lossy(&ok(&["inspect", path])).into_owned();
    assert!(report.contains("Subvolume system:"), "{report}");
    assert!(report.contains("default"), "{report}");
    assert!(
        report.contains("Subvolume people:") && report.contains("read-only"),
        "{report}"
    );

    // A walk crosses the boundary rather than stopping at it, so the tree a reader sees is the
    // filesystem rather than one of its trees — which is the property that makes a subvolume
    // layout usable at all.
    assert_eq!(
        ok(&["extract", path, "--cat", "/system/etc/hostname"]),
        b"ferrosys\n"
    );
}

#[test]
fn every_identifier_and_every_geometry_knob_reaches_the_image() {
    if !available("mkfs.btrfs") {
        return;
    }
    let dir = scratch();
    let image = at(&dir, "knobs.img");
    let path = image.to_str().expect("a text path");

    // Each identifier a distinct value, so a field written out of the wrong one is visible
    // rather than a coincidence of zeros — and a geometry that is not the default at any of
    // its four knobs, so a knob that was read and dropped is a difference rather than a match.
    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "--metadata-uuid",
        "5f2ac1de-0000-4000-8000-0000000000b1",
        "--chunk-tree-uuid",
        "5f2ac1de-0000-4000-8000-0000000000b2",
        "--device-uuid",
        "5f2ac1de-0000-4000-8000-0000000000b3",
        "--subvolume-uuid",
        "5f2ac1de-0000-4000-8000-0000000000b4",
        "--sector-size",
        "4096",
        "--node-size",
        "4096",
        "--metadata-profile",
        "single",
        "--data-profile",
        "dup",
        "--time",
        TIME,
        "--json",
        path,
    ]);
    assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
    btrfs_check_clean(&image);

    let receipt = String::from_utf8_lossy(&out.stdout).into_owned();
    for uuid in [
        "5f2ac1de-0000-4000-8000-0000000000b1",
        "5f2ac1de-0000-4000-8000-0000000000b2",
        "5f2ac1de-0000-4000-8000-0000000000b3",
        "5f2ac1de-0000-4000-8000-0000000000b4",
    ] {
        assert!(receipt.contains(uuid), "{uuid} is not in {receipt}");
    }
    assert!(receipt.contains("\"node_size\":4096"), "{receipt}");
    // A profile decides how many copies of a chunk the device carries, and this line asks for
    // them the other way round from the defaults — so a run that ignored both options would
    // still differ from one that ignored only one.
    let copies = |contents: &str| {
        receipt
            .split(&format!("\"contents\":\"{contents}\""))
            .nth(1)
            .and_then(|tail| tail.split("\"device_offsets\":[").nth(1))
            .and_then(|tail| tail.split(']').next())
            .map(|list| list.split(',').count())
            .unwrap_or_else(|| panic!("no {contents} chunk in {receipt}"))
    };
    assert_eq!(copies("metadata"), 1, "unreplicated metadata is one copy");
    assert_eq!(copies("system"), 1, "the system chunk follows the metadata");
    assert_eq!(copies("data"), 2, "replicated data is two copies");
}

#[test]
fn a_btrfs_format_this_tool_refuses_says_which_word_it_refused_and_writes_nothing() {
    let dir = scratch();

    // Two subvolumes under one identifier make a UUID tree with a repeated key. Caught by the
    // name the caller typed rather than by the tree that came out of it, which is a fact about
    // a structure nobody asked about.
    let image = at(&dir, "repeated.img");
    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "--subvol",
        "5f2ac1de-0000-4000-8000-0000000000a1:/one",
        "--subvol",
        "5f2ac1de-0000-4000-8000-0000000000a1:/two",
        "--time",
        TIME,
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("/one") && said.contains("/two"), "{said}");
    assert!(!image.exists(), "a refused line wrote nothing");

    // An identity is required, as every family's is: an image whose bytes are a function of
    // its inputs is one that has been given them.
    let image = at(&dir, "unidentified.img");
    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--time",
        TIME,
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--fsid"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!image.exists(), "a refused line wrote nothing");

    // Another family's identity is refused by name rather than passed over. `--uuid` is the
    // same width as `--fsid` and a field of a different format, which is exactly the pairing
    // that would otherwise be quietly accepted.
    let out = run(&[
        "format",
        "--size",
        BTRFS_WRITTEN_BYTES,
        "-t",
        "btrfs",
        "--uuid",
        FSID,
        "--time",
        TIME,
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--uuid") && said.contains("btrfs"), "{said}");

    // And `--size auto` names a search this family does not have, refused before a source is
    // read rather than after.
    let out = run(&[
        "format",
        "--size",
        "auto",
        "-t",
        "btrfs",
        "--fsid",
        FSID,
        "--time",
        TIME,
        image.to_str().expect("a text path"),
    ]);
    assert_eq!(code(&out), USAGE);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--size auto"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn two_btrfs_formats_of_one_command_line_are_one_image() {
    let dir = scratch();
    // The reproducibility claim reaching the command line: the tool reads neither the clock nor
    // a random source, so the same words twice are the same bytes twice. Every identifier this
    // family invents is an input above, which is what makes it true here.
    //
    // **From an archive rather than from a directory tree, and the difference is the host's.**
    // A tar member's times are in the archive, so reading it twice describes one source twice.
    // A host tree's times are the host's, and *walking one changes them*: on a filesystem that
    // records access times, the walk that reads a file updates that file's access time, so the
    // second walk of one tree is a walk of a tree that is no longer what the first one saw.
    // btrfs is the family where that shows, because it is the only one of the four that stores
    // an access time to the nanosecond — and the difference is a millisecond. So the claim this
    // asserts is about the tool, and pointing it at a directory would have been asserting
    // something about the machine.
    let archive = write_archive(&dir);
    let mut written = Vec::new();
    for name in ["first.img", "second.img"] {
        let image = at(&dir, name);
        let out = run(&[
            "format",
            "--size",
            BTRFS_WRITTEN_BYTES,
            "-t",
            "btrfs",
            "--fsid",
            FSID,
            "--subvol",
            "5f2ac1de-0000-4000-8000-0000000000a1:/etc",
            "--time",
            TIME,
            "--from-tar",
            archive.to_str().expect("a text path"),
            image.to_str().expect("a text path"),
        ]);
        assert_eq!(code(&out), OK, "{}", String::from_utf8_lossy(&out.stderr));
        written.push(std::fs::read(&image).expect("read the image back"));
    }
    assert!(
        written[0] == written[1],
        "the same inputs wrote different bytes"
    );
}

// ---------------------------------------------------------------------------
// the matrix: one question, every family
// ---------------------------------------------------------------------------

/// One volume of each family, and the two words every report names it by.
struct Volume {
    /// The word `detect` prints and every report carries as `variant`.
    variant: &'static str,
    /// The lineage the variant belongs to, which is the reports' `family`.
    family: &'static str,
    image: PathBuf,
}

/// Write one volume per family from a single tree, so a case can ask each of them the same
/// question and compare the answers.
///
/// What differs between the four calls is only what a family must be told: an identifier of
/// its own kind, a size its minimum fits inside, and — for the two formats with no field for
/// an owner, a mode, or a change time — permission to lose the properties a host tree always
/// carries. Everything a question below could pick up on is the same in all four.
fn one_volume_per_family(dir: &tempfile::TempDir) -> Vec<Volume> {
    let tree = esp_tree(dir);
    let tree = tree.to_str().expect("a text path");
    // The two formats that record neither an owner nor a mode lose the same pair here, plus
    // the change time and the sub-second part of the times, exactly as the FAT and exFAT
    // gates above accept them.
    const LOST: &str = "ownership,permissions,change-time,time-precision";
    let mut volumes = Vec::new();
    for (variant, family, name, argv) in [
        (
            "ext4",
            "ext",
            "ext.img",
            vec![
                "-t", "ext4", "--size", "64M", "--uuid", UUID, "--time", TIME,
            ],
        ),
        (
            "fat32",
            "fat",
            "fat.img",
            vec![
                "-t",
                "fat32",
                "--size",
                "64M",
                "--volume-id",
                SERIAL,
                "--time",
                TIME,
                "--accept-loss",
                LOST,
            ],
        ),
        (
            "exfat",
            "exfat",
            "exfat.img",
            vec![
                "-t",
                "exfat",
                "--size",
                "64M",
                "--volume-serial",
                EXFAT_SERIAL,
                "--accept-loss",
                LOST,
            ],
        ),
        (
            "btrfs",
            "btrfs",
            "btrfs.img",
            vec![
                "-t",
                "btrfs",
                "--size",
                BTRFS_WRITTEN_BYTES,
                "--fsid",
                FSID,
                "--time",
                TIME,
            ],
        ),
    ] {
        let image = at(dir, name);
        let path = image.to_str().expect("a text path");
        let mut args = vec!["format"];
        args.extend_from_slice(&argv);
        args.extend_from_slice(&["--from-dir", tree, path]);
        let out = run(&args);
        assert_eq!(
            code(&out),
            OK,
            "{variant} did not format:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        volumes.push(Volume {
            variant,
            family,
            image,
        });
    }
    volumes
}

#[test]
fn every_family_answers_every_read_command_the_matrix_pairs_it_with() {
    // Per-family drift lives where a command is exercised on one family and assumed for the
    // rest, so the cells are filled rather than sampled: every read verb, every output
    // dialect, and the base offset, against each of the four. What each answer *says* is a
    // family's own business; that it answers at all, in the shape the shared surface
    // promises, is this crate's.
    let dir = scratch();
    let volumes = one_volume_per_family(&dir);
    for volume in &volumes {
        let path = volume.image.to_str().expect("a text path");
        let Volume {
            variant, family, ..
        } = volume;

        // What the image is, in one word.
        assert_eq!(
            String::from_utf8_lossy(&ok(&["detect", path])),
            format!("{variant}\n")
        );

        // The report, in each of its three dialects, plus the two flags that change what a
        // scan costs and what its verdict decides.
        let table = String::from_utf8(ok(&["inspect", path])).expect("text");
        assert!(table.contains("no findings"), "{variant} inspect:\n{table}");
        let head = json_head(&ok(&["inspect", "--json", path]));
        assert_eq!(
            head,
            format!("{family} {variant}"),
            "{variant} inspect json"
        );
        let sarif = String::from_utf8(ok(&["inspect", "--sarif", path])).expect("text");
        assert!(
            sarif.contains("\"version\":\"2.1.0\""),
            "{variant} sarif:\n{sarif}"
        );
        ok(&["inspect", "--quick", path]);
        ok(&["inspect", "--fail-on", "integrity", path]);
        ok(&["inspect", "--fail-on", "conformance", path]);

        // Every way of getting the contents back out. The listing and the single entry come
        // in both dialects, so a consumer of either reads the same tree.
        let listing = String::from_utf8(ok(&["extract", "--list", path])).expect("text");
        assert!(
            listing.contains("/EFI/BOOT/BOOTX64.EFI") && listing.contains("/readme.txt"),
            "{variant} listing:\n{listing}"
        );
        for argv in [
            vec!["extract", "--list", "--json", path],
            vec!["extract", "--stat", "/readme.txt", path],
            vec!["extract", "--stat", "/readme.txt", "--json", path],
        ] {
            let out = ok(&argv);
            assert!(
                !out.is_empty(),
                "{variant}: `{}` said nothing",
                argv.join(" ")
            );
        }
        assert_eq!(
            ok(&["extract", "--cat", "/readme.txt", path]),
            b"hello\n",
            "{variant} --cat"
        );

        // Out to an archive, and out to a tree. The destination is named rather than
        // prepared, and the tree needs the owner a read of the image reports to be one this
        // process may set -- which for the two formats with no owner field is what
        // `--assume-owner` decides.
        let tar = at(&dir, &format!("{variant}.tar"));
        ok(&[
            "extract",
            "--to-tar",
            tar.to_str().expect("a text path"),
            path,
        ]);
        let tar_bytes = std::fs::read(&tar).expect("read the archive");
        assert!(
            tar_bytes
                .windows(b"readme.txt".len())
                .any(|w| w == b"readme.txt"),
            "{variant}: the archive carries no readme"
        );
        let unpacked = at(&dir, &format!("{variant}-tree"));
        let owner = owner_of(&volume.image);
        ok(&[
            "extract",
            "--to-dir",
            unpacked.to_str().expect("a text path"),
            "--assume-owner",
            &owner,
            path,
        ]);
        assert_eq!(
            std::fs::read(unpacked.join("readme.txt")).expect("read the file back"),
            b"hello\n",
            "{variant}: the tree came back wrong"
        );

        // And the same image a megabyte into a larger one, which is where a partition puts
        // it: every read is relative to where the filesystem begins, on every family.
        let disk = at(&dir, &format!("{variant}-disk.img"));
        let mut bytes = vec![0x00; 1 << 20];
        bytes.extend_from_slice(&std::fs::read(&volume.image).expect("read the image"));
        std::fs::write(&disk, &bytes).expect("write the disk");
        let disk = disk.to_str().expect("a text path");
        assert_eq!(
            String::from_utf8_lossy(&ok(&["detect", "--offset", "1M", disk])),
            format!("{variant}\n")
        );
        assert_eq!(
            ok(&["extract", "--offset", "1M", "--cat", "/readme.txt", disk]),
            b"hello\n",
            "{variant} at an offset"
        );
        // And both documents that describe the partition carry the coordinate it was found
        // at, spelled the same way, so a caller scanning a disk can line the pair up.
        let described = ok(&["inspect", "--json", "--offset", "1M", disk]);
        let detected = ok(&["detect", "--json", "--offset", "1M", disk]);
        for document in [&described, &detected] {
            assert!(
                String::from_utf8_lossy(document).contains("\"offset\":1048576"),
                "{variant}: {}",
                String::from_utf8_lossy(document)
            );
        }
    }
}

/// The `family` and `variant` a JSON report names itself by, as one string to compare.
///
/// Read with `python3` rather than a JSON crate for the reason every other JSON gate here
/// does: the document has to be one something outside this workspace parses.
fn json_head(document: &[u8]) -> String {
    let judge = r#"
import json, sys
doc = json.load(sys.stdin)
# The five head fields mean the same thing whatever family answered, so a consumer that
# reads only these never learns which one did.
assert doc["schema"] == 2, doc
assert isinstance(doc["size"], int) and doc["size"] > 0, doc
assert isinstance(doc["allocation_unit"], int) and doc["allocation_unit"] > 0, doc
assert doc["identifier"], doc
assert doc["findings"]["clean"] is True, doc["findings"]
# And the body is the family's own, under its own name and no other's.
for name in ("ext", "fat", "exfat", "btrfs"):
    assert (name in doc) == (name == doc["family"]), (name, doc["family"])
print(doc["family"], doc["variant"])
"#;
    let mut child = tool("python3")
        .args(["-c", judge])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(document)
        .expect("write the document");
    let out = child.wait_with_output().expect("python3 finishes");
    assert!(
        out.status.success(),
        "the report is not the document a consumer reads:\n{}\n{}",
        String::from_utf8_lossy(document),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The owner of a file this process wrote, spelled the way `--assume-owner` reads it.
///
/// Taken from a file rather than asked of the system, because what the option has to name is
/// an owner this process may set on a file it creates -- which is exactly the owner the
/// files it just created have.
fn owner_of(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).expect("stat a file this process wrote");
    format!("{}:{}", meta.uid(), meta.gid())
}

#[test]
fn an_option_only_one_family_can_answer_is_refused_by_name_on_each_of_the_others() {
    // Scoping is enforced after parsing, by name, so the refusal has to be checked on every
    // family that lacks the option rather than on the first one that does. Both of these
    // are ext's alone: a block group is how an ext filesystem divides itself, and `identity`
    // rewrites ext's own identifying fields.
    let dir = scratch();
    for volume in &one_volume_per_family(&dir) {
        let path = volume.image.to_str().expect("a text path");
        let variant = volume.variant;
        if volume.family == "ext" {
            ok(&["inspect", "--groups", path]);
            continue;
        }

        let out = run(&["inspect", "--groups", path]);
        assert_eq!(
            code(&out),
            OPERATIONAL,
            "{variant}: --groups is refused, not faulted"
        );
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains("--groups"), "{variant}: {said}");
        assert!(said.contains(volume.family), "{variant}: {said}");

        // The verdict a request the tool cannot carry out gets, and never the corruption
        // verdict: the volume is sound and a gate keyed on 4 must not hear otherwise.
        let out = run(&["identity", "--label", "renamed", path]);
        assert_eq!(
            code(&out),
            OPERATIONAL,
            "{variant}: identity is refused, not faulted"
        );
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains(variant), "{variant}: {said}");
        assert!(said.contains("ext"), "{variant}: {said}");
    }
}

#[test]
fn a_strict_read_refuses_what_the_default_interprets_and_says_which_refusal_it_fell_back_from() {
    // The contract `--strict` exists for: extraction writes an image's contents somewhere,
    // so a filesystem carrying something the reader does not follow yields output that looks
    // complete and is not. The default recovers what it can and says so; `--strict` makes
    // the refusal the answer.
    let dir = scratch();
    let image = at(&dir, "fs.img");
    let archive = write_archive(&dir);
    assert_eq!(code(&format(&image, "64M", Some(&archive))), OK);

    // An incompatible feature bit no ext feature defines, which is exactly the shape a
    // reader must refuse rather than guess at: `s_feature_incompat` is 0x60 into the
    // superblock, which is 1024 bytes into the image.
    let mut bytes = std::fs::read(&image).expect("read the image");
    let at_bit = 1024 + 0x60;
    let mut word = u32::from_le_bytes(bytes[at_bit..at_bit + 4].try_into().expect("four bytes"));
    word |= 1 << 27;
    bytes[at_bit..at_bit + 4].copy_from_slice(&word.to_le_bytes());
    let unknown = at(&dir, "unknown.img");
    std::fs::write(&unknown, &bytes).expect("write the image");
    let path = unknown.to_str().expect("a text path");
    let tar = at(&dir, "out.tar");
    let tar = tar.to_str().expect("a text path");

    // Leniently by default: the contents come out, and the run says which refusal it fell
    // back from rather than dropping it.
    let out = run(&["extract", "--to-tar", tar, path]);
    assert_eq!(
        code(&out),
        OK,
        "the default recovers what it can:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("0x08000000"), "{said}");
    assert!(said.contains("--strict refuses instead"), "{said}");

    // And with the flag, the refusal is the answer -- exit 8, because a request the tool
    // will not carry out is not a verdict that the filesystem is damaged.
    let out = run(&["extract", "--strict", "--to-tar", tar, path]);
    assert_eq!(code(&out), OPERATIONAL);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("0x08000000"), "{said}");
    assert!(!said.contains("best-effort"), "{said}");
}

#[test]
fn what_a_format_cannot_record_is_reported_as_whatever_the_caller_says_to_assume() {
    // A FAT directory entry has no owner and no mode, so a read of one fills both in. What
    // it fills them in *with* is the caller's to name, and the same two options decide what
    // a format compares a source against -- which is what makes a round trip through a
    // format that records neither of them lossless on paper as well as in fact.
    let dir = scratch();
    let tree = esp_tree(&dir);
    let image = at(&dir, "esp.img");
    assert_eq!(code(&format_esp(&image, &tree)), OK);
    let path = image.to_str().expect("a text path");

    // The defaults a read fills in: root, and the conventional modes.
    let listing = String::from_utf8(ok(&["extract", "--list", path])).expect("text");
    assert!(
        listing.contains("drwxr-xr-x   -      0      0"),
        "{listing}"
    );
    assert!(
        listing.contains("-rw-r--r--   -      0      0"),
        "{listing}"
    );

    // And what the caller said to assume instead, in both halves of both options: the file
    // mode and the directory mode are named apart, and so are the owner's two numbers.
    let listing = String::from_utf8(ok(&[
        "extract",
        "--list",
        "--assume-owner",
        "1000:100",
        "--assume-modes",
        "600:700",
        path,
    ]))
    .expect("text");
    assert!(
        listing.contains("drwx------   -   1000    100"),
        "{listing}"
    );
    assert!(
        listing.contains("-rw-------   -   1000    100"),
        "{listing}"
    );

    // The same values reach a single entry's report, so a caller reading one file sees what
    // a caller listing the tree saw.
    let stat = String::from_utf8(ok(&[
        "extract",
        "--stat",
        "/readme.txt",
        "--assume-owner",
        "1000:100",
        "--assume-modes",
        "600:700",
        path,
    ]))
    .expect("text");
    assert!(stat.contains("1000"), "{stat}");
    assert!(stat.contains("600"), "{stat}");
}

#[test]
fn every_family_writes_a_receipt_a_consumer_reads_the_same_way() {
    // A receipt is what a build hands the step after it, so the head is the same five fields
    // whichever family wrote it and the geometry underneath is the family's own. The verbs
    // that read an image already answer in one shape (the case above); this is the verb that
    // writes one.
    let dir = scratch();
    for (variant, family, name, argv) in [
        (
            "ext4",
            "ext",
            "ext.img",
            vec![
                "-t", "ext4", "--size", "64M", "--uuid", UUID, "--time", TIME,
            ],
        ),
        (
            "fat32",
            "fat",
            "fat.img",
            vec![
                "-t",
                "fat32",
                "--size",
                "64M",
                "--volume-id",
                SERIAL,
                "--time",
                TIME,
            ],
        ),
        (
            "exfat",
            "exfat",
            "exfat.img",
            vec![
                "-t",
                "exfat",
                "--size",
                "64M",
                "--volume-serial",
                EXFAT_SERIAL,
            ],
        ),
        (
            "btrfs",
            "btrfs",
            "btrfs.img",
            vec![
                "-t",
                "btrfs",
                "--size",
                BTRFS_WRITTEN_BYTES,
                "--fsid",
                FSID,
                "--time",
                TIME,
            ],
        ),
    ] {
        let image = at(&dir, name);
        let mut args = vec!["format", "--json"];
        args.extend_from_slice(&argv);
        args.push(image.to_str().expect("a text path"));
        let receipt = ok(&args);

        let judge = r#"
import json, sys
doc = json.load(sys.stdin)
assert doc["schema"] == 2, doc
# How much of the destination the filesystem occupies -- what a step after this one acts on.
assert doc["written"] > 0, doc
# And what the build cost the source, from the families that can cost it anything. ext holds
# every property this crate names, so its receipt has no fidelity object to carry.
if doc["family"] != "ext":
    assert doc["fidelity"]["faithful"] is True, doc["fidelity"]
print(doc["family"], doc["variant"])
"#;
        let mut child = tool("python3")
            .args(["-c", judge])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(&receipt)
            .expect("write the document");
        let out = child.wait_with_output().expect("python3 finishes");
        assert!(
            out.status.success(),
            "{variant}: the receipt is not a document a consumer reads:\n{}\n{}",
            String::from_utf8_lossy(&receipt),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            format!("{family} {variant}")
        );

        // The creation time is reported by every family that has one to report, and the one
        // that refuses `--time` reports none -- so the key's absence means the format has no
        // field rather than that the receipt forgot.
        let carries_time = String::from_utf8_lossy(&receipt).contains("\"created\"");
        assert_eq!(
            carries_time,
            variant != "exfat",
            "{variant}: `created` is reported by exactly the families that record one"
        );
    }
}
