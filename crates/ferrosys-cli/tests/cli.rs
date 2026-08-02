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

// The host-tool helpers below — `tool`, `available`, `e2fsck_clean`, the version pin —
// mirror `ferrosys/tests/util/mod.rs`. They are a copy rather than an include
// because a crate's packaged tests cannot include a file from a sibling crate's
// directory; a behavioral change here belongs there too.

/// The `e2fsprogs` release the gates are written against: the version CI builds from
/// source, and the one whose observed behavior pinned every expected value in these
/// tests.
const E2FSPROGS_VERSION: &str = "1.47.0";

/// The tools that ship in `e2fsprogs` and so are held to [`E2FSPROGS_VERSION`].
/// Anything else (`tar`, `python3`, `getfattr`) has no version pin.
const E2FSPROGS_TOOLS: &[&str] = &["debugfs", "dumpe2fs", "e2fsck", "mke2fs", "resize2fs"];

/// A host-tool invocation with its environment pinned.
///
/// `LC_ALL=C`, because the gates read tool output — `dumpe2fs` field names, `tar`
/// listings — and a translated message would fail them for reasons that have nothing
/// to do with the image. `mke2fs` additionally gets the vendored configuration, so the
/// feature set an oracle image carries is the project's, not whatever the host
/// distribution enables.
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/mke2fs.conf")
}

/// The exit codes the tool contracts to, mirroring `e2fsck`'s.
const OK: i32 = 0;
const IMAGE_BAD: i32 = 4;
const OPERATIONAL: i32 = 8;
const USAGE: i32 = 16;

/// Whether `name` is runnable, printing a loud skip banner when it is not.
///
/// A gate that needs a foreign implementation and does not get one has verified nothing,
/// so where the gates are expected to run (CI sets `FERROSYS_REQUIRE_HOST_TOOLS`) a
/// missing tool fails the run outright.
///
/// The probe only asks whether the binary exists and runs, so any output — a version
/// line, or a complaint that `-V` is not its flag — counts as present; the flag just has
/// to make the tool exit promptly rather than block on input. `-V` is the e2fsprogs
/// version flag, and the tools that spell it `--version` instead (`tar`, `python3`)
/// answer `-V` with a prompt exit all the same.
///
/// An `e2fsprogs` tool is also held to [`E2FSPROGS_VERSION`]: under
/// `FERROSYS_REQUIRE_HOST_TOOLS` a different version is a hard failure — the run would
/// otherwise claim an oracle it did not consult — and elsewhere it is reported once per
/// gate, so a local divergence from CI reads as what it is.
fn available(name: &str) -> bool {
    let probe = tool(name).arg("-V").output();
    let ok = probe
        .as_ref()
        .map(|o| o.status.success() || !o.stderr.is_empty() || !o.stdout.is_empty())
        .unwrap_or(false);
    if !ok {
        assert!(
            std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
            "gate requires `{name}` but it was not found on PATH"
        );
        eprintln!(
            "\n!!! SKIPPING gate: `{name}` not found on PATH — \
             this was NOT verified against a foreign implementation !!!\n"
        );
        return false;
    }
    if E2FSPROGS_TOOLS.contains(&name) {
        let probe = probe.expect("probed above");
        // The banner is "<name> 1.47.0 (5-Feb-2023)"; the version is the token after
        // the tool's own name.
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
        if version != E2FSPROGS_VERSION {
            assert!(
                std::env::var_os("FERROSYS_REQUIRE_HOST_TOOLS").is_none(),
                "the gates pin e2fsprogs {E2FSPROGS_VERSION} as their oracle, \
                 but `{name}` reports {version}"
            );
            eprintln!(
                "note: `{name}` is version {version}, not the {E2FSPROGS_VERSION} the \
                 gates are written against — a divergence may not reproduce under CI's \
                 pinned oracle"
            );
        }
    }
    true
}

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
    let out = tool("e2fsck")
        .args(["-f", "-n"])
        .arg(image)
        .output()
        .expect("spawn e2fsck");
    assert!(
        out.status.success(),
        "e2fsck faulted the image (exit {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
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
            report["Filesystem profile"], profile,
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
    // The writer emits ext4, and inspect labels it as the family its feature words classify to.
    assert_eq!(report["Filesystem profile"], "ext4");
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
    assert!(text.contains("no anomalies"));
}

#[test]
fn inspect_groups_survives_a_hostile_group_count() {
    // A crafted superblock can claim ~4 billion block groups (`blocks_count` maxed,
    // `blocks_per_group` of one). The group listing must not pre-size a vector from that
    // count: reserving capacity for it would ask for hundreds of gigabytes and abort the
    // process before a single descriptor was read. The descriptor loop grows as real
    // descriptors are found and stops when the table runs past the image — a clean
    // image-bad exit, not a crash.
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
assert doc["schema"] == 1, doc["schema"]
assert "version" not in doc, "the envelope field is `schema` in every document"
sb = doc["superblock"]
assert sb["uuid"] == "f0e17055-0000-4000-8000-000000000000", sb["uuid"]
assert sb["block_size"] == 4096, sb["block_size"]
assert sb["blocks"] * sb["block_size"] == 64 * 1024 * 1024, sb["blocks"]
assert sb["created"] == 1700000000, sb["created"]
feats = doc["features"]
assert "has_journal" in feats["compat"], feats["compat"]
assert "extent" in feats["incompat"], feats["incompat"]
assert feats["profile"] == "ext4", feats["profile"]
assert feats["unknown"] == {"compat": 0, "incompat": 0, "ro_compat": 0}, feats["unknown"]
assert doc["scan"]["clean"] is True and doc["scan"]["anomalies"] == [], doc["scan"]
groups = doc["groups"]
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

    // 8: the bytes are not an ext filesystem at all, so there is no opinion to form.
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
            report.contains("Block count:") && report.contains("no anomalies"),
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

    // An ACL is stored in ext's compact form, which nothing else can read: it is decoded to
    // the text `getfacl` prints, or it is not really reported at all.
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
assert doc["schema"] == 1, doc["schema"]
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
assert doc["schema"] == 1, doc["schema"]
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
    use ferrosys::ext::ondisk::Timestamp;
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
    assert!(report.contains("no anomalies"));
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
