//! End-to-end gate for the host-directory source: build a tree on this machine, walk it
//! into a source, format an image, and confirm the image reads back what the tree held and
//! (where `e2fsck` is present) checks clean.
//!
//! Runs where the directory source is built: with the `dir` feature enabled, on the
//! platform whose inode metadata and extended attributes the walk reads.
#![cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]

mod util;

use std::io;
use std::path::Path;

use ferrosys::ext::ondisk::{Inode, Timestamp};
use ferrosys::ext::{
    DirectorySource, FormatOptions, GrowReservation, HostError, Reader, Source, format,
};
use util::{available, e2fsck_clean};

const MIB: u64 = 1024 * 1024;
const FAKE: i64 = 1_700_000_000;

fn opts() -> FormatOptions {
    let mut o = FormatOptions::new([0x33; 16], Timestamp::from_secs(FAKE), [0u8; 16]);
    o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
    o
}

/// The image's tree as a path-to-inode map.
fn walk_tree<R: io::Read + io::Seek>(
    r: &mut Reader<R>,
) -> std::collections::BTreeMap<Vec<u8>, Inode> {
    r.walk()
        .expect("walk the image")
        .into_iter()
        .map(|e| (e.path, e.inode))
        .collect()
}

/// A tree carrying every kind the walk records, built under `root`.
fn build_tree(root: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir(root.join("etc")).expect("etc");
    std::fs::create_dir_all(root.join("var/log")).expect("var/log");
    std::fs::write(root.join("etc/hostname"), b"ferrosys\n").expect("hostname");

    let sh = root.join("etc/init");
    std::fs::write(&sh, vec![0x7f; 4096]).expect("init");
    std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    std::os::unix::fs::symlink("/proc/self/mounts", root.join("etc/mtab")).expect("mtab");
    // Two names for one inode: the sorted-first one carries the file.
    std::fs::hard_link(&sh, root.join("etc/init-alias")).expect("hard link");
    rustix_mkfifo(&root.join("var/pipe"));
}

/// A FIFO, which the standard library cannot create.
fn rustix_mkfifo(path: &Path) {
    // `mkfifo` is not in the standard library and the test crate has no direct syscall
    // dependency, so the node is made by the one host tool every POSIX system ships.
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo failed");
}

#[test]
fn a_host_tree_formats_into_an_image_that_holds_what_it_held() {
    let host = tempfile::tempdir().expect("temp dir");
    build_tree(host.path());

    let source = DirectorySource::from_path(host.path())
        .expect("walk the tree")
        // A build running as an ordinary user still writes a root-owned image.
        .owner(0, 0);
    assert_eq!(source.len(), 9, "root, 3 dirs, 2 files, link, alias, fifo");
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open the image");
    let tree = walk_tree(&mut reader);
    for path in [
        &b"/etc"[..],
        b"/etc/hostname",
        b"/etc/init",
        b"/etc/init-alias",
        b"/etc/mtab",
        b"/var",
        b"/var/log",
        b"/var/pipe",
    ] {
        assert!(
            tree.contains_key(path),
            "{} is missing from the image",
            String::from_utf8_lossy(path)
        );
    }

    // The contents were named by the walk and read when the file was placed.
    let hostname = reader
        .read_data(&tree[&b"/etc/hostname"[..]])
        .expect("read the file");
    assert_eq!(hostname, b"ferrosys\n");

    // The mode and the ownership override reached the inode.
    let init = &tree[&b"/etc/init"[..]];
    assert_eq!(init.mode & 0o7777, 0o755);
    assert_eq!(init.uid, 0);
    assert_eq!(init.gid, 0);

    // The symlink is the link, not what it points at.
    let mtab = &tree[&b"/etc/mtab"[..]];
    assert_eq!(
        reader.read_symlink(mtab).expect("read the link"),
        b"/proc/self/mounts"
    );

    // Both names share one inode, and the inode knows it has two.
    assert_eq!(
        tree[&b"/etc/init-alias"[..]].mode,
        init.mode,
        "the alias is the same inode"
    );
    assert_eq!(init.links_count, 2);

    // The FIFO survived as a FIFO: the mode's file-type bits say so.
    assert_eq!(tree[&b"/var/pipe"[..]].mode & 0xf000, 0x1000);

    if available("e2fsck") {
        let path = host.path().join("../walked.img");
        std::fs::write(&path, image.as_bytes()).expect("write the image out");
        e2fsck_clean(&path).expect("the image checks clean");
    }
}

#[test]
fn the_same_tree_walks_to_the_same_bytes() {
    // Inode numbers follow sorted path order, so the image is a function of the tree and
    // not of the order the host listed its directories in.
    let host = tempfile::tempdir().expect("temp dir");
    build_tree(host.path());

    // Both walks record their metadata before either format runs. A format reads each
    // file's bytes as it places them, and on a filesystem that maintains access times a
    // read moves the atime the next walk would record -- a property of the host, not of
    // the walk. Stating both walks first holds the tree still, so what the comparison
    // below answers is whether one tree walks to one image.
    let first_walk = DirectorySource::from_path(host.path())
        .expect("walk")
        .owner(0, 0);
    let second_walk = DirectorySource::from_path(host.path())
        .expect("walk")
        .owner(0, 0);

    let first = format(first_walk, 16 * MIB, opts()).expect("format");
    let second = format(second_walk, 16 * MIB, opts()).expect("format");
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "two walks of one tree write the same image"
    );
}

#[test]
fn the_walk_refuses_a_root_that_is_not_a_directory() {
    let host = tempfile::tempdir().expect("temp dir");
    let file = host.path().join("plain");
    std::fs::write(&file, b"x").expect("write");
    match DirectorySource::from_path(&file).err() {
        Some(HostError::NotADirectory { path, .. }) => assert_eq!(path, file),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_directory_is_a_source_with_only_a_root() {
    let host = tempfile::tempdir().expect("temp dir");
    let source = DirectorySource::from_path(host.path()).expect("walk");
    assert_eq!(source.len(), 1);
    let entries = source.into_entries();
    assert_eq!(entries[0].path, b"/");
}
