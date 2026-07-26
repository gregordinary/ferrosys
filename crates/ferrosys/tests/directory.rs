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
    DirectorySource, FormatOptions, GrowReservation, HostError, Reader, Source, SourceEntry, format,
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

/// Access time, dropped so the comparison below sees the fields a walk decides.
///
/// A walk reads every directory and every symlink to learn what they hold, and a host
/// that maintains access times records that read -- so a walk moves the access times the
/// next walk reads back. That time is the host's answer, not the walk's.
fn without_atimes(mut entries: Vec<SourceEntry>) -> Vec<SourceEntry> {
    for entry in &mut entries {
        entry.meta.atime = Timestamp::from_secs(0);
    }
    entries
}

#[test]
fn the_same_tree_walks_to_the_same_entries() {
    // Entries sort by path and attributes by name, so the list is a function of the tree
    // and not of the order the host listed its directories in. Everything the walk
    // decides is compared: the paths and their order, which name of an inode carries the
    // contents and which become hard links, modes, ownership, change and modification
    // times, symlink targets, device numbers, and each entry's attributes in order. That
    // one such list formats to one image is the byte-reproducibility gate's subject; this
    // one holds the walk to producing one list.
    let host = tempfile::tempdir().expect("temp dir");
    build_tree(host.path());

    let first = DirectorySource::from_path(host.path())
        .expect("walk")
        .owner(0, 0)
        .into_entries();
    let second = DirectorySource::from_path(host.path())
        .expect("walk")
        .owner(0, 0)
        .into_entries();

    // The tree the comparison runs over, so an equality over two empty lists cannot pass
    // for agreement.
    assert_eq!(first.len(), 9, "root, 3 dirs, 2 files, link, alias, fifo");
    assert_eq!(
        without_atimes(first),
        without_atimes(second),
        "two walks of one tree yield the same entries"
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
