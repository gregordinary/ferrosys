//! End-to-end gate for the host-directory source: build a tree on this machine, walk it
//! into a source, format an image, and confirm the image reads back what the tree held and
//! (where `e2fsck` is present) checks clean.
//!
//! Runs where the directory source is built: with the `dir` feature enabled, on the
//! platform whose inode metadata and extended attributes the walk reads.
#![cfg(all(
    feature = "dir",
    feature = "ext",
    any(target_os = "linux", target_os = "android")
))]

mod util;

use std::io;
use std::path::Path;

use ferrosys::ext::OpenOptions;
use ferrosys::ext::Timestamp;
use ferrosys::ext::ondisk::Inode;
use ferrosys::ext::{FormatOptions, GrowReservation, Reader, Source, SourceEntry, format};
use ferrosys::{DirectorySink, DirectorySource, HostError, Limits};
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
        // Its own directory, not the walked tree and not a fixed name beside it: two
        // checkouts running this gate at once would otherwise write and read one file,
        // and each would hand `e2fsck` bytes the other was in the middle of replacing.
        let out = tempfile::tempdir().expect("temp dir");
        let path = out.path().join("walked.img");
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

/// Move a path's access time far from its modification time, leaving the modification
/// time exactly where it was: the divergence a host that keeps access times produces by
/// being read.
///
/// The modification time is read back and written unchanged, because it is the one time
/// that legitimately reaches the image — a test that moved it would be asking the knob to
/// hide a real difference. Writing the times moves the change time to now, which is the
/// second disturbance the knob absorbs and the kernel's to set rather than a caller's.
fn skew_atime(path: &Path, atime_secs: u64) {
    let mtime = std::fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("modification time");
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(atime_secs);
    let file = std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open to set times");
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(at)
            .set_modified(mtime),
    )
    .expect("set times");
}

/// Where two images first disagree, or `None` if they hold the same bytes. Images run to
/// tens of megabytes, so a failure reports an offset rather than the whole of both.
fn first_difference(a: &[u8], b: &[u8]) -> Option<String> {
    if a.len() != b.len() {
        return Some(format!("lengths differ: {} and {}", a.len(), b.len()));
    }
    let at = a.iter().zip(b).position(|(x, y)| x != y)?;
    Some(format!(
        "first difference at byte {at}: {:#04x} and {:#04x}",
        a[at], b[at]
    ))
}

#[test]
fn the_times_knob_puts_the_modification_time_in_all_three_places() {
    let host = tempfile::tempdir().expect("temp dir");
    build_tree(host.path());
    // A file whose three times all disagree: the access time is set back to 2001, and the
    // change time is whatever the clock said during the call.
    skew_atime(&host.path().join("etc/hostname"), 1_000_000_000);

    let walked = DirectorySource::from_path(host.path())
        .expect("walk")
        .into_entries();
    let hostname = walked
        .iter()
        .find(|e| e.path == b"/etc/hostname")
        .expect("hostname walked");
    // The divergence the knob is asked to collapse is really present, so the assertion
    // below cannot pass on a tree whose times already agreed.
    assert_ne!(
        hostname.meta.atime, hostname.meta.mtime,
        "the host holds an access time apart from the modification time"
    );

    let clamped = DirectorySource::from_path(host.path())
        .expect("walk")
        .times_from_modification()
        .into_entries();
    assert_eq!(walked.len(), clamped.len());
    for entry in &clamped {
        assert_eq!(
            (entry.meta.atime, entry.meta.ctime),
            (entry.meta.mtime, entry.meta.mtime),
            "{}: every time is the modification time",
            String::from_utf8_lossy(&entry.path)
        );
    }
    // Only the times moved: the knob replaces two fields and decides nothing else about
    // the walk.
    let strip = |mut es: Vec<SourceEntry>| {
        for e in &mut es {
            e.meta.atime = Timestamp::from_secs(0);
            e.meta.ctime = Timestamp::from_secs(0);
            e.meta.mtime = Timestamp::from_secs(0);
        }
        es
    };
    assert_eq!(strip(walked), strip(clamped));
}

#[test]
fn a_host_that_moves_the_times_does_not_move_the_image() {
    // The gate the knob exists for. One tree, formatted either side of the disturbance
    // that reading or restaging it produces: with the knob the bytes are the same, and
    // without it they are not — so the equality is the knob's doing rather than a tree
    // nothing happened to.
    let host = tempfile::tempdir().expect("temp dir");
    build_tree(host.path());

    let build = |clamped: bool| {
        let walked = DirectorySource::from_path(host.path())
            .expect("walk")
            .owner(0, 0);
        let source = if clamped {
            walked.times_from_modification()
        } else {
            walked
        };
        format(source, 64 * MIB, opts()).expect("format")
    };

    let bare_before = build(false);
    let clamped_before = build(true);

    skew_atime(&host.path().join("etc/hostname"), 1_000_000_000);
    skew_atime(&host.path().join("etc/init"), 1_200_000_000);

    let bare_after = build(false);
    let clamped_after = build(true);

    if let Some(where_) = first_difference(clamped_before.as_bytes(), clamped_after.as_bytes()) {
        panic!("a disturbed host time changed the image: {where_}");
    }
    assert!(
        first_difference(bare_before.as_bytes(), bare_after.as_bytes()).is_some(),
        "without the knob the disturbed times reach the image"
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

// ---------------------------------------------------------------------------
// The other direction: a filesystem written back out as a tree
// ---------------------------------------------------------------------------

/// Everything about one host entry a round trip has to preserve.
///
/// The change time is not here, and cannot be: it is the kernel's own, set when the entry
/// was created, and no call sets it. The creation time is not here either — ext4 records one
/// and no host filesystem lets a caller write it.
#[derive(PartialEq, Eq, Debug)]
struct Held {
    kind: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    atime: (i64, i64),
    /// A symlink's target, a regular file's bytes, and nothing for anything else.
    contents: Option<Vec<u8>>,
    /// Which entries share an inode, as an index into the order they were read in.
    inode: u64,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Read a host tree into the map a comparison is made over: relative path to what it holds.
fn held(root: &Path) -> std::collections::BTreeMap<String, Held> {
    use std::os::unix::fs::MetadataExt;

    let mut out = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    // The root itself, under the empty name, so its own mode and times are compared too.
    out.insert(String::new(), one(root));
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read the directory") {
            let path = entry.expect("an entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            if meta.is_dir() {
                pending.push(path.clone());
            }
            let name = path
                .strip_prefix(root)
                .expect("under the root")
                .to_string_lossy()
                .into_owned();
            out.insert(name, one(&path));
        }
    }
    return out;

    fn one(path: &Path) -> Held {
        let meta = std::fs::symlink_metadata(path).expect("stat");
        let kind = meta.mode() & 0o170000;
        let contents = match kind {
            0o120000 => Some(
                std::fs::read_link(path)
                    .expect("read the link")
                    .into_os_string()
                    .into_encoded_bytes(),
            ),
            0o100000 => Some(std::fs::read(path).expect("read the file")),
            _ => None,
        };
        let mut xattrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut names = vec![0u8; 4096];
        if let Ok(len) = rustix::fs::llistxattr(path, &mut names[..]) {
            for name in names[..len].split(|&b| b == 0).filter(|n| !n.is_empty()) {
                let mut value = vec![0u8; 4096];
                let cname = std::ffi::CString::new(name).expect("a name without a NUL");
                if let Ok(len) = rustix::fs::lgetxattr(path, &cname, &mut value[..]) {
                    value.truncate(len);
                    xattrs.push((name.to_vec(), value));
                }
            }
        }
        xattrs.sort();
        Held {
            kind,
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            atime: (meta.atime(), meta.atime_nsec()),
            contents,
            inode: meta.ino(),
            xattrs,
        }
    }
}

/// A destination directory for an extraction, inside `dir`.
fn destination(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::create_dir(&path).expect("make the destination");
    path
}

#[test]
fn a_tree_survives_the_round_trip_through_a_filesystem() {
    // The whole claim of the pair: what the walk records, the image holds, and the
    // extraction puts back — the same modes, times, ownership, links, contents, and
    // attributes, at the same paths.
    let host = tempfile::tempdir().expect("temp dir");
    let source_tree = host.path().join("tree");
    std::fs::create_dir(&source_tree).expect("make the tree");
    build_tree(&source_tree);
    // An extended attribute, where the host holds one, so the round trip covers them.
    let _ = rustix::fs::lsetxattr(
        source_tree.join("etc/hostname"),
        "user.origin",
        b"round-trip",
        rustix::fs::XattrFlags::empty(),
    );

    // The walk's own ids are kept rather than overridden: an extraction that has to set an
    // owner other than this process's needs a privilege a test does not have, and the
    // fidelity being checked is the same either way.
    let source = DirectorySource::from_path(&source_tree).expect("walk the tree");
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open the image");
    let report = DirectorySink::new(&out)
        .expect("open the destination")
        .write_tree(&mut reader)
        .expect("write the tree out");
    assert!(!report.ownership_dropped);
    assert!(report.skipped.is_empty());

    // Every time the image records reached the tree, to the nanosecond. Stated here,
    // before anything lists the destination: a host that keeps access times moves a
    // directory's the moment it is read, and `held` below reads every one of them, so this
    // asks through `lstat` — the one way to learn what a name holds without touching it.
    //
    // Access times are stated against the image rather than against the source tree
    // because a walk reads every directory and every symlink to learn what they hold, so
    // the source's own are moved by the very walk that recorded them. Comparing the two
    // ends of the trip would be asking the extraction to reproduce something that changed
    // after it was read. A freshly built tree has its access time equal to its
    // modification time, which is exactly when `relatime` updates, so that is the ordinary
    // case on a host that keeps them and invisible on one mounted `noatime`.
    // `without_atimes` drops them from the walk comparison for the same reason.
    assert_recorded_times_reached_the_tree(&mut reader, &out);

    let before = held(&source_tree);
    let after = held(&out);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the extraction holds a different set of names"
    );
    for (name, was) in &before {
        let now = &after[name];
        // The inode numbers differ between two filesystems, so what is compared is the
        // sharing they express: the two names that were one file still are.
        assert_eq!(
            (was.kind, was.mode, was.uid, was.gid),
            (now.kind, now.mode, now.uid, now.gid),
            "{name}: mode or ownership moved"
        );
        assert_eq!(was.contents, now.contents, "{name}: contents moved");
        assert_eq!(was.mtime, now.mtime, "{name}: modification time moved");
        assert_eq!(was.xattrs, now.xattrs, "{name}: attributes moved");
    }
    // The hard link is a hard link on the way out too.
    assert_eq!(
        after["etc/init"].inode, after["etc/init-alias"].inode,
        "the two names did not come back as one file"
    );
    // Nothing the filesystem makes for itself is written into the tree.
    assert!(!out.join("lost+found").exists());
    assert_eq!(report.written as usize, before.len() - 1, "one per name");
}

/// Assert that every access and modification time the image records reached the tree
/// written from it, to the nanosecond.
///
/// This is what a `DirectorySink` promises about times, and it is stated against the image
/// because the image is what the sink was given. Comparing the destination to the tree the
/// image was built from would instead be a statement about the host's access-time policy,
/// which moves the source's times under both ends of the trip.
fn assert_recorded_times_reached_the_tree<R: io::Read + io::Seek>(
    reader: &mut Reader<R>,
    out: &Path,
) {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let mut checked = 0;
    // The root has no name in the walk, so it is stated separately: the destination
    // directory is what carries the filesystem root's own times across.
    let root = reader.inode(2).expect("the root inode");
    let mut entries = vec![(out.to_path_buf(), root)];
    for entry in reader.walk().expect("walk the image") {
        // Every filesystem makes `/lost+found` for itself, and no extraction writes it.
        if entry.path == b"/lost+found" || entry.path.starts_with(b"/lost+found/") {
            continue;
        }
        let mut path = out.to_path_buf();
        for part in entry.path.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
            path.push(std::ffi::OsStr::from_bytes(part));
        }
        entries.push((path, entry.inode));
    }

    for (path, inode) in entries {
        let meta =
            std::fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            (meta.atime(), meta.atime_nsec()),
            (inode.atime.secs, i64::from(inode.atime.nanos)),
            "{}: the recorded access time did not reach the tree",
            path.display()
        );
        assert_eq!(
            (meta.mtime(), meta.mtime_nsec()),
            (inode.mtime.secs, i64::from(inode.mtime.nanos)),
            "{}: the recorded modification time did not reach the tree",
            path.display()
        );
        checked += 1;
    }
    // So an equality over an empty walk cannot pass for agreement.
    assert_eq!(checked, 9, "root, 3 dirs, 2 files, link, alias, fifo");
}

#[test]
fn the_destination_must_be_an_empty_directory() {
    let host = tempfile::tempdir().expect("temp dir");
    // Not a directory at all.
    let file = host.path().join("plain");
    std::fs::write(&file, b"x").expect("write");
    assert!(matches!(
        DirectorySink::new(&file),
        Err(HostError::NotADirectory { .. })
    ));
    // A directory, but one that already holds something: refused before anything is
    // written, rather than part-way through at the first name that collides.
    let occupied = destination(&host, "occupied");
    std::fs::write(occupied.join("already-here"), b"x").expect("write");
    match DirectorySink::new(&occupied) {
        Err(HostError::NotEmpty { path, .. }) => assert_eq!(path, occupied),
        other => panic!("expected a refusal, got {}", describe(other)),
    }
    // And an empty one is accepted. Both questions are asked of the handle rather than of
    // the name, so what the sink accepted and what it writes into are one object.
    assert!(DirectorySink::new(destination(&host, "empty")).is_ok());

    // A symbolic link to an empty directory is a destination like any other: naming one is
    // the caller's own doing, as it is for `tar -C`, and the handle taken through it refers
    // to the directory itself.
    let target = destination(&host, "pointed-at");
    let link = host.path().join("via-link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(DirectorySink::new(&link).is_ok());

    // A dangling one is not a directory, which is the answer the open itself gives.
    let dangling = host.path().join("dangling");
    std::os::unix::fs::symlink(host.path().join("nowhere"), &dangling).expect("symlink");
    match DirectorySink::new(&dangling) {
        Err(HostError::Io { .. }) => {}
        other => panic!("expected an i/o failure, got {}", describe(other)),
    }
}

/// What a `Result<DirectorySink, _>` was, for a test that expected the other thing.
fn describe(r: Result<DirectorySink, HostError>) -> String {
    match r {
        Ok(_) => "a sink".to_string(),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_device_node_is_refused_or_recorded_rather_than_written_wrong() {
    // Making a device node needs CAP_MKNOD. The default is to say so and stop, because an
    // extraction that quietly produced a tree without `/dev/null` in it would be a tree
    // that boots differently. `skip_privileged` is the opt-in, and what it leaves out comes
    // back in the report.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new()
        .directory(b"/dev".to_vec(), Metadata::new(0o755, time))
        .char_device(b"/dev/null".to_vec(), 1, 3, Metadata::new(0o666, time))
        .file(
            b"/etc".to_vec(),
            b"plain\n".to_vec(),
            Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");
    let host = tempfile::tempdir().expect("temp dir");

    let strict = destination(&host, "strict");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    match DirectorySink::new(&strict)
        .expect("open the destination")
        .write_tree(&mut reader)
    {
        // Unprivileged, which is how this gate usually runs.
        Err(HostError::Unprivileged { path, .. }) => assert_eq!(path, b"/dev/null"),
        // Privileged, in which case the node is there.
        Ok(_) => assert!(strict.join("dev/null").exists()),
        other => panic!("expected a refusal or a node, got {other:?}"),
    }

    let lenient = destination(&host, "lenient");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&lenient)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("skipping what it may not do, an extraction succeeds");
    if lenient.join("dev/null").exists() {
        assert!(
            report.skipped.is_empty(),
            "a node that was made is not skipped"
        );
    } else {
        assert_eq!(report.skipped, vec![b"/dev/null".to_vec()]);
    }
    // Everything it could write, it wrote.
    assert_eq!(
        std::fs::read(lenient.join("etc")).expect("read"),
        b"plain\n"
    );
}

#[test]
fn a_hard_link_reaches_back_into_a_directory_the_image_records_without_read_permission() {
    // The second name for an inode is written as a link from the first, whose directory the
    // walk left behind long ago — so that directory is re-opened, and by then it carries the
    // mode the image records rather than the one it was built with. A tree is free to record
    // a directory the extracting user may search but not read, and traversing it is all a
    // link needs. Two names in the *same* directory never reach this: the parent is still
    // open and still permissive when the second arrives.
    //
    // The second half of the list is the case where searching it is *not* something the mode
    // allows either. There the directory's own metadata waits until the whole walk is over
    // rather than until the walk leaves it, so the link still has somewhere to traverse. An
    // ordinary user extracting an ordinary image is what this is about: the tree is
    // well-formed and a privileged run writes it, so an unprivileged one must too.
    use ferrosys::ext::{Metadata, TreeBuilder};
    use std::os::unix::fs::PermissionsExt;

    let time = Timestamp::from_secs(FAKE);
    // 0o333 is the discriminator: write and search for the owner, no read. 0o111 is the
    // same case with nothing but search. 0o000, 0o444 and 0o600 are the ones with no search
    // at all, which is what a re-traversal cannot get through.
    for mode in [0o333u16, 0o111, 0o500, 0o755, 0o000, 0o444, 0o600] {
        let source = TreeBuilder::new()
            .directory(b"/a".to_vec(), Metadata::new(mode, time))
            .file(
                b"/a/f".to_vec(),
                b"shared\n".to_vec(),
                Metadata::new(0o644, time),
            )
            .directory(b"/z".to_vec(), Metadata::new(0o755, time))
            .hardlink(
                b"/z/g".to_vec(),
                b"/a/f".to_vec(),
                Metadata::new(0o644, time),
            );
        let image = format(source, 16 * MIB, opts()).expect("format the image");

        let host = tempfile::tempdir().expect("temp dir");
        let out = destination(&host, "unpacked");
        let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
        let report = DirectorySink::new(&out)
            .expect("open the destination")
            .skip_privileged()
            .write_tree(&mut reader)
            .unwrap_or_else(|e| panic!("mode {mode:#o}: {e}"));
        assert_eq!(report.written, 4, "mode {mode:#o}: a name each");

        use std::os::unix::fs::MetadataExt;
        // The directory kept the mode the image recorded, which is what made the re-open
        // the interesting part. Read before anything is relaxed, since relaxing it is what
        // the rest of the test needs.
        let dir = std::fs::symlink_metadata(out.join("a")).expect("stat the directory");
        assert_eq!(dir.mode() & 0o7777, u32::from(mode), "mode {mode:#o}");
        // Now look inside, which for the unsearchable modes means giving the test itself the
        // search permission the image did not record.
        std::fs::set_permissions(out.join("a"), std::fs::Permissions::from_mode(0o700))
            .expect("relax the directory the test is about to look into");

        // And it really is a link, not a second copy.
        let first = std::fs::symlink_metadata(out.join("a/f")).expect("stat the first name");
        let second = std::fs::symlink_metadata(out.join("z/g")).expect("stat the second");
        assert_eq!(
            first.ino(),
            second.ino(),
            "mode {mode:#o}: the two names are not one file"
        );
        assert_eq!(first.nlink(), 2, "mode {mode:#o}: link count");
    }
}

#[test]
fn a_second_name_for_a_device_node_the_host_refused_is_skipped_with_the_first() {
    // A device node this process may not make is left out and reported. A later name for
    // the same inode has nothing to link from — the first name was never written — so it is
    // left out with it. Recording a name before knowing whether it was created would make
    // the second name's failure an unexplained ENOENT part-way through an extraction that
    // `skip_privileged` promises will finish.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new()
        .directory(b"/dev".to_vec(), Metadata::new(0o755, time))
        .char_device(b"/dev/null".to_vec(), 1, 3, Metadata::new(0o666, time))
        .hardlink(
            b"/dev/zzz".to_vec(),
            b"/dev/null".to_vec(),
            Metadata::new(0o666, time),
        )
        .file(
            b"/plain".to_vec(),
            b"written\n".to_vec(),
            Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("skipping what it may not do, an extraction succeeds");

    if out.join("dev/null").exists() {
        // Privileged, which is how this runs as root: both names are there, as one inode.
        use std::os::unix::fs::MetadataExt;
        assert!(report.skipped.is_empty());
        assert_eq!(
            std::fs::symlink_metadata(out.join("dev/null"))
                .expect("stat")
                .ino(),
            std::fs::symlink_metadata(out.join("dev/zzz"))
                .expect("stat")
                .ino(),
        );
    } else {
        // Unprivileged: neither name was written, and both are reported.
        assert!(!out.join("dev/zzz").exists(), "the second name was written");
        assert_eq!(
            report.skipped,
            vec![b"/dev/null".to_vec(), b"/dev/zzz".to_vec()],
        );
    }
    // Either way the rest of the tree is there, which is what the flag is for.
    assert_eq!(
        std::fs::read(out.join("plain")).expect("read"),
        b"written\n"
    );
}

#[test]
fn an_attribute_on_something_that_cannot_be_opened_reaches_the_entry_itself() {
    // A symbolic link cannot be opened without following it, so its attributes are the one
    // thing here set through a path rather than a handle — and the path names the handle
    // (`/proc/self/fd/<n>/<name>`) so the directories between the destination and the entry
    // are not walked a second time. What this holds to is that the name resolves: a path
    // that reached nowhere would fail with ENOENT, which is neither a written attribute nor
    // a reported privilege.
    //
    // `trusted.*` on a symbolic link is the shape a real tree has here — the `user.*`
    // namespace is closed to symlinks and special files outright — and it needs
    // CAP_SYS_ADMIN, so unprivileged this is a recorded omission and privileged it is a
    // written attribute. Either is a pass; ENOENT is not.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new()
        .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
        .symlink(
            b"/etc/mtab".to_vec(),
            b"/proc/self/mounts".to_vec(),
            Metadata::new(0o777, time),
        )
        .xattr(b"trusted.origin".to_vec(), b"by-name".to_vec());
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("the attribute is written or reported, never a missing path");

    let mut value = [0u8; 32];
    let read = rustix::fs::lgetxattr(out.join("etc/mtab"), "trusted.origin", &mut value);
    match read {
        Ok(len) => {
            assert_eq!(
                &value[..len],
                b"by-name",
                "the attribute landed on the link"
            );
            assert!(!report.xattrs_dropped);
        }
        Err(_) => assert!(
            report.xattrs_dropped,
            "an attribute that is not there was not reported either"
        ),
    }
    // The link itself is the link, whatever happened to its attribute.
    assert_eq!(
        std::fs::read_link(out.join("etc/mtab")).expect("read the link"),
        Path::new("/proc/self/mounts")
    );
}

#[test]
fn a_capability_attribute_outlives_the_ownership_change_that_would_strip_it() {
    // Setting an owner strips `security.capability`: the kernel raises `ATTR_KILL_PRIV` on
    // every `chown` of a non-directory, whether or not the ids change, and that is what
    // removes the attribute. So an extraction that writes attributes before ownership writes
    // this one and then destroys it — and, because `fsetxattr` succeeded, reports the
    // extraction faithful. A caller gating a release on faithfulness would ship a root
    // filesystem whose binaries have lost every capability, with nothing saying so.
    //
    // Presence is what is asserted, not the bytes: written from inside a user namespace the
    // kernel rewrites a version 2 record into a version 3 one carrying the namespace's root
    // id, so the value that comes back is longer than the value that went in. That rewrite is
    // the host's business. Whether the attribute is *there* is this crate's.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let cap = vec![
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let source = TreeBuilder::new()
        .file(
            b"/ping".to_vec(),
            b"not really an ELF\n".to_vec(),
            // Owned by root, which is what a real root filesystem records — and what makes
            // the `chown` a call the sink actually issues.
            Metadata::new(0o755, time).owned_by(0, 0),
        )
        .xattr(b"security.capability".to_vec(), cap);
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("extraction succeeds whether or not the attribute may be set");

    // Unprivileged the attribute cannot be set at all and the report says so, which is the
    // other half of the contract and is gated above. What must never happen is the third
    // case: the report says nothing was dropped and the attribute is not there.
    if !report.xattrs_dropped {
        let mut buf = [0u8; 64];
        rustix::fs::lgetxattr(out.join("ping"), "security.capability", &mut buf)
            .expect("an extraction that reports no dropped attribute has the capability on disk");
    }
}

#[test]
fn the_read_cap_bounds_what_an_extraction_writes_and_not_only_what_a_read_returns() {
    // A sink streams a file through a fixed buffer, so its own memory is bounded whatever
    // the file claims. What it *writes* is not: the byte count follows the length the image
    // declares, and a hole reads back as zeros — so an inode claiming terabytes and mapping
    // nothing fills the destination until it runs out of room, from an image of a few
    // kilobytes. `Limits::max_file_bytes` is documented as the cap on a read that trusts a
    // declared size, and it reached only whole-file reads; an extraction is the one place
    // that trust is spent on disk.
    //
    // The cap is checked before the name is created, so a refused file leaves nothing.
    let time = Timestamp::from_secs(FAKE);
    let source = ferrosys::ext::TreeBuilder::new()
        .file(
            b"/small".to_vec(),
            b"tiny\n".to_vec(),
            ferrosys::ext::Metadata::new(0o644, time),
        )
        .file(
            b"/big".to_vec(),
            vec![b'x'; 40_000],
            ferrosys::ext::Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open_with(
        io::Cursor::new(image.as_bytes()),
        &OpenOptions::new().limits(Limits::new().max_file_bytes(1000)),
    )
    .expect("open");
    let err = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect_err("a file past the cap is refused rather than written");
    assert!(
        matches!(err, HostError::Read { .. }),
        "the refusal is the read's, named as such: {err:?}"
    );
    assert!(
        !out.join("big").exists(),
        "a refused file left no name behind"
    );

    // And under no cap the same tree extracts whole, so what the cap refuses is the cap's
    // doing rather than the file's.
    let plain = destination(&host, "plain");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    DirectorySink::new(&plain)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("write the tree");
    assert_eq!(
        std::fs::read(plain.join("big")).expect("read").len(),
        40_000
    );
}

#[test]
fn a_tree_of_unsearchable_directories_is_refused_rather_than_running_out_of_handles() {
    // A directory whose recorded mode denies its owner search permission keeps its handle
    // until the walk is over, because applying that mode would close it to the walk still
    // going on. Which directories those are is the *image's* choice, so an image whose
    // directories are all `0o600` asks for one open handle per directory in the tree —
    // about eleven hundred of them passes the default soft `RLIMIT_NOFILE`.
    //
    // What follows the stop is worse than the stop: the deferred directories never get
    // their mode or their owner, so the tree is left at `BUILDING` and owned by this
    // process — the half-written tree the deferral was introduced to remove, reintroduced
    // under a hostile image. So the wait has a ceiling, and reaching it is a refusal that
    // says what it is.
    let time = Timestamp::from_secs(FAKE);
    let mut src = ferrosys::ext::TreeBuilder::new();
    for i in 0..300 {
        src = src.directory(
            format!("/d{i:04}").into_bytes(),
            ferrosys::ext::Metadata::new(0o600, time),
        );
    }
    let image = format(src, 32 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let err = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect_err("a tree of unsearchable directories is refused");
    assert!(
        matches!(err, HostError::TooManyDeferredDirectories { .. }),
        "the refusal names what it is: {err:?}"
    );
}

#[test]
fn a_file_read_at_placement_time_does_not_follow_a_link_swapped_in_behind_the_walk() {
    // A walk records a symlink as a symlink and never reads through one. A file's *bytes*,
    // though, are read when the file is placed, by the name the walk recorded — so a local
    // writer replacing a staged name with a link between the walk and the format would put
    // the target's bytes into the image, with no error and nothing in the fidelity report.
    // The "must not change" caveat on a recorded range covers content changing; it does not
    // cover the name becoming a different kind of thing.
    let host = tempfile::tempdir().expect("temp dir");
    let staged = host.path().join("payload");
    std::fs::write(&staged, b"the real contents\n").expect("write");
    let secret = host.path().join("secret");
    std::fs::write(&secret, b"not for the image\n").expect("write");

    let source = DirectorySource::from_path(host.path())
        .expect("walk the tree")
        .owner(0, 0);

    // The swap, after the walk and before the format reads a byte.
    std::fs::remove_file(&staged).expect("remove");
    std::os::unix::fs::symlink(&secret, &staged).expect("symlink");

    // A format that refused the link is the answer; one that succeeded must at least not
    // have read through it.
    if let Ok(image) = format(source, 16 * MIB, opts()) {
        let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
        let tree = walk_tree(&mut reader);
        if let Some(inode) = tree.get(&b"/payload"[..]) {
            let bytes = reader.read_data(inode).unwrap_or_default();
            assert_ne!(
                bytes, b"not for the image\n",
                "the format read through a link swapped in behind the walk"
            );
        }
    }
}

#[test]
fn an_attribute_this_host_will_not_hold_on_this_kind_is_named_as_that() {
    // Two refusals arrive as the same errno and are not the same thing. The kernel restricts
    // a `user.*` attribute to a regular file or a directory by the *type* of what it is set
    // on, not by who is setting it — so on a symbolic link it fails identically for root.
    // Reported as a missing privilege it named a namespace the attribute is not in and
    // prescribed a privilege that would not help.
    //
    // The ext model puts no such restriction on a namespace, so a tree carrying this formats
    // perfectly well and the image is not malformed. This host simply has nowhere to put it.
    let time = Timestamp::from_secs(FAKE);
    // Owned by this process, so the ownership call before the attribute succeeds and what
    // the run meets is the attribute rule rather than a missing CAP_CHOWN.
    // Read off a file this process just made, since the ids are not otherwise reachable
    // without a dependency this test crate does not carry.
    let probe = tempfile::NamedTempFile::new().expect("temp file");
    let (uid, gid) = {
        use std::os::unix::fs::MetadataExt as _;
        let m = probe.as_file().metadata().expect("stat");
        (m.uid(), m.gid())
    };
    let source = ferrosys::ext::TreeBuilder::new()
        .symlink(
            b"/link".to_vec(),
            b"/etc/passwd".to_vec(),
            ferrosys::ext::Metadata::new(0o777, time).owned_by(uid, gid),
        )
        .xattr(b"user.note".to_vec(), b"x".to_vec());
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    match DirectorySink::new(&out)
        .expect("open the destination")
        .write_tree(&mut reader)
    {
        Err(HostError::UnsupportedAttribute { name, .. }) => assert_eq!(name, b"user.note"),
        // A host that does hold it is not what this is about; what must never happen is the
        // refusal claiming a privilege would help.
        Ok(_) => {}
        Err(other) => panic!("expected a kind refusal, got {other:?}"),
    }

    // And skipping records it as the loss it is rather than failing.
    let lenient = destination(&host, "lenient");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&lenient)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("skipping what it cannot hold, an extraction succeeds");
    assert_eq!(
        std::fs::read_link(lenient.join("link")).expect("read the link"),
        Path::new("/etc/passwd"),
        "the link itself is the link, whatever happened to its attribute"
    );
    let _ = report;
}

#[test]
fn a_directory_carries_its_extended_attributes_across() {
    // A directory's attributes are applied with the rest of its metadata, once its children
    // are written — the same wait its mode takes, for the same reason. Nothing about being a
    // directory makes an attribute optional, and one silently left behind would be a property
    // of the image that the extraction dropped while reporting itself faithful.
    //
    // `user.*` because it is the one namespace an unprivileged process may write, so this
    // gate asserts rather than tolerates.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new()
        .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
        .xattr(b"user.origin".to_vec(), b"on-the-directory".to_vec())
        .file(
            b"/etc/hostname".to_vec(),
            b"host\n".to_vec(),
            Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    // Ownership is skipped rather than demanded: this gate is about the attribute, and a
    // root-owned tree cannot be reproduced by an ordinary process.
    let report = DirectorySink::new(&out)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("write the tree");

    let mut value = [0u8; 32];
    let len = rustix::fs::lgetxattr(out.join("etc"), "user.origin", &mut value)
        .expect("the directory's attribute is on the directory");
    assert_eq!(&value[..len], b"on-the-directory");
    assert!(!report.xattrs_dropped);
}

#[test]
fn a_reserved_attribute_is_refused_or_recorded_rather_than_lost_in_silence() {
    // The `security` and `trusted` namespaces are the host's to write, and a root
    // filesystem is full of them: `security.capability` on every binary that holds one,
    // `security.selinux` throughout a labelled tree. So this is what an unprivileged
    // extraction of a real image meets first.
    //
    // The attribute is put into the image by the builder rather than set on the host and
    // walked in, because a test that can only use an attribute the test process is allowed
    // to write can only ever exercise the one namespace that needs no privilege at all.
    use ferrosys::ext::{Metadata, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    // A file capability as the kernel stores one: revision 2, and its permitted,
    // inheritable, and effective words.
    let cap = vec![
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let source = TreeBuilder::new()
        .file(
            b"/ping".to_vec(),
            b"not really an ELF\n".to_vec(),
            Metadata::new(0o755, time),
        )
        .xattr(b"security.capability".to_vec(), cap.clone())
        .file(
            b"/plain".to_vec(),
            b"plain\n".to_vec(),
            Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");
    let host = tempfile::tempdir().expect("temp dir");

    let strict = destination(&host, "strict");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    match DirectorySink::new(&strict)
        .expect("open the destination")
        .write_tree(&mut reader)
    {
        // Unprivileged, which is how this gate usually runs.
        Err(HostError::Unprivileged { path, .. }) => assert_eq!(path, b"/ping"),
        // Privileged, in which case the attribute was set and nothing was dropped.
        Ok(report) => assert!(!report.xattrs_dropped),
        other => panic!("expected a refusal or a written attribute, got {other:?}"),
    }

    let lenient = destination(&host, "lenient");
    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let report = DirectorySink::new(&lenient)
        .expect("open the destination")
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("skipping what it may not set, an extraction succeeds");

    // Whichever happened, the report says so rather than leaving it to be discovered.
    let mut buf = [0u8; 64];
    match rustix::fs::lgetxattr(lenient.join("ping"), "security.capability", &mut buf) {
        Ok(n) => {
            assert_eq!(&buf[..n], &cap[..]);
            assert!(
                !report.xattrs_dropped,
                "an attribute that landed is not dropped"
            );
        }
        Err(_) => assert!(
            report.xattrs_dropped,
            "an attribute that did not land is reported"
        ),
    }

    // Everything else it could write, it wrote — a dropped attribute is not a dropped file.
    assert_eq!(
        std::fs::read(lenient.join("ping")).expect("read"),
        b"not really an ELF\n"
    );
    assert_eq!(
        std::fs::read(lenient.join("plain")).expect("read"),
        b"plain\n"
    );
    assert!(report.skipped.is_empty(), "no name was left out");
}

#[test]
fn a_failure_names_the_path_it_was_writing_inside_the_destination() {
    // An image path is absolute in the filesystem it came from, so joining one onto the
    // destination discards the destination: a failure on `<dest>/etc` reported as `/etc`
    // reads as though an extraction had tried to write the host's own directory, which is
    // the one thing this never does.
    use ferrosys::ext::{Metadata, TreeBuilder};
    use std::os::unix::fs::PermissionsExt;

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new()
        .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
        .file(
            b"/etc/hostname".to_vec(),
            b"ferrosys\n".to_vec(),
            Metadata::new(0o644, time),
        );
    let image = format(source, 16 * MIB, opts()).expect("format the image");

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let sink = DirectorySink::new(&out).expect("open the destination");
    // The destination stops being writable once it is open, so the first name the walk
    // reaches fails and the failure is one this test can read. It is still readable and
    // searchable, so the handle the sink already holds keeps working.
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o500)).expect("chmod");

    let mut reader = Reader::open(io::Cursor::new(image.as_bytes())).expect("open");
    let result = sink.write_tree(&mut reader);
    // Put it back before asserting, so a failure here still leaves a tree that can be
    // cleaned up.
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).expect("chmod back");

    match result {
        Err(HostError::Io { path, .. }) => {
            assert_eq!(path, out.join("etc"));
            assert!(
                path.starts_with(&out),
                "{} names a place outside the destination",
                path.display()
            );
        }
        // Privileged, where a mode bit stops nothing and the tree is simply written.
        Ok(_) => assert!(out.join("etc/hostname").exists()),
        other => panic!("expected an I/O failure or a written tree, got {other:?}"),
    }
}

#[test]
fn a_name_that_could_leave_the_destination_writes_nothing_outside_it() {
    // The image is the input, and a name in it is not a path to resolve. This crafts the
    // one shape a hostile image would use — a directory entry whose name holds a separator,
    // which no formatter writes — and confirms nothing lands outside the destination.
    use ferrosys::ext::{Metadata, OpenOptions, ReadPolicy, TreeBuilder};

    let time = Timestamp::from_secs(FAKE);
    let source = TreeBuilder::new().file(
        b"/escapee".to_vec(),
        b"should not escape\n".to_vec(),
        Metadata::new(0o644, time),
    );
    let mut bytes = format(source, 16 * MIB, opts())
        .expect("format the image")
        .into_bytes();
    // Rewrite the name in the root directory's block: `escapee` becomes `../out`, padded
    // to the same length so nothing around it moves.
    let at = find(&bytes, b"escapee").expect("the name is in the image");
    bytes[at..at + 7].copy_from_slice(b"../outX");
    // The name length is the byte before the file type, two bytes into the entry header.
    bytes[at - 2] = 6;

    let host = tempfile::tempdir().expect("temp dir");
    let out = destination(&host, "unpacked");
    let mut reader = Reader::open_with(
        io::Cursor::new(bytes),
        // The crafted entry leaves the directory's checksum wrong, which a strict read
        // faults before the walk ever reaches the name.
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .expect("open the crafted image");
    let outcome = DirectorySink::new(&out)
        .expect("open the destination")
        // The crafted tree is root-owned, and this gate is about names rather than
        // privileges: without this it would stop at the first ownership it may not set.
        .skip_privileged()
        .write_tree(&mut reader);

    // Either the name never reached the sink or the sink refused it. What must not happen
    // is a file outside the destination, and there is none.
    match outcome {
        Ok(report) => assert_eq!(report.skipped, Vec::<Vec<u8>>::new()),
        Err(HostError::HostileName { .. }) => {}
        Err(other) => panic!("expected the name to be refused, got {other}"),
    }
    assert!(
        !host.path().join("out").exists(),
        "a name in the image escaped the destination"
    );
    assert!(!out.join("escapee").exists());
    assert!(!out.join("outX").exists());
}

/// The offset of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
