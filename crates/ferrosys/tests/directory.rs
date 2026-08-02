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
    DirectorySink, DirectorySource, FormatOptions, GrowReservation, HostError, Reader, Source,
    SourceEntry, format,
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
        assert_eq!(was.atime, now.atime, "{name}: access time moved");
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
    // And an empty one is accepted.
    assert!(DirectorySink::new(destination(&host, "empty")).is_ok());
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
