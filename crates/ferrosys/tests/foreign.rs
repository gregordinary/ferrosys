//! The foreign-image gate: filesystems this crate did **not** create.
//!
//! Every other gate formats with this crate and then checks the result — with
//! `e2fsck`, with `dumpe2fs`, or by reading it back. That proves the writer, and it
//! proves the reader against exactly one formatter's output: our own. It cannot catch a
//! reader that assumes something only our writer does, because nothing it reads was made
//! by anyone else.
//!
//! So these gates run the oracle the other way round. `mke2fs` builds the filesystem,
//! `e2fsck` certifies it healthy, and then the [`Reader`] must agree — both that it finds
//! nothing wrong with it and that it can actually read what is in it. A clean scan and a
//! readable filesystem are independent properties, and asserting only the first would
//! miss a reader that reports no anomalies about a tree it cannot follow.
//!
//! The matrix covers the seams where "what `mke2fs` writes" and "what this crate writes"
//! diverge: the inode size (and so whether an inode has an extended area at all), the
//! block size, the mapping (extent tree or classic block map), and whether the
//! filesystem carries checksums at all.
//!
//! These shell out to `e2fsprogs` with no crate binding. Each gate declares the tool it
//! needs and, when that tool is absent, prints a loud banner and returns rather than
//! asserting success — a skipped gate is reported, never silently green.

mod util;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ferrosys::ext::acl::{Acl, AclEntry, AclQualifier, EXEC, READ, WRITE};
use ferrosys::ext::{OpenOptions, Profile, ReadPolicy, Reader, Severity, Xattr};
use util::{available, e2fsck_clean, tool};

/// The contents of a file in the source tree, keyed by its path in the image.
const HOSTNAME: &[u8] = b"ferrosys\n";
const FSTAB: &[u8] = b"PARTUUID=abc / ext4 errors=remount-ro 0 1\n";

/// A file large enough to need more than the twelve direct block pointers at every
/// block size in the matrix, so the classic map's *indirect* levels are exercised and
/// not just its direct ones. At a 1 KiB block that is 12 KiB of direct mapping, so 64
/// KiB reaches into the single-indirect block.
const BIG_LEN: usize = 64 * 1024;

fn big_file() -> Vec<u8> {
    // A pattern, not zeros: a hole and a mapped block full of zeros read back the same,
    // so zeros would not prove the mapping was followed.
    (0..BIG_LEN).map(|i| (i % 251) as u8).collect()
}

/// Build the source tree `mke2fs -d` ingests: a merged-`/usr` layout like a Debian root
/// filesystem, a file that outgrows the direct block pointers, and a symlink cycle.
fn build_tree(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    std::fs::create_dir_all(root.join("etc"))?;
    std::fs::create_dir_all(root.join("usr/lib/modules/6.1.0"))?;
    std::fs::create_dir_all(root.join("usr/bin"))?;
    std::fs::write(root.join("etc/hostname"), HOSTNAME)?;
    std::fs::write(root.join("etc/fstab"), FSTAB)?;
    std::fs::write(root.join("usr/lib/modules/6.1.0/ext4.ko"), big_file())?;
    std::fs::write(root.join("usr/bin/sh"), b"#!/bin/sh\n")?;
    // Merged `/usr`: the links that make `/lib/modules` unreachable without following one.
    symlink("usr/lib", root.join("lib"))?;
    symlink("usr/bin", root.join("bin"))?;
    // A cycle, so a resolution that does not bound itself hangs instead of failing.
    symlink("loop_b", root.join("loop_a"))?;
    symlink("loop_a", root.join("loop_b"))?;
    Ok(())
}

/// How many entries `/bigdir` holds. With 200-byte names four pack into a 1 KiB leaf,
/// so 800 of them fill roughly 200 leaf blocks — more than a one-level 1 KiB root
/// indexes (123), so `e2fsck -D` grows a two-level tree to hold them.
const HTREE_ENTRIES: usize = 800;

/// Build a source tree of one large directory, `/bigdir`, whose entries have long
/// names. `mke2fs -d` writes it linear; `e2fsck -D` reindexes it into a hash tree.
fn build_htree_tree(root: &Path) -> std::io::Result<()> {
    let bigdir = root.join("bigdir");
    std::fs::create_dir_all(&bigdir)?;
    for i in 0..HTREE_ENTRIES {
        // Long names mean few entries per leaf, so the directory reaches many leaves —
        // and so an interior index level — without needing hundreds of thousands of
        // files.
        let name = String::from_utf8(htree_name(i)).expect("an ASCII name");
        std::fs::write(bigdir.join(name), b"")?;
    }
    Ok(())
}

/// The 200-byte name of entry `i`: `entry-NNNN` padded to length with `x`.
fn htree_name(i: usize) -> Vec<u8> {
    let mut name = format!("entry-{i:04}").into_bytes();
    name.resize(200, b'x');
    name
}

/// One filesystem to build with `mke2fs` and read back.
struct Case {
    /// What makes this case worth running.
    what: &'static str,
    /// `-t`: `ext2`, `ext3`, or `ext4`.
    fs_type: &'static str,
    /// `-b`: bytes per block.
    block_size: u32,
    /// `-I`: bytes per inode.
    inode_size: u32,
    /// `-O`: feature overrides, if any.
    features: &'static str,
}

/// The cases are named individually so a test that builds on one — the ext2 case for
/// its bare block map, the default case for its checksums — names it, and a reordering
/// of the matrix cannot silently retarget that test at a different filesystem.
const DEFAULT_EXT4: Case = Case {
    what: "the mke2fs default: extent-mapped, checksummed, 256-byte inodes. \
           Its reserved inodes carry no i_checksum_hi, which is every real ext4.",
    fs_type: "ext4",
    block_size: 4096,
    inode_size: 256,
    features: "",
};

const SMALL_INODE_EXT4: Case = Case {
    what: "128-byte inodes: no extended area at all, so no i_extra_isize, \
           no creation time, no sub-second timestamps, and no i_checksum_hi",
    fs_type: "ext4",
    block_size: 1024,
    inode_size: 128,
    features: "",
};

const EXT2: Case = Case {
    what: "ext2: every inode is block-mapped, and there are no checksums to \
           find anything wrong with",
    fs_type: "ext2",
    block_size: 1024,
    inode_size: 256,
    features: "",
};

const EXT3: Case = Case {
    what: "ext3: block-mapped like ext2, but with a journal — whose inode is \
           block-mapped too",
    fs_type: "ext3",
    block_size: 1024,
    inode_size: 256,
    features: "",
};

const NO_CSUM_EXT4: Case = Case {
    what: "ext4 without metadata_csum: the checksums are gone but the extent \
           trees remain",
    fs_type: "ext4",
    block_size: 2048,
    inode_size: 256,
    features: "^metadata_csum",
};

const BIG_INODE_EXT4: Case = Case {
    what: "512-byte inodes: an extended area larger than the one this crate \
           writes, so the inline attribute region is a different size",
    fs_type: "ext4",
    block_size: 4096,
    inode_size: 512,
    features: "",
};

/// The matrix. Each case is here because it stresses a seam the others do not.
const CASES: &[Case] = &[
    DEFAULT_EXT4,
    SMALL_INODE_EXT4,
    EXT2,
    EXT3,
    NO_CSUM_EXT4,
    BIG_INODE_EXT4,
];

/// Build one case with `mke2fs -d` and return the image path (kept alive by `dir`).
fn mke2fs(case: &Case, tree: &Path, dir: &Path) -> PathBuf {
    let image = dir.join(format!(
        "{}-b{}-i{}.img",
        case.fs_type, case.block_size, case.inode_size
    ));
    let mut cmd = tool("mke2fs");
    cmd.args(["-q", "-F", "-t", case.fs_type])
        .args(["-b", &case.block_size.to_string()])
        .args(["-I", &case.inode_size.to_string()])
        .arg("-d")
        .arg(tree)
        // Fixed, so a failure reproduces.
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("32M");
    if !case.features.is_empty() {
        cmd.args(["-O", case.features]);
    }
    let out = cmd.output().expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "mke2fs failed for {}: {}",
        case.what,
        String::from_utf8_lossy(&out.stderr)
    );
    image
}

/// Open an image and assert the scan finds nothing an image `e2fsck` calls clean should
/// not have. Returns the reader, so the caller can go on to read the filesystem.
fn scan_clean(path: &Path, what: &str) -> Reader<std::fs::File> {
    let file = std::fs::File::open(path).expect("open image");
    let mut reader = Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient))
        .unwrap_or_else(|e| panic!("{what}: open: {e}"));
    let report = reader.scan();
    let bad: Vec<_> = report
        .anomalies()
        .iter()
        .filter(|a| a.severity >= Severity::Integrity)
        .collect();
    assert!(
        bad.is_empty(),
        "{what}: e2fsck calls this filesystem clean, but scan() reports {} anomalies:\n{}",
        bad.len(),
        bad.iter()
            .map(|a| format!("  [{:?}/{:?}] {}", a.severity, a.category, a.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
    reader
}

/// Read the tree back through the reader and assert it is the one that went in.
///
/// This is the half a scan cannot cover: a reader that cannot follow an inode's mapping
/// can still report no anomalies about it, so the filesystem is read, not just checked.
fn read_back(reader: &mut Reader<std::fs::File>, what: &str) {
    let expect = |r: &mut Reader<std::fs::File>, path: &[u8], want: &[u8]| {
        let (_, inode) = r
            .lookup(path)
            .unwrap_or_else(|e| panic!("{what}: lookup({}): {e}", String::from_utf8_lossy(path)));
        let got = r
            .read_data(&inode)
            .unwrap_or_else(|e| panic!("{what}: read({}): {e}", String::from_utf8_lossy(path)));
        assert_eq!(
            got,
            want,
            "{what}: contents of {} differ",
            String::from_utf8_lossy(path)
        );
    };

    expect(reader, b"/etc/hostname", HOSTNAME);
    expect(reader, b"/etc/fstab", FSTAB);

    // The file that outgrows the direct block pointers. On ext2 and ext3 this is the
    // single-indirect level of the classic map; on ext4 it is an extent.
    expect(reader, b"/usr/lib/modules/6.1.0/ext4.ko", &big_file());

    // The same file through the merged-`/usr` symlink: unreachable without following it,
    // and the single most important path on a root filesystem that will not boot.
    expect(reader, b"/lib/modules/6.1.0/ext4.ko", &big_file());

    // The link resolves to the same inode as the path through it.
    let (direct, _) = reader
        .lookup(b"/usr/lib/modules")
        .expect("lookup /usr/lib/modules");
    let (linked, _) = reader.lookup(b"/lib/modules").expect("lookup /lib/modules");
    assert_eq!(
        direct, linked,
        "{what}: /lib/modules is not /usr/lib/modules"
    );

    // Without following, the link is the link.
    let (_, link) = reader
        .lookup_no_follow(b"/lib")
        .expect("lookup_no_follow /lib");
    assert_eq!(
        link.mode & 0o170000,
        0o120000,
        "{what}: /lib is not a symlink"
    );
    assert_eq!(
        reader.read_symlink(&link).expect("read link"),
        b"usr/lib",
        "{what}: /lib points somewhere unexpected"
    );

    // A cycle terminates rather than hanging.
    assert!(
        matches!(
            reader.lookup(b"/loop_a"),
            Err(ferrosys::ext::ReadError::SymlinkLoop { .. })
        ),
        "{what}: a symlink cycle did not terminate as a loop"
    );

    // And the whole tree walks.
    let paths: Vec<Vec<u8>> = reader
        .walk()
        .unwrap_or_else(|e| panic!("{what}: walk: {e}"))
        .into_iter()
        .map(|e| e.path)
        .collect();
    for want in [
        &b"/etc/hostname"[..],
        b"/usr/lib/modules/6.1.0/ext4.ko",
        b"/lib",
    ] {
        assert!(
            paths.iter().any(|p| p == want),
            "{what}: walk() did not yield {}",
            String::from_utf8_lossy(want)
        );
    }
}

/// The negative control for the block-map walk.
///
/// A walk that cannot fail is worth no more than not walking at all: either way the scan
/// reports a clean bill of health about a mapping it never really checked. Break one
/// pointer in an otherwise healthy ext2 and the scan must say so.
#[test]
fn the_scan_faults_a_corrupt_block_map() {
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    build_tree(&tree).expect("build source tree");

    // The ext2 case: every inode is block-mapped, and there are no checksums, so the
    // mapping is the *only* thing a scan has to go on.
    let image = mke2fs(&EXT2, &tree, dir.path());
    let mut bytes = std::fs::read(&image).expect("read image");

    // Locate /etc/hostname's inode on disk, then point its first block outside the
    // filesystem. e2fsck must object, and so must the scan.
    let offset = {
        let file = std::fs::File::open(&image).expect("open");
        let mut r =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let (number, _) = r.lookup(b"/etc/hostname").expect("lookup");
        let sb = r.superblock();
        let (ipg, isize, bs) = (
            sb.inodes_per_group,
            sb.inode_size as u64,
            r.feature().block_size as u64,
        );
        let group = (number - 1) / ipg;
        let index = u64::from((number - 1) % ipg);
        let table = r.group_descriptor(group).expect("desc").inode_table;
        (table * bs + index * isize) as usize
    };
    // i_block[0] is at 0x28; a block number far past a 32 MiB filesystem.
    let bogus = 0x00ff_ffffu32.to_le_bytes();
    bytes[offset + 0x28..offset + 0x2c].copy_from_slice(&bogus);
    std::fs::write(&image, &bytes).expect("write back");

    assert!(
        e2fsck_clean(&image).is_err(),
        "the corruption is not corruption: e2fsck still calls this image clean, \
         so this control proves nothing"
    );

    let file = std::fs::File::open(&image).expect("open");
    let mut r =
        Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
    let report = r.scan();
    assert!(
        !report.is_clean(),
        "scan() reported a clean bill of health for a block map pointing outside \
         the filesystem — the walk has no teeth"
    );
    // The stray pointer is filed against the inode that holds the map — /etc/hostname is
    // a regular file — not the superblock, which is intact.
    assert!(
        report
            .anomalies()
            .iter()
            .any(|a| a.category == ferrosys::ext::Category::Inode),
        "an out-of-range block-map pointer must be filed against its inode"
    );
    assert!(
        r.lookup(b"/etc/hostname")
            .and_then(|(_, i)| r.read_data(&i))
            .is_err(),
        "and reading through the broken map must fail rather than return something"
    );
}

#[test]
fn mke2fs_formatted_images_read_clean() {
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    build_tree(&tree).expect("build source tree");

    for case in CASES {
        let what = case.what;
        let image = mke2fs(case, &tree, dir.path());
        e2fsck_clean(&image)
            .unwrap_or_else(|e| panic!("{what}: mke2fs built an image e2fsck rejects:\n{e}"));

        let mut reader = scan_clean(&image, what);

        // The reader labels the image with the family `mke2fs -t` built it as: extent-mapped
        // ext4 (checksums or not), block-mapped ext3 with its journal, and journal-free ext2.
        let expected = match case.fs_type {
            "ext2" => Profile::Ext2,
            "ext3" => Profile::Ext3,
            "ext4" => Profile::Ext4,
            other => panic!("{what}: no expected profile for fs_type {other}"),
        };
        assert_eq!(
            reader.profile(),
            expected,
            "{what}: the reader classified a `mke2fs -t {}` image as {:?}",
            case.fs_type,
            reader.profile()
        );

        read_back(&mut reader, what);
    }
}

/// A filesystem that has been *used*, not merely formatted.
///
/// A freshly formatted image leaves untouched every field only a running kernel writes.
/// A repair tool never sees one of those: it is pointed at filesystems that have been
/// mounted, written to, and have failed. Those carry `l_i_version`, which the kernel
/// bumps on every inode update, and the superblock error record, which it fills in on any
/// error — neither of which this crate models.
///
/// `debugfs` sets them, recomputing the checksums through `libext2fs` as the kernel would,
/// so `e2fsck` still calls the image clean. A reader that recomputes a checksum from its
/// own model of the object rather than from the object's bytes zeroes every field it does
/// not model, and rejects the whole filesystem.
#[test]
fn a_used_filesystem_reads_clean() {
    if !available("mke2fs") || !available("e2fsck") || !available("debugfs") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    build_tree(&tree).expect("build source tree");

    let image = mke2fs(&DEFAULT_EXT4, &tree, dir.path());

    // `l_i_version` on an ordinary inode, and the kernel's superblock error record.
    for request in [
        "sif <12> version 42",
        "ssv error_count 3",
        "ssv mount_opts errors=remount-ro",
        "ssv last_orphan 11",
    ] {
        let out = tool("debugfs")
            .args(["-w", "-R", request])
            .arg(&image)
            .output()
            .expect("spawn debugfs");
        // debugfs exits 0 even when the command it was given failed, so its success
        // proves nothing; e2fsck below is what certifies the image is still healthy.
        assert!(out.status.success(), "debugfs did not run: {request}");
    }

    e2fsck_clean(&image).unwrap_or_else(|e| {
        panic!("debugfs left the image damaged, so this gate proves nothing:\n{e}")
    });

    let mut reader = scan_clean(&image, "a used filesystem");
    read_back(&mut reader, "a used filesystem");
}

/// A hash-indexed directory grown by another tool, deep enough to have interior nodes.
///
/// `mke2fs -d` writes every directory linear, so no gate above reads a foreign hash
/// tree at all. `e2fsck -D` reindexes one, and it grows the tree the way the kernel
/// does: it fills leaf blocks first and allocates an interior index node only when the
/// level above overflows, so the interior nodes land at *high* logical blocks while the
/// low blocks are leaves. This crate's own writer places interior nodes right after the
/// root instead. A reader that decided a block's role from its position — interior if
/// low, leaf if high — would check the leaves with the index-node tail and the index
/// nodes with the leaf tail, and reject this healthy directory as corrupt. Following the
/// index down from the root instead reads either layout, and this is the only gate that
/// covers the foreign one.
#[test]
fn a_foreign_two_level_htree_reads_clean() {
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    build_htree_tree(&tree).expect("build the htree source tree");

    // A 1 KiB block keeps the two-level threshold low; `-N` provides an inode per entry
    // (the default inode count for a filesystem this small would not).
    let image = dir.path().join("htree.img");
    let out = tool("mke2fs")
        .args([
            "-q", "-F", "-t", "ext4", "-b", "1024", "-I", "256", "-N", "4096",
        ])
        .arg("-d")
        .arg(&tree)
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("64M")
        .output()
        .expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "mke2fs failed to build the htree source: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `-D` reindexes the linear /bigdir into a hash tree. It reports the optimization as
    // a modification, so a clean (0) or corrected (1) exit is expected; the `e2fsck -fn`
    // pass that follows is the certificate that the tree it wrote is healthy.
    let opt = tool("e2fsck")
        .args(["-f", "-y", "-D"])
        .arg(&image)
        .output()
        .expect("spawn e2fsck -D");
    assert!(
        matches!(opt.status.code(), Some(0 | 1)),
        "e2fsck -D did not optimize the directory (exit {:?}):\n{}",
        opt.status.code(),
        String::from_utf8_lossy(&opt.stdout)
    );
    e2fsck_clean(&image)
        .unwrap_or_else(|e| panic!("e2fsck -D left the reindexed directory unhealthy:\n{e}"));

    // The reader agrees the tree is clean...
    let mut reader = scan_clean(&image, "a foreign two-level htree");

    // ...over a directory that is provably two-level: a one-level 1 KiB root indexes at
    // most 123 leaves, so a directory spanning more than 124 blocks (root plus leaves)
    // must have grown an interior level. If `e2fsck` ever stopped doing so, this asserts
    // rather than silently testing a one-level tree the position rule handles anyway.
    let (_, dir_inode) = reader.lookup(b"/bigdir").expect("lookup /bigdir");
    let block_count = dir_inode.size / 1024;
    assert!(
        block_count > 124,
        "e2fsck built a {block_count}-block index, not the two-level tree this gate \
         exists to read"
    );

    // ...and can follow it: every name that went in comes back out of the foreign index.
    let names: std::collections::BTreeSet<Vec<u8>> = reader
        .read_dir(&dir_inode)
        .expect("read_dir /bigdir")
        .into_iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| e.name)
        .collect();
    assert_eq!(
        names.len(),
        HTREE_ENTRIES,
        "the reader recovered {} of {HTREE_ENTRIES} names from the foreign index",
        names.len()
    );
    assert!(
        names.contains(&htree_name(HTREE_ENTRIES - 1)),
        "a known name is missing from the foreign index"
    );
}

/// A directory entry that begins in the last twelve bytes of its block.
///
/// A block *without* `metadata_csum` has no checksum tail: the kernel tiles real
/// entries across the whole block, so a legitimate final entry can begin at exactly
/// `block_size - 12`. A reader that reserves those twelve bytes — as every block this
/// crate writes does have — stops one entry short and drops it, and the file vanishes
/// from `read_dir`, `walk`, and `lookup` with no error and no anomaly. `mke2fs -d`
/// tiles a directory but rarely lands an entry there, so this rewrites one to a valid
/// tiling with its last entry in the final twelve bytes and certifies it with e2fsck
/// before reading it back.
#[test]
fn a_final_dir_entry_in_the_last_twelve_bytes_is_read() {
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("probe")).expect("mkdir probe");
    std::fs::write(tree.join("probe/z"), b"tail\n").expect("write probe/z");

    // ext2, 1 KiB blocks: no checksums, block-mapped, and a one-block directory that is
    // simple to rewrite by hand.
    let image = dir.path().join("tail.img");
    let out = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext2", "-b", "1024", "-I", "256"])
        .arg("-d")
        .arg(&tree)
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("16M")
        .output()
        .expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "mke2fs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Locate /probe (its inode number and its single data block) and /probe/z's inode.
    let (probe_no, probe_block, z_no, block_size) = {
        let file = std::fs::File::open(&image).expect("open");
        let mut r =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let (probe_no, probe) = r.lookup(b"/probe").expect("lookup /probe");
        let (z_no, _) = r.lookup(b"/probe/z").expect("lookup /probe/z");
        // ext2 is block-mapped, so i_block[0] is the directory's first data block.
        let block = u32::from_le_bytes(probe.block[0..4].try_into().unwrap());
        (probe_no, block, z_no, r.feature().block_size as usize)
    };
    assert!(
        probe_block != 0,
        "the directory has no data block to rewrite"
    );

    // Rewrite /probe's block to a valid tiling: "." and ".." at the front, one unused
    // slot spanning the middle, and "z" as the final entry beginning at block_size - 12.
    let mut bytes = std::fs::read(&image).expect("read image");
    let base = probe_block as usize * block_size;
    {
        let block = &mut bytes[base..base + block_size];
        block.fill(0);
        put_dirent(block, 0, probe_no, 12, FT_DIR, b"."); // self
        put_dirent(block, 12, 2, 12, FT_DIR, b".."); // parent is root (inode 2)
        // An unused slot (inode 0) spanning the gap, as a deleted entry leaves behind.
        put_dirent(block, 24, 0, (block_size - 36) as u16, 0, b"");
        // The real entry, its first byte at block_size - 12.
        put_dirent(block, block_size - 12, z_no, 12, FT_REG, b"z");
    }
    std::fs::write(&image, &bytes).expect("write back");

    // The crafted directory is a valid ext2 directory, not corruption: e2fsck must agree.
    e2fsck_clean(&image).unwrap_or_else(|e| {
        panic!("the crafted directory is not a valid tiling, so this gate proves nothing:\n{e}")
    });

    // The reader must return `z` — the entry a twelve-byte-tail assumption would drop.
    let file = std::fs::File::open(&image).expect("open");
    let mut r =
        Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
    let (_, probe) = r.lookup(b"/probe").expect("lookup /probe");
    let names: Vec<Vec<u8>> = r
        .read_dir(&probe)
        .expect("read_dir /probe")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(
        names.iter().any(|n| n == b"z"),
        "read_dir dropped the final entry in the last twelve bytes of the block; \
         it returned {:?}",
        names
            .iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect::<Vec<_>>()
    );
    // And it resolves, with the contents that went in.
    let (found, z) = r
        .lookup(b"/probe/z")
        .expect("the final entry does not resolve");
    assert_eq!(found, z_no, "resolved to the wrong inode");
    assert_eq!(r.read_data(&z).expect("read z"), b"tail\n");
}

/// A directory entry whose name a real ext4 filesystem could not hold — one carrying a
/// path separator.
///
/// The kernel's `ext4_check_dir_entry` forbids `/` and NUL in a name, so neither can
/// appear on a filesystem it wrote. A crafted image can hold one anyway, and a reader
/// that built a path from it would let `../../etc/cron.d/evil` out of the tree and into
/// an extractor. The reader instead flags such a name as a structural anomaly and builds
/// no path from it: `scan` reports it, and `walk` skips it. This crafts the name (mke2fs
/// cannot write one) and checks both.
#[test]
fn a_directory_entry_name_that_traverses_is_flagged_and_never_walked() {
    if !available("mke2fs") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("probe")).expect("mkdir probe");
    std::fs::write(tree.join("probe/z"), b"payload\n").expect("write probe/z");

    let image = dir.path().join("hostile.img");
    let out = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext2", "-b", "1024", "-I", "256"])
        .arg("-d")
        .arg(&tree)
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("16M")
        .output()
        .expect("spawn mke2fs");
    assert!(out.status.success(), "mke2fs failed");

    let (probe_no, probe_block, z_no, block_size) = {
        let file = std::fs::File::open(&image).expect("open");
        let mut r =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let (probe_no, probe) = r.lookup(b"/probe").expect("lookup /probe");
        let (z_no, _) = r.lookup(b"/probe/z").expect("lookup /probe/z");
        let block = u32::from_le_bytes(probe.block[0..4].try_into().unwrap());
        (probe_no, block, z_no, r.feature().block_size as usize)
    };

    // Rewrite /probe with an entry literally named "a/b/../evil": "." and ".." at the
    // front, then the hostile entry, then an unused slot filling the block.
    const HOSTILE: &[u8] = b"a/b/../evil";
    let mut bytes = std::fs::read(&image).expect("read image");
    {
        let base = probe_block as usize * block_size;
        let block = &mut bytes[base..base + block_size];
        block.fill(0);
        put_dirent(block, 0, probe_no, 12, FT_DIR, b".");
        put_dirent(block, 12, 2, 12, FT_DIR, b"..");
        let rec = (8 + HOSTILE.len()).next_multiple_of(4);
        put_dirent(block, 24, z_no, rec as u16, FT_REG, HOSTILE);
        let filler = 24 + rec;
        put_dirent(block, filler, 0, (block_size - filler) as u16, 0, b"");
    }
    std::fs::write(&image, &bytes).expect("write back");

    let file = std::fs::File::open(&image).expect("open");
    let mut r =
        Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");

    // The scan reports the hostile name as a structural fault filed against /probe.
    let report = r.scan();
    assert!(
        report
            .anomalies()
            .iter()
            .any(|a| a.location.inode == Some(probe_no)
                && a.category == ferrosys::ext::Category::Directory
                && a.severity == Severity::Structural),
        "scan did not flag the traversing directory-entry name; it reported: {:?}",
        report
            .anomalies()
            .iter()
            .map(|a| a.detail.clone())
            .collect::<Vec<_>>()
    );

    // And no walked path carries the hostile name: the entry is skipped, not turned into
    // a traversing member path an extractor would honor.
    let paths = r.walk().expect("walk");
    assert!(
        paths
            .iter()
            .all(|e| !e.path.windows(3).any(|w| w == b"a/b")),
        "walk() yielded a path built from the traversing name"
    );
}

/// A filesystem whose in-use inodes are scattered, not numbered densely from one.
///
/// A fresh format fills inodes densely, but a live filesystem does not: the allocator
/// spreads new files across block groups, so the first inode of a later group is in use
/// while lower numbers are free. A scan that assumes `inodes_count - free_inodes_count`
/// in-use inodes numbered from one never reaches the scattered ones, so their checksums,
/// extent trees, and directory tails go unchecked while the report still reads "clean."
/// This builds the scattered layout with debugfs — fill a group, spill into the next,
/// then free the bridge — and proves the scan reaches an inode stranded above the dense
/// cutoff by faulting it once its checksum is broken.
#[test]
fn a_scattered_inode_above_the_dense_cutoff_is_scanned() {
    if !available("mke2fs") || !available("e2fsck") || !available("debugfs") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let image = dir.path().join("scattered.img");
    let src = dir.path().join("src");
    std::fs::write(&src, b"scattered\n").expect("write src");

    // Small groups (-g) and few inodes per group (-N) so a handful of files fill the
    // first group and spill into the second.
    let out = tool("mke2fs")
        .args([
            "-q", "-F", "-t", "ext4", "-b", "1024", "-g", "1024", "-N", "64", "-I", "256",
        ])
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("4M")
        .output()
        .expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "mke2fs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Twelve files fill the first group and spill into the second; freeing the first ten
    // leaves the last two stranded in the later group, above where the dense count reaches.
    let fill: String = (1..=12)
        .map(|i| format!("write {} f{i}\n", src.display()))
        .collect();
    run_debugfs(&image, dir.path(), "fill.txt", &fill);
    let del: String = (1..=10).map(|i| format!("rm f{i}\n")).collect();
    run_debugfs(&image, dir.path(), "del.txt", &del);

    // debugfs maintains the bitmaps and counts through libext2fs, so the scattered image
    // is valid: e2fsck must agree before the reader is asked to scan it.
    e2fsck_clean(&image).unwrap_or_else(|e| {
        panic!("the scattered image is not valid, so this proves nothing:\n{e}")
    });

    // Locate the stranded inode, and confirm it really is above the dense cutoff.
    let (high_no, cutoff, offset) = {
        let file = std::fs::File::open(&image).expect("open");
        let mut r =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let (high_no, _) = r.lookup(b"/f12").expect("lookup /f12 (the stranded file)");
        let sb = r.superblock();
        let cutoff = sb.inodes_count.saturating_sub(sb.free_inodes_count);
        let ipg = sb.inodes_per_group;
        let isize = u64::from(sb.inode_size);
        let bs = u64::from(r.feature().block_size);
        let group = (high_no - 1) / ipg;
        let index = u64::from((high_no - 1) % ipg);
        let table = r.group_descriptor(group).expect("desc").inode_table;
        (high_no, cutoff, (table * bs + index * isize) as usize)
    };
    assert!(
        high_no > cutoff,
        "the stranded inode {high_no} is within the dense cutoff {cutoff}, so the \
         fill-spill-delete did not scatter it and this gate proves nothing"
    );

    // The pristine scattered image reads clean.
    scan_clean(&image, "a scattered filesystem");

    // Break the stranded inode's checksum. A scan that reaches it faults it against that
    // inode; a scan that stops at the dense cutoff never sees the corruption at all.
    let mut bytes = std::fs::read(&image).expect("read image");
    // i_atime is at inode offset 0x08 — inside the inode checksum's coverage, and clear
    // of every field the parse depends on.
    bytes[offset + 0x08] ^= 0xff;
    std::fs::write(&image, &bytes).expect("write back");

    let file = std::fs::File::open(&image).expect("open");
    let mut r =
        Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
    let report = r.scan();
    assert!(
        report
            .anomalies()
            .iter()
            .any(|a| a.location.inode == Some(high_no) && a.severity >= Severity::Integrity),
        "scan did not fault the corrupted inode {high_no} scattered above the dense \
         cutoff {cutoff}; a dense-from-one enumeration never reaches it. It reported: {:?}",
        report
            .anomalies()
            .iter()
            .map(|a| a.detail.clone())
            .collect::<Vec<_>>()
    );
}

/// Run a multi-command `debugfs` script against `image`. debugfs exits zero even when a
/// command it was given failed, so a passing status proves only that it ran; the
/// `e2fsck` that follows is what certifies the result.
fn run_debugfs(image: &Path, dir: &Path, name: &str, script: &str) {
    let script_path = dir.join(name);
    std::fs::write(&script_path, script).expect("write debugfs script");
    let out = tool("debugfs")
        .args(["-w", "-f"])
        .arg(&script_path)
        .arg(image)
        .output()
        .expect("spawn debugfs");
    assert!(
        out.status.success(),
        "debugfs did not run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The on-disk file-type byte for a directory and a regular file (the `filetype`
/// feature, which the vendored config enables).
const FT_DIR: u8 = 2;
const FT_REG: u8 = 1;

/// Write one `struct ext4_dir_entry_2` into `block` at `off`.
fn put_dirent(block: &mut [u8], off: usize, inode: u32, rec_len: u16, file_type: u8, name: &[u8]) {
    block[off..off + 4].copy_from_slice(&inode.to_le_bytes());
    block[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
    block[off + 6] = name.len() as u8;
    block[off + 7] = file_type;
    block[off + 8..off + 8 + name.len()].copy_from_slice(name);
}

/// Sparse files, whose logical size and logical offsets outrun the filesystem.
///
/// A hole costs no block, so a file's size can exceed the filesystem it lives on and a
/// valid extent can sit at a logical offset past the last physical block. A reader that
/// bounds a *logical* range by the *physical* block count reads both wrong: it truncates
/// the oversized file's tail to zero-length and rejects the high-offset extent as out of
/// range — silent-wrong-reads of an image e2fsck calls clean. `mke2fs -d` writes these
/// directly, so no crafting is needed: a `truncate`d all-hole file larger than the
/// filesystem, and a marker written at a block past its last.
#[test]
fn sparse_files_read_to_their_full_logical_size() {
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    // Both mapping kinds: extent-mapped ext4 and block-mapped ext2.
    for (fs_type, block_size) in [("ext4", 4096u32), ("ext2", 1024u32)] {
        sparse_case(fs_type, block_size);
    }
}

const SPARSE_MARKER: &[u8] = b"FERROSYS-SPARSE-TAIL";

fn sparse_case(fs_type: &str, block_size: u32) {
    use std::io::{Seek, SeekFrom, Write};

    let what = format!("{fs_type} sparse");
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir tree");

    // An 8 MiB filesystem, and files whose logical extent is larger than it.
    let fs_mib: u64 = 8;
    let fs_bytes = fs_mib * 1024 * 1024;
    let fs_blocks = fs_bytes / u64::from(block_size);
    // A logical offset a few blocks past the last physical one.
    let data_block = fs_blocks + 64;
    let data_offset = data_block * u64::from(block_size);
    let highdata_size = data_offset + SPARSE_MARKER.len() as u64;
    // An all-hole file, larger than the filesystem, with no data at all.
    let allhole_size = fs_bytes + 1024 * 1024;

    std::fs::File::create(tree.join("allhole"))
        .and_then(|f| f.set_len(allhole_size))
        .expect("truncate allhole");
    {
        let mut f = std::fs::File::create(tree.join("highdata")).expect("create highdata");
        f.seek(SeekFrom::Start(data_offset)).expect("seek");
        f.write_all(SPARSE_MARKER).expect("write marker");
    }

    let image = dir.path().join(format!("sparse-{fs_type}.img"));
    let out = tool("mke2fs")
        .args([
            "-q",
            "-F",
            "-t",
            fs_type,
            "-b",
            &block_size.to_string(),
            "-I",
            "256",
        ])
        .arg("-d")
        .arg(&tree)
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg(format!("{fs_mib}M"))
        .output()
        .expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "{what}: mke2fs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    e2fsck_clean(&image)
        .unwrap_or_else(|e| panic!("{what}: mke2fs built an image e2fsck rejects:\n{e}"));

    let mut reader = scan_clean(&image, &what);

    // The filesystem really is smaller than the files' logical reach — otherwise the
    // bug this gate exists for could not fire.
    let blocks_count = reader.superblock().blocks_count;
    assert!(
        data_block > blocks_count,
        "{what}: the data block {data_block} is within the {blocks_count}-block \
         filesystem, so this case does not exercise a logical offset past it"
    );

    // The all-hole file reads back its full size, all zeros — not truncated at the
    // filesystem's last block.
    let (_, allhole) = reader.lookup(b"/allhole").expect("lookup /allhole");
    let got = reader.read_data(&allhole).expect("read /allhole");
    assert_eq!(
        got.len() as u64,
        allhole_size,
        "{what}: the all-hole file was truncated to the physical size"
    );
    assert!(
        got.iter().all(|&b| b == 0),
        "{what}: the all-hole file is not all zeros"
    );

    // The high-offset extent is read, not rejected: the marker comes back at its offset.
    let (_, highdata) = reader.lookup(b"/highdata").expect("lookup /highdata");
    let got = reader
        .read_data(&highdata)
        .expect("read /highdata past the fs");
    assert_eq!(
        got.len() as u64,
        highdata_size,
        "{what}: the high-offset file read back the wrong length"
    );
    assert_eq!(
        &got[data_offset as usize..],
        SPARSE_MARKER,
        "{what}: the marker past the last physical block did not read back"
    );
    assert!(
        got[..data_offset as usize].iter().all(|&b| b == 0),
        "{what}: the hole before the marker did not read back as zeros"
    );
}

#[test]
fn a_revision_zero_filesystem_reads() {
    // A revision-0 filesystem defines no `s_inode_size` and no `s_first_ino`: those
    // words sit outside the superblock that revision describes, and the values they
    // would hold are fixed by the revision itself — the 128-byte classic inode, and
    // inode 11. Reading the zero as an inode stride puts every inode at the wrong
    // offset, so a reader that does not resolve the revision cannot open the
    // filesystem at all.
    if !available("mke2fs") || !available("e2fsck") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    build_tree(&tree).expect("build source tree");

    // `-r 0` is the revision; 128-byte inodes and no features are what it implies.
    let image = dir.path().join("rev0.img");
    let out = tool("mke2fs")
        .args([
            "-q", "-F", "-r", "0", "-b", "1024", "-I", "128", "-O", "none",
        ])
        .arg("-d")
        .arg(&tree)
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .arg(&image)
        .arg("16M")
        .output()
        .expect("spawn mke2fs");
    assert!(
        out.status.success(),
        "mke2fs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `mke2fs` fills both words in even at revision 0. Zeroing them is what an older
    // formatter left behind and what the revision means; `e2fsck` below reads the
    // filesystem the same either way, which is what certifies the image is healthy and
    // so that anything the reader objects to is the reader's fault.
    let mut bytes = std::fs::read(&image).expect("read image");
    bytes[1024 + 0x54..1024 + 0x58].fill(0); // s_first_ino
    bytes[1024 + 0x58..1024 + 0x5a].fill(0); // s_inode_size
    std::fs::write(&image, &bytes).expect("write image");

    let what = "revision-0 ext2";
    e2fsck_clean(&image).unwrap_or_else(|e| panic!("{what}: {e}"));

    let mut reader = scan_clean(&image, what);
    assert_eq!(reader.superblock().rev_level, 0);
    assert_eq!(
        reader.superblock().inode_size,
        128,
        "the inode size the revision fixes"
    );
    assert_eq!(
        reader.superblock().first_ino,
        11,
        "and the first inode it fixes"
    );
    read_back(&mut reader, what);
}

/// The attributes as a name-to-value map, for order-free assertions.
fn xattr_map(attrs: Vec<Xattr>) -> BTreeMap<Vec<u8>, Vec<u8>> {
    attrs.into_iter().map(|x| (x.name, x.value)).collect()
}

/// The access ACL the gate plants: the shape `setfacl -m u:1000:r` leaves behind, with
/// the named user that makes the mask entry mandatory.
fn access_entries() -> Vec<AclEntry> {
    vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: READ | WRITE,
        },
        AclEntry {
            who: AclQualifier::User(1000),
            perm: READ,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: READ,
        },
        AclEntry {
            who: AclQualifier::Mask,
            perm: READ | WRITE,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: 0,
        },
    ]
}

/// A minimal default ACL for a directory: no named entries, so no mask.
fn default_entries() -> Vec<AclEntry> {
    vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: READ | WRITE | EXEC,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: READ | EXEC,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: 0,
        },
    ]
}

/// Encode ACL entries in the userspace extended-attribute form: version 2, then one
/// eight-byte record per entry — what `setfacl` hands the kernel, and what `debugfs`'s
/// `ea_set` expects for the `system.posix_acl_*` names before libext2fs converts it to
/// the on-disk encoding. The tag values are the POSIX ACL ABI's; an entry that names
/// nobody carries the undefined id.
fn acl_xattr_v2(entries: &[AclEntry]) -> Vec<u8> {
    let mut out = 2u32.to_le_bytes().to_vec();
    for e in entries {
        let (tag, id) = match e.who {
            AclQualifier::UserObj => (0x01u16, None),
            AclQualifier::User(id) => (0x02, Some(id)),
            AclQualifier::GroupObj => (0x04, None),
            AclQualifier::Group(id) => (0x08, Some(id)),
            AclQualifier::Mask => (0x10, None),
            AclQualifier::Other => (0x20, None),
        };
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        out.extend_from_slice(&id.unwrap_or(u32::MAX).to_le_bytes());
    }
    out
}

/// Extended attributes and POSIX ACLs written by another implementation.
///
/// Every attribute block and inline set the xattr parsers had read before this gate
/// was written by this crate, so a parser that merely inverted the writer would pass
/// every other gate while misreading a foreign layout. Here `debugfs` (libext2fs)
/// places the attributes on the checksummed default profile: a small value in the
/// inode, a large one spilled to an attribute block, a value on a directory, and both
/// POSIX ACLs. The ACLs are fed to `debugfs` in the userspace encoding and libext2fs
/// *converts* them, so the value bytes on disk are its converter's output — which must
/// equal what this crate's own encoder produces for the same entries, and must decode
/// back to them.
#[test]
fn foreign_xattrs_and_acls_read_back() {
    if !available("mke2fs") || !available("e2fsck") || !available("debugfs") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("etc")).expect("mkdir etc");
    std::fs::write(tree.join("etc/hostname"), HOSTNAME).expect("write hostname");
    std::fs::write(tree.join("etc/fstab"), FSTAB).expect("write fstab");
    std::fs::write(tree.join("probe"), b"inline only\n").expect("write probe");

    let image = mke2fs(&DEFAULT_EXT4, &tree, dir.path());

    // A value too large for the 256-byte inode's attribute region, so libext2fs
    // spills it to an external attribute block. A pattern, so a truncated or shifted
    // read cannot compare equal.
    let big: Vec<u8> = (0..400).map(|i| (i % 253) as u8).collect();
    let big_path = dir.path().join("big.bin");
    std::fs::write(&big_path, &big).expect("write value file");
    let access_path = dir.path().join("access.bin");
    std::fs::write(&access_path, acl_xattr_v2(&access_entries())).expect("write access ACL");
    let default_path = dir.path().join("default.bin");
    std::fs::write(&default_path, acl_xattr_v2(&default_entries())).expect("write default ACL");

    let script = format!(
        "ea_set /etc/hostname user.origin ferrosys-foreign\n\
         ea_set -f {} /etc/hostname user.big\n\
         ea_set /probe user.small probe-value\n\
         ea_set /etc user.dirattr on-a-directory\n\
         ea_set -f {} /etc/fstab system.posix_acl_access\n\
         ea_set -f {} /etc system.posix_acl_default\n",
        big_path.display(),
        access_path.display(),
        default_path.display(),
    );
    run_debugfs(&image, dir.path(), "ea.txt", &script);
    e2fsck_clean(&image).unwrap_or_else(|e| {
        panic!("debugfs left the image damaged, so this gate proves nothing:\n{e}")
    });

    // The scan must stay clean — under this profile that includes verifying the
    // foreign attribute block's checksum against its own bytes.
    let mut r = scan_clean(&image, "foreign xattrs and ACLs");

    // /etc/hostname carries both regions: the small value inline, the large one in
    // the attribute block.
    let (_, hostname) = r.lookup(b"/etc/hostname").expect("lookup /etc/hostname");
    assert_ne!(
        hostname.file_acl, 0,
        "the large value did not spill to an attribute block, so this case no longer \
         reads a foreign block at all"
    );
    let attrs = xattr_map(r.xattrs(&hostname).expect("xattrs of /etc/hostname"));
    assert_eq!(attrs[b"user.origin".as_slice()], b"ferrosys-foreign");
    assert_eq!(attrs[b"user.big".as_slice()], big);

    // /probe carries only the inline region — the foreign in-inode layout, isolated
    // from the block parser.
    let (_, probe) = r.lookup(b"/probe").expect("lookup /probe");
    assert_eq!(
        probe.file_acl, 0,
        "/probe's small attribute should fit in the inode; an attribute block here \
         means the inline case is no longer isolated"
    );
    let attrs = xattr_map(r.xattrs(&probe).expect("xattrs of /probe"));
    assert_eq!(attrs[b"user.small".as_slice()], b"probe-value");

    // A directory inode carries attributes the same way.
    let (_, etc) = r.lookup(b"/etc").expect("lookup /etc");
    let etc_attrs = xattr_map(r.xattrs(&etc).expect("xattrs of /etc"));
    assert_eq!(etc_attrs[b"user.dirattr".as_slice()], b"on-a-directory");

    // The ACLs come back as the on-disk encoding libext2fs's converter wrote. That
    // must be byte-for-byte what this crate's encoder produces for the same entries —
    // two implementations, one on-disk form — and must decode back to them.
    let (_, fstab) = r.lookup(b"/etc/fstab").expect("lookup /etc/fstab");
    let fstab_attrs = xattr_map(r.xattrs(&fstab).expect("xattrs of /etc/fstab"));
    let access = Acl::new(access_entries()).expect("a valid access ACL");
    let on_disk = &fstab_attrs[Acl::ACCESS_NAME];
    assert_eq!(
        *on_disk,
        access.encode(),
        "libext2fs and this crate disagree on the on-disk access-ACL encoding"
    );
    assert_eq!(
        Acl::decode(on_disk).expect("decode the foreign access ACL"),
        access
    );
    let default = Acl::new(default_entries()).expect("a valid default ACL");
    let on_disk = &etc_attrs[Acl::DEFAULT_NAME];
    assert_eq!(
        *on_disk,
        default.encode(),
        "libext2fs and this crate disagree on the on-disk default-ACL encoding"
    );
    assert_eq!(
        Acl::decode(on_disk).expect("decode the foreign default ACL"),
        default
    );
}

/// An attribute block shared between two inodes (`h_refcount > 1`).
///
/// A running kernel deduplicates identical attribute blocks, so a real filesystem can
/// hold one block referenced by two inodes — a layout this crate's writer never
/// produces, which is exactly why the reader must be proven on it. `debugfs` writes
/// the block for `/a`; the second reference is crafted: `/b`'s `i_file_acl` points at
/// the same block, `/b` is charged the block's sectors in `i_blocks`, and the block's
/// `h_refcount` becomes 2 — on the profile without `metadata_csum`, so no checksum
/// needs recomputing. `e2fsck` genuinely checks every field this crafting touches,
/// which is proven mid-flight: with the refcount still 1 it must refuse the image, and
/// only after the bump must it call the sharing clean.
#[test]
fn a_shared_xattr_block_reads_on_both_files() {
    if !available("mke2fs") || !available("e2fsck") || !available("debugfs") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir tree");
    std::fs::write(tree.join("a"), b"first\n").expect("write a");
    std::fs::write(tree.join("b"), b"second\n").expect("write b");

    let image = mke2fs(&NO_CSUM_EXT4, &tree, dir.path());
    let block_size = u64::from(NO_CSUM_EXT4.block_size);

    // Too large for the inode's attribute region, well within one block.
    let value: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
    let value_path = dir.path().join("val.bin");
    std::fs::write(&value_path, &value).expect("write value file");
    run_debugfs(
        &image,
        dir.path(),
        "ea.txt",
        &format!("ea_set -f {} /a user.shared\n", value_path.display()),
    );

    // Where the block landed, and /b's accounting before the second reference.
    let (ea_block, b_blocks) = {
        let file = std::fs::File::open(&image).expect("open");
        let mut r =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let (_, a) = r.lookup(b"/a").expect("lookup /a");
        assert_ne!(
            a.file_acl, 0,
            "the value did not spill to an attribute block, so there is nothing to share"
        );
        let (_, b) = r.lookup(b"/b").expect("lookup /b");
        (a.file_acl, b.blocks)
    };

    // The second reference: /b points at the same block and, as the kernel would, is
    // charged the block's 512-byte sectors in `i_blocks`. debugfs recomputes what
    // depends on the inode; the refcount is the block's own and comes below.
    run_debugfs(
        &image,
        dir.path(),
        "share.txt",
        &format!(
            "sif /b file_acl {ea_block}\nsif /b blocks {}\n",
            b_blocks + block_size / 512
        ),
    );

    // Two references against a refcount of 1 is an inconsistency, and e2fsck must say
    // so — the proof that its clean verdict below actually covers the fields this
    // crafting touched.
    assert!(
        e2fsck_clean(&image).is_err(),
        "e2fsck accepted two references against a refcount of 1, so its verdict \
         certifies nothing about this crafting"
    );

    // The refcount word sits at bytes 4..8 of the attribute-block header.
    let mut bytes = std::fs::read(&image).expect("read image");
    let base = (ea_block * block_size) as usize;
    assert_eq!(
        bytes[base..base + 4],
        0xEA02_0000u32.to_le_bytes(),
        "the pointer does not lead to an attribute block"
    );
    assert_eq!(
        u32::from_le_bytes(bytes[base + 4..base + 8].try_into().unwrap()),
        1,
        "the block is not in the single-reference state this crafting starts from"
    );
    bytes[base + 4..base + 8].copy_from_slice(&2u32.to_le_bytes());
    std::fs::write(&image, &bytes).expect("write back");

    e2fsck_clean(&image).unwrap_or_else(|e| {
        panic!("the shared attribute block is not valid, so this gate proves nothing:\n{e}")
    });

    // The reader agrees the sharing is healthy, and both files read the attribute.
    let mut r = scan_clean(&image, "a shared attribute block");
    let (_, a) = r.lookup(b"/a").expect("lookup /a");
    let (_, b) = r.lookup(b"/b").expect("lookup /b");
    assert_eq!(
        a.file_acl, b.file_acl,
        "the two files no longer share one attribute block"
    );
    for (path, inode) in [("/a", &a), ("/b", &b)] {
        let attrs = xattr_map(
            r.xattrs(inode)
                .unwrap_or_else(|e| panic!("xattrs of {path}: {e}")),
        );
        assert_eq!(
            attrs.get(b"user.shared".as_slice()),
            Some(&value),
            "{path} did not read the shared attribute back"
        );
    }
}

/// A feature word promises what the filesystem's structures look like, so an inode that
/// carries a structure the word denies makes the image self-contradictory — and every one
/// of these is something `e2fsck` faults.
///
/// The writer refuses to emit such a pair, which means an image carrying one always came
/// from somewhere else. That is what this gate builds: `mke2fs` writes a filesystem whose
/// feature words genuinely lack the feature, `debugfs` gives one inode the structure those
/// words deny, and then the two judges must agree — `e2fsck` faults the image, and the
/// scan reports the same disagreement rather than calling it clean.
#[test]
fn feature_incoherent_foreign_images_are_flagged() {
    if !available("mke2fs") || !available("e2fsck") || !available("debugfs") {
        return;
    }

    /// One incoherence: the feature to build without, the `debugfs` edit that introduces
    /// the structure that feature would have covered, and a phrase from the anomaly it
    /// must produce.
    struct Incoherence {
        what: &'static str,
        /// `-O` argument: the feature cleared, so the words really do lack it.
        without: &'static str,
        /// The `debugfs -R` request that gives an inode the denied structure.
        request: &'static str,
        /// A phrase the reported anomaly's detail carries.
        detail: &'static str,
        severity: Severity,
    }

    let cases = [
        Incoherence {
            what: "an attribute block on a filesystem without ext_attr",
            without: "^ext_attr",
            // Any block inside the filesystem: what makes this an incoherence is the
            // pointer existing at all, not where it points.
            request: "sif /etc/hostname file_acl 500",
            detail: "attribute block",
            severity: Severity::Structural,
        },
        Incoherence {
            what: "a 2 GiB regular file on a filesystem without large_file",
            without: "^large_file",
            request: "sif /etc/hostname size 0x80000000",
            detail: "regular file",
            severity: Severity::Conformance,
        },
        Incoherence {
            what: "a hash-indexed directory on a filesystem without dir_index",
            without: "^dir_index",
            request: "sif /etc flags 0x1000",
            detail: "hash-indexed",
            severity: Severity::Conformance,
        },
    ];

    for case in cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let tree = dir.path().join("tree");
        build_tree(&tree).expect("build source tree");
        // A 1024-byte block keeps `mke2fs` from reasserting `large_file` for its own
        // resize inode, so each of these filesystems really is written without the
        // feature the case is about.
        let case_fs = Case {
            what: case.what,
            fs_type: "ext2",
            block_size: 1024,
            inode_size: 256,
            features: case.without,
        };
        let image = mke2fs(&case_fs, &tree, dir.path());

        // The filesystem is sound before the edit, so what follows is the edit's doing.
        e2fsck_clean(&image)
            .unwrap_or_else(|e| panic!("{}: the image was already faulted:\n{e}", case.what));
        {
            let file = std::fs::File::open(&image).expect("open image");
            let mut reader =
                Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient))
                    .expect("open");
            assert!(
                reader.scan().is_clean(),
                "{}: the image was already anomalous",
                case.what
            );
        }

        run_debugfs(&image, dir.path(), "incoherence.txt", case.request);

        // `e2fsck` faults it, which is what makes this an incoherence rather than a
        // preference.
        assert!(
            e2fsck_clean(&image).is_err(),
            "{}: e2fsck accepts the edit, so there is nothing to flag",
            case.what
        );

        let file = std::fs::File::open(&image).expect("open image");
        let mut reader =
            Reader::open_with(file, &OpenOptions::new().policy(ReadPolicy::Lenient)).expect("open");
        let report = reader.scan();
        let found = report
            .anomalies()
            .iter()
            .find(|a| a.detail.contains(case.detail))
            .unwrap_or_else(|| {
                panic!(
                    "{}: the scan calls this image clean where e2fsck faults it:\n{}",
                    case.what,
                    report.to_table()
                )
            });
        assert_eq!(found.severity, case.severity, "{}", case.what);
        assert!(
            found.location.inode.is_some(),
            "{}: the anomaly names the inode it was found on",
            case.what
        );
    }
}
