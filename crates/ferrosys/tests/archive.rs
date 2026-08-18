//! End-to-end gate for the tar archive source: build a tar carrying the fidelity
//! list, parse it into a source, format an image, and confirm the image reads back
//! and (where `e2fsck` is present) checks clean.
//!
//! Runs only with the `tar` feature enabled.
#![cfg(all(feature = "tar", feature = "ext"))]

mod util;

use std::io::{self, Seek, Write};

use tar::{Builder, EntryType, Header};

use ferrosys::ext::Timestamp;
use ferrosys::ext::{
    EntryKind, FileContent, FormatOptions, GrowReservation, Reader, Source, format,
};
use ferrosys::{Acl, AclQualifier, ArchiveError, ArchiveSource};
use util::{available, e2fsck_clean};

const MIB: u64 = 1024 * 1024;
const FAKE: u64 = 1_700_000_000;

fn opts() -> FormatOptions {
    let mut o = FormatOptions::new([0x22; 16], Timestamp::from_secs(FAKE as i64), [0u8; 16]);
    o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
    o
}

/// The image's tree as a path-to-inode map, for the assertions that ask what is at a
/// path rather than which paths share an inode.
fn walk_tree<R: io::Read + io::Seek>(
    r: &mut Reader<R>,
) -> std::collections::BTreeMap<Vec<u8>, ferrosys::ext::ondisk::Inode> {
    r.walk()
        .unwrap()
        .into_iter()
        .map(|e| (e.path, e.inode))
        .collect()
}

/// A directory header at the fixed test time.
fn dir_header(path: &str, mode: u32) -> Header {
    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Directory);
    h.set_mode(mode);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(FAKE);
    h.set_size(0);
    h.set_path(path).unwrap();
    h.set_cksum();
    h
}

/// A regular-file header sized to its data.
fn file_header(mode: u32, uid: u64, gid: u64, len: usize) -> Header {
    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Regular);
    h.set_mode(mode);
    h.set_uid(uid);
    h.set_gid(gid);
    h.set_mtime(FAKE);
    h.set_size(len as u64);
    h
}

/// Build a tar archive exercising files, directories, symlinks, a hard link, a
/// device node, a PAX xattr, and a PAX ACL.
fn build_archive() -> Vec<u8> {
    let mut b = Builder::new(Vec::new());

    for dir in ["etc/", "bin/", "dev/"] {
        b.append(&dir_header(dir, 0o755), io::empty()).unwrap();
    }

    // A regular file with distinct atime/ctime via PAX, owned by a non-root user.
    b.append_pax_extensions([("atime", &b"1600000000"[..]), ("ctime", &b"1650000000"[..])])
        .unwrap();
    let data = b"ferrosys\n";
    let mut h = file_header(0o644, 1000, 1000, data.len());
    h.set_path("etc/hostname").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();

    // A symlink.
    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Symlink);
    h.set_mode(0o777);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(FAKE);
    h.set_size(0);
    b.append_link(&mut h, "etc/mtab", "/proc/self/mounts")
        .unwrap();

    // A file carrying a capability xattr via PAX, then a hard link to it.
    let cap = vec![
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    b.append_pax_extensions([("SCHILY.xattr.security.capability", &cap[..])])
        .unwrap();
    let sh = vec![0x7f; 4096];
    let mut h = file_header(0o755, 0, 0, sh.len());
    h.set_path("bin/sh").unwrap();
    h.set_cksum();
    b.append(&h, &sh[..]).unwrap();

    // A file carrying an access ACL translated from a SCHILY.acl.access record.
    b.append_pax_extensions([(
        "SCHILY.acl.access",
        &b"u::rwx,u:1000:rw-,g::r-x,m::rwx,o::r--"[..],
    )])
    .unwrap();
    let passwd = b"root:x:0:0:root:/root:/bin/sh\n";
    let mut h = file_header(0o644, 0, 0, passwd.len());
    h.set_path("etc/passwd").unwrap();
    h.set_cksum();
    b.append(&h, &passwd[..]).unwrap();

    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Link);
    h.set_mode(0o755);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(FAKE);
    h.set_size(0);
    b.append_link(&mut h, "bin/dash", "bin/sh").unwrap();

    // A char device node.
    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Char);
    h.set_mode(0o666);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(FAKE);
    h.set_size(0);
    h.set_device_major(1).unwrap();
    h.set_device_minor(3).unwrap();
    h.set_path("dev/null").unwrap();
    h.set_cksum();
    b.append(&h, io::empty()).unwrap();

    b.into_inner().unwrap()
}

#[test]
fn archive_source_round_trips_and_checks_clean() {
    let tar_bytes = build_archive();
    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");

    // Read the image back and confirm the fidelity survived.
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);

    let hostname = &tree[&b"/etc/hostname".to_vec()];
    assert_eq!(r.read_data(hostname).unwrap(), b"ferrosys\n");
    assert_eq!(hostname.uid, 1000);
    assert_eq!(hostname.atime, Timestamp::from_secs(1_600_000_000));
    assert_eq!(hostname.ctime, Timestamp::from_secs(1_650_000_000));

    let mtab = &tree[&b"/etc/mtab".to_vec()];
    assert_eq!(r.read_symlink(mtab).unwrap(), b"/proc/self/mounts");

    // The hard link shares /bin/sh's inode. Identity is proven by the inode *number*
    // the two directory entries name — two distinct inodes with equal fields would
    // pass any field comparison — and the link count counts both names.
    let sh = &tree[&b"/bin/sh".to_vec()];
    let (sh_no, _) = r.lookup(b"/bin/sh").unwrap();
    let (dash_no, _) = r.lookup(b"/bin/dash").unwrap();
    assert_eq!(sh_no, dash_no, "/bin/dash is not /bin/sh");
    assert_eq!(sh.links_count, 2);
    let xattrs = r.xattrs(sh).unwrap();
    assert!(
        xattrs.iter().any(|x| x.name == b"security.capability"),
        "capability xattr lost: {xattrs:?}"
    );

    // The ACL translated from the SCHILY.acl.access text record.
    let passwd = &tree[&b"/etc/passwd".to_vec()];
    let acl_value = r
        .xattrs(passwd)
        .unwrap()
        .into_iter()
        .find(|x| x.name == Acl::ACCESS_NAME)
        .expect("access ACL present")
        .value;
    let acl = Acl::decode(&acl_value).expect("valid ACL");
    assert!(
        acl.entries()
            .iter()
            .any(|e| e.who == AclQualifier::User(1000))
    );

    // The device node.
    let null = &tree[&b"/dev/null".to_vec()];
    assert_eq!(null.mode & 0o170000, 0o020000);
    assert_eq!(r.device(null), (1, 3));

    // e2fsck is the authority when it is available, and its absence is loud, not silent.
    if available("e2fsck") {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(image.as_bytes()).unwrap();
        f.flush().unwrap();
        e2fsck_clean(f.path()).expect("archive-built image checks clean");
    }
}

#[test]
fn opening_an_archive_by_path_writes_the_same_image_as_reading_it_whole() {
    // The lazy path is a memory profile, not a different filesystem. Every member's
    // contents are read at placement instead of at parse, and the bytes that reach the
    // image must be identical — a difference here is silently wrong image data, which is
    // the worst failure this project has.
    let tar_bytes = build_archive();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&tar_bytes).unwrap();
    file.flush().unwrap();

    let eager = format(
        ArchiveSource::from_reader(&tar_bytes[..]).expect("parse whole"),
        64 * MIB,
        opts(),
    )
    .expect("format from a read archive");
    let lazy = format(
        ArchiveSource::from_path(file.path()).expect("parse by path"),
        64 * MIB,
        opts(),
    )
    .expect("format from an archive left on disk");

    assert_eq!(
        eager.as_bytes(),
        lazy.as_bytes(),
        "an archive read whole and one left on disk wrote different images"
    );
}

#[test]
fn an_archive_opened_by_path_leaves_its_file_contents_on_disk() {
    // The type change alone buys nothing: the win only arrives if the source actually
    // hands back handles. This is what checks that it does — and that a directory, which
    // has no contents, is unaffected.
    let tar_bytes = build_archive();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&tar_bytes).unwrap();
    file.flush().unwrap();

    let entries = ArchiveSource::from_path(file.path())
        .expect("parse by path")
        .into_entries();
    let hostname = entries
        .iter()
        .find(|e| e.path == b"/etc/hostname")
        .expect("the archive holds /etc/hostname");
    let EntryKind::File(content) = &hostname.kind else {
        panic!("/etc/hostname is not a file: {:?}", hostname.kind);
    };
    assert!(
        matches!(content, FileContent::Range(_)),
        "an archive opened by path held a file's bytes in memory: {content:?}"
    );
    // The length is known without reading, which is what the model's size check needs.
    assert_eq!(content.len(), b"ferrosys\n".len() as u64);
    assert_eq!(
        content.read().expect("read the range").as_ref(),
        b"ferrosys\n"
    );

    // Read whole, the same member's contents are owned.
    let owned = ArchiveSource::from_reader(&tar_bytes[..])
        .expect("parse whole")
        .into_entries();
    let hostname = owned
        .iter()
        .find(|e| e.path == b"/etc/hostname")
        .expect("the archive holds /etc/hostname");
    assert!(matches!(
        &hostname.kind,
        EntryKind::File(FileContent::Owned(_))
    ));
}

#[test]
fn owned_and_located_contents_coexist_in_one_entry_list() {
    // A caller that rewrites one file of a tree it is otherwise passing through replaces
    // that entry's contents with bytes it computed, while every other entry stays backed
    // by the archive. Both provenances must survive in the same list.
    let tar_bytes = build_archive();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&tar_bytes).unwrap();
    file.flush().unwrap();

    let mut entries = ArchiveSource::from_path(file.path())
        .expect("parse by path")
        .into_entries();
    for entry in &mut entries {
        if entry.path == b"/etc/hostname" {
            entry.kind = EntryKind::File(FileContent::Owned(b"spliced\n".to_vec()));
        }
    }
    assert!(
        entries
            .iter()
            .any(|e| matches!(&e.kind, EntryKind::File(FileContent::Range(_)))),
        "the splice replaced every located entry, not just the one"
    );

    let image = format(Spliced(entries), 64 * MIB, opts()).expect("format a mixed list");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let (_, hostname) = r.lookup(b"/etc/hostname").expect("lookup /etc/hostname");
    assert_eq!(r.read_data(&hostname).unwrap(), b"spliced\n");
    // And an archive-backed neighbour still came through its handle.
    let (_, passwd) = r.lookup(b"/etc/passwd").expect("lookup /etc/passwd");
    assert_eq!(
        r.read_data(&passwd).unwrap(),
        b"root:x:0:0:root:/root:/bin/sh\n"
    );
}

/// A source over an entry list a caller has already edited — the shape a consumer that
/// filters, sorts, or splices between parsing and formatting ends up with.
struct Spliced(Vec<ferrosys::ext::SourceEntry>);

impl Source for Spliced {
    fn into_entries(self) -> Vec<ferrosys::ext::SourceEntry> {
        self.0
    }
}

#[test]
fn a_pax_global_header_is_skipped_not_rejected() {
    // Every `git archive` tarball begins with a `pax_global_header`. It must be skipped
    // so the real members parse, not rejected as an unsupported type.
    let mut b = Builder::new(Vec::new());
    let record = b"52 comment=63985a6d5aef6b0d6f0e6f0e6f0e6f0e6f0e6f0e\n";
    let mut gh = Header::new_gnu();
    gh.set_entry_type(EntryType::XGlobalHeader);
    gh.set_mode(0o644);
    gh.set_size(record.len() as u64);
    gh.set_path("pax_global_header").unwrap();
    gh.set_cksum();
    b.append(&gh, &record[..]).unwrap();

    b.append(&dir_header("etc/", 0o755), io::empty()).unwrap();
    let data = b"ferrosys\n";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("etc/hostname").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("global header skipped");
    // The two real members parsed; the global header held only `comment`, which this parser
    // reads off no member either, so passing it over changes nothing.
    assert_eq!(source.len(), 2);
}

#[test]
fn a_pax_global_header_that_would_change_a_member_is_refused_rather_than_dropped() {
    // A `g` header carries defaults for every member after it. This parser resolves
    // per-member records only, so an archive expressing ownership, times, or attributes
    // *only* as a global default would convert to a filesystem that does not carry them —
    // silently, and with the fidelity report saying nothing was lost.
    //
    // So a default that would have changed a member is a refusal. A key this parser ignores
    // per-member is ignored globally to exactly the same effect, and passes: every
    // `git archive` tarball opens with a `g` header, and refusing those would refuse most
    // archives in the world over a `comment` nobody reads.
    for record in [
        &b"11 uid=1000\n"[..],
        b"15 mtime=1700000\n",
        b"36 SCHILY.xattr.user.origin=global\n",
    ] {
        let mut b = Builder::new(Vec::new());
        let mut gh = Header::new_gnu();
        gh.set_entry_type(EntryType::XGlobalHeader);
        gh.set_mode(0o644);
        gh.set_size(record.len() as u64);
        gh.set_path("pax_global_header").unwrap();
        gh.set_cksum();
        b.append(&gh, record).unwrap();
        b.append(&dir_header("etc/", 0o755), io::empty()).unwrap();
        let tar_bytes = b.into_inner().unwrap();

        // `ArchiveSource` holds a whole entry list and is deliberately not `Debug`, which
        // `expect_err` would want.
        match ArchiveSource::from_reader(&tar_bytes[..]) {
            Err(ArchiveError::Malformed { .. }) => {}
            Err(other) => panic!("{record:?}: expected Malformed, got {other:?}"),
            Ok(_) => panic!("{record:?}: a consequential global default was passed over"),
        }
    }
}

#[test]
fn a_gnu_volume_label_is_skipped_not_rejected() {
    // `tar --label=NAME` writes a `V` member whose name field holds the label. It
    // names the archive itself, not a file in it, so it must be passed over the way
    // every extractor passes it over — with the members after it still parsing.
    let mut b = Builder::new(Vec::new());
    let mut label = Header::new_gnu();
    label.set_entry_type(EntryType::new(b'V'));
    label.set_mode(0o644);
    label.set_size(0);
    label.set_path("backup-2026-07-20").unwrap();
    label.set_cksum();
    b.append(&label, io::empty()).unwrap();

    b.append(&dir_header("etc/", 0o755), io::empty()).unwrap();
    let data = b"ferrosys\n";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("etc/hostname").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("volume label skipped");
    // The two real members parsed; the label contributed no entry.
    assert_eq!(source.len(), 2);
}

#[test]
fn a_libarchive_xattr_with_a_schily_twin_is_accepted_and_deduplicated() {
    // bsdtar writes each attribute twice: a SCHILY.xattr record with the raw value and a
    // LIBARCHIVE.xattr record with a base64 one. The SCHILY value is authoritative, so an
    // archive carrying both parses and the attribute survives once, rather than being
    // refused outright for carrying the LIBARCHIVE duplicate at all.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([
        ("SCHILY.xattr.user.foo", &b"bar"[..]),
        ("LIBARCHIVE.xattr.user.foo", &b"YmFy"[..]), // "bar" in base64
    ])
    .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..])
        .expect("an archive carrying both SCHILY and LIBARCHIVE xattrs parses");
    let image = format(source, 16 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    let f = &tree[&b"/f".to_vec()];
    let foo: Vec<_> = r
        .xattrs(f)
        .unwrap()
        .into_iter()
        .filter(|x| x.name == b"user.foo")
        .collect();
    assert_eq!(foo.len(), 1, "the attribute survives exactly once: {foo:?}");
    assert_eq!(
        foo[0].value, b"bar",
        "from the SCHILY record, not the base64 one"
    );
}

#[test]
fn a_repeated_xattr_name_keeps_the_last_value_and_appears_once() {
    // Two records for one name are the archive contradicting itself, and the resolution
    // is the same one every PAX field takes: a later record replaces an earlier one. The
    // attribute reaches the filesystem once, holding the later value.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([
        ("SCHILY.xattr.user.note", &b"first"[..]),
        ("SCHILY.xattr.user.note", &b"second"[..]),
    ])
    .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("a repeated name parses");
    let image = format(source, 16 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    let note: Vec<_> = r
        .xattrs(&tree[&b"/f".to_vec()])
        .unwrap()
        .into_iter()
        .filter(|x| x.name == b"user.note")
        .collect();
    assert_eq!(note.len(), 1, "the name survives exactly once: {note:?}");
    assert_eq!(note[0].value, b"second", "the later record wins");
}

#[test]
fn a_lone_libarchive_xattr_is_refused() {
    // A LIBARCHIVE.xattr record with no SCHILY twin carries its value only in base64,
    // which this crate does not decode; refusing it is better than silently losing it.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("LIBARCHIVE.xattr.user.only", &b"dg=="[..])]) // "v" in base64
        .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a lone LIBARCHIVE.xattr record must be refused, not silently dropped"
    );
}

#[test]
fn a_uid_past_thirty_two_bits_is_a_typed_error() {
    // ext4 stores 32-bit ids; a larger tar uid must be refused, not truncated (2^32
    // would become root).
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    let mut h = file_header(0o644, 1u64 << 32, 0, data.len());
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a uid past 2^32 must be rejected"
    );
}

#[test]
fn a_gid_past_thirty_two_bits_is_a_typed_error() {
    // The gid twin of the uid guard above: the same 32-bit field width, the same
    // silent-truncation hazard (2^32 would become the root group).
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    let mut h = file_header(0o644, 0, 1u64 << 32, data.len());
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a gid past 2^32 must be rejected"
    );
}

#[test]
fn a_pax_mtime_past_the_signed_range_is_a_typed_error() {
    // The PAX-record path of the header-mtime guard below: a `mtime=` record whose
    // seconds do not fit an `i64` must be a typed refusal, not a saturated or wrapped
    // time. The record *refines* the header, so a sane header mtime must not paper
    // over a malformed record.
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    b.append_pax_extensions([("mtime", &b"9223372036854775808"[..])])
        .unwrap();
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_mtime(FAKE);
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a PAX mtime past i64::MAX must be rejected, not folded into range"
    );
}

#[test]
fn a_header_mtime_past_the_signed_range_is_a_typed_error() {
    // ext4 stores a signed second count; a GNU base-256 header mtime past `i64::MAX`
    // must be refused, not truncated. A wrapping cast would reassign a far-future time
    // to a 1901-1969 date, the same silent corruption the uid/gid guard prevents. This
    // is the header-fallback path: no PAX `mtime` record refines it.
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    // Past `i64::MAX` (9223372036854775807); tar-rs encodes it in the base-256 form.
    h.set_mtime((1u64 << 63) + 5);
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a header mtime past i64::MAX must be rejected, not wrapped"
    );
}

#[test]
fn the_archive_root_supplies_the_filesystem_roots_metadata() {
    // `mke2fs -d` gives the filesystem root the source root's metadata, and so does
    // this: the `./` member describes inode 2 rather than being skipped, and it consumes
    // no inode number of its own.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("SCHILY.xattr.user.label", &b"rootfs"[..])])
        .unwrap();
    let mut root = dir_header("./", 0o700);
    root.set_uid(1000);
    root.set_gid(2000);
    root.set_cksum();
    b.append(&root, io::empty()).unwrap();
    b.append(&dir_header("etc/", 0o755), io::empty()).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    assert_eq!(source.len(), 2, "the root member is an entry, not a skip");
    let image = format(source, 64 * MIB, opts()).expect("format");

    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let root = r.inode(2).expect("root inode");
    assert_eq!(root.mode & 0o7777, 0o700, "root took the archive's mode");
    assert_eq!((root.uid, root.gid), (1000, 2000));
    let xattrs = r.xattrs(&root).expect("root xattrs");
    assert!(
        xattrs
            .iter()
            .any(|x| x.name == b"user.label" && x.value == b"rootfs"),
        "the root member's xattr is lost: {xattrs:?}"
    );
    // The archive's other member is unaffected: the root entry describes the root, it
    // does not stand in for anything below it.
    let tree = walk_tree(&mut r);
    assert_eq!(tree[&b"/etc".to_vec()].mode & 0o7777, 0o755);

    if available("e2fsck") {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(image.as_bytes()).unwrap();
        f.flush().unwrap();
        e2fsck_clean(f.path()).expect("a root-metadata image checks clean");
    }
}

#[test]
fn a_binary_posix_acl_xattr_is_translated_to_ext4s_form() {
    // An archiver that copies `getxattr`'s bytes stores the version-2 ACL form. ext4
    // stores the compact version-1 form, so the value must be translated, never written
    // through: the kernel would misparse the version-2 bytes.
    let v2: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, // a_version = 2
        0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
        0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw-
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
        0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
        0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
    ];
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("SCHILY.xattr.system.posix_acl_access", &v2[..])])
        .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");

    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    let value = r
        .xattrs(&tree[&b"/f".to_vec()])
        .unwrap()
        .into_iter()
        .find(|x| x.name == Acl::ACCESS_NAME)
        .expect("access ACL present")
        .value;
    // The value read back is the one the archive stated, whatever ext packed it into.
    assert_eq!(
        value, v2,
        "the ACL survives the round trip as the ACL it was"
    );
    let acl = Acl::decode(&value).expect("the boundary form");
    assert!(
        acl.entries()
            .iter()
            .any(|e| e.who == AclQualifier::User(1000))
    );
}

#[test]
fn a_default_acl_on_a_non_directory_is_rejected() {
    // A default ACL is inherited by a directory's children, so only a directory carries
    // one; on a file it is a state no kernel produces.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("SCHILY.acl.default", &b"u::rwx,g::r-x,o::r--"[..])])
        .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    assert!(
        ArchiveSource::from_reader(&tar_bytes[..]).is_err(),
        "a default ACL on a file must be rejected"
    );
}

#[test]
fn a_pax_uid_gid_record_supplies_ownership() {
    // A posix-format archive can carry the authoritative id in a PAX `uid`/`gid` record.
    // Ownership is taken from the record, so the id the archive states is the id the image
    // stores, whether or not the tar layer also folded it into the header field.
    let mut b = Builder::new(Vec::new());
    b.append(&dir_header("etc/", 0o755), io::empty()).unwrap();
    b.append_pax_extensions([("uid", &b"500000"[..]), ("gid", &b"600000"[..])])
        .unwrap();
    let data = b"x";
    // The header states a different, smaller id; the PAX record is the one that must win.
    let mut h = file_header(0o644, 1, 2, data.len());
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    let f = &tree[&b"/etc/f".to_vec()];
    assert_eq!(f.uid, 500_000, "the PAX uid record supplies ownership");
    assert_eq!(f.gid, 600_000, "the PAX gid record supplies ownership");
}

#[test]
fn a_pax_uid_past_thirty_two_bits_is_a_typed_error() {
    // ext4 stores 32-bit ids; a PAX record past that must be refused, not truncated, the
    // same guard the header path applies.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("uid", &b"4294967296"[..])]) // 2^32
        .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("etc/f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let err = match ArchiveSource::from_reader(&tar_bytes[..]) {
        Ok(_) => panic!("a PAX uid past 2^32 must be rejected"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ArchiveError::Bad { reason, .. } if reason.contains("uid")),
        "expected a uid range error, got {err:?}"
    );
}

#[test]
fn an_old_gnu_sparse_entry_is_rejected_before_its_body_is_read() {
    // Old-GNU sparse ('S') declares a logical size apart from the bytes it stores: the
    // GNU header's real_size and a hole map. Reading its body would expand the holes to
    // zeros and materialize the full logical size, so this 1 KiB archive — 512 physical
    // bytes, one 512-byte block at the very end of a declared 2 GiB file — would force a
    // ~2 GiB allocation. The fix refuses it by type, before its body is read, so the
    // declared size costs nothing.
    const BLOCK: u64 = 512;
    const REAL: u64 = 2 * 1024 * 1024 * 1024;

    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::GNUSparse);
    h.set_mode(0o644);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(FAKE);
    // The header size is the *physical* bytes stored: one block. The logical size and the
    // fragment map live in the GNU header, and tar-rs parses both while iterating, so a
    // consistent map is what makes the entry reach the source at all (an inconsistent one
    // is tar-rs's own error, not the source's).
    h.set_size(BLOCK);
    h.set_path("sparsefile").unwrap();
    {
        let gnu = h
            .as_gnu_mut()
            .expect("a gnu header carries the sparse fields");
        gnu.set_real_size(REAL);
        // One data fragment: the last block of the logical file. Everything before it is a
        // hole, expanded to zeros on read.
        gnu.sparse[0].set_offset(REAL - BLOCK);
        gnu.sparse[0].set_length(BLOCK);
    }
    h.set_cksum();

    let mut b = Builder::new(Vec::new());
    b.append(&h, &[0x7f; BLOCK as usize][..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let err = match ArchiveSource::from_reader(&tar_bytes[..]) {
        Ok(_) => panic!("old-GNU sparse must be rejected, not parsed"),
        Err(e) => e,
    };
    assert!(
        matches!(err, ArchiveError::Bad { reason, .. } if reason.contains("sparse")),
        "old-GNU sparse must be a typed sparse rejection, got {err:?}"
    );
}

#[test]
fn a_pax_value_containing_a_newline_is_read_intact() {
    // A PAX record is delimited by its length prefix, not by its newline, so a value
    // may carry any byte. A binary POSIX ACL naming user or group 10 does exactly
    // that: 10 is `0A 00 00 00` little-endian, and the leading byte is a newline.
    // Splitting the header body on newlines cuts this record in half and takes every
    // record after it with it, so the whole archive is refused.
    let v2: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, // a_version = 2
        0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
        0x02, 0x00, 0x06, 0x00, 0x0a, 0x00, 0x00, 0x00, // USER 10 rw- (value holds 0x0A)
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
        0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
        0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
    ];
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([
        ("SCHILY.xattr.system.posix_acl_access", &v2[..]),
        // A record after the newline-bearing one: it must survive too.
        ("SCHILY.xattr.user.note", &b"after"[..]),
    ])
    .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..])
        .expect("a PAX value carrying a newline must parse");
    let image = format(source, 64 * MIB, opts()).expect("format");

    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    let xattrs = r.xattrs(&tree[&b"/f".to_vec()]).unwrap();
    let acl = xattrs
        .iter()
        .find(|x| x.name == Acl::ACCESS_NAME)
        .expect("access ACL present");
    let acl = Acl::decode(&acl.value).expect("the boundary form");
    assert!(
        acl.entries()
            .iter()
            .any(|e| e.who == AclQualifier::User(10)),
        "the ACL naming user 10 was lost with the newline"
    );
    let note = xattrs
        .iter()
        .find(|x| x.name == b"user.note")
        .expect("the record following the newline-bearing one survived");
    assert_eq!(note.value, b"after");
}

#[test]
fn a_pax_path_record_names_the_member() {
    // A `path` record overrides the header's name field, which caps at 100 bytes.
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("path", &b"renamed"[..])])
        .unwrap();
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("shortname").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    assert!(tree.contains_key(b"/renamed".as_slice()));
    assert!(!tree.contains_key(b"/shortname".as_slice()));
}

#[test]
fn a_gnu_long_name_names_the_member() {
    // A path past the header's 100-byte name field is carried in an `L` member that
    // precedes it, which the framing must consume and attach rather than yield.
    let long = "l".repeat(150);
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_cksum();
    b.append_data(&mut h, &long, &data[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    assert!(tree.contains_key(&format!("/{long}").into_bytes()));
}

#[test]
fn a_pax_size_record_frames_the_member() {
    // A `size` record overrides the header's octal size field, which caps at 8 GiB.
    // Framing from the header's value would start the next member at the wrong
    // offset, so the record has to drive the walk, not just the reported size.
    let data = b"contents!";
    let mut b = Builder::new(Vec::new());
    b.append_pax_extensions([("size", data.len().to_string().as_bytes())])
        .unwrap();
    // The header field disagrees: only the record is right.
    let mut h = file_header(0o644, 0, 0, 0);
    h.set_path("first").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let mut h = file_header(0o644, 0, 0, 1);
    h.set_path("second").unwrap();
    h.set_cksum();
    b.append(&h, &b"y"[..]).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let source = ArchiveSource::from_reader(&tar_bytes[..]).expect("parse archive");
    let image = format(source, 64 * MIB, opts()).expect("format");
    let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
    let tree = walk_tree(&mut r);
    // The second member framed correctly, and the first carries its whole body.
    assert!(tree.contains_key(b"/second".as_slice()));
    assert_eq!(r.read_data(&tree[&b"/first".to_vec()]).unwrap(), data);
}

#[test]
fn a_corrupted_header_block_is_refused() {
    // The header checksum is the archive's own integrity check. A block that fails it
    // is not a member whose fields can be trusted, so the archive is refused rather
    // than parsed from garbage.
    let mut b = Builder::new(Vec::new());
    let data = b"x";
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let mut tar_bytes = b.into_inner().unwrap();
    // Flip a byte in the mode field, which the checksum covers.
    tar_bytes[102] ^= 0x01;

    let err = match ArchiveSource::from_reader(&tar_bytes[..]) {
        Ok(_) => panic!("a header failing its checksum must be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, ArchiveError::Malformed { .. }), "{err:?}");
}

#[test]
fn a_truncated_archive_is_refused() {
    // A body the stream cannot back is a truncation, not a short file: reading it as
    // one would silently store fewer bytes than the header declares.
    let mut b = Builder::new(Vec::new());
    let data = vec![b'z'; 2048];
    let mut h = file_header(0o644, 0, 0, data.len());
    h.set_path("f").unwrap();
    h.set_cksum();
    b.append(&h, &data[..]).unwrap();
    let mut tar_bytes = b.into_inner().unwrap();
    tar_bytes.truncate(1024);

    let err = match ArchiveSource::from_reader(&tar_bytes[..]) {
        Ok(_) => panic!("a truncated archive must be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, ArchiveError::Malformed { .. }), "{err:?}");
}

#[test]
fn a_compressed_archive_is_named_by_its_format() {
    // Every real rootfs archive arrives compressed, so handing one to a tar parser is the
    // commonest mistake there is — and the parser's own vocabulary has nothing useful to say
    // about it, since the fault is not in tar framing the caller never wrote. Each format
    // announces itself in its first bytes, and naming it is the difference between a message
    // that leads somewhere and one that does not.
    //
    // Both a stream long enough to fill a block (where the header checksum fails) and one
    // too short to (where the framing runs out) reach it, since a compressed archive can be
    // either.
    let cases: [(&[u8], &str); 6] = [
        (&[0x1f, 0x8b, 0x08, 0x00], "gzip"),
        (&[0x28, 0xb5, 0x2f, 0xfd, 0x00], "zstd"),
        (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "xz"),
        (b"BZh9", "bzip2"),
        (&[0x04, 0x22, 0x4d, 0x18], "lz4"),
        (&[0x1f, 0x9d, 0x90], "compress"),
    ];
    let mut file = tempfile::NamedTempFile::new().unwrap();
    for (magic, format) in cases {
        for len in [magic.len(), 4096] {
            let mut bytes = magic.to_vec();
            bytes.resize(len.max(magic.len()), 0x5a);
            let err = ArchiveSource::from_reader(&bytes[..])
                .err()
                .unwrap_or_else(|| panic!("{format} at {len} bytes must be refused"));
            assert!(
                matches!(err, ArchiveError::Compressed { format: f, .. } if f == format),
                "{format} at {len} bytes: {err:?}"
            );
            // The message is the whole of what a caller sees, so it has to carry the name.
            assert!(err.to_string().contains(format), "{err}");

            // The seeking parser reads the same head and must agree: a caller choosing
            // `from_path` for its memory behaviour does not thereby get a worse diagnosis.
            file.as_file().set_len(0).unwrap();
            file.as_file_mut().rewind().unwrap();
            file.write_all(&bytes).unwrap();
            file.flush().unwrap();
            let err = ArchiveSource::from_path(file.path())
                .err()
                .unwrap_or_else(|| panic!("{format} at {len} bytes must be refused by path"));
            assert!(
                matches!(err, ArchiveError::Compressed { format: f, .. } if f == format),
                "{format} at {len} bytes by path: {err:?}"
            );
        }
    }

    // And a valid archive whose first member's name begins with one of those bytes is not
    // mislabelled: the magic is consulted only where a block has already failed to be a tar
    // block. `]` opens the lzma magic, which is the weakest of them.
    let mut b = Builder::new(Vec::new());
    let mut h = file_header(0o644, 0, 0, 1);
    h.set_path("]").unwrap();
    h.set_cksum();
    b.append(&h, &b"x"[..]).unwrap();
    let source = ArchiveSource::from_reader(&b.into_inner().unwrap()[..])
        .expect("a member named `]` is a member, not an lzma stream");
    assert_eq!(source.len(), 1);
}

#[test]
fn a_declared_size_no_offset_can_hold_is_refused_by_both_parsers() {
    // A PAX `size` record carries a full `u64`, and the seeking parser turns one into an
    // offset: the body's start plus its length rounded up to a whole block. Near the top
    // of the range that round-up is not representable, and computing it with wrapping
    // arithmetic would name a zero-length padded body — which passes the bound that
    // exists to reject exactly this member and hands back a range of `u64::MAX` bytes.
    // Both parsers must refuse it, by whichever route each frames the stream.
    let mut b = Builder::new(Vec::new());
    let mut h = file_header(0o644, 0, 0, 0);
    h.set_path("big").unwrap();
    h.set_cksum();
    b.append_pax_extensions([("size", u64::MAX.to_string().as_bytes())])
        .unwrap();
    b.append(&h, io::empty()).unwrap();
    let tar_bytes = b.into_inner().unwrap();

    // `ArchiveSource` is not `Debug`, so each `Result` is matched rather than unwrapped.
    let err = match ArchiveSource::from_reader(&tar_bytes[..]) {
        Ok(_) => panic!("a size no offset can hold must be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, ArchiveError::Malformed { .. }), "{err:?}");

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&tar_bytes).unwrap();
    file.flush().unwrap();
    let err = match ArchiveSource::from_path(file.path()) {
        Ok(_) => panic!("a size no offset can hold must be refused by path too"),
        Err(e) => e,
    };
    assert!(matches!(err, ArchiveError::Malformed { .. }), "{err:?}");
}

#[test]
fn an_archive_truncated_under_the_format_names_itself_in_the_error() {
    // The documented hazard of parsing by path: the archive is checked to hold every
    // body at parse time, but an in-place truncation between then and placement reaches
    // the format. It surfaces as an I/O error, and `FormatError::Io` is transparent — so
    // the message the `FileRange` builds is the whole of what a person sees, and it has
    // to say which archive changed and which bytes were lost.
    let tar_bytes = build_archive();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&tar_bytes).unwrap();
    file.flush().unwrap();

    let source = ArchiveSource::from_path(file.path()).expect("parse by path");
    // The same inode the source's handles hold open, cut to nothing.
    file.as_file().set_len(0).unwrap();

    let err = match format(source, 64 * MIB, opts()) {
        Ok(_) => panic!("a truncated archive must not format silently"),
        Err(e) => e,
    };
    let text = err.to_string();
    let name = file.path().file_name().unwrap().to_string_lossy();
    assert!(text.contains(name.as_ref()), "{text}");
    assert!(text.contains("offset"), "{text}");
}

#[test]
fn a_mangled_archive_never_panics() {
    // The never-panic contract for the input this crate does not produce: every mangled
    // archive is a returned error or a parse that yields entries, never a crash. A
    // deterministic smoke test over truncations, byte flips, and spliced-in sizes; the
    // cargo-fuzz `archive_parse` target in fuzz/ is the exhaustive version.
    let base = build_archive();

    let mut cases: Vec<Vec<u8>> = Vec::new();
    // Truncations at every block boundary and one byte off each.
    for cut in (0..base.len()).step_by(512) {
        cases.push(base[..cut].to_vec());
        cases.push(base[..cut + 1].to_vec());
    }
    // A flipped bit in each of the first few blocks: header fields, checksums, and a
    // body byte, so the framing is driven from a header it cannot trust.
    for byte in (0..base.len().min(4096)).step_by(37) {
        let mut m = base.clone();
        m[byte] ^= 0xff;
        cases.push(m);
    }
    // Sizes a member cannot be framed from, declared through PAX. Each is spliced into a
    // fresh archive so the header checksum stays valid and the record is what is tested.
    for size in [u64::MAX, u64::MAX - 511, u64::MAX / 2, 0, 1] {
        let mut b = Builder::new(Vec::new());
        b.append_pax_extensions([("size", size.to_string().as_bytes())])
            .unwrap();
        let mut h = file_header(0o644, 0, 0, 0);
        h.set_path("m").unwrap();
        h.set_cksum();
        b.append(&h, io::empty()).unwrap();
        cases.push(b.into_inner().unwrap());
    }
    // Not a tar at all.
    cases.push(vec![0xff; 4096]);
    cases.push(Vec::new());

    let mut file = tempfile::NamedTempFile::new().unwrap();
    for case in &cases {
        // Whatever each parser returns, neither may panic and neither may allocate from
        // a length the archive merely claims.
        if let Ok(source) = ArchiveSource::from_reader(&case[..]) {
            let _ = source.len();
        }
        file.as_file().set_len(0).unwrap();
        file.as_file_mut().rewind().unwrap();
        file.write_all(case).unwrap();
        file.flush().unwrap();
        if let Ok(source) = ArchiveSource::from_path(file.path()) {
            for entry in source.into_entries() {
                // Reading a located body is what turns a bad offset or length into an
                // allocation, so every one the parser handed back is read.
                if let EntryKind::File(content) = &entry.kind {
                    let _ = content.read();
                }
            }
        }
    }
}
