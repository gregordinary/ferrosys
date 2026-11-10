//! ext features a Linux kernel wrote, read back.
//!
//! Each fixture is a filesystem the pinned `mke2fs` 1.47.0 formatted with one feature this
//! reader follows and the board kernel's ext4 driver (Linux 7.1.1, arm64, under
//! `qemu-system-aarch64 -M virt`) then mounted read-write, filled, and unmounted cleanly. The
//! pinned `e2fsck -fn` passes every one. What each holds, and the digest of every file the
//! kernel wrote, comes from the guest's own listing of it while mounted.
//!
//! Stored without their zero blocks, as [`util::unsparse`] reads them.

#![cfg(feature = "ext")]

mod util;

use std::io::Cursor;

use ferrosys::ext::ondisk::InodeFlags;
use ferrosys::ext::{ReadError, Reader};
use ferrosys::{FsTree, TreeError};
use sha2::Digest as _;

/// The hex SHA-256 of `bytes`.
fn digest(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A fixture opened strictly: a strict open is what refuses a feature this reader does not
/// follow, so opening at all is the first thing each test asserts.
fn open(fixture: &[u8]) -> Reader<Cursor<Vec<u8>>> {
    Reader::open(Cursor::new(util::unsparse(fixture)))
        .expect("the kernel's filesystem opens strictly")
}

/// 1 KiB blocks, 256-byte inodes, no journal, `encrypt`. The kernel added a v2 key, set an
/// AES-256-XTS / AES-256-CTS policy padded to 32 on `/secret`, and filled it: two files and a
/// hard link to one, an empty file, a directory with an empty file, a 6-byte link and a 300-byte
/// one, and a directory of 40 names that the kernel indexed. `/plain` beside it is unencrypted.
const ENCRYPT: &[u8] = include_bytes!("fixtures/ext4-kernel-encrypt.sparse");

#[test]
fn an_encrypted_filesystem_reads_everything_that_is_not_ciphertext() {
    let mut reader = open(ENCRYPT);
    // A clean scan holds every encrypted directory's entries to their framing and to the
    // leaf its hash leads to. Encrypted names are hashed as they are stored, so the index
    // the kernel built over 40 of them is checked like any other.
    let report = reader.scan();
    assert!(report.is_clean(), "{:?}", report.anomalies());

    let (_, hello) = reader.lookup(b"/plain/hello.txt").expect("the plain file");
    assert_eq!(
        digest(&reader.read_data(&hello).expect("its bytes")),
        "0b42a67553bd39c8bc84253db1709870ffb6e427a35c019af606ed202e9ceb1c"
    );
    let (_, data) = reader
        .lookup(b"/plain/sub/data.bin")
        .expect("the plain file");
    assert_eq!(
        digest(&reader.read_data(&data).expect("its bytes")),
        "34398b85297bf7d9dfb59b8d511d8bbb44ab23e891570e4395e7871475fc8afb"
    );
}

#[test]
fn an_encrypted_directory_is_reached_and_its_names_are_refused() {
    let mut reader = open(ENCRYPT);
    let (_, secret) = reader
        .lookup(b"/secret")
        .expect("the directory itself resolves");
    assert!(secret.flags.contains(InodeFlags::ENCRYPT));
    // Its attributes are plaintext, and the encryption's own record is not among them.
    assert!(
        reader.xattrs(&secret).expect("its attributes").is_empty(),
        "the encryption context is not an attribute of the directory"
    );
    assert!(matches!(
        reader.read_dir(&secret),
        Err(ReadError::Encrypted {
            node: "directory",
            ..
        })
    ));
    // A name inside it is a name this reader cannot match against ciphertext, so the
    // resolution is refused rather than answered "not found".
    assert!(matches!(
        reader.lookup(b"/secret/a.txt"),
        Err(ReadError::Encrypted {
            node: "directory",
            ..
        })
    ));
    // `/secret/many`'s own name is ciphertext in `/secret`, so it is found by number: the one
    // encrypted directory the kernel indexed, whose names a clean scan holds one by one to
    // the leaf their stored bytes hash to.
    let indexed = (11..=200)
        .map(|number| reader.inode(number).expect("an inode in range"))
        .filter(|inode| {
            inode.mode & 0o170000 == 0o040000
                && inode.flags.contains(InodeFlags::ENCRYPT)
                && inode.flags.contains(InodeFlags::INDEX)
        })
        .count();
    assert_eq!(indexed, 1, "the kernel indexed the directory of 40 names");
}

#[test]
fn an_encrypted_files_data_and_an_encrypted_links_target_are_refused() {
    let mut reader = open(ENCRYPT);
    // Reached by number, since no name inside `/secret` resolves. Inode 17 is `a.txt`, 34
    // bytes, which the guest reported while it held the key.
    let a = reader.inode(17).expect("the inode");
    assert!(a.flags.contains(InodeFlags::ENCRYPT));
    assert_eq!(a.size, 34, "the size is stored in the clear");
    assert!(matches!(
        reader.read_data(&a),
        Err(ReadError::Encrypted { node: "file", .. })
    ));
    assert!(matches!(
        reader.read_into(&a, 0, &mut [0u8; 64]),
        Err(ReadError::Encrypted { node: "file", .. })
    ));
    assert!(matches!(
        reader.read_data_to(&a, std::io::sink()),
        Err(ReadError::Encrypted { node: "file", .. })
    ));
    let mut links = 0;
    for number in 11..=200 {
        let inode = reader.inode(number).expect("an inode in range");
        if inode.mode & 0o170000 == 0o120000 && inode.flags.contains(InodeFlags::ENCRYPT) {
            links += 1;
            assert!(matches!(
                reader.read_symlink(&inode),
                Err(ReadError::Encrypted {
                    node: "symbolic link",
                    ..
                })
            ));
        }
    }
    assert_eq!(links, 2, "the short link and the long one");
}

#[test]
fn a_walk_stops_at_an_encrypted_directory_as_unsupported() {
    let mut reader = open(ENCRYPT);
    let walked = reader.walk_tree::<TreeError, _>(|_, _| Ok(()));
    assert!(
        matches!(walked, Err(TreeError::Unsupported { .. })),
        "{walked:?}"
    );
}

/// Each file a fixture holds, its length, and the SHA-256 of its bytes, as the guest read them
/// while it was mounted.
type Files = &'static [(&'static str, u64, &'static str)];

/// Every file of `files` reads back through a strict open as the kernel wrote it.
fn reads_back(reader: &mut Reader<Cursor<Vec<u8>>>, files: Files) {
    for (path, len, want) in files {
        let (_, inode) = reader
            .lookup(path.as_bytes())
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let bytes = reader
            .read_data(&inode)
            .unwrap_or_else(|e| panic!("{path} reads: {e}"));
        assert_eq!(bytes.len() as u64, *len, "{path}");
        assert_eq!(&digest(&bytes), want, "{path}: the bytes the kernel wrote");
    }
}

/// 1 KiB blocks, 256-byte inodes, no journal, `inline_data`. The kernel wrote files of 0 to
/// 5000 bytes — up to 100 of which it kept inline, the bytes past 60 in `system.data` — one
/// grown past inline across a commit and one truncated, directories of one, six and sixty
/// names, and links of 5, 90 and 300 bytes.
const INLINE: &[u8] = include_bytes!("fixtures/ext4-kernel-inline.sparse");

const INLINE_FILES: &[(&str, u64, &str)] = &[
    (
        "/dirs/grown/entry-number-1",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-10",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-11",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-12",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-13",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-14",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-15",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-16",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-17",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-18",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-19",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-2",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-20",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-21",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-22",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-23",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-24",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-25",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-26",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-27",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-28",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-29",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-3",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-30",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-31",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-32",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-33",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-34",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-35",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-36",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-37",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-38",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-39",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-4",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-40",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-41",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-42",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-43",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-44",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-45",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-46",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-47",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-48",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-49",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-5",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-50",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-51",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-52",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-53",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-54",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-55",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-56",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-57",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-58",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-59",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-6",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-60",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-7",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-8",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/grown/entry-number-9",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-1",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-2",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-3",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-4",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-5",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/medium/name-6",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/dirs/tiny/a",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/small/empty",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/small/grown",
        3040,
        "fb0fa1cc44eb6f5d62b6b1d473a3811bb966181c70a3a2070c1b49f10f74c599",
    ),
    (
        "/small/len-1",
        1,
        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
    ),
    (
        "/small/len-100",
        100,
        "2f52d6c67152b0e2a107af8bce27a809bc086d1cc5eb5d485a0c7cb7bf631a7a",
    ),
    (
        "/small/len-140",
        140,
        "ac670bdfc0de58ff51be1d9d351e1ba6be1c2df824b6c104cd301555d16448ab",
    ),
    (
        "/small/len-1500",
        1500,
        "5ce6cace56c3bbd310224feff93dae6260628098418eda459700b89a2375d3c2",
    ),
    (
        "/small/len-160",
        160,
        "c7cb16bc7ab0a7870306f5d99c460dc12055de572e36a44af27f78fe25a70d8c",
    ),
    (
        "/small/len-200",
        200,
        "8e3f3819b4f1b1f71c011c6b854c43601f132c3c88b8982b20733d2b1695c593",
    ),
    (
        "/small/len-5000",
        5000,
        "ade8bdfe08fd12ee01239edc8a5b68b5221a1f38fa9371499435b4ca86febd55",
    ),
    (
        "/small/len-59",
        59,
        "1b70d65ef02ab7524c4070295da64f4bc1742de82bc0f53a7241a211827bb65c",
    ),
    (
        "/small/len-60",
        60,
        "a7395392b500ee1855fd4fb13ce5d863a5581fd02b981710533d5a83fbfab7bd",
    ),
    (
        "/small/len-61",
        61,
        "eb75a7c80ccaebf13a9fbbe4db10e9fda98c623597d1ff194ba34a21852127d7",
    ),
    (
        "/small/shrunk",
        30,
        "901c4db9c0ce099610312042797cd388dae75fc8091d6081a9338ddd32f30e8e",
    ),
];

#[test]
fn files_and_directories_a_kernel_kept_inline_read_back() {
    let mut reader = open(INLINE);
    let report = reader.scan();
    assert!(report.is_clean(), "{:?}", report.anomalies());
    // The fixture holds what the test is about: files and directories kept inline.
    let inline = (11..=120)
        .map(|n| reader.inode(n).expect("an inode in range"))
        .filter(|i| i.links_count > 0 && i.flags.contains(InodeFlags::INLINE_DATA))
        .count();
    assert!(inline >= 8, "{inline} inline inodes");
    reads_back(&mut reader, INLINE_FILES);

    // A directory kept inline lists the names its block area and its system.data hold, and
    // stores no dot entries of its own.
    let (_, medium) = reader.lookup(b"/dirs/medium").expect("the directory");
    assert!(medium.flags.contains(InodeFlags::INLINE_DATA));
    let mut names: Vec<Vec<u8>> = reader
        .read_dir(&medium)
        .expect("its entries")
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    let want: Vec<Vec<u8>> = (1..=6).map(|i| format!("name-{i}").into_bytes()).collect();
    assert_eq!(names, want);
    for (path, len) in [
        (&b"/links/long"[..], 300),
        (&b"/links/ninety"[..], 90),
        (&b"/links/short"[..], 5),
    ] {
        let (_, link) = reader.lookup_no_follow(path).expect("the link");
        assert_eq!(
            reader.read_symlink(&link).expect("its target").len(),
            len,
            "{}",
            String::from_utf8_lossy(path)
        );
    }
}

#[test]
fn a_file_kept_inline_is_held_to_the_read_cap_by_every_read() {
    // The cap a caller sets on a whole-file read holds whatever keeps the content: a streamed
    // read of a file kept inline refuses what a whole-file read of it refuses.
    let mut reader = Reader::open_with(
        Cursor::new(util::unsparse(INLINE)),
        &ferrosys::ext::OpenOptions::new().limits(ferrosys::Limits::new().max_file_bytes(10)),
    )
    .expect("it opens");
    let (_, file) = reader.lookup(b"/small/len-59").expect("the file");
    assert!(file.flags.contains(InodeFlags::INLINE_DATA));
    assert!(matches!(
        reader.read_data(&file),
        Err(ReadError::FileTooLarge {
            size: 59,
            limit: 10,
            ..
        })
    ));
    assert!(matches!(
        reader.read_data_to(&file, std::io::sink()),
        Err(ReadError::FileTooLarge {
            size: 59,
            limit: 10,
            ..
        })
    ));
}

#[test]
fn an_inline_directory_without_its_system_data_is_one_finding() {
    // The fault is the directory's content, which the walk of its entries reports; the check
    // of the inode's stored values leaves a directory's to that walk rather than naming the
    // same fault twice.
    let mut image = util::unsparse(INLINE);
    let (number, inode_size, table, per_group) = {
        let mut reader = Reader::open(Cursor::new(image.clone())).expect("it opens");
        let (number, _) = reader.lookup(b"/dirs/medium").expect("the directory");
        let sb = reader.superblock().clone();
        let group = (number - 1) / sb.inodes_per_group;
        let table = reader
            .group_descriptor(group)
            .expect("its group")
            .inode_table;
        (number, sb.inode_size as usize, table, sb.inodes_per_group)
    };
    let at = table as usize * 1024 + ((number - 1) % per_group) as usize * inode_size;
    let body = &mut image[at..at + inode_size];
    let name = body
        .windows(4)
        .position(|w| w == b"data")
        .expect("the system.data entry");
    // The entry's header is sixteen bytes before its name, and its name index the second.
    assert_eq!(body[name - 16 + 1], 7, "stored as a system attribute");
    body[name - 16 + 1] = 1;
    let mut reader = Reader::open_with(
        Cursor::new(image),
        &ferrosys::ext::OpenOptions::new().policy(ferrosys::ReadPolicy::Lenient),
    )
    .expect("a lenient open");
    let found: Vec<String> = reader
        .scan()
        .anomalies()
        .iter()
        .map(|a| a.detail.clone())
        .filter(|d| d.contains("system.data"))
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
}

/// 1 KiB blocks, 256-byte inodes, no journal, `ea_inode`. The kernel set `user.*` values of
/// 50, 600, 4000 and 65536 bytes, one 3000-byte value on two files, and five of 2000 and one
/// of 20 on a sixth: those past what an attribute block holds it kept in inodes of their own,
/// one inode for the two equal values. Byte `i` of a value set with seed `s` is
/// `(i * 131 + s) % 251`.
const EA_INODE: &[u8] = include_bytes!("fixtures/ext4-kernel-ea-inode.sparse");

/// The values the guest set on one file: each one's name, length, and seed.
type Values = &'static [(&'static str, usize, usize)];

/// The value the guest set: `len` bytes from `seed`.
fn value(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + seed) % 251) as u8).collect()
}

#[test]
fn attribute_values_a_kernel_kept_in_inodes_of_their_own_read_back() {
    let mut reader = open(EA_INODE);
    let report = reader.scan();
    assert!(report.is_clean(), "{:?}", report.anomalies());
    let held = (11..=60)
        .map(|n| reader.inode(n).expect("an inode in range"))
        .filter(|i| i.links_count > 0 && i.flags.contains(InodeFlags::EA_INODE))
        .count();
    assert!(held >= 4, "{held} inodes holding a value");

    let expect: [(&str, Values); 7] = [
        ("small", &[("user.a", 50, 1)]),
        ("block", &[("user.b", 600, 2)]),
        ("big", &[("user.c", 4000, 3)]),
        ("huge", &[("user.d", 65536, 4)]),
        ("twin1", &[("user.t", 3000, 5)]),
        ("twin2", &[("user.t", 3000, 5)]),
        (
            "many",
            &[
                ("user.m1", 2000, 11),
                ("user.m2", 2000, 12),
                ("user.m3", 2000, 13),
                ("user.m4", 2000, 14),
                ("user.m5", 2000, 15),
                ("user.s", 20, 9),
            ],
        ),
    ];
    for (file, values) in expect {
        let (_, inode) = reader
            .lookup(format!("/x/{file}").as_bytes())
            .expect("the file");
        let mut got = reader.xattrs(&inode).expect("its attributes");
        got.sort_by(|a, b| a.name.cmp(&b.name));
        let mut want: Vec<(Vec<u8>, Vec<u8>)> = values
            .iter()
            .map(|(name, len, seed)| (name.as_bytes().to_vec(), value(*len, *seed)))
            .collect();
        want.sort();
        let got: Vec<(Vec<u8>, Vec<u8>)> = got.into_iter().map(|x| (x.name, x.value)).collect();
        assert_eq!(got, want, "{file}");
    }
}

/// 1 KiB blocks, 256-byte inodes, no journal, `casefold` (UTF-8) and `encrypt`. The kernel set
/// the case-folding flag on `/folded` and filled it: 120 long mixed-case names, which it
/// indexed by their folded hashes, `README.txt`, a name holding non-ASCII letters, and a
/// directory with one file. `/both` is folded and encrypted, and `/plain` neither.
const CASEFOLD: &[u8] = include_bytes!("fixtures/ext4-kernel-casefold.sparse");

const CASEFOLD_FILES: &[(&str, u64, &str)] = &[
    (
        "/folded/Mixed-Case-000-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-001-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-002-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-003-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-004-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-005-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-006-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-007-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-008-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-009-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-010-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-011-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-012-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-013-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-014-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-015-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-016-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-017-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-018-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-019-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-020-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-021-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-022-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-023-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-024-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-025-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-026-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-027-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-028-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-029-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-030-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-031-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-032-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-033-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-034-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-035-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-036-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-037-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-038-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-039-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-040-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-041-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-042-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-043-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-044-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-045-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-046-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-047-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-048-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-049-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-050-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-051-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-052-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-053-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-054-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-055-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-056-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-057-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-058-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-059-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-060-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-061-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-062-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-063-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-064-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-065-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-066-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-067-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-068-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-069-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-070-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-071-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-072-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-073-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-074-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-075-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-076-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-077-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-078-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-079-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-080-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-081-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-082-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-083-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-084-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-085-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-086-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-087-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-088-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-089-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-090-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-091-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-092-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-093-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-094-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-095-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-096-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-097-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-098-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-099-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-100-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-101-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-102-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-103-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-104-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-105-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-106-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-107-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-108-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-109-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-110-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-111-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-112-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-113-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-114-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-115-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-116-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-117-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-118-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/Mixed-Case-119-WzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWzWz",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "/folded/README.txt",
        7,
        "00d75b5176b48ccc71d91bcc1d7b90fc2820429b1629b77fd1d5f4c5dcee4f6d",
    ),
    (
        "/folded/SubDir/Inner.TXT",
        6,
        "940a68104d3b690442453f4be394b0a14721a174127d84c1c2f834b7ad05d684",
    ),
    (
        "/folded/Über-ßtraße",
        7,
        "eefeabce9a2687ecae740bf791ad4e768b642ec837cc05e9677b25de098e2547",
    ),
    (
        "/plain/File.txt",
        6,
        "dacf36547c7774a0a170806363b5d412991fbc0d6260b2c00b1d3a80a816c23f",
    ),
];

#[test]
fn a_case_folded_directory_reads_its_names_as_they_are_stored() {
    let mut reader = open(CASEFOLD);
    // The scan holds the folded directory's entries to their framing and references; where
    // each sits in the index is a question of folded hashes, which it does not ask.
    let report = reader.scan();
    assert!(report.is_clean(), "{:?}", report.anomalies());
    let (_, folded) = reader.lookup(b"/folded").expect("the directory");
    assert!(folded.flags.contains(InodeFlags::CASEFOLD));
    assert!(
        folded.flags.contains(InodeFlags::INDEX),
        "the kernel indexed it"
    );
    reads_back(&mut reader, CASEFOLD_FILES);

    // A name matches as it is stored, and only so: this reader does not fold it.
    assert!(reader.lookup(b"/folded/README.txt").is_ok());
    assert!(matches!(
        reader.lookup(b"/folded/readme.txt"),
        Err(ReadError::NotFound { .. })
    ));
    let listed = reader.read_dir(&folded).expect("its entries");
    assert_eq!(
        listed
            .iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .count(),
        123
    );
    // Folded and encrypted at once, it is refused as any encrypted directory is.
    let (_, both) = reader.lookup(b"/both").expect("the directory");
    assert!(matches!(
        reader.read_dir(&both),
        Err(ReadError::Encrypted { .. })
    ));
}
