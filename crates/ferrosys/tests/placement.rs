//! The gate for how a writer places a file's contents: whole, in order, and from a range of
//! a host file as faithfully as from bytes in memory, however many windows the file spans.
//!
//! A writer reads a file named by range a window at a time, so a file longer than a window is
//! the case where an off-by-one at a window boundary would land. Every family is driven
//! through the same two files — one owned, one a range starting part way into its host file —
//! and read back through the shared surface, so the comparison is written once.
//!
//! A file declared by its length alone has no bytes for a writer to read, and every family
//! whose writer reads them refuses one when the plan is made, before a destination exists.
#![cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]

use std::fs::File;
use std::io::Write as _;

use ferrosys::{
    FileContent, FileRange, FsReader, FsTree, Metadata, NodeKind, Timestamp, TreeBuilder,
    TreeEntry, TreeError, open,
};

/// Two and a half windows and an odd remainder, so the last window is short and ends inside
/// a block or a sector in every family.
const LEN: usize = (5 << 19) + 7;

/// Where the range starts within its host file, so a read that forgot the range's own offset
/// reads the wrong bytes rather than the right ones by luck.
const SKIP: u64 = 100;

const TIME: i64 = 1_700_000_000;

/// A pattern no two windows share, so a window placed at the wrong offset reads differently.
fn pattern() -> Vec<u8> {
    (0..LEN).map(|i| (i / 3 + i / 4099) as u8).collect()
}

/// A host file holding the pattern after [`SKIP`] bytes of something else, and the range that
/// names the pattern within it.
fn host_file() -> (tempfile::NamedTempFile, FileRange) {
    let mut file = tempfile::NamedTempFile::new().expect("create the host file");
    file.write_all(&[0xEE; SKIP as usize])
        .expect("write the lead");
    file.write_all(&pattern()).expect("write the pattern");
    let range = FileRange::at_path(file.path(), SKIP, LEN as u64);
    (file, range)
}

/// The tree every family is given: the pattern once owned and once by range.
fn source(range: FileRange) -> TreeBuilder {
    let meta = Metadata::new(0o644, Timestamp::from_secs(TIME));
    TreeBuilder::new()
        .file(b"/owned.bin".to_vec(), pattern(), meta)
        .file(b"/ranged.bin".to_vec(), FileContent::Range(range), meta)
}

/// Every regular file's bytes, read back through the shared surface a few bytes short of a
/// window at a time, so the reader's own windows fall elsewhere than the writer's did.
fn contents<T: FsTree>(tree: &mut T) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    tree.walk_tree::<TreeError, _>(|tree, entry: TreeEntry<T::Node>| {
        if let NodeKind::File { size } = entry.kind {
            let mut bytes = Vec::new();
            let mut buf = vec![0u8; (1 << 20) - 13];
            while (bytes.len() as u64) < size {
                let filled = tree.read_bytes(&entry.node, bytes.len() as u64, &mut buf)?;
                assert_ne!(filled, 0, "a read stopped short of the file's size");
                bytes.extend_from_slice(&buf[..filled]);
            }
            out.push((entry.path.clone(), bytes));
        }
        Ok(())
    })
    .expect("the walk succeeds");
    out
}

/// Open `image` without naming a family and read back every file in it.
fn read_back(image: &File) -> Vec<(Vec<u8>, Vec<u8>)> {
    match open(image).expect("the image opens") {
        #[cfg(feature = "ext")]
        FsReader::Ext(mut r) => contents(&mut r),
        #[cfg(feature = "fat")]
        FsReader::Fat(mut r) => contents(&mut r),
        #[cfg(feature = "exfat")]
        FsReader::ExFat(mut r) => contents(&mut r),
        #[cfg(feature = "btrfs")]
        FsReader::Btrfs(mut r) => contents(&mut r),
        _ => panic!("a family this build does not carry claimed the image"),
    }
}

/// Assert both files came back as the pattern, for the family `what` names.
fn assert_placed(what: &str, image: &File) {
    let files = read_back(image);
    let names: Vec<&[u8]> = files.iter().map(|(p, _)| p.as_slice()).collect();
    assert_eq!(
        names,
        [b"/owned.bin".as_slice(), b"/ranged.bin".as_slice()],
        "{what}"
    );
    for (path, bytes) in &files {
        let at = bytes.iter().zip(pattern()).position(|(a, b)| *a != b);
        assert!(
            bytes.len() == LEN && at.is_none(),
            "{what}: {} came back {} bytes long, first differing at {at:?}",
            String::from_utf8_lossy(path),
            bytes.len()
        );
    }
}

#[cfg(feature = "ext")]
#[test]
fn an_ext_file_longer_than_a_window_is_placed_whole_from_a_range() {
    use ferrosys::ext::{FormatOptions, format_to};
    let (_host, range) = host_file();
    let image = tempfile::tempfile().expect("create the image");
    let time = Timestamp::from_secs(TIME);
    format_to(
        source(range),
        32 << 20,
        FormatOptions::new([0x11; 16], time, [0; 16]),
        &image,
    )
    .expect("format");
    assert_placed("ext", &image);
}

#[cfg(feature = "ext")]
#[test]
fn an_ext2_file_longer_than_a_window_is_placed_whole_through_its_block_map() {
    // A block map puts an indirect block between the twelfth data block and the thirteenth,
    // so the file's blocks are more than one run and the windows cross from one to the next.
    use ferrosys::ext::{FormatOptions, Profile, format_to};
    let (_host, range) = host_file();
    let image = tempfile::tempfile().expect("create the image");
    let time = Timestamp::from_secs(TIME);
    format_to(
        source(range),
        32 << 20,
        FormatOptions::new([0x11; 16], time, [0; 16]).profile(Profile::Ext2),
        &image,
    )
    .expect("format");
    assert_placed("ext2", &image);
}

#[cfg(feature = "fat")]
#[test]
fn a_fat_file_longer_than_a_window_is_placed_whole_from_a_range() {
    use ferrosys::fat::{FormatOptions, format_to};
    let (_host, range) = host_file();
    let image = tempfile::tempfile().expect("create the image");
    let options = FormatOptions::new(0x1234_abcd, Timestamp::from_secs(TIME));
    format_to(source(range), 32 << 20, options, &image).expect("format");
    assert_placed("FAT", &image);
}

#[cfg(feature = "exfat")]
#[test]
fn an_exfat_file_longer_than_a_window_is_placed_whole_from_a_range() {
    use ferrosys::exfat::{FormatOptions, format_to};
    let (_host, range) = host_file();
    let image = tempfile::tempfile().expect("create the image");
    format_to(
        &image,
        source(range),
        32 << 20,
        FormatOptions::new(0x1234_abcd),
    )
    .expect("format");
    assert_placed("exFAT", &image);
}

#[cfg(feature = "btrfs")]
#[test]
fn a_btrfs_file_longer_than_a_window_is_placed_whole_from_a_range() {
    use ferrosys::btrfs::{FormatOptions, format_to};
    let (_host, range) = host_file();
    let image = tempfile::tempfile().expect("create the image");
    let options = FormatOptions::new([0x22; 16], Timestamp::from_secs(TIME));
    format_to(&image, source(range), 256 << 20, options).expect("format");
    assert_placed("btrfs", &image);
}

/// The tree every refusal below is given: one file declared by its length alone.
fn declared() -> TreeBuilder {
    let meta = Metadata::new(0o644, Timestamp::from_secs(TIME));
    TreeBuilder::new().file(
        b"/os.img".to_vec(),
        FileContent::Declared { len: 4096, key: 1 },
        meta,
    )
}

#[cfg(feature = "ext")]
#[test]
fn an_ext_plan_refuses_a_file_declared_by_its_length_alone() {
    use ferrosys::ext::{FormatError, FormatOptions, FormatPlan, ModelError};
    let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(TIME), [0; 16]);
    let err = FormatPlan::new(declared(), 32 << 20, options)
        .err()
        .expect("refused");
    assert!(
        matches!(&err, FormatError::Model(ModelError::ContentsNotHeld { path, .. }) if path == b"/os.img"),
        "{err}"
    );
}

#[cfg(feature = "fat")]
#[test]
fn a_fat_plan_refuses_a_file_declared_by_its_length_alone() {
    use ferrosys::fat::{FormatError, FormatOptions, FormatPlan, ModelError};
    let options = FormatOptions::new(0x1234_abcd, Timestamp::from_secs(TIME));
    let err = FormatPlan::new(declared(), 32 << 20, options)
        .err()
        .expect("refused");
    assert!(
        matches!(&err, FormatError::Model(ModelError::ContentsNotHeld { path, .. }) if path == b"/os.img"),
        "{err}"
    );
}

#[cfg(feature = "btrfs")]
#[test]
fn a_btrfs_plan_refuses_a_file_declared_by_its_length_alone() {
    use ferrosys::btrfs::{FormatError, FormatOptions, FormatPlan, ModelError};
    let options = FormatOptions::new([0x22; 16], Timestamp::from_secs(TIME));
    let err = FormatPlan::new(declared(), 256 << 20, options)
        .err()
        .expect("refused");
    assert!(
        matches!(&err, FormatError::Model(ModelError::ContentsNotHeld { path, .. }) if path == b"/os.img"),
        "{err}"
    );
}
