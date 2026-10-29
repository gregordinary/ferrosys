//! The gate for a tree this crate reads, handed back to the write side: `ImageSource` over one
//! family's reader, written by another family's writer, and what a Darwin filesystem records
//! of an entry carried where it can be held and refused where it cannot.
#![cfg(all(feature = "apfs", feature = "ext", feature = "btrfs", feature = "fat"))]

use std::collections::BTreeMap;
use std::io::Cursor;

use ferrosys::apfs::{FormatOptions, Reader, VolumeName, VolumeRequest};
use ferrosys::{
    AcceptedLoss, CompressedFile, Darwin, EntryKind, FsReader, FsTree, ImageSource, LayeredSource,
    Metadata, NodeKind, Property, RemovalError, Source, SourceEntry, Synthesis, Timestamp,
    TreeBuilder, TreeError, Xattr, open,
};

const TIME: Timestamp = Timestamp::from_secs(1_700_000_000);

/// `UF_HIDDEN`, which macOS sets on the system names at the top of a volume.
const HIDDEN: u32 = 0x8000;

fn apfs(source: impl Source) -> Vec<u8> {
    let options = FormatOptions::new(
        [0x11; 16],
        TIME,
        VolumeRequest::new(VolumeName::new("Source").expect("a name"), [0x22; 16]),
    );
    ferrosys::apfs::format(source, 64 << 20, options)
        .expect("the APFS writer formats it")
        .into_bytes()
}

fn ext(source: impl Source) -> Result<Vec<u8>, ferrosys::ext::FormatError> {
    let options = ferrosys::ext::FormatOptions::new([0x33; 16], TIME, [0; 16]);
    ferrosys::ext::format(source, 32 << 20, options).map(ferrosys::ext::Image::into_bytes)
}

fn btrfs(source: impl Source) -> Result<Vec<u8>, ferrosys::btrfs::FormatError> {
    let options = ferrosys::btrfs::FormatOptions::new([0x44; 16], TIME)
        .chunk_tree_uuid([0x45; 16])
        .device_uuid([0x46; 16])
        .subvolume_uuid([0x47; 16]);
    ferrosys::btrfs::format(source, 256 << 20, options).map(|image| image.into_bytes())
}

fn fat(source: impl Source, accepted: AcceptedLoss) -> Result<Vec<u8>, ferrosys::fat::FormatError> {
    let mut options = ferrosys::fat::FormatOptions::new(0x1234_5678, TIME);
    options.accepted_loss = accepted;
    ferrosys::fat::format(source, 32 << 20, options).map(ferrosys::fat::Image::into_bytes)
}

/// The image's first volume or filesystem, read as a source.
fn source_of(image: Vec<u8>) -> ImageSource {
    let reader = open(Cursor::new(image)).expect("the image opens");
    let synthesis = Synthesis::default();
    match reader {
        FsReader::Apfs(r) => ImageSource::read(r, &synthesis),
        FsReader::Ext(r) => ImageSource::read(r, &synthesis),
        FsReader::Btrfs(r) => ImageSource::read(r, &synthesis),
        FsReader::Fat(r) => ImageSource::read(r, &synthesis),
        _ => unreachable!("a family this test writes"),
    }
    .expect("the tree reads as a source")
}

/// What one entry of a tree is, as this test compares two trees.
#[derive(Debug, PartialEq, Eq)]
struct Held {
    kind: NodeKind,
    meta: Metadata,
    xattrs: Vec<Xattr>,
    bytes: Option<Vec<u8>>,
    target: Option<Vec<u8>>,
    shared: bool,
}

/// Every entry a reader walks, by path.
fn held<T: FsTree>(tree: &mut T) -> BTreeMap<Vec<u8>, Held> {
    let mut out = BTreeMap::new();
    tree.walk_tree::<TreeError, _>(|tree, entry| {
        let attributes = tree.stat(&entry.node, &Synthesis::default())?;
        let mut xattrs = attributes.xattrs;
        xattrs.sort_by(|a, b| a.name.cmp(&b.name));
        let bytes = match entry.kind {
            NodeKind::File { size } => {
                let mut buf = vec![0u8; usize::try_from(size).expect("a small file")];
                let mut at = 0;
                while at < buf.len() {
                    at += tree.read_bytes(&entry.node, at as u64, &mut buf[at..])?;
                }
                Some(buf)
            }
            _ => None,
        };
        let target = match entry.kind {
            NodeKind::Symlink => Some(tree.link_target(&entry.node)?),
            _ => None,
        };
        out.insert(
            entry.path.clone(),
            Held {
                kind: entry.kind,
                meta: attributes.meta,
                xattrs,
                bytes,
                target,
                shared: entry.shared.is_some(),
            },
        );
        Ok(())
    })
    .expect("the tree walks");
    out
}

fn held_in(image: Vec<u8>) -> BTreeMap<Vec<u8>, Held> {
    match open(Cursor::new(image)).expect("the image opens") {
        FsReader::Apfs(mut r) => held(&mut r),
        FsReader::Ext(mut r) => held(&mut r),
        FsReader::Btrfs(mut r) => held(&mut r),
        _ => unreachable!("a family this test compares"),
    }
}

/// A tree every family here holds whole: directories, files, a symbolic link, a hard link, a
/// device node, a pipe, and an attribute in the namespace every one of them stores.
fn tree() -> TreeBuilder {
    let meta = |mode| Metadata::new(mode, TIME).owned_by(1000, 1000);
    TreeBuilder::new()
        .directory("/etc", meta(0o755))
        .file("/etc/hostname", "ferrosys\n", meta(0o644))
        .xattr("user.origin", "image")
        .file("/etc/large", vec![7u8; 300_000], meta(0o600))
        .symlink("/etc/mtab", "/proc/mounts", meta(0o777))
        .hardlink("/etc/again", "/etc/hostname", meta(0o644))
        .char_device("/null", 1, 3, meta(0o666))
        .fifo("/pipe", meta(0o644))
}

/// `got` holds every entry of `want` as `want` holds it, and nothing else but `own`: what the
/// family that wrote it makes for itself, which the source never held.
fn same(
    family: &str,
    mut got: BTreeMap<Vec<u8>, Held>,
    want: &BTreeMap<Vec<u8>, Held>,
    own: &[&[u8]],
) {
    let extra: Vec<Vec<u8>> = got
        .keys()
        .filter(|path| !want.contains_key(*path))
        .cloned()
        .collect();
    assert_eq!(extra, own, "{family}: entries the source did not hold");
    got.retain(|path, _| want.contains_key(path));
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "{family}"
    );
    for (path, held) in want {
        let other = &got[path];
        assert_eq!(other.kind, held.kind, "{family}: {path:?}");
        assert_eq!(other.bytes, held.bytes, "{family}: {path:?}");
        assert_eq!(other.target, held.target, "{family}: {path:?}");
        assert_eq!(other.xattrs, held.xattrs, "{family}: {path:?}");
        assert_eq!(other.shared, held.shared, "{family}: {path:?}");
        assert_eq!(
            (
                other.meta.mode,
                other.meta.uid,
                other.meta.gid,
                other.meta.mtime,
                other.meta.btime
            ),
            (
                held.meta.mode,
                held.meta.uid,
                held.meta.gid,
                held.meta.mtime,
                held.meta.btime
            ),
            "{family}: {path:?}"
        );
    }
}

#[test]
fn a_tree_read_from_an_image_is_written_again_entry_for_entry_by_another_family() {
    let first = apfs(tree());
    let want = held_in(first.clone());
    assert!(want.len() > 7, "{} entries", want.len());

    // Read back and written again, by APFS and by two families that hold the same properties.
    let again = held_in(apfs(source_of(first.clone())));
    assert_eq!(again, want, "APFS again");
    let ext_image = ext(source_of(first.clone())).expect("ext formats it");
    let btrfs_image = btrfs(source_of(first)).expect("btrfs formats it");
    let lost: &[&[u8]] = &[b"/lost+found"];
    same("ext", held_in(ext_image.clone()), &want, lost);
    same("btrfs", held_in(btrfs_image.clone()), &want, &[]);

    // And each of those, read as a source in turn, writes the same tree on APFS and on its own
    // family: every reader's metadata is what a writer accepts, and what a format makes for
    // itself is not carried into the next.
    same(
        "ext to APFS",
        held_in(apfs(source_of(ext_image.clone()))),
        &want,
        &[],
    );
    let ext_again = ext(source_of(ext_image.clone())).expect("ext formats an ext tree again");
    same("ext to ext", held_in(ext_again), &want, lost);
    let btrfs_again = btrfs(source_of(ext_image)).expect("btrfs formats an ext tree");
    same("ext to btrfs", held_in(btrfs_again), &want, &[]);
    same(
        "btrfs to APFS",
        held_in(apfs(source_of(btrfs_image))),
        &want,
        &[],
    );
}

#[test]
fn a_family_recording_less_names_what_its_source_invented() {
    let meta = Metadata::new(0o755, TIME);
    let entries = vec![
        SourceEntry::new("/docs", EntryKind::Directory, meta),
        SourceEntry::new(
            "/docs/note.txt",
            EntryKind::File(b"a note\n".to_vec().into()),
            meta,
        ),
    ];
    let image = fat(entries, AcceptedLoss::ALL).expect("FAT formats it");
    let source = source_of(image);
    // FAT records no owner, so every entry's owner is the synthesis's, and the source says so.
    assert!(!source.fidelity().is_faithful());
    let named = |path: &[u8]| {
        source
            .fidelity()
            .records()
            .iter()
            .any(|r| r.path == path && r.property == Property::Ownership)
    };
    assert!(named(b"/docs") && named(b"/docs/note.txt"));
    let written = held_in(apfs(source));
    assert_eq!(
        written[b"/docs/note.txt".as_slice()].bytes.as_deref(),
        Some(b"a note\n".as_slice())
    );
}

#[test]
fn a_file_in_an_image_is_read_when_it_is_placed_and_no_sooner() {
    let source = source_of(apfs(tree()));
    let entries = source.entries();
    let large = entries
        .iter()
        .find(|e| e.path == b"/etc/large")
        .expect("the file");
    let EntryKind::File(content) = &large.kind else {
        panic!("a file");
    };
    // The content is a handle into the image, not its bytes, and reads them on request.
    assert!(matches!(content, ferrosys::FileContent::Image(_)));
    assert_eq!(content.len(), 300_000);
    let mut window = vec![0u8; 10];
    content.read_at(299_990, &mut window).expect("reads");
    assert_eq!(window, [7u8; 10]);
    assert!(
        content.read_at(299_995, &mut window).is_err(),
        "past the end"
    );
}

/// A tree whose top-level name carries `UF_HIDDEN`, as the system names of a Mac's volume do.
fn hidden() -> Vec<SourceEntry> {
    let meta = Metadata::new(0o755, TIME);
    vec![
        SourceEntry::new("/System", EntryKind::Directory, meta).with_darwin(Darwin::new(HIDDEN)),
        SourceEntry::new("/System/name", EntryKind::File(b"x".to_vec().into()), meta),
    ]
}

#[test]
fn bsd_flags_are_kept_on_apfs_and_refused_where_a_family_holds_none() {
    let image = apfs(hidden());
    let mut reader = Reader::open(Cursor::new(image.clone())).expect("opens");
    let node = reader.lookup(b"/System").expect("the directory");
    assert_eq!(
        reader.darwin(&node).expect("reads").map(|d| d.bsd_flags),
        Some(HIDDEN)
    );

    // Read back and written again, the flag survives on APFS.
    let mut again = Reader::open(Cursor::new(apfs(source_of(image.clone())))).expect("opens");
    let node = again.lookup(b"/System").expect("the directory");
    assert_eq!(
        again.darwin(&node).expect("reads").map(|d| d.bsd_flags),
        Some(HIDDEN)
    );

    // Every other family refuses it, naming the loss.
    let refused = ext(source_of(image.clone())).expect_err("ext refuses");
    assert!(refused.to_string().contains("BSD flags"), "{refused}");
    let refused = btrfs(source_of(image.clone())).expect_err("btrfs refuses");
    assert!(refused.to_string().contains("BSD flags"), "{refused}");
    let all_but = AcceptedLoss::ALL.without(Property::BsdFlags);
    let refused = fat(source_of(image.clone()), all_but).expect_err("FAT refuses");
    assert!(refused.to_string().contains("bsd flags"), "{refused}");

    // A caller accepts the loss by saying so: through the family's own acceptance, or by
    // clearing the entry's Darwin part.
    fat(source_of(image.clone()), AcceptedLoss::ALL).expect("FAT accepts it when told to");
    let cleared: Vec<SourceEntry> = source_of(image)
        .into_entries()
        .into_iter()
        .map(|mut entry| {
            entry.darwin = None;
            entry
        })
        .collect();
    ext(cleared).expect("ext formats the tree without the flag");
}

#[cfg(feature = "tar")]
#[test]
fn an_archive_of_an_image_names_the_bsd_flags_it_does_not_carry() {
    // A tar header has no field for them, so the archive is written without them and its
    // report says so, as a writer of another family refuses or records the same loss.
    let mut reader = Reader::open(Cursor::new(apfs(hidden()))).expect("opens");
    let fidelity = ferrosys::ArchiveSink::new(Vec::new())
        .write_tree(&mut reader)
        .expect("the archive is written");
    assert_eq!(
        fidelity.count(ferrosys::Direction::Dropped, Property::BsdFlags),
        1
    );
}

#[cfg(all(feature = "dir", target_os = "linux"))]
#[test]
fn a_directory_written_from_an_image_refuses_bsd_flags_unless_told_to_leave_them_out() {
    // No Linux destination holds them: a faithful extraction stops at the entry, and one that
    // writes what the destination holds leaves them out and records each entry as dropped.
    let image = apfs(hidden());
    let root = std::env::temp_dir().join(format!("ferrosys-bsd-flags-{}", std::process::id()));
    let refused = root.join("refused");
    let kept = root.join("kept");
    for dir in [&refused, &kept] {
        std::fs::create_dir_all(dir).expect("a destination");
    }
    let mut reader = Reader::open(Cursor::new(image.clone())).expect("opens");
    let err = ferrosys::DirectorySink::new(&refused)
        .expect("the sink")
        .write_tree(&mut reader)
        .expect_err("refused");
    assert!(
        matches!(&err, ferrosys::HostError::FlagsNotHeld { path, flags: HIDDEN, .. } if path == b"/System"),
        "{err}"
    );
    let mut reader = Reader::open(Cursor::new(image)).expect("opens");
    let report = ferrosys::DirectorySink::new(&kept)
        .expect("the sink")
        .skip_unsupported()
        .skip_privileged()
        .write_tree(&mut reader)
        .expect("written");
    assert!(kept.join("System").is_dir());
    assert_eq!(
        report
            .fidelity
            .count(ferrosys::Direction::Dropped, Property::BsdFlags),
        1
    );
    std::fs::remove_dir_all(&root).expect("cleaned up");
}

#[test]
fn an_image_with_paths_added_and_removed_is_written_as_composed() {
    let mut base = tree().into_entries();
    base.extend(hidden());
    let image = apfs(base);

    let overlay = TreeBuilder::new().file("/etc/motd", "hello\n", Metadata::new(0o644, TIME));
    let composed = LayeredSource::new()
        .layer(source_of(image.clone()))
        .remove("/etc/hostname")
        .expect("held")
        .remove("/pipe")
        .expect("held")
        .layer(overlay);
    assert!(
        matches!(
            LayeredSource::new().layer(source_of(image)).remove("/etc/hostnmae"),
            Err(RemovalError::NotHeld { path, .. }) if path == b"/etc/hostnmae"
        ),
        "a misspelled removal"
    );

    let written = apfs(composed);
    let got = held_in(written.clone());
    assert!(!got.contains_key(b"/etc/hostname".as_slice()));
    assert!(!got.contains_key(b"/pipe".as_slice()));
    // The file kept its other name, and that name now holds it alone.
    let again = &got[b"/etc/again".as_slice()];
    assert_eq!(again.bytes.as_deref(), Some(b"ferrosys\n".as_slice()));
    assert_eq!(again.xattrs.len(), 1);
    assert!(!again.shared, "one name left");
    assert_eq!(
        got[b"/etc/motd".as_slice()].bytes.as_deref(),
        Some(b"hello\n".as_slice())
    );
    // What the image recorded beyond the rest travels with its entry through the steps.
    let mut reader = Reader::open(Cursor::new(written)).expect("opens");
    let node = reader.lookup(b"/System").expect("the directory");
    assert_eq!(
        reader.darwin(&node).expect("reads").map(|d| d.bsd_flags),
        Some(HIDDEN)
    );
}

/// A compression header of type 9, which holds the content raw after a marker byte.
fn inline_header(content: &[u8]) -> Vec<u8> {
    let mut header = b"fpmc".to_vec();
    header.extend_from_slice(&9u32.to_le_bytes());
    header.extend_from_slice(&(content.len() as u64).to_le_bytes());
    header.push(0xCC);
    header.extend_from_slice(content);
    header
}

/// A compression header of type 10, and its resource fork: one chunk's offset and the end's,
/// then the chunk, raw after a marker byte.
fn fork_form(content: &[u8]) -> CompressedFile {
    let mut header = b"fpmc".to_vec();
    header.extend_from_slice(&10u32.to_le_bytes());
    header.extend_from_slice(&(content.len() as u64).to_le_bytes());
    let mut fork = 8u32.to_le_bytes().to_vec();
    fork.extend_from_slice(&(8 + 1 + content.len() as u32).to_le_bytes());
    fork.push(0xCC);
    fork.extend_from_slice(content);
    CompressedFile::new(header, Some(fork))
}

#[test]
fn a_compressed_file_passes_through_as_stored_and_reads_as_its_content() {
    let small = b"held after the header".to_vec();
    let medium = vec![b'm'; 400];
    let forked = vec![b'f'; 5000];
    let meta = Metadata::new(0o644, TIME);
    let file = |path: &str, content: &[u8], form: CompressedFile| {
        SourceEntry::new(path, EntryKind::File(content.to_vec().into()), meta)
            .with_darwin(Darwin::new(0).compressed(form))
    };
    let entries = vec![
        file(
            "/small",
            &small,
            CompressedFile::new(inline_header(&small), None),
        ),
        file(
            "/medium",
            &medium,
            CompressedFile::new(inline_header(&medium), None),
        ),
        file("/forked", &forked, fork_form(&forked)),
    ];
    let image = apfs(entries.clone());
    let mut reader = Reader::open(Cursor::new(image.clone())).expect("opens");
    assert!(reader.scan().anomalies().is_empty());
    for entry in &entries {
        let node = reader.lookup(&entry.path).expect("the file");
        let EntryKind::File(content) = &entry.kind else {
            unreachable!()
        };
        assert_eq!(
            reader.read_data(&node).expect("reads"),
            content.read().expect("held").as_ref()
        );
        // The stored form is the one given, whole, and the file says it is compressed.
        let darwin = reader.darwin(&node).expect("reads").expect("a Darwin part");
        assert_eq!(darwin.bsd_flags, Darwin::COMPRESSED);
        assert_eq!(
            &darwin.compressed,
            &entry.darwin.as_ref().unwrap().compressed
        );
        assert_eq!(node.value.uncompressed_size, content.len());
        assert!(node.stream.is_none(), "no data stream");
    }

    // Read back and written again it is the same; written to ext it is its content, decoded,
    // since the compressed form is how the content is stored and not a property of it.
    let again = held_in(apfs(source_of(image.clone())));
    assert_eq!(again, held_in(image.clone()));
    let decoded = held_in(ext(source_of(image)).expect("ext formats it"));
    for (path, content) in [("/small", small), ("/medium", medium), ("/forked", forked)] {
        assert_eq!(
            decoded[path.as_bytes()].bytes.as_deref(),
            Some(content.as_slice())
        );
    }
}
