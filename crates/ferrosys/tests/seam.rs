//! The gate for the crate's family-agnostic surface: what a caller reaches without naming
//! a family, driven against the one family there is.
//!
//! Everything here is written in root vocabulary alone — `ferrosys::open`, `ferrosys::FsTree`,
//! `ferrosys::Finding` — and never in `ferrosys::ext::`. That is the point: these cases pass
//! only while the shared surface is genuinely usable without knowing which format answered,
//! and a later family runs the same cases against itself.
//!
//! The one thing here that does name a family is the fixture: an image has to be written by
//! something, and only ext writes one that every case below can read. So the target needs
//! that family even though nothing it asserts does. What a build carrying some other family
//! reaches is pinned by the API snapshots instead, which is the instrument that notices an
//! item gated on the wrong family.
#![cfg(feature = "ext")]

use std::io::Cursor;

use ferrosys::{
    Attributes, Direction, Family, FidelityReport, Filesystem, FsReader, FsTree, Metadata,
    NodeKind, OpenOptions, Property, ReadPolicy, Severity, Synthesis, Timestamp, TreeEntry,
    TreeError, open, open_with,
};

/// A formatted image holding a small tree, built through the ext writer because it is the
/// only writer there is. Nothing below reads it through ext vocabulary.
fn image() -> Vec<u8> {
    use ferrosys::ext::{FormatOptions, TreeBuilder, format};

    let time = Timestamp::from_secs(1_700_000_000);
    let source = TreeBuilder::new()
        .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
        .file(
            b"/etc/hostname".to_vec(),
            b"ferrosys\n".to_vec(),
            Metadata::new(0o644, time).owned_by(0, 42),
        )
        .file(
            b"/etc/issue".to_vec(),
            b"welcome\n".to_vec(),
            Metadata::new(0o600, time),
        )
        .xattr(b"user.note".to_vec(), b"hello".to_vec())
        .symlink(
            b"/etc/mtab".to_vec(),
            b"/proc/mounts".to_vec(),
            Metadata::new(0o777, time),
        )
        .file(
            b"/one".to_vec(),
            b"shared\n".to_vec(),
            Metadata::new(0o644, time),
        )
        .hardlink(
            b"/two".to_vec(),
            b"/one".to_vec(),
            Metadata::new(0o644, time),
        );

    format(
        source,
        16 << 20,
        FormatOptions::new([0x33; 16], time, [0; 16]),
    )
    .expect("format")
    .into_bytes()
}

/// One name a walk reached, as this file compares them.
type Name = (String, NodeKind);
/// One name that shares its node with another, and the identity they share.
type Shared = (String, u64);

/// Every name a walk reached, plus whichever of them share a node.
fn walk<T: FsTree>(tree: &mut T) -> (Vec<Name>, Vec<Shared>) {
    let mut names: Vec<Name> = Vec::new();
    let mut shared: Vec<Shared> = Vec::new();
    tree.walk_tree::<TreeError, _>(|_, entry: TreeEntry<T::Node>| {
        let path = String::from_utf8_lossy(&entry.path).into_owned();
        if let Some(id) = entry.shared {
            shared.push((path.clone(), id));
        }
        names.push((path, entry.kind));
        Ok(())
    })
    .expect("the walk succeeds");
    (names, shared)
}

#[test]
fn opening_an_image_without_naming_a_family_hands_back_the_family_that_claimed_it() {
    let bytes = image();
    let reader = open(Cursor::new(&bytes)).expect("open");
    assert_eq!(reader.family(), Family::Ext);
    // The variant matches what detection says about the same bytes, so the two answers
    // about one image cannot disagree.
    assert_eq!(
        ferrosys::detect(Cursor::new(&bytes)).expect("detect"),
        Filesystem::Ext(ferrosys::ext::Profile::Ext4)
    );
    // The enum is `#[non_exhaustive]`, so a caller matches with a wildcard and adding a
    // family later is not a breaking change.
    match reader {
        FsReader::Ext(mut r) => {
            assert_eq!(r.inode(2).expect("root inode").mode & 0o170000, 0o040000);
        }
        _ => panic!("the ext family claimed the image"),
    }
}

#[test]
fn a_filesystem_inside_a_larger_source_opens_at_the_offset_it_was_given() {
    const BASE: u64 = 1 << 20;
    let mut disk = vec![0u8; BASE as usize];
    disk.extend_from_slice(&image());

    // At the start of the source there is nothing to open, and the failure says so rather
    // than a family's own refusal.
    match open(Cursor::new(&disk)) {
        Err(ferrosys::OpenError::Detect(_)) => {}
        Err(other) => panic!("expected a detection failure, got {other}"),
        Ok(_) => panic!("the head of the disk is not a filesystem"),
    }

    let reader = open_with(Cursor::new(&disk), &OpenOptions::new().base(BASE)).expect("open");
    assert_eq!(reader.family(), Family::Ext);
}

#[test]
fn a_walk_yields_the_root_first_and_then_the_tree_in_order() {
    let bytes = image();
    let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
        panic!("the ext family claimed the image")
    };

    let (names, shared) = walk(&mut reader);
    let paths: Vec<&str> = names.iter().map(|(p, _)| p.as_str()).collect();

    // The root comes first, under the empty path: a sink that has to apply the root's own
    // metadata needs no second way of asking for it.
    assert_eq!(paths[0], "", "the root is the walk's first entry");
    assert_eq!(names[0].1, NodeKind::Directory);

    // Then the tree, parent before child, which is what lets a sink hold one open handle
    // per directory on the current path rather than one per directory in the tree.
    assert!(paths.contains(&"/etc"), "{paths:?}");
    let etc = paths.iter().position(|p| *p == "/etc").expect("/etc");
    let hostname = paths
        .iter()
        .position(|p| *p == "/etc/hostname")
        .expect("/etc/hostname");
    assert!(etc < hostname, "a parent precedes its children: {paths:?}");

    // Each kind reaches the shared frame as itself, sizes and link targets included.
    let kind = |path: &str| names.iter().find(|(p, _)| p == path).expect(path).1;
    assert_eq!(kind("/etc"), NodeKind::Directory);
    assert_eq!(kind("/etc/hostname"), NodeKind::File { size: 9 });
    assert_eq!(kind("/etc/mtab"), NodeKind::Symlink);

    // The two names for one file both carry the same identity, and nothing else carries
    // one — which is what keeps a sink's hard-link table down to the tree's actual links.
    assert_eq!(
        shared.len(),
        2,
        "exactly the two names for one node: {shared:?}"
    );
    assert_eq!(shared[0].1, shared[1].1, "both names name one node");
    let linked: Vec<&str> = shared.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(linked, ["/one", "/two"]);
}

#[test]
fn a_stat_is_complete_and_says_nothing_was_invented() {
    let bytes = image();
    let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
        panic!("the ext family claimed the image")
    };

    let mut seen: Vec<(String, Attributes)> = Vec::new();
    reader
        .walk_tree::<TreeError, _>(|tree, entry| {
            let attrs = tree.stat(&entry.node, &Synthesis::new())?;
            seen.push((String::from_utf8_lossy(&entry.path).into_owned(), attrs));
            Ok(())
        })
        .expect("the walk succeeds");

    let at = |path: &str| {
        &seen
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("{path} was walked"))
            .1
    };

    // ext records every property the shared frame names, so nothing is invented — whatever
    // synthesis inputs the caller supplied.
    for (path, attrs) in &seen {
        assert!(
            attrs.synthesized.is_empty(),
            "{path} reported an invented property: {:?}",
            attrs.synthesized
        );
    }

    let hostname = at("/etc/hostname");
    assert_eq!(hostname.meta.mode, 0o644);
    assert_eq!((hostname.meta.uid, hostname.meta.gid), (0, 42));
    assert_eq!(hostname.meta.mtime, Timestamp::from_secs(1_700_000_000));

    // Attributes come back through the same call, in the boundary form, so a sink never
    // asks a second question to get them.
    let issue = at("/etc/issue");
    assert_eq!(issue.xattrs.len(), 1);
    assert_eq!(issue.xattrs[0].name, b"user.note");
    assert_eq!(issue.xattrs[0].value, b"hello");
    assert!(at("/etc/hostname").xattrs.is_empty());
}

#[test]
fn a_synthesis_input_never_overrides_what_the_image_holds() {
    // The inputs answer for a format that records nothing. A family that records a property
    // ignores them, so an ext image extracts as itself however permissive a caller asked to
    // be — otherwise naming a mode would silently rewrite a whole tree's permissions.
    let bytes = image();
    let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
        panic!("the ext family claimed the image")
    };
    let permissive = Synthesis::new().owner(1000, 1000).modes(0o777, 0o777);

    let root = reader.inode(2).expect("root inode");
    let attrs = reader.stat(&root, &permissive).expect("stat the root");
    assert_eq!(attrs.meta.mode, 0o755, "the image's mode, not the input's");
    assert_eq!((attrs.meta.uid, attrs.meta.gid), (0, 0));
    assert!(attrs.synthesized.is_empty());
}

#[test]
fn a_files_bytes_stream_through_the_shared_surface() {
    let bytes = image();
    let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
        panic!("the ext family claimed the image")
    };

    let mut read: Option<Vec<u8>> = None;
    let mut target: Option<Vec<u8>> = None;
    reader
        .walk_tree::<TreeError, _>(|tree, entry| {
            match entry.kind {
                NodeKind::File { size } if entry.path == b"/etc/hostname" => {
                    // Filled a window at a time, which is what keeps a sink's memory the
                    // size of its buffer rather than of the largest file in the tree.
                    let mut out = Vec::new();
                    let mut buf = [0u8; 4];
                    let mut offset = 0u64;
                    while offset < size {
                        let filled = tree.read_bytes(&entry.node, offset, &mut buf)?;
                        if filled == 0 {
                            break;
                        }
                        out.extend_from_slice(&buf[..filled]);
                        offset += filled as u64;
                    }
                    read = Some(out);
                }
                NodeKind::Symlink => target = Some(tree.link_target(&entry.node)?),
                _ => {}
            }
            Ok(())
        })
        .expect("the walk succeeds");

    assert_eq!(read.expect("/etc/hostname was read"), b"ferrosys\n");
    assert_eq!(target.expect("the symlink was resolved"), b"/proc/mounts");
}

#[test]
fn the_wrong_operation_for_a_node_is_a_typed_error_rather_than_a_wrong_answer() {
    let bytes = image();
    let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
        panic!("the ext family claimed the image")
    };
    // A directory is not a symbolic link, and asking for its target must not read its block
    // area as a path — which is the shape of bug that turns a block pointer into a filename.
    let root = reader.inode(2).expect("root inode");
    let err = reader
        .link_target(&root)
        .expect_err("the root is not a symbolic link");
    assert!(
        matches!(
            err,
            TreeError::Malformed {
                family: Family::Ext,
                ..
            }
        ),
        "expected a malformed-node error, got {err}"
    );
}

#[test]
fn an_inode_naming_no_file_type_stops_the_walk_rather_than_being_guessed_at() {
    // The type nibble of a mode names one of seven things. An image opened leniently — which
    // is what every extraction does, so that a report describes a bad image rather than
    // refusing it — reaches the walk with whatever the bytes said, so a nibble naming none
    // of the seven is the image's claim and not a fact. Resolving it to the nearest kind
    // would turn an unreadable inode into a socket a sink then goes and creates.
    let mut bytes = image();

    // The root inode is the second in the table, and `S_IFDIR` sits in the high nibble of
    // its first field. Find where the table begins the way the image itself says to: the
    // first group descriptor's `bg_inode_table` at offset 0x08, times the block size.
    let block_size = 1usize << (10 + u32::from(bytes[1024 + 0x18]));
    let desc = block_size.max(1024) + if block_size == 1024 { 1024 } else { 0 };
    let table = u32::from_le_bytes([
        bytes[desc + 0x08],
        bytes[desc + 0x09],
        bytes[desc + 0x0a],
        bytes[desc + 0x0b],
    ]) as usize;
    let inode_size = u16::from_le_bytes([bytes[1024 + 0x58], bytes[1024 + 0x59]]) as usize;
    // Inode numbers are one-based, so inode 2 is the second entry in the table.
    let root = table * block_size + inode_size;
    let mode = u16::from_le_bytes([bytes[root], bytes[root + 1]]);
    assert_eq!(mode & 0o170000, 0o040000, "the root inode was located");
    // `0o030000` is not one of the seven types a mode names.
    let broken = (mode & 0o7777) | 0o030000;
    bytes[root..root + 2].copy_from_slice(&broken.to_le_bytes());

    let FsReader::Ext(mut reader) = open_with(
        Cursor::new(&bytes),
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .expect("the image still classifies and opens") else {
        panic!("the ext family claimed the image")
    };

    let err = reader
        .walk_tree::<TreeError, _>(|_, _| Ok(()))
        .expect_err("a node naming no file type stops the walk");
    match err {
        TreeError::Malformed {
            family, ref detail, ..
        } => {
            assert_eq!(family, Family::Ext);
            assert!(detail.contains("file type"), "{detail}");
        }
        other => panic!("expected a malformed-node error, got {other}"),
    }
}

#[test]
fn a_scan_projects_into_the_shared_findings_frame() {
    let bytes = image();
    let FsReader::Ext(mut reader) = open_with(
        Cursor::new(&bytes),
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .expect("open") else {
        panic!("the ext family claimed the image")
    };

    // A sound image this crate wrote is clean in the shared frame as well as in ext's own.
    let report = reader.scan().to_report();
    assert!(report.is_clean(), "{}", report.to_table());
    assert_eq!(report.worst_severity(), None);
    assert!(!report.has_fatal(ReadPolicy::Strict));
    assert_eq!(report.to_table(), "no findings\n");

    // A superblock field the checksum covers, changed: the image parses and is no longer
    // self-consistent, so the scan has something to report through the shared frame.
    let mut damaged = bytes.clone();
    damaged[1024 + 0x30] ^= 0xff;
    let FsReader::Ext(mut reader) = open_with(
        Cursor::new(&damaged),
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .expect("open") else {
        panic!("the ext family claimed the image")
    };
    let report = reader.scan().to_report();
    assert!(!report.is_clean());
    let finding = &report.findings()[0];
    assert_eq!(finding.family, Family::Ext);
    assert_eq!(finding.severity, Severity::Integrity);
    // The subsystem is ext's own word, carried as a string so a later family carries its
    // own rather than borrowing one that means nothing about it.
    assert_eq!(finding.category, "superblock");
    assert!(report.has_fatal(ReadPolicy::Strict));
    // And the rendered documents are the shared ones, so one parser reads every family.
    assert!(report.to_json().contains("\"family\":\"ext\""));
    assert!(
        report
            .to_sarif(None)
            .contains("\"ruleId\":\"ext/superblock\"")
    );
}

#[test]
fn an_extraction_from_a_family_that_records_everything_invents_nothing() {
    // The write side of the fidelity report has no producer for ext, and the read side has
    // one that produces nothing, so an ext extraction is faithful by construction. That is
    // the claim a caller draining an image wants to be able to make.
    let report = FidelityReport::new();
    assert!(report.is_faithful());
    assert_eq!(report.count(Direction::Synthesized, Property::Ownership), 0);

    #[cfg(feature = "tar")]
    {
        use ferrosys::ArchiveSink;

        let bytes = image();
        let FsReader::Ext(mut reader) = open(Cursor::new(&bytes)).expect("open") else {
            panic!("the ext family claimed the image")
        };
        let mut archive = Vec::new();
        let fidelity = ArchiveSink::new(&mut archive)
            // Named deliberately: an image that records everything must report nothing
            // invented even when a caller has said what to invent.
            .synthesis(Synthesis::new().owner(1000, 1000).modes(0o777, 0o777))
            .write_tree(&mut reader)
            .expect("write the archive");
        assert!(
            fidelity.is_faithful(),
            "an ext image lost nothing:\n{}",
            fidelity.to_table()
        );
        assert!(!archive.is_empty());
    }
}

#[test]
fn every_committed_fuzz_seed_still_opens_and_walks_without_naming_a_family() {
    // A seed is the one part of the fuzzing setup with no compiler to catch its drift, so
    // it is checked rather than assumed. Written in root vocabulary, which is what lets one
    // case cover every family's seeds: whichever claims an image, the walk is the same four
    // operations.
    let mut checked = 0usize;
    for family in ["reader_scan", "reader_inspect", "fat_reader"] {
        let dir = std::path::Path::new("fuzz/seeds").join(family);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // A directory only present in a build that compiles that family in.
            continue;
        };
        for entry in entries {
            let path = entry.expect("read the seed directory").path();
            if path.extension().is_none_or(|e| e != "img") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("read the seed");
            let name = path.display().to_string();
            let reader = open_with(
                Cursor::new(&bytes),
                // Leniently, because a seed may deliberately be an image a strict read
                // refuses — that is the whole point of some of them.
                &OpenOptions::new().policy(ReadPolicy::Lenient),
            )
            .unwrap_or_else(|e| panic!("{name} is no longer a readable image: {e}"));
            let names = match reader {
                FsReader::Ext(mut r) => walk(&mut r).0,
                #[cfg(feature = "fat")]
                FsReader::Fat(mut r) => walk(&mut r).0,
                _ => panic!("{name}: no compiled-in family claimed a committed seed"),
            };
            assert_eq!(names[0].0, "", "{name}: the root is the walk's first entry");
            checked += 1;
        }
    }
    assert!(checked >= 7, "only {checked} seeds were checked");
}

/// The same claims the cases above make of the ext family, made of the FAT family.
///
/// This is what the shared surface was built for and the only way to find out whether it
/// holds: the two families agree on almost nothing — one has inodes, link counts, owners,
/// modes, symbolic links, and extended attributes, and the other has none of the six — so a
/// surface that reads both without a `match` is a surface that abstracted the right things.
#[cfg(feature = "fat")]
mod fat {
    use super::{Name, Shared, walk};
    use ferrosys::{
        Family, FsReader, FsTree, Metadata, NodeKind, OpenOptions, Property, ReadPolicy, Severity,
        Synthesis, Timestamp, TreeBuilder, TreeError, open, open_with,
    };
    use std::io::Cursor;

    /// The same shape of tree the ext fixture holds, less what FAT cannot represent: no
    /// symbolic link, no hard link, no extended attribute, and no ownership.
    fn image() -> Vec<u8> {
        use ferrosys::fat::{FatType, FatTypeRequest, FormatOptions, PlanRequest, format};

        let time = Timestamp::from_secs(1_700_000_000);
        let source = TreeBuilder::new()
            .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
            .file(
                b"/etc/hostname".to_vec(),
                b"ferrosys\n".to_vec(),
                Metadata::new(0o644, time),
            )
            .file(
                b"/etc/issue".to_vec(),
                b"welcome\n".to_vec(),
                // Read-only, which is the one permission bit the format holds.
                Metadata::new(0o444, time),
            );

        format(
            source,
            16 << 20,
            FormatOptions::new(0x1234_abcd, time)
                .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16))),
        )
        .expect("format")
        .into_bytes()
    }

    fn reader(bytes: &[u8]) -> ferrosys::fat::Reader<Cursor<&[u8]>> {
        match open(Cursor::new(bytes)).expect("open") {
            FsReader::Fat(r) => r,
            _ => panic!("the FAT family claimed the image"),
        }
    }

    #[test]
    fn opening_an_image_without_naming_a_family_hands_back_the_family_that_claimed_it() {
        let bytes = image();
        let handle = open(Cursor::new(&bytes)).expect("open");
        assert_eq!(handle.family(), Family::Fat);
        assert_eq!(
            ferrosys::detect(Cursor::new(&bytes)).expect("detect"),
            ferrosys::Filesystem::Fat(ferrosys::fat::FatType::Fat16)
        );
        // The concrete reader behind the variant is FAT's whole surface, not a narrowed one.
        match handle {
            FsReader::Fat(r) => assert_eq!(r.layout().fat_type, ferrosys::fat::FatType::Fat16),
            _ => panic!("the FAT family claimed the image"),
        }
    }

    #[test]
    fn a_walk_yields_the_root_first_and_then_the_tree_in_order() {
        let bytes = image();
        let mut r = reader(&bytes);
        let (names, shared): (Vec<Name>, Vec<Shared>) = walk(&mut r);
        let paths: Vec<&str> = names.iter().map(|(p, _)| p.as_str()).collect();

        assert_eq!(paths[0], "", "the root is the walk's first entry");
        assert_eq!(names[0].1, NodeKind::Directory);

        let etc = paths.iter().position(|p| *p == "/etc").expect("/etc");
        let hostname = paths
            .iter()
            .position(|p| *p == "/etc/hostname")
            .expect("/etc/hostname");
        assert!(etc < hostname, "a parent precedes its children: {paths:?}");

        let kind = |path: &str| names.iter().find(|(p, _)| p == path).expect(path).1;
        assert_eq!(kind("/etc"), NodeKind::Directory);
        assert_eq!(kind("/etc/hostname"), NodeKind::File { size: 9 });

        // Nothing shares a node, and that is a fact about the format rather than about this
        // tree: FAT has no second name for a file, so a sink's hard-link table stays empty
        // whatever it is draining.
        assert!(shared.is_empty(), "{shared:?}");
    }

    #[test]
    fn a_stat_is_complete_and_says_exactly_what_was_invented() {
        // The mirror of the ext case. ext records every property the frame names and invents
        // nothing; FAT records almost none and must say so, entry by entry — which is what
        // lets one sink write host files out of either without knowing which it drained.
        let bytes = image();
        let mut r = reader(&bytes);
        let synthesis = Synthesis::new().owner(1000, 1000).modes(0o644, 0o755);

        let mut seen = Vec::new();
        r.walk_tree::<TreeError, _>(|tree, entry| {
            let attrs = tree.stat(&entry.node, &synthesis)?;
            seen.push((String::from_utf8_lossy(&entry.path).into_owned(), attrs));
            Ok(())
        })
        .expect("the walk succeeds");

        let at = |path: &str| {
            &seen
                .iter()
                .find(|(p, _)| p == path)
                .unwrap_or_else(|| panic!("{path} was walked"))
                .1
        };

        // The caller's values, because the volume holds none — and named, so nothing is
        // passed off as read.
        let hostname = at("/etc/hostname");
        assert_eq!((hostname.meta.uid, hostname.meta.gid), (1000, 1000));
        assert_eq!(hostname.meta.mode, 0o644);
        assert!(
            hostname.meta.mtime.secs > 0,
            "the volume does record a time"
        );
        for property in [
            Property::Ownership,
            Property::Permissions,
            Property::ChangeTime,
        ] {
            assert!(
                hostname.synthesized.contains(&property),
                "{property:?} was invented and not reported: {:?}",
                hostname.synthesized
            );
        }
        // A directory takes the directory mode, so a tree does not extract unsearchable.
        assert_eq!(at("/etc").meta.mode, 0o755);

        // The one permission bit the format does hold clears the write bits of whatever the
        // caller named, so a read-only file does not extract writable.
        assert_eq!(at("/etc/issue").meta.mode, 0o444);

        // No extended attributes on any node, which is the format having none rather than
        // this tree having none.
        assert!(seen.iter().all(|(_, a)| a.xattrs.is_empty()));
    }

    #[test]
    fn a_files_bytes_stream_through_the_shared_surface() {
        let bytes = image();
        let mut r = reader(&bytes);
        let mut read: Option<Vec<u8>> = None;
        r.walk_tree::<TreeError, _>(|tree, entry| {
            if let NodeKind::File { size } = entry.kind
                && entry.path == b"/etc/hostname"
            {
                let mut out = Vec::new();
                let mut buf = [0u8; 4];
                let mut offset = 0u64;
                while offset < size {
                    let filled = tree.read_bytes(&entry.node, offset, &mut buf)?;
                    if filled == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..filled]);
                    offset += filled as u64;
                }
                read = Some(out);
            }
            Ok(())
        })
        .expect("the walk succeeds");
        assert_eq!(read.expect("/etc/hostname was read"), b"ferrosys\n");
    }

    #[test]
    fn the_wrong_operation_for_a_node_is_a_typed_error_rather_than_a_wrong_answer() {
        // No node a FAT walk yields is a symbolic link, so asking for a target is always the
        // wrong question — and it must be answered as one rather than by reading a directory
        // entry's bytes as a path.
        let bytes = image();
        let mut r = reader(&bytes);
        let root = r.root();
        let err = r
            .link_target(&root)
            .expect_err("a FAT volume holds no symbolic links");
        assert!(
            matches!(
                err,
                TreeError::Malformed {
                    family: Family::Fat,
                    ..
                }
            ),
            "expected a malformed-node error, got {err}"
        );
    }

    #[test]
    fn a_scan_projects_into_the_shared_findings_frame() {
        let bytes = image();
        let mut r = reader(&bytes);
        let report = r.scan().to_report();
        assert!(report.is_clean(), "{}", report.to_table());
        assert_eq!(report.to_table(), "no findings\n");

        // The mirror, damaged: a copy of the allocation table that no longer matches the
        // first. FAT carries no checksums, so this is what integrity means here — and it
        // reaches the shared frame at the same severity an ext checksum failure does.
        let mut damaged = bytes.clone();
        let second = {
            let layout = *reader(&bytes).layout();
            layout.fat_start_sector(1).expect("two tables") as usize
                * layout.bytes_per_sector as usize
        };
        damaged[second + 8] ^= 0xFF;

        let FsReader::Fat(mut r) = open_with(
            Cursor::new(&damaged),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("open") else {
            panic!("the FAT family claimed the image")
        };
        let report = r.scan().to_report();
        assert!(!report.is_clean());
        let finding = report
            .findings()
            .iter()
            .find(|f| f.severity == Severity::Integrity)
            .expect("an integrity finding");
        assert_eq!(finding.family, Family::Fat);
        // FAT's own subsystem word, which means nothing about ext — the reason a category
        // stays with its family rather than hoisting into the shared frame.
        assert_eq!(finding.category, "allocation table");
        assert!(report.has_fatal(ReadPolicy::Strict));
        assert!(report.to_json().contains("\"family\":\"fat\""));
        assert!(
            report
                .to_sarif(None)
                .contains("\"ruleId\":\"fat/allocation table\"")
        );
    }

    #[test]
    fn an_extraction_from_a_family_that_records_nothing_reports_what_it_invented() {
        // The mirror of the ext case, and the reason the fidelity report carries both
        // directions in one type: a caller draining a FAT image into an archive is asking
        // the same question a caller writing a tree into one asks, from the other side.
        #[cfg(feature = "tar")]
        {
            // Named flat, which is the whole point: the sink is generic over `FsTree` and
            // drains any family, so extracting a FAT volume names no family at all.
            use ferrosys::ArchiveSink;
            use ferrosys::Direction;

            let bytes = image();
            let mut r = reader(&bytes);
            let mut archive = Vec::new();
            let fidelity = ArchiveSink::new(&mut archive)
                .synthesis(Synthesis::new().owner(0, 0).modes(0o644, 0o755))
                .write_tree(&mut r)
                .expect("write the archive");
            assert!(!archive.is_empty());
            assert!(
                !fidelity.is_faithful(),
                "a FAT extraction invents an owner and a mode for every node"
            );
            assert!(
                fidelity.count(Direction::Synthesized, Property::Ownership) > 0,
                "{}",
                fidelity.to_table()
            );
        }
    }
}
