#![no_main]

//! Drive the btrfs reader over arbitrary bytes. Opening a filesystem, walking every tree,
//! resolving a path, reading a file, verifying its data, and a whole-filesystem scan must never
//! panic: every malformed input is a returned error, not a crash.
//!
//! This family has more parseable structure per byte than any other here — a logical address
//! space translated through a chunk map, B-trees of items whose offsets index backward from a
//! block's end, and records packed several to an item — so both layers are driven. `Volume` is
//! the address space and the trees on it; `Reader` is the filesystem view built on it, and an
//! input that gets past the first does not necessarily get past the second.

use std::io::Cursor;

use ferrosys::btrfs::{Reader, Volume};
use ferrosys::{OpenOptions, ReadPolicy};
use libfuzzer_sys::fuzz_target;

/// How many bytes of one file the target reads before moving on. A file's declared length is a
/// number the image supplied and a hole reads back as zeros, so an inode claiming a terabyte
/// costs a terabyte of them — which is a bound the caller sets rather than a bug.
const READ_CAP: u64 = 1 << 16;

fuzz_target!(|data: &[u8]| {
    // The lower layer alone, leniently: opening reads every superblock copy, the bootstrap
    // array, and the chunk tree through it, so a crafted image is driven through the map every
    // later read goes past before a caller has asked for anything.
    if let Ok(mut volume) = Volume::open_with(
        Cursor::new(data),
        OpenOptions::new().policy(ReadPolicy::Lenient),
    ) {
        let _ = volume.mirrors();
        let _ = volume.chunk_map().len();
        if let Ok(roots) = volume.tree_roots() {
            for root in roots {
                // Every block of every tree, which verifies each one's checksum and drives the
                // item bounds and the leaf packing check on the way past.
                let _ = volume.tree(root).for_each_block(|_| true);
                let _ = volume.tree(root).count_items();
            }
        }
    }

    // The filesystem view, strictly, capped: this is the block that gathers whole files, so
    // the cap has to be on the reader that does it — a cap built and not applied leaves
    // `read_data` trusting whatever length the input declares.
    let limits = ferrosys::Limits::new().max_file_bytes(READ_CAP);
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new().limits(limits),
    ) {
        let _ = reader.subvolumes().len();
        let _ = reader.default_subvolume();
        if let Ok(entries) = reader.walk() {
            for e in &entries {
                let _ = reader.read_data(&e.node);
                let _ = reader.xattrs(&e.node);
                let _ = reader.verify_data(&e.node);
                let _ = reader.link_target(&e.node);
            }
            // Resolution goes through the name hash rather than the bytes, so a lookup drives
            // a descent per component past whatever the walk reached.
            for e in &entries {
                let _ = reader.lookup(&e.path);
            }
        }
        // Paths the filesystem never had, so resolution is driven past what a walk found.
        for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./", b"/\xff\xfe"] {
            let _ = reader.lookup(path);
        }
    }

    // Leniently and under a cap, which is what reaches the scan: it walks every tree and
    // collects rather than stopping, so it reads structures a strict open refuses to look at.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new()
            .policy(ReadPolicy::Lenient)
            .limits(limits),
    ) {
        let report = reader.scan();
        // The projections too: a finding's coordinates are numbers the image supplied.
        let _ = report.to_report().to_json();
        let _ = report.to_report().to_sarif(Some("fuzz.img"));
        let _ = report.to_report().to_table();
        // Reading from an offset that is not the start of an extent, which is the case the
        // covering-record search exists for.
        if let Ok(entries) = reader.walk() {
            let mut buf = [0u8; 512];
            for e in &entries {
                for at in [0u64, 1, 4095, 1 << 20, u64::MAX - 1] {
                    let _ = reader.read_into(&e.node, at, &mut buf);
                }
            }
        }
    }

    // At a nonzero base, which exercises the base-relative addressing a filesystem inside a
    // larger image is read through. The superblock is 64 kibibytes in, so a base shifts every
    // location the format defines rather than only the first.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new()
            .base(512)
            .policy(ReadPolicy::Lenient)
            .limits(limits),
    ) {
        let _ = reader.scan();
        let _ = reader.walk();
    }
});
