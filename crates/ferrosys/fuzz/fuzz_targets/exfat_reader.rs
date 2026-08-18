#![no_main]

//! Drive the exFAT reader over arbitrary bytes. Opening a volume, a strict walk, a lenient
//! whole-volume scan, and every by-node read must never panic: every malformed input is a
//! returned error, not a crash.

use std::io::Cursor;

use ferrosys::exfat::Reader;
use ferrosys::{OpenOptions, ReadPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Strict, at the start of the source: the path a caller takes by default, where a
    // deviation stops the read rather than being collected. Opening alone reads the two boot
    // regions, both their checksums, the root directory's describing entries, and the up-case
    // table the volume folds through — so a crafted image is driven through four structures
    // before a caller has asked for anything.
    if let Ok(mut reader) = Reader::open(Cursor::new(data)) {
        let _ = reader.volume_label();
        if let Ok(entries) = reader.walk() {
            for e in &entries {
                let _ = reader.read_data(&e.node);
            }
            // Resolution goes through the volume's own case folding, which is a table an
            // image supplied — so a lookup drives the decoder as well as the walk.
            for e in &entries {
                let _ = reader.lookup(&e.path);
            }
        }
        // Paths the volume never had, so resolution is driven past what the walk found.
        for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./", b"/\xff\xfe"] {
            let _ = reader.lookup(path);
        }
    }

    // Lenient: the scan, which follows every stream and every entry set and collects rather
    // than stopping — so it reaches structures a strict read refuses before touching, and
    // compares every cluster the tree occupies against the allocation bitmap.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    ) {
        let report = reader.scan();
        // The projections too: a finding's coordinates and byte offset are arithmetic over
        // numbers the image supplied.
        let _ = report.to_report().to_json();
        let _ = report.to_report().to_sarif(Some("fuzz.img"));
        let _ = report.to_report().to_table();
    }

    // At a nonzero base, which exercises the base-relative addressing a volume embedded
    // inside a larger image is read through.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new().base(512).policy(ReadPolicy::Lenient),
    ) {
        let _ = reader.scan();
        let _ = reader.walk();
    }
});
