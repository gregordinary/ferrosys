#![no_main]

//! Drive the FAT reader over arbitrary bytes. Opening a volume, a strict walk, a lenient
//! whole-volume scan, and the table mirror check must never panic: every malformed input is
//! a returned error, not a crash.

use std::io::Cursor;

use ferrosys::fat::{OpenOptions, Reader, ShortNameCharset, Storage};
use ferrosys::ReadPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Strict, at the start of the source: the path a caller takes by default, where a
    // deviation stops the read rather than being collected.
    if let Ok(mut reader) = Reader::open(Cursor::new(data)) {
        let _ = reader.verify_tables();
        let _ = reader.info_sector();
        let _ = reader.volume_label();
        if let Ok(entries) = reader.walk() {
            for e in &entries {
                let _ = reader.read_data(&e.node);
                // The chain walker directly, so a crafted table is followed by the code that
                // bounds it rather than only by the code that reads through it.
                if let Storage::Chain(start) = e.node.storage {
                    let _ = reader.chain(start);
                }
            }
            for e in &entries {
                let _ = reader.lookup(&e.path);
            }
        }
        // Paths the volume never had, so resolution is driven past what the walk found.
        for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./", b"/\xff\xfe"] {
            let _ = reader.lookup(path);
        }
    }

    // Lenient: the scan, which follows every chain and every directory entry and collects
    // rather than stopping — so it reaches structures a strict read refuses before touching.
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

    // With a code page named, which is the branch that turns a short name's bytes into
    // characters, and at a nonzero base offset, which exercises the base-relative accessors
    // that read a volume embedded inside a larger image.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new()
            .base(512)
            .policy(ReadPolicy::Lenient)
            .charset(ShortNameCharset::Cp437),
    ) {
        let _ = reader.scan();
        let _ = reader.walk();
    }
});
