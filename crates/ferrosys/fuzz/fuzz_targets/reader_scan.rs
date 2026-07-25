#![no_main]

//! Drive the reader over arbitrary bytes. Opening a filesystem, a strict walk, a
//! lenient whole-image scan, and checksum verification must never panic: every
//! malformed input is a returned error, not a crash.

use std::io::Cursor;

use ferrosys::ext::{OpenOptions, ReadPolicy, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // At the start of the source: open, then drive every read path.
    if let Ok(mut reader) = Reader::open(Cursor::new(data)) {
        let _ = reader.verify_checksums();
        let _ = reader.scan();
        let _ = reader.journal_superblock();
        // Every inode the walk reaches feeds the data, symlink, and xattr parsers, so a
        // crafted extent tree, symlink, or attribute block is exercised, not just the
        // directory walk. The inodes are collected first to end the walk's borrow.
        if let Ok(entries) = reader.walk() {
            for e in &entries {
                let _ = reader.read_data(&e.inode);
                let _ = reader.read_symlink(&e.inode);
                let _ = reader.xattrs(&e.inode);
            }
            // Resolve every path the walk found, which drives the symlink expansion over
            // whatever link targets the image happens to contain — a cycle, a chain, or a
            // target that is itself a path into the same crafted tree.
            for e in &entries {
                let _ = reader.lookup(&e.path);
                let _ = reader.lookup_no_follow(&e.path);
            }
        }
        // Paths the image never had, so resolution is driven past what the walk found.
        for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./"] {
            let _ = reader.lookup(path);
        }
    }

    // At a nonzero base offset, exercising the base-relative accessors that read a
    // filesystem embedded inside a larger image.
    if let Ok(mut reader) = Reader::open_with(Cursor::new(data), &OpenOptions::new().base(512).policy(ReadPolicy::Lenient)) {
        let _ = reader.scan();
    }
});
