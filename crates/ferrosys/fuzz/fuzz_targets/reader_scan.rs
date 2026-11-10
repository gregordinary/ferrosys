#![no_main]

//! Drive the reader over arbitrary bytes. Opening a filesystem, a strict walk, a
//! lenient whole-image scan, checksum verification, and writing a filesystem's
//! contents into an archive must never panic: every malformed input is a returned
//! error, not a crash.
//!
//! Two answers are also held to each other, since a reader that gives one image two
//! answers is wrong in one of them. A file read whole and the same file streamed a
//! window at a time read the same bytes where both read. And a read refused for the
//! image's own bytes is a read of an image the scan does not call clean.

use std::io::Cursor;

use ferrosys::ext::{OpenOptions, ReadPolicy, Reader};
use ferrosys::{ArchiveSink, Limits, TreeError};
use libfuzzer_sys::fuzz_target;

/// What one file may cost this target.
///
/// A regular file's length is a number the image declares, and the default limits trust it
/// so that a sparse file reads as the size it says it is. A fuzzer hands that number
/// arbitrary values, so the cap is set here: without it the target spends its budget
/// allocating rather than reaching the parsers past the allocation.
const READ_CAP: u64 = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::new().max_file_bytes(READ_CAP);

    // At the start of the source: open, then drive every read path.
    if let Ok(mut reader) = Reader::open_with(Cursor::new(data), &OpenOptions::new().limits(limits))
    {
        let _ = reader.verify_checksums();
        let clean = reader.scan().is_clean();
        let _ = reader.journal_superblock();
        // Every inode the walk reaches feeds the data, symlink, and xattr parsers, so a
        // crafted extent tree, symlink, or attribute block is exercised, not just the
        // directory walk. The inodes are collected first to end the walk's borrow.
        if let Ok(entries) = reader.walk() {
            for e in &entries {
                match reader.read_data(&e.inode) {
                    Ok(whole) => {
                        let mut streamed = Vec::new();
                        let read = reader.read_data_to(&e.inode, &mut streamed);
                        assert!(
                            read.is_ok() && streamed == whole,
                            "a file read whole and streamed differ: {read:?}"
                        );
                    }
                    Err(refused) => {
                        let malformed =
                            matches!(TreeError::from(refused.clone()), TreeError::Malformed { .. });
                        assert!(
                            !(malformed && clean),
                            "a read refused for the image's bytes on an image the scan calls \
                             clean: {refused}"
                        );
                    }
                }
                let _ = reader.read_symlink(&e.inode);
                let _ = reader.xattrs(&e.inode);
            }
            // Reading from an offset the caller chose rather than from the start, which is
            // the path a windowed reader takes: the offset decides which block the map is
            // asked for, and every one of those numbers came out of the image.
            let mut buf = [0u8; 512];
            for e in &entries {
                for at in [0u64, 1, 4095, 1 << 20, u64::MAX - 1] {
                    let _ = reader.read_into(&e.inode, at, &mut buf);
                }
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

    // The whole tree through the archive sink, which is the other thing that consumes an
    // untrusted reader: it walks, reads, and turns every name, mode, time, and link target
    // the image supplied into a header. Into memory, bounded by the cap above and by the
    // sink writing only what the reader hands it.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new()
            .policy(ReadPolicy::Lenient)
            .limits(limits),
    ) {
        let mut archive = Vec::new();
        let _ = ArchiveSink::new(&mut archive).write_tree(&mut reader);
    }

    // At a nonzero base offset, exercising the base-relative accessors that read a
    // filesystem embedded inside a larger image.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new()
            .base(512)
            .policy(ReadPolicy::Lenient)
            .limits(limits),
    ) {
        let _ = reader.scan();
    }
});
