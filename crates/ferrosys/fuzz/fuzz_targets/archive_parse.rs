#![no_main]

//! Drive the tar archive parser over arbitrary bytes, through both of the ways a caller
//! reaches it. Framing a stream, resolving its PAX records, and locating every member's
//! body must never panic: malformed input is a returned error, not a crash and not an
//! allocation sized from a number the archive claims.
//!
//! Both entry points are driven because they frame the stream differently. The eager
//! parser reads each body and is bounded by the bytes the stream actually yields; the
//! seeking one trusts nothing but the archive's length and must check every offset it
//! computes from a declared size. A PAX `size` record carries a full `u64`, so those
//! computations are exactly where an unrepresentable value would land.

use std::io::{Seek, SeekFrom, Write};

use ferrosys::ext::{ArchiveSource, Source};
use libfuzzer_sys::fuzz_target;

/// The scratch file the seeking parser is pointed at, reused across iterations so a run
/// creates one file rather than millions. The pid keeps parallel fuzzer workers apart.
fn scratch() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ferrosys-fuzz-archive-{}.tar", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    // The eager parser: the whole archive in memory, every body read.
    if let Ok(source) = ArchiveSource::from_reader(data) {
        for entry in source.into_entries() {
            // The entry list is what the model consumes, so the parsed contents are
            // touched rather than only counted.
            let _ = entry.path.len();
            let _ = entry.xattrs.len();
        }
    }

    // The seeking parser: bodies left on disk, each located by an offset the parser
    // computed and must have checked against the archive's length.
    let path = scratch();
    let Ok(mut file) = std::fs::File::create(&path) else {
        return;
    };
    if file.write_all(data).is_err() || file.set_len(data.len() as u64).is_err() {
        return;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    drop(file);
    if let Ok(source) = ArchiveSource::from_path(&path) {
        for entry in source.into_entries() {
            // Reading a located body is what turns a bad offset or length into an
            // allocation, so every one the parser handed back is read.
            if let ferrosys::ext::EntryKind::File(content) = &entry.kind {
                let _ = content.len();
                let _ = content.read();
            }
        }
    }
});
