#![no_main]

//! Drive the reader the way the `inspect` command does, over arbitrary bytes. Opening a
//! filesystem, listing every group descriptor, scanning the whole image, and rendering
//! the report as JSON, as a table, and as SARIF must never panic and never allocate from
//! an attacker-controlled count: a crafted superblock can claim billions of groups, so
//! the descriptor list is grown from the descriptors that actually exist, never pre-sized
//! from the claimed count.

use std::io::Cursor;

use ferrosys::ext::{OpenOptions, ReadPolicy, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `inspect` opens leniently: a malformed image is described, not rejected.
    let Ok(mut reader) = Reader::open_with(Cursor::new(data), &OpenOptions::new().policy(ReadPolicy::Lenient)) else {
        return;
    };

    // The group listing, exactly as `inspect --groups` builds it. `group_count()` is a
    // pure function of superblock fields a crafted image can inflate to `u32::MAX`, so
    // the vector must grow as real descriptors are found rather than reserve capacity for
    // the claimed count; `group_descriptor` returns an out-of-range error once the table
    // runs past the source, ending the loop in bytes-of-input time rather than crashing.
    let count = reader.group_count();
    let mut descriptors = Vec::new();
    for g in 0..count {
        match reader.group_descriptor(g) {
            Ok(d) => descriptors.push((g, d)),
            Err(_) => break,
        }
    }

    // The scan and every rendering, as `inspect` produces them: the report is rendered
    // whatever the scan found. The projection into the shared frame is driven too, since
    // it is what converts image-derived block numbers into byte offsets and is therefore
    // reachable by arithmetic a crafted image controls.
    let report = reader.scan();
    let projected = report.to_report();
    // Each rendering walks the findings independently and escapes image-derived text into
    // its own dialect, so all three are driven.
    let _ = projected.to_json();
    let _ = projected.to_table();
    // Both `--sarif` shapes: with the artifact URI the CLI always supplies, and without,
    // which takes the branch that emits a result carrying no `locations` at all.
    let _ = projected.to_sarif(Some("fuzz.img"));
    let _ = projected.to_sarif(None);
    let _ = projected.worst_severity();
    let _ = projected.findings();
    let _ = report.worst_severity();
    let _ = report.anomalies();
    let _ = reader.feature();
    let _ = reader.superblock();
});
