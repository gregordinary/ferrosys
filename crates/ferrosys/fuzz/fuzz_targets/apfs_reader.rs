#![no_main]

//! Drive the APFS reader over arbitrary bytes. Opening a container, reading every volume it
//! lists, walking one, resolving a path, reading a file, listing and opening its snapshots, and
//! a whole-volume scan must never panic: every malformed input is a returned error, not a
//! crash.
//!
//! Both layers are driven. `Container` is the checkpoint, the object map and the volumes it
//! lists; `Reader` is one volume read as files through its own object map and tree, and an
//! input that gets past the first does not necessarily get past the second.
//!
//! Every volume is read under both policies at the start of the input. A lenient read is the
//! one the command line falls back to, and the only one that reaches a container whose block
//! zero is damaged or whose newer checkpoints were passed over; a strict one reaches the
//! refusals each rule makes. Each snapshot is opened through its own volume's reader. A file's
//! content is read under a cap, and everything a read bounds without one — attribute values,
//! link targets, the scan — is read again with none.

use std::io::Cursor;

use ferrosys::apfs::{Container, OpenOptions, Reader, VolumeEntry};
use ferrosys::ReadPolicy;
use libfuzzer_sys::fuzz_target;

/// How many bytes of one file the target reads before moving on. A file's declared length is a
/// number the image supplied and a hole reads back as zeros, so an inode claiming a terabyte
/// costs a terabyte of them — which is a bound the caller sets rather than a bug.
const READ_CAP: u64 = 1 << 16;

/// Open `volume` of the container at the start of `data` under `common`.
fn reader_of<'d>(
    data: &'d [u8],
    common: ferrosys::OpenOptions,
    volume: &VolumeEntry,
) -> Option<Reader<Cursor<&'d [u8]>>> {
    let container = Container::open_with(Cursor::new(data), &common).ok()?;
    Reader::over(container, volume.clone()).ok()
}

/// Read everything a caller can ask of one volume, its file content under the cap `common`
/// carries.
fn drive(reader: &mut Reader<Cursor<&[u8]>>) {
    if let Ok(entries) = reader.walk() {
        let mut buf = [0u8; 512];
        for e in &entries {
            let _ = reader.read_data(&e.node);
            let _ = reader.xattrs(&e.node);
            let _ = reader.link_target(&e.node);
            for at in [0u64, 1, 4095, 65_535, 1 << 20, u64::MAX - 1] {
                let _ = reader.read_into(&e.node, at, &mut buf);
            }
        }
        for e in &entries {
            let _ = reader.lookup(&e.path);
        }
    }
    for path in [&b"/"[..], b"/../..", b"/a/b/c", b"//./", b"/\xff\xfe"] {
        let _ = reader.lookup(path);
    }
    let report = reader.scan();
    let _ = report.to_report().to_json();
    let _ = report.to_report().to_sarif(Some("fuzz.img"));
    let _ = report.to_report().to_table();
}

fuzz_target!(|data: &[u8]| {
    let capped = ferrosys::Limits::new().max_file_bytes(READ_CAP);
    let lenient = ferrosys::OpenOptions::new()
        .limits(capped)
        .policy(ReadPolicy::Lenient);

    let Ok(container) = Container::open_with(Cursor::new(data), &lenient) else {
        return;
    };
    let _ = container.unreadable_volumes();
    let volumes = container.volumes().to_vec();
    for volume in &volumes {
        let _ = volume.refusal();
        for policy in [ReadPolicy::Lenient, ReadPolicy::Strict] {
            let common = lenient.policy(policy);
            let Some(mut reader) = reader_of(data, common, volume) else {
                continue;
            };
            drive(&mut reader);
            // Every snapshot the volume lists, read as a view through this volume's reader.
            if let Ok(snapshots) = reader.snapshots() {
                for snapshot in snapshots.iter().take(4) {
                    let Some(reader) = reader_of(data, common, volume) else {
                        break;
                    };
                    if let Ok(mut past) = reader.at_snapshot(&snapshot.name) {
                        drive(&mut past);
                    }
                }
            }
        }
        // With no cap: what a read bounds by the image rather than by the caller.
        let uncapped = lenient.limits(ferrosys::Limits::new());
        if let Some(mut reader) = reader_of(data, uncapped, volume) {
            if let Ok(entries) = reader.walk() {
                for e in &entries {
                    let _ = reader.xattrs(&e.node);
                    let _ = reader.link_target(&e.node);
                }
            }
            let _ = reader.scan();
        }
    }

    // At a nonzero base, which every block address is read relative to.
    if let Ok(mut reader) = Reader::open_with(
        Cursor::new(data),
        &OpenOptions::new().common(lenient.base(512)),
    ) {
        let _ = reader.scan();
        let _ = reader.walk();
    }
});
