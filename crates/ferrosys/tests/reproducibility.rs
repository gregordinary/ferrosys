//! Byte-reproducibility gate: the same source and options format to the same bytes.
//!
//! Reproducible output is the crate's headline guarantee — the UUID, hash seed, and
//! timestamps are inputs, never read from a clock or a random source, so two formats
//! of one input are byte-for-byte identical. These are pure-crate checks; they need
//! no host tools.

#![cfg(feature = "ext")]

use ferrosys::ext::Timestamp;
use ferrosys::ext::{
    FeatureSet, FormatOptions, GrowReservation, Metadata, TreeBuilder, format, format_to,
};

const MIB: u64 = 1024 * 1024;
const TIME: i64 = 1_700_000_000;

/// A representative tree: files, a directory, and both symlink forms, enough that the
/// image carries inodes, extents, and directory blocks rather than only fixed
/// metadata.
fn source() -> TreeBuilder {
    let time = Timestamp::from_secs(TIME);
    let m = |mode| Metadata::new(mode, time);
    TreeBuilder::new()
        .directory(b"/etc".to_vec(), m(0o755))
        .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
        .file(b"/etc/motd".to_vec(), vec![b'x'; 20_000], m(0o644))
        .symlink(
            b"/etc/mtab".to_vec(),
            b"/proc/self/mounts".to_vec(),
            m(0o777),
        )
}

fn options() -> FormatOptions {
    let mut o = FormatOptions::new([0x11; 16], Timestamp::from_secs(TIME), [0u8; 16]);
    o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
    o
}

#[test]
fn formatting_the_same_source_twice_yields_identical_bytes() {
    // The core guarantee: nothing but the inputs decides a byte.
    let first = format(source(), 64 * MIB, options()).expect("first format");
    let second = format(source(), 64 * MIB, options()).expect("second format");
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "two formats of one source differ"
    );
}

#[test]
fn reproducibility_holds_at_every_block_size() {
    // The geometry differs per block size, but each is deterministic on its own.
    for bs in [1024u32, 2048, 4096] {
        let mut o = options();
        o.feature = FeatureSet::default().with_block_size(bs);
        let first = format(source(), 128 * MIB, o).expect("first");
        let second = format(source(), 128 * MIB, o).expect("second");
        assert_eq!(
            first.as_bytes(),
            second.as_bytes(),
            "{bs}-byte-block formats differ"
        );
    }
}

#[test]
fn the_streaming_and_collecting_paths_agree_across_runs() {
    // `format_to` streams and `format` collects, yet both obey the same plan, so a
    // streamed image equals a collected one and equals itself on a second run.
    let collected = format(source(), 64 * MIB, options()).expect("collect");

    let mut a = std::io::Cursor::new(Vec::new());
    format_to(source(), 64 * MIB, options(), &mut a).expect("stream a");
    let mut b = std::io::Cursor::new(Vec::new());
    format_to(source(), 64 * MIB, options(), &mut b).expect("stream b");

    assert_eq!(a.get_ref(), b.get_ref(), "two streamed images differ");
    assert_eq!(
        a.into_inner(),
        collected.as_bytes(),
        "the streamed image differs from the collected one"
    );
}

#[test]
fn the_fixed_time_clamp_makes_output_independent_of_source_timestamps() {
    // With `fixed_time` set, every inode time is forced to it, so two sources that
    // differ only in their entry timestamps format to identical bytes.
    let clamp = Timestamp::from_secs(1_600_000_000);
    let build = |entry_secs: i64| {
        let m = Metadata::new(0o644, Timestamp::from_secs(entry_secs));
        let src = TreeBuilder::new()
            .directory(
                b"/d".to_vec(),
                Metadata::new(0o755, Timestamp::from_secs(entry_secs)),
            )
            .file(b"/d/f".to_vec(), b"data\n".to_vec(), m);
        let mut o = options();
        o.fixed_time = Some(clamp);
        format(src, 64 * MIB, o).expect("format")
    };
    assert_eq!(
        build(TIME).as_bytes(),
        build(TIME + 999_999).as_bytes(),
        "the fixed-time clamp did not erase the source timestamp difference"
    );
}
