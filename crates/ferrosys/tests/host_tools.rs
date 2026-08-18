//! Host-tool validation gates: `e2fsck`, the `mke2fs`/`dumpe2fs` differential
//! oracle, and the offline `resize2fs` matrix.
//!
//! These shell out to `e2fsprogs` with no crate binding. Each gate declares the
//! tool it needs and, when that tool is absent, prints a loud banner and returns
//! rather than asserting success — a skipped gate is reported, never silently
//! green. With `e2fsprogs` on `PATH` (as in CI) the gates run in
//! full.

#![cfg(feature = "ext")]

mod util;

use std::io::{self, Read as _, Seek as _, Write as _};
use std::num::NonZeroU64;
use std::path::Path;

use util::{available, e2fsck_clean, tool};

use ferrosys::Slack;
use ferrosys::ext::Timestamp;
use ferrosys::ext::{
    Compat, FormatOptions, FormatPlan, GrowReservation, IdentityChange, IdentityError, Image,
    Incompat, InodeCount, LayeredSource, Metadata, OpenOptions, Profile, Reader, ReservedRatio,
    RoCompat, Source, TreeBuilder, format, format_to, rewrite_identity,
};
use ferrosys::{Acl, AclEntry, AclQualifier};

const MIB: u64 = 1024 * 1024;
const GROW_TARGET: u64 = 32 * 1024 * MIB;
/// The reserved-GDT-sizing input in blocks, for the `mke2fs` baseline's `-E resize=`.
const RESIZE_BLOCKS: u64 = GROW_TARGET / 4096;
const UUID: [u8; 16] = [
    0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
];
const FAKE_TIME: u64 = 1_700_000_000;

fn options() -> FormatOptions {
    let mut o = FormatOptions::new(UUID, Timestamp::from_secs(FAKE_TIME as i64), [0u8; 16]);
    o.grow = GrowReservation::UpTo(GROW_TARGET);
    o
}

/// Options with the journal cleared from the feature set. The journal is a data
/// file whose placement ferrosys does not mimic from mke2fs, so a gate that compares
/// the geometry-determined uninit-BG accounting builds both sides without one to keep
/// journal placement from perturbing which groups are dataless.
fn options_no_journal() -> FormatOptions {
    let mut o = options();
    // The orphan file's entries are journalled, so it goes when the journal does — which
    // is what mke2fs does with its own baseline, whatever the configuration asks for.
    o.feature.compat = Compat::from_bits(
        o.feature.compat.bits() & !(Compat::HAS_JOURNAL.bits() | Compat::ORPHAN_FILE.bits()),
    );
    o
}

/// Build the standard populated tree exercising the fidelity list: files,
/// directories, ownership and modes, fast and slow symlinks, a hard link, device /
/// FIFO / socket nodes, and both inline and external-block extended attributes.
fn populated() -> TreeBuilder {
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    let m = |mode| Metadata::new(mode, time);
    TreeBuilder::new()
        .directory(b"/etc".to_vec(), m(0o755))
        .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), m(0o644))
        .symlink(
            b"/etc/mtab".to_vec(),
            b"/proc/self/mounts".to_vec(),
            m(0o777),
        )
        .directory(b"/bin".to_vec(), m(0o755))
        .file(b"/bin/sh".to_vec(), vec![0x7f; 5000], m(0o755))
        // An inline capability attribute, as a package-built rootfs carries.
        .xattr(
            b"security.capability".to_vec(),
            vec![
                0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .hardlink(b"/bin/dash".to_vec(), b"/bin/sh".to_vec(), m(0o755))
        .directory(b"/home".to_vec(), m(0o755))
        .directory(b"/home/user".to_vec(), m(0o700).owned_by(1000, 1000))
        // Access and default POSIX ACLs, stored as system.posix_acl_* attributes.
        .xattr(Acl::ACCESS_NAME.to_vec(), access_acl())
        .xattr(Acl::DEFAULT_NAME.to_vec(), default_acl())
        .file(
            b"/home/user/notes".to_vec(),
            vec![b'n'; 40_000],
            m(0o644).owned_by(1000, 1000),
        )
        // A value too large for the inode spills to an external xattr block, whose
        // name/value hash e2fsck validates.
        .xattr(b"user.big".to_vec(), vec![0xcd; 400])
        .symlink(
            b"/home/user/link".to_vec(),
            vec![b'p'; 120],
            m(0o777).owned_by(1000, 1000),
        )
        .directory(b"/dev".to_vec(), m(0o755))
        .char_device(b"/dev/null".to_vec(), 1, 3, m(0o666))
        .block_device(b"/dev/sda".to_vec(), 8, 0, m(0o660))
        .fifo(b"/dev/initctl".to_vec(), m(0o600))
        .socket(b"/dev/log".to_vec(), m(0o666))
}

/// A non-minimal access ACL (owner rwx, a named user, owning group, mask, other) —
/// the shape a package that grants a service account access produces.
fn access_acl() -> Vec<u8> {
    Acl::new(vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: Acl::READ | Acl::WRITE | Acl::EXEC,
        },
        AclEntry {
            who: AclQualifier::User(1000),
            perm: Acl::READ | Acl::WRITE,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: Acl::READ | Acl::EXEC,
        },
        AclEntry {
            who: AclQualifier::Mask,
            perm: Acl::READ | Acl::WRITE | Acl::EXEC,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: Acl::READ,
        },
    ])
    .expect("valid access ACL")
    .encode()
}

/// A minimal default ACL inherited by new entries in the directory.
fn default_acl() -> Vec<u8> {
    Acl::new(vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: Acl::READ | Acl::WRITE | Acl::EXEC,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: Acl::READ | Acl::EXEC,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: Acl::READ | Acl::EXEC,
        },
    ])
    .expect("valid default ACL")
    .encode()
}

/// Write an image to a scratch file and return the temp file holding it.
fn write_image(image: &Image) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().expect("temp file");
    image.write_to(f.as_file()).expect("write image");
    f
}

/// Format straight into a temp file, streaming the image rather than assembling it in
/// memory first. A gate that only needs a path for a host tool uses this: a
/// multi-gigabyte case would otherwise hold the whole image in RAM, and hold it twice
/// over while the file is written, which several such gates running in parallel can
/// exhaust. The written file stays sparse, so only the used blocks occupy space.
fn format_file(
    source: impl Source,
    size_bytes: u64,
    options: FormatOptions,
) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().expect("temp file");
    format_to(source, size_bytes, options, f.as_file()).expect("format");
    f
}

#[test]
fn e2fsck_gate() {
    if !available("e2fsck") {
        return;
    }
    // Empty and populated, across single-group, multi-group-with-backups, and a
    // full flex block group.
    for (mib, populate) in [
        (64u64, false),
        (64, true),
        (200, true),  // partial final group
        (512, true),  // backups at groups 1 and 3
        (2048, true), // a full 16-group flex block group
    ] {
        let src = if populate {
            populated()
        } else {
            TreeBuilder::new()
        };
        let file = format_file(src, mib * MIB, options());
        e2fsck_clean(file.path()).unwrap_or_else(|e| {
            panic!("e2fsck faulted the {mib} MiB image (populate={populate}):\n{e}")
        });
    }
}

#[test]
fn a_filesystem_sized_to_its_source_passes_e2fsck() {
    if !available("e2fsck") {
        return;
    }
    // A fitted filesystem is the tightest one this crate writes: every structure sized to
    // the size the search settled on, and almost nothing free. That is exactly where an
    // accounting slip hides — a free count off by one, a final group whose metadata barely
    // fits — so the gate is that an external checker still finds nothing wrong with it.
    //
    // Across the families, because each places its data differently, and across the slack
    // settings, because the room left over moves which size is chosen and so which group is
    // the last one.
    for profile in [Profile::Ext2, Profile::Ext3, Profile::Ext4] {
        for slack in [Slack::None, Slack::Bytes(4 * MIB), Slack::Share(2500)] {
            let mut opts = options();
            opts.feature = profile.feature_set();
            let plan = FormatPlan::fit(populated(), opts, slack)
                .unwrap_or_else(|e| panic!("{profile:?} with {slack:?}: {e}"));
            let size = plan.size_bytes();
            let file = tempfile::NamedTempFile::new().expect("temp file");
            plan.write_to(file.as_file())
                .expect("write the fitted image");
            e2fsck_clean(file.path()).unwrap_or_else(|e| {
                panic!("e2fsck faulted the {profile:?} image fitted to {size} bytes with {slack:?}:\n{e}")
            });
        }
    }
}

#[test]
fn a_layered_source_formats_into_an_image_that_holds_the_composition() {
    // The composition's rules are unit-tested; this is the end-to-end claim, that the
    // entry list they produce is one the model accepts and the writer realizes. The
    // subtree drop is the part worth proving here: it removes entries whose parent is
    // gone, and a list that kept them would be a model error rather than a wrong image.
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    let m = |mode| Metadata::new(mode, time);

    let base = populated()
        .directory(b"/opt".to_vec(), m(0o755))
        .directory(b"/opt/pkg".to_vec(), m(0o755))
        .file(
            b"/opt/pkg/data".to_vec(),
            b"from the base\n".to_vec(),
            m(0o644),
        );
    let overlay = TreeBuilder::new()
        // Replaces a file the base placed.
        .file(b"/etc/hostname".to_vec(), b"overlaid\n".to_vec(), m(0o600))
        // Replaces a directory, so the base's /opt/pkg and its file go with it.
        .file(b"/opt".to_vec(), b"now a file\n".to_vec(), m(0o644))
        // And adds something no layer had.
        .file(b"/etc/issue".to_vec(), b"welcome\n".to_vec(), m(0o644))
        // Replaces the target of a hard link the base placed. The link names a path, so
        // under later-wins it is the new content that both names reach — and they are
        // still one file.
        .file(
            b"/bin/sh".to_vec(),
            b"the overlay's shell\n".to_vec(),
            m(0o755),
        );

    let source = LayeredSource::new().layer(base).layer(overlay);
    let file = format_file(source, 64 * MIB, options());

    let mut r = Reader::open(std::fs::File::open(file.path()).expect("open")).expect("read back");
    assert_eq!(
        read_path(&mut r, b"/etc/hostname"),
        b"overlaid\n",
        "the overlay won"
    );
    assert_eq!(
        read_path(&mut r, b"/etc/issue"),
        b"welcome\n",
        "the overlay's addition"
    );
    assert_eq!(
        read_path(&mut r, b"/opt"),
        b"now a file\n",
        "a file where a directory was"
    );
    assert!(
        r.lookup(b"/opt/pkg/data").is_err(),
        "the replaced directory's contents are gone"
    );
    // A hard link names a path, so replacing its target replaces what both names hold —
    // and leaves them one file rather than two.
    assert_eq!(read_path(&mut r, b"/bin/sh"), b"the overlay's shell\n");
    assert_eq!(
        read_path(&mut r, b"/bin/dash"),
        b"the overlay's shell\n",
        "the link followed the new content"
    );
    let (sh, inode) = r.lookup(b"/bin/sh").expect("lookup");
    let (dash, _) = r.lookup(b"/bin/dash").expect("lookup");
    assert_eq!(sh, dash, "the two names are still one inode");
    assert_eq!(inode.links_count, 2);

    if available("e2fsck") {
        e2fsck_clean(file.path()).expect("a layered image checks clean");
    }
}

/// The bytes at one path inside an image, following symbolic links as a lookup does.
fn read_path(r: &mut Reader<std::fs::File>, path: &[u8]) -> Vec<u8> {
    let (_, inode) = r.lookup(path).expect("lookup");
    r.read_data(&inode).expect("read")
}

/// Open an image for the read-modify-write a re-identification performs.
fn open_rw(path: &std::path::Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open the image for rewriting")
}

/// The UUID `dumpe2fs` reports, so what a foreign implementation reads back is the
/// assertion rather than what this crate believes it wrote.
fn dumped_uuid(path: &std::path::Path) -> String {
    header_text(path, "Filesystem UUID:")
}

#[test]
fn a_rewritten_identity_is_what_dumpe2fs_reads_and_e2fsck_accepts() {
    if !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    // 512 MiB puts backups in groups 1 and 3, so this covers the copies and not only the
    // primary. The default profile carries metadata_csum_seed, so the UUID moves freely.
    let file = format_file(populated(), 512 * MIB, options());
    let before = dumped_uuid(file.path());

    let new_uuid = [
        0x5a, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x45, 0x66, 0x87, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee,
    ];
    let mut change = IdentityChange::new();
    change.uuid = Some(new_uuid);
    change.volume_name = Some(*b"relabelled\0\0\0\0\0\0");
    let report = rewrite_identity(&mut open_rw(file.path()), &change).expect("rewrite");

    assert_eq!(
        report.superblocks, 3,
        "primary plus backups in groups 1 and 3"
    );
    assert!(report.journal_superblock, "the log records the UUID too");
    assert!(!report.checksum_seed_set, "the seed was already a field");

    let after = dumped_uuid(file.path());
    assert_ne!(before, after);
    assert_eq!(after, "5a5a1122-3344-4566-8788-99aabbccddee");
    assert_eq!(
        header_text(file.path(), "Filesystem volume name:"),
        "relabelled"
    );
    // The whole point: a foreign checker still accepts the image, so every checksum the
    // rewrite did not touch is still right and the copies still agree.
    e2fsck_clean(file.path()).expect("a re-identified image checks clean");

    // The log's own record of the UUID, read back through the parser rather than trusted
    // from the offset the write used.
    let mut r = Reader::open(std::fs::File::open(file.path()).expect("open")).expect("read back");
    let journal = r
        .journal_superblock()
        .expect("parse the journal")
        .expect("the image has a journal");
    assert_eq!(journal.uuid, new_uuid, "the log records the new UUID");

    // And the backups really carry it, rather than the primary alone reading back.
    for group in [1u32, 3] {
        let out = tool("dumpe2fs")
            .args(["-o", &format!("superblock={}", u64::from(group) * 32768)])
            .arg("-h")
            .arg(file.path())
            .output()
            .expect("spawn dumpe2fs");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("5a5a1122-3344-4566-8788-99aabbccddee"),
            "the backup in group {group} kept the old UUID:\n{text}"
        );
    }
}

#[test]
fn a_rewrite_keeps_every_superblock_field_this_crate_does_not_model() {
    if !available("e2fsck") || !available("mke2fs") {
        return;
    }
    // The failure this guards against has bitten this crate once already, on the reading
    // side: a foreign superblock re-serialized through the fields ferrosys models loses
    // every field it does not — `s_last_orphan`, `s_snapshot_*`, `s_mmp_*`, `s_error_*`,
    // `s_encoding`, `s_backup_bgs`, the reserved tail. So the image here is `mke2fs`'s
    // rather than this crate's, because a ferrosys-written image has most of those zero
    // and would pass a re-serializing implementation just as well.
    //
    // The claim is exact: after the rewrite, every byte of the primary superblock is the
    // byte that was there, except the three windows the change names.
    let image = mke2fs_baseline_of(Profile::Ext4, 4096, 64 * MIB);
    let before = superblock_bytes(image.path());

    let new_uuid = [
        0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43,
        0x21,
    ];
    let mut change = IdentityChange::new();
    change.uuid = Some(new_uuid);
    change.volume_name = Some(*b"foreign\0\0\0\0\0\0\0\0\0");
    rewrite_identity(&mut open_rw(image.path()), &change).expect("rewrite the foreign image");

    let after = superblock_bytes(image.path());
    // `s_uuid` at 0x68, `s_volume_name` at 0x78, and `s_checksum` at 0x3fc, which is
    // recomputed over whatever the record now holds.
    let changed = |i: usize| (0x68..0x88).contains(&i) || (0x3fc..0x400).contains(&i);
    assert_eq!(before.len(), after.len());
    for i in 0..before.len() {
        if changed(i) {
            continue;
        }
        assert_eq!(
            before[i], after[i],
            "byte {i:#x} of the superblock moved: {:#04x} became {:#04x}",
            before[i], after[i]
        );
    }
    // And the windows that were meant to move did, so the comparison above is not passing
    // because nothing happened at all.
    assert_ne!(&before[0x68..0x78], &after[0x68..0x78], "the UUID moved");
    assert_eq!(&after[0x68..0x78], &new_uuid, "to the one asked for");
    assert_ne!(&before[0x78..0x88], &after[0x78..0x88], "the label moved");
    e2fsck_clean(image.path()).expect("a re-identified foreign image checks clean");
}

#[test]
fn a_rewrite_keeps_a_checksummed_journal_loadable() {
    if !available("e2fsck") || !available("mke2fs") {
        return;
    }
    // A journal `mke2fs` has just written declares no jbd2 features at all, so its
    // superblock carries no checksum and a UUID written into it invalidates nothing. Every
    // image that has ever been mounted is the other case: Linux sets `csum_v3` on the log
    // of any `metadata_csum` filesystem the first time it mounts one, and the crc32c that
    // comes with it covers `s_uuid`. So the fixture puts the image into the state a mount
    // leaves behind, which is the state a rescue image being cloned or a built rootfs being
    // re-stamped per device is actually in.
    let image = mke2fs_baseline_of(Profile::Ext4, 4096, 64 * MIB);
    let journal = journal_superblock_offset(image.path());
    mount_the_journal(image.path(), journal);
    e2fsck_clean(image.path()).expect("the mounted-once fixture is itself clean");

    let new_uuid = [
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x41, 0x11, 0x8f, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
        0x88,
    ];
    let mut change = IdentityChange::new();
    change.uuid = Some(new_uuid);
    let report =
        rewrite_identity(&mut open_rw(image.path()), &change).expect("rewrite the mounted image");
    assert!(report.journal_superblock, "the log's record was written");

    // The claim in three parts: the log records the new UUID, its own checksum agrees with
    // the bytes it now holds, and `e2fsck` will still load it.
    let after = read_at(image.path(), journal, JOURNAL_SB_LEN);
    assert_eq!(&after[0x30..0x40], &new_uuid, "the log took the new UUID");
    let stored = u32::from_be_bytes([after[0xfc], after[0xfd], after[0xfe], after[0xff]]);
    let mut recomputed = after.clone();
    seal_journal_checksum(&mut recomputed);
    assert_eq!(
        stored,
        u32::from_be_bytes([
            recomputed[0xfc],
            recomputed[0xfd],
            recomputed[0xfe],
            recomputed[0xff]
        ]),
        "the journal superblock's checksum matches its contents"
    );
    e2fsck_clean(image.path()).expect("a re-identified checksummed journal checks clean");
}

#[test]
fn the_log_takes_the_new_uuid_where_tune2fs_leaves_it_behind() {
    if !available("e2fsck") || !available("mke2fs") || !available("tune2fs") {
        return;
    }
    // A divergence from the tool this replaces, pinned so it stays a decision rather than
    // becoming a discovery. `tune2fs -U` does not touch an internal journal at all: the log
    // keeps the UUID it had, and `e2fsck` is content, because nothing in ext4 matches an
    // internal log's `s_uuid` against the filesystem's. This crate writes it, so a cloned
    // image's log does not go on naming the filesystem it was cloned from — and the crc32c
    // over the log's superblock is recomputed with it, which is what keeps the result one
    // jbd2 will load.
    //
    // Nothing is lost by moving it. The log's `s_uuid` is also jbd2's seed for the
    // checksums on the log's own blocks, so moving it under a log with transactions to
    // replay would make them unrecoverable — but such a filesystem declares
    // `needs_recovery`, an incompatible feature the reader does not follow, so it is refused
    // before a byte is planned. The log this reaches is always an empty one.
    let uuid_text = "77665544-3322-4111-8fee-ddccbbaa9988";
    let uuid = [
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x41, 0x11, 0x8f, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
        0x88,
    ];

    let ours = mke2fs_baseline_of(Profile::Ext4, 4096, 64 * MIB);
    let journal = journal_superblock_offset(ours.path());
    mount_the_journal(ours.path(), journal);
    let theirs = tempfile::NamedTempFile::new().expect("temp");
    std::fs::copy(ours.path(), theirs.path()).expect("copy the fixture");
    let before = read_at(ours.path(), journal, JOURNAL_SB_LEN);

    let mut change = IdentityChange::new();
    change.uuid = Some(uuid);
    rewrite_identity(&mut open_rw(ours.path()), &change).expect("rewrite");

    let status = tool("tune2fs")
        .args(["-U", uuid_text])
        .arg(theirs.path())
        .status()
        .expect("spawn tune2fs");
    assert!(status.success(), "tune2fs -U failed");

    // What tune2fs left: the log exactly as it was, old UUID and old checksum.
    assert_eq!(
        read_at(theirs.path(), journal, JOURNAL_SB_LEN),
        before,
        "tune2fs is expected to leave the internal journal untouched",
    );
    // What this crate leaves: the new UUID, and nothing else moved but the checksum over it.
    let after = read_at(ours.path(), journal, JOURNAL_SB_LEN);
    assert_eq!(&after[0x30..0x40], &uuid);
    let moved: Vec<usize> = (0..JOURNAL_SB_LEN)
        .filter(|&i| after[i] != before[i])
        .collect();
    let expected: Vec<usize> = (0x30..0x40).chain(0xfc..0x100).collect();
    assert_eq!(moved, expected, "only the UUID and its checksum moved");

    // And both images are ones `e2fsck` accepts, which is the property the divergence
    // must not cost.
    e2fsck_clean(ours.path()).expect("the re-identified log checks clean");
    e2fsck_clean(theirs.path()).expect("tune2fs's image checks clean");
}

/// Put an image's journal into the state Linux leaves it in after a mount: `csum_v3` in
/// `s_feature_incompat`, crc32c as `s_checksum_type`, and the checksum that follows.
///
/// A journal `mke2fs` has just written declares no jbd2 features at all, so nothing in it
/// is checksummed and a UUID written into it invalidates nothing. Linux sets `csum_v3` on
/// the log of any `metadata_csum` filesystem the first time it mounts one, which makes this
/// the state of every image that has ever been used.
fn mount_the_journal(path: &Path, journal: u64) {
    let mut record = read_at(path, journal, JOURNAL_SB_LEN);
    // `s_feature_incompat` at 0x28, big-endian like every word of this record, gains
    // `JBD2_FEATURE_INCOMPAT_CSUM_V3`; `s_checksum_type` at 0x50 becomes crc32c.
    let incompat = u32::from_be_bytes([record[0x28], record[0x29], record[0x2a], record[0x2b]]);
    record[0x28..0x2c].copy_from_slice(&(incompat | 0x10).to_be_bytes());
    record[0x50] = 4;
    seal_journal_checksum(&mut record);
    write_at(path, journal, &record);
}

#[test]
fn a_rewrite_refuses_an_image_whose_journal_superblock_is_damaged() {
    if !available("mke2fs") {
        return;
    }
    // The refusal the filesystem's own superblock already gets, for the same reason: a log
    // whose checksum does not match its bytes is damaged, and recomputing one over it would
    // replace a detectable fault with an undetectable one.
    let image = mke2fs_baseline_of(Profile::Ext4, 4096, 64 * MIB);
    let journal = journal_superblock_offset(image.path());
    mount_the_journal(image.path(), journal);
    // One byte the checksum covers, moved after the log was sealed.
    let mut record = read_at(image.path(), journal, JOURNAL_SB_LEN);
    record[0x18] ^= 0xff;
    write_at(image.path(), journal, &record);

    let mut change = IdentityChange::new();
    change.uuid = Some([0x5a; 16]);
    let err = rewrite_identity(&mut open_rw(image.path()), &change)
        .expect_err("a damaged log is refused");
    assert!(
        matches!(err, IdentityError::JournalChecksumMismatch { .. }),
        "expected a journal checksum refusal, got {err:?}"
    );
    // And the refusal left the image alone: the log still holds the UUID it did.
    let after = read_at(image.path(), journal, JOURNAL_SB_LEN);
    assert_eq!(&after[0x30..0x40], &record[0x30..0x40]);
}

/// The size of `journal_superblock_t`, which is what its checksum covers.
const JOURNAL_SB_LEN: usize = 1024;

/// The byte offset of the journal superblock in `path`, found by its jbd2 magic.
///
/// The tests reach it this way rather than through the crate, so what they exercise is not
/// also what located what they exercise.
fn journal_superblock_offset(path: &Path) -> u64 {
    let bytes = std::fs::read(path).expect("read the image");
    let magic = 0xc03b_3998u32.to_be_bytes();
    // Block-aligned at 4096, which is the block size every caller here builds with, and the
    // journal superblock is a whole block of its own.
    for offset in (0..bytes.len().saturating_sub(4)).step_by(4096) {
        if bytes[offset..offset + 4] == magic {
            return offset as u64;
        }
    }
    panic!("no jbd2 superblock in the image");
}

/// Write the checksum a journal superblock's bytes compute to into the record itself:
/// crc32c seeded `!0` over all 1024 bytes with `s_checksum` at 0xfc read as zero, stored
/// big-endian.
///
/// Spelled out from the jbd2 definition rather than called through the crate, so it is an
/// independent statement of the same rule.
fn seal_journal_checksum(record: &mut [u8]) {
    record[0xfc..0x100].copy_from_slice(&[0u8; 4]);
    let c = ferrosys::crc32c(!0, &record[..JOURNAL_SB_LEN]);
    record[0xfc..0x100].copy_from_slice(&c.to_be_bytes());
}

/// `len` bytes of `path` from `offset`.
fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("open the image");
    file.seek(io::SeekFrom::Start(offset)).expect("seek");
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).expect("read");
    bytes
}

/// Put `bytes` at `offset` in `path`.
fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = open_rw(path);
    file.seek(io::SeekFrom::Start(offset)).expect("seek");
    file.write_all(bytes).expect("write");
    file.flush().expect("flush");
}

/// The primary superblock's 1024 bytes, read straight out of the image at offset 1024.
fn superblock_bytes(path: &Path) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("open the image");
    file.seek(io::SeekFrom::Start(1024)).expect("seek");
    let mut bytes = vec![0u8; 1024];
    file.read_exact(&mut bytes).expect("read the superblock");
    bytes
}

#[test]
fn a_uuid_that_seeds_the_checksums_is_refused_until_the_seed_is_recorded() {
    if !available("e2fsck") {
        return;
    }
    // metadata_csum without metadata_csum_seed: every checksum in the filesystem derives
    // from the UUID, so moving it would invalidate all of them at once.
    let mut o = options();
    o.feature.incompat =
        Incompat::from_bits(o.feature.incompat.bits() & !Incompat::CSUM_SEED.bits());
    let file = format_file(populated(), 64 * MIB, o);
    e2fsck_clean(file.path()).expect("the starting image is clean");

    let mut change = IdentityChange::new();
    change.uuid = Some([0x77; 16]);
    let refused = rewrite_identity(&mut open_rw(file.path()), &change);
    assert!(
        matches!(refused, Err(IdentityError::UuidWouldInvalidateChecksums)),
        "expected a refusal, got {refused:?}"
    );
    // Refused before anything was written, so the image is exactly as it was.
    e2fsck_clean(file.path()).expect("a refused rewrite left the image untouched");

    // Recording the seed is the way through, and the result is still clean: every
    // existing checksum now derives from the recorded seed rather than from the UUID.
    change.set_checksum_seed = true;
    let report = rewrite_identity(&mut open_rw(file.path()), &change).expect("rewrite");
    assert!(report.checksum_seed_set);
    e2fsck_clean(file.path()).expect("recording the seed kept every checksum valid");

    // A second rewrite now needs no opt-in, because the feature it sets is set.
    let mut again = IdentityChange::new();
    again.uuid = Some([0x88; 16]);
    rewrite_identity(&mut open_rw(file.path()), &again).expect("the second rewrite is free");
    e2fsck_clean(file.path()).expect("and is still clean");
}

#[test]
fn a_label_alone_moves_no_uuid_and_needs_no_seed() {
    if !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    // A label change touches no checksum seed, so it is free even on the feature set the
    // test above has to refuse a UUID change on.
    let mut o = options();
    o.feature.incompat =
        Incompat::from_bits(o.feature.incompat.bits() & !Incompat::CSUM_SEED.bits());
    let file = format_file(populated(), 64 * MIB, o);
    let uuid_before = dumped_uuid(file.path());

    let mut change = IdentityChange::new();
    change.volume_name = Some(*b"just-a-label\0\0\0\0");
    rewrite_identity(&mut open_rw(file.path()), &change).expect("rewrite");

    assert_eq!(
        dumped_uuid(file.path()),
        uuid_before,
        "the UUID did not move"
    );
    assert_eq!(
        header_text(file.path(), "Filesystem volume name:"),
        "just-a-label"
    );
    e2fsck_clean(file.path()).expect("clean");
}

/// A tree that drives the block-mapped family's classic map into every region: a
/// directory with small files, a slow symlink, and two files that reach the single- and
/// double-indirect blocks (20 and 1040 blocks at a 4 KiB block size).
fn block_mapped_tree() -> TreeBuilder {
    let t = Timestamp::from_secs(FAKE_TIME as i64);
    let mut double = vec![0u8; 1040 * 4096];
    for (i, b) in double.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    TreeBuilder::new()
        .directory(b"/d".to_vec(), Metadata::new(0o755, t))
        .file(
            b"/d/a".to_vec(),
            b"hello\n".to_vec(),
            Metadata::new(0o644, t),
        )
        .symlink(
            b"/d/link".to_vec(),
            vec![b'x'; 200],
            Metadata::new(0o777, t),
        )
        .file(
            b"/single".to_vec(),
            vec![0xb2; 20 * 4096],
            Metadata::new(0o644, t),
        )
        .file(b"/double".to_vec(), double, Metadata::new(0o600, t))
}

/// Options for a block-mapped profile at a given block size: the profile's feature
/// words with the block size overridden, on top of the shared UUID/time/grow defaults.
fn block_mapped_options(profile: Profile, block_size: u32) -> FormatOptions {
    let mut o = options();
    o.feature = profile.feature_set();
    o.feature.block_size = block_size;
    o
}

/// The block-mapped family (ext2 and ext3) writes `e2fsck`-clean images across the
/// single-group, multi-group-with-backups, and indirect-mapped cases, at every block
/// size — including 1024 and 2048, where a group spans fewer blocks so the geometry's
/// edges bite. ext3 additionally carries the classic-mapped journal, so this is where a
/// journal that maps through the indirect scheme rather than an extent tree, and its own
/// indirect blocks, are checked end to end.
#[test]
fn the_block_mapped_family_passes_e2fsck() {
    if !available("e2fsck") {
        return;
    }
    for profile in [Profile::Ext2, Profile::Ext3] {
        for bs in [1024u32, 2048, 4096] {
            for (mib, populate) in [(64u64, false), (64, true), (200, true), (512, true)] {
                let src = if populate {
                    block_mapped_tree()
                } else {
                    TreeBuilder::new()
                };
                let file = format_file(src, mib * MIB, block_mapped_options(profile, bs));
                e2fsck_clean(file.path()).unwrap_or_else(|e| {
                    panic!(
                        "e2fsck faulted the {profile} {bs}-byte-block {mib} MiB image \
                         (populate={populate}):\n{e}"
                    )
                });
            }
        }
    }
}

/// The classic block map's triple-indirect level — the least-trodden branch of the
/// writer's `build_indirect` and the reader's `walk_indirect`/`scan_indirect` — is
/// reached only by a file past the double-indirect span. At a 1024-byte block that span
/// ends at logical block `12 + 256 + 256*256 = 65804`, so a file a few blocks larger is
/// the smallest that enters the triple-indirect tree. This writes one, checks `e2fsck`
/// accepts its structure, reads it back byte-for-byte, and scans it clean — so both the
/// writer's and the reader's level-3 paths run end to end.
#[test]
fn a_triple_indirect_file_round_trips_and_passes_e2fsck() {
    if !available("e2fsck") {
        return;
    }
    const BS: u32 = 1024;
    const PPB: usize = (BS / 4) as usize; // 256 pointers per indirect block
    const DIRECT: usize = 12;
    // The first logical block the triple-indirect tree maps.
    const TRIPLE_START: usize = DIRECT + PPB + PPB * PPB; // 65804
    // A few blocks into the triple tree, so its indirect block holds more than one entry
    // and the walk continues past the first.
    let block_count = TRIPLE_START + 5;
    let size = block_count * BS as usize;

    let t = Timestamp::from_secs(FAKE_TIME as i64);
    let mut content = vec![0u8; size];
    for (i, b) in content.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let src = TreeBuilder::new().file(b"/triple".to_vec(), content, Metadata::new(0o644, t));

    // ext2 keeps the image small (no journal); no grow reservation keeps the reserved GDT
    // from inflating a 1024-byte-block filesystem. 96 MiB holds the ~64 MiB file plus its
    // indirect metadata and per-group overhead.
    let mut o = FormatOptions::new(UUID, t, [0u8; 16]);
    o.feature = Profile::Ext2.feature_set();
    o.feature.block_size = BS;
    o.grow = GrowReservation::None;
    let file = format_file(src, 96 * MIB, o);

    e2fsck_clean(file.path()).expect("e2fsck accepts the triple-indirect map");

    let f = std::fs::File::open(file.path()).expect("open image");
    let mut r = Reader::open(f).expect("open reader");
    let (_, inode) = r.lookup(b"/triple").expect("find the triple-indirect file");
    let read_back = r.read_data(&inode).expect("read the triple-indirect file");
    assert_eq!(read_back.len(), size, "the whole file reads back");
    assert!(
        read_back
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (i % 251) as u8),
        "triple-indirect file reads back byte-for-byte"
    );
    // A strict scan walks scan_indirect at level 3 too, and finds nothing to report.
    assert!(r.scan().is_clean(), "the triple-indirect map scans clean");
}

/// The byte-identity regression gate for the block-mapped family: ext2 and ext3 must
/// place their per-group metadata exactly where `mke2fs -t ext2`/`-t ext3` does and
/// report the same block, inode, and inodes-per-group counts, at every block size. This
/// is the guard the extent family's `every_block_size_passes_e2fsck_and_matches_mke2fs_geometry`
/// is for the block-mapped family — nothing else pins the placement to `mke2fs`'s.
#[test]
fn the_block_mapped_family_matches_mke2fs_geometry() {
    if !available("e2fsck") || !available("mke2fs") || !available("dumpe2fs") {
        return;
    }
    for profile in [Profile::Ext2, Profile::Ext3] {
        for bs in [1024u32, 2048, 4096] {
            for mib in [16u64, 64, 200, 512] {
                let ours = format_file(
                    block_mapped_tree(),
                    mib * MIB,
                    block_mapped_options(profile, bs),
                );
                e2fsck_clean(ours.path()).unwrap_or_else(|e| {
                    panic!("e2fsck faulted the {profile} {bs}-byte-block {mib} MiB image:\n{e}")
                });

                let baseline = mke2fs_baseline_of(profile, bs, mib * MIB);
                let dump = geometry_dump(ours.path());
                // Guard against a vacuous pass: a `dumpe2fs` whose wording drifted would
                // filter to nothing on both sides, and the comparison would be
                // `assert_eq!("", "")`. The geometry always has group and placement lines.
                assert!(
                    dump.contains("Group 0"),
                    "geometry_dump extracted nothing from the {profile} {bs}-byte-block \
                     {mib} MiB image — the dumpe2fs format may have drifted"
                );
                assert_eq!(
                    dump,
                    geometry_dump(baseline.path()),
                    "{profile} geometry diverges from mke2fs at {bs}-byte blocks, {mib} MiB"
                );
                for field in ["Block count", "Inode count", "Inodes per group"] {
                    assert_eq!(
                        header_field(ours.path(), field),
                        header_field(baseline.path(), field),
                        "{profile} {field} diverges from mke2fs at {bs}-byte blocks, {mib} MiB"
                    );
                }
            }
        }
    }
}

/// Every inode size the feature set accepts must produce a filesystem `e2fsck` accepts.
///
/// A geometry the writer validates but cannot honour is the worst thing this crate can
/// do: it returns `Ok` and hands back a corrupt filesystem. The inode is serialized at
/// `s_inode_size` and written at a stride of `s_inode_size`, so the two agreeing is what
/// keeps one inode out of the next one's bytes — and the extra area, which only the
/// larger inodes have, is what decides whether the creation time, the sub-second
/// timestamps, and `i_checksum_hi` exist at all.
#[test]
fn every_inode_size_writes_an_e2fsck_clean_image() {
    if !available("e2fsck") {
        return;
    }
    for inode_size in [128u16, 256, 512, 1024] {
        let mut o = options();
        o.feature.inode_size = inode_size;
        assert_eq!(
            o.feature.validate(),
            Ok(()),
            "inode_size {inode_size} is accepted"
        );
        let file = format_file(populated(), 64 * MIB, o);
        e2fsck_clean(file.path()).unwrap_or_else(|e| {
            panic!("e2fsck faulted the image written at inode_size {inode_size}:\n{e}")
        });
    }
}

#[test]
fn the_e2fsck_gate_fails_a_corrupted_image() {
    if !available("e2fsck") {
        return;
    }
    // Negative control: the gate is only meaningful if it rejects a broken image.
    // Corrupt the root inode's block map so `e2fsck -fn` must report an error, and
    // assert the helper surfaces it rather than returning `Ok`.
    let image = format(populated(), 64 * MIB, options()).expect("format");
    let mut bytes = image.into_bytes();
    // The root inode (2) sits in group 0's inode table; flip bytes across its block
    // map and size so the structure e2fsck walks is inconsistent.
    let root_off = {
        let mut r = ferrosys::ext::Reader::open(std::io::Cursor::new(&bytes)).expect("open");
        r.group_descriptor(0).expect("desc").inode_table as usize * 4096 + 256
    };
    for b in &mut bytes[root_off + 0x28..root_off + 0x64] {
        *b ^= 0xff;
    }
    let f = tempfile::NamedTempFile::new().expect("temp");
    std::fs::write(f.path(), &bytes).expect("write");
    assert!(
        e2fsck_clean(f.path()).is_err(),
        "the e2fsck gate accepted a corrupted image — the gate is not actually checking"
    );
}

#[test]
fn every_grow_reservation_passes_e2fsck() {
    if !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    // The reservation sizes the resize inode's map. Each variant threads a different
    // amount through it, so each must reach the foreign checker. `None` leaves it empty;
    // `UpTo` sizes it to a target; `Max` is the shipped default, and it is exercised on both
    // sides of the knee at which the whole map becomes affordable — 256 MiB, where the map's
    // 1024 blocks are a sixty-fourth of the filesystem. Filling the map is the case no other
    // gate reaches, and the share below it is what every small image gets.
    let base = FormatOptions::new(UUID, Timestamp::from_secs(FAKE_TIME as i64), [0u8; 16]);
    let cases = [
        ("None", 64 * MIB, GrowReservation::None, 0u32),
        ("Max below the knee", 64 * MIB, GrowReservation::Max, 256),
        ("Max at the knee", 256 * MIB, GrowReservation::Max, 1024),
        (
            "UpTo(32 GiB)",
            64 * MIB,
            GrowReservation::UpTo(GROW_TARGET),
            3,
        ),
    ];
    for (label, size, grow, expect_reserved) in cases {
        let mut o = base;
        o.grow = grow;
        let image = format(populated(), size, o).expect("format");
        assert_eq!(
            image.layout().reserved_gdt_blocks,
            expect_reserved,
            "{label}: reserved GDT blocks"
        );
        let file = write_image(&image);
        e2fsck_clean(file.path())
            .unwrap_or_else(|e| panic!("e2fsck faulted the {label} reservation:\n{e}"));
        // The reservation as a foreign tool reads it back. `dumpe2fs` prints the field
        // when blocks are reserved and omits the line when none are, so this pins both
        // readings — and it is what makes the absent line the >32-bit gate asserts on a
        // fact about the image rather than a helper that never finds anything.
        assert_eq!(
            header_field_opt(file.path(), "Reserved GDT blocks"),
            (expect_reserved != 0).then_some(u64::from(expect_reserved)),
            "{label}: dumpe2fs's reading of the reservation"
        );
    }
}

#[test]
fn debugfs_confirms_fidelity() {
    if !available("debugfs") {
        return;
    }
    // An independent foreign reader (e2fsprogs' debugfs) must see the device nodes
    // and extended attributes, confirming they are truly on disk and well-formed —
    // e2fsck proves the structure is valid, this proves it is present and correct.
    let image = format(populated(), 64 * MIB, options()).expect("format");
    let file = write_image(&image);

    let stat = |path: &str| -> String {
        let out = tool("debugfs")
            .args(["-R", &format!("stat {path}")])
            .arg(file.path())
            .output()
            .expect("spawn debugfs");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let null = stat("/dev/null");
    assert!(
        null.contains("character special"),
        "/dev/null is not a char device:\n{null}"
    );
    assert!(
        null.contains("01:03") || null.contains("1, 3"),
        "/dev/null device number wrong:\n{null}"
    );

    let sda = stat("/dev/sda");
    assert!(
        sda.contains("block special"),
        "/dev/sda is not a block device:\n{sda}"
    );

    // The inline capability attribute and the external-block attribute both appear.
    let sh = stat("/bin/sh");
    assert!(
        sh.contains("security.capability"),
        "inline xattr missing from /bin/sh:\n{sh}"
    );
    let notes = stat("/home/user/notes");
    assert!(
        notes.contains("user.big"),
        "block xattr missing from /home/user/notes:\n{notes}"
    );

    // The POSIX ACLs are present under their system.posix_acl_* names.
    let user = stat("/home/user");
    assert!(
        user.contains("system.posix_acl_access") && user.contains("system.posix_acl_default"),
        "ACLs missing from /home/user:\n{user}"
    );

    // Names prove presence; bytes prove fidelity. `ea_get -f` dumps each value raw
    // through libext2fs — the value as a foreign implementation reads it, compared
    // byte for byte, for one inline attribute and one that lives in the external
    // block. Both ACLs are compared too, but as values rather than as bytes: `ea_get`
    // renders a `system.posix_acl_*` attribute in the boundary encoding rather than
    // dumping the stored bytes, and it writes zero in the id field of the four tags that
    // identify nobody where the kernel writes ACL_UNDEFINED_ID. Neither parser reads that
    // field for those tags, so the two encodings mean one ACL and differ in bytes; the
    // kernel's own rendering is pinned by the walk instead. What this gate states is that
    // the ACL a source named survives ext's narrowing and comes back out of a foreign
    // implementation as the same ACL.
    let dumps = tempfile::tempdir().expect("dump dir");
    let ea_value = |path: &str, name: &str| -> Vec<u8> {
        let out = dumps.path().join(name.replace('.', "_"));
        let run = tool("debugfs")
            .args(["-R", &format!("ea_get -f {} {path} {name}", out.display())])
            .arg(file.path())
            .output()
            .expect("spawn debugfs");
        assert!(
            run.status.success(),
            "debugfs did not run ea_get for {name}"
        );
        std::fs::read(&out).unwrap_or_else(|e| panic!("{name} of {path} did not dump: {e}"))
    };
    assert_eq!(
        ea_value("/bin/sh", "security.capability"),
        [
            0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        "the inline capability value does not read back through debugfs"
    );
    assert_eq!(
        ea_value("/home/user/notes", "user.big"),
        vec![0xcd; 400],
        "the external-block value does not read back through debugfs"
    );
    let read_acl =
        |name: &str| Acl::decode(&ea_value("/home/user", name)).expect("debugfs rendered an ACL");
    assert_eq!(
        read_acl("system.posix_acl_access"),
        Acl::decode(&access_acl()).expect("the access ACL"),
        "the access ACL does not read back through debugfs as it was stated"
    );
    assert_eq!(
        read_acl("system.posix_acl_default"),
        Acl::decode(&default_acl()).expect("the default ACL"),
        "the default ACL does not read back through debugfs as it was stated"
    );
}

#[test]
fn e2fsck_accepts_a_xattr_set_split_between_inode_and_block() {
    if !available("e2fsck") || !available("debugfs") {
        return;
    }
    // A set that exists on disk only because it is split: `user.huge` fills a whole
    // 4096-byte attribute block by itself (32-byte header + 20-byte entry +
    // 4040-byte value + 4-byte terminator), so `user.tiny` must live in the inode's
    // inline region for the set to be representable at all. e2fsck validates both
    // regions' structure, the block's per-entry and block hashes, and its checksum;
    // debugfs then reads both attributes back, value bytes included.
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    let src = TreeBuilder::new()
        .file(
            b"/split".to_vec(),
            b"content".to_vec(),
            Metadata::new(0o644, time),
        )
        .xattr(b"user.huge".to_vec(), vec![0xCD; 4040])
        .xattr(b"user.tiny".to_vec(), b"tiny value".to_vec());
    let image = format(src, 64 * MIB, options()).expect("format");
    let file = write_image(&image);

    e2fsck_clean(file.path()).expect("e2fsck accepts the split set");

    let stat = debugfs_out(file.path(), "stat /split");
    assert!(
        stat.contains("user.huge (4040)"),
        "the spilled attribute and its full size are missing:\n{stat}"
    );
    assert!(
        stat.contains("user.tiny (10)"),
        "the inline attribute and its size are missing:\n{stat}"
    );
    let tiny = debugfs_out(file.path(), "ea_get /split user.tiny");
    assert!(
        tiny.contains("tiny value"),
        "the inline value does not read back through debugfs:\n{tiny}"
    );
    let huge = debugfs_out(file.path(), "ea_get -x /split user.huge");
    assert!(
        huge.contains("cd cd cd cd") || huge.contains("cdcd"),
        "the spilled value does not read back through debugfs:\n{huge}"
    );
}

#[test]
fn offline_resize_matrix() {
    // `dumpe2fs` is as load-bearing here as the other two: it is what reads the grown
    // image's feature set, and the gate's whole assertion is the absence of `meta_bg`.
    // Gating on it keeps a host without it to the loud skip banner rather than a panic
    // from inside a helper.
    if !available("resize2fs") || !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    // Grow a populated single-group start image across the geometry edges and up to
    // the full grow target, re-checking after each.
    let start = format(populated(), 64 * MIB, options()).expect("format");
    let start_file = write_image(&start);

    // MiB targets hitting: within/across a group boundary, a partial final group,
    // sparse_super backup groups, the flex_bg boundary, and the full 32 GiB target.
    for target_mib in [120u64, 129, 200, 384, 640, 2048, 2049, 32 * 1024] {
        let work = tempfile::NamedTempFile::new().expect("temp");
        std::fs::copy(start_file.path(), work.path()).expect("copy");
        // Grow the backing file, then the filesystem.
        let size = target_mib * MIB;
        work.as_file().set_len(size).expect("truncate");
        let out = tool("resize2fs")
            .arg(work.path())
            .output()
            .expect("spawn resize2fs");
        assert!(
            out.status.success(),
            "resize2fs to {target_mib} MiB failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The reserved GDT must absorb the growth; a meta_bg conversion is the
        // corruption path this project prevents. Read the grown image's feature set
        // directly — resize2fs does not name the conversion on its output.
        assert!(
            !image_has_meta_bg(work.path()),
            "growing to {target_mib} MiB forced a meta_bg conversion"
        );
        e2fsck_clean(work.path())
            .unwrap_or_else(|e| panic!("e2fsck faulted after growth to {target_mib} MiB:\n{e}"));
    }
}

/// The image's feature set, read from `dumpe2fs` and sorted so the two sides are
/// compared as sets — `dumpe2fs` prints the features in feature-word order, which says
/// nothing about whether the same features are present.
fn feature_set(path: &Path) -> Vec<String> {
    let out = tool("dumpe2fs")
        .arg("-h")
        .arg(path)
        .output()
        .expect("spawn dumpe2fs");
    let mut features: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Filesystem features:"))
        .expect("dumpe2fs reports a feature line")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    features.sort();
    features
}

/// The names a feature set reports must be the names `e2fsprogs` prints.
///
/// [`FeatureSet::names`] is the vocabulary every consumer of this crate renders and
/// every user types, and it is a hand-written table: no test inside the crate would
/// notice if a name drifted from the one the rest of the world uses, because both sides
/// of such a test would drift together. `dumpe2fs` reading an image this crate wrote is
/// what settles it — the same feature word, named by an implementation that did not
/// learn the names from us.
#[test]
fn the_feature_names_are_the_ones_dumpe2fs_prints() {
    if !available("dumpe2fs") {
        return;
    }
    let file = format_file(TreeBuilder::new(), 64 * MIB, options());
    let mut ours: Vec<String> = options()
        .feature
        .names()
        .into_iter()
        .map(str::to_string)
        .collect();
    ours.sort();
    // Guard against a vacuous pass: an empty list on both sides would compare equal.
    assert!(!ours.is_empty(), "the default profile names its features");
    assert_eq!(
        ours,
        feature_set(file.path()),
        "the feature names this crate reports diverge from the ones dumpe2fs prints"
    );
}

/// Whether the image's feature set includes `feature`, by the name `dumpe2fs` spells it
/// with — so what is asserted is the feature word a foreign tool reads out of the image,
/// not the one this crate believes it wrote.
fn image_has_feature(path: &Path, feature: &str) -> bool {
    let out = tool("dumpe2fs")
        .arg("-h")
        .arg(path)
        .output()
        .expect("spawn dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Filesystem features:"))
        .is_some_and(|features| features.split_whitespace().any(|f| f == feature))
}

/// Whether the image carries `meta_bg`. A resize that overran the reserved descriptor
/// blocks converts to `meta_bg`, so its absence confirms the reservation absorbed the
/// growth.
fn image_has_meta_bg(path: &Path) -> bool {
    image_has_feature(path, "meta_bg")
}

/// A `dumpe2fs -h` header field, or `None` when the header carries no such line.
///
/// `dumpe2fs` omits a field it has nothing to say about, so an absent line is itself an
/// assertable fact — `Reserved GDT blocks` appears only when some are reserved.
fn header_field_opt(path: &Path, field: &str) -> Option<u64> {
    let out = tool("dumpe2fs")
        .arg("-h")
        .arg(path)
        .output()
        .expect("spawn dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with(field))
        .map(|l| {
            l.rsplit(':')
                .next()
                .expect("a field line has a value")
                .trim()
                .parse()
                .expect("a numeric header field")
        })
}

#[test]
fn journal_superblock_matches_mke2fs_and_reads_back() {
    if !available("mke2fs") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::Reader;
    use ferrosys::ext::journal::default_journal_blocks;

    // The jbd2 superblock the crate writes must be byte-identical to mke2fs's, and the
    // crate's own reader must parse it back as an empty, well-formed v2 log. Sizes
    // exercise three journal-size tiers (1024 / 4096 / 4096 blocks).
    for mib in [64u64, 512, 2048] {
        let file = format_file(TreeBuilder::new(), mib * MIB, options());
        let expect_blocks =
            default_journal_blocks(mib * MIB / 4096).expect("a journal fits at this size");

        // Reader side: the parsed journal superblock reflects the chosen size.
        let mut reader =
            Reader::open(std::fs::File::open(file.path()).expect("open image")).expect("open");
        let jsb = reader
            .journal_superblock()
            .expect("journal superblock reads")
            .expect("image carries a journal");
        assert_eq!(jsb.block_size, 4096);
        assert_eq!(jsb.max_len, expect_blocks);
        assert_eq!(jsb.first, 1);
        assert_eq!(jsb.sequence, 1);
        assert_eq!(jsb.start, 0, "a fresh log has nothing to replay");
        assert_eq!(jsb.nr_users, 1);
        assert_eq!(jsb.uuid, UUID);

        // Extract our journal's first block (the jbd2 superblock) via its extent.
        let ours = journal_superblock_bytes(&mut reader);

        // mke2fs baseline with the same UUID: its journal superblock is the reference.
        let baseline = tempfile::NamedTempFile::new().expect("temp");
        baseline.as_file().set_len(mib * MIB).expect("truncate");
        let status = tool("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-b", "4096"])
            .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
            .args(["-E", &format!("resize={RESIZE_BLOCKS}")])
            .args(["-O", "^dir_index"])
            .arg(baseline.path())
            .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
            .status()
            .expect("spawn mke2fs");
        assert!(status.success(), "mke2fs baseline failed");
        let theirs = mke2fs_journal_superblock(baseline.path());

        // Compare the whole 1024-byte jbd2 superblock, not just the header: mke2fs and
        // ferrosys both write the fields through s_nr_users and then zero to the end, so
        // any garbage ferrosys wrote past the header would be caught here. They allocate
        // the log at different blocks, but the superblock content is identical.
        assert_eq!(
            &ours[..1024],
            &theirs[..1024],
            "jbd2 superblock diverges from mke2fs at {mib} MiB"
        );

        // debugfs (foreign reader) must see inode 8 as a regular journal file of the
        // expected size.
        let out = tool("debugfs")
            .args(["-R", "stat <8>"])
            .arg(file.path())
            .output()
            .expect("spawn debugfs");
        let stat = String::from_utf8_lossy(&out.stdout);
        assert!(
            stat.contains("Type: regular"),
            "inode 8 not regular:\n{stat}"
        );
        let expect_size = u64::from(expect_blocks) * 4096;
        assert!(
            stat.contains(&format!("Size: {expect_size}")),
            "journal size wrong at {mib} MiB:\n{stat}"
        );
    }

    /// Read the journal's first block (the jbd2 superblock) out of a ferrosys image by
    /// walking inode 8's extent tree through the reader.
    fn journal_superblock_bytes(
        reader: &mut Reader<impl std::io::Read + std::io::Seek>,
    ) -> Vec<u8> {
        let inode = reader.inode(8).expect("journal inode");
        let data = reader.read_data(&inode).expect("journal data");
        data[..4096].to_vec()
    }

    /// Extract mke2fs's journal superblock (inode 8, first block) via debugfs. The
    /// journal's logical block 0 is its superblock, so the first extent's physical
    /// start locates it.
    fn mke2fs_journal_superblock(path: &Path) -> Vec<u8> {
        let out = tool("debugfs")
            .args(["-R", "dump_extents <8>"])
            .arg(path)
            .output()
            .expect("spawn debugfs");
        let text = String::from_utf8_lossy(&out.stdout);
        // The first data row after the "Physical" header maps logical block 0. Parse
        // its integers (slashes and dashes become separators): the columns are
        // [depth, _, entry, _, logical_start, logical_end, phys_start, phys_end, len].
        let row = text
            .lines()
            .skip_while(|l| !l.contains("Physical"))
            .nth(1)
            .expect("first journal extent row");
        let nums: Vec<usize> = row
            .replace(['/', '-'], " ")
            .split_whitespace()
            .filter_map(|t| t.parse::<usize>().ok())
            .collect();
        let phys = nums[6]; // phys_start for a depth-0 leaf row
        let bytes = std::fs::read(path).expect("read baseline");
        bytes[phys * 4096..phys * 4096 + 4096].to_vec()
    }
}

#[test]
fn the_orphan_file_matches_mke2fs_and_e2fsck_checks_its_blocks() {
    if !available("mke2fs")
        || !available("dumpe2fs")
        || !available("debugfs")
        || !available("e2fsck")
    {
        return;
    }
    // The orphan file is a real file the kernel writes into on the first deletion, so
    // its inode number, its size, and every block's magic-and-checksum tail must be what
    // e2fsprogs expects. Sizes straddle the size heuristic's floor (32 blocks) and the
    // ratio above it (128 blocks at 2 GiB).
    for mib in [64u64, 2048] {
        let ours = format_file(TreeBuilder::new(), mib * MIB, options());
        let baseline = mke2fs_baseline(4096, mib * MIB);

        assert_eq!(
            header_field(ours.path(), "Orphan file inode"),
            header_field(baseline.path(), "Orphan file inode"),
            "the orphan file takes a different inode than mke2fs gives it at {mib} MiB"
        );
        assert_eq!(
            orphan_file_size(ours.path()),
            orphan_file_size(baseline.path()),
            "the orphan file is sized differently from mke2fs's at {mib} MiB"
        );
        e2fsck_clean(ours.path())
            .unwrap_or_else(|e| panic!("e2fsck faulted the orphan file at {mib} MiB:\n{e}"));
    }

    // Negative control: the gate above only means something if e2fsck reads those tails.
    // Corrupt one block's checksum and confirm it faults, so a wrong tail could not pass
    // unnoticed.
    let image = format(TreeBuilder::new(), 64 * MIB, options()).expect("format");
    let clean = write_image(&image);
    let ino = header_field(clean.path(), "Orphan file inode") as u32;
    let block = first_extent_block(clean.path(), ino) as usize;
    let mut bytes = image.into_bytes();
    let tail = (block + 1) * 4096 - 4; // the last four bytes: the block's checksum
    bytes[tail] ^= 0xff;
    let f = tempfile::NamedTempFile::new().expect("temp");
    std::fs::write(f.path(), &bytes).expect("write");
    assert!(
        e2fsck_clean(f.path()).is_err(),
        "e2fsck accepted a corrupted orphan-block checksum — it is not checking the tails, \
         so the gate above proves nothing"
    );
}

/// The orphan file's size in bytes, read by a foreign tool (`debugfs`) from the inode
/// the superblock names.
fn orphan_file_size(path: &Path) -> u64 {
    let ino = header_field(path, "Orphan file inode");
    let out = tool("debugfs")
        .args(["-R", &format!("stat <{ino}>")])
        .arg(path)
        .output()
        .expect("spawn debugfs");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|w| *w != "Size:")
        .nth(1)
        .expect("debugfs reports the inode's size")
        .parse()
        .expect("a numeric size")
}

/// The first physical block of an inode's data, parsed from `debugfs dump_extents`.
fn first_extent_block(path: &Path, ino: u32) -> u64 {
    let out = tool("debugfs")
        .args(["-R", &format!("dump_extents <{ino}>")])
        .arg(path)
        .output()
        .expect("spawn debugfs");
    let text = String::from_utf8_lossy(&out.stdout);
    // The first data row after the "Physical" header maps logical block 0; its columns
    // are [depth, _, entry, _, logical_start, logical_end, phys_start, phys_end, len].
    let row = text
        .lines()
        .skip_while(|l| !l.contains("Physical"))
        .nth(1)
        .expect("an extent row");
    let nums: Vec<u64> = row
        .replace(['/', '-'], " ")
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    nums[6]
}

#[test]
fn differential_oracle_geometry_matches_mke2fs() {
    if !available("mke2fs") || !available("dumpe2fs") {
        return;
    }
    // Build a feature-matched mke2fs baseline and a ferrosys image at the same size,
    // and confirm the geometry-determined dumpe2fs fields are identical. Empty
    // images keep allocation noise minimal.
    for mib in [64u64, 512, 2048] {
        let fers = format_file(TreeBuilder::new(), mib * MIB, options());

        let baseline = tempfile::NamedTempFile::new().expect("temp");
        baseline.as_file().set_len(mib * MIB).expect("truncate");
        let status = tool("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-b", "4096"])
            .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
            .args(["-E", &format!("resize={RESIZE_BLOCKS}")])
            // The baseline needs no feature overrides; it uses mke2fs's default ext4
            // feature set. The geometry diff compares placement, not the checksum
            // fields or the allocation-derived journal, so a byte-exact match of the
            // geometry skeleton is expected.
            .arg(baseline.path())
            .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
            .status()
            .expect("spawn mke2fs");
        assert!(status.success(), "mke2fs baseline failed");

        // The features are the ground the rest of the comparison stands on: two images
        // whose feature words differ are not the same kind of filesystem, and a geometry
        // that matched anyway would be matching by accident.
        assert_eq!(
            feature_set(fers.path()),
            feature_set(baseline.path()),
            "the feature set diverges from the mke2fs baseline at {mib} MiB"
        );

        let ours = geometry_dump(fers.path());
        let theirs = geometry_dump(baseline.path());
        // Guard against a vacuous pass: if the dumpe2fs format drifted so the filter
        // matched nothing, both sides would be empty and the comparison would be
        // `assert_eq!("", "")`. The geometry always has group and placement lines.
        assert!(
            ours.contains("Group 0"),
            "geometry_dump extracted nothing at {mib} MiB — the dumpe2fs format may have drifted"
        );
        assert_eq!(
            ours, theirs,
            "geometry diverges from the mke2fs baseline at {mib} MiB"
        );
    }
}

/// What a [`DumpMask`] does with the lines it matches.
enum MaskAction {
    /// The line may differ, or exist on only one side: it is removed from the
    /// comparison entirely.
    Drop,
    /// Only the trailing `csum 0x…` may differ: it is rewritten to `csum <masked>`,
    /// and everything else on the line still has to match.
    MaskChecksum,
    /// The group header: the descriptor checksum and the `BLOCK_UNINIT` flag may
    /// differ; the group's block range and its other flags still have to match.
    MaskGroupHeader,
    /// The line's leading integer may differ; everything after it still has to match.
    MaskLeadingCount,
}

/// One allowed divergence in the full-dump differential.
struct DumpMask {
    /// Matched against the start of the raw line, indentation included — so the group
    /// section's `"  Free blocks:"` is a different mask than the header total
    /// `"Free blocks:"`, which is compared.
    prefix: &'static str,
    /// A second required substring, for lines a prefix alone cannot single out (the
    /// per-group summary starts with its count). Empty means the prefix decides.
    contains: &'static str,
    action: MaskAction,
    /// Why the divergence is justified. Every mask is a recorded decision; an
    /// unexplained difference is a finding, not a mask candidate.
    reason: &'static str,
}

/// The complete list of lines on which a ferrosys image may differ from the
/// feature-matched `mke2fs` baseline. Everything else in the whole `dumpe2fs` output
/// must match byte for byte.
///
/// Five of the seven masks are one divergence seen through different lines: `mke2fs`
/// aims the journal at the middle of the filesystem while this crate packs it into the
/// first free run — allocation placement, a recorded non-goal. Placement decides which
/// ranges stay free, which group's free-block count absorbs the journal, which groups
/// keep `BLOCK_UNINIT`, and through the bitmap the two checksum lines. Everything the
/// placement does not touch — totals, locations, inode-side counts and ranges, sizes,
/// flags — still has to match exactly.
const FULL_DUMP_MASKS: &[DumpMask] = &[
    DumpMask {
        prefix: "Filesystem flags:",
        contains: "",
        action: MaskAction::Drop,
        reason: "mke2fs stamps the formatting host's directory-hash signedness (signed \
                 on x86); this crate writes the machine-independent unsigned flag on \
                 every host — a deliberate, documented divergence",
    },
    DumpMask {
        prefix: "Lifetime writes:",
        contains: "",
        action: MaskAction::Drop,
        reason: "s_kbytes_written is mke2fs recording its own formatting IO; this crate \
                 leaves the lifetime counter at zero for the kernel to maintain, and \
                 dumpe2fs omits the zero",
    },
    DumpMask {
        prefix: "Directory Hash Seed:",
        contains: "",
        action: MaskAction::Drop,
        reason: "mke2fs draws the seed at random on every run, so no two of its own \
                 runs agree either; this crate takes the seed as an input",
    },
    DumpMask {
        prefix: "Checksum:",
        contains: "",
        action: MaskAction::Drop,
        reason: "the superblock checksum covers the masked header fields above, so it \
                 differs exactly when they do",
    },
    DumpMask {
        prefix: "  Free blocks:",
        contains: "",
        action: MaskAction::Drop,
        reason: "which ranges remain free is journal and orphan-file placement; the \
                 header's free-block total and every inode-side line are still \
                 compared and must match",
    },
    DumpMask {
        prefix: "  ",
        contains: " free blocks, ",
        action: MaskAction::MaskLeadingCount,
        reason: "the group whose free-block count absorbs the journal is placement; \
                 the free-inode, directory, and unused-inode counts on the same line \
                 still have to match",
    },
    DumpMask {
        prefix: "  Block bitmap at",
        contains: "",
        action: MaskAction::MaskChecksum,
        reason: "the block bitmap's bits encode journal and orphan placement, so its \
                 checksum differs; its location still has to match",
    },
    DumpMask {
        prefix: "Group ",
        contains: "",
        action: MaskAction::MaskGroupHeader,
        reason: "the descriptor checksum covers the block-bitmap checksum, and whether \
                 a group keeps BLOCK_UNINIT is whether placement touched it; the \
                 group's block range and its other flags still have to match",
    },
];

/// Rewrite the first `csum 0x…` on the line to `csum <masked>`, leaving everything
/// around it — locations, flags — for the comparison.
fn mask_checksum(line: &str) -> String {
    let Some(pos) = line.find(" csum 0x") else {
        return line.to_string();
    };
    let hex_start = pos + " csum 0x".len();
    let hex_end = line[hex_start..]
        .find(|c: char| !c.is_ascii_hexdigit())
        .map_or(line.len(), |i| hex_start + i);
    format!("{} csum <masked>{}", &line[..pos], &line[hex_end..])
}

/// [`mask_checksum`], plus the `BLOCK_UNINIT` flag removed from the group's flag list
/// in whichever position it appears.
fn mask_group_header(line: &str) -> String {
    mask_checksum(line)
        .replace("BLOCK_UNINIT, ", "")
        .replace(", BLOCK_UNINIT", "")
        .replace("[BLOCK_UNINIT]", "[]")
}

/// Rewrite the line's leading integer (after indentation) to `<masked>`.
fn mask_leading_count(line: &str) -> String {
    let indent = line.len() - line.trim_start().len();
    let digits = line[indent..]
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(line.len() - indent);
    format!("{}<masked>{}", &line[..indent], &line[indent + digits..])
}

/// The whole `dumpe2fs` output as lines, trailing whitespace trimmed (`dumpe2fs` pads
/// some fields to a column).
fn full_dump(path: &Path) -> Vec<String> {
    let out = tool("dumpe2fs").arg(path).output().expect("spawn dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_end().to_string())
        .collect()
}

/// Every `dumpe2fs` line compared, not just the whitelisted geometry: a blacklist
/// differential in which a difference is either on [`FULL_DUMP_MASKS`] with a recorded
/// justification or a failure.
///
/// The geometry gate above proves the placement skeleton matches, but a field it never
/// names — a count, a policy line, something a newer e2fsprogs starts printing — could
/// drift without any test noticing. Here the two dumps are read whole. Each mask must
/// fire at every size, so a mask for a line `dumpe2fs` no longer prints fails the gate
/// rather than lingering as a silent hole. Building this gate is what surfaced (and
/// fixed) `s_overhead_clusters` omitting the journal blocks that `mke2fs` and the
/// kernel's own accounting include.
#[test]
fn differential_oracle_full_dump_matches_mke2fs_except_the_masked_lines() {
    if !available("mke2fs") || !available("dumpe2fs") {
        return;
    }
    for mib in [64u64, 512, 2048] {
        let fers = format_file(TreeBuilder::new(), mib * MIB, options());
        let baseline = mke2fs_baseline(4096, mib * MIB);

        // The ground the comparison stands on: the same kind of filesystem.
        assert_eq!(
            feature_set(fers.path()),
            feature_set(baseline.path()),
            "the feature set diverges from the mke2fs baseline at {mib} MiB"
        );

        let mut fired = [false; FULL_DUMP_MASKS.len()];
        let mut process = |lines: Vec<String>| -> Vec<String> {
            let mut out = Vec::new();
            'line: for l in lines {
                for (i, m) in FULL_DUMP_MASKS.iter().enumerate() {
                    if l.starts_with(m.prefix) && l.contains(m.contains) {
                        fired[i] = true;
                        match m.action {
                            MaskAction::Drop => continue 'line,
                            MaskAction::MaskChecksum => out.push(mask_checksum(&l)),
                            MaskAction::MaskGroupHeader => out.push(mask_group_header(&l)),
                            MaskAction::MaskLeadingCount => out.push(mask_leading_count(&l)),
                        }
                        continue 'line;
                    }
                }
                out.push(l);
            }
            out
        };
        let ours = process(full_dump(fers.path()));
        let theirs = process(full_dump(baseline.path()));

        // Guard against a vacuous pass: a dump that failed to parse would compare as
        // two empty lists.
        assert!(
            ours.iter().any(|l| l.starts_with("Group 0:")),
            "the dump carries no group section at {mib} MiB — dumpe2fs output drifted"
        );

        let count = ours.len().max(theirs.len());
        let mut diffs = Vec::new();
        for i in 0..count {
            let a = ours.get(i).map_or("<missing>", String::as_str);
            let b = theirs.get(i).map_or("<missing>", String::as_str);
            if a != b {
                diffs.push(format!("  ours:   {a}\n  mke2fs: {b}"));
            }
        }
        let shown = diffs
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            diffs.is_empty(),
            "the full dumpe2fs dump diverges from mke2fs at {mib} MiB beyond the \
             masked lines ({} difference(s)):\n{shown}\n\
             An unexplained difference is a finding to fix or to mask with a recorded \
             reason in FULL_DUMP_MASKS.",
            diffs.len()
        );

        // A mask that matches nothing is stale: the line it excuses is gone, so the
        // excuse must go too (or the gate has drifted off the output it thinks it
        // reads).
        for (m, fired) in FULL_DUMP_MASKS.iter().zip(fired) {
            assert!(
                fired,
                "mask `{}` matched no line at {mib} MiB — delete it or renew its \
                 justification ({})",
                m.prefix, m.reason
            );
        }
    }
}

/// An `mke2fs` baseline like [`mke2fs_baseline`] with extra flags appended — the tunable
/// under test (`-N`, `-i`, `-m`, `-L`).
fn mke2fs_baseline_with(size: u64, extra: &[&str]) -> tempfile::NamedTempFile {
    let baseline = tempfile::NamedTempFile::new().expect("temp");
    baseline.as_file().set_len(size).expect("truncate");
    let resize = format!("resize={RESIZE_BLOCKS}");
    let path = baseline.path().to_string_lossy().into_owned();
    let mut args = vec![
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-U",
        "f0e17055-0000-4000-8000-000000000000",
        "-E",
        &resize,
    ];
    args.extend_from_slice(extra);
    args.push(&path);
    let status = tool("mke2fs")
        .args(&args)
        .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
        .status()
        .expect("spawn mke2fs");
    assert!(status.success(), "mke2fs baseline with {extra:?} failed");
    baseline
}

/// A `dumpe2fs -h` field's value as text — for the volume name and other non-numeric
/// fields, where [`header_field`] would fail to parse.
fn header_text(path: &Path, field: &str) -> String {
    let out = tool("dumpe2fs")
        .arg("-h")
        .arg(path)
        .output()
        .expect("spawn dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("dumpe2fs reports no {field}"))
}

#[test]
fn inode_reserved_and_label_overrides_match_mke2fs() {
    if !available("mke2fs") || !available("dumpe2fs") || !available("e2fsck") {
        return;
    }
    // 256 MiB is two whole groups, so both formatters use the same 65536-block count and
    // the tunables are the only thing that varies.
    let size = 256 * MIB;

    // Absolute inode count (`-N`): the count and the per-group density both agree, and the
    // image an override produces still checks clean.
    let mut o = options();
    o.inodes = InodeCount::Count(5000);
    let fers = format_file(TreeBuilder::new(), size, o);
    let base = mke2fs_baseline_with(size, &["-N", "5000"]);
    e2fsck_clean(fers.path()).expect("the -N image is not e2fsck-clean");
    assert_eq!(
        header_field(fers.path(), "Inode count"),
        header_field(base.path(), "Inode count"),
        "-N: inode count",
    );
    assert_eq!(
        header_field(fers.path(), "Inodes per group"),
        header_field(base.path(), "Inodes per group"),
        "-N: inodes per group",
    );

    // Bytes-per-inode (`-i`): the count the ratio yields agrees.
    let mut o = options();
    o.inodes = InodeCount::BytesPerInode(NonZeroU64::new(65536).unwrap());
    let fers = format_file(TreeBuilder::new(), size, o);
    let base = mke2fs_baseline_with(size, &["-i", "65536"]);
    e2fsck_clean(fers.path()).expect("the -i image is not e2fsck-clean");
    assert_eq!(
        header_field(fers.path(), "Inode count"),
        header_field(base.path(), "Inode count"),
        "-i: inode count",
    );

    // Reserved percentage (`-m`), integer and fractional: the reserved block count is the
    // same floor mke2fs computes in floating point, reached here with exact integers.
    for (hundredths, flag) in [(1000u16, "10"), (150, "1.5")] {
        let mut o = options();
        o.reserved = ReservedRatio::from_hundredths_of_percent(hundredths).unwrap();
        let fers = format_file(TreeBuilder::new(), size, o);
        let base = mke2fs_baseline_with(size, &["-m", flag]);
        assert_eq!(
            header_field(fers.path(), "Reserved block count"),
            header_field(base.path(), "Reserved block count"),
            "-m {flag}: reserved block count",
        );
    }

    // Volume label (`-L`): the name reads back byte for byte, and matches mke2fs's.
    let mut o = options();
    o.volume_name = *b"rootfs\0\0\0\0\0\0\0\0\0\0";
    let fers = format_file(TreeBuilder::new(), size, o);
    let base = mke2fs_baseline_with(size, &["-L", "rootfs"]);
    assert_eq!(header_text(fers.path(), "Filesystem volume name"), "rootfs");
    assert_eq!(
        header_text(fers.path(), "Filesystem volume name"),
        header_text(base.path(), "Filesystem volume name"),
        "-L: volume name",
    );
}

#[test]
fn uninit_bg_flags_match_mke2fs() {
    if !available("mke2fs") || !available("dumpe2fs") {
        return;
    }
    // Under metadata_csum the block-group descriptor flags (INODE_UNINIT,
    // BLOCK_UNINIT, ITABLE_ZEROED) and the itable_unused counts follow rules that
    // depend on which groups hold inodes and data, not on exact block placement, so
    // they match a feature-matched mke2fs baseline byte for byte even though the
    // checksums (allocation-sensitive) need not. Both sides omit the journal: it is a
    // data file whose placement ferrosys does not mimic, and where it lands changes
    // which groups are dataless (hence BLOCK_UNINIT). Sizes exercise: a single group,
    // a full 16-group flex block group, a partial trailing flex head (group 16), and a
    // partial final group.
    for mib in [64u64, 200, 2048, 2176] {
        let fers = format_file(TreeBuilder::new(), mib * MIB, options_no_journal());

        let baseline = tempfile::NamedTempFile::new().expect("temp");
        baseline.as_file().set_len(mib * MIB).expect("truncate");
        let status = tool("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-b", "4096"])
            .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
            .args(["-E", &format!("resize={RESIZE_BLOCKS}")])
            .args(["-O", "^has_journal,^dir_index"])
            .arg(baseline.path())
            .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
            .status()
            .expect("spawn mke2fs");
        assert!(status.success(), "mke2fs baseline failed");

        let ours = group_flags(fers.path());
        // Guard against a vacuous pass: the per-group flag lines are always present, so
        // an empty extraction means the dumpe2fs format drifted, not that the flags
        // matched.
        assert!(
            ours.contains("Group 0:"),
            "group_flags extracted nothing at {mib} MiB — the dumpe2fs format may have drifted"
        );
        assert_eq!(
            ours,
            group_flags(baseline.path()),
            "group flags / itable_unused diverge from mke2fs at {mib} MiB"
        );
    }
}

/// Per-group `[FLAGS]` and `itable_unused` counts from `dumpe2fs`, the fields
/// `metadata_csum` governs that do not depend on exact block placement. The bitmap
/// and descriptor checksums are excluded because they follow allocation order, which
/// ferrosys does not mimic.
fn group_flags(path: &Path) -> String {
    let out = tool("dumpe2fs").arg(path).output().expect("spawn dumpe2fs");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|line| {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("Group ") {
                // "Group N: (...) csum 0xXXXX [FLAGS]" -> "Group N: [FLAGS]".
                let num = rest.split(':').next().unwrap_or("");
                let flags = l.find('[').map_or("[]", |i| &l[i..]);
                Some(format!("Group {num}: {flags}"))
            } else if let Some(count) = l.strip_suffix(" unused inodes") {
                // "... 2 directories, 8181 unused inodes" -> "unused 8181".
                count.rsplit(", ").next().map(|n| format!("unused {n}"))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The geometry-determined lines of `dumpe2fs`, with volatile fields removed: group
/// count and ranges, backup and reserved-GDT placement, and per-group bitmap and
/// inode-table locations. Free counts and the hash seed vary
/// with allocation and are excluded.
fn geometry_dump(path: &Path) -> String {
    let out = tool("dumpe2fs").arg(path).output().expect("spawn dumpe2fs");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter(|l| {
            let l = l.trim_start();
            l.starts_with("Group ")
                || l.contains("superblock at")
                || l.contains("Reserved GDT blocks at")
                || l.contains("Block bitmap at")
                || l.contains("Inode bitmap at")
                || l.contains("Inode table at")
        })
        // Strip the "(+N)" / "(bg #0 + N)" annotations that name relative offsets.
        .map(|l| l.split('(').next().unwrap_or(l).trim_end().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A file large enough that its extent leaves cannot fit in the inode's inline
/// root, forcing the tree to spill into an external node block. Each leaf maps at
/// most 32768 blocks (128 MiB), and the inline root holds four, so anything past
/// 512 MiB needs a deeper tree.
const BIG_FILE_BYTES: usize = 600 * 1024 * 1024;
const BIG_FILE_BLOCKS: u64 = BIG_FILE_BYTES as u64 / 4096;

fn big_file_source() -> TreeBuilder {
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    TreeBuilder::new().file(
        b"/big".to_vec(),
        vec![0xab; BIG_FILE_BYTES],
        Metadata::new(0o644, time),
    )
}

/// Options with `metadata_csum` cleared. An external extent node reserves its
/// checksum tail either way; with the feature off the tail stays zero, so the two
/// seams produce different bytes for the same tree and both must check out.
fn options_no_csum() -> FormatOptions {
    let mut o = options();
    o.feature.ro_compat =
        RoCompat::from_bits(o.feature.ro_compat.bits() & !RoCompat::METADATA_CSUM.bits());
    // The stored checksum seed exists to serve those checksums, so it goes with them.
    o.feature.incompat =
        Incompat::from_bits(o.feature.incompat.bits() & !Incompat::CSUM_SEED.bits());
    o
}

#[test]
fn deep_extent_tree_reads_back_and_passes_e2fsck() {
    if !available("e2fsck") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::ExtentNode;
    use ferrosys::ext::Reader;
    use ferrosys::ext::extent::parse_node;

    for (name, has_csum, opts) in [
        ("metadata_csum", true, options()),
        ("no metadata_csum", false, options_no_csum()),
    ] {
        let image = format(big_file_source(), 900 * MIB, opts).expect("format");

        // Reader side: the root is an index node, and every external node's checksum
        // tail verifies. The file's bytes survive the descent through it.
        let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        reader.verify_checksums().expect("checksums verify");
        let inode = reader
            .walk()
            .expect("walk")
            .into_iter()
            .find(|e| e.path == b"/big")
            .expect("the big file is in the tree")
            .inode;

        let root = parse_node(&inode.block).expect("root parses");
        let ExtentNode::Index { depth, entries } = &root else {
            panic!("600 MiB cannot be mapped by the inode's four inline leaves ({name})");
        };
        assert_eq!(*depth, 1, "one external level is enough for 600 MiB");
        assert_eq!(entries.len(), 1, "one node block holds every leaf");

        // i_blocks counts the external node alongside the file's data blocks.
        let node_blocks = entries.len() as u64;
        assert_eq!(inode.blocks, (BIG_FILE_BLOCKS + node_blocks) * 8);

        let back = reader.read_data(&inode).expect("read back");
        assert_eq!(back.len(), BIG_FILE_BYTES);
        assert!(
            back.iter().all(|&b| b == 0xab),
            "the file's contents survive the extent tree ({name})"
        );
        drop(back);

        // Foreign judges: e2fsck validates the tree and its checksum tails, and
        // debugfs independently walks it and agrees on the block accounting.
        let file = write_image(&image);
        e2fsck_clean(file.path())
            .unwrap_or_else(|e| panic!("e2fsck faulted a deep tree ({name}):\n{e}"));

        let ex = tool("debugfs")
            .args(["-R", "ex /big"])
            .arg(file.path())
            .output()
            .expect("spawn debugfs");
        let ex = String::from_utf8_lossy(&ex.stdout);
        assert!(
            ex.lines().any(|l| l.trim_start().starts_with("1/ 1")),
            "debugfs does not see a second extent-tree level ({name}):\n{ex}"
        );

        let stat = tool("debugfs")
            .args(["-R", "stat /big"])
            .arg(file.path())
            .output()
            .expect("spawn debugfs");
        let stat = String::from_utf8_lossy(&stat.stdout);
        let want = format!("Blockcount: {}", (BIG_FILE_BLOCKS + 1) * 8);
        assert!(
            stat.contains(&want),
            "debugfs disagrees on the block count ({name}, expected {want}):\n{stat}"
        );

        // Negative control: the external node's checksum tail is genuinely recomputed,
        // not merely read. `eh_generation` sits inside the region the tail covers and
        // nothing else reads it, so a flipped byte there can surface only as this
        // node's own mismatch. The corruption is applied last, to the on-disk copy the
        // foreign judges have already finished with, so no second image is built.
        if has_csum {
            let node_block = entries[0].leaf;
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.path())
                .expect("reopen the image");
            f.seek(io::SeekFrom::Start(node_block * 4096 + 8))
                .expect("seek to eh_generation");
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).expect("read eh_generation");
            byte[0] ^= 0xff;
            f.seek(io::SeekFrom::Start(node_block * 4096 + 8))
                .expect("seek back");
            f.write_all(&byte).expect("corrupt eh_generation");
            f.flush().expect("flush");

            let mut r = Reader::open(f).expect("open the corrupted image");
            assert!(
                matches!(
                    r.verify_checksums(),
                    Err(ferrosys::ext::ReadError::ChecksumMismatch {
                        object: "extent node",
                        ..
                    })
                ),
                "a corrupted external extent node passed checksum verification"
            );
        }
    }
}

#[test]
fn deep_extent_tree_block_accounting_matches_mke2fs() {
    if !available("mke2fs") || !available("debugfs") {
        return;
    }
    // mke2fs builds depth-N extent trees for large files, so unlike the directory
    // index it is a real differential oracle here. Both formatters map this file with
    // one external node, so both must charge i_blocks for it — the accounting rule,
    // not the identical placement, is what is compared.
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("big"), vec![0xabu8; BIG_FILE_BYTES]).expect("write source");

    let baseline = tempfile::NamedTempFile::new().expect("temp");
    let status = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-b", "4096"])
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .args(["-d"])
        .arg(dir.path())
        .arg(baseline.path())
        .arg(format!("{}", 900 * MIB / 1024))
        .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
        .status()
        .expect("spawn mke2fs");
    assert!(status.success(), "mke2fs baseline failed");

    let blockcount = |path: &Path| -> u64 {
        let out = tool("debugfs")
            .args(["-R", "stat /big"])
            .arg(path)
            .output()
            .expect("spawn debugfs");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .skip_while(|w| *w != "Blockcount:")
            .nth(1)
            .expect("debugfs reports a block count")
            .parse()
            .expect("block count is a number")
    };

    let image = format(big_file_source(), 900 * MIB, options()).expect("format");
    let ours = write_image(&image);
    assert_eq!(
        blockcount(ours.path()),
        blockcount(baseline.path()),
        "i_blocks disagrees with mke2fs on a file whose extent tree needs one node"
    );
}

/// Options with `dir_index` cleared: directories stay linear however large they get.
fn options_no_dir_index() -> FormatOptions {
    let mut o = options();
    o.feature.compat = Compat::from_bits(o.feature.compat.bits() & !Compat::DIR_INDEX.bits());
    o
}

/// A directory of `n` empty files under `/bigdir`, each named with a unique numeric
/// prefix padded to `name_len` bytes. A longer name means fewer entries per block,
/// which is how a directory reaches many entry blocks without many inodes.
fn big_dir_source(n: u32, name_len: usize) -> TreeBuilder {
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    let mut b = TreeBuilder::new().directory(b"/bigdir".to_vec(), Metadata::new(0o755, time));
    for i in 0..n {
        let mut name = format!("/bigdir/entry-name-number-{i:06}").into_bytes();
        name.resize(name.len().max(name_len + b"/bigdir/".len()), b'x');
        b = b.file(name, Vec::new(), Metadata::new(0o644, time));
    }
    b
}

fn debugfs_out(path: &Path, cmd: &str) -> String {
    let out = tool("debugfs")
        .args(["-R", cmd])
        .arg(path)
        .output()
        .expect("spawn debugfs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn a_large_self_written_image_reads_back_whole_at_the_default_limits() {
    // A resource limit added for safety against a hostile image is a contract nothing
    // else checks: it has no signature, no compile error, and no semver signal, and a
    // default set too tight would silently start refusing images this crate itself wrote.
    // So the defaults are exercised against a large image with many names, read back
    // through every path that allocates from a field the image supplies.
    if !available("e2fsck") {
        return;
    }
    // A 2 GiB filesystem, so the size-driven inode count comfortably holds the names.
    const N: u32 = 40_000;
    let image = format(big_dir_source(N, 40), 2048 * MIB, options()).expect("format");
    let mut reader = Reader::open_with(std::io::Cursor::new(image.as_bytes()), &OpenOptions::new())
        .expect("open at the default limits");

    // Every name comes back: the walk's structural bound is derived from the source's
    // own length, so it is orders of magnitude above what a real filesystem holds.
    let walked = reader.walk().expect("walk at the default limits");
    assert_eq!(
        walked.len() as u32,
        N + 2,
        "the walk dropped names at the default limits: {} entries for {N} files, \
         /bigdir, and /lost+found",
        walked.len()
    );

    // The scan reaches a verdict rather than stopping at its cap.
    let report = reader.scan();
    assert!(
        !report.is_truncated(),
        "a sound image filled the finding cap: {:?}",
        report.anomalies()
    );
    assert!(
        report.anomalies().is_empty(),
        "a self-written image scanned dirty: {:?}",
        report.anomalies()
    );

    // And a file reads back at its full length.
    let (_, dir) = reader.lookup(b"/bigdir").expect("lookup /bigdir");
    assert!(!reader.read_dir(&dir).expect("read /bigdir").is_empty());

    let file = write_image(&image);
    e2fsck_clean(file.path()).expect("e2fsck rejects an image this gate read as sound");
}

/// The inode of the sole entry under `/bigdir` in a walked image.
fn bigdir_inode(image: &Image) -> ferrosys::ext::ondisk::Inode {
    use ferrosys::ext::Reader;
    let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
    reader
        .walk()
        .expect("walk")
        .into_iter()
        .find(|e| e.path == b"/bigdir")
        .expect("the directory is in the tree")
        .inode
}

#[test]
fn htree_directory_passes_e2fsck_and_debugfs_walks_it() {
    if !available("e2fsck") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::Reader;
    use ferrosys::ext::ondisk::InodeFlags;

    const N: u32 = 3000;
    let image = format(big_dir_source(N, 24), 64 * MIB, options()).expect("format");

    // Reader side: the directory is marked indexed, and a linear walk of its blocks
    // still recovers every name -- the index hides behind "..'s" record.
    let inode = bigdir_inode(&image);
    assert!(
        inode.flags.contains(InodeFlags::INDEX),
        "a {N}-entry directory must be indexed, flags {:#x}",
        inode.flags.bits()
    );
    let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
    reader.verify_checksums().expect("checksums verify");
    let entries = reader.read_dir(&inode).expect("read_dir");
    let names: std::collections::BTreeSet<Vec<u8>> = entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| e.name.clone())
        .collect();
    assert_eq!(names.len(), N as usize, "every name survives the index");
    assert!(names.contains(b"entry-name-number-002999".as_slice()));

    // Foreign judges: e2fsck validates the index, its ordering, and its checksums.
    let file = write_image(&image);
    e2fsck_clean(file.path()).unwrap_or_else(|e| panic!("e2fsck faulted an htree:\n{e}"));

    let stat = debugfs_out(file.path(), "stat /bigdir");
    assert!(
        stat.contains("Flags: 0x81000"),
        "debugfs does not see the INDEX flag:\n{stat}"
    );

    // debugfs parses the tree independently and reports the shape we wrote.
    let dump = debugfs_out(file.path(), "htree_dump /bigdir");
    assert!(
        dump.contains("Hash Version: 1"),
        "wrong hash algorithm:\n{dump}"
    );
    assert!(
        dump.contains("Indirect levels: 0"),
        "a {N}-entry directory needs no interior level:\n{dump}"
    );
    assert!(
        dump.contains("Number of entries (limit): 507"),
        "wrong index capacity under metadata_csum:\n{dump}"
    );
}

#[test]
fn an_htree_with_an_interior_level_passes_e2fsck() {
    if !available("e2fsck") || !available("debugfs") {
        return;
    }
    // A 4096-byte root names 507 entry blocks. With 200-byte names only 19 records
    // fit in a block, so 10000 of them need 527 entry blocks and the index grows a
    // level of interior nodes between the root and them. This is the only tier that
    // exercises that level end to end.
    const N: u32 = 10_000;
    let image = format(big_dir_source(N, 200), 64 * MIB, options()).expect("format");
    let file = write_image(&image);
    e2fsck_clean(file.path()).unwrap_or_else(|e| panic!("e2fsck faulted a two-level htree:\n{e}"));

    let dump = debugfs_out(file.path(), "htree_dump /bigdir");
    assert!(
        dump.contains("Indirect levels: 1"),
        "a {N}-entry directory needs an interior level:\n{dump}"
    );
}

/// Every hash algorithm, under a nonzero seed, ordering an index the oracle accepts.
///
/// The hash functions have known-answer tests, but only the default variant had ever
/// ordered an index that a foreign checker then read. `e2fsck` recomputes every
/// name's hash with the algorithm and seed the superblock declares and demands the
/// index's ranges contain it — so a `s_def_hash_version` byte wired to a different
/// algorithm than the one the writer hashed with, or a seed stored but not hashed
/// with, fails here. `dumpe2fs` pins the declared algorithm and the exact seed bytes,
/// `debugfs` pins the version byte in the index root, and the crate's reader pins
/// that the index still resolves names.
#[test]
fn every_hash_version_orders_an_index_e2fsck_accepts_under_a_nonzero_seed() {
    if !available("e2fsck") || !available("dumpe2fs") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::ondisk::InodeFlags;
    use ferrosys::ext::{HashVersion, Reader};

    // Sixteen distinct byte values: a seed stored with its words swapped, truncated,
    // or zeroed cannot print back as this sequence.
    const SEED: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const SEED_TEXT: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";

    const N: u32 = 800;
    for (version, name, dx_byte) in [
        (HashVersion::Legacy, "legacy", 0u8),
        (HashVersion::HalfMd4, "half_md4", 1),
        (HashVersion::Tea, "tea", 2),
    ] {
        let mut o = options();
        o.hash_seed = SEED;
        o.hash_version = version;
        let image = format(big_dir_source(N, 24), 64 * MIB, o).expect("format");

        // The gate is vacuous unless the directory is really indexed: a linear
        // directory passes e2fsck without a single hash being checked.
        let inode = bigdir_inode(&image);
        assert!(
            inode.flags.contains(InodeFlags::INDEX),
            "the {name} case's directory is not indexed, so no hash would be verified"
        );

        // The crate's own reader resolves a name through the variant-ordered index
        // and recovers every entry.
        let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        reader
            .lookup(b"/bigdir/entry-name-number-000799")
            .unwrap_or_else(|e| panic!("lookup through the {name} index: {e}"));
        let entries = reader.read_dir(&inode).expect("read_dir");
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.name != b"." && e.name != b"..")
                .count(),
            N as usize,
            "the {name} index dropped entries"
        );

        let file = write_image(&image);
        e2fsck_clean(file.path()).unwrap_or_else(|e| {
            panic!("e2fsck faulted the {name} index under a nonzero seed:\n{e}")
        });

        // The declared algorithm and the exact seed bytes, read by a foreign tool.
        assert_eq!(
            header_text(file.path(), "Default directory hash:"),
            name,
            "the superblock declares a different algorithm than the one requested"
        );
        assert_eq!(
            header_text(file.path(), "Directory Hash Seed:"),
            SEED_TEXT,
            "the stored seed is not the seed given"
        );

        // And the version byte in the index root itself, which the kernel reads in
        // preference to nothing — it must agree with the superblock.
        let dump = debugfs_out(file.path(), "htree_dump /bigdir");
        assert!(
            dump.contains(&format!("Hash Version: {dx_byte}")),
            "the index root's hash version is not {name}'s:\n{dump}"
        );
    }
}

/// A feature word and the bytes written under it must agree, and `large_file` is the
/// pairing the geometry itself can break: the resize inode is a regular file whose size
/// records the classic block map's reach, which at a 4096-byte block is 4 GiB — a large
/// file. `mke2fs` resolves the conflict by setting the feature back; this crate refuses
/// the combination instead. Either way the boundary is the same, and it is the boundary
/// that matters: this pins it against `mke2fs` at every block size, and then confirms
/// that the sizes the rule leaves alone really do write `e2fsck`-clean images without the
/// feature.
#[test]
fn the_large_file_pairing_matches_mke2fs_at_every_block_size() {
    if !available("mke2fs") || !available("dumpe2fs") || !available("e2fsck") {
        return;
    }
    for block_size in [1024u32, 2048, 4096] {
        // The reference's own verdict: `mke2fs -O ^large_file` honors the clear where the
        // resize inode fits under the bound and sets the feature back where it does not.
        let baseline = tempfile::NamedTempFile::new().expect("temp file");
        let status = tool("mke2fs")
            .args(["-q", "-F", "-t", "ext2", "-I", "256"])
            .args(["-b", &block_size.to_string()])
            .args(["-O", "^large_file"])
            .arg(baseline.path())
            .arg("64m")
            .status()
            .expect("spawn mke2fs");
        assert!(status.success(), "mke2fs failed at {block_size}");
        let needed = image_has_feature(baseline.path(), "large_file");

        // The crate's rule, derived from the resize inode's own declared size, must draw
        // the line in the same place.
        let mut o = block_mapped_options(Profile::Ext2, block_size);
        o.feature = o
            .feature
            .with_feature("large_file", false)
            .expect("a known name");
        assert!(o.feature.has_resize_inode());
        let planned = o.feature.validate();
        assert_eq!(
            planned.is_err(),
            needed,
            "at a {block_size}-byte block mke2fs {} large_file, so the rule must {} the set",
            if needed { "reasserts" } else { "drops" },
            if needed { "refuse" } else { "accept" }
        );

        // Where the rule accepts, the image it writes is one `e2fsck` calls clean — the
        // check that the acceptance is not merely permissive.
        if planned.is_ok() {
            let file = format_file(block_mapped_tree(), 64 * MIB, o);
            assert!(
                !image_has_feature(file.path(), "large_file"),
                "the emitted image must carry the feature words asked for"
            );
            e2fsck_clean(file.path()).unwrap_or_else(|e| {
                panic!("e2fsck faulted a {block_size}-byte-block image without large_file:\n{e}")
            });
        }
    }
}

#[test]
fn clearing_dir_index_leaves_a_large_directory_linear() {
    if !available("e2fsck") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::ondisk::InodeFlags;

    let image = format(big_dir_source(3000, 24), 64 * MIB, options_no_dir_index()).expect("format");
    let inode = bigdir_inode(&image);
    assert!(
        !inode.flags.contains(InodeFlags::INDEX),
        "clearing dir_index must leave the directory linear"
    );

    let file = write_image(&image);
    e2fsck_clean(file.path()).unwrap_or_else(|e| panic!("e2fsck faulted a linear directory:\n{e}"));
    let stat = debugfs_out(file.path(), "stat /bigdir");
    assert!(stat.contains("Flags: 0x80000"), "unexpected flags:\n{stat}");
}

/// A directory whose names carry bytes at or above `0x80` — the only names whose
/// hash depends on whether bytes are read as signed or unsigned.
fn accented_dir_source(n: u32) -> TreeBuilder {
    let time = Timestamp::from_secs(FAKE_TIME as i64);
    let mut b = TreeBuilder::new().directory(b"/bigdir".to_vec(), Metadata::new(0o755, time));
    for i in 0..n {
        let mut name = b"/bigdir/caf\xc3\xa9-na\xc3\xafve-".to_vec();
        name.extend_from_slice(format!("{i:06}").as_bytes());
        b = b.file(name, Vec::new(), Metadata::new(0o644, time));
    }
    b
}

#[test]
fn hash_signedness_is_recorded_and_e2fsck_honors_it() {
    if !available("e2fsck") || !available("dumpe2fs") || !available("debugfs") {
        return;
    }
    use ferrosys::ext::HashSignedness;
    use ferrosys::ext::Reader;

    let order = |signedness: HashSignedness| -> Vec<Vec<u8>> {
        let mut o = options();
        o.hash_signedness = signedness;
        let image = format(accented_dir_source(3000), 64 * MIB, o).expect("format");
        let file = write_image(&image);

        // dumpe2fs reads the choice back out of s_flags.
        let hdr = tool("dumpe2fs")
            .arg("-h")
            .arg(file.path())
            .output()
            .expect("spawn dumpe2fs");
        let hdr = String::from_utf8_lossy(&hdr.stdout);
        let want = match signedness {
            HashSignedness::Unsigned => "unsigned_directory_hash",
            HashSignedness::Signed => "signed_directory_hash",
        };
        assert!(hdr.contains(want), "s_flags does not record {want}:\n{hdr}");

        // The real test: e2fsck rehashes every name using the signedness the
        // superblock records and checks it against the block the name landed in. A
        // mismatch between what we ordered by and what we recorded faults here.
        e2fsck_clean(file.path()).unwrap_or_else(|e| panic!("e2fsck faulted a {want} htree:\n{e}"));
        assert!(debugfs_out(file.path(), "htree_dump /bigdir").contains("Hash Version: 1"));

        // The on-disk order of the names is the hash order.
        let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        let inode = bigdir_inode(&image);
        reader
            .read_dir(&inode)
            .expect("read_dir")
            .into_iter()
            .map(|e| e.name)
            .filter(|n| n != b"." && n != b"..")
            .collect()
    };

    let unsigned = order(HashSignedness::Unsigned);
    let signed = order(HashSignedness::Signed);
    assert_eq!(unsigned.len(), 3000);
    assert_eq!(signed.len(), 3000);
    assert_ne!(
        unsigned, signed,
        "high-bit names must order differently under the two signedness rules"
    );

    // Both orderings hold the same names, just in a different sequence.
    let mut a = unsigned;
    let mut b = signed;
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

/// Options at a given block size. The grow target is fixed in bytes, so the reserved
/// descriptor blocks it implies scale with the block size.
fn options_at(block_size: u32) -> FormatOptions {
    let mut o = options();
    o.feature.block_size = block_size;
    o
}

/// Build an `mke2fs` baseline of the given profile at `block_size` and return its file.
/// The profile selects `mke2fs`'s `-t` type, so ext2, ext3, and ext4 baselines share
/// one path.
fn mke2fs_baseline_of(profile: Profile, block_size: u32, size: u64) -> tempfile::NamedTempFile {
    let baseline = tempfile::NamedTempFile::new().expect("temp");
    baseline.as_file().set_len(size).expect("truncate");
    let status = tool("mke2fs")
        .args([
            "-q",
            "-F",
            "-t",
            profile.as_str(),
            "-b",
            &block_size.to_string(),
        ])
        .args(["-U", "f0e17055-0000-4000-8000-000000000000"])
        .args([
            "-E",
            &format!("resize={}", GROW_TARGET / u64::from(block_size)),
        ])
        .arg(baseline.path())
        .env("E2FSPROGS_FAKE_TIME", FAKE_TIME.to_string())
        .status()
        .expect("spawn mke2fs");
    assert!(
        status.success(),
        "mke2fs {} baseline at {block_size} failed",
        profile.as_str()
    );
    baseline
}

/// Build an `mke2fs -t ext4` baseline at `block_size`.
fn mke2fs_baseline(block_size: u32, size: u64) -> tempfile::NamedTempFile {
    mke2fs_baseline_of(Profile::Ext4, block_size, size)
}

fn header_field(path: &Path, field: &str) -> u64 {
    let out = tool("dumpe2fs")
        .arg("-h")
        .arg(path)
        .output()
        .expect("spawn dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.rsplit(':').next().map(|v| v.trim().to_string()))
        .unwrap_or_else(|| panic!("dumpe2fs reports no {field}"))
        .parse()
        .expect("a numeric header field")
}

#[test]
fn every_block_size_passes_e2fsck_and_matches_mke2fs_geometry() {
    if !available("e2fsck") || !available("mke2fs") || !available("dumpe2fs") {
        return;
    }
    // The 1024-byte block size is where the geometry's edges bite: the first data
    // block is 1 rather than 0, a group spans only 8 MiB so a flex block group's
    // inode tables run past their head group and around the backup superblocks they
    // meet, and a group's inode count need not be a multiple of eight.
    for bs in [1024u32, 2048, 4096] {
        for mib in [16u64, 64, 200, 512] {
            let ours = format_file(populated(), mib * MIB, options_at(bs));
            e2fsck_clean(ours.path()).unwrap_or_else(|e| {
                panic!("e2fsck faulted a {bs}-byte-block {mib} MiB image:\n{e}")
            });

            let baseline = mke2fs_baseline(bs, mib * MIB);
            let dump = geometry_dump(ours.path());
            // The same vacuity guard as the sibling gates: a filter that matched nothing
            // would compare two empty strings and pass.
            assert!(
                dump.contains("Group 0"),
                "geometry_dump extracted nothing from the {bs}-byte-block {mib} MiB \
                 image — the dumpe2fs format may have drifted"
            );
            assert_eq!(
                dump,
                geometry_dump(baseline.path()),
                "geometry diverges from mke2fs at {bs}-byte blocks, {mib} MiB"
            );
            for field in ["Block count", "Inode count", "Inodes per group"] {
                assert_eq!(
                    header_field(ours.path(), field),
                    header_field(baseline.path(), field),
                    "{field} diverges from mke2fs at {bs}-byte blocks, {mib} MiB"
                );
            }
        }
    }
}

#[test]
fn a_final_group_too_small_for_mke2fs_is_still_used() {
    if !available("e2fsck") || !available("dumpe2fs") || !available("mke2fs") {
        return;
    }
    // 33 MiB of 2048-byte blocks leaves a 512-block final group. mke2fs discards it
    // and formats 32 MiB; ferrosys keeps it, because it can hold its backup
    // superblock and still leave data blocks free. Both images are valid — this is a
    // sizing policy, not a geometry rule — so the gate pins the difference rather
    // than letting it drift unnoticed.
    let ours = format_file(TreeBuilder::new(), 33 * MIB, options_at(2048));
    e2fsck_clean(ours.path()).expect("a kept partial final group checks clean");

    let baseline = mke2fs_baseline(2048, 33 * MIB);
    let ours_blocks = header_field(ours.path(), "Block count");
    let theirs_blocks = header_field(baseline.path(), "Block count");
    assert_eq!(
        ours_blocks,
        33 * MIB / 2048,
        "the whole device is addressed"
    );
    assert!(
        ours_blocks > theirs_blocks,
        "mke2fs discards the final group, so ferrosys must address more blocks \
         (ours {ours_blocks}, mke2fs {theirs_blocks})"
    );
}

#[test]
fn every_block_size_survives_an_offline_grow() {
    // `dumpe2fs` is as load-bearing here as the other two: it is what reads the grown
    // image's feature set, and the gate's whole assertion is the absence of `meta_bg`.
    // Gating on it keeps a host without it to the loud skip banner rather than a panic
    // from inside a helper.
    if !available("resize2fs") || !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    // Resize safety is the property the crate exists for, and the reserved
    // descriptor blocks that deliver it are sized in blocks, so it must hold at
    // every block size.
    for bs in [1024u32, 2048] {
        let start_file = format_file(populated(), 64 * MIB, options_at(bs));
        for target_mib in [200u64, 512, 2048] {
            let work = tempfile::NamedTempFile::new().expect("temp");
            std::fs::copy(start_file.path(), work.path()).expect("copy");
            work.as_file().set_len(target_mib * MIB).expect("truncate");
            let out = tool("resize2fs")
                .arg(work.path())
                .output()
                .expect("spawn resize2fs");
            assert!(
                out.status.success(),
                "resize2fs to {target_mib} MiB at {bs}-byte blocks failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                !image_has_meta_bg(work.path()),
                "growing to {target_mib} MiB at {bs}-byte blocks forced a meta_bg conversion"
            );
            e2fsck_clean(work.path()).unwrap_or_else(|e| {
                panic!("e2fsck faulted after growth to {target_mib} MiB at {bs}-byte blocks:\n{e}")
            });
        }
    }
}

#[test]
fn a_filesystem_past_thirty_two_bits_streams_and_passes_e2fsck() {
    if !available("e2fsck") || !available("dumpe2fs") {
        return;
    }
    use ferrosys::ext::format_to;
    use ferrosys::ext::ondisk::GroupDescriptor;
    use std::io::{Read, Seek, SeekFrom};

    // 9 TiB of 2048-byte blocks is 4,831,838,208 blocks, past the 2^32 that a 32-bit
    // block number addresses. The same threshold needs 16 TiB of 4096-byte blocks,
    // which is ext4's own maximum file size, so that variant cannot live in a file
    // and belongs to the root-gated loopback tier; 2048 reaches the 64-bit path here.
    const TIB: u64 = 1024 * MIB * 1024;
    let size = 9 * TIB;

    // In the target directory, not the system temp dir: nearly 300 thousand groups'
    // descriptors and bitmaps are real written pages even in a sparse file, and a
    // tmpfs `/tmp` backs them with memory until it returns ENOSPC.
    let file =
        tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).expect("temp in target/");
    let mut o = options_at(2048);
    o.grow = GrowReservation::UpTo(size);
    let layout = format_to(TreeBuilder::new(), size, o, file.as_file()).expect("format_to");

    assert_eq!(layout.total_blocks, size / 2048);
    assert!(
        layout.total_blocks > u64::from(u32::MAX),
        "this size must exceed a 32-bit block number"
    );
    // Past the 32-bit ceiling the resize inode's map cannot name a block of this
    // filesystem, so no reservation is possible however small — a target equal to the size
    // asks for none and gets none, where a larger one is refused outright.
    assert_eq!(
        layout.reserved_gdt_blocks, 0,
        "no reserved descriptor blocks the 32-bit resize map could name"
    );
    assert_eq!(
        std::fs::metadata(file.path()).expect("stat").len(),
        size,
        "the image spans the whole filesystem, however little of it is written"
    );

    // The last group's inode table sits above 2^32, so its descriptor can only be
    // right if the high halves of the 64-byte descriptor were written. Read it
    // straight out of the primary descriptor table.
    let desc_size = 64usize;
    let gdt_offset = (u64::from(layout.first_data_block) + 1) * u64::from(layout.block_size);
    let last = u64::from(layout.group_count - 1);
    let mut raw = vec![0u8; desc_size];
    let mut f = std::fs::File::open(file.path()).expect("open");
    f.seek(SeekFrom::Start(gdt_offset + last * desc_size as u64))
        .expect("seek");
    f.read_exact(&mut raw).expect("read the last descriptor");
    let desc = GroupDescriptor::read_from(&raw, desc_size).expect("parse");
    assert!(
        desc.inode_table > u64::from(u32::MAX),
        "the last group's inode table at {} does not exercise the high half",
        desc.inode_table
    );

    // The foreign judge: e2fsck walks every one of the 294912 group descriptors.
    e2fsck_clean(file.path())
        .unwrap_or_else(|e| panic!("e2fsck faulted a filesystem past 2^32 blocks:\n{e}"));

    let blocks: u64 = header_field(file.path(), "Block count");
    assert_eq!(blocks, layout.total_blocks);

    // The feature policy at this size, pinned in both directions.
    //
    // The image keeps `resize_inode`: inode 7 is written and well-formed, it just maps
    // nothing, which is the same state a filesystem reaches once a resize has consumed
    // every block it had reserved. `dumpe2fs` prints `Reserved GDT blocks` only when some
    // are reserved, so the line's absence is the foreign reading of the zero above, and
    // the `e2fsck -f -n` above is the judge that the pair is a filesystem it accepts.
    //
    // This is a deliberate divergence from `mke2fs`, which drops `resize_inode` entirely
    // above the ceiling (measured at this exact size and block size: its feature line
    // carries no `resize_inode`). Both images are clean; the crate keeps the feature word
    // the caller named rather than clearing a bit behind their back, and reports the
    // reservation it could actually make in the returned layout.
    assert!(
        image_has_feature(file.path(), "resize_inode"),
        "the feature set the caller named is the one written"
    );
    assert_eq!(
        header_field_opt(file.path(), "Reserved GDT blocks"),
        None,
        "dumpe2fs must report no reserved descriptor blocks past the 32-bit ceiling"
    );
}
