//! Reading a filesystem whose journal needs recovery, held to e2fsprogs's own recovery.
//!
//! `debugfs` writes transactions into a journal and leaves the filesystem needing recovery,
//! and `debugfs journal_run` recovers a copy of it. The reader opens the filesystem as it was
//! left, and every block it presents must be the block that recovery leaves — except the two
//! a recovery rewrites to mark the filesystem recovered: the block holding the primary
//! superblock, and the journal's own superblock.
//!
//! The domain: the six tag layouts — journal checksums v3, v2, or none, each with and without
//! 64-bit block numbers — on an `mke2fs` filesystem; the default layout on one this crate
//! wrote; and, across them, every scenario in [`SCENARIOS`].

mod util;

use std::io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use ferrosys::ext::{FormatOptions, OpenOptions, ReadError, ReadPolicy, Reader, Timestamp, format};
use util::{available, tool};

const KIB: usize = 1024;
const MIB: u64 = 1024 * 1024;
const BLOCK: usize = KIB;
const MAGIC: u32 = 0xc03b_3998;

/// What recovery makes of a scenario's log, under a layout that checksums it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    /// Every transaction that committed soundly is applied.
    Replays,
    /// A copy fails its checksum and is skipped.
    SkipsCopies,
    /// A descriptor or revoke block fails its checksum, and nothing is applied.
    Aborts,
}

/// One log: the `debugfs` transactions that write it, then bytes of it to damage.
struct Scenario {
    name: &'static str,
    /// `journal_write` commands, one transaction each.
    transactions: &'static [&'static str],
    /// Bytes to flip, as (log block, offset within it): damage a log can come to by itself.
    damage: &'static [(u32, usize)],
    /// What recovery makes of it where the log carries checksums. A log without them has
    /// nothing to fail, so it replays whatever the damage left.
    expect: Expect,
}

/// Three single-block transactions: each is a descriptor, its data block, and a commit, so
/// the first occupies log blocks 1 to 3, the second 4 to 6, the third 7 to 9.
const THREE: &[&str] = &[
    "jw -b 2000 t1.bin",
    "jw -b 2001 t2.bin",
    "jw -b 2002 t3.bin",
];

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "three transactions",
        transactions: THREE,
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a later revoke",
        transactions: &["jw -b 2000 t1.bin", "jw -r 2000 t2.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a revoke in the same transaction",
        transactions: &["jw -b 2000 -r 2000 t1.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a block logged after its revoke",
        transactions: &["jw -r 2000 t1.bin", "jw -b 2000 t2.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "the last copy applies",
        transactions: &["jw -b 2000 t1.bin", "jw -b 2000 t2.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "an uncommitted transaction",
        transactions: &["jw -b 2000 t1.bin", "jw -b 2001 -c t2.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "an uncommitted revoke",
        transactions: &["jw -b 2000 t1.bin", "jw -r 2000 -c t2.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "an escaped block",
        transactions: &["jw -b 2002 magic.bin"],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "several blocks and a revoke",
        transactions: &[
            "jw -b 2000,2001 t1.bin",
            "jw -b 2001 t2.bin",
            "jw -b 2002,2003 -r 2000 t3.bin",
        ],
        damage: &[],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a damaged copy in the second transaction",
        transactions: THREE,
        damage: &[(5, 100)],
        expect: Expect::SkipsCopies,
    },
    Scenario {
        name: "a damaged copy in the first transaction",
        transactions: THREE,
        damage: &[(2, 100)],
        expect: Expect::SkipsCopies,
    },
    Scenario {
        name: "a damaged later copy leaves the earlier one",
        transactions: &["jw -b 2000 t1.bin", "jw -b 2000 t2.bin"],
        damage: &[(5, 100)],
        expect: Expect::SkipsCopies,
    },
    Scenario {
        name: "a damaged descriptor",
        transactions: THREE,
        damage: &[(4, BLOCK - 1)],
        expect: Expect::Aborts,
    },
    Scenario {
        name: "a damaged commit checksum",
        transactions: THREE,
        damage: &[(6, 0x10)],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a damaged commit magic",
        transactions: THREE,
        damage: &[(6, 0)],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a descriptor out of sequence",
        transactions: THREE,
        damage: &[(4, 11)],
        expect: Expect::Replays,
    },
    Scenario {
        name: "a damaged revoke block",
        transactions: &[
            "jw -b 2000 t1.bin",
            "jw -r 2000 t2.bin",
            "jw -b 2002 t3.bin",
        ],
        damage: &[(4, BLOCK - 1)],
        expect: Expect::Aborts,
    },
];

/// How `debugfs` is asked to set up the journal's checksums.
#[derive(Clone, Copy, Debug)]
enum Checksums {
    V3,
    V2,
    None,
}

impl Checksums {
    fn open(self) -> &'static str {
        match self {
            Checksums::V3 => "jo -c -v 3",
            Checksums::V2 => "jo -c -v 2",
            Checksums::None => "jo",
        }
    }
}

/// A scratch directory holding the transactions' data files.
struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch directory");
        // Four blocks of one byte each, so which transaction's copy reached a block is
        // readable off its first byte; and a block that begins with the log's magic, which
        // the log must escape.
        for (name, byte) in [("t1.bin", 0x11u8), ("t2.bin", 0x22), ("t3.bin", 0x33)] {
            std::fs::write(dir.path().join(name), vec![byte; 4 * BLOCK]).expect("data file");
        }
        let mut magic = vec![0x77u8; BLOCK];
        magic[..4].copy_from_slice(&MAGIC.to_be_bytes());
        std::fs::write(dir.path().join("magic.bin"), magic).expect("data file");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// An `mke2fs` filesystem of 32 MiB at 1 KiB blocks, with or without `64bit`.
fn mke2fs_base(ws: &Workspace, wide: bool) -> Vec<u8> {
    let path = ws.path("base.img");
    let _ = std::fs::remove_file(&path);
    let mut cmd = tool("mke2fs");
    cmd.args(["-q", "-F", "-t", "ext4", "-b", "1024"]);
    if !wide {
        cmd.args(["-O", "^64bit"]);
    }
    let out = cmd.arg(&path).arg("32M").output().expect("mke2fs");
    assert!(
        out.status.success(),
        "mke2fs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&path).expect("read the base")
}

/// A filesystem this crate wrote, of 32 MiB at 1 KiB blocks, in its default profile.
fn ferrosys_base() -> Vec<u8> {
    let mut o = FormatOptions::new([0x42; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
    o.feature = o.feature.with_block_size(1024);
    format(ferrosys::ext::TreeBuilder::new(), 32 * MIB, o)
        .expect("format")
        .into_bytes()
}

/// Run `debugfs -w` with `commands` over the image at `path`.
fn debugfs(ws: &Workspace, path: &Path, commands: &[String]) {
    let script = ws.path("script");
    std::fs::write(&script, commands.join("\n") + "\n").expect("script");
    let out = tool("debugfs")
        .current_dir(ws.dir.path())
        .arg("-w")
        .arg("-f")
        .arg(&script)
        .arg(path)
        .output()
        .expect("debugfs");
    assert!(
        out.status.success(),
        "debugfs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The block of the image holding log block `n`. The journal `mke2fs` and this crate make is
/// one contiguous run, which the test asserts rather than assumes.
fn log_home(ws: &Workspace, path: &Path, n: u32) -> u64 {
    let out = tool("debugfs")
        .current_dir(ws.dir.path())
        .arg("-R")
        .arg(format!("bmap <8> {n}"))
        .arg(path)
        .output()
        .expect("debugfs bmap");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("bmap of log block {n}: {:?}", out))
}

/// Flip one byte of the log.
fn damage(ws: &Workspace, path: &Path, n: u32, offset: usize) {
    let at = log_home(ws, path, n) * BLOCK as u64 + offset as u64;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open");
    let mut byte = [0u8; 1];
    f.seek(SeekFrom::Start(at)).expect("seek");
    f.read_exact(&mut byte).expect("read");
    byte[0] ^= 0xff;
    f.seek(SeekFrom::Start(at)).expect("seek");
    f.write_all(&byte).expect("write");
}

/// The image the oracle's recovery leaves, from a copy of `dirty`.
fn recovered(ws: &Workspace, dirty: &Path) -> Vec<u8> {
    let copy = ws.path("recovered.img");
    std::fs::copy(dirty, &copy).expect("copy");
    let out = tool("debugfs")
        .arg("-w")
        .arg("-R")
        .arg("journal_run")
        .arg(&copy)
        .output()
        .expect("debugfs journal_run");
    assert!(
        out.status.success(),
        "journal_run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&copy).expect("read the recovered image")
}

/// Hold the reader's view of `dirty` to the oracle's recovery of it, block for block, and the
/// two policies to what `expect` says recovery makes of the log.
fn hold(ws: &Workspace, label: &str, dirty: &Path, expect: Expect) {
    let bytes = std::fs::read(dirty).expect("read the dirty image");
    let oracle = recovered(ws, dirty);
    let journal_superblock = log_home(ws, dirty, 0);

    // The strict policy refuses what recovery cannot apply whole.
    let strict = Reader::open(Cursor::new(bytes.as_slice()));
    match expect {
        Expect::Replays => {
            let r = strict.unwrap_or_else(|e| panic!("{label}: a strict open: {e}"));
            assert!(r.needs_recovery(), "{label}");
            assert!(r.journal_replay().is_some(), "{label}: replayed");
        }
        Expect::SkipsCopies => assert!(
            matches!(strict, Err(ReadError::JournalCopyChecksum { .. })),
            "{label}: {:?}",
            strict.err()
        ),
        Expect::Aborts => assert!(
            matches!(strict, Err(ReadError::ChecksumMismatch { object, .. }) if object.starts_with("journal")),
            "{label}: {:?}",
            strict.err()
        ),
    }

    // The lenient policy reads what recovery leaves, and a scan says what it could not apply.
    let mut r = Reader::open_with(
        Cursor::new(bytes.as_slice()),
        &OpenOptions::new().policy(ReadPolicy::Lenient),
    )
    .unwrap_or_else(|e| panic!("{label}: a lenient open: {e}"));
    let blocks = r.superblock().blocks_count;
    assert_eq!(oracle.len() as u64, blocks * BLOCK as u64, "{label}");
    let mut differ = Vec::new();
    for block in 0..blocks {
        if block == 1 || block == journal_superblock {
            continue;
        }
        let at = block as usize * BLOCK;
        let ours = r.read_block(block).expect("read a block");
        if ours != oracle[at..at + BLOCK] {
            differ.push(block);
        }
    }
    assert!(
        differ.is_empty(),
        "{label}: blocks unlike the oracle's: {differ:?}"
    );
    // A filesystem needing recovery was not cleanly unmounted, which a scan names whatever
    // recovery made of the log. Anything past that is what recovery could not apply.
    let findings = r.scan();
    let unclean = ReadError::NotCleanlyUnmounted.anomaly();
    assert!(
        findings.anomalies().contains(&unclean),
        "{label}: the scan names the unclean shutdown: {:?}",
        findings.anomalies()
    );
    let rest: Vec<_> = findings
        .anomalies()
        .iter()
        .filter(|a| **a != unclean)
        .collect();
    match expect {
        Expect::Replays => assert!(rest.is_empty(), "{label}: {rest:?}"),
        Expect::SkipsCopies | Expect::Aborts => {
            assert!(!rest.is_empty(), "{label}: the scan names the fault");
        }
    }
}

/// Write `scenario`'s log into a copy of `base`, damage it, and hold the reader to it.
fn run(ws: &Workspace, base: &[u8], checksums: Checksums, label: &str, scenario: &Scenario) {
    let dirty = ws.path("dirty.img");
    std::fs::write(&dirty, base).expect("write the base");
    let mut commands = vec![checksums.open().to_string()];
    commands.extend(scenario.transactions.iter().map(|t| (*t).to_string()));
    commands.push("jc".to_string());
    debugfs(ws, &dirty, &commands);
    for &(n, offset) in scenario.damage {
        damage(ws, &dirty, n, offset);
    }
    let expect = match checksums {
        Checksums::None => Expect::Replays,
        Checksums::V2 | Checksums::V3 => scenario.expect,
    };
    hold(ws, &format!("{label}, {}", scenario.name), &dirty, expect);
}

#[test]
fn every_block_is_what_recovery_leaves() {
    if !available("debugfs") || !available("mke2fs") {
        return;
    }
    let ws = Workspace::new();
    let mut held = 0;
    for wide in [true, false] {
        let base = mke2fs_base(&ws, wide);
        for checksums in [Checksums::V3, Checksums::V2, Checksums::None] {
            let label = format!("{checksums:?}, {}", if wide { "64-bit" } else { "32-bit" });
            for scenario in SCENARIOS {
                run(&ws, &base, checksums, &label, scenario);
                held += 1;
            }
        }
    }
    let ours = ferrosys_base();
    for scenario in SCENARIOS {
        run(
            &ws,
            &ours,
            Checksums::V3,
            "this crate's filesystem",
            scenario,
        );
        held += 1;
    }
    assert_eq!(held, 7 * SCENARIOS.len());
}

#[test]
fn a_log_that_wraps_past_the_journal_end_is_followed() {
    // The log continues at the journal's first log block after its last. A sound log is
    // moved so it begins two blocks before the end, which puts the wrap inside the first
    // transaction's data, and the journal superblock is pointed at the new start.
    if !available("debugfs") || !available("mke2fs") {
        return;
    }
    let ws = Workspace::new();
    let base = mke2fs_base(&ws, true);
    let dirty = ws.path("dirty.img");
    std::fs::write(&dirty, &base).expect("write the base");
    let mut commands = vec![Checksums::V3.open().to_string()];
    commands.extend(THREE.iter().map(|t| (*t).to_string()));
    commands.push("jc".to_string());
    debugfs(&ws, &dirty, &commands);

    let mut image = std::fs::read(&dirty).expect("read");
    let home = |n: u32| log_home(&ws, &dirty, n) as usize * BLOCK;
    let jsb = home(0);
    let max_len = u32::from_be_bytes(image[jsb + 0x10..jsb + 0x14].try_into().unwrap());
    let first = u32::from_be_bytes(image[jsb + 0x14..jsb + 0x18].try_into().unwrap());
    let log: Vec<Vec<u8>> = (1..=9)
        .map(|n| image[home(n)..home(n) + BLOCK].to_vec())
        .collect();
    for n in 1..=9 {
        image[home(n)..home(n) + BLOCK].fill(0);
    }
    let start = max_len - 2;
    let mut at = start;
    for block in &log {
        image[home(at)..home(at) + BLOCK].copy_from_slice(block);
        at = if at + 1 >= max_len { first } else { at + 1 };
    }
    image[jsb + 0x1c..jsb + 0x20].copy_from_slice(&start.to_be_bytes());
    // The journal superblock's checksum covers the start: crc32c over the record with the
    // checksum's own four bytes as zero.
    let record = &image[jsb..jsb + 1024];
    let c = ferrosys::crc32c(!0, &record[..0xfc]);
    let c = ferrosys::crc32c(c, &[0u8; 4]);
    let c = ferrosys::crc32c(c, &record[0x100..]);
    image[jsb + 0xfc..jsb + 0x100].copy_from_slice(&c.to_be_bytes());
    std::fs::write(&dirty, &image).expect("write");

    hold(&ws, "a wrapped log", &dirty, Expect::Replays);
    let r = Reader::open(Cursor::new(image.as_slice())).expect("open");
    assert_eq!(r.journal_replay().expect("replayed").transactions, 3);
}

#[test]
fn transaction_numbers_wrap_past_the_top_of_their_range() {
    // Sequence numbers are 32 bits and wrap. A log whose first transaction is the last
    // number below 2^32 and whose third revokes the first's block is followed across the
    // wrap, and the revoke still reaches back.
    if !available("debugfs") || !available("mke2fs") {
        return;
    }
    let ws = Workspace::new();
    let mut base = mke2fs_base(&ws, true);
    // The journal superblock of a fresh filesystem expects sequence 1; it is set to expect
    // 2^32 - 2, and its checksum is left for `debugfs` to rewrite when it opens the journal
    // with checksums.
    let path = ws.path("base.img");
    std::fs::write(&path, &base).expect("write");
    let jsb = log_home(&ws, &path, 0) as usize * BLOCK;
    base[jsb + 0x18..jsb + 0x1c].copy_from_slice(&(u32::MAX - 1).to_be_bytes());
    let scenario = Scenario {
        name: "sequence numbers past 2^32",
        transactions: &[
            "jw -b 2000 t1.bin",
            "jw -b 2001 t2.bin",
            "jw -b 2002 -r 2000 t3.bin",
        ],
        damage: &[],
        expect: Expect::Replays,
    };
    run(&ws, &base, Checksums::None, "a fresh journal", &scenario);
}

#[test]
fn a_journaled_superblock_is_the_superblock_read() {
    // A transaction carrying the block that holds the primary superblock: recovery writes it
    // home, and the reader reads the superblock through the replay. Here the copy changes the
    // label, and it is held to every check the home copy is.
    if !available("debugfs") || !available("mke2fs") {
        return;
    }
    let ws = Workspace::new();
    let base = mke2fs_base(&ws, true);
    let mut block = base[BLOCK..2 * BLOCK].to_vec();
    block[0x78..0x88].copy_from_slice(b"from-the-journal");
    // The superblock's own checksum covers the label: crc32c over everything before it,
    // stored little-endian.
    let c = ferrosys::crc32c(!0, &block[..0x3fc]);
    block[0x3fc..].copy_from_slice(&c.to_le_bytes());
    std::fs::write(ws.path("sb.bin"), &block).expect("write");

    let dirty = ws.path("dirty.img");
    std::fs::write(&dirty, &base).expect("write the base");
    debugfs(
        &ws,
        &dirty,
        &[
            Checksums::V3.open().to_string(),
            "jw -b 1 sb.bin".to_string(),
            "jc".to_string(),
        ],
    );
    let bytes = std::fs::read(&dirty).expect("read");
    let oracle = recovered(&ws, &dirty);
    let r = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
    assert_eq!(&r.superblock().volume_name, b"from-the-journal");
    assert_eq!(&oracle[BLOCK + 0x78..BLOCK + 0x88], b"from-the-journal");
}
