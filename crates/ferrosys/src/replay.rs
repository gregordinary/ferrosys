//! Recovering a jbd2 log without writing it: which home blocks a recovery rewrites, and
//! where in the image the copy each one takes sits.
//!
//! A filesystem that was not unmounted cleanly carries `needs_recovery`, and its log holds
//! committed transactions whose blocks have not reached their homes. [`plan`] walks that log
//! and decides what a recovery would apply, and the reader lays the answer over every read
//! it makes. Nothing is written: the plan names, for each home block, the block in the image
//! that holds the copy recovery would put there.
//!
//! # Purity
//!
//! The planner reads through a [`Log`] it is handed and nothing else, and it decides
//! everything from what that returns. It allocates in proportion to the transactions in the
//! log, and visits no more blocks than the journal spans however its fields are set.
//!
//! # Where the rules come from
//!
//! The layouts, the flag values, and three rules are the jbd2 documentation's: a revoke
//! record stops an earlier copy of its block from applying, a transaction without a sound
//! commit record is discarded, and an escaped block has its first four bytes restored to the
//! magic. Everything else here is the behaviour of e2fsprogs's recovery, observed by writing
//! logs of every shape and replaying them, and this module reproduces what was observed:
//!
//! - a tag is 16 bytes under `csum_v3`; 8 bytes otherwise, 12 under `64bit`, and two more
//!   under `csum_v2`; and the 16-byte UUID follows any tag without the same-UUID flag;
//! - the log continues at `s_first` after the journal's last block;
//! - a revoke record cancels the copies of its block in its own transaction and every one
//!   before it;
//! - the log ends at the first block whose magic or sequence is not the expected one, and at
//!   a commit block whose checksum does not hold, which discards that transaction and every
//!   one after it;
//! - copies apply in log order, a copy whose checksum does not hold is skipped, and the copy
//!   before it stands;
//! - a descriptor or revoke block whose checksum does not hold stops recovery before anything
//!   is applied.
//!
//! What no pinned tool can produce, and so cannot be checked, is refused rather than guessed
//! at: the v1 commit checksum, asynchronous commits, fast commits, a deleted-block tag, both
//! checksum versions at once, and any journal feature this module does not name.

use std::collections::{BTreeMap, HashMap};

use crate::bytes::{get_u32_be, get_u64_be};
use crate::crc32c::crc32c;
use crate::journal::{
    self, BLOCKTYPE_COMMIT, BLOCKTYPE_DESCRIPTOR, BLOCKTYPE_REVOKE, COMPAT_CHECKSUM, CRC32C_CHKSUM,
    INCOMPAT_64BIT, INCOMPAT_ASYNC_COMMIT, INCOMPAT_CSUM_V2, INCOMPAT_CSUM_V3,
    INCOMPAT_FAST_COMMIT, INCOMPAT_REVOKE, JBD2_MAGIC, JBD2_SUPERBLOCK_V1, JBD2_SUPERBLOCK_V2,
    TAG_DELETED, TAG_ESCAPED, TAG_LAST, TAG_SAME_UUID, offset,
};
use crate::read::ReadError;

/// The most blocks a journal may span: the largest journal `mke2fs` documents creating. A
/// superblock claiming more is refused before a block of the log is read.
const MAX_JOURNAL_BLOCKS: u32 = 10_240_000;

/// The size of a block header: magic, block type, and sequence, each a big-endian word.
const HEADER: usize = 12;

/// The size of the checksum tail a descriptor or revoke block carries under `csum_v2` or
/// `csum_v3`.
const TAIL: usize = 4;

/// Where the commit block's checksum sits (`h_chksum[0]`).
const COMMIT_CHECKSUM: usize = 0x10;

/// Where a revoke block's byte count sits (`r_count`), and where its records begin.
const REVOKE_COUNT: usize = 0x0c;
const REVOKE_RECORDS: usize = 0x10;

/// The 16-byte UUID that follows a tag without the same-UUID flag.
const TAG_UUID: usize = 16;

/// The blocks of a journal, as the reader that holds the image reaches them.
pub(crate) trait Log {
    /// The block of the image that holds log block `n`.
    fn locate(&mut self, n: u32) -> Result<u64, ReadError>;
    /// The bytes of log block `n`, as the image holds them.
    fn read(&mut self, n: u32) -> Result<Vec<u8>, ReadError>;
}

/// What a recovery would apply: for each home block, where the copy it takes sits.
#[derive(Debug, Default)]
pub(crate) struct Replay {
    /// Home block to the copy recovery puts there.
    pub copies: BTreeMap<u64, Copy>,
    /// Committed transactions in the log.
    pub transactions: u32,
    /// Copies skipped because their checksum does not hold, in log order.
    pub skipped: Vec<Skipped>,
}

/// The copy a home block takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Copy {
    /// The block of the image holding it.
    pub at: u64,
    /// Whether its first four bytes were logged as zeroes in place of the magic, and are to
    /// be put back.
    pub escaped: bool,
}

/// A copy a recovery skips, because its checksum does not hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Skipped {
    /// The home block it would have rewritten.
    pub home: u64,
    /// The transaction it was logged in.
    pub sequence: u32,
    /// The checksum its tag records.
    pub stored: u32,
    /// The checksum its bytes compute to.
    pub computed: u32,
}

/// Which checksums the log carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Checksums {
    None,
    V2,
    V3,
}

/// What the journal superblock says about the log's shape.
struct Layout {
    max_len: u32,
    first: u32,
    checksums: Checksums,
    wide: bool,
    seed: u32,
}

impl Layout {
    /// A tag's size, the UUID that may follow it aside.
    fn tag_size(&self) -> usize {
        match self.checksums {
            Checksums::V3 => 16,
            Checksums::V2 => 10 + if self.wide { 4 } else { 0 },
            Checksums::None => 8 + if self.wide { 4 } else { 0 },
        }
    }

    /// Where the room for tags or records ends in a block of `len` bytes.
    fn body_end(&self, len: usize) -> usize {
        match self.checksums {
            Checksums::None => len,
            Checksums::V2 | Checksums::V3 => len.saturating_sub(TAIL),
        }
    }

    /// The log block after `n`: the next one, or `s_first` after the journal's last.
    fn next(&self, n: u32) -> u32 {
        if n.saturating_add(1) >= self.max_len {
            self.first
        } else {
            n + 1
        }
    }
}

/// One copy as a descriptor names it.
struct Tag {
    home: u64,
    at: u32,
    escaped: bool,
    stored: u32,
}

/// A transaction as the log holds it.
struct Transaction {
    sequence: u32,
    tags: Vec<Tag>,
    revokes: Vec<u64>,
}

/// Decide what recovering the log whose superblock is `superblock` would apply.
///
/// `fs_blocks` bounds every home block a copy may name, and `journal_blocks` the blocks the
/// journal file maps, which `s_maxlen` may not exceed.
///
/// # Errors
///
/// [`ReadError::JournalUnsupported`] for a log this module does not replay;
/// [`ReadError::JournalMalformed`] for one whose fields or records do not describe a log;
/// [`ReadError::ChecksumMismatch`] for a journal superblock, descriptor, or revoke block whose
/// checksum does not hold; and whatever `log` returns for a block it cannot read.
pub(crate) fn plan(
    superblock: &[u8],
    block_size: usize,
    fs_blocks: u64,
    journal_blocks: u64,
    log: &mut impl Log,
) -> Result<Replay, ReadError> {
    let layout = layout(superblock, block_size, journal_blocks)?;
    let start = get_u32_be(superblock, offset::START);
    if start == 0 {
        // An empty log: nothing was committed that has not reached its home.
        return Ok(Replay::default());
    }
    if start < layout.first || start >= layout.max_len {
        return Err(malformed(0, "a log start outside the journal"));
    }
    let sequence = get_u32_be(superblock, offset::SEQUENCE);
    let committed = scan(&layout, start, sequence, block_size, log)?;
    apply(&layout, committed, fs_blocks, log)
}

/// Read the journal superblock's description of the log, refusing what is not replayed.
fn layout(superblock: &[u8], block_size: usize, journal_blocks: u64) -> Result<Layout, ReadError> {
    if superblock.len() < journal::SUPERBLOCK_SIZE || get_u32_be(superblock, 0) != JBD2_MAGIC {
        return Err(malformed(0, "a journal superblock without the jbd2 magic"));
    }
    match get_u32_be(superblock, 4) {
        JBD2_SUPERBLOCK_V2 => {}
        JBD2_SUPERBLOCK_V1 => return Err(unsupported("a version 1 journal superblock")),
        _ => return Err(malformed(0, "a journal superblock of an unknown version")),
    }
    let compat = get_u32_be(superblock, offset::FEATURE_COMPAT);
    let incompat = get_u32_be(superblock, offset::FEATURE_INCOMPAT);
    let ro_compat = get_u32_be(superblock, offset::FEATURE_RO_COMPAT);
    if compat & COMPAT_CHECKSUM != 0 {
        return Err(unsupported("the version 1 commit checksum"));
    }
    if incompat & INCOMPAT_ASYNC_COMMIT != 0 {
        return Err(unsupported("asynchronous commits"));
    }
    if incompat & INCOMPAT_FAST_COMMIT != 0 {
        return Err(unsupported("fast commits"));
    }
    let known = INCOMPAT_REVOKE | INCOMPAT_64BIT | INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3;
    if incompat & !known != 0 {
        return Err(unsupported(
            "an incompatible journal feature it does not know",
        ));
    }
    if ro_compat != 0 {
        return Err(unsupported(
            "a read-only-compatible journal feature it does not know",
        ));
    }
    let checksums = match (
        incompat & INCOMPAT_CSUM_V2 != 0,
        incompat & INCOMPAT_CSUM_V3 != 0,
    ) {
        (false, false) => Checksums::None,
        (true, false) => Checksums::V2,
        (false, true) => Checksums::V3,
        (true, true) => return Err(unsupported("both journal checksum versions at once")),
    };
    if checksums != Checksums::None {
        let kind = superblock[offset::CHECKSUM_TYPE];
        if kind != CRC32C_CHKSUM {
            return Err(unsupported("a journal checksum other than crc32c"));
        }
        let stored = get_u32_be(superblock, offset::CHECKSUM);
        let computed = journal::superblock_checksum(superblock);
        if stored != computed {
            return Err(ReadError::ChecksumMismatch {
                object: "journal superblock",
                index: 0,
                stored,
                computed,
            });
        }
    }
    if usize::try_from(get_u32_be(superblock, offset::BLOCK_SIZE)).ok() != Some(block_size) {
        return Err(malformed(
            0,
            "a journal block size other than the filesystem's",
        ));
    }
    let max_len = get_u32_be(superblock, offset::MAX_LEN);
    let first = get_u32_be(superblock, offset::FIRST);
    if max_len > MAX_JOURNAL_BLOCKS || u64::from(max_len) > journal_blocks {
        return Err(malformed(0, "a journal longer than the file holding it"));
    }
    if first == 0 || first >= max_len {
        return Err(malformed(0, "a first log block outside the journal"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&superblock[offset::UUID..offset::UUID + 16]);
    Ok(Layout {
        max_len,
        first,
        checksums,
        wide: incompat & INCOMPAT_64BIT != 0,
        seed: crc32c(!0, &uuid),
    })
}

/// Walk the log from `start`, and return the transactions a sound commit record closes, in
/// log order.
fn scan(
    layout: &Layout,
    start: u32,
    sequence: u32,
    block_size: usize,
    log: &mut impl Log,
) -> Result<Vec<Transaction>, ReadError> {
    // A sound log is shorter than the journal: it would otherwise have overwritten its own
    // start. Counting the blocks visited is what ends a walk around a log whose every block
    // claims the sequence it is expected to.
    let span = layout.max_len - layout.first;
    let mut visited = 0u32;
    let mut visit = |at: u32| -> Result<(), ReadError> {
        visited += 1;
        if visited > span {
            return Err(malformed(at, "a log longer than its journal"));
        }
        Ok(())
    };

    let mut committed = Vec::new();
    let mut current = Transaction {
        sequence,
        tags: Vec::new(),
        revokes: Vec::new(),
    };
    let mut at = start;
    loop {
        visit(at)?;
        let block = log.read(at)?;
        if block.len() != block_size
            || get_u32_be(&block, 0) != JBD2_MAGIC
            || get_u32_be(&block, 8) != current.sequence
        {
            break;
        }
        match get_u32_be(&block, 4) {
            BLOCKTYPE_DESCRIPTOR => {
                check_tail(layout, &block, "journal descriptor", at)?;
                for (home, escaped, stored) in tags(layout, &block, at)? {
                    at = layout.next(at);
                    visit(at)?;
                    current.tags.push(Tag {
                        home,
                        at,
                        escaped,
                        stored,
                    });
                }
            }
            BLOCKTYPE_REVOKE => {
                check_tail(layout, &block, "journal revoke block", at)?;
                current.revokes.extend(revokes(layout, &block, at)?);
            }
            BLOCKTYPE_COMMIT => {
                if !commit_holds(layout, &block) {
                    break;
                }
                let next = current.sequence.wrapping_add(1);
                committed.push(std::mem::replace(
                    &mut current,
                    Transaction {
                        sequence: next,
                        tags: Vec::new(),
                        revokes: Vec::new(),
                    },
                ));
            }
            // A block of no type the log uses ends it, as one with the wrong sequence does.
            _ => break,
        }
        at = layout.next(at);
    }
    Ok(committed)
}

/// Decide which copy each home block takes, from the committed transactions in log order.
fn apply(
    layout: &Layout,
    committed: Vec<Transaction>,
    fs_blocks: u64,
    log: &mut impl Log,
) -> Result<Replay, ReadError> {
    // The last transaction revoking each block. A transaction's position in the log orders
    // it, so the comparison below needs no arithmetic on sequence numbers, which wrap.
    let mut revoked: HashMap<u64, usize> = HashMap::new();
    for (index, transaction) in committed.iter().enumerate() {
        for &home in &transaction.revokes {
            revoked.insert(home, index);
        }
    }

    let mut replay = Replay {
        transactions: u32::try_from(committed.len()).unwrap_or(u32::MAX),
        ..Replay::default()
    };
    for (index, transaction) in committed.iter().enumerate() {
        for tag in &transaction.tags {
            if revoked.get(&tag.home).is_some_and(|&by| by >= index) {
                continue;
            }
            if tag.home >= fs_blocks {
                return Err(malformed(tag.at, "a copy of a block past the filesystem"));
            }
            if layout.checksums != Checksums::None {
                let bytes = log.read(tag.at)?;
                let computed = tag_checksum(layout, transaction.sequence, &bytes);
                if computed != tag.stored {
                    replay.skipped.push(Skipped {
                        home: tag.home,
                        sequence: transaction.sequence,
                        stored: tag.stored,
                        computed,
                    });
                    continue;
                }
            }
            let at = log.locate(tag.at)?;
            replay.copies.insert(
                tag.home,
                Copy {
                    at,
                    escaped: tag.escaped,
                },
            );
        }
    }
    Ok(replay)
}

/// The tags of a descriptor block: each copy's home block, whether it was escaped, and the
/// checksum its tag records — the low sixteen bits under `csum_v2`.
fn tags(layout: &Layout, block: &[u8], at: u32) -> Result<Vec<(u64, bool, u32)>, ReadError> {
    let size = layout.tag_size();
    let end = layout.body_end(block.len());
    let mut out = Vec::new();
    let mut pos = HEADER;
    while pos + size <= end {
        let low = u64::from(get_u32_be(block, pos));
        let (flags, high, stored) = match layout.checksums {
            Checksums::V3 => (
                get_u32_be(block, pos + 4),
                get_u32_be(block, pos + 8),
                get_u32_be(block, pos + 12),
            ),
            Checksums::V2 | Checksums::None => {
                let word = get_u32_be(block, pos + 4);
                let high = if layout.wide {
                    get_u32_be(block, pos + 8)
                } else {
                    0
                };
                (word & 0xffff, high, word >> 16)
            }
        };
        if flags & TAG_DELETED != 0 {
            return Err(unsupported("a tag marking a deleted block"));
        }
        let high = if layout.wide { u64::from(high) } else { 0 };
        out.push(((high << 32) | low, flags & TAG_ESCAPED != 0, stored));
        pos += size;
        if flags & TAG_SAME_UUID == 0 {
            pos += TAG_UUID;
        }
        if flags & TAG_LAST != 0 {
            return Ok(out);
        }
    }
    if out.is_empty() {
        return Err(malformed(at, "a descriptor block with no tag"));
    }
    Ok(out)
}

/// The blocks a revoke block names.
fn revokes(layout: &Layout, block: &[u8], at: u32) -> Result<Vec<u64>, ReadError> {
    let record = if layout.wide { 8 } else { 4 };
    let count = usize::try_from(get_u32_be(block, REVOKE_COUNT)).unwrap_or(usize::MAX);
    if count < REVOKE_RECORDS
        || count > layout.body_end(block.len())
        || !(count - REVOKE_RECORDS).is_multiple_of(record)
    {
        return Err(malformed(
            at,
            "a revoke block whose count runs past its records",
        ));
    }
    Ok((REVOKE_RECORDS..count)
        .step_by(record)
        .map(|pos| {
            if layout.wide {
                get_u64_be(block, pos)
            } else {
                u64::from(get_u32_be(block, pos))
            }
        })
        .collect())
}

/// Refuse a descriptor or revoke block whose checksum tail does not hold. Such a block ends
/// recovery before anything is applied.
fn check_tail(
    layout: &Layout,
    block: &[u8],
    object: &'static str,
    at: u32,
) -> Result<(), ReadError> {
    if layout.checksums == Checksums::None {
        return Ok(());
    }
    let tail = block.len() - TAIL;
    let stored = get_u32_be(block, tail);
    let computed = crc32c(crc32c(layout.seed, &block[..tail]), &[0u8; TAIL]);
    if stored != computed {
        return Err(ReadError::ChecksumMismatch {
            object,
            index: u64::from(at),
            stored,
            computed,
        });
    }
    Ok(())
}

/// Whether a commit block's checksum holds, where the log carries one.
fn commit_holds(layout: &Layout, block: &[u8]) -> bool {
    if layout.checksums == Checksums::None {
        return true;
    }
    let stored = get_u32_be(block, COMMIT_CHECKSUM);
    let c = crc32c(layout.seed, &block[..COMMIT_CHECKSUM]);
    let c = crc32c(c, &[0u8; 4]);
    crc32c(c, &block[COMMIT_CHECKSUM + 4..]) == stored
}

/// The checksum a data block's tag records: over the transaction's sequence number, big-endian,
/// then the block as it was logged. `csum_v2` keeps the low sixteen bits.
fn tag_checksum(layout: &Layout, sequence: u32, bytes: &[u8]) -> u32 {
    let c = crc32c(crc32c(layout.seed, &sequence.to_be_bytes()), bytes);
    match layout.checksums {
        Checksums::V2 => c & 0xffff,
        Checksums::V3 | Checksums::None => c,
    }
}

fn malformed(log_block: u32, detail: &'static str) -> ReadError {
    ReadError::JournalMalformed { log_block, detail }
}

fn unsupported(feature: &'static str) -> ReadError {
    ReadError::JournalUnsupported { feature }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::put_u32_be;

    const BS: usize = 1024;

    /// A change made to a journal superblock before it is planned.
    type Edit = fn(&mut Vec<u8>);

    /// A journal held in memory, one block per entry, its blocks placed at block 1000 on.
    struct Memory(Vec<Vec<u8>>);

    impl Log for Memory {
        fn locate(&mut self, n: u32) -> Result<u64, ReadError> {
            Ok(1000 + u64::from(n))
        }
        fn read(&mut self, n: u32) -> Result<Vec<u8>, ReadError> {
            self.0
                .get(n as usize)
                .cloned()
                .ok_or(ReadError::OutOfRange {
                    what: "block",
                    index: u64::from(n),
                })
        }
    }

    /// A journal of `len` blocks with no checksums and a log starting at block 1, expecting
    /// transaction 7.
    fn journal(len: u32) -> Memory {
        let mut sb = vec![0u8; BS];
        put_u32_be(&mut sb, 0, JBD2_MAGIC);
        put_u32_be(&mut sb, 4, JBD2_SUPERBLOCK_V2);
        put_u32_be(&mut sb, offset::BLOCK_SIZE, BS as u32);
        put_u32_be(&mut sb, offset::MAX_LEN, len);
        put_u32_be(&mut sb, offset::FIRST, 1);
        put_u32_be(&mut sb, offset::SEQUENCE, 7);
        put_u32_be(&mut sb, offset::START, 1);
        let mut blocks = vec![sb];
        blocks.resize(len as usize, vec![0u8; BS]);
        Memory(blocks)
    }

    fn header(block: &mut [u8], kind: u32, sequence: u32) {
        put_u32_be(block, 0, JBD2_MAGIC);
        put_u32_be(block, 4, kind);
        put_u32_be(block, 8, sequence);
    }

    /// One transaction at log block `at`: a descriptor naming `homes` (32-bit tags, the first
    /// with a UUID after it), their data, and a commit.
    fn transaction(j: &mut Memory, at: usize, sequence: u32, homes: &[u32]) -> usize {
        let mut d = vec![0u8; BS];
        header(&mut d, BLOCKTYPE_DESCRIPTOR, sequence);
        let mut pos = HEADER;
        for (i, &home) in homes.iter().enumerate() {
            put_u32_be(&mut d, pos, home);
            let mut flags = if i == 0 { 0 } else { TAG_SAME_UUID };
            if i + 1 == homes.len() {
                flags |= TAG_LAST;
            }
            put_u32_be(&mut d, pos + 4, flags);
            pos += 8 + if i == 0 { TAG_UUID } else { 0 };
        }
        j.0[at] = d;
        for (i, &home) in homes.iter().enumerate() {
            j.0[at + 1 + i] = vec![home as u8; BS];
        }
        let commit = at + 1 + homes.len();
        header(&mut j.0[commit], BLOCKTYPE_COMMIT, sequence);
        commit + 1
    }

    fn plan_of(j: &mut Memory) -> Result<Replay, ReadError> {
        let sb = j.0[0].clone();
        let len = j.0.len() as u64;
        plan(&sb, BS, 1 << 20, len, j)
    }

    #[test]
    fn a_hand_built_log_replays_in_order() {
        let mut j = journal(64);
        let next = transaction(&mut j, 1, 7, &[500, 501]);
        transaction(&mut j, next, 8, &[501]);
        let replay = plan_of(&mut j).expect("plan");
        assert_eq!(replay.transactions, 2);
        assert_eq!(
            replay.copies[&500].at, 1002,
            "the first transaction's first data block"
        );
        assert_eq!(
            replay.copies[&501].at, 1006,
            "the second transaction's copy is the last"
        );
    }

    #[test]
    fn an_empty_log_replays_nothing() {
        let mut j = journal(64);
        put_u32_be(&mut j.0[0], offset::START, 0);
        transaction(&mut j, 1, 7, &[500]);
        assert!(plan_of(&mut j).expect("plan").copies.is_empty());
    }

    #[test]
    fn what_no_tool_writes_is_refused_by_name() {
        // Each is a log no pinned tool produces, so nothing could check a replay of it.
        let cases: [(&str, Edit); 7] = [
            ("the version 1 commit checksum", |sb| {
                put_u32_be(sb, offset::FEATURE_COMPAT, COMPAT_CHECKSUM)
            }),
            ("asynchronous commits", |sb| {
                put_u32_be(sb, offset::FEATURE_INCOMPAT, INCOMPAT_ASYNC_COMMIT)
            }),
            ("fast commits", |sb| {
                put_u32_be(sb, offset::FEATURE_INCOMPAT, INCOMPAT_FAST_COMMIT)
            }),
            ("an incompatible journal feature it does not know", |sb| {
                put_u32_be(sb, offset::FEATURE_INCOMPAT, 0x8000_0000)
            }),
            (
                "a read-only-compatible journal feature it does not know",
                |sb| put_u32_be(sb, offset::FEATURE_RO_COMPAT, 1),
            ),
            ("both journal checksum versions at once", |sb| {
                put_u32_be(
                    sb,
                    offset::FEATURE_INCOMPAT,
                    INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3,
                )
            }),
            ("a version 1 journal superblock", |sb| {
                put_u32_be(sb, 4, JBD2_SUPERBLOCK_V1)
            }),
        ];
        for (expected, set) in cases {
            let mut j = journal(64);
            transaction(&mut j, 1, 7, &[500]);
            set(&mut j.0[0]);
            match plan_of(&mut j) {
                Err(ReadError::JournalUnsupported { feature }) => assert_eq!(feature, expected),
                other => panic!("{expected}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_deleted_block_tag_is_refused() {
        let mut j = journal(64);
        transaction(&mut j, 1, 7, &[500]);
        put_u32_be(&mut j.0[1], HEADER + 4, TAG_LAST | TAG_DELETED);
        assert!(matches!(
            plan_of(&mut j),
            Err(ReadError::JournalUnsupported {
                feature: "a tag marking a deleted block"
            })
        ));
    }

    #[test]
    fn geometry_outside_the_journal_is_malformed() {
        let cases: [(&str, Edit); 5] = [
            ("a journal block size other than the filesystem's", |sb| {
                put_u32_be(sb, offset::BLOCK_SIZE, 4096)
            }),
            ("a journal longer than the file holding it", |sb| {
                put_u32_be(sb, offset::MAX_LEN, 65)
            }),
            ("a first log block outside the journal", |sb| {
                put_u32_be(sb, offset::FIRST, 0)
            }),
            ("a log start outside the journal", |sb| {
                put_u32_be(sb, offset::START, 64)
            }),
            ("a journal superblock without the jbd2 magic", |sb| {
                put_u32_be(sb, 0, 0)
            }),
        ];
        for (expected, set) in cases {
            let mut j = journal(64);
            transaction(&mut j, 1, 7, &[500]);
            set(&mut j.0[0]);
            match plan_of(&mut j) {
                Err(ReadError::JournalMalformed { detail, .. }) => assert_eq!(detail, expected),
                other => panic!("{expected}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_log_that_never_ends_is_refused_rather_than_followed() {
        // Every block of the log is a revoke block of the expected sequence, so the walk meets
        // no end of its own, and the journal's span is what stops it.
        let mut j = journal(16);
        for at in 1..16 {
            let mut b = vec![0u8; BS];
            header(&mut b, BLOCKTYPE_REVOKE, 7);
            put_u32_be(&mut b, REVOKE_COUNT, REVOKE_RECORDS as u32);
            j.0[at] = b;
        }
        assert!(matches!(
            plan_of(&mut j),
            Err(ReadError::JournalMalformed {
                detail: "a log longer than its journal",
                ..
            })
        ));
    }

    #[test]
    fn a_copy_of_a_block_past_the_filesystem_is_malformed() {
        let mut j = journal(64);
        transaction(&mut j, 1, 7, &[500]);
        let sb = j.0[0].clone();
        assert!(matches!(
            plan(&sb, BS, 400, 64, &mut j),
            Err(ReadError::JournalMalformed {
                detail: "a copy of a block past the filesystem",
                ..
            })
        ));
    }

    #[test]
    fn a_revoke_count_past_its_block_is_malformed() {
        for count in [0u32, 15, BS as u32 + 4, 18] {
            let mut j = journal(64);
            let mut b = vec![0u8; BS];
            header(&mut b, BLOCKTYPE_REVOKE, 7);
            put_u32_be(&mut b, REVOKE_COUNT, count);
            j.0[1] = b;
            assert!(
                matches!(
                    plan_of(&mut j),
                    Err(ReadError::JournalMalformed {
                        detail: "a revoke block whose count runs past its records",
                        ..
                    })
                ),
                "r_count {count}"
            );
        }
    }
}
