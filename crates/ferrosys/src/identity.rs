//! Re-identifying an image in place: the UUID it is known by, the label it presents, and
//! the seed its metadata checksums derive from.
//!
//! An image is written once and identified many times. A build produces one filesystem and
//! stamps a UUID into each copy it ships; a rescue image is cloned and the copy must not
//! answer to the original's `UUID=` mount entry. Both want the identity fields rewritten
//! and nothing else touched, which is what [`rewrite_identity`] does.
//!
//! # The bytes are patched, never rebuilt
//!
//! Each superblock copy is read, the identity fields are overwritten in the bytes that came
//! off the image, and the result is written back. A superblock holds fields this crate does
//! not model — multi-mount protection, snapshots, encryption, the error-log records, the
//! reserved tail — and a rewrite that serialized a parsed superblock would write zeroes over
//! every one of them. What a copy held is what it keeps, save the fields named here.
//!
//! # Checksums and the UUID
//!
//! Under `metadata_csum` every metadata object in the filesystem — each group descriptor,
//! inode, bitmap, directory block, and extent node — carries a crc32c seeded from the
//! filesystem's seed. Where `metadata_csum_seed` is set, that seed is a superblock field
//! and the UUID is free to change. Where it is not, the seed *is* the UUID, so changing the
//! UUID invalidates every checksum in the image at once.
//!
//! That case is refused rather than half-performed. The way through it is
//! [`IdentityChange::set_checksum_seed`], which records the seed the current UUID implies
//! into `s_checksum_seed` and turns `metadata_csum_seed` on, after which the UUID changes
//! and every existing checksum stays valid. It is opt-in because it sets an incompatible
//! feature: a kernel that does not know `metadata_csum_seed` will not mount the result.
//!
//! # The journal keeps its own record
//!
//! The log records the filesystem's UUID as its own, so a new UUID goes there too. A log
//! that declares `csum_v2` or `csum_v3` carries a crc32c over its whole superblock, and
//! that word covers the UUID — so it is recomputed with it. Linux sets `csum_v3` on the
//! journal of any filesystem carrying `metadata_csum` the first time it mounts one, which
//! makes a checksummed log the ordinary case for any image that has ever been used rather
//! than a corner of the format.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::bytes::{get_u16, get_u32, get_u32_be, put_arr, put_u32, put_u32_be};
use crate::crc32c::crc32c;
use crate::feature::Incompat;
use crate::geometry::sparse_super_has_copy;
use crate::io::{offset_of, read_exact_at};
use crate::journal;
use crate::ondisk::{SuperBlock, superblock_checksum};
use crate::read::{OpenOptions, ReadError, Reader};

/// What to change about an image's identity. Every field left unset is left alone.
///
/// See [`rewrite_identity`].
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct IdentityChange {
    /// The new filesystem UUID (`s_uuid`).
    pub uuid: Option<[u8; 16]>,
    /// The new volume label (`s_volume_name`), NUL-padded to sixteen bytes; all zero
    /// leaves the filesystem unlabelled.
    pub volume_name: Option<[u8; 16]>,
    /// Record the seed the current UUID implies into `s_checksum_seed` and turn
    /// `metadata_csum_seed` on, so that a UUID change leaves every existing metadata
    /// checksum valid.
    ///
    /// Only meaningful on a filesystem carrying `metadata_csum` without
    /// `metadata_csum_seed`, which is the one combination where a UUID change would
    /// otherwise invalidate the image. Requesting it anywhere else is an error rather than
    /// a no-op, because the feature it sets is one an older kernel refuses to mount and
    /// setting it for no benefit is not a thing to do quietly.
    pub set_checksum_seed: bool,
}

impl IdentityChange {
    /// A change that changes nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this change would write anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.uuid.is_none() && self.volume_name.is_none() && !self.set_checksum_seed
    }
}

/// What a rewrite wrote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct IdentityReport {
    /// Superblock copies written: the primary, and one per group carrying a backup.
    pub superblocks: u32,
    /// Whether the journal's own record of the filesystem UUID was written.
    pub journal_superblock: bool,
    /// Whether `metadata_csum_seed` was turned on and the seed recorded.
    pub checksum_seed_set: bool,
}

/// A failure re-identifying an image.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Reading or writing the image failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The image could not be read as an ext filesystem.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The UUID would change on a filesystem whose metadata checksums derive from it, so
    /// every checksum in the image would become wrong at once.
    #[error(
        "changing the UUID would invalidate every metadata checksum: this filesystem has \
         metadata_csum without metadata_csum_seed, so its checksums are seeded from the \
         UUID itself — set the checksum seed to keep them valid"
    )]
    UuidWouldInvalidateChecksums,
    /// The checksum seed was asked for where it changes nothing.
    #[error(
        "setting the checksum seed needs a filesystem with metadata_csum and without \
         metadata_csum_seed; this one is {found}"
    )]
    #[non_exhaustive]
    ChecksumSeedPointless {
        /// What the filesystem's checksum features actually are.
        found: &'static str,
    },
    /// The image ends before a group the superblock's geometry claims exists, so a backup
    /// this rewrite must patch is not in the file at all.
    ///
    /// The group count follows from `s_blocks_count` and `s_blocks_per_group`, neither of
    /// which opening the filesystem validates against the image it came from. A superblock
    /// claiming far more groups than the file holds — from a bit-flip, or written that way
    /// on purpose — is refused here rather than driving the rewrite through offsets that are
    /// not there.
    #[error(
        "group {group}'s backup superblock lies past the end of a {blocks}-block image: \
         the superblock describes a larger filesystem than this file holds"
    )]
    #[non_exhaustive]
    BackupPastEnd {
        /// The group whose backup is out of reach.
        group: u32,
        /// Blocks the image itself holds.
        blocks: u64,
    },
    /// A group that should carry a backup superblock does not hold one, so the copies
    /// cannot be brought into agreement.
    #[error(
        "group {group} should hold a backup superblock at block {block} and does not: \
         re-identifying would leave the copies disagreeing about the filesystem"
    )]
    #[non_exhaustive]
    BackupNotASuperblock {
        /// The group whose backup is missing.
        group: u32,
        /// The block the backup should begin at.
        block: u64,
    },
    /// A superblock copy's own checksum does not match its contents, so the image is
    /// damaged or is not what it claims and must not be rewritten.
    ///
    /// Every copy is held to this, not only the primary. A copy's checksum covers its own
    /// bytes, so a backup left *stale* by a later change to the filesystem still checks out
    /// against itself; only a damaged one fails. Patching a damaged copy would write a
    /// freshly correct checksum over wrong bytes, which turns bit rot inside one copy into
    /// self-consistency and takes it out of `e2fsck`'s reach.
    #[error(
        "the superblock in group {group} has checksum {found:#010x} but its contents \
         compute to {computed:#010x}: the image is damaged, and re-identifying it would \
         write a correct checksum over a wrong superblock"
    )]
    #[non_exhaustive]
    SuperblockChecksumMismatch {
        /// The group whose copy does not check out; zero is the primary.
        group: u32,
        /// The checksum the superblock stores.
        found: u32,
        /// The checksum its bytes compute to.
        computed: u32,
    },
    /// The journal superblock's own checksum does not match its contents, so the log is
    /// damaged and writing a new UUID into it would leave a correct checksum over wrong
    /// bytes.
    #[error(
        "the journal superblock's checksum is {found:#010x} but its contents compute to \
         {computed:#010x}: the log is damaged, and re-identifying it would write a correct \
         checksum over a wrong journal superblock"
    )]
    #[non_exhaustive]
    JournalChecksumMismatch {
        /// The checksum the journal superblock stores.
        found: u32,
        /// The checksum its bytes compute to.
        computed: u32,
    },
    /// The journal declares a checksummed log whose checksum is not the crc32c jbd2
    /// defines, so the word covering its UUID cannot be recomputed.
    #[error(
        "the journal declares checksums of type {checksum_type} rather than crc32c, so its \
         superblock checksum cannot be brought back into agreement with a new UUID"
    )]
    #[non_exhaustive]
    JournalChecksumUnsupported {
        /// The checksum type the journal superblock names (`s_checksum_type`).
        checksum_type: u8,
    },
}

/// Rewrite an image's identity in place, leaving everything else exactly as it was.
///
/// Every superblock copy is written — the primary and each group's backup — so no copy is
/// left claiming the old identity, and the journal's own record of the UUID is written with
/// them. Nothing is written until every copy has been read and every check has passed, so a
/// refusal leaves the image untouched rather than half re-identified.
///
/// A failure of the writing itself is the one case that leaves copies disagreeing, and the
/// answer to it is to run this again: the change is stated as what each copy becomes rather
/// than as an edit to what it holds, so a second run over a half-written image reaches the
/// same result as a first run over an untouched one. The primary is written before any backup,
/// so a run cut short still leaves the copy every reader consults holding the new identity.
///
/// The image is rewritten where it lies. There is no write-elsewhere-and-rename form of this,
/// because the image already exists and copying it to gain one would duplicate every byte of a
/// filesystem to change a few hundred, and would leave behind a file that is no longer sparse
/// and no longer the one any other name refers to.
///
/// # Memory
///
/// Reading every copy before writing any is what makes a refusal leave the image untouched,
/// and it is also what this holds: one superblock-sized buffer per copy, and one for the
/// journal superblock. With `sparse_super` — which every filesystem this crate writes and
/// nearly every one it reads carries — copies are placed at the powers of 3, 5, and 7, so
/// that is a few dozen kilobytes for a filesystem of any size. Without it every group holds
/// a copy, and the cost grows with the filesystem instead: a kilobyte per group.
///
/// # Errors
///
/// [`IdentityError::Read`] if the image is not a readable ext filesystem;
/// [`IdentityError::SuperblockChecksumMismatch`] if its primary superblock is damaged;
/// [`IdentityError::UuidWouldInvalidateChecksums`] if the UUID seeds the filesystem's
/// checksums and [`set_checksum_seed`](IdentityChange::set_checksum_seed) was not asked
/// for; [`IdentityError::ChecksumSeedPointless`] if it was asked for where it does nothing;
/// [`IdentityError::BackupNotASuperblock`] if a backup copy is missing;
/// [`IdentityError::JournalChecksumMismatch`] if the journal superblock is damaged;
/// [`IdentityError::JournalChecksumUnsupported`] if the log declares a checksum that is not
/// crc32c; and [`IdentityError::Io`] if the image cannot be read or written.
///
/// # Example
///
/// ```no_run
/// use ferrosys::ext::{IdentityChange, rewrite_identity};
///
/// let mut image = std::fs::OpenOptions::new().read(true).write(true).open("rootfs.img")?;
/// let mut change = IdentityChange::new();
/// change.uuid = Some([0x5a; 16]);
/// change.volume_name = Some(*b"rootfs\0\0\0\0\0\0\0\0\0\0");
/// let report = rewrite_identity(&mut image, &change)?;
/// assert!(report.superblocks >= 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn rewrite_identity<F: Read + Write + Seek>(
    image: &mut F,
    change: &IdentityChange,
) -> Result<IdentityReport, IdentityError> {
    rewrite_identity_at(image, change, 0)
}

/// [`rewrite_identity`], for a filesystem `base` bytes into `image` — a partition inside a
/// whole-disk image, or a region a carver located. The same offset every reader takes
/// through [`OpenOptions::base`](crate::OpenOptions::base), reaching the one verb that
/// writes.
///
/// # Errors
///
/// As [`rewrite_identity`].
pub fn rewrite_identity_at<F: Read + Write + Seek>(
    image: &mut F,
    change: &IdentityChange,
    base: u64,
) -> Result<IdentityReport, IdentityError> {
    // Everything that can refuse happens here, over a reader borrowing the handle. Only
    // once the whole set of copies is read and patched does a byte go back. The plan's
    // offsets are the filesystem's own, so the base is applied at each I/O and nowhere
    // else.
    let plan = plan_rewrite(image, change, base)?;
    for (offset, bytes) in &plan.writes {
        image.seek(SeekFrom::Start(base + *offset))?;
        image.write_all(bytes)?;
    }
    image.flush()?;
    Ok(plan.report)
}

/// The patched copies and where each goes, with nothing yet written.
struct Rewrite {
    writes: Vec<(u64, Vec<u8>)>,
    report: IdentityReport,
}

/// Read every copy, decide what each becomes, and refuse anything that cannot be done
/// wholly.
fn plan_rewrite<F: Read + Write + Seek>(
    image: &mut F,
    change: &IdentityChange,
    base: u64,
) -> Result<Rewrite, IdentityError> {
    // The reader borrows the handle rather than taking it, so the same descriptor writes
    // the copies afterwards.
    let mut reader = Reader::open_with(&mut *image, &OpenOptions::new().base(base))?;
    let feature = reader.feature();
    let sb = reader.superblock().clone();
    let group_count = reader.group_count();
    let block_size = u64::from(feature.block_size);
    let journal_block = if change.uuid.is_some() {
        reader.journal_superblock_block()?
    } else {
        None
    };
    drop(reader);

    let checksummed = feature.has_metadata_csum();
    let seeded = feature.has_csum_seed();
    let seed_to_set = decide_checksum_seed(change, &sb, checksummed, seeded)?;

    // The image's own length in blocks, which is what bounds the loop below. The group
    // count is derived from `s_blocks_count` and `s_blocks_per_group` and reaches `u32::MAX`,
    // and neither field is validated against the file when the filesystem is opened — so
    // without this the loop would build an entry per *claimed* group, and compute every
    // offset, before the first read could refuse one.
    let source_blocks = image.seek(SeekFrom::End(0))?.saturating_sub(base) / block_size;

    // The primary is 1024 bytes into the image whatever the block size; a backup begins at
    // its group's first block.
    let mut copies = vec![(0u32, 1024u64)];
    for group in 1..group_count {
        // Checked, and checked before the sparse-super test rather than after it: a block
        // number that leaves the range or leaves the image ends the loop whether or not that
        // particular group carries a copy, so nothing is computed past the first group the
        // image cannot hold.
        let block = match offset_of(
            u64::from(sb.first_data_block),
            u64::from(group),
            u64::from(sb.blocks_per_group),
        ) {
            Some(block) if block < source_blocks => block,
            _ => {
                return Err(IdentityError::BackupPastEnd {
                    group,
                    blocks: source_blocks,
                });
            }
        };
        if feature.is_sparse_super() && !sparse_super_has_copy(group) {
            continue;
        }
        // The block is under `source_blocks`, which is the image's own length divided by
        // this same block size, so the byte offset is inside the image and the checked form
        // cannot answer `None` here. It is the checked form all the same: nothing in this
        // function should depend on a bound another line applies.
        let offset = offset_of(0, block, block_size).ok_or(IdentityError::BackupPastEnd {
            group,
            blocks: source_blocks,
        })?;
        copies.push((group, offset));
    }

    let superblocks = u32::try_from(copies.len()).unwrap_or(u32::MAX);
    let mut writes = Vec::with_capacity(copies.len() + 1);
    for (group, offset) in copies {
        let mut bytes = read_exact_at(image, base + offset, SuperBlock::SIZE)?;
        // Every copy must be a superblock before any is written, so a damaged backup is a
        // refusal rather than an image whose copies disagree about their filesystem.
        if get_u16(&bytes, SuperBlock::MAGIC_OFFSET) != crate::ondisk::SUPERBLOCK_MAGIC {
            return Err(IdentityError::BackupNotASuperblock {
                group,
                block: offset / block_size,
            });
        }
        // Every copy is checked, not only the primary. A copy is self-describing: its
        // checksum covers its own bytes, so a *stale* backup — one written before some later
        // change to the filesystem — still checks out against itself, and only a damaged one
        // fails. Patching a damaged copy would write a freshly correct checksum over wrong
        // bytes, which launders bit rot inside one copy into self-consistency and takes it
        // out of `e2fsck`'s reach. That is the same reason the primary is checked, and the
        // reason applies to each of them.
        if checksummed {
            verify_checksum(&bytes, group)?;
        }
        patch(&mut bytes, change, seed_to_set, checksummed);
        writes.push((offset, bytes));
    }

    // The log records the filesystem's UUID as its own, so a UUID that changed everywhere
    // else and not here would leave the journal describing a different filesystem.
    let journal_written = match (journal_block, change.uuid) {
        (Some(block), Some(uuid)) => {
            // The block came from the log's own extent tree, which the reader bounded
            // against the filesystem; the checked form states that here rather than
            // trusting it, since a byte offset that wrapped would patch the wrong bytes
            // and write a correct checksum over them.
            let offset = offset_of(0, block, block_size).ok_or(IdentityError::BackupPastEnd {
                group: 0,
                blocks: source_blocks,
            })?;
            let mut bytes = read_exact_at(image, base + offset, journal::SUPERBLOCK_SIZE)?;
            patch_journal(&mut bytes, uuid)?;
            writes.push((offset, bytes));
            true
        }
        _ => false,
    };

    Ok(Rewrite {
        writes,
        report: IdentityReport {
            superblocks,
            journal_superblock: journal_written,
            checksum_seed_set: seed_to_set.is_some(),
        },
    })
}

/// The seed to record and the feature to set, or `None` when neither is wanted.
///
/// This is where the one combination that cannot be re-identified is refused: `metadata_csum`
/// without `metadata_csum_seed` seeds every checksum in the filesystem from the UUID.
fn decide_checksum_seed(
    change: &IdentityChange,
    sb: &SuperBlock,
    checksummed: bool,
    seeded: bool,
) -> Result<Option<u32>, IdentityError> {
    let seedable = checksummed && !seeded;
    if change.set_checksum_seed {
        if !seedable {
            return Err(IdentityError::ChecksumSeedPointless {
                found: match (checksummed, seeded) {
                    (false, _) => "without metadata_csum, so nothing is seeded",
                    (true, true) => "already carrying metadata_csum_seed",
                    (true, false) => unreachable!("seedable is checked above"),
                },
            });
        }
        // The seed every existing checksum was computed from: the crc32c of the UUID the
        // image carries now. Recording it is what lets the UUID move without them.
        return Ok(Some(crc32c(!0, &sb.uuid)));
    }
    if change.uuid.is_some() && seedable {
        return Err(IdentityError::UuidWouldInvalidateChecksums);
    }
    Ok(None)
}

/// Overwrite the identity fields in one superblock copy's own bytes, then its checksum.
fn patch(bytes: &mut [u8], change: &IdentityChange, seed: Option<u32>, checksummed: bool) {
    if let Some(uuid) = change.uuid {
        put_arr(bytes, SuperBlock::UUID_OFFSET, &uuid);
    }
    if let Some(label) = change.volume_name {
        put_arr(bytes, SuperBlock::VOLUME_NAME_OFFSET, &label);
    }
    if let Some(seed) = seed {
        put_u32(bytes, SuperBlock::CHECKSUM_SEED_OFFSET, seed);
        let incompat =
            get_u32(bytes, SuperBlock::FEATURE_INCOMPAT_OFFSET) | Incompat::CSUM_SEED.bits();
        put_u32(bytes, SuperBlock::FEATURE_INCOMPAT_OFFSET, incompat);
    }
    if checksummed {
        // The record's checksum covers the identity fields written above, so it is
        // recomputed here whatever the UUID did. The recipe is the writer's and the
        // reader's, called rather than restated.
        put_u32(
            bytes,
            SuperBlock::CHECKSUM_OFFSET,
            superblock_checksum(bytes),
        );
    }
}

/// Overwrite the UUID the log records as its own, and the checksum covering it.
///
/// A log declaring `csum_v2` or `csum_v3` carries a crc32c over its whole superblock, and
/// `s_uuid` is inside what that word covers — so a UUID written without it would leave a
/// journal jbd2 refuses to load. The stored checksum is verified before the UUID moves, for
/// the reason [`verify_checksum`] verifies each superblock copy's: a damaged log must be a
/// refusal rather than a freshly correct checksum over wrong bytes.
///
/// A log declaring neither carries no checksum here and takes the UUID alone. That is every
/// log `mke2fs` creates and none that Linux has mounted on a `metadata_csum` filesystem.
fn patch_journal(bytes: &mut [u8], uuid: [u8; 16]) -> Result<(), IdentityError> {
    let checksummed = journal::superblock_is_checksummed(bytes);
    if checksummed {
        let kind = bytes[journal::offset::CHECKSUM_TYPE];
        if kind != journal::CRC32C_CHKSUM {
            return Err(IdentityError::JournalChecksumUnsupported {
                checksum_type: kind,
            });
        }
        let found = get_u32_be(bytes, journal::offset::CHECKSUM);
        let computed = journal::superblock_checksum(bytes);
        if found != computed {
            return Err(IdentityError::JournalChecksumMismatch { found, computed });
        }
    }
    put_arr(bytes, journal::offset::UUID, &uuid);
    if checksummed {
        // Big-endian, as every other word of this record is: the jbd2 superblock is the one
        // structure in the format whose byte order is not ext's.
        put_u32_be(
            bytes,
            journal::offset::CHECKSUM,
            journal::superblock_checksum(bytes),
        );
    }
    Ok(())
}

/// Refuse a superblock copy whose stored checksum does not match its contents.
fn verify_checksum(bytes: &[u8], group: u32) -> Result<(), IdentityError> {
    let found = get_u32(bytes, SuperBlock::CHECKSUM_OFFSET);
    let computed = superblock_checksum(bytes);
    if found != computed {
        return Err(IdentityError::SuperblockChecksumMismatch {
            group,
            found,
            computed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::Profile;
    use crate::materialize::{FormatOptions, format};
    use crate::source::{Metadata, TreeBuilder};
    use crate::time::Timestamp;
    use std::io::Cursor;

    const MIB: u64 = 1024 * 1024;

    fn options(profile: Profile) -> FormatOptions {
        FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(profile)
    }

    /// A small formatted image, at whichever profile the caller wants its checksum policy
    /// from.
    fn image(profile: Profile) -> Vec<u8> {
        let time = Timestamp::from_secs(1_700_000_000);
        let source = TreeBuilder::new().file(
            b"/a".to_vec(),
            b"contents\n".to_vec(),
            Metadata::new(0o644, time),
        );
        format(source, 8 * MIB, options(profile))
            .expect("format")
            .into_bytes()
    }

    /// Overwrite a little-endian `u32` in the primary superblock, which begins 1024 bytes in.
    fn put_u32(bytes: &mut [u8], field: usize, value: u32) {
        bytes[1024 + field..1024 + field + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn a_superblock_claiming_more_groups_than_the_image_holds_is_refused() {
        // The group count is `s_blocks_count / s_blocks_per_group`, and opening a filesystem
        // validates neither field against the file it came from. Both reach their whole
        // range, so a superblock a bit-flip or a hostile writer left claiming hundreds of
        // millions of groups drove one entry per *claimed* group to be built, and every
        // offset computed, before the first read could refuse one — hundreds of megabytes of
        // allocation, or seconds of spinning, from an image of a few kilobytes.
        //
        // The image's own length is what bounds it: a backup past the end of the file is a
        // backup no read could reach, and the rewrite says so rather than working toward it.
        let mut bytes = image(Profile::Ext2);
        // 4 GiB of 1 KiB blocks in eight-block groups: 536,870,912 groups claimed by an
        // 8 MiB file.
        put_u32(&mut bytes, 0x04, u32::MAX);
        put_u32(&mut bytes, 0x20, 8);

        let mut change = IdentityChange::new();
        change.uuid = Some([0x5a; 16]);
        let err = rewrite_identity(&mut Cursor::new(&mut bytes), &change)
            .expect_err("a geometry the file cannot hold is refused");
        assert!(
            matches!(err, IdentityError::BackupPastEnd { .. }),
            "expected BackupPastEnd, got {err:?}"
        );
    }

    #[test]
    fn a_group_size_that_puts_the_first_backup_past_the_image_is_refused_at_that_group() {
        // The other end of the same field. A group of the largest size the format allows —
        // what a one-block block bitmap indexes — puts the first backup's block far past
        // anything an 8 MiB image holds, and the loop stops at the first group rather than
        // computing offsets for the hundred thousand behind it.
        //
        // A group size past *that* is refused when the filesystem is opened, so the offset
        // arithmetic can no longer be driven to overflow at all; the checked multiply
        // remains because nothing in this function should depend on a bound another one
        // applies.
        let mut bytes = image(Profile::Ext2);
        put_u32(&mut bytes, 0x04, u32::MAX);
        put_u32(&mut bytes, 0x20, 8 * 4096);

        let mut change = IdentityChange::new();
        change.uuid = Some([0x5a; 16]);
        let err = rewrite_identity(&mut Cursor::new(&mut bytes), &change)
            .expect_err("an unreachable backup is refused");
        assert!(
            matches!(err, IdentityError::BackupPastEnd { group: 1, .. }),
            "expected BackupPastEnd at group 1, got {err:?}"
        );
    }

    #[test]
    fn an_untouched_image_still_rewrites_every_copy() {
        // The bound is on the image, not on the work: a filesystem whose geometry the file
        // does hold has every one of its backups patched, which is what the refusals above
        // must not have cost.
        let mut bytes = image(Profile::Ext2);
        let mut change = IdentityChange::new();
        change.uuid = Some([0x5a; 16]);
        let report = rewrite_identity(&mut Cursor::new(&mut bytes), &change).expect("rewrite");
        assert!(report.superblocks >= 1);
        let reader = Reader::open(Cursor::new(bytes.as_slice())).expect("open");
        assert_eq!(reader.superblock().uuid, [0x5a; 16]);
    }
}
