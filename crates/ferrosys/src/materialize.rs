//! The materializer: turn a plan, an allocator, and an inode model into image
//! bytes.
//!
//! This is the layer that does I/O in the sense of producing the final byte image;
//! everything it decides was decided by the pure layers it consumes. It places each
//! inode's data through the allocator, writes the inode table, block and inode
//! bitmaps, group descriptors, and the primary and backup superblocks, and threads
//! the reserved descriptor blocks through the resize inode's double-indirect map so
//! the image can grow safely.
//!
//! Bytes go to any seekable writer. [`format()`] collects them into an in-memory
//! [`Image`]; [`format_to()`] streams them straight out, touching only the blocks it
//! writes, so a filesystem far larger than memory can be created into a file that
//! stays sparse. Nothing is ever read back from the destination.
//!
//! Every checksum field is written through the [`Checksummer`] seam: with
//! `metadata_csum` set the seam is a real crc32c and each metadata object — the
//! superblock and its backups, the group descriptors, inodes, block and inode
//! bitmaps, directory blocks, and attribute blocks — is checksummed as it is laid
//! down; without it the seam zeroes those fields. Which seam is active is the only
//! thing that changes between the two, not this code.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Seek, Write};

use crate::alloc::{AllocError, Allocator};
use crate::crc32c::crc32c;
use crate::csum::{Checksummer, Crc32c, CsumScheme, NullCsum};
use crate::dir::{DirBlock, DirBlockKind, DirError, DirLayout, HtreeDir, LinearDir};
use crate::extent::{
    ExtentError, build_leaves, build_tree, node_capacity, plan_tree, tail_offset, write_node,
};
use crate::feature::{FeatureSet, LARGE_FILE_MIN_SIZE, Profile, resize_inode_size};
use crate::geometry::{
    BlockRange, GeometryError, GroupLayout, GrowReservation, InodeCount, Layout, PlanRequest,
    ReservedRatio, plan_layout,
};
use crate::hash::{HashSignedness, HashVersion};
use crate::journal::{self, JournalSize};
use crate::model::{
    Content, FIRST_USER_INO, FsModel, LOST_FOUND_INO, ModelConfig, ModelError, ModelInode,
    build_model,
};
use crate::ondisk::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, DIR_TAIL_LEN, DX_ENTRY_LEN, DX_TAIL_LEN,
    DirEntry, GroupDescriptor, Inode, InodeFlags, ParseError, SuperBlock, encode_block,
    encode_device, encode_inline, extra_isize_for, get_u16, orphan_entries_len, orphan_tail_bytes,
    put_u16, put_u32, split_for_storage, write_dir_tail, write_dx_tail,
};
use crate::sink::ByteSink;
use crate::sizing::Slack;
use crate::source::Source;
use crate::time::Timestamp;
use crate::xattr::Xattr;

/// The reserved inode mapping the reserved group-descriptor-table blocks.
const RESIZE_INO: u32 = 7;

/// Relabel an out-of-space failure as the journal's own.
///
/// The journal is the largest structure a filesystem places for itself, so on a small
/// filesystem it is the allocation that runs out of room — and a bare "out of space" for it
/// reads as though the caller's contents did not fit, on a filesystem that may hold none.
/// Any other failure passes through unchanged.
fn journal_space(e: impl Into<FormatError>) -> FormatError {
    match e.into() {
        FormatError::Alloc(AllocError::OutOfSpace {
            requested,
            available,
        }) => FormatError::JournalDoesNotFit {
            requested,
            available,
        },
        other => other,
    }
}

/// The reserved inode holding the journal (`s_journal_inum`).
const JOURNAL_INO: u32 = 8;

/// The inode holding the orphan file (`s_orphan_file_inum`). It is not one of the
/// reserved inodes: the orphan file is allocated at format time, so it takes the first
/// inode past `/lost+found` — which is why a source's entries begin one higher when
/// `orphan_file` is on.
const ORPHAN_INO: u32 = FIRST_USER_INO;

/// The inode number a source's entries start at: the first past `/lost+found`, moved up
/// by the inodes the feature set claims for itself at format time.
fn first_user_inode(feature: &FeatureSet) -> u32 {
    if feature.has_orphan_file() {
        ORPHAN_INO + 1
    } else {
        FIRST_USER_INO
    }
}

/// The most 512-byte sectors an inode is charged without `huge_file`.
///
/// `i_blocks_lo` is 32 bits wide, and without the feature the two bytes above it are ext2's
/// `l_i_frag` and `l_i_fsize` rather than a high half — so this is the whole field. Two
/// tebibytes, less one sector.
const MAX_SECTORS_WITHOUT_HUGE_FILE: u64 = u32::MAX as u64;

/// The orphan file's size in blocks: one block per 4096 filesystem blocks, held between
/// 32 and 512 blocks. The floor keeps concurrent deletions on a small filesystem from
/// contending for the few entries a strict ratio would give them, and the ceiling stops
/// a large one from reserving space for far more orphans than can ever exist at once.
///
/// It is a count of blocks, not of bytes, so a filesystem of a given block count is
/// given the same orphan file whatever its block size.
fn orphan_file_blocks(total_blocks: u64) -> u32 {
    const RATIO: u64 = 4096;
    const MIN: u64 = 32;
    const MAX: u64 = 512;
    (total_blocks / RATIO).clamp(MIN, MAX) as u32
}

/// What the kernel does when it detects an error on the mounted filesystem, recorded in
/// the superblock's `s_errors` field (offset `0x3c`) and consulted by the kernel at mount
/// time.
///
/// This is a runtime policy the image carries, not a property of the layout: every value
/// produces a filesystem this crate considers equally correct, differing only in that one
/// superblock field and the checksum computed over it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ErrorBehavior {
    /// Note the error and carry on (`s_errors = 1`) — the kernel's own default, and this
    /// crate's.
    #[default]
    Continue,
    /// Remount the filesystem read-only (`s_errors = 2`), so a detected inconsistency
    /// cannot spread through further writes.
    RemountReadOnly,
    /// Panic the kernel (`s_errors = 3`), halting the machine on any filesystem error.
    Panic,
}

impl ErrorBehavior {
    /// The on-disk `s_errors` value this policy is stored as.
    const fn to_s_errors(self) -> u16 {
        match self {
            Self::Continue => 1,
            Self::RemountReadOnly => 2,
            Self::Panic => 3,
        }
    }
}

/// Options controlling a format that do not come from the source or the size.
///
/// Build one with [`new`](Self::new), which takes the three identity inputs every image
/// needs and defaults the rest, then set the fields a format departs from the default on.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The 16-byte filesystem UUID (`s_uuid`), supplied by the caller.
    pub uuid: [u8; 16],
    /// The filesystem creation and write time.
    pub time: Timestamp,
    /// The 16-byte directory-hash seed (`s_hash_seed`).
    pub hash_seed: [u8; 16],
    /// The algorithm a hash-indexed directory orders its names by
    /// (`s_def_hash_version`). Defaults to [`HashVersion::HalfMd4`].
    pub hash_version: HashVersion,
    /// Whether a name's bytes are read as signed or unsigned when hashed
    /// (`s_flags`). Defaults to [`HashSignedness::Unsigned`], which makes a name's
    /// hash — and so the image's bytes — independent of the machine that wrote it.
    ///
    /// Set it to [`HashSignedness::Signed`] to match an image built by a tool that
    /// takes its signedness from the host's `char`, which is signed on x86 and
    /// unsigned on arm64. An image records the choice, so either is read correctly.
    pub hash_signedness: HashSignedness,
    /// How much reserved descriptor headroom to build in, sizing the reserved GDT
    /// blocks that make the image resize-safe. Defaults to [`GrowReservation::Max`].
    pub grow: GrowReservation,
    /// How many inodes to provide. Defaults to [`InodeCount::Auto`], the size-driven
    /// count; an override sets the density or the count directly.
    pub inodes: InodeCount,
    /// The share of blocks held back for the super-user (`s_r_blocks_count`). Defaults to
    /// [`ReservedRatio::DEFAULT`], 5%.
    pub reserved: ReservedRatio,
    /// The volume label (`s_volume_name`), NUL-padded to sixteen bytes; all zero for an
    /// unlabelled filesystem, which is the default.
    pub volume_name: [u8; 16],
    /// The feature profile to emit.
    pub feature: FeatureSet,
    /// What the kernel does on a detected filesystem error (`s_errors`). Defaults to
    /// [`ErrorBehavior::Continue`], the kernel's own default.
    pub errors: ErrorBehavior,
    /// How large the journal is, when the feature set carries a journal. Ignored when
    /// `has_journal` is off. Defaults to [`JournalSize::Auto`].
    pub journal: JournalSize,
    /// When set, every inode's access, change, modification, and creation time is
    /// forced to this value — the source-derived inodes and the reserved structural
    /// ones (resize, journal, orphan) alike — overriding the per-entry times a source
    /// supplies. This makes output byte-reproducible regardless of the source's
    /// timestamps: the clamp a build takes when reproducibility outranks timestamp
    /// fidelity. Unset, each source-derived inode keeps its own times and the
    /// structural inodes take the format [`time`](Self::time).
    pub fixed_time: Option<Timestamp>,
}

impl FormatOptions {
    /// Reject a format-time clock the superblock's 32-bit time fields cannot hold, so a
    /// far-future creation time is refused rather than silently truncated to 1970-plus.
    fn validate_format_time(&self) -> Result<(), FormatError> {
        let secs = self.time.secs;
        if secs < 0 || secs > u64::from(u32::MAX) as i64 {
            return Err(FormatError::FormatTimeOutOfRange { secs });
        }
        Ok(())
    }

    /// Options for the default feature profile ([`FeatureSet::DEFAULT`]) with the
    /// given identity inputs. The grow reservation defaults to [`GrowReservation::Max`]
    /// — the fail-safe choice that reserves the most online-grow headroom the format
    /// allows; set [`grow`](Self::grow) to [`GrowReservation::UpTo`] for a known
    /// deployment target or [`GrowReservation::None`] to reserve nothing.
    #[must_use]
    pub fn new(uuid: [u8; 16], time: Timestamp, hash_seed: [u8; 16]) -> Self {
        Self {
            uuid,
            time,
            hash_seed,
            hash_version: HashVersion::default(),
            hash_signedness: HashSignedness::default(),
            grow: GrowReservation::default(),
            inodes: InodeCount::default(),
            reserved: ReservedRatio::default(),
            volume_name: [0; 16],
            feature: FeatureSet::default(),
            errors: ErrorBehavior::default(),
            journal: JournalSize::Auto,
            fixed_time: None,
        }
    }

    /// The geometry planner's inputs for a filesystem of `size_bytes` under these
    /// options: the feature set and the three sizing knobs, gathered into the request
    /// [`plan_layout`] takes.
    ///
    /// This is the one place the format options become a plan, so a geometry knob added
    /// here reaches the planner once rather than at every entry point that formats.
    #[must_use]
    pub const fn plan_request(&self, size_bytes: u64) -> PlanRequest {
        PlanRequest::new(size_bytes, self.feature)
            .grow(self.grow)
            .inodes(self.inodes)
            .reserved(self.reserved)
    }

    /// Seed the feature set from an ext filesystem profile, replacing
    /// [`feature`](Self::feature) with the baseline words `mke2fs -t` writes for that
    /// family. Sugar for `options.feature = profile.feature_set()`, chainable from
    /// [`new`](Self::new); set individual features on [`feature`](Self::feature) afterward
    /// to depart from the baseline.
    #[must_use]
    pub fn profile(mut self, profile: Profile) -> Self {
        self.feature = profile.feature_set();
        self
    }
}

/// A failure formatting an image.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// Writing to the destination failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Planning the geometry failed.
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    /// Building the inode model failed.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// Packing a directory failed.
    #[error(transparent)]
    Dir(#[from] DirError),
    /// Building an extent tree failed.
    #[error(transparent)]
    Extent(#[from] ExtentError),
    /// Allocating blocks failed.
    #[error(transparent)]
    Alloc(#[from] AllocError),
    /// Serializing an on-disk structure failed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The source needs more inodes than the geometry provides.
    #[error("source needs {needed} inodes but the filesystem has {available}")]
    #[non_exhaustive]
    TooManyInodes {
        /// Inodes the source needs.
        needed: u32,
        /// Inodes the geometry provides.
        available: u32,
    },
    /// An explicit [`JournalSize::Blocks`] is below the minimum jbd2 accepts.
    #[error("journal of {requested} blocks is below the minimum of {minimum}")]
    #[non_exhaustive]
    JournalTooSmall {
        /// Journal blocks requested.
        requested: u32,
        /// The minimum journal size in blocks.
        minimum: u32,
    },
    /// The journal does not fit in the blocks left free after the filesystem's fixed
    /// metadata.
    ///
    /// The bare allocator failure ([`Alloc`](Self::Alloc)) is what a *source's* files
    /// running out of room looks like; the journal earns its own variant because it is the
    /// filesystem's own structure and the largest one a small filesystem places, so "out of
    /// space" for it would otherwise read as though the caller's contents did not fit.
    #[error(
        "the journal needs {requested} blocks but only {available} are free: build a \
         smaller journal, none at all, or a larger filesystem"
    )]
    #[non_exhaustive]
    JournalDoesNotFit {
        /// Blocks the journal needs.
        requested: u64,
        /// Blocks left free for it.
        available: u64,
    },
    /// The feature set carries a journal, but the filesystem is too small to hold the
    /// smallest one jbd2 accepts.
    ///
    /// This is a different fault from [`JournalTooSmall`](Self::JournalTooSmall), which is
    /// a size the caller named: here no size would do, so the ways out are a filesystem
    /// large enough for a journal or a feature set without one. A journal is not silently
    /// dropped to make the format succeed — a feature word is a promise about what the
    /// filesystem carries, and clearing one the caller asked for would break it quietly.
    #[error(
        "a filesystem of {blocks} blocks has no room for a journal, which needs at least \
         {minimum} blocks: build it without the has_journal feature, or make it larger"
    )]
    #[non_exhaustive]
    FilesystemTooSmallForJournal {
        /// Blocks the filesystem has.
        blocks: u64,
        /// The smallest journal jbd2 accepts, in blocks.
        minimum: u32,
    },
    /// A regular file the filesystem provides for itself reaches
    /// [`LARGE_FILE_MIN_SIZE`] on a feature set without `large_file`, which is the
    /// feature that describes such a file. Only a journal sized past the bound by an
    /// explicit [`JournalSize::Blocks`] reaches this: the resize inode's pairing is
    /// settled at plan time by [`FeatureSet::validate`], the orphan file is bounded far
    /// below it, and a source entry is refused by the model, which can name its path.
    #[error("the {what} is {size} bytes, a large file on a filesystem without large_file")]
    #[non_exhaustive]
    LargeFileWithoutFeature {
        /// The structure whose size crosses the bound.
        what: &'static str,
        /// The size it declares.
        size: u64,
    },
    /// An inode is charged more 512-byte sectors than a feature set without `huge_file`
    /// records. Without the feature only `i_blocks_lo` exists — the two bytes beside it are
    /// ext2's `l_i_frag` and `l_i_fsize` — so the count is 32 bits wide and stops at two
    /// tebibytes.
    ///
    /// A classic block map reaches 4.004 TiB at a 4096-byte block, and
    /// [`FeatureSet::validate`] refuses `huge_file` on a non-extent set — so on ext2 and
    /// ext3 the map outruns the field, and a file in that range is refused here rather than
    /// serialized with a wrapped low half and a high half the feature words say is not
    /// there.
    #[error(
        "the {what} is charged {sectors} sectors, past the {limit} an inode records \
         without the huge_file feature"
    )]
    #[non_exhaustive]
    BlockCountWithoutHugeFile {
        /// The structure whose block count crosses the bound.
        what: &'static str,
        /// The 512-byte sectors it is charged.
        sectors: u64,
        /// The most an inode records without the feature.
        limit: u64,
    },
    /// A file needs more blocks than a classic (ext2/ext3) block map reaches: twelve direct
    /// pointers and three levels of indirect blocks, `12 + p + p² + p³` blocks for
    /// `p = block_size / 4`. That is 16.06 GiB at a 1024-byte block and 4.004 TiB at the
    /// 4096-byte default.
    ///
    /// This is the block-mapped twin of [`ExtentError::FileTooLarge`]. A file past the reach
    /// would otherwise be mapped as far as the words go and written no further, while its
    /// size claimed the whole length — so it is refused instead. Only a feature set without
    /// `extent` reaches it: an extent-mapped file has the extent tree's own bound.
    #[error(
        "a file of {blocks} blocks exceeds the {limit} a classic block map reaches at a \
         {block_size}-byte block: build it on a feature set with extents, or at a larger \
         block size"
    )]
    #[non_exhaustive]
    FileTooLargeForBlockMap {
        /// Logical blocks the file needs.
        blocks: u64,
        /// Logical blocks the map reaches.
        limit: u64,
        /// The block size whose pointer count fixes that reach.
        block_size: u32,
    },
    /// A block the resize inode must map lies past what its block map addresses. The
    /// map is a classic 32-bit block map, and the geometry reserves descriptor blocks
    /// only on a filesystem a 32-bit block number spans, so a block past that reaching
    /// the map means the two disagree. It is refused rather than truncated into a
    /// pointer at the wrong block.
    #[error("the resize inode's 32-bit block map cannot name block {block}")]
    #[non_exhaustive]
    ResizeMapNeeds32BitBlocks {
        /// The block the map would have had to name.
        block: u64,
    },
    /// The inode the orphan file takes is already held by an entry, so writing the file
    /// there would displace it — leaving a directory entry that names the orphan file
    /// rather than the entry it was written for.
    ///
    /// Formatting derives the first entry's inode number from the feature set, so the
    /// two cannot disagree. The check stands guard over that derivation: a feature added
    /// later that claims an inode of its own must move the entries up, and until it does,
    /// this refuses the image rather than writing a directory that points at the wrong
    /// file.
    #[error("the orphan file's inode {inode} is already held by an entry")]
    #[non_exhaustive]
    OrphanInodeInUse {
        /// The contested inode number.
        inode: u32,
    },
    /// The image does not fit in memory on this platform: its byte count exceeds what a
    /// `usize` addresses, which a 32-bit target reaches at 4 GiB. [`format_to`] streams an
    /// image of any size to a seekable destination and is the path for one this large.
    #[error(
        "an image of {bytes} bytes exceeds what this platform addresses in memory; \
         stream it with format_to"
    )]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// The image's size in bytes.
        bytes: u64,
    },
    /// No filesystem this format describes holds the source with the room
    /// [`FormatPlan::fit`] was asked to leave free.
    ///
    /// The search tries sizes up to a ceiling — the largest filesystem the feature set
    /// addresses, or the grow target when [`GrowReservation::UpTo`] names one — and this is
    /// what it says when the largest of them was planned and placed successfully and still
    /// had less room left than the slack asks for. A size that *failed* is reported by its
    /// own failure instead, so this names the case where nothing was wrong except that the
    /// filesystem could not be made big enough.
    #[error(
        "no filesystem of up to {ceiling} blocks holds the source with the requested room \
         to spare"
    )]
    #[non_exhaustive]
    DoesNotFit {
        /// The largest block count the search was allowed to try.
        ceiling: u64,
    },
    /// A [`Slack::Share`] asks for a larger share of the filesystem than a fit search will
    /// look for.
    ///
    /// Past the limit the filesystem is more than ten times the source it holds, and a size
    /// that far from what the contents need is better named outright than searched for.
    #[error("slack share of {hundredths} hundredths of a percent is past the {limit} limit")]
    #[non_exhaustive]
    SlackShareTooLarge {
        /// The share asked for, in hundredths of one percent.
        hundredths: u16,
        /// The largest share a fit search accepts.
        limit: u16,
    },
    /// The format-time clock ([`FormatOptions::time`]) lies outside the range the
    /// superblock's 32-bit time fields hold: seconds in `[0, 2^32)`, from 1970 to 2106.
    /// It is refused rather than truncated to a different instant. Per-file timestamps
    /// span a wider range; this bound is on the filesystem's own creation clock.
    #[error("format time of {secs}s is outside the superblock range [0, 2^32) seconds")]
    #[non_exhaustive]
    FormatTimeOutOfRange {
        /// The out-of-range seconds value.
        secs: i64,
    },
}

/// A block number as the resize inode's block map stores it.
///
/// The map is 32 bits wide, so every block it names must be one a 32-bit block number
/// addresses. Converting through this function refuses a block past that rather than
/// silently truncating it into a pointer at the wrong block.
fn map_block(block: u64) -> Result<u32, FormatError> {
    u32::try_from(block).map_err(|_| FormatError::ResizeMapNeeds32BitBlocks { block })
}

/// The classic (ext2/ext3) block map's twelve direct pointers, filling the first twelve
/// of the inode's fifteen block-area words. The remaining three hold the single-,
/// double-, and triple-indirect roots.
const DIRECT_BLOCKS: usize = 12;

/// Levels of indirection above the direct pointers: single, double, and triple.
const INDIRECT_LEVELS: usize = 3;

/// The most logical blocks a classic block map reaches at `block_size`: the twelve direct
/// pointers, plus one, two, and three levels of indirect blocks each holding
/// `block_size / 4` pointers.
///
/// A 1024-byte block reaches 16,843,020 blocks — 16.06 GiB — and a 4096-byte block reaches
/// 1,074,791,436, which is 4.004 TiB. Past that the map runs out of words, and a file that
/// needs more of them is refused rather than mapped short.
fn classic_map_reach(block_size: usize) -> u64 {
    let ppb = (block_size / 4) as u64;
    DIRECT_BLOCKS as u64 + ppb + ppb * ppb + ppb * ppb * ppb
}

/// A finished filesystem image: the bytes, and the geometry that produced them.
pub struct Image {
    /// The complete image bytes, `total_blocks * block_size` long.
    bytes: Vec<u8>,
    /// The layout the image was written against.
    layout: Layout,
}

impl Image {
    /// The image bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the image, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The layout the image was written against.
    #[must_use]
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Write the image to `w`.
    ///
    /// # Errors
    ///
    /// Any I/O error from `w`.
    pub fn write_to(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        w.write_all(&self.bytes)
    }
}

/// Format a filesystem of `size_bytes` populated from `source`, assembling the whole
/// image in memory.
///
/// The image is held as one buffer of its full size, so this needs as much memory as the
/// filesystem is large. [`format_to`] writes the same bytes to a seekable destination
/// without ever holding them all.
///
/// # Errors
///
/// A [`FormatError`] if the geometry, model, allocation, or serialization cannot be
/// realized, or [`FormatError::ImageTooLargeInMemory`] if the image is larger than this
/// platform addresses.
pub fn format(
    source: impl Source,
    size_bytes: u64,
    options: FormatOptions,
) -> Result<Image, FormatError> {
    let plan = FormatPlan::new(source, size_bytes, options)?;

    // The whole image is one buffer, so its size must be one this platform can address:
    // a 32-bit target holds no 4 GiB image, and a cast would silently size the buffer to
    // the low bits of the count and write a filesystem into the wrong number of bytes.
    let image_bytes = plan.layout.total_blocks * u64::from(plan.layout.block_size);
    let len = usize::try_from(image_bytes)
        .map_err(|_| FormatError::ImageTooLargeInMemory { bytes: image_bytes })?;
    let mut sink = std::io::Cursor::new(vec![0u8; len]);
    let layout = plan.write_to(&mut sink)?;
    Ok(Image {
        bytes: sink.into_inner(),
        layout,
    })
}

/// Format a filesystem of `size_bytes` populated from `source`, streaming its bytes
/// into `sink` and returning the layout they realize.
///
/// Only the blocks the filesystem actually uses are written, and nothing is read
/// back, so a file destination stays sparse and the whole image never exists in
/// memory. The sink is extended to the filesystem's full size, and every byte it
/// holds that is not written must read back as zero — a freshly created file, or one
/// truncated to zero length, satisfies that.
///
/// # Memory
///
/// Three things are held while the image streams out, and none of them is the image:
///
/// - **The entry list.** Every [`SourceEntry`](crate::source::SourceEntry) the source yields — its path, metadata,
///   and extended attributes — is materialized before the first block is written, and the
///   inode model built from it is held until the last one is. This grows with the number
///   of entries, not with their size.
/// - **A file's contents, while it is placed.** How long that is depends on what the
///   source supplies. A [`FileContent::Owned`](crate::source::FileContent::Owned) entry
///   holds its bytes from the moment the source is built, so a list of them costs the sum
///   of every file. A [`FileContent::Range`](crate::source::FileContent::Range) is read at
///   placement and dropped after, so a list of them costs the largest single file.
///   `ArchiveSource::from_path` is the difference for a tar source.
/// - **The allocator's used-block bitmap**, for the whole run, at one bit per filesystem
///   block: `total_blocks / 8` bytes, 128 MiB for a 4 TiB image at a 4 KiB block.
///
/// So peak memory grows with the entry count, the largest file, and the filesystem's
/// block count — never with the image's size in bytes.
///
/// # Errors
///
/// A [`FormatError`] if the geometry, model, allocation, or serialization cannot be
/// realized, or if writing to `sink` fails.
pub fn format_to(
    source: impl Source,
    size_bytes: u64,
    options: FormatOptions,
    mut sink: impl Write + Seek,
) -> Result<Layout, FormatError> {
    FormatPlan::new(source, size_bytes, options)?.write_to(&mut sink)
}

/// Everything a format decides before a byte is written: the geometry the planner produces
/// and the inode model the source builds, checked against each other.
///
/// This is the whole fallible half of a format, and holding it as a value is what lets a
/// caller find out whether a format will work **before** touching the destination. That
/// matters because a format's destination must read as zero where the filesystem does not
/// write — so creating or truncating it is part of formatting — and a destination truncated
/// for a format that then failed on its source would be a file destroyed by a run that
/// wrote no filesystem. [`write_to`](Self::write_to) is the half that can only fail on I/O.
///
/// It is also what a caller reports from without writing anything: [`layout`](Self::layout)
/// is the geometry the bytes would realize, exact rather than estimated, because it is the
/// same value the write uses.
///
/// [`plan_layout`] plans the *geometry* alone, from a size and a feature set. A plan here is
/// that plus the model built from a source, and the check that the one fits the other.
///
/// Both entry points build one, so a knob added to [`FormatOptions`] reaches them together.
/// Two paths that derived this separately would be two paths that could disagree, and a
/// disagreement between them is not a compile error — it is one entry point formatting
/// differently from the other.
///
/// ```no_run
/// # use ferrosys::ext::{FormatOptions, FormatPlan, TreeBuilder};
/// # use ferrosys::ext::Timestamp;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0; 16]);
/// let plan = FormatPlan::new(TreeBuilder::new(), 64 << 20, options)?;
/// println!("{} blocks, {} reserved to grow into",
///     plan.layout().total_blocks, plan.layout().reserved_gdt_blocks);
///
/// // Nothing has been written yet, and the destination is untouched until here.
/// let out = std::fs::File::create("rootfs.img")?;
/// let layout = plan.write_to(out)?;
/// # let _ = layout;
/// # Ok(())
/// # }
/// ```
pub struct FormatPlan {
    layout: Layout,
    model: FsModel,
    options: FormatOptions,
    /// The journal's size in blocks, or `None` under a feature set without one.
    journal_blocks: Option<u32>,
}

impl FormatPlan {
    /// Plan a format of `size_bytes` from `source` under `options`, deciding everything
    /// but the bytes.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the geometry cannot be realized, the source cannot be modelled,
    /// or the model needs more inodes than the geometry provides. Every failure a format has
    /// that is not an I/O failure of the destination is here.
    pub fn new(
        source: impl Source,
        size_bytes: u64,
        options: FormatOptions,
    ) -> Result<Self, FormatError> {
        options.validate_format_time()?;
        let model = model_of(source, &options)?;
        let (layout, journal_blocks) = plan_geometry(&model, &options, size_bytes)?;
        Ok(Self {
            layout,
            model,
            options,
            journal_blocks,
        })
    }

    /// Plan the smallest filesystem that holds `source` with `slack` left free, deciding
    /// the size as well as everything else.
    ///
    /// [`new`](Self::new) is given a size; this one finds it. The floor is not a formula —
    /// how much room a filesystem has depends on how many groups it has, how large its
    /// inode tables are, and how large a journal its size earns, all of which follow from
    /// the size itself — so it is found by planning candidate sizes and placing the source
    /// into each, which is the same placement a format performs. A candidate is judged by
    /// what the placement leaves free, not by an estimate beside it, so a size this returns
    /// is a size that formats.
    ///
    /// **The size returned formats, and one block less does not.** The search closes a
    /// bracket whose ends are both established by placing: it ends holding a size that was
    /// placed successfully and the size one block below it that was not. Fit is not
    /// monotone in size — a filesystem one block larger can need another group, and so have
    /// less room than the one below it — so that is a smallest size rather than provably
    /// *the* smallest, and it is the guarantee worth having either way.
    ///
    /// The source is consumed once and the model built from it is kept, so the finished
    /// plan is ready to [`write_to`](Self::write_to) with no second walk of the source.
    /// [`size_bytes`](Self::size_bytes) reports what was decided.
    ///
    /// # What the search costs
    ///
    /// A handful of placements rather than one: a bracket found by doubling from what the
    /// contents occupy, then a bisection within it. No file's bytes are read and no block is
    /// written at any of them — a probe places, and the destination it places into keeps
    /// nothing.
    ///
    /// A probe's memory is a format's at that size, because it is a format's own placement:
    /// the allocator's bitmap, at one bit per block. So the search costs what formatting the
    /// sizes it tries would cost, and it tries sizes near the answer.
    ///
    /// ```no_run
    /// # use ferrosys::Slack;
    /// # use ferrosys::ext::{FormatOptions, FormatPlan, Timestamp, TreeBuilder};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let source = TreeBuilder::new();
    /// let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0; 16]);
    /// // The smallest filesystem holding the source, with a fifth of it still free.
    /// let plan = FormatPlan::fit(source, options, Slack::Share(2000))?;
    /// println!("{} bytes", plan.size_bytes());
    /// plan.write_to(std::fs::File::create("rootfs.img")?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`FormatError::SlackShareTooLarge`] if the slack asks for a share past the limit,
    /// [`FormatError::DoesNotFit`] if no filesystem the format describes holds the source
    /// with that room, and otherwise whatever the largest size tried failed with — which
    /// for a source too large for its feature set is the failure that size met, not a bare
    /// statement that nothing worked.
    pub fn fit(
        source: impl Source,
        options: FormatOptions,
        slack: Slack,
    ) -> Result<Self, FormatError> {
        options.validate_format_time()?;
        // A feature set that cannot be realized fails at every size, so it is refused once
        // here rather than found again at each candidate and reported as a sizing failure.
        options.feature.validate().map_err(GeometryError::from)?;
        let model = model_of(source, &options)?;
        let fitted = crate::fit::search(&model, &options, slack)?;
        Ok(Self {
            layout: fitted.layout,
            model,
            options,
            journal_blocks: fitted.journal_blocks,
        })
    }

    /// The geometry the bytes will realize.
    #[must_use]
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The filesystem's size in bytes: its block count times its block size.
    ///
    /// This is what [`fit`](Self::fit) decided, and with [`Slack::None`] it is the smallest
    /// filesystem that holds the source. For a plan from [`new`](Self::new) it is the size
    /// that was asked for, rounded down to a whole number of blocks.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.layout.total_blocks * u64::from(self.layout.block_size)
    }

    /// How many inodes the source occupies, of the [`Layout::total_inodes`] the geometry
    /// provides. The reserved inodes every filesystem carries are part of the count.
    #[must_use]
    pub fn used_inodes(&self) -> u32 {
        self.model.used_inode_count()
    }

    /// The geometry this plan realized, as one canonical document.
    ///
    /// This is what the *size* decided: block and inode counts, the group table, the
    /// descriptor headroom the grow reservation sized, and the journal's realized length.
    /// It moves with the filesystem size, so two images built to the same contract at
    /// different sizes have different geometry pins and that is correct rather than drift.
    ///
    /// ```text
    /// ferrosys-geometry-pin 1
    /// block_size 4096
    /// total_blocks 16384
    /// blocks_per_group 32768
    /// first_data_block 0
    /// group_count 1
    /// inodes_per_group 16384
    /// inode_table_blocks 1024
    /// total_inodes 16384
    /// gdt_blocks 1
    /// reserved_gdt_blocks 256
    /// flex_bg_size 16
    /// max_grow_blocks 538968064
    /// reserved_blocks 819
    /// groups 1 crc32c 0x8a137015
    /// journal_blocks 1024
    /// ```
    ///
    /// **Pin this at a size you choose, not at the size you happen to be building.** A
    /// [`policy_pin`](FormatOptions::policy_pin) records the options by name, so it moves
    /// when an option is renamed or re-defaulted — and not when the formula behind one
    /// changes underneath an unchanged name. `grow max` reads the same before and after a
    /// change to what `Max` reserves; `reserved_gdt_blocks` does not. Planning at one
    /// reference size and pinning the result is what turns that class of change into a
    /// diff, and the reference size makes the pin independent of what any particular build
    /// is sized to.
    ///
    /// The per-group placements are one line rather than one per group — the count, and a
    /// `crc32c` over every field of every group in order. A filesystem has as many groups
    /// as it has room for and a large one has millions, so the document stays a fixed size
    /// while a placement that moves still changes it. The projection is an exhaustive
    /// destructure, so a field added to [`Layout`] or [`GroupLayout`] is a compile error
    /// rather than a silent omission from every recorded pin.
    #[must_use]
    pub fn geometry_pin(&self) -> String {
        let mut out = String::from("ferrosys-geometry-pin 1\n");
        push_layout_pin(&mut out, &self.layout);
        out.push_str("journal_blocks ");
        match self.journal_blocks {
            Some(blocks) => out.push_str(&blocks.to_string()),
            None => out.push_str("none"),
        }
        out.push('\n');
        out
    }

    /// Write the filesystem into `sink`, returning the geometry it realized.
    ///
    /// Only the blocks the filesystem uses are written, and nothing is read back, so a file
    /// destination stays sparse. The sink is extended to the filesystem's full size, and
    /// every byte it holds that is not written must read back as zero — a freshly created
    /// file, or one truncated to zero length, satisfies that.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the allocation or serialization cannot be realized, or
    /// [`FormatError::Io`] if the sink cannot be written or sought.
    pub fn write_to(self, mut sink: impl Write + Seek) -> Result<Layout, FormatError> {
        let Self {
            layout,
            model,
            options,
            journal_blocks,
        } = self;
        let feature = options.feature;
        let bytes = Bytes(ByteSink::new(&mut sink));
        let mut writer = Writer::new(&layout, &feature, options, journal_blocks, bytes)?;
        writer.materialize(&model)?;
        writer.extend_to_full_size()?;
        Ok(layout)
    }
}

/// Build the inode model one source implies under these options.
///
/// The model depends on the feature set and the timestamps and not at all on the
/// filesystem's size, which is what lets a fit search build it once and try it against
/// many sizes.
fn model_of(source: impl Source, options: &FormatOptions) -> Result<FsModel, FormatError> {
    let feature = options.feature;
    let mut config = ModelConfig::new(feature, first_user_inode(&feature), options.time);
    config.fixed_time = options.fixed_time;
    Ok(build_model(source, config)?)
}

/// The geometry a size implies, checked against the model it has to hold.
///
/// Everything a size decides before a block is placed: the layout, whether it provides
/// inodes enough for the model, and how large a journal it earns. One function so that
/// planning a named size and probing a candidate one settle these the same way.
pub(crate) fn plan_geometry(
    model: &FsModel,
    options: &FormatOptions,
    size_bytes: u64,
) -> Result<(Layout, Option<u32>), FormatError> {
    let layout = plan_layout(&options.plan_request(size_bytes))?;
    if model.used_inode_count() > layout.total_inodes {
        return Err(FormatError::TooManyInodes {
            needed: model.used_inode_count(),
            available: layout.total_inodes,
        });
    }
    let journal_blocks = journal_size(&layout, options)?;
    Ok((layout, journal_blocks))
}

/// Place the model into this geometry and report the blocks left free, writing nothing.
///
/// This is the format's own placement pass over a sink that keeps nothing: the same
/// allocator, the same calls, in the same order — so what it says about a size is what a
/// format would find, rather than an estimate that could drift from it. The count it
/// returns is the one the superblock's `s_free_blocks_count` would carry.
///
/// # Errors
///
/// Whatever placing the model into this geometry fails with: out of space, a journal with
/// no room, a directory that cannot be packed.
pub(crate) fn free_after_placing(
    layout: &Layout,
    options: &FormatOptions,
    journal_blocks: Option<u32>,
    model: &FsModel,
) -> Result<u64, FormatError> {
    let feature = options.feature;
    let mut writer = Writer::new(layout, &feature, *options, journal_blocks, Discard)?;
    writer.place(model)?;
    Ok(writer.alloc.free_count())
}

/// Render bytes as lower-case hex, the form the pin document gives a UUID, a hash seed,
/// and a volume label: exact whatever the bytes are, and one fixed width.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A timestamp as `seconds.nanoseconds`, so the sub-second half a source can carry is part
/// of the contract rather than rounded out of it.
fn pin_time(t: Timestamp) -> String {
    format!("{}.{}", t.secs, t.nanos)
}

impl FormatOptions {
    /// The contract these options state, as one canonical document: the feature set, and
    /// every option that is a property of *how* images are built rather than of which image
    /// this is.
    ///
    /// The document is the contract. A caller records what this emits — verbatim, as a blob
    /// — and compares it string-for-string on a later build; a difference is drift in what
    /// the build promises, surfaced as a diff a person reads rather than as changed image
    /// bytes nobody notices. Comparison is exactly string equality: the rendering is
    /// deterministic, ordered, and stable across releases of this crate under the version
    /// on its first line.
    ///
    /// ```text
    /// ferrosys-policy-pin 1
    /// compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
    /// incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
    /// ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
    /// block_size 4096
    /// inode_size 256
    /// grow max
    /// inodes auto
    /// reserved 500
    /// errors continue
    /// journal auto
    /// hash_version half_md4
    /// hash_signedness unsigned
    /// timestamp_clamp none
    /// ```
    ///
    /// **Nothing here varies with the image.** No UUID, no timestamp, no label, no block
    /// count — those are [`identity_pin`](Self::identity_pin) and
    /// [`FormatPlan::geometry_pin`], and each moves for reasons that are not drift. A
    /// builder that writes many images from one set of constants gets one policy pin for
    /// all of them, so an empty diff between two images' recorded pins means they were
    /// built to the same contract, and a non-empty one always means something changed.
    ///
    /// **This is why the pin is the whole policy and not
    /// [`FeatureSet::pin`](crate::feature::FeatureSet::pin).** The feature set decides five
    /// of the values above. The grow reservation, inode count, reserved share, error
    /// behavior, journal size, and the two hash choices each move bytes too, and a contract
    /// recorded from the feature set alone shows no difference across a change to any of
    /// them — `errors` least visibly of all, since it reaches neither the feature words nor
    /// the geometry.
    ///
    /// What it does *not* catch is a change to the formula behind an option whose name is
    /// unchanged: `grow max` reads the same before and after a change to what `Max`
    /// reserves. [`FormatPlan::geometry_pin`] at a fixed reference size is what covers that.
    ///
    /// Every option is routed to one of the two documents by a single exhaustive
    /// destructure, so a field added to [`FormatOptions`] is a compile error until it is
    /// given a home rather than a silent omission from both.
    #[must_use]
    pub fn policy_pin(&self) -> String {
        let mut policy = String::from("ferrosys-policy-pin 1\n");
        let mut identity = String::new();
        self.push_pins(&mut policy, &mut identity);
        policy
    }

    /// Which image this is, as one canonical document: the identity inputs the superblock
    /// carries verbatim.
    ///
    /// ```text
    /// ferrosys-identity-pin 1
    /// uuid 11111111111111111111111111111111
    /// time 1700000000.0
    /// hash_seed 00000000000000000000000000000000
    /// volume_name 00000000000000000000000000000000
    /// fixed_time none
    /// ```
    ///
    /// This is a separate document because these fields move for a reason that is not
    /// drift. An image is meant to have its own UUID and its own timestamps, so a builder
    /// producing one image per board, or one per run, gets a different identity pin every
    /// time and nothing is wrong. Recording it alongside a [`policy_pin`](Self::policy_pin)
    /// would make every such diff non-empty and the comparison worthless.
    ///
    /// Every field here is recoverable from the image itself — `s_uuid`, `s_mkfs_time`,
    /// `s_hash_seed`, and `s_volume_name` are superblock fields a reader reports — so a
    /// caller that can open the image it built need not record this at all.
    #[must_use]
    pub fn identity_pin(&self) -> String {
        let mut policy = String::new();
        let mut identity = String::from("ferrosys-identity-pin 1\n");
        self.push_pins(&mut policy, &mut identity);
        identity
    }

    /// Route every option into the document it belongs in.
    ///
    /// Both documents are rendered together and the caller keeps the one it asked for. One
    /// function rather than two is what makes the routing total: the destructure below is
    /// exhaustive, so a field added to [`FormatOptions`] cannot be left out of both
    /// documents without failing to compile — which two independent projections, each
    /// ignoring what the other emits, would allow.
    fn push_pins(&self, policy: &mut String, identity: &mut String) {
        // Exhaustive on purpose: see the note above. Do not replace with field accesses.
        let Self {
            uuid,
            time,
            hash_seed,
            hash_version,
            hash_signedness,
            grow,
            inodes,
            reserved,
            volume_name,
            feature,
            errors,
            journal,
            fixed_time,
        } = self;

        // ── Policy: the contract, identical across every image built from these options ──
        //
        // The feature set is emitted in the form `FeatureSet::pin` gives it, so the two
        // documents agree line for line about the fields they share.
        feature.push_pin_body(policy);
        let line = |out: &mut String, key: &str, value: String| {
            out.push_str(key);
            out.push(' ');
            out.push_str(&value);
            out.push('\n');
        };
        line(
            policy,
            "grow",
            match grow {
                GrowReservation::None => "none".to_string(),
                GrowReservation::Max => "max".to_string(),
                GrowReservation::UpTo(bytes) => format!("upto {bytes}"),
            },
        );
        line(
            policy,
            "inodes",
            match inodes {
                InodeCount::Auto => "auto".to_string(),
                InodeCount::BytesPerInode(n) => format!("bytes_per_inode {n}"),
                InodeCount::Count(n) => format!("count {n}"),
            },
        );
        // The exact stored fixed-point share, not a percentage rendered back out of it.
        line(
            policy,
            "reserved",
            reserved.hundredths_of_percent().to_string(),
        );
        line(
            policy,
            "errors",
            match errors {
                ErrorBehavior::Continue => "continue".to_string(),
                ErrorBehavior::RemountReadOnly => "remount_read_only".to_string(),
                ErrorBehavior::Panic => "panic".to_string(),
            },
        );
        line(
            policy,
            "journal",
            match journal {
                JournalSize::Auto => "auto".to_string(),
                JournalSize::Blocks(n) => format!("blocks {n}"),
            },
        );
        line(
            policy,
            "hash_version",
            match hash_version {
                HashVersion::Legacy => "legacy".to_string(),
                HashVersion::HalfMd4 => "half_md4".to_string(),
                HashVersion::Tea => "tea".to_string(),
            },
        );
        line(
            policy,
            "hash_signedness",
            match hash_signedness {
                HashSignedness::Unsigned => "unsigned".to_string(),
                HashSignedness::Signed => "signed".to_string(),
            },
        );
        // Whether the build clamps every inode to one time is a property of the build; the
        // time it clamps to is a property of the image, so the two are recorded apart.
        line(
            policy,
            "timestamp_clamp",
            match fixed_time {
                None => "none".to_string(),
                Some(_) => "fixed".to_string(),
            },
        );

        // ── Identity: which image this is ──
        line(identity, "uuid", hex(uuid));
        line(identity, "time", pin_time(*time));
        line(identity, "hash_seed", hex(hash_seed));
        line(identity, "volume_name", hex(volume_name));
        line(
            identity,
            "fixed_time",
            match fixed_time {
                None => "none".to_string(),
                Some(t) => pin_time(*t),
            },
        );
    }
}

/// The realized geometry as the pin document's lines. See [`FormatPlan::geometry_pin`].
fn push_layout_pin(out: &mut String, layout: &Layout) {
    // Exhaustive on purpose, as above.
    let Layout {
        // The feature set this layout was planned for is the options' own, and states the
        // contract rather than the geometry: it belongs to the policy pin, which emits it.
        feature: _,
        block_size,
        total_blocks,
        blocks_per_group,
        first_data_block,
        group_count,
        inodes_per_group,
        inode_table_blocks,
        total_inodes,
        gdt_blocks,
        reserved_gdt_blocks,
        flex_bg_size,
        max_grow_blocks,
        reserved_blocks,
        groups,
    } = layout;

    for (key, value) in [
        // The block size is geometry as much as it is contract: every count below is in
        // these units, so a document without it states numbers with no scale.
        ("block_size", u64::from(*block_size)),
        ("total_blocks", *total_blocks),
        ("blocks_per_group", u64::from(*blocks_per_group)),
        ("first_data_block", u64::from(*first_data_block)),
        ("group_count", u64::from(*group_count)),
        ("inodes_per_group", u64::from(*inodes_per_group)),
        ("inode_table_blocks", u64::from(*inode_table_blocks)),
        ("total_inodes", u64::from(*total_inodes)),
        ("gdt_blocks", u64::from(*gdt_blocks)),
        ("reserved_gdt_blocks", u64::from(*reserved_gdt_blocks)),
        ("flex_bg_size", u64::from(*flex_bg_size)),
        ("max_grow_blocks", *max_grow_blocks),
        ("reserved_blocks", *reserved_blocks),
    ] {
        out.push_str(key);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }

    // One line for a table with as many rows as the filesystem has groups: the count, and
    // a checksum over every field of every row. A placement that moves changes the digest.
    let digest = groups_digest(groups);
    out.push_str(&format!("groups {group_count} crc32c 0x{digest:08x}\n"));
}

/// A `crc32c` over the per-group placements, field by field in group order.
///
/// Each field is fed in its widest form and in a fixed order, so the digest depends on the
/// placements and on nothing about how they happen to be stored.
fn groups_digest(groups: &[GroupLayout]) -> u32 {
    let mut crc = !0u32;
    for group in groups {
        // Exhaustive on purpose, as above: a placement field added here must change the
        // digest, so leaving it out has to be a compile error.
        let GroupLayout {
            index,
            start_block,
            block_count,
            has_super,
            block_bitmap,
            inode_bitmap,
            inode_table,
        } = group;
        crc = crc32c(crc, &u64::from(*index).to_le_bytes());
        crc = crc32c(crc, &start_block.to_le_bytes());
        crc = crc32c(crc, &u64::from(*block_count).to_le_bytes());
        crc = crc32c(crc, &[u8::from(*has_super)]);
        crc = crc32c(crc, &block_bitmap.to_le_bytes());
        crc = crc32c(crc, &inode_bitmap.to_le_bytes());
        crc = crc32c(crc, &inode_table.to_le_bytes());
    }
    !crc
}

/// The journal's size in blocks for a planned geometry, or `None` under a feature set that
/// carries no journal.
///
/// This is decided at plan time because it is decided by the geometry and the options alone,
/// and because both of its failures are failures of the *request* rather than of the
/// writing: a filesystem with no room for the smallest journal jbd2 accepts, and an explicit
/// size below that minimum or past what the feature set can describe. Discovering either
/// after the destination was opened would mean a truncated file and no filesystem.
///
/// # Errors
///
/// [`FormatError::FilesystemTooSmallForJournal`] if no journal fits;
/// [`FormatError::JournalTooSmall`] if an explicit size is below the jbd2 minimum;
/// [`FormatError::LargeFileWithoutFeature`] if an explicit size makes the log a large file
/// on a filesystem without `large_file`.
fn journal_size(layout: &Layout, options: &FormatOptions) -> Result<Option<u32>, FormatError> {
    if !options.feature.has_journal() {
        return Ok(None);
    }
    let minimum = journal::MIN_JOURNAL_BLOCKS;
    let blocks = match options.journal {
        JournalSize::Auto => journal::default_journal_blocks(layout.total_blocks).ok_or(
            FormatError::FilesystemTooSmallForJournal {
                blocks: layout.total_blocks,
                minimum,
            },
        )?,
        JournalSize::Blocks(n) if n >= minimum => n,
        JournalSize::Blocks(n) => {
            return Err(FormatError::JournalTooSmall {
                requested: n,
                minimum,
            });
        }
    };
    // The journal is a regular file, so a log an explicit size pushed to 2 GiB needs
    // `large_file` like any other. The heuristic never reaches that far; an explicit block
    // count can, and the conflict is stated rather than written to disk.
    let size = u64::from(blocks) * u64::from(options.feature.block_size);
    if size >= LARGE_FILE_MIN_SIZE && !options.feature.has_large_file() {
        return Err(FormatError::LargeFileWithoutFeature {
            what: "journal",
            size,
        });
    }
    Ok(Some(blocks))
}

/// Where a format's bytes go.
///
/// There are two, and the second is what a fit search runs on: [`Bytes`] writes to a
/// seekable destination, [`Discard`] keeps nothing at all. Which one is in place changes
/// no placement decision — the same allocator calls happen in the same order either way —
/// so a search that only places settles exactly what a write would find out about a size,
/// without writing a block or reading a file.
trait Sink {
    /// Take `bytes` at absolute byte offset `offset`.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError>;

    /// Whether the bytes are kept. A sink that discards them lets a file's contents go
    /// unread, which is the difference between a fit search costing a placement and
    /// costing a whole format.
    fn keeps_bytes(&self) -> bool;

    /// Make the destination as long as the filesystem, for the case where its final
    /// blocks hold nothing and so were never written.
    fn extend_to(&mut self, size: u64) -> Result<(), FormatError>;
}

/// The sink that writes: bytes go to a seekable destination at absolute offsets, and
/// nothing is ever read back. The destination itself is [`ByteSink`], which every family's
/// materializer writes through; what this adds is the fit search's question of whether the
/// bytes are being kept.
struct Bytes<W>(ByteSink<W>);

impl<W: Write + Seek> Sink for Bytes<W> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        Ok(self.0.write_at(offset, bytes)?)
    }

    fn keeps_bytes(&self) -> bool {
        true
    }

    fn extend_to(&mut self, size: u64) -> Result<(), FormatError> {
        Ok(self.0.extend_to(size)?)
    }
}

/// The sink that keeps nothing, so what a format decides can be found out without a
/// destination to decide it into.
struct Discard;

impl Sink for Discard {
    fn write_at(&mut self, _offset: u64, _bytes: &[u8]) -> Result<(), FormatError> {
        Ok(())
    }

    fn keeps_bytes(&self) -> bool {
        false
    }

    fn extend_to(&mut self, _size: u64) -> Result<(), FormatError> {
        Ok(())
    }
}

/// The mutable state of one format: the destination, the allocator, and the inodes
/// as they are built.
struct Writer<'a, S> {
    layout: &'a Layout,
    feature: &'a FeatureSet,
    options: FormatOptions,
    alloc: Allocator,
    /// Where the bytes go.
    sink: S,
    block_size: usize,
    /// The metadata-checksum seam: [`Crc32c`] when `metadata_csum` is on, otherwise
    /// [`NullCsum`], which zeroes every checksum. Held dynamically so the per-object
    /// checksum construction sites read the same seam regardless of which is active.
    csum: Box<dyn Checksummer>,
    /// The directory-layout seam: [`HtreeDir`] when `dir_index` is on, otherwise
    /// [`LinearDir`]. A directory small enough to need no index is packed linearly
    /// by either.
    dir: Box<dyn DirLayout>,
    /// The serialized inodes, by number.
    inodes: BTreeMap<u32, Inode>,
    /// The primary descriptor table, retained to copy into the backup groups.
    gdt_bytes: Vec<u8>,
    /// The journal inode's block map and size, backed up into the superblock's
    /// `s_jnl_blocks`. `None` until the journal is materialized, and when the feature
    /// set carries no journal.
    journal_backup: Option<[u32; 17]>,
    /// How many blocks the journal takes, decided at plan time, or `None` when the feature
    /// set carries no journal. The size is a pure function of the geometry and the options,
    /// so it is settled before the destination is opened — a journal a filesystem has no
    /// room for must not be discovered half way through writing one.
    journal_blocks: Option<u32>,
}

impl<'a, S: Sink> Writer<'a, S> {
    fn new(
        layout: &'a Layout,
        feature: &'a FeatureSet,
        options: FormatOptions,
        journal_blocks: Option<u32>,
        sink: S,
    ) -> Result<Self, FormatError> {
        let block_size = layout.block_size as usize;
        let csum: Box<dyn Checksummer> = if feature.has_metadata_csum() {
            Box::new(Crc32c::new(&options.uuid))
        } else {
            Box::new(NullCsum)
        };
        let dir: Box<dyn DirLayout> = if feature.has_dir_index() {
            Box::new(HtreeDir {
                seed: options.hash_seed,
                version: options.hash_version,
                signedness: options.hash_signedness,
                checksums: feature.has_metadata_csum(),
            })
        } else {
            Box::new(LinearDir {
                tail_len: if feature.has_metadata_csum() {
                    DIR_TAIL_LEN
                } else {
                    0
                },
            })
        };
        Ok(Self {
            layout,
            feature,
            options,
            alloc: Allocator::new(layout)?,
            sink,
            block_size,
            csum,
            dir,
            inodes: BTreeMap::new(),
            gdt_bytes: Vec::new(),
            journal_backup: None,
            journal_blocks,
        })
    }

    /// Place every block the filesystem occupies: the source's inodes, then the ones the
    /// filesystem provides for itself.
    ///
    /// This is the whole of what consumes free space, so it is what decides whether a size
    /// works — and it is all a fit search runs. Once it returns, the allocator holds the
    /// filesystem's settled free state and every remaining pass only reads it.
    fn place(&mut self, model: &FsModel) -> Result<(), FormatError> {
        for minode in model.inodes.values() {
            let inode = self.materialize_inode(minode)?;
            self.inodes.insert(minode.number, inode);
        }
        self.materialize_reserved_inodes()
    }

    fn materialize(&mut self, model: &FsModel) -> Result<(), FormatError> {
        // Data first: allocating file, directory, symlink, and resize-map blocks
        // settles the allocator before free counts and bitmaps are read back.
        self.place(model)?;

        // Then the fixed structures, in any order — they read the settled state.
        self.write_inode_tables()?;
        self.write_bitmaps_and_descriptors(model)?;
        self.write_superblocks(model)?;
        Ok(())
    }

    /// Write `bytes` at absolute byte offset `offset`.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        self.sink.write_at(offset, bytes)
    }

    /// Make the destination as long as the filesystem, for the case where its final
    /// blocks hold nothing and so were never written.
    fn extend_to_full_size(&mut self) -> Result<(), FormatError> {
        let size = self.layout.total_blocks * u64::from(self.layout.block_size);
        self.sink.extend_to(size)
    }

    /// A blank inode carrying the extra area this filesystem's inode size affords.
    ///
    /// Every inode this writer builds starts here, so the extra area is decided in one
    /// place from `s_inode_size` rather than assumed. At 128 bytes there is no extra
    /// area, and the inode carries no creation time, no sub-second timestamps, no
    /// inline attributes, and no `i_checksum_hi`.
    fn new_inode(&self) -> Inode {
        Inode::empty(self.feature.inode_size)
    }

    /// Stamp a reserved structural inode's four timestamps (resize, journal, orphan).
    /// The fixed-time clamp forces the value when set, otherwise the format time stands
    /// — the same resolution the model gives a source-derived inode, so the clamp
    /// reaches every inode and leaves no source-independent time unforced.
    fn stamp_structural_times(&self, inode: &mut Inode) {
        let t = self.options.fixed_time.unwrap_or(self.options.time);
        inode.atime = t;
        inode.ctime = t;
        inode.mtime = t;
        inode.crtime = t;
    }

    /// Build and write one model inode, returning its on-disk form.
    fn materialize_inode(&mut self, minode: &ModelInode) -> Result<Inode, FormatError> {
        let mut inode = self.new_inode();
        inode.mode = minode.mode;
        inode.uid = minode.uid;
        inode.gid = minode.gid;
        inode.links_count = minode.links_count;
        inode.atime = minode.atime;
        inode.ctime = minode.ctime;
        inode.mtime = minode.mtime;
        inode.crtime = minode.crtime;

        match &minode.content {
            Content::Directory(children) => {
                let entries: Vec<DirEntry> = children
                    .iter()
                    .map(|c| DirEntry {
                        inode: c.inode,
                        file_type: c.file_type,
                        name: c.name.clone(),
                    })
                    .collect();
                let mut blocks = self.dir.build_blocks(&entries, self.block_size)?;
                // /lost+found is preallocated to 16 KiB so a repair has room to
                // reconnect orphaned inodes. Its entries fit in one block, so it is
                // never indexed and the padding is plain entry blocks.
                if minode.number == LOST_FOUND_INO {
                    let min_blocks = (16 * 1024usize).div_ceil(self.block_size);
                    while blocks.len() < min_blocks {
                        blocks.push(DirBlock {
                            bytes: self.empty_dir_block(),
                            kind: DirBlockKind::Entries,
                        });
                    }
                }
                let indexed = blocks
                    .iter()
                    .any(|b| matches!(b.kind, DirBlockKind::Index { .. }));
                self.write_dir_checksums(minode.number, &mut blocks);
                let bytes: Vec<Vec<u8>> = blocks.into_iter().map(|b| b.bytes).collect();
                self.place_blocks(minode.number, &mut inode, bytes.iter())?;
                if indexed {
                    inode.flags = inode.flags | InodeFlags::INDEX;
                }
            }
            Content::File(content) => {
                // The block count comes from the length the content declares, which is
                // known without reading it. That is what lets a fit search place a file
                // without opening it — and it is the same count the bytes below chunk
                // into, because a content that read short is a file that changed since the
                // source named it, which `FileContent::read` refuses rather than reports.
                let count = content.len().div_ceil(self.block_size as u64);
                let physical = self.map_data_blocks(minode.number, &mut inode, count, "file")?;
                if self.sink.keeps_bytes() {
                    // The bytes are read here, at placement, rather than held from the
                    // moment the source was built: peak memory is the largest single file
                    // rather than every file at once. A source that supplied them owned
                    // pays nothing extra — the read hands back what it already holds.
                    let bytes = content.read()?;
                    let block_size = self.block_size;
                    for (data, &phys) in block_chunks(&bytes, block_size).zip(&physical) {
                        self.write_block(phys, data.as_ref())?;
                    }
                }
                inode.size = content.len();
            }
            Content::SlowSymlink(target) => {
                let block_size = self.block_size;
                self.place_blocks(minode.number, &mut inode, block_chunks(target, block_size))?;
                inode.size = target.len() as u64;
            }
            Content::FastSymlink(target) => {
                // The target lives inline in the block area; no data block, no
                // extents flag.
                inode.block[..target.len()].copy_from_slice(target);
                inode.size = target.len() as u64;
            }
            Content::Device { major, minor } => {
                // A device node stores its number in the block area and maps no
                // blocks; the file type (char vs block) is already in the mode.
                let (b0, b1) = encode_device(*major, *minor);
                put_u32(&mut inode.block, 0, b0);
                put_u32(&mut inode.block, 4, b1);
            }
            Content::Special => {
                // A FIFO or socket has no data and no block map.
            }
        }
        self.encode_xattrs(&mut inode, &minode.xattrs)?;
        Ok(inode)
    }

    /// Attach an inode's extended attributes: as many as fit go inline in the inode,
    /// and the rest spill to a freshly allocated external block charged to the inode.
    /// The split is [`split_for_storage`]'s, the same one the model validated against,
    /// so a set that reaches here always fits.
    ///
    /// The model also settled that this filesystem holds attributes at all: a non-empty
    /// set on a feature word without `ext_attr` is refused there, naming the entry, so
    /// what reaches here is a set the emitted feature words describe.
    fn encode_xattrs(&mut self, inode: &mut Inode, xattrs: &[Xattr]) -> Result<(), FormatError> {
        if xattrs.is_empty() {
            return Ok(());
        }
        // What is left of the inode after the classic fields and the extra area. A
        // 128-byte inode has none, so its attributes all spill.
        let region_len = inode.inline_xattr_capacity(self.feature.inode_size);
        let (inline, spilled) = split_for_storage(xattrs, region_len);
        if !inline.is_empty() {
            inode.inline_xattr = encode_inline(&inline, region_len)
                .expect("the inline side of the split fits the region by construction");
        }
        if !spilled.is_empty() {
            // The per-entry name hash follows the image's directory-hash signedness, so
            // one choice governs every name hash the image carries.
            let signed = matches!(self.options.hash_signedness, HashSignedness::Signed);
            let mut block = encode_block(&spilled, self.block_size, signed);
            let phys = self.alloc.allocate_one()?;
            if self.csum.scheme().writes_object_checksums() {
                // The xattr block checksum (`h_checksum` at offset 16, zero in the
                // encoded block) covers the whole block, seeded from the filesystem
                // seed and the block number as a little-endian 64-bit value.
                let mut c = self.csum.crc32c(self.csum.base_seed(), &phys.to_le_bytes());
                c = self.csum.crc32c(c, &block);
                put_u32(&mut block, 16, c);
            }
            self.write_block(phys, &block)?;
            inode.file_acl = phys;
            inode.blocks += self.sectors_per_block();
        }
        Ok(())
    }

    /// Allocate `count` data blocks, map them at the inode, and return the physical block
    /// each logical block `0..count` landed on, in order.
    ///
    /// The extent family roots an extent tree; the block-mapped family fills the classic
    /// direct-and-indirect map. Either way the map's own blocks — extent nodes, indirect
    /// blocks — are allocated here too and counted into `i_blocks`, so this is every block
    /// an inode's contents cost. A count of zero still gets an empty extent header (extent
    /// family) or an empty map (block-mapped family), so the inode is valid.
    ///
    /// The map is placed and the data written separately, which is what lets a file whose
    /// blocks are mostly zero (the journal) write only the blocks it must — and what lets a
    /// fit search take this path and stop, since nothing below it moves a block.
    fn map_data_blocks(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        count: u64,
        what: &'static str,
    ) -> Result<Vec<u64>, FormatError> {
        // Refused from the count, before a block is allocated, so the bound fires without a
        // filesystem large enough to hold the file existing. The exact charge is checked
        // again once the mapping's own blocks are known, since those only add to it.
        self.check_sectors(count * self.sectors_per_block(), what)?;
        if self.feature.has_extents() {
            inode.flags = InodeFlags::EXTENTS;
            let ranges = self.alloc.allocate(count)?;
            let physical = flatten(&ranges);
            let meta = self.root_extent_tree(ino, inode, &ranges)?;
            self.charge_sectors(inode, (count + meta) * self.sectors_per_block(), what)?;
            Ok(physical)
        } else {
            self.build_classic_map(inode, count, what)
        }
    }

    /// Allocate blocks for `blocks`, write their contents, and map them at the inode.
    ///
    /// This is [`map_data_blocks`](Self::map_data_blocks) for content already in memory: a
    /// directory's packed blocks, or a symlink target too long to live in the inode. A
    /// regular file's contents take the mapping call directly, so its bytes are read only
    /// when the sink keeps them.
    fn place_blocks<B: AsRef<[u8]>>(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        blocks: impl ExactSizeIterator<Item = B>,
    ) -> Result<(), FormatError> {
        // The blocks are consumed once, as they are written, so a caller may hand over
        // chunks that borrow their source rather than a materialized copy of it.
        let count = blocks.len();
        let physical = self.map_data_blocks(ino, inode, count as u64, "file")?;
        for (data, &phys) in blocks.zip(&physical) {
            self.write_block(phys, data.as_ref())?;
        }
        if inode.size == 0 {
            inode.size = (count * self.block_size) as u64;
        }
        Ok(())
    }

    /// Lay out a classic (ext2/ext3) block map for `n` logical data blocks: allocate the
    /// data and the indirect blocks that map them, fill the inode's fifteen-word block
    /// area, and write every indirect block. Returns the physical block of each logical
    /// block `0..n`, in order, for the caller to write the data into — the map's
    /// structure and its data are placed in one pass but written separately, so a file
    /// whose blocks are mostly zero (the journal) writes only the blocks it must.
    ///
    /// Indirect blocks are allocated just before the first data block each maps: the map
    /// is a pre-order walk of the block tree with every node allocated the moment it is
    /// first entered, which is the order `mke2fs` writes and the interleaving that fixes
    /// each block's number. Sets `inode.flags` and `inode.blocks`; leaves `inode.size` to
    /// the caller.
    fn build_classic_map(
        &mut self,
        inode: &mut Inode,
        n: u64,
        what: &'static str,
    ) -> Result<Vec<u64>, FormatError> {
        // Reached directly by the journal as well as through `map_data_blocks`, so the
        // charge bound is checked here too, before a block is allocated.
        self.check_sectors(n * self.sectors_per_block(), what)?;
        // The map's words run out at three levels of indirection, and the loop below simply
        // stops when they do — so a file past the reach would be mapped short while its size
        // claimed the whole length, which is a file whose tail is neither mapped nor written.
        // Refused here instead, as the extent path refuses a file past what a 32-bit logical
        // block number addresses.
        let reach = classic_map_reach(self.block_size);
        if n > reach {
            return Err(FormatError::FileTooLargeForBlockMap {
                blocks: n,
                limit: reach,
                block_size: self.block_size as u32,
            });
        }
        inode.flags = InodeFlags::NONE;
        let mut physical = Vec::new();
        let mut meta = 0u64;

        // Twelve direct pointers: logical blocks 0..11 in words 0..11.
        for slot in 0..n.min(DIRECT_BLOCKS as u64) {
            let phys = self.alloc.allocate_one()?;
            physical.push(phys);
            put_u32(&mut inode.block, slot as usize * 4, map_block(phys)?);
        }

        // Single-, double-, and triple-indirect trees hang off words 12, 13, 14. Each is
        // built only when the data reaches it, and allocated at the moment it is entered.
        for level in 1..=INDIRECT_LEVELS {
            if physical.len() as u64 >= n {
                break;
            }
            let root = self.build_indirect(level as u32, n, &mut physical, &mut meta)?;
            put_u32(
                &mut inode.block,
                (DIRECT_BLOCKS + level - 1) * 4,
                map_block(root)?,
            );
        }

        self.charge_sectors(inode, (n + meta) * self.sectors_per_block(), what)?;
        Ok(physical)
    }

    /// Build one indirect block `level` levels above the data — `1` single, `2` double,
    /// `3` triple — mapping data blocks from where `physical` left off up to `n` total.
    /// The indirect block itself is allocated first, before any child, so the allocation
    /// order is the pre-order walk `mke2fs` writes; its slots then fill left to right with
    /// data blocks (level 1) or deeper indirect blocks (levels 2 and 3) until this subtree
    /// is full or the data runs out. Appends each data block's physical number to
    /// `physical` and counts every indirect block it roots into `meta`. Returns the
    /// indirect block's own physical number.
    fn build_indirect(
        &mut self,
        level: u32,
        n: u64,
        physical: &mut Vec<u64>,
        meta: &mut u64,
    ) -> Result<u64, FormatError> {
        let ind_block = self.alloc.allocate_one()?;
        *meta += 1;
        let ppb = self.block_size / 4;
        let mut ptrs = vec![0u8; self.block_size];
        for slot in 0..ppb {
            if physical.len() as u64 >= n {
                break;
            }
            let child = if level == 1 {
                let phys = self.alloc.allocate_one()?;
                physical.push(phys);
                phys
            } else {
                self.build_indirect(level - 1, n, physical, meta)?
            };
            put_u32(&mut ptrs, slot * 4, map_block(child)?);
        }
        self.write_block(ind_block, &ptrs)?;
        Ok(ind_block)
    }

    /// Map `ranges` with an extent tree rooted in `inode`'s inline block area,
    /// spilling into external node blocks when the leaves outgrow it. Returns the
    /// node blocks the tree consumed — metadata blocks `i_blocks` counts alongside
    /// the file's data.
    fn root_extent_tree(
        &mut self,
        ino: u32,
        inode: &mut Inode,
        ranges: &[BlockRange],
    ) -> Result<u64, FormatError> {
        let inline_capacity = node_capacity(Inode::BLOCK_BYTES);
        let node_capacity = node_capacity(self.block_size);
        let leaves = build_leaves(ranges)?;

        let shape = plan_tree(leaves.len(), inline_capacity, node_capacity)?;
        let mut node_blocks = Vec::with_capacity(shape.node_blocks);
        for _ in 0..shape.node_blocks {
            node_blocks.push(self.alloc.allocate_one()?);
        }
        let tree = build_tree(&leaves, inline_capacity, node_capacity, &node_blocks)?;

        for node in &tree.nodes {
            let mut buf = vec![0u8; self.block_size];
            write_node(&node.node, node_capacity, &mut buf)?;
            self.write_extent_node_checksum(ino, &mut buf);
            self.write_block(node.block, &buf)?;
        }
        write_node(&tree.root, inline_capacity, &mut inode.block)?;
        Ok(shape.node_blocks as u64)
    }

    /// Fill an external extent node's reserved checksum tail. Under `metadata_csum`
    /// the tail's crc32c covers the node's header and its whole entry area, seeded
    /// from the filesystem seed, the owning inode's number, and its generation (zero
    /// here). With checksums off the tail stays zero, as the node reserved it.
    fn write_extent_node_checksum(&self, ino: u32, buf: &mut [u8]) {
        if !self.csum.scheme().writes_object_checksums() {
            return;
        }
        let tail = tail_offset(self.block_size);
        let mut c = self.csum.crc32c(self.csum.base_seed(), &ino.to_le_bytes());
        c = self.csum.crc32c(c, &0u32.to_le_bytes());
        c = self.csum.crc32c(c, &buf[..tail]);
        put_u32(buf, tail, c);
    }

    /// A directory block holding no entries: one empty slot spanning the block up to
    /// the reserved checksum tail. Used to pad a preallocated directory.
    fn empty_dir_block(&self) -> Vec<u8> {
        // The block reserves a checksum tail only under `metadata_csum`; without it the
        // empty slot spans the whole block, as mke2fs writes a non-checksummed directory.
        let tail_len = if self.csum.scheme().writes_object_checksums() {
            DIR_TAIL_LEN
        } else {
            0
        };
        let usable = self.block_size - tail_len;
        let mut block = vec![0u8; self.block_size];
        put_u32(&mut block, 0, 0); // inode 0 — an unused slot
        put_u16(&mut block, 4, usable as u16); // rec_len spans to the tail (or block end)
        if tail_len != 0 {
            // The tail slice is exactly DIR_TAIL_LEN, so this cannot fail.
            write_dir_tail(&mut block[usable..usable + DIR_TAIL_LEN], 0)
                .expect("tail slice is exactly DIR_TAIL_LEN");
        }
        block
    }

    /// Fill each directory block's reserved tail checksum. Under `metadata_csum` the
    /// tail's crc32c is seeded from the filesystem seed, the owning directory's inode
    /// number, and its generation (zero here). With checksums off the tails stay zero,
    /// exactly as they were reserved.
    ///
    /// A block of entries is covered up to its twelve-byte tail. An index block is
    /// covered only through the entries it actually holds, followed by its own
    /// eight-byte tail with the checksum field zeroed — the two tails differ in size,
    /// in position, and in what they cover.
    fn write_dir_checksums(&self, dir_ino: u32, blocks: &mut [DirBlock]) {
        if !self.csum.scheme().writes_object_checksums() {
            return;
        }
        let seed = self.csum.base_seed();
        for block in blocks {
            let mut c = self.csum.crc32c(seed, &dir_ino.to_le_bytes());
            c = self.csum.crc32c(c, &0u32.to_le_bytes());
            match block.kind {
                DirBlockKind::Entries => {
                    let covered = self.block_size - DIR_TAIL_LEN;
                    c = self.csum.crc32c(c, &block.bytes[..covered]);
                    put_u32(&mut block.bytes, self.block_size - 4, c);
                }
                DirBlockKind::Index {
                    count_offset,
                    limit,
                } => {
                    let count = get_u16(&block.bytes, count_offset + 2) as usize;
                    let covered = count_offset + DX_ENTRY_LEN * count;
                    c = self.csum.crc32c(c, &block.bytes[..covered]);
                    // The tail folds in as `dt_reserved` followed by four zero bytes
                    // standing in for `dt_checksum`. Both words are zero here — the
                    // reserved one because `write_dx_tail` writes it so, and the
                    // checksum because it is the field being computed — so the whole
                    // tail folds as zeros, and it is folded before it is written.
                    c = self.csum.crc32c(c, &[0u8; DX_TAIL_LEN]);
                    write_dx_tail(&mut block.bytes, count_offset, limit, c)
                        .expect("the index block reserved its tail");
                }
            }
        }
    }

    /// Write the inodes the filesystem provides for itself: the empty bad-blocks and
    /// unused reserved inodes, the resize inode with its reserved-descriptor map, the
    /// journal, and the orphan file.
    fn materialize_reserved_inodes(&mut self) -> Result<(), FormatError> {
        // Reserved inodes with no content: bad-blocks (1) and the unused range (3-6,
        // 9-10). The journal (8) is empty only when `has_journal` is off.
        for n in [1u32, 3, 4, 5, 6, 9, 10] {
            self.inodes.insert(n, self.new_inode());
        }
        let resize = if self.feature.has_resize_inode() {
            self.materialize_resize_inode()?
        } else {
            self.new_inode()
        };
        self.inodes.insert(RESIZE_INO, resize);
        let journal = match self.journal_blocks {
            Some(blocks) => self.materialize_journal_inode(blocks)?,
            None => self.new_inode(),
        };
        self.inodes.insert(JOURNAL_INO, journal);
        // The orphan file is not a reserved inode: it exists only with the feature, and
        // when it does not, inode 12 is the source's first entry instead. The model was
        // built to leave it free, so finding an entry there means the two disagree about
        // which inodes the feature set claims — the image is refused rather than written
        // with the entry displaced.
        if self.feature.has_orphan_file() {
            if self.inodes.contains_key(&ORPHAN_INO) {
                return Err(FormatError::OrphanInodeInUse { inode: ORPHAN_INO });
            }
            let orphan = self.materialize_orphan_inode()?;
            self.inodes.insert(ORPHAN_INO, orphan);
        }
        Ok(())
    }

    /// Build the orphan file (inode 12): a regular extent-mapped file holding the
    /// inodes awaiting deletion, of which a fresh filesystem has none — so every entry
    /// is zero and each block carries only its magic-and-checksum tail.
    fn materialize_orphan_inode(&mut self) -> Result<Inode, FormatError> {
        let blocks = orphan_file_blocks(self.layout.total_blocks);
        // One contiguous run keeps the file's extents inline in the inode, as its size
        // always fits a single extent.
        let ranges = match self.alloc.allocate_contiguous(u64::from(blocks)) {
            Some(range) => vec![range],
            None => self.alloc.allocate(u64::from(blocks))?,
        };

        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);
        inode.flags = InodeFlags::EXTENTS;
        let meta = self.root_extent_tree(ORPHAN_INO, &mut inode, &ranges)?;
        inode.size = u64::from(blocks) * u64::from(self.feature.block_size);
        self.charge_sectors(
            &mut inode,
            (u64::from(blocks) + meta) * self.sectors_per_block(),
            "orphan file",
        )?;

        // The image starts zeroed and every entry is zero, so each block needs only its
        // tail written. The checksum covers the entry array — the block but for that
        // tail — behind the file's identity and the block's own number, so it differs
        // from block to block even though their contents are identical.
        let entries_len = orphan_entries_len(self.block_size);
        let entries = vec![0u8; entries_len];
        let seed = self.csum.base_seed();
        for block in ranges.iter().flat_map(|r| r.start..r.start + r.len) {
            let mut c = self.csum.crc32c(seed, &ORPHAN_INO.to_le_bytes());
            c = self.csum.crc32c(c, &inode.generation.to_le_bytes());
            c = self.csum.crc32c(c, &block.to_le_bytes());
            c = self.csum.crc32c(c, &entries);
            let offset = block * u64::from(self.layout.block_size) + entries_len as u64;
            self.write_at(offset, &orphan_tail_bytes(c))?;
        }
        Ok(inode)
    }

    /// Build the journal inode (inode 8): a regular extent-mapped file whose first
    /// block is the jbd2 superblock and whose remaining blocks are the empty log. The
    /// journal maps as one extent whenever a contiguous run is free, falling back to a
    /// fragmented allocation otherwise.
    fn materialize_journal_inode(&mut self, blocks: u32) -> Result<Inode, FormatError> {
        let size = u64::from(blocks) * u64::from(self.feature.block_size);
        // The image starts zeroed, so only the first block — the jbd2 superblock — needs
        // writing; the rest of the log is already the zero blocks it must be.
        let sb = journal::build_superblock(&journal::JournalParams::new(
            self.feature.block_size,
            blocks,
            self.options.uuid,
        ));

        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);

        if self.feature.has_extents() {
            // Prefer one contiguous run so the journal maps inline; the sparse_super
            // backup gaps leave runs long enough for any journal size the heuristic picks.
            let ranges = match self.alloc.allocate_contiguous(u64::from(blocks)) {
                Some(range) => vec![range],
                None => self
                    .alloc
                    .allocate(u64::from(blocks))
                    .map_err(journal_space)?,
            };
            // The log's first block, which is the jbd2 superblock. Indexing the first range
            // cannot be out of bounds: `blocks` is at least `MIN_JOURNAL_BLOCKS` — the size
            // is checked against that floor before this is called, whether it came from the
            // heuristic or from an explicit `JournalSize::Blocks` — so the allocation is of
            // a nonzero count, and an allocation of a nonzero count either yields at least
            // one range or fails.
            self.write_block(ranges[0].start, &sb)?;
            inode.flags = InodeFlags::EXTENTS;
            let meta = self.root_extent_tree(JOURNAL_INO, &mut inode, &ranges)?;
            self.charge_sectors(
                &mut inode,
                (u64::from(blocks) + meta) * self.sectors_per_block(),
                "journal",
            )?;
        } else {
            // ext3: the journal maps through the classic block map, its indirect blocks
            // interleaved with the log the same way `mke2fs` writes them. Only the first
            // block, the jbd2 superblock, is written; the rest stays zeroed.
            let physical = self
                .build_classic_map(&mut inode, u64::from(blocks), "journal")
                .map_err(journal_space)?;
            // As above: `blocks` is at least `MIN_JOURNAL_BLOCKS`, and the map holds one
            // entry per logical block, so there is a first one.
            self.write_block(physical[0], &sb)?;
        }
        inode.size = size;

        // Back the block map up into the superblock: the 15 i_block words, then the
        // high and low halves of the size.
        let mut backup = [0u32; 17];
        for (i, word) in inode.block.chunks_exact(4).enumerate() {
            backup[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        backup[15] = (inode.size >> 32) as u32;
        backup[16] = inode.size as u32;
        self.journal_backup = Some(backup);
        Ok(inode)
    }

    /// Build the resize inode (inode 7): a classic double-indirect map whose indirect
    /// blocks are the primary reserved descriptor blocks, each listing the matching
    /// reserved descriptor block in every backup group.
    ///
    /// The double-indirect block exists whenever the `resize_inode` feature does, even
    /// with nothing reserved: an image carrying the feature with an empty resize inode
    /// is not a valid ext4 filesystem. A zero reservation simply leaves the map blank.
    fn materialize_resize_inode(&mut self) -> Result<Inode, FormatError> {
        let mut inode = self.new_inode();
        inode.mode = 0o100600;
        inode.links_count = 1;
        self.stamp_structural_times(&mut inode);
        // No extents: the resize inode uses the classic block map.
        inode.flags = InodeFlags::NONE;

        let reserved = self.layout.reserved_gdt_blocks;
        let bs = self.block_size;
        let fdb = u64::from(self.layout.first_data_block);
        let gdt = u64::from(self.layout.gdt_blocks);
        let backups = self.layout.backup_groups();

        // A freshly allocated double-indirect block indexes the primary reserved
        // descriptor blocks. A descriptor block's slot is its absolute table slot taken
        // modulo the slots one block holds, so a reservation may fill the map: with
        // `gdt` at 1 and `block_size / 4` blocks reserved, the last slot written wraps
        // back to 0, which the primary descriptor table's own slot never claims. The
        // reservation is therefore bounded by the map's `block_size / 4` slots alone,
        // not by the table's slots plus the reservation's.
        let slots = u64::from(self.layout.block_size) / 4;
        let dind_block = self.alloc.allocate_one()?;
        let mut dind = vec![0u8; bs];
        for r in 0..u64::from(reserved) {
            let primary = fdb + 1 + gdt + r; // the r-th primary reserved GDT block
            let slot = (gdt + r) % slots;
            put_u32(&mut dind, (slot * 4) as usize, map_block(primary)?);
        }
        self.write_block(dind_block, &dind)?;

        // Each primary reserved descriptor block, used as an indirect block, lists
        // the matching reserved descriptor block in every backup group.
        for r in 0..u64::from(reserved) {
            let ind_block = fdb + 1 + gdt + r;
            let mut ind = vec![0u8; bs];
            for (j, &bg) in backups.iter().enumerate() {
                let start = fdb + u64::from(bg) * u64::from(self.layout.blocks_per_group);
                let backup_resv = start + 1 + gdt + r;
                put_u32(&mut ind, j * 4, map_block(backup_resv)?);
            }
            self.write_block(ind_block, &ind)?;
        }

        // The map hangs entirely off the double-indirect slot (index 13). The size records
        // the classic map's reach rather than the blocks reserved, which is what makes the
        // resize inode a large file at a 4096-byte block — the pairing `validate` enforces.
        inode.size = resize_inode_size(self.layout.block_size);
        let data_blocks = 1 + u64::from(reserved) + u64::from(reserved) * backups.len() as u64;
        self.charge_sectors(
            &mut inode,
            data_blocks * self.sectors_per_block(),
            "resize inode",
        )?;
        put_u32(&mut inode.block, 13 * 4, map_block(dind_block)?);
        Ok(inode)
    }

    /// Write every built inode into its group's inode table.
    fn write_inode_tables(&mut self) -> Result<(), FormatError> {
        let ipg = self.layout.inodes_per_group;
        let inode_size = self.feature.inode_size;
        let isize = inode_size as usize;
        let writes_checksums = self.csum.scheme().writes_object_checksums();
        let seed = self.csum.base_seed();
        // Held aside so each write may borrow the sink mutably; the inodes go back
        // afterwards, because the superblock's accounting still reads them.
        let inodes = std::mem::take(&mut self.inodes);
        let mut bytes = vec![0u8; isize];
        for (&number, inode) in &inodes {
            let group = (number - 1) / ipg;
            let index = ((number - 1) % ipg) as usize;
            let table = self.layout.groups[group as usize].inode_table;
            let offset = table * u64::from(self.layout.block_size) + (index * isize) as u64;
            // On the block-mapped family an unused inode — no mode, no links —
            // serializes as all zeros, the way mke2fs leaves the reserved inodes it does
            // not fill: no `i_extra_isize`, and (there being no checksums) nothing else.
            // Under `metadata_csum` an unused inode still carries the `i_extra_isize` and
            // the crc32c the checksum pass writes below, so the zeroing is confined to the
            // family that has no checksums to write.
            if !writes_checksums && inode.mode == 0 && inode.links_count == 0 {
                bytes.iter_mut().for_each(|b| *b = 0);
                self.write_at(offset, &bytes)?;
                continue;
            }
            inode.write_to(&mut bytes, inode_size)?;
            if writes_checksums {
                // The inode checksum covers the whole inode with its checksum fields
                // taken as zero — they are zero in `bytes` here, because the field this
                // is about to fill in serialized from a zero `Inode::checksum`.
                //
                // The high half only exists when the inode is large enough to hold it.
                // Writing it regardless would land two bytes of checksum in whatever
                // occupies 0x82 on an inode that has no extended area — for a 128-byte
                // inode, past its end and into the next one.
                let mut c = self.csum.crc32c(seed, &number.to_le_bytes());
                c = self.csum.crc32c(c, &inode.generation.to_le_bytes());
                c = self.csum.crc32c(c, &bytes);
                put_u16(&mut bytes, Inode::CHECKSUM_LO_OFFSET, (c & 0xffff) as u16);
                if Inode::has_checksum_hi(inode_size, inode.extra_isize) {
                    put_u16(&mut bytes, Inode::CHECKSUM_HI_OFFSET, (c >> 16) as u16);
                }
            }
            self.write_at(offset, &bytes)?;
        }
        self.inodes = inodes;
        Ok(())
    }

    /// Write each group's block bitmap and inode bitmap, and build and write the
    /// group descriptor table.
    fn write_bitmaps_and_descriptors(&mut self, model: &FsModel) -> Result<(), FormatError> {
        let ipg = self.layout.inodes_per_group;
        let desc_size = self.feature.desc_size() as usize;
        let mut gdt_bytes = vec![0u8; self.layout.gdt_blocks as usize * self.block_size];

        // Directory counts per group, for `bg_used_dirs_count`.
        let mut dir_counts = vec![0u32; self.layout.group_count as usize];
        for minode in model.inodes.values() {
            if minode.is_dir() {
                dir_counts[((minode.number - 1) / ipg) as usize] += 1;
            }
        }

        let uninit_bg = self.csum.scheme().uninit_bg_semantics();
        let last_group = self.layout.group_count - 1;
        let seed = self.csum.base_seed();
        // The bytes of each bitmap the checksum covers, as the kernel measures them:
        // `ext4_block_bitmap_csum_set` takes `clusters_per_group / 8`, which is exact
        // because a group's block count is always a multiple of eight, while
        // `ext4_inode_bitmap_csum_set` takes `(inodes_per_group + 7) / 8` — rounding up,
        // so a count that is not a multiple of eight still has its final partial byte
        // covered. The planner and `mke2fs` both round the inode count down to a multiple
        // of eight, so the two forms agree on every image either writes; the kernel's is
        // used so they also agree on one that does not.
        let bb_len = (self.layout.blocks_per_group / 8) as usize;
        let ib_len = ipg.div_ceil(8) as usize;

        for g in 0..self.layout.group_count {
            let gl = &self.layout.groups[g as usize];
            let used_inodes = used_inodes_in_group(g, ipg, model.first_free_inode);

            // Under metadata_csum a group with no in-use inodes leaves its inode
            // bitmap uninitialized, and one with no data blocks leaves its block
            // bitmap uninitialized — except a flex-group head, which physically holds
            // the packed tables, and the final group. An uninitialized bitmap is
            // written zero and its checksum field left zero; the group is derived from
            // its layout instead.
            let inode_uninit = uninit_bg && used_inodes == 0;
            let block_uninit = uninit_bg
                && !self.layout.is_flex_head(g)
                && g != last_group
                && self.group_is_dataless(g);

            let bbmp = if block_uninit {
                vec![0u8; self.block_size]
            } else {
                // The allocator is built over this layout, so every group the layout
                // has, it has a bitmap for: `g` is never past the last.
                self.alloc
                    .group_bitmap(g)
                    .expect("a group of this layout has a bitmap")
                    .to_vec()
            };
            let ibmp = if inode_uninit {
                vec![0u8; self.block_size]
            } else {
                self.inode_bitmap(g, model.first_free_inode)
            };

            let block_bitmap_csum = if block_uninit {
                0
            } else {
                self.csum.crc32c(seed, &bbmp[..bb_len])
            };
            let inode_bitmap_csum = if inode_uninit {
                0
            } else {
                self.csum.crc32c(seed, &ibmp[..ib_len])
            };

            // `bg_flags` is meaningful only under metadata_csum / uninit_bg: `BG_INODE_ZEROED`
            // marks an initialized inode table, the two UNINIT bits an uninitialized bitmap.
            // Without the feature the whole field is zero, as `mke2fs` writes it, rather than
            // a flag no feature backs.
            let mut flags = if uninit_bg { BG_INODE_ZEROED } else { 0 };
            if inode_uninit {
                flags |= BG_INODE_UNINIT;
            }
            if block_uninit {
                flags |= BG_BLOCK_UNINIT;
            }

            let mut desc = GroupDescriptor {
                block_bitmap: gl.block_bitmap,
                inode_bitmap: gl.inode_bitmap,
                inode_table: gl.inode_table,
                free_blocks_count: self.alloc.group_free_count(g),
                free_inodes_count: ipg - used_inodes,
                used_dirs_count: dir_counts[g as usize],
                flags,
                // The count of never-used inodes at the tail of the table lets a
                // checker skip scanning them; meaningful only under metadata_csum.
                itable_unused: if uninit_bg { ipg - used_inodes } else { 0 },
                checksum: 0,
                block_bitmap_csum,
                inode_bitmap_csum,
            };
            // The descriptor checksum covers the two bitmap checksums, so it is
            // computed last, over the otherwise-complete descriptor.
            desc.checksum = self.group_desc_csum(g, &desc, desc_size);

            let off = g as usize * desc_size;
            desc.write_to(&mut gdt_bytes[off..off + desc_size], desc_size)
                .expect("descriptor buffer is sized to the whole table");
            self.write_block(gl.block_bitmap, &bbmp)?;
            self.write_block(gl.inode_bitmap, &ibmp)?;
        }

        // Write the primary group-descriptor table right after the primary superblock.
        let gdt_start =
            (u64::from(self.layout.first_data_block) + 1) * u64::from(self.layout.block_size);
        self.write_at(gdt_start, &gdt_bytes)?;
        // Keep the table for the backup copies.
        self.gdt_bytes = gdt_bytes;
        Ok(())
    }

    /// Whether group `g` holds no data blocks — only its fixed metadata — and so is
    /// eligible for `BLOCK_UNINIT`. A non-flex-head group's only local metadata is its
    /// superblock-and-descriptor backup, if it carries one; anything used beyond that
    /// is data. Called only for non-flex-head groups (a flex head holds the packed
    /// tables and is never treated as dataless).
    fn group_is_dataless(&self, g: u32) -> bool {
        let block_count = u64::from(self.layout.groups[g as usize].block_count);
        let free = u64::from(self.alloc.group_free_count(g));
        let meta = self.layout.super_overhead_region(g).map_or(0, |r| r.len);
        block_count - free == meta
    }

    /// The group descriptor checksum (`bg_checksum`): the low 16 bits of a crc32c
    /// over the filesystem seed, the group number, and the descriptor bytes with the
    /// checksum field taken as zero. Zero when checksums are off.
    ///
    /// This is the one field whose *algorithm* the checksum scheme names rather than
    /// merely switching on and off, so it reads the scheme itself: a scheme added to
    /// [`CsumScheme`] is a compile error here, which is where the choice belongs.
    fn group_desc_csum(&self, group: u32, desc: &GroupDescriptor, desc_size: usize) -> u16 {
        match self.csum.scheme() {
            CsumScheme::None => return 0,
            CsumScheme::Crc32c => {}
        }
        let mut buf = [0u8; GroupDescriptor::SIZE_64];
        desc.write_to(&mut buf[..desc_size], desc_size)
            .expect("descriptor buffer holds a full descriptor");
        // `desc.checksum` is zero here, so the two bg_checksum bytes in `buf` already
        // hold the zeros ext4 folds in place of the field.
        let mut c = self
            .csum
            .crc32c(self.csum.base_seed(), &group.to_le_bytes());
        c = self.csum.crc32c(c, &buf[..desc_size]);
        (c & 0xffff) as u16
    }

    /// Build one group's inode bitmap: a used bit per in-use inode, and set padding
    /// past the group's inode count.
    fn inode_bitmap(&self, group: u32, first_free_inode: u32) -> Vec<u8> {
        let ipg = self.layout.inodes_per_group;
        let mut bmp = vec![0u8; self.block_size];
        let base = u64::from(group) * u64::from(ipg);
        for i in 0..ipg {
            let inode = base + u64::from(i) + 1;
            if inode < u64::from(first_free_inode) {
                bmp[(i / 8) as usize] |= 1 << (i % 8);
            }
        }
        // Padding past the group's inodes is marked used.
        for i in ipg..(self.block_size as u32 * 8) {
            bmp[(i / 8) as usize] |= 1 << (i % 8);
        }
        bmp
    }

    /// Write the primary superblock and, in every backup group, a superblock copy
    /// (with its own group number) and a group-descriptor-table copy.
    fn write_superblocks(&mut self, model: &FsModel) -> Result<(), FormatError> {
        let sb = self.build_superblock(model);

        // Primary: 1024 bytes into the image, inside block 0 for a 4 KiB block.
        let mut primary = sb.to_bytes();
        self.finalize_sb_csum(&mut primary);
        self.write_at(1024, &primary)?;

        let gdt = std::mem::take(&mut self.gdt_bytes);
        for g in self.layout.backup_groups() {
            let start = (u64::from(self.layout.first_data_block)
                + u64::from(g) * u64::from(self.layout.blocks_per_group))
                * u64::from(self.layout.block_size);
            // The backup superblock sits at the group's first block, and records its
            // own group number — the one field that differs from the primary, so its
            // checksum is computed over the backup's own bytes.
            //
            // `s_block_group_nr` is sixteen bits, so a backup group past 65535 keeps
            // only the low sixteen. e2fsprogs truncates the same field identically, so
            // the backups this writes stay byte-compatible with it; the truncation is
            // deliberate parity, not a defect.
            let mut backup = sb.clone();
            backup.block_group_nr = g as u16;
            let mut bytes = backup.to_bytes();
            self.finalize_sb_csum(&mut bytes);
            self.write_at(start, &bytes)?;
            // The descriptor-table copy follows in the next block.
            self.write_at(start + u64::from(self.layout.block_size), &gdt)?;
        }
        Ok(())
    }

    /// Write the superblock crc32c (`s_checksum`) into a serialized superblock. The
    /// checksum covers the record up to its own field and, unlike every other
    /// metadata object, ext4 seeds it from `!0` rather than the filesystem seed. With
    /// checksums off the seam returns zero, leaving the field zero.
    fn finalize_sb_csum(&self, bytes: &mut [u8; SuperBlock::SIZE]) {
        let c = self.csum.crc32c(!0, &bytes[..SuperBlock::SIZE - 4]);
        put_u32(bytes, SuperBlock::SIZE - 4, c);
    }

    /// Assemble the superblock from the layout, feature set, and settled counts.
    fn build_superblock(&self, model: &FsModel) -> SuperBlock {
        let mut sb = SuperBlock::new();
        let l = self.layout;
        sb.inodes_count = l.total_inodes;
        sb.blocks_count = l.total_blocks;
        sb.r_blocks_count = l.reserved_blocks;
        sb.free_blocks_count = self.alloc.free_count();
        sb.free_inodes_count = l.total_inodes - model.used_inode_count();
        sb.first_data_block = l.first_data_block;
        sb.log_block_size = l.block_size.trailing_zeros() - 10;
        sb.log_cluster_size = sb.log_block_size;
        sb.blocks_per_group = l.blocks_per_group;
        sb.clusters_per_group = l.blocks_per_group;
        sb.inodes_per_group = l.inodes_per_group;
        sb.wtime = self.options.time.secs as u32;
        sb.max_mnt_count = 0xffff;
        sb.state = 1; // cleanly unmounted
        sb.errors = self.options.errors.to_s_errors();
        sb.lastcheck = self.options.time.secs as u32;
        sb.rev_level = 1; // dynamic
        sb.first_ino = 11;
        sb.inode_size = self.feature.inode_size;
        sb.feature_compat = self.feature.compat.bits();
        sb.feature_incompat = self.feature.incompat.bits();
        sb.feature_ro_compat = self.feature.ro_compat.bits();
        sb.uuid = self.options.uuid;
        sb.volume_name = self.options.volume_name;
        if let Some(backup) = self.journal_backup {
            sb.journal_inum = JOURNAL_INO;
            sb.jnl_backup_type = 1; // the block map is backed up in s_jnl_blocks
            sb.jnl_blocks = backup;
        }
        if self.feature.has_orphan_file() {
            sb.orphan_file_inum = ORPHAN_INO;
        }
        if self.feature.has_csum_seed() {
            // The stored seed is the one the UUID yields, so it changes no checksum;
            // recording it is what lets the UUID change later without rewriting them.
            sb.checksum_seed = self.csum.base_seed();
        }
        sb.reserved_gdt_blocks = l.reserved_gdt_blocks as u16;
        sb.hash_seed = self.options.hash_seed;
        sb.def_hash_version = self.options.hash_version.to_u8();
        sb.flags = self.options.hash_signedness.to_flag();
        // The superblock's `s_desc_size` records the 64-byte descriptor width only under
        // `64bit`; a 32-byte-descriptor filesystem leaves it zero, which every tool reads
        // as the classic 32. The descriptors are still serialized at their real width
        // (`feature.desc_size()`) — this is the advertised field, not the layout.
        sb.desc_size = if self.feature.is_64bit() {
            self.feature.desc_size()
        } else {
            0
        };
        sb.default_mount_opts = 0x0c; // user_xattr | acl
        sb.mkfs_time = self.options.time.secs as u32;
        // The extra area every inode declares. A 128-byte inode has none, and
        // advertising one the inodes do not carry would misdescribe the filesystem.
        sb.min_extra_isize = extra_isize_for(self.feature.inode_size);
        sb.want_extra_isize = sb.min_extra_isize;
        // `s_log_groups_per_flex` describes the flex packing; a non-flex filesystem
        // leaves it zero even though the layout still groups by `flex_bg_size` internally.
        sb.log_groups_per_flex = if self.feature.has_flex_bg() {
            l.flex_bg_size.trailing_zeros() as u8
        } else {
            0
        };
        // `s_checksum_type` names the algorithm: 1 is crc32c, and a filesystem with no
        // object checksums leaves it zero.
        sb.checksum_type = match self.csum.scheme() {
            CsumScheme::None => 0,
            CsumScheme::Crc32c => 1,
        };
        // The filesystem's own bookkeeping as the kernel's ext4_calculate_overhead()
        // accounts it: the per-group metadata plus the internal journal's full footprint
        // (the orphan file is ordinary file data to that accounting). That footprint is
        // the log blocks plus the metadata its own block map costs — the extent-tree
        // nodes on ext4, the indirect blocks on ext3 — which the materialized journal
        // inode already totals in `i_blocks`, so it is read from there rather than
        // re-derived as the log size alone. A recomputable hint (e2fsck ignores it), so
        // saturate rather than wrap at the exabyte scale where the count exceeds a u32.
        let journal_blocks = if self.feature.has_journal() {
            self.inodes
                .get(&JOURNAL_INO)
                .map_or(0, |journal| journal.blocks / self.sectors_per_block())
        } else {
            0
        };
        sb.overhead_clusters =
            u32::try_from(l.overhead_blocks() + journal_blocks).unwrap_or(u32::MAX);
        sb
    }

    /// Blocks-to-512-byte-sectors conversion for `i_blocks`.
    fn sectors_per_block(&self) -> u64 {
        u64::from(self.layout.block_size) / 512
    }

    /// Record the sectors an inode is charged, refusing a count its feature set cannot hold.
    ///
    /// Every `i_blocks` this writer sets goes through here, because the field is only 32
    /// bits wide without `huge_file` and the bytes above it are another field entirely. A
    /// count past that would serialize as a wrapped low half beside a high half the feature
    /// words deny — no panic, no error, and an image every checker faults.
    fn charge_sectors(
        &self,
        inode: &mut Inode,
        sectors: u64,
        what: &'static str,
    ) -> Result<(), FormatError> {
        self.check_sectors(sectors, what)?;
        inode.blocks = sectors;
        Ok(())
    }

    /// The bound alone, for a caller that knows the count before it has an inode to put it
    /// on — which is how a request too large to record is refused before a block of it is
    /// allocated.
    fn check_sectors(&self, sectors: u64, what: &'static str) -> Result<(), FormatError> {
        if !self.feature.has_huge_file() && sectors > MAX_SECTORS_WITHOUT_HUGE_FILE {
            return Err(FormatError::BlockCountWithoutHugeFile {
                what,
                sectors,
                limit: MAX_SECTORS_WITHOUT_HUGE_FILE,
            });
        }
        Ok(())
    }

    fn write_block(&mut self, block: u64, data: &[u8]) -> Result<(), FormatError> {
        self.write_at(block * u64::from(self.layout.block_size), data)
    }
}

/// Split content into block-sized chunks for placement, zero-padding the final chunk.
///
/// The chunks borrow the source. Only a final short chunk is copied, into a padded block
/// of its own, so placing a file costs one block beyond the file's own bytes rather than a
/// second copy of it — which is what lets the contract be "peak memory is the largest
/// single file" rather than twice that.
fn block_chunks(bytes: &[u8], block_size: usize) -> impl ExactSizeIterator<Item = Cow<'_, [u8]>> {
    bytes.chunks(block_size).map(move |chunk| {
        if chunk.len() == block_size {
            Cow::Borrowed(chunk)
        } else {
            let mut block = vec![0u8; block_size];
            block[..chunk.len()].copy_from_slice(chunk);
            Cow::Owned(block)
        }
    })
}

/// Flatten allocated ranges into the physical block numbers they cover, in order.
fn flatten(ranges: &[BlockRange]) -> Vec<u64> {
    let mut out = Vec::new();
    for r in ranges {
        out.extend(r.start..r.end());
    }
    out
}

/// Inodes in use within group `group`, given the first free inode number.
fn used_inodes_in_group(group: u32, ipg: u32, first_free_inode: u32) -> u32 {
    let base = group * ipg; // one below this group's first inode number
    (first_free_inode - 1).saturating_sub(base).min(ipg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::Reader;
    use crate::source::TreeBuilder;

    const MIB: u64 = 1024 * 1024;

    fn opts() -> FormatOptions {
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
        o
    }

    /// The plan the pin tests read: the default profile at a size small enough to state
    /// every geometry number in the golden document.
    fn pinned_options() -> FormatOptions {
        let mut o = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        o.grow = GrowReservation::Max;
        o
    }

    fn pinned_plan() -> FormatPlan {
        FormatPlan::new(TreeBuilder::new(), 64 * MIB, pinned_options()).expect("plan")
    }

    #[test]
    fn the_policy_pin_is_the_document_it_documents() {
        // The golden document, and what `policy_pin`'s rustdoc shows, so the example a
        // reader copies is the one the code emits. Every value here is a decision that
        // moves bytes and none of them varies with the image.
        let expected = "\
ferrosys-policy-pin 1
compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
block_size 4096
inode_size 256
grow max
inodes auto
reserved 500
errors continue
journal auto
hash_version half_md4
hash_signedness unsigned
timestamp_clamp none
";
        assert_eq!(pinned_options().policy_pin(), expected);
    }

    #[test]
    fn the_identity_pin_is_the_document_it_documents() {
        let expected = "\
ferrosys-identity-pin 1
uuid 11111111111111111111111111111111
time 1700000000.0
hash_seed 00000000000000000000000000000000
volume_name 00000000000000000000000000000000
fixed_time none
";
        assert_eq!(pinned_options().identity_pin(), expected);
    }

    #[test]
    fn the_geometry_pin_is_the_document_it_documents() {
        let expected = "\
ferrosys-geometry-pin 1
block_size 4096
total_blocks 16384
blocks_per_group 32768
first_data_block 0
group_count 1
inodes_per_group 16384
inode_table_blocks 1024
total_inodes 16384
gdt_blocks 1
reserved_gdt_blocks 256
flex_bg_size 16
max_grow_blocks 538968064
reserved_blocks 819
groups 1 crc32c 0x8a137015
journal_blocks 1024
";
        assert_eq!(pinned_plan().geometry_pin(), expected);
    }

    #[test]
    fn the_policy_pin_holds_still_while_the_image_varies() {
        // The property the split exists for. A builder writing one image per board changes
        // the identity and the size every time; if either reached the policy pin, an
        // empty-diff comparison of two boards' contracts would be impossible.
        let base = pinned_options().policy_pin();
        for (what, mut options) in [
            ("uuid", pinned_options()),
            ("time", pinned_options()),
            ("hash_seed", pinned_options()),
            ("volume_name", pinned_options()),
        ] {
            match what {
                "uuid" => options.uuid = [0x99; 16],
                "time" => options.time = Timestamp::from_secs(1_800_000_123),
                "hash_seed" => options.hash_seed = [0x44; 16],
                _ => options.volume_name = *b"board-two\0\0\0\0\0\0\0",
            }
            assert_eq!(base, options.policy_pin(), "{what} reached the policy pin");
            assert_ne!(
                pinned_options().identity_pin(),
                options.identity_pin(),
                "{what} did not reach the identity pin"
            );
        }
        // And the size, which is not an option at all: two filesystems built to one
        // contract at different sizes pin the same policy and different geometry.
        let small = FormatPlan::new(TreeBuilder::new(), 64 * MIB, pinned_options()).expect("plan");
        let large = FormatPlan::new(TreeBuilder::new(), 512 * MIB, pinned_options()).expect("plan");
        assert_eq!(base, pinned_options().policy_pin());
        assert_ne!(
            small.geometry_pin(),
            large.geometry_pin(),
            "two sizes pin the same geometry"
        );
    }

    #[test]
    fn every_option_that_moves_bytes_moves_one_of_the_two_pins() {
        // Each case changes exactly one input. A knob absent from *both* documents would
        // produce identical pins for a different image, which is the failure the pins exist
        // to prevent -- and `errors` is the field that reaches neither the feature words
        // nor the geometry, so nothing else would record it.
        /// One knob's name, whether it belongs to the policy, and the change that moves it.
        type Case = (&'static str, bool, Box<dyn Fn(&mut FormatOptions)>);
        let cases: Vec<Case> = vec![
            (
                "uuid",
                false,
                Box::new(|o: &mut FormatOptions| o.uuid = [0x22; 16]),
            ),
            (
                "time",
                false,
                Box::new(|o: &mut FormatOptions| o.time = Timestamp::from_secs(1_700_000_001)),
            ),
            (
                "hash_seed",
                false,
                Box::new(|o: &mut FormatOptions| o.hash_seed = [0x33; 16]),
            ),
            (
                "volume_name",
                false,
                Box::new(|o: &mut FormatOptions| o.volume_name = *b"rootfs\0\0\0\0\0\0\0\0\0\0"),
            ),
            (
                "fixed_time",
                // Both: whether a build clamps is policy, the time it clamps to is identity.
                true,
                Box::new(|o: &mut FormatOptions| {
                    o.fixed_time = Some(Timestamp::from_secs(1_600_000_000));
                }),
            ),
            (
                "hash_version",
                true,
                Box::new(|o: &mut FormatOptions| o.hash_version = HashVersion::Tea),
            ),
            (
                "hash_signedness",
                true,
                Box::new(|o: &mut FormatOptions| o.hash_signedness = HashSignedness::Signed),
            ),
            (
                "grow",
                true,
                Box::new(|o: &mut FormatOptions| o.grow = GrowReservation::None),
            ),
            (
                "inodes",
                true,
                Box::new(|o: &mut FormatOptions| o.inodes = InodeCount::Count(2048)),
            ),
            (
                "reserved",
                true,
                Box::new(|o: &mut FormatOptions| {
                    o.reserved = ReservedRatio::from_hundredths_of_percent(1000).expect("10%");
                }),
            ),
            (
                "feature",
                true,
                Box::new(|o: &mut FormatOptions| o.feature = FeatureSet::EXT2),
            ),
            (
                "errors",
                true,
                Box::new(|o: &mut FormatOptions| o.errors = ErrorBehavior::Panic),
            ),
            (
                "journal",
                true,
                Box::new(|o: &mut FormatOptions| o.journal = JournalSize::Blocks(2048)),
            ),
        ];

        let base_policy = pinned_options().policy_pin();
        let base_identity = pinned_options().identity_pin();
        for (name, is_policy, change) in cases {
            let mut o = pinned_options();
            change(&mut o);
            let moved = if is_policy {
                base_policy != o.policy_pin()
            } else {
                base_identity != o.identity_pin()
            };
            let which = if is_policy { "policy" } else { "identity" };
            assert!(moved, "changing {name} left the {which} pin unchanged");
        }
    }

    #[test]
    fn a_moved_group_placement_moves_the_digest() {
        // The group table is a digest rather than a list, so this is what proves the
        // digest is load-bearing: two layouts whose scalar geometry agrees but whose
        // placements differ must not pin alike.
        let mut layout = pinned_plan().layout().clone();
        let before = groups_digest(&layout.groups);
        layout.groups[0].inode_table += 1;
        assert_ne!(
            before,
            groups_digest(&layout.groups),
            "a moved inode table changed no digest"
        );
    }

    #[test]
    fn the_profile_setter_seeds_the_matching_feature_set() {
        let base = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        assert_eq!(base.profile(Profile::Ext2).feature, FeatureSet::EXT2);
        assert_eq!(base.profile(Profile::Ext3).feature, FeatureSet::EXT3);
        assert_eq!(base.profile(Profile::Ext4).feature, FeatureSet::DEFAULT);
        // Sugar over the feature field only: no other option is disturbed.
        let seeded = base.profile(Profile::Ext3);
        assert_eq!(seeded.uuid, base.uuid);
        assert_eq!(seeded.grow, base.grow);
        assert_eq!(seeded.inodes, base.inodes);
    }

    #[test]
    fn a_volume_label_is_written_into_the_superblock_and_reads_back() {
        let mut o = opts();
        o.volume_name = *b"rootfs\0\0\0\0\0\0\0\0\0\0";
        let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");
        // `s_volume_name` sits at offset 0x78 in the 1024-byte superblock, which begins
        // 1024 bytes into the image.
        assert_eq!(
            &image.as_bytes()[1024 + 0x78..1024 + 0x78 + 16],
            b"rootfs\0\0\0\0\0\0\0\0\0\0"
        );
        // The reader hands the same label back, NUL-padding and all.
        let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        assert_eq!(
            reader.superblock().volume_name,
            *b"rootfs\0\0\0\0\0\0\0\0\0\0"
        );

        // An unlabelled format leaves the field all zero, matching mke2fs's default.
        let image = format(TreeBuilder::new(), 64 * MIB, opts()).expect("format");
        assert_eq!(image.as_bytes()[1024 + 0x78..1024 + 0x78 + 16], [0u8; 16]);
    }

    #[test]
    fn the_error_behavior_reaches_the_superblock_and_reads_back() {
        // `s_errors` sits at offset 0x3c in the 1024-byte superblock. Each policy maps to
        // the kernel's value (1 continue, 2 remount-ro, 3 panic); the default is continue.
        let read_errors = |image: &Image| {
            u16::from_le_bytes(
                image.as_bytes()[1024 + 0x3c..1024 + 0x3c + 2]
                    .try_into()
                    .expect("two bytes"),
            )
        };
        assert_eq!(
            read_errors(&format(TreeBuilder::new(), 64 * MIB, opts()).expect("format")),
            1,
            "the default continues, matching the kernel"
        );
        for (policy, expected) in [
            (ErrorBehavior::Continue, 1u16),
            (ErrorBehavior::RemountReadOnly, 2),
            (ErrorBehavior::Panic, 3),
        ] {
            let mut o = opts();
            o.errors = policy;
            let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");
            assert_eq!(
                read_errors(&image),
                expected,
                "{policy:?} in the raw superblock"
            );
            // The reader hands the same value back, and it survives the superblock
            // checksum the metadata_csum profile computes over the field.
            let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
            assert_eq!(reader.superblock().errors, expected, "{policy:?} read back");
        }
    }

    #[test]
    fn the_orphan_file_size_follows_the_block_count_between_its_floor_and_ceiling() {
        // The curve mke2fs 1.47 realizes, in filesystem blocks: one orphan block per 4096
        // of them, no fewer than 32 and no more than 512. It counts blocks, not bytes, so
        // these hold at any block size.
        assert_eq!(orphan_file_blocks(2048), 32, "below the floor");
        assert_eq!(orphan_file_blocks(131_072), 32, "exactly at the floor");
        assert_eq!(orphan_file_blocks(262_144), 64);
        assert_eq!(orphan_file_blocks(524_288), 128);
        assert_eq!(orphan_file_blocks(2_097_152), 512, "exactly at the ceiling");
        assert_eq!(orphan_file_blocks(67_108_864), 512, "above the ceiling");
    }

    #[test]
    fn an_entry_on_the_orphan_files_inode_is_refused() {
        // `format` derives the first entry's inode from the feature set, so this cannot
        // arise through the public API — it is reached here by building the model with a
        // first user inode that ignores the orphan file, which is what a feature added
        // later that claims an inode and forgets to move the entries up would do. The
        // image must be refused: writing it would leave `/f`'s directory entry naming the
        // orphan file.
        let options = opts();
        let feature = options.feature;
        assert!(feature.has_orphan_file());
        let layout = plan_layout(&options.plan_request(64 * MIB)).expect("layout");
        let model = build_model(
            TreeBuilder::new().file(
                b"/f".to_vec(),
                b"x".to_vec(),
                crate::source::Metadata::new(0o644, options.time),
            ),
            // The collision a stale derivation produces: entries starting at the inode
            // the orphan file takes.
            ModelConfig::new(feature, ORPHAN_INO, options.time),
        )
        .expect("model");
        assert!(model.inodes.contains_key(&ORPHAN_INO), "the entry took it");

        let journal = journal_size(&layout, &options).expect("the journal size is realizable");
        // The refusal happens while placing, so no destination is needed to provoke it.
        let mut writer = Writer::new(&layout, &feature, options, journal, Discard)
            .expect("an allocator for a layout this size");
        let err = writer
            .materialize(&model)
            .expect_err("the collision is refused");
        assert!(
            matches!(err, FormatError::OrphanInodeInUse { inode } if inode == ORPHAN_INO),
            "expected OrphanInodeInUse, got {err:?}"
        );
    }

    #[test]
    fn the_orphan_file_takes_the_inode_below_the_first_entry() {
        // With the orphan file the source's entries start at 13; without it, at 12. The
        // number is not a detail: it is what a foreign tool reads out of
        // `s_orphan_file_inum`, and what the first user inode has to make room for.
        let with = FeatureSet::default();
        assert!(with.has_orphan_file());
        assert_eq!(first_user_inode(&with), ORPHAN_INO + 1);

        let mut without = FeatureSet::default();
        without.compat = crate::feature::Compat::from_bits(
            without.compat.bits()
                & !(crate::feature::Compat::HAS_JOURNAL.bits()
                    | crate::feature::Compat::ORPHAN_FILE.bits()),
        );
        assert_eq!(first_user_inode(&without), FIRST_USER_INO);
    }

    #[test]
    fn the_block_mapped_family_round_trips_direct_and_indirect_files() {
        // The ext2/ext3 classic block map — twelve direct pointers, then single- and
        // double-indirect trees — must read back exactly what it wrote. Files sized to
        // land in each region prove the writer and the reader agree on the map's shape and
        // that its just-in-time metadata blocks are placed where the reader looks for them.
        use crate::source::Metadata;
        let time = Timestamp::from_secs(1_700_000_000);
        let bs = 4096usize;
        // Direct only (a partial final block); across the single indirect boundary; and
        // across the single into the double indirect (12 + 1024 + 4 blocks).
        let direct = vec![0xa1u8; 5 * bs - 17];
        let single = vec![0xb2u8; 20 * bs];
        let mut double = vec![0u8; 1040 * bs];
        for (i, byte) in double.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        for profile in [Profile::Ext2, Profile::Ext3] {
            let src = TreeBuilder::new()
                .file(
                    b"/direct".to_vec(),
                    direct.clone(),
                    Metadata::new(0o644, time),
                )
                .file(
                    b"/single".to_vec(),
                    single.clone(),
                    Metadata::new(0o644, time),
                )
                .file(
                    b"/double".to_vec(),
                    double.clone(),
                    Metadata::new(0o644, time),
                );
            let mut o = FormatOptions::new([7u8; 16], time, [0u8; 16]).profile(profile);
            o.grow = GrowReservation::UpTo(32 * 1024 * MIB);
            let image = format(src, 64 * MIB, o).expect("format block-mapped");
            let mut r = Reader::open(std::io::Cursor::new(image.into_bytes())).expect("open");
            assert_eq!(
                r.profile(),
                profile,
                "reads back as the family it was written for"
            );
            for (name, want) in [
                (b"/direct".as_slice(), &direct),
                (b"/single".as_slice(), &single),
                (b"/double".as_slice(), &double),
            ] {
                let (_, inode) = r.lookup(name).expect("lookup");
                assert!(
                    !inode.flags.contains(crate::ondisk::InodeFlags::EXTENTS),
                    "{profile} {}: block-mapped inode carries no EXTENTS flag",
                    String::from_utf8_lossy(name)
                );
                let got = r.read_data(&inode).expect("read");
                assert_eq!(got, *want, "{profile} {}", String::from_utf8_lossy(name));
            }
        }
    }

    #[test]
    fn a_checksum_off_profile_writes_zero_group_flags() {
        // bg_flags is meaningful only under metadata_csum / uninit_bg. With the checksum
        // off, every descriptor's flags are zero, as mke2fs writes them — not
        // BG_INODE_ZEROED carried with no feature to back it.
        let mut feature = FeatureSet::default();
        feature.ro_compat = crate::feature::RoCompat::from_bits(
            feature.ro_compat.bits() & !crate::feature::RoCompat::METADATA_CSUM.bits(),
        );
        // metadata_csum_seed cannot stand without metadata_csum, so it is cleared too.
        feature.incompat = crate::feature::Incompat::from_bits(
            feature.incompat.bits() & !crate::feature::Incompat::CSUM_SEED.bits(),
        );
        assert!(!feature.has_metadata_csum());
        feature.validate().expect("a checksum-off profile is valid");

        let mut o = opts();
        o.feature = feature;
        let image = format(TreeBuilder::new(), 64 * MIB, o).expect("format");

        let group_count = image.layout().group_count;
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        for g in 0..group_count {
            let desc = r.group_descriptor(g).expect("group descriptor");
            assert_eq!(
                desc.flags, 0,
                "group {g}: bg_flags must be zero without metadata_csum"
            );
        }
    }

    #[test]
    fn the_resize_map_refuses_a_block_past_thirty_two_bits() {
        // The map stores 32-bit block numbers. Converting a block past that must be a
        // typed error, not a truncated pointer at the wrong block — the geometry never
        // reserves such a block, so this guards a future planner change, not today's.
        assert_eq!(map_block(0).unwrap(), 0);
        assert_eq!(map_block(u64::from(u32::MAX)).unwrap(), u32::MAX);
        let err = map_block(u64::from(u32::MAX) + 1).unwrap_err();
        assert!(matches!(
            err,
            FormatError::ResizeMapNeeds32BitBlocks { block } if block == u64::from(u32::MAX) + 1
        ));
    }

    #[test]
    fn a_format_time_past_the_superblock_range_is_rejected() {
        // The superblock's time fields are 32 bits; a format clock past 2106 would
        // truncate to a different instant, so it is refused rather than written wrong.
        let mut o = opts();
        o.time = Timestamp::from_secs(i64::from(u32::MAX) + 1);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected FormatTimeOutOfRange");
        };
        assert!(
            matches!(err, FormatError::FormatTimeOutOfRange { secs } if secs == i64::from(u32::MAX) + 1),
            "expected FormatTimeOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn the_default_max_reservation_formats_and_reads_back() {
        // Every other test overrides `grow`, so the shipped default — Max — is
        // exercised only here: a plain `FormatOptions::new` must format, fill the
        // resize inode's map without running off its block, and read back clean.
        let plain = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16]);
        assert_eq!(plain.grow, GrowReservation::Max);
        let image = format(TreeBuilder::new(), 64 * MIB, plain).expect("default format");
        // 64 MiB is below the knee at which the whole map is affordable, so the
        // reservation is the share of the filesystem `Max` will spend: 16384 blocks / 64.
        assert_eq!(
            image.layout().reserved_gdt_blocks,
            256,
            "Max reserves the share of a 64 MiB filesystem it can spare"
        );
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        // The resize inode (7) maps its reservation through the classic block map, so
        // it carries no extents flag and a nonzero double-indirect pointer.
        let resize = r.inode(7).expect("resize inode");
        let dind = u32::from_le_bytes([
            resize.block[52],
            resize.block[53],
            resize.block[54],
            resize.block[55],
        ]);
        assert_ne!(
            dind, 0,
            "the reservation hangs off the double-indirect slot"
        );
    }

    #[test]
    fn streaming_a_format_writes_the_same_bytes_as_collecting_one() {
        // The two entry points share every decision; only the destination differs, so
        // a streamed image must be byte-identical to the collected one.
        use crate::source::Metadata;

        let time = Timestamp::from_secs(1_700_000_000);
        let source = || {
            TreeBuilder::new()
                .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
                .file(
                    b"/etc/hostname".to_vec(),
                    b"ferrosys\n".to_vec(),
                    Metadata::new(0o644, time),
                )
                .symlink(
                    b"/etc/mtab".to_vec(),
                    b"/proc/self/mounts".to_vec(),
                    Metadata::new(0o777, time),
                )
        };

        let collected = format(source(), 64 * MIB, opts()).expect("format");

        let mut streamed = std::io::Cursor::new(Vec::new());
        let layout = format_to(source(), 64 * MIB, opts(), &mut streamed).expect("format_to");
        let streamed = streamed.into_inner();

        assert_eq!(layout, *collected.layout());
        assert_eq!(
            streamed.len(),
            collected.as_bytes().len(),
            "a streamed image is extended to the filesystem's full size"
        );
        assert_eq!(streamed, collected.as_bytes(), "the images differ");
    }

    #[test]
    fn a_streamed_image_leaves_the_blocks_it_never_writes_alone() {
        // Streaming touches only the blocks the filesystem uses, which is what keeps
        // a file destination sparse. The rest read back as the zeros they were.
        let mut sink = std::io::Cursor::new(Vec::new());
        let layout = format_to(TreeBuilder::new(), 64 * MIB, opts(), &mut sink).expect("format_to");
        let bytes = sink.into_inner();
        assert_eq!(
            bytes.len() as u64,
            layout.total_blocks * u64::from(layout.block_size)
        );
        // The final block of a fresh 64 MiB filesystem holds nothing.
        let last = bytes.len() - layout.block_size as usize;
        assert!(bytes[last..].iter().all(|&b| b == 0));
    }

    #[test]
    fn explicit_journal_size_is_honored() {
        let mut o = opts();
        o.journal = JournalSize::Blocks(2048);
        let image = format(TreeBuilder::new(), 512 * MIB, o).expect("format");
        let mut r = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
        let jsb = r.journal_superblock().unwrap().expect("journal");
        assert_eq!(jsb.max_len, 2048);
        assert_eq!(r.inode(8).unwrap().size, 2048 * 4096);
    }

    #[test]
    fn the_classic_block_map_reaches_what_its_pointer_words_hold() {
        // Twelve direct pointers plus one, two, and three levels of `block_size / 4`
        // pointers each. These are the whole reach of an ext2/ext3 file at each block size
        // the format allows, and the bound a file past them is refused against.
        assert_eq!(classic_map_reach(1024), 16_843_020); // 16.06 GiB
        assert_eq!(classic_map_reach(2048), 134_480_396); // 256.5 GiB
        assert_eq!(classic_map_reach(4096), 1_074_791_436); // 4.004 TiB
    }

    #[test]
    fn a_block_count_the_feature_words_cannot_record_is_refused_rather_than_wrapped() {
        // Without `huge_file` an inode's block count is `i_blocks_lo` alone — the two bytes
        // above it are ext2's `l_i_frag` and `l_i_fsize`, not a high half. So the field
        // stops at two tebibytes, while a classic map at a 4096-byte block reaches 4.004 —
        // and `FeatureSet::validate` refuses adding `huge_file` to a non-extent set, so on
        // ext2 and ext3 the map genuinely outruns the field.
        //
        // Written anyway, it serializes as a wrapped low half beside a high half the feature
        // words deny: no panic, no error, and an image every checker faults. The journal is
        // the structure an explicit size pushes there without a filesystem large enough to
        // hold it existing.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.grow = GrowReservation::None;
        assert!(
            !o.feature.has_huge_file(),
            "the block-mapped profiles cannot carry huge_file"
        );
        // Two tebibytes at a 4096-byte block: 536,870,912 blocks of eight sectors each is
        // exactly `u32::MAX + 1`, so this is the first count the field cannot hold.
        o.journal = JournalSize::Blocks(536_870_912);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected BlockCountWithoutHugeFile");
        };
        assert!(
            matches!(
                err,
                FormatError::BlockCountWithoutHugeFile {
                    what: "journal",
                    limit,
                    ..
                } if limit == u64::from(u32::MAX)
            ),
            "expected BlockCountWithoutHugeFile, got {err:?}"
        );

        // And the bound is the field's, not a refusal of every large log: one block below it
        // gets as far as running out of filesystem.
        o.journal = JournalSize::Blocks(536_870_911);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected the log not to fit in 64 MiB");
        };
        assert!(
            !matches!(err, FormatError::BlockCountWithoutHugeFile { .. }),
            "the count one below the field's reach is a count it records: {err:?}"
        );
    }

    #[test]
    fn a_file_past_the_classic_block_maps_reach_is_refused_rather_than_mapped_short() {
        // The block-mapped twin of the extent tree's own bound. A map that ran out of words
        // would leave the tail of a file neither mapped nor written while its size claimed
        // the whole length, so the count is checked before a block is allocated — which is
        // what lets this fire without a filesystem large enough to hold the file existing.
        //
        // The journal is the structure an explicit size can push past the bound: a source
        // entry that large would have to be read, and the resize inode is bounded far below
        // it. A 1024-byte block puts the reach at 16,843,020 blocks.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.feature.block_size = 1024;
        o.grow = GrowReservation::None;
        o.journal = JournalSize::Blocks(16_843_021);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected FileTooLargeForBlockMap");
        };
        assert!(
            matches!(
                err,
                FormatError::FileTooLargeForBlockMap {
                    blocks: 16_843_021,
                    limit: 16_843_020,
                    block_size: 1024,
                }
            ),
            "expected FileTooLargeForBlockMap, got {err:?}"
        );

        // One block below the reach is a map the words hold, so what refuses the log above
        // is the bound and not the size alone: it gets as far as running out of filesystem.
        o.journal = JournalSize::Blocks(16_843_020);
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected the log not to fit in 64 MiB");
        };
        assert!(
            matches!(err, FormatError::JournalDoesNotFit { .. }),
            "expected JournalDoesNotFit, got {err:?}"
        );
    }

    #[test]
    fn a_journal_past_the_large_file_bound_is_rejected_without_the_feature() {
        // The journal is a regular file, so a log an explicit size pushed to 2 GiB needs
        // `large_file` like any other. A 1024-byte block keeps the resize inode under the
        // bound, so this profile is otherwise valid without the feature — which is what
        // leaves the journal as the one structure that reaches it. The check runs before
        // any journal block is allocated, so no filesystem large enough to hold the log
        // has to exist for it to fire.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.feature.block_size = 1024;
        o.feature = o
            .feature
            .with_feature("large_file", false)
            .expect("a known name");
        o.grow = GrowReservation::None;
        o.journal = JournalSize::Blocks(2 * 1024 * 1024); // 2 GiB at a 1024-byte block
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("expected LargeFileWithoutFeature");
        };
        assert!(
            matches!(
                err,
                FormatError::LargeFileWithoutFeature {
                    what: "journal",
                    size
                } if size == 2 * 1024 * MIB
            ),
            "expected LargeFileWithoutFeature for the journal, got {err:?}"
        );

        // The same journal is written where the feature permits it — the rule is about
        // the pairing, not about the size alone.
        let mut o = FormatOptions::new([1u8; 16], Timestamp::from_secs(1_700_000_000), [0u8; 16])
            .profile(Profile::Ext3);
        o.feature.block_size = 1024;
        o.grow = GrowReservation::None;
        o.journal = JournalSize::Blocks(2 * 1024 * 1024);
        assert!(o.feature.has_large_file());
        let Err(err) = format(TreeBuilder::new(), 64 * MIB, o) else {
            panic!("a 2 GiB log does not fit a 64 MiB image");
        };
        assert!(
            matches!(err, FormatError::JournalDoesNotFit { .. }),
            "the feature check must give way to the space the journal needs, got {err:?}"
        );
    }

    #[test]
    fn journal_below_the_minimum_is_rejected() {
        let mut o = opts();
        o.journal = JournalSize::Blocks(512);
        assert!(matches!(
            format(TreeBuilder::new(), 512 * MIB, o),
            Err(FormatError::JournalTooSmall {
                requested: 512,
                minimum: 1024
            })
        ));
    }

    #[test]
    fn auto_journal_maps_as_a_single_extent() {
        // A contiguous run holds any heuristic journal size, so the map stays inline.
        // Streamed to a file rather than held as bytes: the two gigabytes that put
        // the heuristic in its top tier are almost entirely unwritten, and an
        // in-memory image would cost that much resident memory for zeros.
        let file = tempfile::tempfile().expect("temp file");
        format_to(TreeBuilder::new(), 2048 * MIB, opts(), &file).expect("format");
        let mut r = Reader::open(file).unwrap();
        let inode = r.inode(8).unwrap();
        // A single leaf: the inline extent header reports one entry.
        let entries = u16::from_le_bytes([inode.block[2], inode.block[3]]);
        assert_eq!(entries, 1, "journal should map as one contiguous extent");
    }
}
