//! The materializer: turn a planned [`BtrfsLayout`] into the bytes of a filesystem.
//!
//! Everything written here was decided by the pure layers beneath it. [`plan_layout`] said which
//! chunks exist, where each sits in both address spaces, and how many tree blocks the whole
//! filesystem may spend; this module builds the trees, hands every block an address out of the
//! chunks planned for it, checksums each one, and writes the superblock copies last.
//!
//! Bytes go to any seekable writer. [`format()`] collects them into an in-memory [`Image`];
//! [`format_to`] streams them straight out, touching only the blocks it writes, so a volume far
//! larger than memory becomes a file that stays sparse. Nothing is ever read back from the
//! destination.
//!
//! # One transaction, and what follows from it
//!
//! A filesystem written here is at [`GENERATION`] and stops. There is no history: nothing is
//! ever rewritten, no block is ever freed, and every tree is built from records that are all
//! known before the first one is placed. That is what makes the whole of it decidable in
//! advance, and it is the difference between building a filesystem and maintaining one.
//!
//! It shows in the result, in two ways worth naming. Every block group is filled from its start
//! and left with **one** run of free space, where a filesystem that has had blocks freed has
//! several. And each tree's leaves are packed full in key order, where a tree grown by
//! inserting one record at a time and splitting a full block down the middle ends up with
//! leaves half full.
//!
//! # The one circularity, and how it is closed
//!
//! The extent tree records every allocated tree block, **its own included**, so how large it is
//! depends on how large it is. The [`Reservation`](super::Reservation) answers that as a bound,
//! with a closed form and no loop, which is what a planner owes a caller before anything is
//! written. A writer needs the exact number instead, and finds it by laying the filesystem out,
//! seeing how many blocks the extent tree then needs, and laying it out again if that is not the
//! number it assumed.
//! The iteration only ever grows and is bounded above by the reservation. Every filesystem this
//! writes today settles on the **first** round, an empty one's extent tree being the single leaf
//! the first round assumes — which is a fact about what is written rather than about the
//! arithmetic, and is why the loop is here and bounded rather than absent.
//!
//! The reservation is then what the finished filesystem is held to:
//! [`Reservation::account`](super::Reservation::account) is called with what was spent from each
//! of its two pools, and a bound that turned out too small is a typed failure rather than an
//! image with a tree running past its own block group.
//!
//! # Reproducibility
//!
//! Two formats of the same parameters produce the same bytes. Every value a formatter would
//! conventionally take from the clock or from a random source is a [`FormatOptions`] input:
//! four identifiers and one instant. The fifth identifier a filesystem may carry — the id every
//! tree block is stamped with, where it is to differ from the one a person sees — is an input
//! too, and defaults to being the same value rather than a second one.

use std::io::{Cursor, Seek, Write};

use crate::Timestamp;
use crate::fidelity::FidelityReport;
use crate::io::ByteSink;
use crate::source::Source;

use super::MappedChunk;
use super::btree::levels_above;
use super::geometry::{
    BtrfsLayout, CSUM_BYTES_PER_SECTOR, GeometryError, MAX_CSUM_RECORD, PlanRequest, Pool,
    RESERVED_HEAD, ReservationExceeded, STRIPE_LEN, Slack, block_sizes, plan_layout,
};
use super::model::{
    BtrfsModel, DirEntry, EntryTarget, MAX_EXTENT_BYTES, ModelError, ModelObject, ModelSubvolume,
    ObjectKind, SubvolumeRequest, build_model,
};
use super::ondisk::{
    BACKREF_REV_MIXED, BACKREF_REV_SHIFT, BlockGroupFlags, BlockGroupItem, CSUM_FIELD_LEN,
    ChecksumType, Chunk, CompatFlags, CompatRoFlags, DevExtent, DevItem, DevStats, DirEntryType,
    DirItem, DiskKey, ExtentDataRef, ExtentFlags, ExtentItem, ExtentKind, FileExtentItem,
    FreeSpaceInfo, HEADER_FLAG_WRITTEN, Header, IncompatFlags, InlineRef, InodeExtref, InodeFlags,
    InodeItem, InodeRef, Item, ItemType, KeyPtr, LABEL_SIZE, MAGIC, MIRRORS, RootBackup, RootFlags,
    RootItem, RootRef, SUPER_INFO_SIZE, SYS_CHUNK_ARRAY_SIZE, Stripe, SuperBlock, SuperFlags,
    crc32c_over, extref_hash, name_hash, objectid, seal, uuid_key,
};

/// The transaction every filesystem this crate writes is at.
///
/// One. A filesystem is built whole and committed once, so there is no earlier state for a
/// larger number to be counting from. The format's own tooling arrives at eight instead, having
/// committed several transactions on the way, and the format requires neither — a generation is
/// an ordering, and a filesystem with one state has one thing to order.
pub const GENERATION: u64 = 1;

/// The device number the one device of a single-device filesystem carries.
pub const DEVICE_ID: u64 = 1;

/// The name the root tree's directory knows the top-level subvolume by.
///
/// Every btrfs has it, and it is the name a mount resolves through when told to mount a
/// subvolume by name rather than by id.
const SUBVOLUME_NAME: &[u8] = b"default";

/// The name a subvolume's root directory has for its parent, which is itself.
const PARENT_NAME: &[u8] = b"..";

/// The mode a root directory is created with: a directory, traversable by everyone and writable
/// by its owner.
const DIRECTORY_MODE: u32 = 0o040_755;

/// What the superblock's free-space-cache generation holds where there is no such cache.
///
/// A filesystem carrying a free-space *tree* has no use for the older cache, and the two values
/// the pinned baseline writes are measurements rather than guesses: zero where the tree is
/// present, and this where it is not — which a driver reads as "there is no cache to trust"
/// rather than as a transaction number.
const NO_FREE_SPACE_CACHE: u64 = u64::MAX;

/// How many times the layout may be re-derived before the writer gives up.
///
/// Only the extent tree's size is in question and it only ever grows towards the least size that
/// records itself, so the rounds converge. Every filesystem this writes today settles on the
/// first of them — an empty filesystem's extent tree is one leaf, which is what the first round
/// assumes — and the bound is here for the case that stops being true, so that a defect in the
/// arithmetic is a typed failure rather than a program that does not finish.
const LAYOUT_ROUNDS: usize = 8;

/// A name for the filesystem, as the superblock records it.
///
/// Bytes rather than text, because the field records no encoding: whatever a caller supplies is
/// what every reader of the image sees, and this crate's own reader hands the same bytes back.
/// [`new`](Self::new) is there for the ordinary case of a name that is already UTF-8.
///
/// The field is [`LABEL_SIZE`] bytes and a label may occupy all but one of them
/// ([`MAX_BYTES`](Self::MAX_BYTES)), because the rest is NUL padding and a reader stops at the
/// first NUL. That is also why a label may not contain one: it would be a name that comes back
/// shorter than it went in.
///
/// ```
/// # use ferrosys::btrfs::VolumeLabel;
/// assert_eq!(VolumeLabel::new("root")?.as_bytes(), b"root");
/// assert!(VolumeLabel::UNNAMED.as_bytes().is_empty());
///
/// // The terminator has to fit, so the field's width is one more than a label's.
/// assert!(VolumeLabel::from_bytes(&[b'a'; VolumeLabel::MAX_BYTES]).is_ok());
/// assert!(VolumeLabel::from_bytes(&[b'a'; VolumeLabel::MAX_BYTES + 1]).is_err());
/// # Ok::<(), ferrosys::btrfs::LabelError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VolumeLabel([u8; LABEL_SIZE]);

impl VolumeLabel {
    /// The most bytes a label may occupy, which is the field's width less its terminator.
    pub const MAX_BYTES: usize = LABEL_SIZE - 1;

    /// The label a filesystem with no name carries: the field, filled with padding.
    pub const UNNAMED: Self = Self([0; LABEL_SIZE]);

    /// The label `name` states.
    ///
    /// # Errors
    ///
    /// As [`from_bytes`](Self::from_bytes).
    pub fn new(name: &str) -> Result<Self, LabelError> {
        Self::from_bytes(name.as_bytes())
    }

    /// The label `name`'s bytes state, for a caller whose name is not UTF-8.
    ///
    /// # Errors
    ///
    /// [`LabelError::TooLong`] beyond [`MAX_BYTES`](Self::MAX_BYTES), and
    /// [`LabelError::NulByte`] for a name containing a NUL, which is what the padding is.
    pub fn from_bytes(name: &[u8]) -> Result<Self, LabelError> {
        if name.len() > Self::MAX_BYTES {
            return Err(LabelError::TooLong {
                bytes: name.len(),
                limit: Self::MAX_BYTES,
            });
        }
        if let Some(at) = name.iter().position(|&byte| byte == 0) {
            return Err(LabelError::NulByte { at });
        }
        let mut field = [0u8; LABEL_SIZE];
        field[..name.len()].copy_from_slice(name);
        Ok(Self(field))
    }

    /// The label's bytes, without the padding that fills the rest of the field.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let end = self
            .0
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(LABEL_SIZE);
        &self.0[..end]
    }

    /// The whole field, as the superblock stores it.
    const fn field(&self) -> [u8; LABEL_SIZE] {
        self.0
    }
}

impl Default for VolumeLabel {
    fn default() -> Self {
        Self::UNNAMED
    }
}

impl core::fmt::Debug for VolumeLabel {
    /// The label as text where its bytes are UTF-8, so a failure quotes a name rather than two
    /// hundred and fifty-six numbers, and as bytes where they are not.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match core::str::from_utf8(self.as_bytes()) {
            Ok(text) => write!(f, "VolumeLabel({text:?})"),
            Err(_) => write!(f, "VolumeLabel({:?})", self.as_bytes()),
        }
    }
}

/// A name a btrfs filesystem cannot carry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LabelError {
    /// The name is longer than the field holds with room for its terminator.
    #[error("a label of {bytes} bytes exceeds the {limit} the superblock holds")]
    #[non_exhaustive]
    TooLong {
        /// Bytes the name needs.
        bytes: usize,
        /// Bytes the field holds.
        limit: usize,
    },
    /// The name contains a NUL, which is what the unused tail of the field is filled with.
    #[error("a label may not contain a NUL byte, and this one does at byte {at}")]
    #[non_exhaustive]
    NulByte {
        /// Which byte of the name it is.
        at: usize,
    },
}

/// What a caller states that a filesystem's bytes cannot be derived from.
///
/// Build one with [`new`](Self::new), which takes the filesystem's own id and the instant its
/// root directory is stamped with, then set the fields a format departs from the default on.
///
/// Every value a formatter would conventionally take from the clock or from a random source is
/// here, which is what makes two formats of the same parameters produce the same bytes. There
/// are five: the filesystem's id, the chunk tree's own id that every tree block repeats, the
/// device's id, the top-level subvolume's id, and one instant.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The filesystem's id, as a person sees it and as every device of it records.
    pub fsid: [u8; 16],
    /// The id every tree block is stamped with, where it is to differ from
    /// [`fsid`](Self::fsid).
    ///
    /// The field exists so that changing the id a person sees does not mean rewriting every
    /// block. Defaults to [`None`], which is a filesystem whose two ids are one and which
    /// therefore does not carry the feature bit — the state every filesystem is in until
    /// someone changes its id. A value equal to [`fsid`](Self::fsid) describes that same state
    /// and is written as it: without the bit, with the superblock field zero.
    pub metadata_uuid: Option<[u8; 16]>,
    /// The chunk tree's own id, repeated in every tree block and every device extent so that a
    /// block belonging to another filesystem says so.
    pub chunk_tree_uuid: [u8; 16],
    /// The device's own id, which the device record and every chunk copy name.
    pub device_uuid: [u8; 16],
    /// The top-level subvolume's own id, which its root item records and the UUID tree is
    /// keyed by.
    ///
    /// All zeros — the default — records that none was set: the root item carries the zeros
    /// and the UUID tree carries no entry for it. A nonzero value must differ from every
    /// [`SubvolumeRequest::uuid`], since the UUID tree keys them alike.
    pub subvolume_uuid: [u8; 16],
    /// The instant the root directory and the top-level subvolume are stamped with.
    ///
    /// Every other time in an empty filesystem is zero, which is what the format's own tooling
    /// writes: a tree that is not a subvolume has no creation to record.
    pub time: Timestamp,
    /// The name the filesystem is known by, or [`VolumeLabel::UNNAMED`] for one with none.
    ///
    /// It is recorded in the superblock and nowhere else, so every mirror of it carries the same
    /// name and no tree has to be rewritten to change it.
    pub label: VolumeLabel,
    /// What the geometry must be. Defaults to a request at every default;
    /// [`PlanRequest::volume_bytes`] is replaced by the size the format is asked for and
    /// [`PlanRequest::content`] by what the source turns out to hold, so neither is a number
    /// stated twice that could disagree with itself.
    pub plan: PlanRequest,
    /// Which of the source's directories become subvolumes of their own.
    ///
    /// Empty for a filesystem with the one subvolume every btrfs has. Where a path names a
    /// directory the source does not declare, the format is refused rather than the request
    /// dropped.
    pub subvolumes: Vec<SubvolumeRequest>,
    /// Which subvolume a mount resolves to when it is told none.
    ///
    /// The path of one of [`subvolumes`](Self::subvolumes), or [`None`] for the top-level one —
    /// which is where every btrfs starts and what the format's own tooling leaves it at.
    pub default_subvolume: Option<Vec<u8>>,
}

impl FormatOptions {
    /// Options for a filesystem identified by `fsid` and stamped `time`, with every other
    /// identifier zero and every geometry knob at its default.
    ///
    /// Zero is a legitimate id and an obvious one: a caller that has not decided what to put
    /// here gets a filesystem whose ids say so, rather than one whose ids came from somewhere
    /// this crate does not control.
    #[must_use]
    pub const fn new(fsid: [u8; 16], time: Timestamp) -> Self {
        Self {
            fsid,
            metadata_uuid: None,
            chunk_tree_uuid: [0; 16],
            device_uuid: [0; 16],
            subvolume_uuid: [0; 16],
            time,
            label: VolumeLabel::UNNAMED,
            // Replaced with the size the format is asked for, so the placeholder here is never
            // the size anything is planned against.
            plan: PlanRequest::new(0),
            subvolumes: Vec::new(),
            default_subvolume: None,
        }
    }

    /// These options with the filesystem's name replaced.
    #[must_use]
    pub fn label(mut self, label: VolumeLabel) -> Self {
        self.label = label;
        self
    }

    /// These options with the metadata id replaced.
    #[must_use]
    pub fn metadata_uuid(mut self, uuid: Option<[u8; 16]>) -> Self {
        self.metadata_uuid = uuid;
        self
    }

    /// These options with the chunk tree's id replaced.
    #[must_use]
    pub fn chunk_tree_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.chunk_tree_uuid = uuid;
        self
    }

    /// These options with the device's id replaced.
    #[must_use]
    pub fn device_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.device_uuid = uuid;
        self
    }

    /// These options with the top-level subvolume's id replaced.
    #[must_use]
    pub fn subvolume_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.subvolume_uuid = uuid;
        self
    }

    /// These options with the geometry request replaced.
    ///
    /// The request's [`volume_bytes`](PlanRequest::volume_bytes) and
    /// [`content`](PlanRequest::content) are ignored: the size a format is asked for is the size
    /// it plans against, and what the source holds is what it is planned to hold.
    #[must_use]
    pub fn plan(mut self, plan: PlanRequest) -> Self {
        self.plan = plan;
        self
    }

    /// These options with one more subvolume asked for.
    #[must_use]
    pub fn subvolume(mut self, request: SubvolumeRequest) -> Self {
        self.subvolumes.push(request);
        self
    }

    /// These options with the subvolume a mount resolves to by default named by path.
    #[must_use]
    pub fn default_subvolume(mut self, path: impl Into<Vec<u8>>) -> Self {
        self.default_subvolume = Some(path.into());
        self
    }

    /// The id every tree block of the filesystem these options describe carries.
    fn metadata_id(&self) -> [u8; 16] {
        self.metadata_uuid.unwrap_or(self.fsid)
    }

    /// The metadata id the superblock records as distinct from the filesystem's, or [`None`].
    ///
    /// Normalized rather than transcribed: the feature bit this field turns on tells a reader
    /// the two ids differ, and the format's own tooling clears the bit where they are equal —
    /// so an equal id stated explicitly is written the way not stating one is, and no
    /// filesystem leaves here carrying the bit over two equal ids.
    fn distinct_metadata_uuid(&self) -> Option<[u8; 16]> {
        self.metadata_uuid.filter(|uuid| *uuid != self.fsid)
    }
}

/// A failure formatting a filesystem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// Writing to the destination failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The geometry cannot be realized.
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    /// The source names something this filesystem cannot hold.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// More tree blocks were spent than the planner reserved.
    ///
    /// Nothing a caller passes reaches this: the reservation is a bound over what the content
    /// they described can cost, so exceeding it is a defect in the bound. It is a failure
    /// rather than an assertion because the alternative is an image whose trees run past the
    /// block group holding them, which nothing about the finished bytes would show.
    #[error(transparent)]
    Reservation(#[from] ReservationExceeded),
    /// One record is larger than a whole tree block, so no leaf can hold it.
    #[error("a record of {bytes} bytes does not fit a leaf, which holds {capacity}")]
    #[non_exhaustive]
    RecordTooLarge {
        /// The record's data, in bytes.
        bytes: usize,
        /// The most one leaf of this filesystem holds.
        capacity: usize,
    },
    /// The layout did not settle.
    ///
    /// Unreachable on a filesystem this crate plans, and typed rather than silent for the same
    /// reason [`Reservation`](Self::Reservation) is: the alternative is a writer that does not
    /// finish.
    #[error("the layout did not settle in {LAYOUT_ROUNDS} rounds")]
    LayoutUnsettled,
    /// The data block groups did not hold the source's bytes.
    ///
    /// Nothing a caller passes reaches this: the planner sizes those block groups from the same
    /// count of bytes the writer then places in them, so the two cannot disagree. It is a
    /// failure rather than an assertion for the reason [`Reservation`](Self::Reservation) is —
    /// the alternative is a file whose extents run past the block group holding them.
    #[error("the data block groups were planned for {planned} bytes and did not hold them")]
    #[non_exhaustive]
    DataExhausted {
        /// Bytes of data the planner was told to make room for.
        planned: u64,
    },
    /// The image is larger than this machine can hold in memory.
    ///
    /// Reached only by [`format()`], which collects the whole image. [`format_to`] streams and
    /// has no such limit.
    #[error("an image of {bytes} bytes cannot be held in memory on this machine")]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// The size asked for, in bytes.
        bytes: u64,
    },
}

/// A finished filesystem image: the bytes, and the geometry that produced them.
pub struct Image {
    bytes: Vec<u8>,
    layout: BtrfsLayout,
    slack: Slack,
    fidelity: FidelityReport,
}

impl Image {
    /// What the source offered that the format could not hold, and what it stored more coarsely.
    ///
    /// Always empty, and answered rather than absent so that a caller writing one build step
    /// against four families asks every one of them the same question. btrfs records every
    /// property a [`SourceEntry`](crate::SourceEntry) carries, so there is nothing for it to say
    /// — which is a fact about the format worth being able to *check* rather than one to take on
    /// trust.
    #[must_use]
    pub fn fidelity(&self) -> &FidelityReport {
        &self.fidelity
    }

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
    pub fn layout(&self) -> &BtrfsLayout {
        &self.layout
    }

    /// Tree blocks reserved for this filesystem and not spent, which are free space in it.
    #[must_use]
    pub fn slack(&self) -> Slack {
        self.slack
    }

    /// Write the image to `w`.
    ///
    /// # Errors
    ///
    /// Any I/O error from `w`.
    pub fn write_to(&self, mut w: impl Write) -> std::io::Result<()> {
        w.write_all(&self.bytes)
    }
}

/// A format decided but not yet performed: the tree the source describes, and the geometry
/// planned to hold it.
///
/// Everything a format can fail on but I/O has already happened by the time one of these
/// exists, so a caller can find out what a filesystem will be — and whether it can be built at
/// all — before opening a destination. [`write_to`](Self::write_to) is the half that can only
/// fail on I/O.
///
/// # Example
///
/// ```no_run
/// use ferrosys::btrfs::{FormatOptions, FormatPlan};
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// let source = TreeBuilder::new()
///     .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
///     .file(b"/etc/hostname".to_vec(), "ferrosys\n", Metadata::new(0o644, time));
///
/// let plan = FormatPlan::new(source, 1 << 30, FormatOptions::new([0x11; 16], time))?;
///
/// // What it will be, and what it will cost, before the destination is touched.
/// println!("{} chunks", plan.layout().chunks.len());
/// assert!(plan.fidelity().is_faithful());
///
/// let mut file = std::fs::File::create("root.img")?;
/// plan.write_to(&mut file)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct FormatPlan {
    prepared: Prepared,
    /// The size the format was asked for, which is the size the destination becomes. It is the
    /// same number the layout carries, and it is held here because that is what a caller reads
    /// it as: how large the file will be, rather than how large the filesystem on it is.
    volume_bytes: u64,
    options: FormatOptions,
}

impl FormatPlan {
    /// Plan a format of `volume_bytes` populated from `source`.
    ///
    /// Everything a format can fail on but I/O happens here.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the geometry cannot be realized or the source names something the
    /// filesystem cannot hold.
    pub fn new(
        source: impl Source,
        volume_bytes: u64,
        options: FormatOptions,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            prepared: prepare(source, volume_bytes, &options)?,
            volume_bytes,
            options,
        })
    }

    /// The geometry the bytes will realize — exact rather than estimated, because it is the
    /// same value the write uses.
    #[must_use]
    pub fn layout(&self) -> &BtrfsLayout {
        &self.prepared.layout
    }

    /// Bytes the destination will hold, which is the size the format was asked for.
    #[must_use]
    pub const fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }

    /// What the source offered that the format cannot hold, and what it will store more
    /// coarsely.
    ///
    /// Always faithful for this family, which holds every property a source states. It answers
    /// rather than being absent so that a caller writing one build step against several
    /// families asks all of them the same question.
    #[must_use]
    pub fn fidelity(&self) -> &FidelityReport {
        &self.prepared.model.fidelity
    }

    /// Write the planned filesystem to `sink`, returning the tree blocks it reserved and did
    /// not spend.
    ///
    /// Only the blocks the filesystem occupies are written and nothing is read back, so a file
    /// destination stays sparse and the image never exists in memory. The sink is extended to
    /// [`volume_bytes`](Self::volume_bytes), and every byte of it that is not written must read
    /// back as zero — a freshly created file, or one truncated to zero length, satisfies that.
    ///
    /// The plan is not consumed, so what it reports is readable on either side of the write and
    /// one plan may be written more than once. Two writes of one plan produce the same bytes,
    /// unless a file a [`FileRange`](crate::FileRange) names changed in between.
    ///
    /// # Errors
    ///
    /// [`FormatError::Io`] if writing to `sink` fails, or if a file the source named by range
    /// cannot be read — which is what a file edited after the source was built looks like.
    pub fn write_to(&self, sink: impl Write + Seek) -> Result<Slack, FormatError> {
        write_filesystem(sink, &self.prepared, &self.options, self.volume_bytes)
    }
}

/// Format a btrfs filesystem of `volume_bytes` populated from `source`, collecting it into
/// memory.
///
/// # Example
///
/// ```
/// use ferrosys::btrfs::{FormatOptions, GENERATION, Reader, Volume, format};
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_700_000_000);
/// let options = FormatOptions::new([0x11; 16], time)
///     .chunk_tree_uuid([0x22; 16])
///     .device_uuid([0x33; 16])
///     .subvolume_uuid([0x44; 16]);
///
/// let source = TreeBuilder::new()
///     .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
///     .file(b"/etc/hostname".to_vec(), "ferrosys\n", Metadata::new(0o644, time));
///
/// let image = format(source.clone(), 1 << 30, options.clone())?;
/// assert_eq!(image.as_bytes().len(), 1 << 30);
/// // btrfs holds every property a source states, so nothing was lost on the way in.
/// assert!(image.fidelity().is_faithful());
///
/// // Read it back with this crate's own reader: every tree is reachable, and every block's
/// // checksum is verified on the way to it. Ten trees — the eight a root item names, and the
/// // root tree and chunk tree the superblock points at directly.
/// let mut volume = Volume::open(std::io::Cursor::new(image.as_bytes()))?;
/// assert_eq!(volume.superblock().generation, GENERATION);
/// assert_eq!(volume.tree_roots()?.len(), 10);
///
/// let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
/// let node = reader.lookup(b"/etc/hostname")?;
/// assert_eq!(reader.read_data(&node)?, b"ferrosys\n");
///
/// // Two formats of the same source and the same parameters are the same bytes.
/// assert_eq!(image.as_bytes(), format(source, 1 << 30, options)?.as_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, the source names something the
/// filesystem cannot hold, or the image will not fit in memory.
pub fn format(
    source: impl Source,
    volume_bytes: u64,
    options: FormatOptions,
) -> Result<Image, FormatError> {
    // Planned before the buffer is allocated, so a geometry or a source that cannot be realized
    // fails without first asking for the volume's worth of memory.
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    let size = usize::try_from(volume_bytes).map_err(|_| FormatError::ImageTooLargeInMemory {
        bytes: volume_bytes,
    })?;
    let mut image = Cursor::new(vec![0u8; size]);
    let slack = plan.write_to(&mut image)?;
    Ok(Image {
        bytes: image.into_inner(),
        layout: plan.prepared.layout,
        slack,
        fidelity: plan.prepared.model.fidelity,
    })
}

/// Format a btrfs filesystem of `volume_bytes` populated from `source`, streaming its bytes into
/// `sink` and returning the layout they realize.
///
/// Only the blocks the filesystem occupies are written and nothing is read back, so a file
/// destination stays sparse and the image never exists in memory. What this costs in memory is
/// the source's entry records and the largest single file's bytes — each file is read whole as
/// it is placed — neither of which grows with the volume, so a volume far larger than this
/// machine's memory is a file that stays sparse.
///
/// The sink is extended to `volume_bytes`, and every byte of it that is not written must read
/// back as zero — a freshly created file, or one truncated to zero length, satisfies that.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, the source names something the
/// filesystem cannot hold, a file the source named by range cannot be read, or writing to `sink`
/// fails.
pub fn format_to<W: Write + Seek>(
    sink: W,
    source: impl Source,
    volume_bytes: u64,
    options: FormatOptions,
) -> Result<BtrfsLayout, FormatError> {
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    plan.write_to(sink)?;
    Ok(plan.prepared.layout)
}

/// A source turned into a tree, and the geometry planned to hold it.
struct Prepared {
    model: BtrfsModel,
    layout: BtrfsLayout,
}

/// Turn a source into a tree and plan the geometry that holds it.
///
/// Both entry points come through here, so an input a format refuses is refused by both, and is
/// refused before the destination is touched. The order is the load-bearing part: the two block
/// sizes are resolved first because which files live inside the metadata depends on them, then
/// the tree is built, and only then is the geometry planned — from what the tree turned out to
/// need rather than from what a caller guessed it would.
fn prepare(
    source: impl Source,
    volume_bytes: u64,
    options: &FormatOptions,
) -> Result<Prepared, FormatError> {
    let mut request = options.plan;
    request.volume_bytes = volume_bytes;
    let (sector_size, node_size) = block_sizes(&request)?;
    let model = build_model(
        source.into_entries(),
        &options.subvolumes,
        options.default_subvolume.as_deref(),
        options.subvolume_uuid,
        sector_size,
        node_size,
        options.time,
    )?;
    request.content = model.content;
    let layout = plan_layout(&request)?;
    Ok(Prepared { model, layout })
}

// ---------------------------------------------------------------------------
// Records, and how they divide into blocks

/// One record to be placed in a tree: the key it is found under, and its bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Record {
    key: DiskKey,
    data: Vec<u8>,
}

impl Record {
    /// Bytes this record costs a leaf: its data, and the array entry describing it.
    fn cost(&self) -> usize {
        self.data.len() + Item::SIZE
    }
}

/// How a tree's records divide into blocks, before any block has an address.
///
/// Leaves are packed full in key order — as many records as fit, then the next leaf — which is
/// what a tree built all at once arrives at and is denser than what a tree grown by insertion
/// ends with.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Shape {
    /// One entry per leaf: how many records it holds. Never empty — a tree with no records at
    /// all is one empty leaf, because a tree still has a root.
    leaves: Vec<usize>,
    /// One entry per level above the leaves, lowest first. The last is always one, the root.
    upper: Vec<u64>,
}

impl Shape {
    /// How many blocks the whole tree occupies.
    fn blocks(&self) -> u64 {
        self.upper.iter().sum::<u64>() + self.leaves.len() as u64
    }

    /// The height of the tree's top block, zero where the tree is one leaf.
    fn level(&self) -> u8 {
        // A tree deeper than a byte could count is not reachable from a reservation this crate
        // plans: at the narrowest fan-out the format admits, eight levels hold more records
        // than any volume has room for.
        self.upper.len() as u8
    }
}

/// Divide `records` into leaves and stack the levels above them.
///
/// # Errors
///
/// [`FormatError::RecordTooLarge`] where one record is larger than a whole leaf, which no
/// packing can place.
fn shape(records: &[Record], node_size: u32) -> Result<Shape, FormatError> {
    let capacity = node_size as usize - Header::SIZE;
    let mut leaves = Vec::new();
    let mut count = 0usize;
    let mut used = 0usize;
    for record in records {
        let cost = record.cost();
        if cost > capacity {
            return Err(FormatError::RecordTooLarge {
                bytes: record.data.len(),
                capacity: capacity - Item::SIZE,
            });
        }
        if used + cost > capacity {
            leaves.push(count);
            count = 0;
            used = 0;
        }
        count += 1;
        used += cost;
    }
    // The trailing leaf, and the empty tree's only one: a tree with nothing in it still has a
    // root, and that root is an empty leaf.
    leaves.push(count);

    Ok(Shape {
        upper: levels_above(leaves.len() as u64, capacity as u64 / KeyPtr::SIZE as u64),
        leaves,
    })
}

/// `records` in the order a tree holds them, which is the key tuple's.
fn sorted(mut records: Vec<Record>) -> Vec<Record> {
    records.sort_by_key(|record| record.key);
    records
}

/// `len` zero bytes, with `fill` run over them.
fn encode(len: usize, fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    fill(&mut bytes);
    bytes
}

// ---------------------------------------------------------------------------
// Allocation

/// What has been allocated out of each block group, so that the free-space tree and the
/// block-group tree are written from one account rather than from two.
///
/// Every block group is filled from its start and the blocks in it are contiguous, so what it
/// holds is a prefix and what is free is the single run behind that prefix. That is a property
/// of writing a filesystem once, and it is why one written here has a single free run per block
/// group where one the format's own tooling writes has several.
#[derive(Clone)]
struct Allocation {
    /// Bytes allocated from the start of each chunk, in the layout's own order.
    used: Vec<u64>,
    node_size: u64,
    /// The first chunk [`take_data`](Self::take_data) still considers; every one before it
    /// is a data chunk it filled or a chunk of another kind it stepped past.
    data_cursor: usize,
}

impl Allocation {
    /// Nothing allocated anywhere.
    fn new(layout: &BtrfsLayout) -> Self {
        Self {
            used: vec![0; layout.chunks.len()],
            node_size: u64::from(layout.node_size),
            data_cursor: 0,
        }
    }

    /// Hand out `count` block addresses from the block groups of `kind`, in ascending order.
    ///
    /// [`None`] where those block groups have no room left, which is the reservation having
    /// been too small: the planner sizes them against a bound on exactly this.
    fn take(
        &mut self,
        layout: &BtrfsLayout,
        kind: BlockGroupFlags,
        count: u64,
    ) -> Option<Vec<u64>> {
        let mut out = Vec::with_capacity(count as usize);
        for (index, chunk) in layout.chunks.iter().enumerate() {
            if !chunk.flags.contains(kind) {
                continue;
            }
            while out.len() as u64 != count && self.used[index] + self.node_size <= chunk.length {
                out.push(chunk.logical + self.used[index]);
                self.used[index] += self.node_size;
            }
        }
        (out.len() as u64 == count).then_some(out)
    }

    /// Hand out up to `bytes` of consecutive data space, from wherever the data block groups
    /// have room.
    ///
    /// It grants **less than asked** where the block group it is filling ends first, which is
    /// what keeps every block group filled from its start with one run of free space behind —
    /// the property the free-space tree and the block-group accounting both rest on. A caller
    /// asks again for the rest, and the file gains an extent boundary there.
    ///
    /// [`None`] where no data block group has room left, which the planner sizes them against.
    fn take_data(&mut self, layout: &BtrfsLayout, bytes: u64) -> Option<(u64, u64)> {
        // Resumes at the chunk the last grant came from: space is granted in layout order
        // and a chunk never regains any, so everything before the cursor is spoken for,
        // and rescanning it per grant would make data placement quadratic in the chunk
        // count.
        while self.data_cursor < layout.chunks.len() {
            let index = self.data_cursor;
            let chunk = &layout.chunks[index];
            if !chunk.flags.contains(BlockGroupFlags::DATA) {
                self.data_cursor += 1;
                continue;
            }
            let free = chunk.length - self.used[index];
            if free == 0 {
                self.data_cursor += 1;
                continue;
            }
            let granted = bytes.min(free);
            let logical = chunk.logical + self.used[index];
            self.used[index] += granted;
            return Some((logical, granted));
        }
        None
    }

    /// Blocks handed out from the block groups of `kind`.
    fn blocks_of(&self, layout: &BtrfsLayout, kind: BlockGroupFlags) -> u64 {
        self.bytes_of(layout, kind) / self.node_size
    }

    /// Bytes handed out from the block groups of `kind`.
    fn bytes_of(&self, layout: &BtrfsLayout, kind: BlockGroupFlags) -> u64 {
        layout
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.flags.contains(kind))
            .map(|(index, _)| self.used[index])
            .sum()
    }
}

// ---------------------------------------------------------------------------
// The file data
//
// Everything here is decided before a tree is built, because the records naming these addresses
// are what the trees are made of. What is *not* decided here is a single checksum: a record's
// key and its length follow from the extents alone, and its bytes are filled as the data is
// written, so the whole filesystem's checksums never exist in memory at once.

/// One run of a file's bytes on the volume.
///
/// Both offsets and the length are whole numbers of sectors. A file whose length is not one is
/// covered to the end of its last sector, which is what the format does: an extent is addressed
/// in sectors and the inode's size is what says where the file stops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DataExtent {
    /// Where in the file the run begins.
    offset: u64,
    /// Where its first byte sits in the logical address space.
    logical: u64,
    /// How many bytes of the volume it occupies.
    length: u64,
    /// The subvolume whose tree holds the file, which the extent's back-reference names.
    root: u64,
    /// The file's inode number in that tree.
    inode: u64,
}

impl DataExtent {
    /// One past the last logical address the run covers.
    const fn logical_end(&self) -> u64 {
        self.logical + self.length
    }
}

/// Where every file's bytes went: one list per object, in the model's own order.
struct DataPlan {
    per_object: Vec<Vec<Vec<DataExtent>>>,
}

impl DataPlan {
    /// Every extent of the filesystem in ascending logical order.
    ///
    /// Which is the order they were handed out in: data space is filled from the first block
    /// group forward with no gaps, so walking the model in its own order walks the address space
    /// in ascending order. The checksum tree is built on that, and so is the one pass that
    /// writes the bytes.
    fn ordered(&self) -> impl Iterator<Item = &DataExtent> {
        self.per_object
            .iter()
            .flat_map(|subvolume| subvolume.iter().flatten())
    }
}

/// Give every byte of every file an address.
///
/// A file becomes as many extents as it takes: one per [`MAX_EXTENT_BYTES`], and one more
/// wherever a block group ends inside a run — which is what keeps every block group filled from
/// its start rather than leaving a hole an extent would not fit in.
fn plan_data(
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    allocation: &mut Allocation,
) -> Result<DataPlan, FormatError> {
    let sector = u64::from(layout.sector_size);
    let mut per_object = Vec::with_capacity(model.subvolumes.len());
    for subvolume in &model.subvolumes {
        let mut objects = Vec::with_capacity(subvolume.objects.len());
        for object in &subvolume.objects {
            let mut extents = Vec::new();
            if let ObjectKind::File {
                size,
                inline: false,
                ..
            } = object.kind
            {
                let stored = size.div_ceil(sector) * sector;
                let mut at = 0;
                while at < stored {
                    let want = (stored - at).min(MAX_EXTENT_BYTES);
                    let (logical, granted) =
                        allocation
                            .take_data(layout, want)
                            .ok_or(FormatError::DataExhausted {
                                planned: model.content.data_bytes,
                            })?;
                    extents.push(DataExtent {
                        offset: at,
                        logical,
                        length: granted,
                        root: subvolume.id,
                        inode: object.inode,
                    });
                    at += granted;
                }
            }
            objects.push(extents);
        }
        per_object.push(objects);
    }
    Ok(DataPlan { per_object })
}

/// The checksum tree's records: their keys and their lengths, with no checksum in them yet.
///
/// One record per run of consecutive addresses, capped at [`MAX_CSUM_RECORD`] bytes of checksum
/// so that a leaf holds more than one. The cap is the same constant the reservation counted
/// against, which is what makes that count exact rather than an approximation of this.
fn csum_records(data: &DataPlan, sector_size: u32) -> Vec<Record> {
    let sector = u64::from(sector_size);
    let per_record = MAX_CSUM_RECORD / CSUM_BYTES_PER_SECTOR;
    let mut records: Vec<Record> = Vec::new();
    // One past the last address the record being filled covers, so a run that begins here
    // continues it and a run that begins anywhere else starts a record of its own.
    let mut covered = 0;
    for extent in data.ordered() {
        let mut at = extent.logical;
        while at < extent.logical_end() {
            let room = match records.last() {
                Some(last) if at == covered => {
                    per_record - last.data.len() as u64 / CSUM_BYTES_PER_SECTOR
                }
                _ => 0,
            };
            if room == 0 {
                records.push(Record {
                    key: DiskKey::new(objectid::EXTENT_CSUM, ItemType::EXTENT_CSUM, at),
                    data: Vec::new(),
                });
            }
            let last = records
                .last_mut()
                .expect("a record was just pushed or found");
            let room = per_record - last.data.len() as u64 / CSUM_BYTES_PER_SECTOR;
            let sectors = ((extent.logical_end() - at) / sector).min(room);
            last.data.resize(
                last.data.len() + (sectors * CSUM_BYTES_PER_SECTOR) as usize,
                0,
            );
            at += sectors * sector;
            covered = at;
        }
    }
    records
}

/// The checksum tree's records, being filled in the order the data is written.
///
/// The records were sized from the same extent list this walks, so the two agree by
/// construction — and [`finish`](Self::finish) is what says so rather than leaving it assumed.
struct CsumFill<'a> {
    records: &'a mut [Record],
    at: usize,
    offset: usize,
}

impl<'a> CsumFill<'a> {
    fn new(records: &'a mut [Record]) -> Self {
        Self {
            records,
            at: 0,
            offset: 0,
        }
    }

    /// Record one sector's checksum.
    fn push(&mut self, digest: u32) {
        while self
            .records
            .get(self.at)
            .is_some_and(|record| self.offset == record.data.len())
        {
            self.at += 1;
            self.offset = 0;
        }
        let record = &mut self.records[self.at];
        crate::bytes::put_u32(&mut record.data, self.offset, digest);
        self.offset += CSUM_BYTES_PER_SECTOR as usize;
    }

    /// Assert that every checksum the records were sized for was supplied.
    fn finish(self) {
        let filled = self.records[..self.at]
            .iter()
            .map(|record| record.data.len())
            .sum::<usize>()
            + self.offset;
        let wanted = self
            .records
            .iter()
            .map(|record| record.data.len())
            .sum::<usize>();
        assert_eq!(
            filled, wanted,
            "the checksum tree was sized for bytes the data pass did not produce"
        );
    }
}

/// Write every file's bytes, checksumming each sector on the way past.
///
/// One read per file and one buffer at a time, so what this costs in memory is the largest
/// single file rather than the sum of them — which is what [`FileContent`](crate::FileContent)
/// exists to make possible. The bytes go to every copy of the logical space holding them, so a
/// replicated data block group protects what is in it.
fn write_data<W: Write + Seek>(
    sink: &mut ByteSink<W>,
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    data: &DataPlan,
    csums: &mut CsumFill<'_>,
) -> Result<(), FormatError> {
    let sector = layout.sector_size as usize;
    let mut buffer = Vec::new();
    for (subvolume, objects) in model.subvolumes.iter().zip(&data.per_object) {
        for (object, extents) in subvolume.objects.iter().zip(objects) {
            if extents.is_empty() {
                continue;
            }
            let ObjectKind::File { content, .. } = object.kind else {
                unreachable!("only a regular file is given data extents")
            };
            let bytes = model.contents[content].read()?;
            for extent in extents {
                // The run's bytes, and zeros where the file stops inside its last sector. A
                // sector is checksummed whole, so what is past the end of the file has to be a
                // value rather than whatever the destination happened to hold.
                buffer.clear();
                let from = extent.offset as usize;
                let to = (from + extent.length as usize).min(bytes.len());
                buffer.extend_from_slice(&bytes[from.min(bytes.len())..to]);
                buffer.resize(extent.length as usize, 0);
                for at in (0..buffer.len()).step_by(sector) {
                    csums.push(crc32c_over(&buffer[at..at + sector]));
                }
                for offset in copies_of(layout, extent.logical) {
                    sink.write_at(offset, &buffer)?;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The trees

/// One tree of the filesystem: what it holds, and where each of its blocks sits.
struct BuiltTree {
    objectid: u64,
    records: Vec<Record>,
    shape: Shape,
    /// One entry per level, leaves first: the address of every block of that level, in key
    /// order. The last level holds exactly one address, the root's.
    levels: Vec<Vec<u64>>,
}

impl BuiltTree {
    /// Shape `records`, take the addresses the shape needs, and slice them into levels.
    fn place(
        objectid: u64,
        records: Vec<Record>,
        layout: &BtrfsLayout,
        allocation: &mut Allocation,
        kind: BlockGroupFlags,
    ) -> Result<Self, FormatError> {
        let shape = shape(&records, layout.node_size)?;
        let addresses = allocation
            .take(layout, kind, shape.blocks())
            .ok_or_else(|| exhausted(layout, allocation, kind))?;
        Ok(Self::from_addresses(objectid, records, shape, addresses))
    }

    /// The same, for a tree whose addresses were taken before its records were known.
    fn from_addresses(
        objectid: u64,
        records: Vec<Record>,
        shape: Shape,
        addresses: Vec<u64>,
    ) -> Self {
        let mut rest = addresses.as_slice();
        let mut levels = Vec::with_capacity(shape.upper.len() + 1);
        let (leaves, tail) = rest.split_at(shape.leaves.len());
        levels.push(leaves.to_vec());
        rest = tail;
        for width in &shape.upper {
            let (level, tail) = rest.split_at(*width as usize);
            levels.push(level.to_vec());
            rest = tail;
        }
        Self {
            objectid,
            records,
            shape,
            levels,
        }
    }

    /// The tree's top block, which is what a root item or the superblock points at.
    fn root(&self) -> u64 {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("every tree has a root block")
    }

    /// How many blocks the tree occupies.
    fn blocks(&self) -> u64 {
        self.shape.blocks()
    }

    /// Every block of the tree, with the level it sits at.
    fn extents(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.levels
            .iter()
            .enumerate()
            .flat_map(|(level, blocks)| blocks.iter().map(move |address| (*address, level as u8)))
    }
}

/// Which blocks of the level below belong to block `within` of a level `count` blocks wide.
///
/// Children are divided evenly and in order, which is the same division the shaping arrived at:
/// a level of *n* blocks under a level of *m* has each of the *m* taking the same fan-out, and
/// the last taking whatever is left.
fn children_range(below: usize, count: usize, within: usize) -> std::ops::Range<usize> {
    let fan_out = below.div_ceil(count);
    let from = within * fan_out;
    from..(from + fan_out).min(below)
}

/// The failure a block group with no room left for another block is reported as.
///
/// It is the reservation having been too small, and is reported in the reservation's own
/// numbers: the planner sizes these block groups *from* that bound, so a filesystem that filled
/// them is one that wanted more blocks than were reserved for it. The two cannot come apart —
/// a plan whose block groups were smaller than its own reservation would be a defect in the
/// planner, and it is asserted against there rather than guessed at here.
fn exhausted(layout: &BtrfsLayout, allocation: &Allocation, kind: BlockGroupFlags) -> FormatError {
    let system = kind.contains(BlockGroupFlags::SYSTEM);
    FormatError::Reservation(ReservationExceeded {
        pool: if system { Pool::System } else { Pool::Metadata },
        reserved: if system {
            layout.reservation.system_blocks
        } else {
            layout.reservation.metadata_blocks
        },
        // One more than fitted, which is the block that had nowhere to go.
        used: allocation.blocks_of(layout, kind) + 1,
    })
}

/// Every tree of the filesystem, assembled and addressed.
struct Filesystem {
    trees: Vec<BuiltTree>,
    allocation: Allocation,
}

impl Filesystem {
    /// The tree with this objectid.
    fn tree(&self, objectid: u64) -> &BuiltTree {
        self.trees
            .iter()
            .find(|tree| tree.objectid == objectid)
            .expect("every tree the order names was placed")
    }

    /// Every tree block of the filesystem, with its level and the tree that owns it, in
    /// ascending address order — which is the order the extent tree records them in.
    fn all_extents(&self) -> Vec<(u64, u8, u64)> {
        let mut out: Vec<(u64, u8, u64)> = self
            .trees
            .iter()
            .flat_map(|tree| {
                tree.extents()
                    .map(|(address, level)| (address, level, tree.objectid))
            })
            .collect();
        out.sort_unstable();
        out
    }
}

/// Which trees a filesystem has, in the order their blocks are laid down.
///
/// The order is the one the format's own tooling arrives at, minus the gaps its freed blocks
/// leave behind. The root tree is last because it names every other tree, so it is the one that
/// cannot be written until the rest are placed. A subvolume's tree follows the top-level one,
/// which is where a filesystem's own trees leave off.
fn tree_order(compat_ro: CompatRoFlags, model: &BtrfsModel) -> Vec<u64> {
    let mut order = Vec::new();
    if compat_ro.contains(CompatRoFlags::BLOCK_GROUP_TREE) {
        order.push(objectid::BLOCK_GROUP_TREE);
    }
    order.push(objectid::DEV_TREE);
    order.extend(model.subvolumes.iter().map(|subvolume| subvolume.id));
    order.push(objectid::UUID_TREE);
    order.push(objectid::CSUM_TREE);
    order.push(objectid::DATA_RELOC_TREE);
    if compat_ro.contains(CompatRoFlags::FREE_SPACE_TREE) {
        order.push(objectid::FREE_SPACE_TREE);
    }
    order.push(objectid::EXTENT_TREE);
    order.push(objectid::ROOT_TREE);
    order
}

/// Every tree that has a root item in the root tree.
///
/// The root tree and the chunk tree are absent because the superblock points at both directly,
/// which is what makes them reachable before any tree has been read.
fn root_item_trees(compat_ro: CompatRoFlags, model: &BtrfsModel) -> Vec<u64> {
    let mut trees = vec![objectid::EXTENT_TREE, objectid::DEV_TREE];
    trees.extend(model.subvolumes.iter().map(|subvolume| subvolume.id));
    trees.push(objectid::CSUM_TREE);
    trees.push(objectid::UUID_TREE);
    if compat_ro.contains(CompatRoFlags::FREE_SPACE_TREE) {
        trees.push(objectid::FREE_SPACE_TREE);
    }
    if compat_ro.contains(CompatRoFlags::BLOCK_GROUP_TREE) {
        trees.push(objectid::BLOCK_GROUP_TREE);
    }
    trees.push(objectid::DATA_RELOC_TREE);
    trees
}

/// One round of the layout: every tree but the extent tree built and addressed, and what the
/// extent tree would have to be to record what that round allocated.
struct Round {
    filesystem: Filesystem,
    /// The addresses set aside for the extent tree, as many as the round assumed.
    reserved: Vec<u64>,
    /// The extent tree's records as this round would have them.
    records: Vec<Record>,
    /// What those records divide into, which is what the next round assumes.
    shape: Shape,
}

/// Everything the rounds below start from, decided once because none of it depends on how many
/// blocks the extent tree turns out to take.
///
/// The file data in particular: it is allocated out of block groups the metadata never touches,
/// and every file's bytes are read here rather than in each round — a filesystem whose small
/// files live inside the metadata would otherwise read each of them once per round.
struct Placed {
    allocation: Allocation,
    data: DataPlan,
    /// One entry per subvolume, in the model's order: its records, ready but for nothing.
    subvolume_records: Vec<Vec<Record>>,
}

/// Assemble every tree and give every block an address.
///
/// This is where the circularity described at the top of the module is closed. Each round lays
/// the whole filesystem out on an assumption about how many blocks the extent tree takes, then
/// counts what the extent tree would actually need; the round where the two agree is the
/// answer. The assumption only ever grows, so the rounds converge upward on the least size that
/// records itself.
fn assemble(
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    options: &FormatOptions,
    volume_bytes: u64,
) -> Result<(Filesystem, DataPlan), FormatError> {
    let mut allocation = Allocation::new(layout);
    let data = plan_data(model, layout, &mut allocation)?;
    let mut subvolume_records = Vec::with_capacity(model.subvolumes.len());
    for (index, subvolume) in model.subvolumes.iter().enumerate() {
        subvolume_records.push(fs_tree_records(
            subvolume,
            &data.per_object[index],
            model,
            layout,
        )?);
    }
    let placed = Placed {
        allocation,
        data,
        subvolume_records,
    };

    let mut extent_blocks = 1u64;
    for _ in 0..LAYOUT_ROUNDS {
        let round = lay_out(model, &placed, layout, options, volume_bytes, extent_blocks)?;
        let needed = round.shape.blocks();
        if needed == extent_blocks {
            let filesystem = settle(round, model, &placed, layout, options)?;
            return Ok((filesystem, placed.data));
        }
        extent_blocks = needed;
    }
    Err(FormatError::LayoutUnsettled)
}

/// One round of the layout, with the extent tree taking exactly `extent_blocks` blocks.
fn lay_out(
    model: &BtrfsModel,
    placed: &Placed,
    layout: &BtrfsLayout,
    options: &FormatOptions,
    volume_bytes: u64,
    extent_blocks: u64,
) -> Result<Round, FormatError> {
    let compat_ro = layout.compat_ro_flags;
    let mut allocation = placed.allocation.clone();
    let mut trees = Vec::new();

    // The chunk tree lives in the system block group, alone: the map has to be readable before
    // the map has been read, which is the whole reason that block group exists.
    trees.push(BuiltTree::place(
        objectid::CHUNK_TREE,
        chunk_tree_records(layout, options, volume_bytes),
        layout,
        &mut allocation,
        BlockGroupFlags::SYSTEM,
    )?);

    // Every other tree, in the order their blocks are laid down. Three of them hold records
    // naming addresses that are still being handed out, and are filled in by `refill` once
    // every address is known; their *shapes* do not depend on any address, so they are placed
    // here from records of the right count and the right sizes.
    let mut reserved = Vec::new();
    for objectid in tree_order(compat_ro, model) {
        if objectid == objectid::EXTENT_TREE {
            reserved = allocation
                .take(layout, BlockGroupFlags::METADATA, extent_blocks)
                .ok_or_else(|| exhausted(layout, &allocation, BlockGroupFlags::METADATA))?;
            continue;
        }
        let records = match model
            .subvolumes
            .iter()
            .position(|subvolume| subvolume.id == objectid)
        {
            Some(index) => placed.subvolume_records[index].clone(),
            None => match objectid {
                objectid::DEV_TREE => dev_tree_records(layout, options),
                objectid::DATA_RELOC_TREE => relocation_tree_records(options, layout.node_size),
                objectid::UUID_TREE => uuid_tree_records(model),
                objectid::CSUM_TREE => csum_records(&placed.data, layout.sector_size),
                objectid::BLOCK_GROUP_TREE => block_group_records(layout, &allocation),
                objectid::FREE_SPACE_TREE => {
                    free_space_tree_settled(layout, &allocation, extent_blocks, model, options)?
                }
                _ => root_tree_records(
                    &|_| TreePlacement::UNPLACED,
                    model,
                    layout,
                    options,
                    compat_ro,
                ),
            },
        };
        trees.push(BuiltTree::place(
            objectid,
            records,
            layout,
            &mut allocation,
            BlockGroupFlags::METADATA,
        )?);
    }

    let filesystem = Filesystem { trees, allocation };
    // The extent tree's own blocks are in the list it records, at a level this round does not
    // know yet. A level does not change what a record costs and cannot change where one sorts —
    // every address is distinct — so the division into blocks this produces is the division the
    // finished tree has.
    let mut extents = filesystem.all_extents();
    extents.extend(
        reserved
            .iter()
            .map(|&address| (address, 0, objectid::EXTENT_TREE)),
    );
    extents.sort_unstable();
    let records = extent_tree_records(
        &extents,
        &placed.data,
        layout,
        &filesystem.allocation,
        compat_ro,
    );
    Ok(Round {
        shape: shape(&records, layout.node_size)?,
        filesystem,
        reserved,
        records,
    })
}

/// Turn the round that agreed with itself into the finished filesystem.
///
/// The extent tree joins the others, which is what finally gives its own blocks a level; its
/// records are then rebuilt so that each key carries the level its block turned out to sit at,
/// and the three trees whose contents name addresses are filled in.
fn settle(
    round: Round,
    model: &BtrfsModel,
    placed: &Placed,
    layout: &BtrfsLayout,
    options: &FormatOptions,
) -> Result<Filesystem, FormatError> {
    let Round {
        mut filesystem,
        reserved,
        records,
        shape: divided,
    } = round;
    filesystem.trees.push(BuiltTree::from_addresses(
        objectid::EXTENT_TREE,
        records,
        divided,
        reserved,
    ));

    let extents = filesystem.all_extents();
    let records = extent_tree_records(
        &extents,
        &placed.data,
        layout,
        &filesystem.allocation,
        layout.compat_ro_flags,
    );
    let at = filesystem.trees.len() - 1;
    assert_eq!(
        shape(&records, layout.node_size)?,
        filesystem.trees[at].shape,
        "the extent tree changed shape once its own blocks had levels, and its blocks were \
         addressed against the shape it had"
    );
    filesystem.trees[at].records = records;

    refill(&mut filesystem, model, layout, options)?;
    Ok(filesystem)
}

/// Replace the records of the three trees whose contents name addresses, now that every address
/// is known.
///
/// The shape each was given is asserted to survive. A record that turned out a different size
/// would move a leaf boundary, and the addresses were handed out against the boundaries the
/// shaping decided — so a shape that changed here is a block placed where nothing reserved room
/// for it, which is the one mistake this two-pass arrangement exists to make impossible.
fn refill(
    filesystem: &mut Filesystem,
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    options: &FormatOptions,
) -> Result<(), FormatError> {
    let compat_ro = layout.compat_ro_flags;
    let allocation = filesystem.allocation.clone();
    for objectid in [
        objectid::BLOCK_GROUP_TREE,
        objectid::FREE_SPACE_TREE,
        objectid::ROOT_TREE,
    ] {
        let Some(at) = filesystem
            .trees
            .iter()
            .position(|tree| tree.objectid == objectid)
        else {
            continue;
        };
        let records = match objectid {
            objectid::BLOCK_GROUP_TREE => block_group_records(layout, &allocation),
            objectid::FREE_SPACE_TREE => free_space_tree_records(layout, &allocation),
            _ => root_tree_records(
                &|id| {
                    let tree = filesystem.tree(id);
                    TreePlacement {
                        root: tree.root(),
                        bytes_used: tree.blocks() * u64::from(layout.node_size),
                        level: tree.shape.level(),
                    }
                },
                model,
                layout,
                options,
                compat_ro,
            ),
        };
        let reshaped = shape(&records, layout.node_size)?;
        assert_eq!(
            reshaped, filesystem.trees[at].shape,
            "tree {objectid} changed shape once its records held real values, and its blocks \
             were addressed against the shape it had"
        );
        filesystem.trees[at].records = records;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// What each tree holds

/// The chunk tree: the one device, and every chunk of the address space.
fn chunk_tree_records(
    layout: &BtrfsLayout,
    options: &FormatOptions,
    volume_bytes: u64,
) -> Vec<Record> {
    let mut records = vec![Record {
        key: DiskKey::new(objectid::DEV_ITEMS, ItemType::DEV_ITEM, DEVICE_ID),
        data: encode(DevItem::SIZE, |buf| {
            device_item(layout, options, volume_bytes).write_to(buf);
        }),
    }];
    for chunk in &layout.chunks {
        records.push(Record {
            key: DiskKey::new(
                objectid::FIRST_CHUNK_TREE,
                ItemType::CHUNK_ITEM,
                chunk.logical,
            ),
            data: chunk_record(layout, options, chunk),
        });
    }
    records
}

/// The device record, which the chunk tree and the superblock both carry.
///
/// Its embedded filesystem id is the id every *tree block* carries rather than the one a person
/// sees, which is the same rule and not the same value on a filesystem whose two ids differ.
/// The record lives in the chunk tree, and a device belongs to the metadata it is part of.
fn device_item(layout: &BtrfsLayout, options: &FormatOptions, volume_bytes: u64) -> DevItem {
    DevItem {
        devid: DEVICE_ID,
        total_bytes: volume_bytes,
        bytes_used: layout.device_bytes_used(),
        io_align: layout.sector_size,
        io_width: layout.sector_size,
        sector_size: layout.sector_size,
        ty: 0,
        generation: 0,
        start_offset: 0,
        dev_group: 0,
        seek_speed: 0,
        bandwidth: 0,
        uuid: options.device_uuid,
        fsid: options.metadata_id(),
    }
}

/// One chunk item: the run of logical space, and one stripe per copy of it.
fn chunk_record(layout: &BtrfsLayout, options: &FormatOptions, chunk: &MappedChunk) -> Vec<u8> {
    // The chunk a filesystem is bootstrapped with is filled by hand, before there is an
    // allocator to fill one — so it carries the sector size in the two alignment fields and no
    // sub-stripe count at all, where every chunk the allocator lays down carries the stripe unit
    // and one. It is the chunk at the reserved head, and it survives into the finished
    // filesystem exactly where metadata is unreplicated and so nothing replaced it.
    //
    // Reproduced rather than normalized, for the reason the unallocated spans it leaves behind
    // are: the differential this writer is held to is record for record, and a field written
    // differently on one chunk of one profile pairing is a carve-out in the sharpest evidence
    // there is. Neither value is consulted by any driver — they are allocator hints — so
    // matching costs nothing but the conditional.
    let bootstrap = chunk.logical == RESERVED_HEAD && chunk.flags.contains(BlockGroupFlags::SYSTEM);
    let record = Chunk {
        length: chunk.length,
        owner: objectid::EXTENT_TREE,
        stripe_len: STRIPE_LEN,
        ty: chunk.flags,
        // The alignment and width a *chunk* records are the stripe unit, where the same two
        // fields of a *device* record hold the sector size. Both are measurements from the
        // baseline rather than one rule applied twice.
        io_align: if bootstrap {
            layout.sector_size
        } else {
            STRIPE_LEN as u32
        },
        io_width: if bootstrap {
            layout.sector_size
        } else {
            STRIPE_LEN as u32
        },
        sector_size: layout.sector_size,
        num_stripes: chunk.copies.len() as u16,
        sub_stripes: u16::from(!bootstrap),
    };
    encode(record.encoded_len(), |buf| {
        record.write_to(buf);
        for (index, &offset) in chunk.copies.iter().enumerate() {
            Stripe {
                devid: DEVICE_ID,
                offset,
                dev_uuid: options.device_uuid,
            }
            .write_to(&mut buf[Chunk::SIZE + index * Stripe::SIZE..]);
        }
    })
}

/// The device tree: what has gone wrong with the device, and what occupies each run of it.
fn dev_tree_records(layout: &BtrfsLayout, options: &FormatOptions) -> Vec<Record> {
    let mut records = vec![Record {
        key: DiskKey::new(DevStats::DEV_STATS, ItemType::PERSISTENT_ITEM, DEVICE_ID),
        data: encode(DevStats::SIZE, |buf| DevStats::default().write_to(buf)),
    }];
    for chunk in &layout.chunks {
        // One record per *copy*: the device tree maps runs of a disk, and a replicated chunk
        // occupies two of them.
        for &offset in &chunk.copies {
            records.push(Record {
                key: DiskKey::new(DEVICE_ID, ItemType::DEV_EXTENT, offset),
                data: encode(DevExtent::SIZE, |buf| {
                    DevExtent {
                        chunk_tree: objectid::CHUNK_TREE,
                        chunk_objectid: objectid::FIRST_CHUNK_TREE,
                        chunk_offset: chunk.logical,
                        length: chunk.length,
                        chunk_tree_uuid: options.chunk_tree_uuid,
                    }
                    .write_to(buf);
                }),
            });
        }
    }
    sorted(records)
}

/// The data-relocation tree: a subvolume a balance copies extents through.
///
/// It is created empty and stays empty on a filesystem nothing has balanced, which is every
/// filesystem this crate writes — so it is a root directory and the name that directory has for
/// its parent, and nothing else.
fn relocation_tree_records(options: &FormatOptions, node_size: u32) -> Vec<Record> {
    let root = objectid::FIRST_FREE;
    sorted(vec![
        Record {
            key: DiskKey::new(root, ItemType::INODE_ITEM, 0),
            data: encode(InodeItem::SIZE, |buf| {
                InodeItem {
                    generation: GENERATION,
                    transid: 0,
                    size: 0,
                    nbytes: u64::from(node_size),
                    block_group: 0,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    mode: DIRECTORY_MODE,
                    rdev: 0,
                    flags: InodeFlags::NONE,
                    sequence: 0,
                    atime: options.time,
                    ctime: options.time,
                    mtime: options.time,
                    otime: options.time,
                }
                .write_to(buf);
            }),
        },
        parent_name_record(root),
    ])
}

/// The name a subvolume's root directory has for its parent, which is itself.
fn parent_name_record(root: u64) -> Record {
    named_record(
        DiskKey::new(root, ItemType::INODE_REF, root),
        InodeRef {
            index: 0,
            name_len: PARENT_NAME.len() as u16,
        },
        PARENT_NAME,
    )
}

/// A record that is an [`InodeRef`] followed by the name it declares.
fn named_record(key: DiskKey, head: InodeRef, name: &[u8]) -> Record {
    let mut data = encode(InodeRef::SIZE, |buf| head.write_to(buf));
    data.extend_from_slice(name);
    Record { key, data }
}

// ---------------------------------------------------------------------------
// A subvolume's own tree

/// One subvolume's whole tree: every object in it, the names they answer to, their extended
/// attributes, and where their bytes are.
///
/// Nothing here depends on a tree block's address, which is why it is built once rather than in
/// each round of the layout: a file's bytes have addresses by the time this runs, and a tree
/// block does not yet have one.
fn fs_tree_records(
    subvolume: &ModelSubvolume,
    data: &[Vec<DataExtent>],
    model: &BtrfsModel,
    layout: &BtrfsLayout,
) -> Result<Vec<Record>, FormatError> {
    let mut records = vec![parent_name_record(objectid::FIRST_FREE)];
    for (index, object) in subvolume.objects.iter().enumerate() {
        let extents = &data[index];
        records.push(inode_record(object, extents, index == 0, layout.node_size));
        records.extend(name_records(object, layout.node_size));
        records.extend(xattr_records(object));
        if let ObjectKind::Directory(entries) = &object.kind {
            records.extend(directory_records(object.inode, entries));
        }
        records.extend(extent_records(object, extents, model)?);
    }
    packed(records, layout.node_size)
}

/// One object's inode record.
fn inode_record(
    object: &ModelObject,
    extents: &[DataExtent],
    is_subvolume_root: bool,
    node_size: u32,
) -> Record {
    // What the object is charged with holding. A directory's entries live in the tree rather
    // than in extents of its own, so it is charged nothing — with the one exception the format's
    // own tooling makes and this reproduces: a subvolume's root directory is charged the tree
    // block its tree is.
    let nbytes = match &object.kind {
        ObjectKind::Directory(_) if is_subvolume_root => u64::from(node_size),
        ObjectKind::Directory(_) => 0,
        ObjectKind::File { inline: true, .. } | ObjectKind::Symlink(_) => object.size(),
        ObjectKind::File { .. } => extents.iter().map(|extent| extent.length).sum(),
        _ => 0,
    };
    let rdev = match object.kind {
        ObjectKind::Device { major, minor, .. } => InodeItem::encode_device(major, minor),
        _ => 0,
    };
    // A directory has one link whatever is beneath it: btrfs does not count a subdirectory's
    // name for its parent the way a filesystem with a `..` entry does. Everything else has as
    // many links as it has names, and the root of a subvolume has the one the tree above gives
    // it.
    let nlink = match &object.kind {
        ObjectKind::Directory(_) => 1,
        _ => object.names.len() as u32,
    };
    Record {
        key: DiskKey::new(object.inode, ItemType::INODE_ITEM, 0),
        data: encode(InodeItem::SIZE, |buf| {
            InodeItem {
                generation: GENERATION,
                transid: 0,
                size: object.size(),
                nbytes,
                block_group: 0,
                nlink,
                uid: object.meta.uid,
                gid: object.meta.gid,
                mode: object.kind.mode_bits() | u32::from(object.meta.mode),
                rdev,
                flags: InodeFlags::NONE,
                sequence: 0,
                atime: object.meta.atime,
                ctime: object.meta.ctime,
                // No source records a birth time, so the modification time stands for it: it is
                // the earliest instant anything states about this object, and the alternative is
                // a value invented out of nothing.
                mtime: object.meta.mtime,
                otime: object.meta.mtime,
            }
            .write_to(buf);
        }),
    }
}

/// The records naming an object from the directories that hold it.
///
/// Every name an object has in one directory goes in one record, which is what the format does
/// and what keeps a lookup from having to search. A directory that holds so many names of one
/// object that they outgrow a leaf spills the rest into records of the *extended* shape, keyed
/// by a hash of the directory and the name rather than by the directory alone — which is the
/// whole reason that shape exists.
fn name_records(object: &ModelObject, node_size: u32) -> Vec<Record> {
    let capacity = node_size as usize - Header::SIZE - Item::SIZE;
    let mut records = Vec::new();
    let mut parents: Vec<u64> = Vec::new();
    for name in &object.names {
        if !parents.contains(&name.parent) {
            parents.push(name.parent);
        }
    }
    for parent in parents {
        let mut data: Vec<u8> = Vec::new();
        for name in object.names.iter().filter(|name| name.parent == parent) {
            let head = InodeRef {
                index: name.index,
                name_len: name.name.len() as u16,
            };
            if !data.is_empty() && data.len() + InodeRef::SIZE + name.name.len() > capacity {
                let mut extended = encode(InodeExtref::SIZE, |buf| {
                    InodeExtref {
                        parent_objectid: parent,
                        index: name.index,
                        name_len: head.name_len,
                    }
                    .write_to(buf);
                });
                extended.extend_from_slice(&name.name);
                records.push(Record {
                    key: DiskKey::new(
                        object.inode,
                        ItemType::INODE_EXTREF,
                        extref_hash(parent, &name.name),
                    ),
                    data: extended,
                });
                continue;
            }
            let at = data.len();
            data.resize(at + InodeRef::SIZE, 0);
            head.write_to(&mut data[at..]);
            data.extend_from_slice(&name.name);
        }
        if !data.is_empty() {
            records.push(Record {
                key: DiskKey::new(object.inode, ItemType::INODE_REF, parent),
                data,
            });
        }
    }
    records
}

/// One object's extended attributes.
///
/// The format spells an extended attribute as a directory entry that names nothing: the same
/// record, keyed by the hash of the attribute's name, with the value where a directory entry has
/// no value at all.
fn xattr_records(object: &ModelObject) -> Vec<Record> {
    object
        .xattrs
        .iter()
        .map(|xattr| Record {
            key: DiskKey::new(object.inode, ItemType::XATTR_ITEM, name_hash(&xattr.name)),
            data: dir_item_data(
                &DirItem {
                    location: DiskKey::MIN,
                    transid: 0,
                    data_len: xattr.value.len() as u16,
                    name_len: xattr.name.len() as u16,
                    kind: DirEntryType::Xattr,
                },
                &xattr.name,
                &xattr.value,
            ),
        })
        .collect()
}

/// A directory's entries: each name twice, once to be found by and once to be read in order.
fn directory_records(inode: u64, entries: &[DirEntry]) -> Vec<Record> {
    let mut records = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        let (location, kind) = match entry.target {
            EntryTarget::Inode { inode, kind } => {
                (DiskKey::new(inode, ItemType::INODE_ITEM, 0), kind)
            }
            // A subvolume appears in a directory as a directory, and what the entry names is the
            // root of another tree rather than an inode of this one.
            EntryTarget::Subvolume { id } => {
                (DiskKey::new(id, ItemType::ROOT_ITEM, 0), DirEntryType::Dir)
            }
        };
        let head = DirItem {
            location,
            transid: GENERATION,
            data_len: 0,
            name_len: entry.name.len() as u16,
            kind,
        };
        let data = dir_item_data(&head, &entry.name, &[]);
        records.push(Record {
            key: DiskKey::new(inode, ItemType::DIR_ITEM, name_hash(&entry.name)),
            data: data.clone(),
        });
        records.push(Record {
            key: DiskKey::new(inode, ItemType::DIR_INDEX, entry.index),
            data,
        });
    }
    records
}

/// A named record's bytes: the head, the name, and whatever value follows it.
fn dir_item_data(head: &DirItem, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut data = encode(DirItem::SIZE, |buf| head.write_to(buf));
    data.extend_from_slice(name);
    data.extend_from_slice(value);
    data
}

/// Where one object's bytes are: one record inside the metadata, or one per extent.
fn extent_records(
    object: &ModelObject,
    extents: &[DataExtent],
    model: &BtrfsModel,
) -> Result<Vec<Record>, FormatError> {
    let inline = |bytes: &[u8]| Record {
        key: DiskKey::new(object.inode, ItemType::EXTENT_DATA, 0),
        data: {
            let mut data = encode(FileExtentItem::INLINE_DATA_START, |buf| {
                FileExtentItem {
                    generation: GENERATION,
                    ram_bytes: bytes.len() as u64,
                    compression: super::ondisk::Compression::None,
                    encryption: 0,
                    other_encoding: 0,
                    kind: ExtentKind::Inline,
                    disk_bytenr: 0,
                    disk_num_bytes: 0,
                    offset: 0,
                    num_bytes: 0,
                }
                .write_to(buf);
            });
            data.extend_from_slice(bytes);
            data
        },
    };
    Ok(match &object.kind {
        // A symbolic link's target is its content, and it always lives in the record.
        ObjectKind::Symlink(target) => vec![inline(target)],
        // A file of no bytes has no record at all: `no-holes` says a run nothing describes
        // reads back as zeros, and a file of zero length is entirely such a run. Matched ahead
        // of the two content arms, so the answer for an empty file does not depend on which of
        // them the model's classification routes it to.
        ObjectKind::File { size: 0, .. } => Vec::new(),
        ObjectKind::File {
            content,
            inline: true,
            ..
        } => vec![inline(&model.contents[*content].read()?)],
        ObjectKind::File { .. } => extents
            .iter()
            .map(|extent| Record {
                key: DiskKey::new(object.inode, ItemType::EXTENT_DATA, extent.offset),
                data: encode(FileExtentItem::SIZE, |buf| {
                    FileExtentItem {
                        generation: GENERATION,
                        ram_bytes: extent.length,
                        compression: super::ondisk::Compression::None,
                        encryption: 0,
                        other_encoding: 0,
                        kind: ExtentKind::Regular,
                        disk_bytenr: extent.logical,
                        disk_num_bytes: extent.length,
                        // Every record covers a whole extent of its own, so none of them begins
                        // part-way into one. A driver that later rewrites part of a file is what
                        // produces the other case.
                        offset: 0,
                        num_bytes: extent.length,
                    }
                    .write_to(buf);
                }),
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// `records` sorted, with the ones sharing a key joined into the single record the format holds
/// them as.
///
/// Two names in one directory can hash alike, and so can two extended attributes; the format's
/// answer is one record holding both, which is why every reader of these records walks a packed
/// list rather than reading one head. It is rare and it is not exotic — a directory large enough
/// makes it likely — and a writer that emitted two records under one key would produce a tree
/// whose keys are not unique, which no driver expects and no checker accepts.
///
/// # Errors
///
/// [`FormatError::RecordTooLarge`] where the joined record outgrows a leaf, which is a directory
/// holding more colliding names than one block can describe.
fn packed(records: Vec<Record>, node_size: u32) -> Result<Vec<Record>, FormatError> {
    let capacity = node_size as usize - Header::SIZE - Item::SIZE;
    let mut out: Vec<Record> = Vec::with_capacity(records.len());
    for record in sorted(records) {
        match out.last_mut() {
            Some(last) if last.key == record.key => {
                last.data.extend_from_slice(&record.data);
                if last.data.len() > capacity {
                    return Err(FormatError::RecordTooLarge {
                        bytes: last.data.len(),
                        capacity,
                    });
                }
            }
            _ => out.push(record),
        }
    }
    Ok(out)
}

/// The UUID tree: every subvolume's id, mapped back to the subvolume it belongs to.
///
/// Sorted, and this is the one tree where that is not the order the records were produced in:
/// a record's key is halves of the identifier a caller stated, so the sequence follows those
/// identifiers rather than the subvolume numbering the model walks in. Two identifiers whose
/// order differs from their subvolumes' is the ordinary case rather than a corner.
///
/// A subvolume whose identifier is all zeros has no entry: the tree maps identifiers, and all
/// zeros records that none was set. That is the format's own convention — its tooling neither
/// writes such an entry nor adds one when it rescans the tree against the root items.
fn uuid_tree_records(model: &BtrfsModel) -> Vec<Record> {
    sorted(
        model
            .subvolumes
            .iter()
            .filter(|subvolume| subvolume.uuid != [0; 16])
            .map(|subvolume| {
                let (objectid_half, offset_half) = uuid_key(subvolume.uuid);
                Record {
                    key: DiskKey::new(objectid_half, ItemType::UUID_SUBVOL, offset_half),
                    data: subvolume.id.to_le_bytes().to_vec(),
                }
            })
            .collect(),
    )
}

/// The block-group tree: one record per chunk, saying how much of it is spoken for.
fn block_group_records(layout: &BtrfsLayout, allocation: &Allocation) -> Vec<Record> {
    layout
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| Record {
            key: DiskKey::new(chunk.logical, ItemType::BLOCK_GROUP_ITEM, chunk.length),
            data: encode(BlockGroupItem::SIZE, |buf| {
                BlockGroupItem {
                    used: allocation.used[index],
                    chunk_objectid: objectid::FIRST_CHUNK_TREE,
                    flags: chunk.flags,
                }
                .write_to(buf);
            }),
        })
        .collect()
}

/// The free-space tree: per block group, how its free space is written down, and the run that
/// is free.
///
/// One run per block group, because a block group written once is filled from its start. The
/// count is stated rather than assumed: a group filled to its very end has none, and the record
/// that says how many follow has to say zero.
fn free_space_tree_records(layout: &BtrfsLayout, allocation: &Allocation) -> Vec<Record> {
    let mut records = Vec::new();
    for (index, chunk) in layout.chunks.iter().enumerate() {
        let used = allocation.used[index];
        let free = chunk.length - used;
        records.push(Record {
            key: DiskKey::new(chunk.logical, ItemType::FREE_SPACE_INFO, chunk.length),
            data: encode(FreeSpaceInfo::SIZE, |buf| {
                FreeSpaceInfo {
                    extent_count: u32::from(free > 0),
                    flags: 0,
                }
                .write_to(buf);
            }),
        });
        if free > 0 {
            records.push(Record {
                key: DiskKey::new(chunk.logical + used, ItemType::FREE_SPACE_EXTENT, free),
                // A free run is its key and nothing else: where it begins and how long it is
                // are both in the key, so the item carries no data at all.
                data: Vec::new(),
            });
        }
    }
    sorted(records)
}

/// The free-space tree's records as they will stand once every block is handed out.
///
/// How many records that tree holds depends on the allocation — a block group filled to its
/// very end has no free run to record — and blocks are still being handed out when the tree is
/// placed: its own, the extent tree's reservation, and the root tree's all follow it. The
/// refill recomputes the records from the finished allocation, and a count that changed by
/// then would be a shape the addresses were not handed out against. So the finished allocation
/// is computed first, here: what follows this tree costs the same however this tree reads,
/// except the tree's own blocks — which are found by the same assume-and-check the whole
/// layout runs on, since handing them out is what can fill a block group exactly.
///
/// # Errors
///
/// [`FormatError::LayoutUnsettled`] where no size of this tree agrees with the records that
/// size produces — which takes a block group filling exactly and a leaf boundary moving at the
/// same step, and is typed rather than asserted for the reason
/// [`Reservation`](FormatError::Reservation) is.
fn free_space_tree_settled(
    layout: &BtrfsLayout,
    allocation: &Allocation,
    extent_blocks: u64,
    model: &BtrfsModel,
    options: &FormatOptions,
) -> Result<Vec<Record>, FormatError> {
    let compat_ro = layout.compat_ro_flags;
    // The root tree's block count, from the same unplaced records the layout shapes it on.
    let root_records = root_tree_records(
        &|_| TreePlacement::UNPLACED,
        model,
        layout,
        options,
        compat_ro,
    );
    let root_blocks = shape(&root_records, layout.node_size)?.blocks();
    let mut own_blocks = 1u64;
    for _ in 0..LAYOUT_ROUNDS {
        // Three takes follow this tree's placement, and one take of their sum fills the same
        // block groups to the same levels: an allocation is a prefix per group, and a prefix
        // does not care where its parts came from.
        let mut settled = allocation.clone();
        settled
            .take(
                layout,
                BlockGroupFlags::METADATA,
                own_blocks + extent_blocks + root_blocks,
            )
            .ok_or_else(|| exhausted(layout, allocation, BlockGroupFlags::METADATA))?;
        let records = free_space_tree_records(layout, &settled);
        let needed = shape(&records, layout.node_size)?.blocks();
        if needed == own_blocks {
            return Ok(records);
        }
        own_blocks = needed;
    }
    Err(FormatError::LayoutUnsettled)
}

/// The extent tree: one record per allocated tree block, and the block groups where there is no
/// tree of their own to hold them.
fn extent_tree_records(
    extents: &[(u64, u8, u64)],
    data: &DataPlan,
    layout: &BtrfsLayout,
    allocation: &Allocation,
    compat_ro: CompatRoFlags,
) -> Vec<Record> {
    let mut records: Vec<Record> = extents
        .iter()
        .map(|&(address, level, owner)| Record {
            // A skinny metadata extent is keyed by the block's *level*, where the older form is
            // keyed by its length. Nothing but the feature bit says which, so a filesystem
            // carrying `skinny-metadata` and a key holding a length is one a driver misreads.
            key: DiskKey::new(address, ItemType::METADATA_ITEM, u64::from(level)),
            data: encode(ExtentItem::SIZE + InlineRef::SIZE, |buf| {
                ExtentItem {
                    refs: 1,
                    generation: GENERATION,
                    flags: ExtentFlags::TREE_BLOCK,
                }
                .write_to(buf);
                InlineRef {
                    kind: ItemType::TREE_BLOCK_REF,
                    offset: owner,
                }
                .write_to(&mut buf[ExtentItem::SIZE..]);
            }),
        })
        .collect();

    // A data extent, whose record is keyed by its *length* where a tree block's is keyed by its
    // level, and whose reference names the file rather than the tree. Both differences are the
    // format's own: a tree block is one block and a data extent is a run, and a tree block
    // belongs to a tree where a run of bytes belongs to a position in a file.
    records.extend(data.ordered().map(|extent| Record {
        key: DiskKey::new(extent.logical, ItemType::EXTENT_ITEM, extent.length),
        data: encode(ExtentItem::SIZE + 1 + ExtentDataRef::SIZE, |buf| {
            ExtentItem {
                refs: 1,
                generation: GENERATION,
                flags: ExtentFlags::DATA,
            }
            .write_to(buf);
            buf[ExtentItem::SIZE] = ItemType::EXTENT_DATA_REF.value();
            ExtentDataRef {
                root: extent.root,
                objectid: extent.inode,
                offset: extent.offset,
                count: 1,
            }
            .write_to(&mut buf[ExtentItem::SIZE + 1..]);
        }),
    }));

    if !compat_ro.contains(CompatRoFlags::BLOCK_GROUP_TREE) {
        // Without the feature the block groups live here, interleaved with the extents by
        // address, which is why this list is sorted rather than concatenated.
        records.extend(block_group_records(layout, allocation));
    }
    sorted(records)
}

/// Where one tree the root tree names ended up: the address of its top block, the bytes its
/// blocks occupy, and its height.
#[derive(Clone, Copy)]
struct TreePlacement {
    root: u64,
    bytes_used: u64,
    level: u8,
}

impl TreePlacement {
    /// The placement every tree has before any block has an address.
    const UNPLACED: Self = Self {
        root: 0,
        bytes_used: 0,
        level: 0,
    };
}

/// The root tree: a record naming every other tree, and the directory that names the
/// subvolumes.
///
/// `placement` answers where each named tree sits. The first pass shapes this tree before any
/// address exists and answers [`TreePlacement::UNPLACED`] for every tree; the refill answers
/// with the addresses the shaping handed out. Both passes run this one function, so the keys,
/// the record sizes, and therefore the division into leaves are the same in each by
/// construction — only the three placement fields change, and a placement is the same bytes
/// whatever its values. The refill's shape assertion is what holds this to being true.
fn root_tree_records(
    placement: &dyn Fn(u64) -> TreePlacement,
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    options: &FormatOptions,
    compat_ro: CompatRoFlags,
) -> Vec<Record> {
    let node_size = u64::from(layout.node_size);
    let mut records: Vec<Record> = root_item_trees(compat_ro, model)
        .into_iter()
        .map(|id| {
            let placed = placement(id);
            // Only a subvolume has an identity and a creation to record. The trees a filesystem
            // keeps of its own carry a zero id and a zero time, which is not the same thing as
            // an unset field: they were not created, they were always there.
            let subvolume = model.subvolumes.iter().find(|sub| sub.id == id);
            let has_directory = subvolume.is_some() || id == objectid::DATA_RELOC_TREE;
            let zero = Timestamp::from_secs(0);
            Record {
                key: DiskKey::new(id, ItemType::ROOT_ITEM, 0),
                data: encode(RootItem::SIZE, |buf| {
                    RootItem {
                        generation: GENERATION,
                        root_dirid: if has_directory {
                            objectid::FIRST_FREE
                        } else {
                            0
                        },
                        bytenr: placed.root,
                        byte_limit: 0,
                        bytes_used: placed.bytes_used,
                        last_snapshot: 0,
                        flags: match subvolume {
                            Some(sub) if sub.read_only => RootFlags::SUBVOL_RDONLY,
                            _ => RootFlags::NONE,
                        },
                        refs: 1,
                        drop_progress: DiskKey::MIN,
                        drop_level: 0,
                        level: placed.level,
                        generation_v2: GENERATION,
                        uuid: subvolume.map_or([0; 16], |sub| sub.uuid),
                        parent_uuid: [0; 16],
                        received_uuid: [0; 16],
                        ctransid: 0,
                        otransid: 0,
                        stransid: 0,
                        rtransid: 0,
                        ctime: if subvolume.is_some() {
                            options.time
                        } else {
                            zero
                        },
                        otime: if subvolume.is_some() {
                            options.time
                        } else {
                            zero
                        },
                        stime: zero,
                        rtime: zero,
                    }
                    .write_to(buf);
                }),
            }
        })
        .collect();

    // Each subvolume beyond the top-level one, linked from both ends: the parent's tree names
    // the child, and the child's names the parent. Two records of one shape, keyed the two ways
    // round, so either question is one descent.
    for subvolume in &model.subvolumes {
        let Some(link) = &subvolume.link else {
            continue;
        };
        let head = RootRef {
            dirid: link.dir,
            sequence: link.index,
            name_len: link.name.len() as u16,
        };
        for (objectid, kind, offset) in [
            (link.parent, ItemType::ROOT_REF, subvolume.id),
            (subvolume.id, ItemType::ROOT_BACKREF, link.parent),
        ] {
            let mut data = encode(RootRef::SIZE, |buf| head.write_to(buf));
            data.extend_from_slice(&link.name);
            records.push(Record {
                key: DiskKey::new(objectid, kind, offset),
                data,
            });
        }
    }

    // The top-level subvolume's link back to the directory naming it. The format spells this
    // one as an `INODE_REF` in the root tree, where a subvolume created later gets the
    // `ROOT_REF`/`ROOT_BACKREF` pair instead.
    records.push(named_record(
        DiskKey::new(
            objectid::FS_TREE,
            ItemType::INODE_REF,
            objectid::ROOT_TREE_DIR,
        ),
        InodeRef {
            index: 0,
            name_len: SUBVOLUME_NAME.len() as u16,
        },
        SUBVOLUME_NAME,
    ));

    // The root tree's own directory: an inode, the name it has for its parent, and the entry
    // naming the top-level subvolume. There is no `DIR_INDEX` beside that entry — this
    // directory is never read in sequence, so it carries one record where a filesystem tree's
    // directory carries two.
    records.push(Record {
        key: DiskKey::new(objectid::ROOT_TREE_DIR, ItemType::INODE_ITEM, 0),
        data: encode(InodeItem::SIZE, |buf| {
            InodeItem {
                generation: GENERATION,
                transid: 0,
                size: 0,
                nbytes: node_size,
                block_group: 0,
                nlink: 1,
                uid: 0,
                gid: 0,
                mode: DIRECTORY_MODE,
                rdev: 0,
                flags: InodeFlags::NONE,
                sequence: 0,
                atime: options.time,
                ctime: options.time,
                mtime: options.time,
                otime: options.time,
            }
            .write_to(buf);
        }),
    });
    records.push(named_record(
        DiskKey::new(
            objectid::ROOT_TREE_DIR,
            ItemType::INODE_REF,
            objectid::ROOT_TREE_DIR,
        ),
        InodeRef {
            index: 0,
            name_len: PARENT_NAME.len() as u16,
        },
        PARENT_NAME,
    ));
    records.push(Record {
        key: DiskKey::new(
            objectid::ROOT_TREE_DIR,
            ItemType::DIR_ITEM,
            name_hash(SUBVOLUME_NAME),
        ),
        data: {
            let entry = DirItem {
                // Where a mount that was told no subvolume goes. The top-level one is named with
                // every bit of the offset set, which is how the format spells "the newest one"
                // for a key whose offset counts transactions; a subvolume named here instead is
                // named by its own root key, which is what changing the default writes.
                location: DiskKey::new(
                    model.default_subvolume,
                    ItemType::ROOT_ITEM,
                    if model.default_subvolume == objectid::FS_TREE {
                        u64::MAX
                    } else {
                        0
                    },
                ),
                transid: GENERATION,
                data_len: 0,
                name_len: SUBVOLUME_NAME.len() as u16,
                kind: DirEntryType::Dir,
            };
            let mut data = encode(DirItem::SIZE, |buf| entry.write_to(buf));
            data.extend_from_slice(SUBVOLUME_NAME);
            data
        },
    });
    sorted(records)
}

// ---------------------------------------------------------------------------
// Serialization

/// Lay every block of the filesystem down, then every superblock copy the device holds.
///
/// The superblocks come last because each names the trees, and a superblock naming a tree that
/// has not been written yet is what an interrupted run would otherwise leave behind: a device
/// that claims to hold a filesystem and does not.
fn write_filesystem<W: Write + Seek>(
    sink: W,
    prepared: &Prepared,
    options: &FormatOptions,
    volume_bytes: u64,
) -> Result<Slack, FormatError> {
    let Prepared { model, layout } = prepared;
    let (mut filesystem, data) = assemble(model, layout, options, volume_bytes)?;
    let mut sink = ByteSink::new(sink);
    let metadata_id = options.metadata_id();

    // The file data first, because writing it is what produces the checksums the checksum tree's
    // records were sized for. They are taken out of the tree and put back rather than filled in
    // place, so nothing here can move a leaf boundary the addresses were handed out against —
    // and the assertion that every one of them was filled is `CsumFill::finish`.
    let csum_at = filesystem
        .trees
        .iter()
        .position(|tree| tree.objectid == objectid::CSUM_TREE)
        .expect("every filesystem has a checksum tree");
    let mut csum_records = std::mem::take(&mut filesystem.trees[csum_at].records);
    let mut fill = CsumFill::new(&mut csum_records);
    write_data(&mut sink, model, layout, &data, &mut fill)?;
    fill.finish();
    filesystem.trees[csum_at].records = csum_records;

    let mut block = vec![0u8; layout.node_size as usize];
    for tree in &filesystem.trees {
        // Bottom up, so that each level is written knowing the lowest key of every block
        // beneath it — which is what an internal node records for each of its children.
        let mut below: Vec<DiskKey> = Vec::new();
        for (level, addresses) in tree.levels.iter().enumerate() {
            let mut keys = Vec::with_capacity(addresses.len());
            for (within, &address) in addresses.iter().enumerate() {
                block.fill(0);
                let header = Header {
                    csum: [0; CSUM_FIELD_LEN],
                    fsid: metadata_id,
                    bytenr: address,
                    flags: HEADER_FLAG_WRITTEN
                        | (u64::from(BACKREF_REV_MIXED) << BACKREF_REV_SHIFT),
                    chunk_tree_uuid: options.chunk_tree_uuid,
                    generation: GENERATION,
                    owner: tree.objectid,
                    nritems: 0,
                    level: level as u8,
                };
                keys.push(if level == 0 {
                    let from: usize = tree.shape.leaves[..within].iter().sum();
                    let records = &tree.records[from..from + tree.shape.leaves[within]];
                    write_leaf(&mut block, &header, records)
                } else {
                    let range = children_range(below.len(), addresses.len(), within);
                    let children: Vec<(DiskKey, u64)> = range
                        .clone()
                        .map(|at| (below[at], tree.levels[level - 1][at]))
                        .collect();
                    write_node(&mut block, &header, &children)
                });
                // A block goes to every copy of the logical space holding it, which is what
                // makes a replicated block group protect anything at all.
                for offset in copies_of(layout, address) {
                    sink.write_at(offset, &block)?;
                }
            }
            below = keys;
        }
    }

    let used_metadata = filesystem
        .allocation
        .blocks_of(layout, BlockGroupFlags::METADATA);
    let used_system = filesystem
        .allocation
        .blocks_of(layout, BlockGroupFlags::SYSTEM);
    let slack = layout.reservation.account(used_metadata, used_system)?;

    let superblock = superblock(&filesystem, model, layout, options, volume_bytes, slack);
    let backup = backup_of(&filesystem, &superblock);
    let mut bytes = vec![0u8; SUPER_INFO_SIZE];
    for &at in &layout.superblock_mirrors {
        bytes.fill(0);
        let mut copy = superblock.clone();
        // Each copy records where it lives, so a copy carved out of a disk at the wrong offset
        // says the wrong thing about itself however well its checksum verifies.
        copy.bytenr = at;
        copy.write_to(&mut bytes);
        backup.write_to(&mut bytes[RootBackup::offset_of(0).expect("the first of the ring")..]);
        seal(&mut bytes);
        sink.write_at(at, &bytes)?;
    }
    sink.extend_to(volume_bytes)?;
    Ok(slack)
}

/// Where each copy of the block at `logical` sits on the device.
///
/// Empty for an address no chunk covers, which nothing here reaches: every address handed out
/// came from a chunk of this same layout.
fn copies_of(layout: &BtrfsLayout, logical: u64) -> impl Iterator<Item = u64> + '_ {
    // The chunks are in ascending logical order with no overlap, so the covering chunk —
    // if any — is the first whose end is past the address, found by bisection. This is
    // the per-block step of the write path, and a scan of the whole list per block would
    // make writing quadratic in the chunk count.
    let at = layout
        .chunks
        .partition_point(|chunk| chunk.logical_end() <= logical);
    layout
        .chunks
        .get(at)
        .filter(|chunk| (chunk.logical..chunk.logical_end()).contains(&logical))
        .into_iter()
        .flat_map(move |chunk| {
            let within = logical - chunk.logical;
            chunk.copies.iter().map(move |copy| copy + within)
        })
}

/// Fill a leaf the way the format fills one: the item array growing forward from the header,
/// and the item data growing backward from the end of the block. Answers its lowest key.
fn write_leaf(block: &mut [u8], header: &Header, records: &[Record]) -> DiskKey {
    let mut head = *header;
    head.nritems = records.len() as u32;
    head.write_to(block);

    let mut data_end = block.len();
    for (index, record) in records.iter().enumerate() {
        data_end -= record.data.len();
        block[data_end..data_end + record.data.len()].copy_from_slice(&record.data);
        Item {
            key: record.key,
            offset: (data_end - Header::SIZE) as u32,
            size: record.data.len() as u32,
        }
        .write_to(&mut block[Header::SIZE + index * Item::SIZE..]);
    }
    assert!(
        Header::SIZE + records.len() * Item::SIZE <= data_end,
        "a leaf's item array and its data met, which the shaping exists to prevent"
    );
    seal(block);
    records.first().map_or(DiskKey::MIN, |record| record.key)
}

/// Fill an internal node with its children. Answers its lowest key, which is its first child's.
fn write_node(block: &mut [u8], header: &Header, children: &[(DiskKey, u64)]) -> DiskKey {
    assert!(
        Header::SIZE + children.len() * KeyPtr::SIZE <= block.len(),
        "an internal node was given more children than a block holds, which the fan-out the          shaping divided by exists to prevent"
    );
    let mut head = *header;
    head.nritems = children.len() as u32;
    head.write_to(block);
    for (index, &(key, blockptr)) in children.iter().enumerate() {
        KeyPtr {
            key,
            blockptr,
            generation: GENERATION,
        }
        .write_to(&mut block[Header::SIZE + index * KeyPtr::SIZE..]);
    }
    seal(block);
    children.first().map_or(DiskKey::MIN, |&(key, _)| key)
}

/// The superblock describing the finished filesystem.
fn superblock(
    filesystem: &Filesystem,
    model: &BtrfsModel,
    layout: &BtrfsLayout,
    options: &FormatOptions,
    volume_bytes: u64,
    slack: Slack,
) -> SuperBlock {
    let root = filesystem.tree(objectid::ROOT_TREE);
    let chunk = filesystem.tree(objectid::CHUNK_TREE);
    let spent = layout.reservation.metadata_blocks + layout.reservation.system_blocks
        - slack.metadata_blocks
        - slack.system_blocks;
    let data_bytes = filesystem
        .allocation
        .bytes_of(layout, BlockGroupFlags::DATA);

    let mut array = [0u8; SYS_CHUNK_ARRAY_SIZE];
    let mut array_len = 0usize;
    for mapped in layout.chunks_of(BlockGroupFlags::SYSTEM) {
        // The bootstrap carries the system chunks and only those: they are what the chunk
        // tree's own address is translated through, and nothing else can be read until it has
        // been.
        let record = chunk_record(layout, options, mapped);
        DiskKey::new(
            objectid::FIRST_CHUNK_TREE,
            ItemType::CHUNK_ITEM,
            mapped.logical,
        )
        .write_to(&mut array[array_len..]);
        array_len += DiskKey::SIZE;
        array[array_len..array_len + record.len()].copy_from_slice(&record);
        array_len += record.len();
    }

    let mut incompat = layout.incompat_flags;
    if options.distinct_metadata_uuid().is_some() {
        incompat |= IncompatFlags::METADATA_UUID;
    }
    // The bit says a mount that was told no subvolume does not land on the top-level tree. It
    // follows from what the root tree's directory ends up naming rather than from a request,
    // which is why it is set here and not among the words the planner validates.
    if model.default_subvolume != objectid::FS_TREE {
        incompat |= IncompatFlags::DEFAULT_SUBVOL;
    }
    SuperBlock {
        csum: [0; CSUM_FIELD_LEN],
        fsid: options.fsid,
        bytenr: MIRRORS[0],
        flags: SuperFlags::from_bits(HEADER_FLAG_WRITTEN),
        magic: MAGIC,
        generation: GENERATION,
        root: root.root(),
        chunk_root: chunk.root(),
        log_root: 0,
        total_bytes: volume_bytes,
        // Logical bytes rather than device bytes: what a replicated block group costs the
        // device is the device record's business, and this is the filesystem's. Both kinds are
        // counted — a filesystem's used bytes are its metadata and its data.
        bytes_used: spent * u64::from(layout.node_size) + data_bytes,
        root_dir_objectid: objectid::ROOT_TREE_DIR,
        num_devices: 1,
        sectorsize: layout.sector_size,
        nodesize: layout.node_size,
        stripesize: layout.sector_size,
        sys_chunk_array_size: array_len as u32,
        chunk_root_generation: GENERATION,
        compat_flags: CompatFlags::NONE,
        compat_ro_flags: layout.compat_ro_flags,
        incompat_flags: incompat,
        csum_type: ChecksumType::CRC32C,
        root_level: root.shape.level(),
        chunk_root_level: chunk.shape.level(),
        log_root_level: 0,
        dev_item: device_item(layout, options, volume_bytes),
        label: options.label.field(),
        cache_generation: if layout
            .compat_ro_flags
            .contains(CompatRoFlags::FREE_SPACE_TREE)
        {
            0
        } else {
            NO_FREE_SPACE_CACHE
        },
        uuid_tree_generation: 0,
        metadata_uuid: options.distinct_metadata_uuid().unwrap_or([0; 16]),
        nr_global_roots: 0,
        remap_root: 0,
        remap_root_generation: 0,
        remap_root_level: 0,
        sys_chunk_array: array,
    }
}

/// The one backup record a filesystem with one transaction has.
///
/// The superblock's ring holds four, and three of them stay zero: a filesystem that has
/// committed once has one state to remember, and filling the ring would claim three
/// transactions that did not happen. A driver picking the newest finds the one that is there.
fn backup_of(filesystem: &Filesystem, sb: &SuperBlock) -> RootBackup {
    let root_of = |id: u64| filesystem.tree(id).root();
    let level_of = |id: u64| filesystem.tree(id).shape.level();
    RootBackup {
        tree_root: sb.root,
        tree_root_gen: GENERATION,
        chunk_root: sb.chunk_root,
        chunk_root_gen: GENERATION,
        extent_root: root_of(objectid::EXTENT_TREE),
        extent_root_gen: GENERATION,
        fs_root: root_of(objectid::FS_TREE),
        fs_root_gen: GENERATION,
        dev_root: root_of(objectid::DEV_TREE),
        dev_root_gen: GENERATION,
        csum_root: root_of(objectid::CSUM_TREE),
        csum_root_gen: GENERATION,
        total_bytes: sb.total_bytes,
        bytes_used: sb.bytes_used,
        num_devices: sb.num_devices,
        tree_root_level: sb.root_level,
        chunk_root_level: sb.chunk_root_level,
        extent_root_level: level_of(objectid::EXTENT_TREE),
        fs_root_level: level_of(objectid::FS_TREE),
        dev_root_level: level_of(objectid::DEV_TREE),
        csum_root_level: level_of(objectid::CSUM_TREE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::forge::Sparse;
    use crate::btrfs::ondisk::{CompatRoFlags, Header, ItemType, SuperBlock};
    use crate::btrfs::{
        DEFAULT_COMPAT_RO, DEFAULT_INCOMPAT, Mirror, NodeSize, Profile, Reader, SectorSize, Volume,
    };
    use crate::source::{Metadata, TreeBuilder};

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    /// The instant every image here is stamped with, so nothing depends on a clock.
    const TIME: Timestamp = Timestamp {
        secs: 1_786_472_859,
        nanos: 0,
    };

    /// Options whose four identifiers each hold a distinct value, so a field written from the
    /// wrong one is visible rather than a coincidence of zeros.
    fn options() -> FormatOptions {
        FormatOptions::new([0x11; 16], TIME)
            .chunk_tree_uuid([0x22; 16])
            .device_uuid([0x33; 16])
            .subvolume_uuid([0x44; 16])
    }

    /// The model a source implies, at the defaults every image here is written with.
    fn model_of(source: impl crate::Source) -> BtrfsModel {
        build_model(source.into_entries(), &[], None, [0; 16], 4096, 16384, TIME)
            .expect("a buildable tree")
    }

    /// An image of `bytes`, planned through `plan`.
    fn image_of(bytes: u64, plan: PlanRequest) -> Image {
        format(TreeBuilder::new(), bytes, options().plan(plan)).expect("a volume past the minimum")
    }

    /// A volume opened over an image, which verifies every block it reaches on the way.
    fn opened(image: &Image) -> Volume<Cursor<&[u8]>> {
        Volume::open(Cursor::new(image.as_bytes())).expect("this crate reads what it wrote")
    }

    #[test]
    fn every_tree_the_format_defines_is_written_and_reachable() {
        let image = image_of(GIB, PlanRequest::new(0));
        let mut volume = opened(&image);
        let mut found: Vec<u64> = volume
            .tree_roots()
            .expect("the root tree")
            .iter()
            .map(|root| root.objectid)
            .collect();
        found.sort_unstable();
        let mut wanted = vec![objectid::ROOT_TREE, objectid::CHUNK_TREE];
        wanted.extend(root_item_trees(
            image.layout().compat_ro_flags,
            &model_of(TreeBuilder::new()),
        ));
        wanted.sort_unstable();
        assert_eq!(found, wanted);

        // Reaching a tree is not reading it. Every block of every tree is walked, which is
        // what verifies each one's checksum and each one's claim about its own address.
        for root in volume.tree_roots().expect("the root tree") {
            volume
                .tree(root)
                .count_items()
                .unwrap_or_else(|e| panic!("tree {} does not read back: {e}", root.objectid));
        }
    }

    #[test]
    fn the_filesystem_reads_back_as_one_empty_directory_owned_by_root() {
        let image = image_of(GIB, PlanRequest::new(0));
        let mut reader =
            Reader::open(Cursor::new(image.as_bytes())).expect("this crate reads what it wrote");
        let root = reader.root().expect("a root directory");
        assert_eq!(root.item.mode, DIRECTORY_MODE);
        assert_eq!((root.item.uid, root.item.gid), (0, 0));
        assert_eq!(root.item.mtime, TIME, "the instant the options named");
        assert_eq!(root.item.otime, TIME, "including the birth time");
        // A walk yields the root itself and then what is under it, so an empty filesystem is
        // one entry rather than none.
        let walked = reader.walk().expect("a walk of an empty tree");
        assert_eq!(walked.len(), 1, "{:?}", walked);
        assert!(
            walked[0].path.is_empty(),
            "the root is the path of no components"
        );

        // One subvolume, the top-level one, carrying the id and the creation the options named.
        assert_eq!(reader.subvolumes().len(), 1);
        let subvolume = &reader.subvolumes()[0];
        assert_eq!(subvolume.id, objectid::FS_TREE);
        assert_eq!(subvolume.uuid, [0x44; 16]);
        assert_eq!(subvolume.otime, TIME);
        assert!(!subvolume.read_only);
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
    }

    #[test]
    fn two_formats_of_one_parameter_set_are_the_same_bytes() {
        // The whole of the reproducibility claim: nothing here consults a clock or a random
        // source, so the only inputs are the ones a caller stated.
        let first = image_of(GIB, PlanRequest::new(0));
        let second = image_of(GIB, PlanRequest::new(0));
        assert_eq!(first.as_bytes(), second.as_bytes());

        // And an identifier that differs produces bytes that differ, which is what says the
        // inputs are inputs rather than ignored.
        let other = format(
            TreeBuilder::new(),
            GIB,
            options().subvolume_uuid([0x45; 16]),
        )
        .expect("formattable");
        assert_ne!(first.as_bytes(), other.as_bytes());
    }

    #[test]
    fn a_name_reaches_every_superblock_copy_and_reads_back_as_the_bytes_it_was_given() {
        // A label is stored once per copy and nowhere else, so what a driver sees depends on
        // which copy it read — and a copy carrying a different name from its neighbours is a
        // filesystem with two names. A gibibyte reaches past the second copy at 64 MiB, which
        // is why the size is not the smallest one that formats.
        let label = VolumeLabel::from_bytes("système de fichiers".as_bytes()).expect("a label");
        let image = format(TreeBuilder::new(), GIB, options().label(label))
            .expect("a volume past the minimum");
        let copies = &image.layout().superblock_mirrors;
        assert_eq!(copies.len(), 2, "one copy proves nothing here");
        for &at in copies {
            let at = at as usize;
            let sb = SuperBlock::read_from(&image.as_bytes()[at..at + SUPER_INFO_SIZE])
                .expect("a superblock at every copy");
            assert_eq!(sb.label_bytes(), label.as_bytes());
        }

        // And an unnamed filesystem is the field's padding rather than a name of no bytes that
        // reads back as something: the two are the same on disk and the reader says so.
        let plain = image_of(GIB, PlanRequest::new(0));
        assert_eq!(opened(&plain).superblock().label_bytes(), b"");
    }

    #[test]
    fn a_filesystem_with_two_ids_stamps_its_blocks_and_its_device_with_the_second() {
        // The id a person sees and the id the metadata carries are two fields for one reason:
        // changing the first must not mean rewriting every block. So every tree block carries
        // the second — and so does the *device* record, which lives in the chunk tree and is
        // part of the metadata rather than part of what a person sees. A writer that stamped
        // the device with the visible id produces a filesystem whose own checker refuses to
        // open it, and no checksum notices: both values are inside what the checksums cover.
        const VISIBLE: [u8; 16] = [0x11; 16];
        const METADATA: [u8; 16] = [0x77; 16];
        let image = format(
            TreeBuilder::new(),
            GIB,
            options().metadata_uuid(Some(METADATA)),
        )
        .expect("a volume past the minimum");

        let mut volume = opened(&image);
        let sb = volume.superblock();
        assert_eq!(sb.fsid, VISIBLE);
        assert_eq!(sb.metadata_uuid, METADATA);
        assert_eq!(
            sb.dev_item.fsid, METADATA,
            "the device belongs to the metadata"
        );
        assert!(sb.incompat_flags.contains(IncompatFlags::METADATA_UUID));

        for root in volume.tree_roots().expect("the trees") {
            let block = volume.read_block(root.bytenr).expect("a tree block");
            assert_eq!(
                block.header().fsid,
                METADATA,
                "tree {} is stamped with the visible id",
                root.objectid
            );
        }

        // And a filesystem whose two ids are one does not carry the feature that distinguishes
        // them, which is the state every btrfs is in until somebody changes its id.
        let plain = image_of(GIB, PlanRequest::new(0));
        let sb = opened(&plain).superblock().clone();
        assert_eq!(sb.dev_item.fsid, VISIBLE);
        assert_eq!(sb.metadata_uuid, [0; 16]);
        assert!(!sb.incompat_flags.contains(IncompatFlags::METADATA_UUID));

        // A metadata id stated explicitly and equal to the filesystem's describes that same
        // one-id state, and is written as it: the format's own tooling clears the bit for
        // equal ids, and a filesystem carrying the bit over two equal ids is a state no
        // driver produces.
        let stated = format(
            TreeBuilder::new(),
            GIB,
            options().metadata_uuid(Some(VISIBLE)),
        )
        .expect("a volume past the minimum");
        let sb = opened(&stated).superblock().clone();
        assert_eq!(sb.metadata_uuid, [0; 16]);
        assert!(!sb.incompat_flags.contains(IncompatFlags::METADATA_UUID));
        assert_eq!(stated.as_bytes(), plain.as_bytes(), "the same filesystem");
    }

    #[test]
    fn a_name_the_field_cannot_hold_is_refused_rather_than_cut_short() {
        // The terminator has to fit, because a reader stops at the first NUL: a label filling
        // the whole field would come back as itself only for a reader that counts rather than
        // terminates, and the two would disagree about one filesystem.
        assert!(VolumeLabel::from_bytes(&[b'a'; VolumeLabel::MAX_BYTES]).is_ok());
        assert!(matches!(
            VolumeLabel::from_bytes(&[b'a'; VolumeLabel::MAX_BYTES + 1]),
            Err(LabelError::TooLong { bytes, limit })
                if bytes == VolumeLabel::MAX_BYTES + 1 && limit == VolumeLabel::MAX_BYTES
        ));
        // A NUL inside a name is the padding byte, so a name holding one is a name that comes
        // back shorter than it went in.
        assert!(matches!(
            VolumeLabel::from_bytes(b"ro\0ot"),
            Err(LabelError::NulByte { at: 2 })
        ));
    }

    #[test]
    fn a_streamed_image_is_the_collected_one_and_touches_only_what_it_writes() {
        // Both an empty filesystem and one with a tree in it, because the streaming entry point
        // gained a second pass when it gained content: the file data is written before any tree
        // block is, and a collected image is the one place the two orders can be held together.
        for source in [TreeBuilder::new(), populated()] {
            let collected =
                format(source.clone(), GIB, options()).expect("a volume past the minimum");
            let mut streamed = Cursor::new(vec![0u8; GIB as usize]);
            let layout = format_to(&mut streamed, source, GIB, options()).expect("formattable");
            assert_eq!(&streamed.into_inner()[..], collected.as_bytes());
            assert_eq!(&layout, collected.layout());
        }
    }

    #[test]
    fn every_block_records_the_address_it_was_written_to_and_the_filesystem_it_belongs_to() {
        // The two checks no checksum can make: a block written to the wrong place, and a block
        // from another filesystem, both verify perfectly and say the wrong thing about
        // themselves. Every block this writer emits is held to both.
        let image = image_of(GIB, PlanRequest::new(0));
        let mut volume = opened(&image);
        let roots = volume.tree_roots().expect("the root tree");
        let node_size = image.layout().node_size as usize;
        for root in roots {
            let block = volume.read_block(root.bytenr).expect("a tree block");
            let header = Header::read_from(block.bytes()).expect("a header");
            assert_eq!(header.bytenr, root.bytenr);
            assert_eq!(
                header.fsid, [0x11; 16],
                "the filesystem id, not the chunk's"
            );
            assert_eq!(header.chunk_tree_uuid, [0x22; 16]);
            assert_eq!(header.generation, GENERATION);
            assert_eq!(block.bytes().len(), node_size);
        }
    }

    #[test]
    fn every_superblock_copy_the_device_holds_is_written_and_says_where_it_is() {
        // A volume of a quarter of a terabyte plus one superblock is the smallest that carries
        // all three, and the streaming entry point is what makes writing one affordable: only
        // the blocks the filesystem occupies are touched.
        let bytes = (256 << 30) + SUPER_INFO_SIZE as u64;
        let mut sink = Sparse::new(bytes);
        let layout =
            format_to(&mut sink, TreeBuilder::new(), bytes, options()).expect("formattable");
        assert_eq!(layout.superblock_mirrors, MIRRORS);

        for &at in &layout.superblock_mirrors {
            let sb = SuperBlock::read_from(&sink.read_at(at, SUPER_INFO_SIZE))
                .expect("a superblock at every mirror");
            assert_eq!(sb.bytenr, at, "a copy records where it lives");
            assert_eq!(sb.generation, GENERATION);
            assert_eq!(sb.total_bytes, bytes);
        }
        // Read back through the reader, which chooses among the copies and reports on each.
        let volume = Volume::open(sink).expect("readable");
        assert!(
            volume.mirrors().iter().all(|mirror| matches!(
                mirror,
                Mirror::Present {
                    generation: GENERATION
                }
            )),
            "every copy is a superblock at the one transaction: {:?}",
            volume.mirrors()
        );
    }

    #[test]
    fn a_replicated_block_group_holds_every_copy_of_every_block_it_covers() {
        // What makes `DUP` protect anything: a block is written to each copy of the logical
        // space holding it. A writer that wrote the first copy only would produce a filesystem
        // that reads perfectly until the sector under the first copy fails.
        let image = image_of(GIB, PlanRequest::new(0).metadata_profile(Profile::Dup));
        let layout = image.layout();
        let node_size = layout.node_size as usize;
        let metadata = layout
            .chunks_of(crate::btrfs::ondisk::BlockGroupFlags::METADATA)
            .next()
            .expect("a metadata chunk");
        assert_eq!(metadata.copies.len(), 2, "the profile asked for two");
        let bytes = image.as_bytes();
        let first = metadata.copies[0] as usize;
        let second = metadata.copies[1] as usize;
        assert_eq!(
            &bytes[first..first + node_size],
            &bytes[second..second + node_size],
            "the two copies of the first metadata block are not the same bytes"
        );
    }

    #[test]
    fn the_reservation_covers_what_the_writer_spends_and_the_slack_is_reported() {
        for node in [4096u32, 16384, 65536] {
            let image = image_of(GIB, PlanRequest::new(0).node_size(NodeSize::Bytes(node)));
            let slack = image.slack();
            let reservation = image.layout().reservation;
            assert!(
                slack.metadata_blocks < reservation.metadata_blocks,
                "node {node}: a filesystem that spent nothing is not a filesystem"
            );
            // The chunk tree is one leaf on a volume this size, so the system pool is spent
            // exactly once whatever the node size.
            assert_eq!(slack.system_blocks, reservation.system_blocks - 1);
        }
    }

    #[test]
    fn the_root_tree_grows_a_level_where_a_node_is_too_small_to_hold_it() {
        // Eight root items of 439 bytes plus the root directory's four records overflow a
        // four-kilobyte block and fit a sixteen-kilobyte one, so the same filesystem is two
        // levels deep at one node size and one at the next. The level a tree reports and the
        // level the superblock records are two separate fields and both are asserted.
        for (node, level) in [(4096u32, 1u8), (16384, 0), (65536, 0)] {
            let image = image_of(GIB, PlanRequest::new(0).node_size(NodeSize::Bytes(node)));
            let volume = opened(&image);
            assert_eq!(
                volume.superblock().root_level,
                level,
                "the root tree at a {node}-byte node"
            );
            assert_eq!(volume.superblock().nodesize, node);
        }
    }

    #[test]
    fn the_extent_tree_records_every_block_of_every_tree_including_its_own() {
        // The circularity, checked from the outside: one record per allocated tree block, each
        // keyed by the block's address and its level, and each naming the tree that owns it.
        // A writer that forgot its own blocks would produce a filesystem whose extent tree the
        // checker rejects for a missing backref, so this is where that is caught without one.
        for node in [4096u32, 16384] {
            let image = image_of(GIB, PlanRequest::new(0).node_size(NodeSize::Bytes(node)));
            let mut volume = opened(&image);
            let roots = volume.tree_roots().expect("the root tree");
            let extent = roots
                .iter()
                .find(|root| root.objectid == objectid::EXTENT_TREE)
                .copied()
                .expect("an extent tree");

            let mut recorded = Vec::new();
            volume
                .tree(extent)
                .for_each_item(|key, _| {
                    if key.kind == ItemType::METADATA_ITEM {
                        recorded.push((key.objectid, key.offset as u8));
                    }
                    true
                })
                .expect("the extent tree reads back");
            recorded.sort_unstable();

            // Every block the filesystem has, gathered independently: walk each tree and take
            // the address and level of every block it holds.
            let mut allocated = Vec::new();
            for root in &roots {
                volume
                    .tree(*root)
                    .for_each_block(|block| {
                        let header = Header::read_from(block.bytes()).expect("a header");
                        allocated.push((header.bytenr, header.level));
                        true
                    })
                    .expect("every tree reads back");
            }
            allocated.sort_unstable();
            allocated.dedup();
            assert_eq!(recorded, allocated, "at a {node}-byte node");
        }
    }

    #[test]
    fn the_free_space_tree_accounts_for_every_byte_of_every_block_group() {
        // What is used and what is free are two records of one fact, so a filesystem whose
        // block-group item and free-space run disagree is one a driver allocates over its own
        // metadata from. The two are written from a single account and this is what says so.
        let image = image_of(GIB, PlanRequest::new(0));
        let layout = image.layout();
        let mut volume = opened(&image);
        let roots = volume.tree_roots().expect("the root tree");
        let free_space = roots
            .iter()
            .find(|root| root.objectid == objectid::FREE_SPACE_TREE)
            .copied()
            .expect("a free-space tree");

        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut infos: Vec<(u64, u64, u32)> = Vec::new();
        volume
            .tree(free_space)
            .for_each_item(|key, data| {
                if key.kind == ItemType::FREE_SPACE_EXTENT {
                    runs.push((key.objectid, key.offset));
                } else if key.kind == ItemType::FREE_SPACE_INFO {
                    let info = FreeSpaceInfo::read_from(data).expect("a free-space record");
                    infos.push((key.objectid, key.offset, info.extent_count));
                }
                true
            })
            .expect("the free-space tree reads back");

        assert_eq!(
            infos.len(),
            layout.chunks.len(),
            "one record per block group"
        );
        for (index, chunk) in layout.chunks.iter().enumerate() {
            let (start, length, count) = infos[index];
            assert_eq!((start, length), (chunk.logical, chunk.length));
            assert_eq!(count, 1, "a block group written once has one free run");
            let (run_start, run_length) = runs[index];
            assert!(run_start >= chunk.logical && run_start < chunk.logical_end());
            assert_eq!(
                run_start + run_length,
                chunk.logical_end(),
                "the free run reaches the end of its block group"
            );
        }
    }

    #[test]
    fn every_combination_of_the_knobs_produces_a_filesystem_this_crate_reads_back() {
        // A sweep rather than a list, because the riskiest thing here is the one part that is
        // not a straight derivation: the layout is laid out again whenever the extent tree
        // turns out to need a different number of blocks than the round assumed, and the three
        // trees whose records name addresses are re-made against a shape that was fixed before
        // those addresses existed. Both are asserted from the inside — the round count is
        // bounded and `refill` asserts the shape survived — and neither is exercised by a
        // parameter set somebody chose.
        //
        // It costs what it writes rather than what it claims: the destination is the sparse
        // device, so a three-hundred-gibibyte volume in this list is a few hundred kibibytes of
        // pages.
        let mut formatted = 0usize;
        let mut refused = 0usize;
        for volume in [45 * MIB, 229 * MIB, GIB, 17 * GIB, 300 * GIB] {
            for sector in [4096u32, 16384, 65536] {
                for node in [4096u32, 16384, 65536] {
                    if node < sector {
                        continue;
                    }
                    for metadata in [Profile::Single, Profile::Dup] {
                        for data in [Profile::Single, Profile::Dup] {
                            for compat_ro in [
                                DEFAULT_COMPAT_RO,
                                DEFAULT_COMPAT_RO.without(CompatRoFlags::BLOCK_GROUP_TREE),
                                CompatRoFlags::NONE,
                            ] {
                                let plan = PlanRequest::new(0)
                                    .sector_size(SectorSize::Bytes(sector))
                                    .node_size(NodeSize::Bytes(node))
                                    .metadata_profile(metadata)
                                    .data_profile(data)
                                    .features(DEFAULT_INCOMPAT, compat_ro);
                                let what = format!(
                                    "{volume} bytes, {sector}-byte sector, {node}-byte node,                                      {metadata:?}/{data:?}, compat_ro {:#x}",
                                    compat_ro.bits()
                                );
                                let mut sink = Sparse::new(volume);
                                match format_to(
                                    &mut sink,
                                    TreeBuilder::new(),
                                    volume,
                                    options().plan(plan),
                                ) {
                                    // A volume below what these profiles fit in is the one
                                    // refusal this sweep expects, and it is typed.
                                    Err(FormatError::Geometry(_)) => {
                                        refused += 1;
                                        continue;
                                    }
                                    Err(e) => panic!("{what}: {e}"),
                                    Ok(_) => formatted += 1,
                                }
                                let mut volume_read = Volume::open(sink.clone())
                                    .unwrap_or_else(|e| panic!("{what}: {e}"));
                                let roots = volume_read
                                    .tree_roots()
                                    .unwrap_or_else(|e| panic!("{what}: {e}"));
                                for root in roots {
                                    volume_read.tree(root).count_items().unwrap_or_else(|e| {
                                        panic!(
                                            "{what}: tree {} does not read back: {e}",
                                            root.objectid
                                        )
                                    });
                                }
                                // And the filesystem view over the same bytes finds nothing to
                                // report. A scan walks every tree and names every record it has
                                // no opinion about, so this is where a writer emitting a record
                                // its own reader does not recognize would say so.
                                let mut reader =
                                    Reader::open(sink).unwrap_or_else(|e| panic!("{what}: {e}"));
                                let report = reader.scan();
                                assert!(report.is_clean(), "{what}: {:?}", report.anomalies());
                            }
                        }
                    }
                }
            }
        }
        // The sweep's own yield guard: a change that made most of the space unformattable
        // would leave this green and vacuous.
        assert!(
            formatted > refused,
            "only {formatted} of {} combinations produced a filesystem",
            formatted + refused
        );
    }

    #[test]
    fn a_volume_too_small_for_its_profiles_is_refused_before_anything_is_written() {
        let mut sink = Cursor::new(Vec::new());
        let err = format_to(&mut sink, TreeBuilder::new(), 8 * MIB, options())
            .expect_err("far below the minimum");
        assert!(matches!(err, FormatError::Geometry(_)), "{err}");
        assert!(
            sink.into_inner().is_empty(),
            "a destination is not touched by a format that could not have succeeded"
        );
    }

    #[test]
    fn a_record_larger_than_a_leaf_is_refused_rather_than_split() {
        // Unreachable from an empty filesystem, whose largest record is a 439-byte root item.
        // The guard is what a leaf's packing rests on: without it, a record no leaf can hold
        // would be placed in one anyway and the item array would run into its own data.
        let node = 4096u32;
        let records = vec![Record {
            key: DiskKey::MIN,
            data: vec![0; node as usize],
        }];
        assert!(matches!(
            shape(&records, node),
            Err(FormatError::RecordTooLarge { .. })
        ));
    }

    #[test]
    fn a_tree_with_nothing_in_it_is_one_empty_leaf_rather_than_no_blocks() {
        // The checksum tree of an empty filesystem. A tree still has a root, and a root item
        // pointing at no block is a filesystem a driver cannot mount.
        let empty = shape(&[], 16384).expect("shapeable");
        assert_eq!(empty.blocks(), 1);
        assert_eq!(empty.level(), 0);
        assert_eq!(empty.leaves, vec![0]);
    }

    #[test]
    fn leaves_are_packed_full_rather_than_left_half_empty() {
        // What a tree built all at once arrives at, and the divergence from a tree grown by
        // inserting one record at a time: every leaf but the last is as full as the next
        // record allows.
        let node = 4096u32;
        let records: Vec<Record> = (0..200)
            .map(|n| Record {
                key: DiskKey::new(n, ItemType::INODE_ITEM, 0),
                data: vec![0; 100],
            })
            .collect();
        let shaped = shape(&records, node).expect("shapeable");
        let capacity = node as usize - Header::SIZE;
        for (index, count) in shaped.leaves.iter().enumerate() {
            let used = count * (100 + Item::SIZE);
            if index + 1 < shaped.leaves.len() {
                assert!(
                    used + 100 + Item::SIZE > capacity,
                    "leaf {index} had room for another record"
                );
            }
            assert!(used <= capacity);
        }
        assert_eq!(shaped.leaves.iter().sum::<usize>(), 200);
    }

    // -----------------------------------------------------------------------
    // A source written into a filesystem

    /// A tree exercising every kind of entry a source can state, so one round trip covers the
    /// whole vocabulary rather than the parts that were easy to write.
    fn populated() -> TreeBuilder {
        let meta = Metadata::new(0o644, TIME).owned_by(1000, 100);
        let dir = Metadata::new(0o755, TIME);
        TreeBuilder::new()
            .directory(b"/dir".to_vec(), dir)
            .file(b"/dir/one".to_vec(), b"x", meta)
            .hardlink(b"/dir/two".to_vec(), b"/dir/one".to_vec(), meta)
            .symlink(b"/dir/link".to_vec(), b"/small.txt".to_vec(), meta)
            .symlink(b"/dir/up".to_vec(), b"../small.txt".to_vec(), meta)
            .file(b"/small.txt".to_vec(), b"hello\n", meta)
            .xattr(b"user.note".to_vec(), b"hi".to_vec())
            // Larger than one extent, and not a whole number of sectors: the two cases whose
            // extent records differ from the simple one.
            .file(b"/big.bin".to_vec(), vec![7u8; (1 << 20) + 5000], meta)
            .file(b"/empty".to_vec(), Vec::new(), meta)
            .char_device(b"/nulldev".to_vec(), 1, 3, meta)
            .block_device(b"/disk".to_vec(), 8, 0, meta)
            .fifo(b"/pipe".to_vec(), meta)
            .socket(b"/sock".to_vec(), meta)
    }

    /// An image of `bytes` holding `source`.
    fn filled(source: impl crate::Source, bytes: u64) -> Image {
        format(source, bytes, options()).expect("a formattable tree")
    }

    /// A reader over an image, which verifies every block it reaches on the way.
    fn read(image: &Image) -> Reader<Cursor<&[u8]>> {
        Reader::open(Cursor::new(image.as_bytes())).expect("this crate reads what it wrote")
    }

    #[test]
    fn every_kind_of_entry_a_source_states_reads_back_as_what_it_was() {
        let image = filled(populated(), GIB);
        let mut reader = read(&image);

        // The tree, path for path. A walk yields the root first, and the rest in the order the
        // directories hold them.
        let mut paths: Vec<String> = reader
            .walk()
            .expect("a walk")
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.path).into_owned())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                "",
                "/big.bin",
                "/dir",
                "/dir/link",
                "/dir/one",
                "/dir/two",
                "/dir/up",
                "/disk",
                "/empty",
                "/nulldev",
                "/pipe",
                "/small.txt",
                "/sock"
            ]
        );

        // Ownership and mode, on the entry that states something other than the default.
        let small = reader.lookup(b"/small.txt").expect("the file is there");
        assert_eq!(small.item.mode & 0o7777, 0o644);
        assert_eq!((small.item.uid, small.item.gid), (1000, 100));
        assert_eq!(small.item.mtime, TIME);
        // No source carries a birth time, so the modification time stands for it — which is what
        // makes a read of this image hand back what the source stated rather than an epoch.
        assert_eq!(small.item.otime, TIME);
        assert_eq!(reader.read_data(&small).expect("bytes"), b"hello\n");
        let xattrs = reader.xattrs(&small).expect("attributes");
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].name, b"user.note");
        assert_eq!(xattrs[0].value, b"hi");

        // A file of more than one extent, and of a length that is not a whole sector.
        let big = reader.lookup(b"/big.bin").expect("the file is there");
        let bytes = reader.read_data(&big).expect("bytes");
        assert_eq!(bytes.len(), (1 << 20) + 5000);
        assert!(bytes.iter().all(|&b| b == 7));
        // And a read from the middle of it, which is the case a forward-only search gets wrong.
        let mut middle = [0u8; 16];
        reader
            .read_into(&big, (1 << 20) + 8, &mut middle)
            .expect("a read past the first extent");
        assert_eq!(middle, [7u8; 16]);

        // A file of no bytes has no extent record at all, and reads back as nothing.
        let empty = reader.lookup(b"/empty").expect("the file is there");
        assert_eq!(empty.item.size, 0);
        assert!(reader.read_data(&empty).expect("bytes").is_empty());

        // A link is followed by a lookup and read whole by another, and the two must agree about
        // what is there.
        let link = reader
            .lookup_no_follow(b"/dir/link")
            .expect("the link is there");
        assert!(link.is_symlink());
        assert_eq!(reader.link_target(&link).expect("target"), b"/small.txt");
        assert_eq!(
            reader.lookup(b"/dir/link").expect("through the link").inode,
            reader.lookup(b"/small.txt").expect("the target").inode
        );
        // A relative target comes back exactly as it was stated, `..` and all — the bytes of a
        // link are its content and nothing here interprets them.
        let up = reader
            .lookup_no_follow(b"/dir/up")
            .expect("the link is there");
        assert_eq!(reader.link_target(&up).expect("target"), b"../small.txt");

        // Two names, one inode, and a link count that says two.
        let one = reader.lookup(b"/dir/one").expect("the file is there");
        let two = reader.lookup(b"/dir/two").expect("the second name");
        assert_eq!(one.inode, two.inode);
        assert_eq!(one.item.nlink, 2);
        assert_eq!(reader.read_data(&two).expect("bytes"), b"x");

        // The nodes that are neither files nor directories, each with the identity it was given.
        let device = reader.lookup(b"/nulldev").expect("the node is there");
        assert_eq!(device.item.device(), (1, 3));
        assert_eq!(device.item.mode & 0o170_000, 0o020_000);
        let disk = reader.lookup(b"/disk").expect("the node is there");
        assert_eq!(disk.item.device(), (8, 0));
        assert_eq!(disk.item.mode & 0o170_000, 0o060_000);
        assert_eq!(
            reader.lookup(b"/pipe").expect("the node").item.mode & 0o170_000,
            0o010_000
        );
        assert_eq!(
            reader.lookup(b"/sock").expect("the node").item.mode & 0o170_000,
            0o140_000
        );

        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
    }

    #[test]
    fn every_byte_written_verifies_against_the_checksum_written_beside_it() {
        // The gate no other family here has: a data checksum covers the bytes, so a writer that
        // built a correct checksum tree over the wrong ones — or the right ones under the wrong
        // address — is caught by nothing else this crate does.
        let image = filled(populated(), GIB);
        let mut reader = read(&image);
        for entry in reader.walk().expect("a walk") {
            if entry.node.is_file() {
                reader
                    .verify_data(&entry.node)
                    .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(&entry.path)));
            }
        }

        // And a byte of the data altered is caught, which is what says the check above is a
        // check rather than a comparison of a value with itself.
        let mut bytes = image.into_bytes();
        let at = image_data_offset(&bytes);
        bytes[at] ^= 0xff;
        let mut reader = Reader::open(Cursor::new(&bytes[..])).expect("still readable");
        let big = reader.lookup(b"/big.bin").expect("the file is there");
        assert!(matches!(
            reader.verify_data(&big),
            Err(super::super::ReadError::DataChecksum { .. })
        ));
    }

    /// Where the first data extent of an image built from [`populated`] begins, on the device.
    ///
    /// Read out of the image's own layout rather than assumed: the first data block group is
    /// where a chunk says it is, and a constant here would be a second copy of the placement
    /// rule that could fall out of step with the planner's.
    fn image_data_offset(bytes: &[u8]) -> usize {
        let volume = Volume::open(Cursor::new(bytes)).expect("readable");
        let chunk = volume
            .chunk_map()
            .chunks()
            .iter()
            .find(|chunk| chunk.flags.contains(BlockGroupFlags::DATA))
            .expect("a data block group");
        chunk.copies[0] as usize
    }

    #[test]
    fn a_source_and_its_image_hold_the_same_tree_whatever_order_the_source_gave_it() {
        // Two sources describing one tree in two orders produce one image, byte for byte. It is
        // the reproducibility claim at the level a caller sees it: what the bytes depend on is
        // the tree, not the walk that found it.
        let forward = filled(populated(), GIB);
        let mut entries = populated().into_entries();
        entries.reverse();
        let backward = format(Reversed(entries), GIB, options()).expect("a formattable tree");
        assert_eq!(forward.as_bytes(), backward.as_bytes());
    }

    /// A source that yields exactly the entries it was built from, in that order.
    struct Reversed(Vec<crate::SourceEntry>);

    impl crate::Source for Reversed {
        fn into_entries(self) -> Vec<crate::SourceEntry> {
            self.0
        }
    }

    #[test]
    fn nothing_a_source_states_is_lost_on_the_way_in() {
        // The fidelity claim this family alone can make, checked rather than asserted: btrfs
        // has a field for every property a source carries, so the report is empty — including
        // for the two properties a walked host tree loses on every other family here, which are
        // a change time and a time finer than a second.
        let image = filled(populated(), GIB);
        assert!(image.fidelity().is_faithful());
        assert!(image.fidelity().records().is_empty());

        let precise = Metadata::new(0o600, TIME).with_times(
            Timestamp {
                secs: 1_700_000_001,
                nanos: 123_456_789,
            },
            Timestamp {
                secs: 1_700_000_002,
                nanos: 987_654_321,
            },
            Timestamp {
                secs: 1_700_000_003,
                nanos: 500_000_000,
            },
        );
        let image = filled(
            TreeBuilder::new().file(b"/precise".to_vec(), b"x", precise),
            GIB,
        );
        assert!(image.fidelity().is_faithful());
        let mut reader = read(&image);
        let node = reader.lookup(b"/precise").expect("the file is there");
        assert_eq!(node.item.atime, precise.atime);
        assert_eq!(node.item.ctime, precise.ctime, "the change time survives");
        assert_eq!(node.item.mtime, precise.mtime);
        assert_eq!(node.item.mtime.nanos, 500_000_000, "and its fraction");
    }

    #[test]
    fn a_subvolume_is_a_tree_of_its_own_that_a_walk_crosses_into() {
        let meta = Metadata::new(0o644, TIME);
        let dir = Metadata::new(0o755, TIME);
        let source = TreeBuilder::new()
            .directory(b"/@".to_vec(), dir)
            .file(b"/@/etc".to_vec(), b"root\n", meta)
            .directory(b"/@home".to_vec(), dir)
            .file(b"/@home/user".to_vec(), b"home\n", meta)
            .file(b"/outside".to_vec(), b"top\n", meta);
        // The identifiers descend where the subvolumes ascend, which is the ordinary case and
        // not a corner: an identifier is a caller's to state and has no relation to the order
        // the tree is walked in. The UUID tree is keyed by them, so a writer that emitted its
        // records in subvolume order would produce a tree whose keys descend — which every
        // driver reads by binary search and no checker accepts.
        let image = format(
            source,
            GIB,
            options()
                .subvolume(SubvolumeRequest::new(b"/@".to_vec(), [0x66; 16]))
                .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x55; 16]).read_only(true))
                .default_subvolume(b"/@".to_vec()),
        )
        .expect("a formattable tree");

        let mut reader = read(&image);
        // Three subvolumes: the one every btrfs has, and the two that were asked for.
        let found: Vec<(u64, [u8; 16], bool, Vec<u8>)> = reader
            .subvolumes()
            .iter()
            .map(|sub| (sub.id, sub.uuid, sub.read_only, sub.name.clone()))
            .collect();
        assert_eq!(
            found,
            [
                (objectid::FS_TREE, [0x44; 16], false, Vec::new()),
                (256, [0x66; 16], false, b"@".to_vec()),
                (257, [0x55; 16], true, b"@home".to_vec()),
            ]
        );
        assert_eq!(reader.default_subvolume(), 256);

        // A walk crosses the seam rather than stopping at it, so what it yields is the
        // filesystem and not one tree.
        let mut paths: Vec<String> = reader
            .walk()
            .expect("a walk")
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.path).into_owned())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            ["", "/@", "/@/etc", "/@home", "/@home/user", "/outside"]
        );

        // And a file inside a subvolume is in that subvolume's tree, not the top-level one.
        let inside = reader.lookup(b"/@home/user").expect("the file is there");
        assert_eq!(inside.tree, 257);
        assert_eq!(reader.read_data(&inside).expect("bytes"), b"home\n");
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
    }

    #[test]
    fn every_tree_this_writer_emits_holds_its_records_in_key_order() {
        // A B-tree *is* its ordering: every lookup is a binary search, so a tree whose records
        // descend anywhere answers "not found" for records that are there and hands back the
        // wrong one for records that are not. Nothing in a block says which order it is in, and
        // no checksum covers the question — so a producer that emitted its records in the order
        // it happened to walk them writes a filesystem that verifies perfectly and cannot be
        // read.
        //
        // Held over every tree of every image rather than over the one that got it wrong,
        // because a record set is produced per tree and each is a separate chance to forget.
        // The identifiers below descend where the objects they belong to ascend, which is what
        // makes the UUID tree's order differ from its producer's.
        let meta = Metadata::new(0o644, TIME);
        let source = TreeBuilder::new()
            .directory(b"/@".to_vec(), Metadata::new(0o755, TIME))
            .file(b"/@/etc".to_vec(), b"root\n", meta)
            .directory(b"/@home".to_vec(), Metadata::new(0o755, TIME))
            .file(b"/@home/user".to_vec(), vec![7u8; 300_000], meta)
            .file(b"/outside".to_vec(), b"top\n", meta);
        let image = format(
            source,
            GIB,
            options()
                .subvolume(SubvolumeRequest::new(b"/@".to_vec(), [0xee; 16]))
                .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x11; 16])),
        )
        .expect("a formattable tree");

        let mut volume = opened(&image);
        for root in volume.tree_roots().expect("the trees") {
            let mut previous: Option<crate::btrfs::ondisk::DiskKey> = None;
            let mut count = 0usize;
            volume
                .tree(root)
                .for_each_item(|key, _| {
                    if let Some(before) = previous {
                        assert!(
                            before < *key,
                            "tree {} holds {key:?} after {before:?}",
                            root.objectid
                        );
                    }
                    previous = Some(*key);
                    count += 1;
                    true
                })
                .expect("a walkable tree");
            // A tree of no records would pass the loop above by never entering it, and three of
            // these carry records only because the filesystem was given something to hold.
            assert!(count > 0, "tree {} is empty", root.objectid);
        }
    }

    #[test]
    fn a_root_tree_spanning_more_than_one_leaf_is_shaped_and_refilled_alike() {
        // The root tree is shaped before its records hold real placements and refilled once
        // they do, and the two passes must divide the records into leaves identically: the
        // shaping is what handed every block its address. Subvolumes are what push it past one
        // leaf — each adds a root item and two link records, and the link records sort far
        // from the items they belong to — so the division depends on the whole order, not on
        // the order any one kind was produced in. Two sizes, because the leaf boundary has to
        // fall inside that interleaving for the order to matter: two subvolumes overflow a
        // 4096-byte node, and it takes over twenty to overflow the default.
        for (node_size, count) in [(4096u32, 2u8), (16384, 22)] {
            let mut source = TreeBuilder::new();
            let mut with =
                options().plan(PlanRequest::new(0).node_size(NodeSize::Bytes(node_size)));
            for at in 0..count {
                let path = vec![b'/', b'a' + at];
                source = source.directory(path.clone(), Metadata::new(0o755, TIME));
                with = with.subvolume(SubvolumeRequest::new(path, [at + 1; 16]));
            }
            let image = format(source, GIB, with)
                .unwrap_or_else(|e| panic!("{count} subvolumes at a {node_size}-byte node: {e}"));
            let mut reader = Reader::open(Cursor::new(image.as_bytes()))
                .expect("this crate reads what it wrote");
            assert_eq!(reader.subvolumes().len(), usize::from(count) + 1);
            assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
        }
    }

    #[test]
    fn the_uuid_tree_maps_the_identifier_each_subvolume_records() {
        // Two records name the top-level subvolume's identifier: its root item, and the UUID
        // tree entry mapping the identifier back to it. A writer that fills one and not the
        // other produces a filesystem whose lookup by identifier misses — every checksum
        // verifying all the while — and whose own tooling rewrites the tree on the next
        // writable mount.
        let image = image_of(GIB, PlanRequest::new(0));
        let mut volume = opened(&image);
        let uuid_tree = |volume: &mut Volume<Cursor<&[u8]>>| {
            volume
                .tree_roots()
                .expect("the trees")
                .into_iter()
                .find(|root| root.objectid == objectid::UUID_TREE)
                .expect("a UUID tree")
        };
        let root = uuid_tree(&mut volume);
        let mut entries = Vec::new();
        volume
            .tree(root)
            .for_each_item(|key, data| {
                entries.push((key.objectid, key.kind, key.offset, data.to_vec()));
                true
            })
            .expect("a walkable tree");
        let (low, high) = uuid_key([0x44; 16]);
        assert_eq!(
            entries,
            [(
                low,
                ItemType::UUID_SUBVOL,
                high,
                objectid::FS_TREE.to_le_bytes().to_vec()
            )]
        );

        // An all-zero identifier records that none was set, and an identifier never set has no
        // entry: the tree maps identifiers, not subvolumes.
        let unset = format(TreeBuilder::new(), GIB, options().subvolume_uuid([0; 16]))
            .expect("a volume past the minimum");
        let mut volume = Volume::open(Cursor::new(unset.as_bytes())).expect("readable");
        let root = uuid_tree(&mut volume);
        assert_eq!(volume.tree(root).count_items().expect("walkable"), 0);
    }

    #[test]
    fn two_subvolumes_sharing_an_identifier_are_refused_before_anything_is_written() {
        // The UUID tree is keyed by the identifier, so two subvolumes sharing one would put
        // one key in it twice — a tree no driver expects and no checker accepts. The refusal
        // covers the top-level subvolume too: its identifier is an option rather than a
        // request, and the tree keys them alike.
        let dir = Metadata::new(0o755, TIME);
        let source = || {
            TreeBuilder::new()
                .directory(b"/a".to_vec(), dir)
                .directory(b"/b".to_vec(), dir)
        };
        let repeated = format(
            source(),
            GIB,
            options()
                .subvolume(SubvolumeRequest::new(b"/a".to_vec(), [0x77; 16]))
                .subvolume(SubvolumeRequest::new(b"/b".to_vec(), [0x77; 16])),
        )
        .err()
        .expect("one identifier for two subvolumes");
        assert!(
            matches!(
                repeated,
                FormatError::Model(ModelError::SubvolumeUuidRepeated { .. })
            ),
            "{repeated:?}"
        );

        let with_top = format(
            source(),
            GIB,
            options().subvolume(SubvolumeRequest::new(b"/a".to_vec(), [0x44; 16])),
        )
        .err()
        .expect("the top-level subvolume holds 0x44 already");
        assert!(
            matches!(
                with_top,
                FormatError::Model(ModelError::SubvolumeUuidRepeated { .. })
            ),
            "{with_top:?}"
        );

        // Two subvolumes with no identifier at all do not collide: all zeros records that none
        // was set, and the tree holds no entry for either.
        format(
            source(),
            GIB,
            options()
                .subvolume_uuid([0; 16])
                .subvolume(SubvolumeRequest::new(b"/a".to_vec(), [0; 16]))
                .subvolume(SubvolumeRequest::new(b"/b".to_vec(), [0; 16])),
        )
        .expect("identifiers never set collide with nothing");
    }

    #[test]
    fn a_source_larger_than_the_volume_is_refused_before_anything_is_written() {
        // The refusal a caller most wants to be a refusal rather than a truncated image, and it
        // has to come from the planner: the volume is large enough to be formatted and too small
        // to hold what it was told it would be given.
        let source = TreeBuilder::new().file(
            b"/huge".to_vec(),
            vec![0u8; 300 << 20],
            Metadata::new(0o644, TIME),
        );
        let err = format(source, 256 << 20, options())
            .err()
            .expect("more than the volume holds");
        assert!(
            matches!(
                err,
                FormatError::Geometry(GeometryError::ContentTooLarge { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_tree_the_filesystem_cannot_hold_is_refused_and_names_the_entry() {
        let err = format(
            TreeBuilder::new().hardlink(
                b"/a".to_vec(),
                b"/nowhere".to_vec(),
                Metadata::new(0o644, TIME),
            ),
            GIB,
            options(),
        )
        .err()
        .expect("the link names nothing");
        assert!(
            matches!(
                err,
                FormatError::Model(ModelError::HardlinkTargetMissing { .. })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("/nowhere"), "{err}");
    }

    /// A file with `count` names in one directory, on a filesystem of `node` tree blocks.
    ///
    /// The names are long enough that a modest count outgrows what one record holds, which is
    /// the point: how many names an `INODE_REF` carries is a function of the tree block's size,
    /// so a small block reaches the overflow at a count a test can afford to write.
    fn densely_linked(count: usize, node: u32) -> Image {
        let meta = Metadata::new(0o644, TIME);
        let long = "n".repeat(200);
        let mut source = TreeBuilder::new().file(b"/target".to_vec(), b"x", meta);
        for n in 0..count {
            source = source.hardlink(
                format!("/{long}{n:04}").into_bytes(),
                b"/target".to_vec(),
                meta,
            );
        }
        format(
            source,
            GIB,
            options().plan(PlanRequest::new(0).node_size(NodeSize::Bytes(node))),
        )
        .expect("a formattable tree")
    }

    #[test]
    fn names_past_what_one_record_holds_go_into_the_extended_form_and_read_back() {
        // The format has two records for a name and the second exists only because the first
        // runs out of room: an `INODE_REF` holds every name an inode has in one directory, and
        // what does not fit becomes an `INODE_EXTREF` keyed by a hash of the directory and the
        // name. A writer that only ever emitted the first would produce a record no leaf holds.
        let image = densely_linked(40, 4096);
        let mut reader = read(&image);
        let target = reader.lookup(b"/target").expect("the file is there");
        assert_eq!(target.item.nlink, 41, "one name and forty more");
        assert_eq!(reader.walk().expect("a walk").len(), 42);
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());

        // Both forms are present, which is what says the overflow was reached rather than
        // avoided by a filesystem large enough to hold every name in one record.
        let mut volume = opened(&image);
        let root = volume
            .tree_roots()
            .expect("the root tree")
            .into_iter()
            .find(|root| root.objectid == objectid::FS_TREE)
            .expect("the filesystem tree");
        let mut kinds = std::collections::BTreeSet::new();
        volume
            .tree(root)
            .for_each_item(|key, _| {
                kinds.insert(key.kind);
                true
            })
            .expect("a walk of the filesystem tree");
        assert!(kinds.contains(&ItemType::INODE_REF), "{kinds:?}");
        assert!(kinds.contains(&ItemType::INODE_EXTREF), "{kinds:?}");

        // And a larger tree block holds every one of them in the first form, which is what says
        // the threshold is the block's size rather than a count written down.
        let roomy = densely_linked(40, 65536);
        let mut volume = opened(&roomy);
        let root = volume
            .tree_roots()
            .expect("the root tree")
            .into_iter()
            .find(|root| root.objectid == objectid::FS_TREE)
            .expect("the filesystem tree");
        let mut kinds = std::collections::BTreeSet::new();
        volume
            .tree(root)
            .for_each_item(|key, _| {
                kinds.insert(key.kind);
                true
            })
            .expect("a walk of the filesystem tree");
        assert!(!kinds.contains(&ItemType::INODE_EXTREF), "{kinds:?}");
    }

    #[test]
    fn a_tree_of_small_files_with_attributes_stays_inside_its_reservation() {
        // The tree the reservation is loosest on: every file lives inside the metadata, so none
        // of them reaches a data block group at all and the whole cost is records. What a bound
        // that came out short produces is `FormatError::Reservation` rather than a bad image,
        // which is what makes this a gate over the planner rather than over the writer.
        let meta = Metadata::new(0o644, TIME);
        let mut source = TreeBuilder::new();
        for n in 0..2000u32 {
            source = source
                .file(format!("/f{n:05}").into_bytes(), vec![b'x'; 512], meta)
                .xattr(b"user.n".to_vec(), vec![b'v'; 64]);
        }
        let image = filled(source, 2 * GIB);
        let mut reader = read(&image);
        assert_eq!(reader.walk().expect("a walk").len(), 2001);
        let one = reader.lookup(b"/f01234").expect("the file is there");
        assert_eq!(reader.read_data(&one).expect("bytes"), vec![b'x'; 512]);
        assert_eq!(reader.xattrs(&one).expect("attributes").len(), 1);
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
    }

    #[test]
    fn a_name_in_every_directory_and_a_file_in_every_leaf_still_reads_back() {
        // A tree large enough that the fs tree gains a level and the checksum tree holds more
        // than one record — which is the shape every claim above was made on a single leaf.
        let meta = Metadata::new(0o644, TIME);
        let mut source = TreeBuilder::new();
        for n in 0..400u32 {
            source = source.file(format!("/f{n:04}").into_bytes(), vec![0xab; 8192], meta);
        }
        let image = filled(source, 2 * GIB);
        let mut reader = read(&image);
        assert_eq!(reader.walk().expect("a walk").len(), 401);
        let one = reader.lookup(b"/f0123").expect("the file is there");
        assert_eq!(reader.read_data(&one).expect("bytes"), vec![0xab; 8192]);
        reader.verify_data(&one).expect("its checksums");
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());

        // The tree really did gain a level, or the claim above is about the same shape as every
        // other test here.
        let root = reader
            .volume_mut()
            .tree_roots()
            .expect("the root tree")
            .into_iter()
            .find(|root| root.objectid == objectid::FS_TREE)
            .expect("the filesystem tree");
        assert!(root.level > 0, "the filesystem tree is still one leaf");
    }

    #[test]
    fn a_file_larger_than_a_data_chunk_spans_several_and_reads_back_whole() {
        // Content past the first data chunk: the planner appends chunks for it, the allocator
        // grants extents across the boundary between them, the checksum tree restarts a record
        // at each discontinuity, and every chunk's block group counts what landed in it. None
        // of those paths runs for content that fits one chunk, which every smaller test's does.
        let meta = Metadata::new(0o644, TIME);
        let content: Vec<u8> = (0..20 * MIB).map(|n| (n % 251) as u8).collect();
        let source = TreeBuilder::new().file(b"/span.bin".to_vec(), content.clone(), meta);
        let image = filled(source, 2 * GIB);

        let volume = opened(&image);
        let data_chunks = volume
            .chunk_map()
            .chunks()
            .iter()
            .filter(|chunk| chunk.flags.contains(BlockGroupFlags::DATA))
            .count();
        assert!(
            data_chunks > 1,
            "{data_chunks} data chunks — the file fit one"
        );

        let mut reader = read(&image);
        let entry = reader.lookup(b"/span.bin").expect("the file is there");
        assert_eq!(reader.read_data(&entry).expect("bytes"), content);
        reader.verify_data(&entry).expect("its checksums");
        assert!(reader.scan().is_clean(), "{:?}", reader.scan().anomalies());
    }
}
