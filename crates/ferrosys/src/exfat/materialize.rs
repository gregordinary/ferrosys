//! The materializer: turn a planned [`ExfatLayout`] and a modelled tree into image bytes.
//!
//! Everything this layer writes was decided by the pure layers below it. A format is five
//! stages, applied in order. The first zeroes everything before the cluster heap and the end
//! of the volume. The second lays down the allocation table's head, with the two entries the
//! format reserves and the chains for what the format itself allocates, then the allocation
//! bitmap, the up-case table, and every directory and file. The last three write the boot
//! regions, the backup first and the main boot sector last, each region carrying its own
//! computed checksum.
//!
//! Every byte a reader or a prober could consult is written, so what the destination held
//! before does not matter. [`format()`] collects the bytes into an in-memory [`Image`];
//! [`format_to`] streams them to any seekable writer and reads nothing back, so a volume far
//! larger than memory can be created into a file that stays sparse across the free clusters
//! of its heap. [`FormatPlan::stages`] hands the same write back as pieces, for a caller that
//! does its own I/O.
//!
//! # What the allocation table holds, and what it does not
//!
//! Every stream this crate writes is contiguous, so every one of them declares `NoFatChain` —
//! the flag that says a reader must follow the clusters in order and not consult the table at
//! all. The table therefore holds chains only for what the format itself allocated: the
//! bitmap, the up-case table, and the root directory, none of which has a flags field to
//! declare anything with. The allocation *bitmap* is what says a cluster is in use either way,
//! and both come out of one planned allocation rather than being maintained separately.
//!
//! # Reproducibility
//!
//! Two formats of the same source and the same parameters produce the same bytes. Every value
//! a formatter would conventionally take from the clock or from a random source is a
//! [`FormatOptions`] input, and there is exactly one — the volume serial number. The times an
//! entry records come from the source that named the entry, and the creation time is derived
//! from the modification time rather than read from a clock.

use std::borrow::Cow;
use std::io::{Cursor, Seek, Write};

use crate::fidelity::{AcceptedLoss, FidelityReport, LossPolicy, Synthesis};
use crate::io::ByteSink;
use crate::source::{FileContent, FileRange, Source};

use super::geometry::{ExfatLayout, GeometryError, PlanRequest, plan_layout};
use super::model::{
    ClusterRun, ExfatModel, ModelConfig, ModelEntry, ModelError, Node, ROOT_DIR,
    ROOT_LEADING_SLOTS, build_model,
};
use super::ondisk::{
    AllocationBitmapEntry, BOOT_CODE_LEN, BOOT_REGION_SECTORS, CHECKSUM_SECTOR, DIR_ENTRY_SIZE,
    DirEntry, END_OF_CHAIN, EXTENDED_BOOT_FIRST_SECTOR, EXTENDED_BOOT_SECTORS, EntryType,
    FAT_ENTRY_MEDIA, FAT_ENTRY_RESERVED, FILE_SYSTEM_NAME, FILE_SYSTEM_REVISION, FileEntry,
    FileNameEntry, MAX_LABEL_UNITS, MainBootSector, NAME_UNITS_PER_ENTRY, ParseError,
    RECOMMENDED_UPCASE_BYTES, RECOMMENDED_UPCASE_CHECKSUM, RECOMMENDED_UPCASE_TABLE,
    SECONDARY_ALLOCATION_POSSIBLE, SECONDARY_NO_FAT_CHAIN, StreamExtensionEntry, UTC_OFFSET,
    UpcaseTable, UpcaseTableEntry, VolumeLabelEntry, boot_checksum, entry_set_checksum,
    pack_timestamp, percent_in_use, write_checksum_sector, write_extended_boot_sector,
    write_upcase_table,
};
use crate::bytes::put_u32;

/// The BIOS drive number a volume records: `0x80`, a fixed disk.
///
/// Nothing but boot code reads it, and every implementation writes this value whatever the
/// medium — a card reader presents its card as a disk like any other.
const DRIVE_SELECT: u8 = 0x80;

/// Allocation tables on a volume this crate writes. The two-table transaction-safe variant is
/// a different filesystem wearing this one's boot sector, and this crate neither writes it nor
/// reads it as though it were the same thing.
const NUMBER_OF_FATS: u8 = 1;

/// Allocation table entries in one piece.
///
/// The table's head is the only part of it holding anything but zeros — everything past the
/// residents is free. Building that head a batch at a time is what keeps the memory a format
/// costs constant however many clusters the allocation bitmap spans. Sixteen kibibytes, a
/// whole number of sectors at every sector size, so no two batches share a sector.
const TABLE_BATCH_ENTRIES: usize = 4096;

/// Allocation bitmap bytes in one piece, for the same reasons.
const BITMAP_BATCH_BYTES: usize = 16 << 10;

/// How much of the end of the volume a format zeroes, wherever the clusters there are free.
///
/// Some formats keep their labels at the end of a device rather than at its start, and a
/// prober reads both ends. The allocator fills the heap from the front, so this much of the
/// end is free on any volume that is not nearly full.
const TAIL_BYTES: u64 = 1 << 20;

/// Zero bytes written in one call, so zeroing a long run costs one constant buffer.
const ZERO_BATCH_BYTES: usize = 64 << 10;

/// A volume label: up to eleven UTF-16 code units, as the root directory's first entry records
/// it.
///
/// Eleven *units*, which is eleven characters only for characters the Basic Multilingual Plane
/// holds — an emoji is a surrogate pair and costs two. The limit is the field's width and
/// nothing softer, so a name that does not fit is refused rather than cut short at a boundary
/// that might fall inside a pair.
///
/// A volume with no name carries [`UNNAMED`](Self::UNNAMED), which is the label entry with a
/// character count of zero. The entry is written either way: exFAT has no state in which the
/// root directory lacks one.
///
/// ```
/// # use ferrosys::exfat::VolumeLabel;
/// assert_eq!(VolumeLabel::new("ferrosys")?.units().len(), 8);
/// assert!(VolumeLabel::UNNAMED.units().is_empty());
///
/// // Eleven units is the whole field; a twelfth has nowhere to go.
/// assert!(VolumeLabel::new("ELEVENCHARS").is_ok());
/// assert!(VolumeLabel::new("TWELVECHARSX").is_err());
/// # Ok::<(), ferrosys::exfat::LabelError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VolumeLabel {
    units: [u16; MAX_LABEL_UNITS],
    len: u8,
}

impl VolumeLabel {
    /// The most UTF-16 code units a label holds.
    pub const MAX_UNITS: usize = MAX_LABEL_UNITS;

    /// The label of a volume with no name: the entry, with a character count of zero.
    pub const UNNAMED: Self = Self {
        units: [0; MAX_LABEL_UNITS],
        len: 0,
    };

    /// The label `name` states.
    ///
    /// The name is taken as it stands — exFAT stores Unicode and folds only for comparison, so
    /// nothing here changes a character's case.
    ///
    /// # Errors
    ///
    /// [`LabelError::TooLong`] beyond [`MAX_UNITS`](Self::MAX_UNITS) UTF-16 code units,
    /// [`LabelError::NulUnit`] for a label containing `U+0000` — which is what the field's
    /// padding is, so a label holding one is a label every implementation that reads the field
    /// as terminated rather than counted would read differently — and
    /// [`LabelError::ForbiddenCharacter`] for any other character a name may not hold, which
    /// a label reserves as a name does.
    pub fn new(name: &str) -> Result<Self, LabelError> {
        let mut units = [0u16; MAX_LABEL_UNITS];
        let mut len = 0usize;
        if let Some(ch) = name
            .chars()
            .find(|ch| *ch != '\0' && crate::path::is_reserved_name_char(*ch))
        {
            return Err(LabelError::ForbiddenCharacter { ch });
        }
        for unit in name.encode_utf16() {
            if unit == 0 {
                return Err(LabelError::NulUnit { at: len });
            }
            if len == MAX_LABEL_UNITS {
                return Err(LabelError::TooLong {
                    units: name.encode_utf16().count(),
                    limit: MAX_LABEL_UNITS,
                });
            }
            units[len] = unit;
            len += 1;
        }
        Ok(Self {
            // Bounded by the check above, which refuses at the limit.
            len: len as u8,
            units,
        })
    }

    /// The label's UTF-16 code units, without the padding that fills the rest of the field.
    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.units[..self.len as usize]
    }

    /// The entry the root directory's first slot carries for this label.
    fn entry(&self) -> VolumeLabelEntry {
        VolumeLabelEntry {
            character_count: self.len,
            label: self.units,
        }
    }
}

impl Default for VolumeLabel {
    fn default() -> Self {
        Self::UNNAMED
    }
}

impl core::fmt::Debug for VolumeLabel {
    /// The label as text, so a failure quotes a name rather than eleven numbers. The units
    /// came from a `&str`, so they are always well-formed UTF-16.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text: String = char::decode_utf16(self.units().iter().copied())
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
        write!(f, "VolumeLabel({text:?})")
    }
}

/// A label an exFAT volume cannot carry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LabelError {
    /// The label is longer than the eleven UTF-16 code units the entry holds.
    #[error("volume label of {units} UTF-16 units exceeds the {limit} the format holds")]
    #[non_exhaustive]
    TooLong {
        /// Units the label needs.
        units: usize,
        /// Units the format holds.
        limit: usize,
    },
    /// The label contains `U+0000`, which is what the unused tail of the field is filled with.
    #[error("a volume label may not contain U+0000, and this one does at unit {at}")]
    #[non_exhaustive]
    NulUnit {
        /// Which unit of the label it is.
        at: usize,
    },
    /// The label contains a character a name may not hold: a control code, or one of the
    /// nine a path or a pattern gives a meaning to. A label reserves the same ones.
    #[error("a volume label may not contain {ch:?}")]
    #[non_exhaustive]
    ForbiddenCharacter {
        /// The first such character.
        ch: char,
    },
}

/// Options controlling a format that do not come from the volume's size.
///
/// Build one with [`new`](Self::new), which takes the one identity input an image needs and
/// defaults the rest, then set the fields a format departs from the default on.
///
/// Every value a formatter would conventionally take from the clock or from a random source is
/// here, which is what makes two formats of the same parameters produce the same bytes. There
/// is exactly one: an empty exFAT volume records no time anywhere.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The volume serial number, recorded in both boot regions. Conventionally derived from
    /// the moment of formatting; supplied here so that it is not.
    ///
    /// It is inside the boot region's checksum, so changing it after the fact means
    /// recomputing that checksum in both regions — which is why it is an input rather than
    /// something to patch afterwards.
    pub volume_serial: u32,
    /// The volume's name. Defaults to [`VolumeLabel::UNNAMED`], which is the label entry with
    /// a character count of zero rather than no entry at all.
    pub label: VolumeLabel,
    /// The boot loader's own bytes, at offset 120 of the Main Boot Sector, inside the region's
    /// checksum. Defaults to zeroes, which is a volume that does not boot.
    ///
    /// Writing a boot loader is a layer above this crate, so what goes here is supplied rather
    /// than generated. The field is exactly as wide as the region, so there is no length to
    /// get wrong and no padding rule to state.
    pub boot_code: [u8; BOOT_CODE_LEN],
    /// What the volume's geometry must be. Defaults to a request for the volume's own size
    /// with every knob at the value convention selects; [`PlanRequest::volume_bytes`] is
    /// replaced by the size the format is asked for, so a size named twice cannot disagree.
    pub plan: PlanRequest,
    /// Which properties the caller accepts losing. Defaults to none, so a source naming
    /// anything an exFAT volume cannot hold is refused rather than quietly dropped.
    ///
    /// What each accepted loss then cost comes back as a [`FidelityReport`], entry by entry.
    pub accepted_loss: AcceptedLoss,
    /// What a read of this image would fill an owner and a mode with, which is what decides
    /// whether a value the format has no field for was *lost*.
    ///
    /// A tree matching these defaults goes into an exFAT volume and comes back out unchanged,
    /// so it loses nothing and the report says so. Set this to what the eventual reader will
    /// be told to use, and the accounting describes that round trip rather than a different
    /// one.
    pub synthesis: Synthesis,
}

impl FormatOptions {
    /// Options for a volume identified by `volume_serial`, with every other knob at its
    /// default.
    #[must_use]
    pub const fn new(volume_serial: u32) -> Self {
        Self {
            volume_serial,
            label: VolumeLabel::UNNAMED,
            boot_code: [0; BOOT_CODE_LEN],
            // Replaced with the size the format is asked for, so the placeholder here is
            // never the size anything is planned against.
            plan: PlanRequest::new(0),
            accepted_loss: AcceptedLoss::NONE,
            synthesis: Synthesis::new(),
        }
    }

    /// These options with the volume label replaced.
    #[must_use]
    pub const fn label(mut self, label: VolumeLabel) -> Self {
        self.label = label;
        self
    }

    /// These options with the boot code replaced.
    #[must_use]
    pub const fn boot_code(mut self, boot_code: [u8; BOOT_CODE_LEN]) -> Self {
        self.boot_code = boot_code;
        self
    }

    /// These options with the geometry request replaced.
    ///
    /// The request's [`volume_bytes`](PlanRequest::volume_bytes) is ignored: the size a format
    /// is asked for is the size it plans against.
    #[must_use]
    pub const fn plan(mut self, plan: PlanRequest) -> Self {
        self.plan = plan;
        self
    }

    /// These options with the accepted losses replaced.
    #[must_use]
    pub const fn accepted_loss(mut self, accepted: AcceptedLoss) -> Self {
        self.accepted_loss = accepted;
        self
    }

    /// These options with the read-side synthesis defaults replaced.
    #[must_use]
    pub const fn synthesis(mut self, synthesis: Synthesis) -> Self {
        self.synthesis = synthesis;
        self
    }

    /// What the model needs of these options, against the folding `upcase` defines.
    fn model_config<'a>(&self, upcase: &'a UpcaseTable) -> ModelConfig<'a> {
        ModelConfig {
            loss: LossPolicy {
                accepted: self.accepted_loss,
                synthesis: self.synthesis,
            },
            upcase,
        }
    }
}

/// A failure formatting a volume.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// Writing to the destination failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Planning the geometry failed.
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    /// Serializing an on-disk structure failed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The source names something the volume cannot hold.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// A directory was written past the clusters it was given.
    ///
    /// Nothing a caller passes reaches this: the model sizes every directory and allocates for
    /// what it sized, so the two agree and reaching this is a defect in this crate.
    ///
    /// It is checked on every write rather than only in a debug build, because the finished
    /// bytes do not show it. A directory written past its own clusters lands on whatever was
    /// placed after it, and that is written second — so the overflow is covered over and the
    /// image reads plausibly with one stream's contents inside another's.
    #[error(
        "directory {index} needs {bytes} bytes of entries and was given {capacity} bytes of \
         clusters"
    )]
    #[non_exhaustive]
    DirectoryOverflowsItsClusters {
        /// Which directory, by its index in the model.
        index: usize,
        /// Bytes of entries it holds.
        bytes: u64,
        /// Bytes its clusters hold.
        capacity: u64,
    },
    /// The source declared a file by its length alone, and a write to a sink has no bytes to
    /// put there.
    ///
    /// A plan holding one is applied through [`FormatPlan::stages`], whose pieces say where
    /// the caller's bytes go. The write is refused before the sink is touched.
    #[error(
        "a file declared by its length alone, under key {key}, holds no bytes for a write to \
         place; the plan's stages say where they go"
    )]
    #[non_exhaustive]
    ContentsNotHeld {
        /// The key the file was declared with.
        key: u64,
    },
    /// The image is larger than this platform addresses in memory. Only [`format()`] can reach
    /// this; [`format_to`] never holds an image.
    #[error("an image of {bytes} bytes is larger than this platform addresses in memory")]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// Bytes the image needs.
        bytes: u64,
    },
    /// A structure the format writes needs a cluster the layout's own fields say the volume
    /// does not have.
    ///
    /// Nothing a caller passes reaches this. [`plan_layout`] places the three residents
    /// inside the heap and sizes the allocation table for every cluster, so the fields it
    /// returns agree with each other, and reaching this is a defect in this crate rather than
    /// something to correct in a [`FormatOptions`].
    ///
    /// It is a returned failure rather than a debug assertion, and rather than a write
    /// quietly skipped, because of what the alternatives look like. A volume written without
    /// its allocation bitmap reads as a filesystem a driver cannot allocate in; one written
    /// without its up-case table folds names through nothing. Neither is visible in the bytes
    /// afterwards without knowing what should have been there, and a debug assertion is
    /// absent from exactly the build that writes the images anyone keeps.
    #[error(
        "{region} needs cluster {cluster}, which the layout's own fields say the volume does \
         not have"
    )]
    #[non_exhaustive]
    ClusterOutsideVolume {
        /// What needed the cluster.
        region: &'static str,
        /// The cluster number it needed.
        cluster: u32,
    },
}

/// A finished volume image: the bytes, the geometry that produced them, and what the format
/// could not carry.
pub struct Image {
    bytes: Vec<u8>,
    layout: ExfatLayout,
    fidelity: FidelityReport,
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
    pub fn layout(&self) -> &ExfatLayout {
        &self.layout
    }

    /// What the source offered that the format could not hold, and what it stored more
    /// coarsely.
    #[must_use]
    pub fn fidelity(&self) -> &FidelityReport {
        &self.fidelity
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

/// A format decided but not yet performed: what the volume will be, and what putting the
/// source in it will cost.
///
/// Everything a format can fail on but I/O happens when the plan is built, which is why the
/// two halves are separate. A destination has to be created or truncated before a filesystem
/// can be written into it, so a format that failed on its source *after* the destination was
/// truncated would be a file destroyed by a run that wrote no filesystem. And an exFAT volume
/// cannot hold everything a source may offer, so [`fidelity`](Self::fidelity) is an answer
/// worth having in advance: a hard link is written as a second copy of its file, and the plan
/// is where the size that costs is a number a caller reads rather than discovers.
///
/// [`write_to`](Self::write_to) is the half that can only fail on I/O, and
/// [`stages`](Self::stages) hands the same write back as pieces for a caller that does its own.
///
/// # Example
///
/// ```no_run
/// use ferrosys::exfat::{FormatOptions, FormatPlan, VolumeLabel};
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_426_325_212);
/// let source = TreeBuilder::new()
///     .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
///     .file(b"/DCIM/README.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));
///
/// let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
/// let plan = FormatPlan::new(source, 512 << 20, options)?;
///
/// // What it will be, and what it will cost, before the destination is touched.
/// println!("{} clusters free", plan.free_clusters());
/// assert!(plan.fidelity().is_faithful());
///
/// let mut file = std::fs::File::create("card.img")?;
/// plan.write_to(&mut file)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct FormatPlan {
    layout: ExfatLayout,
    /// The size the format was asked for, which is the size the destination becomes. It is
    /// held apart from the layout because the two are not always the same number: a size that
    /// is not a whole number of sectors leaves a remainder past the filesystem's end.
    volume_bytes: u64,
    options: FormatOptions,
    model: ExfatModel,
}

impl FormatPlan {
    /// Plan a format of `volume_bytes` populated from `source`.
    ///
    /// Everything a format can fail on but I/O happens here.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the geometry cannot be realized or the source names something the
    /// volume cannot hold — including a property it would lose that
    /// [`FormatOptions::accepted_loss`] does not cover.
    pub fn new(
        source: impl Source,
        volume_bytes: u64,
        options: FormatOptions,
    ) -> Result<Self, FormatError> {
        let layout = plan(volume_bytes, &options)?;
        // The folding this volume's names are compared through is the table the volume itself
        // will carry, so it is built from what the writer is about to lay down rather than
        // from anything about the host.
        let upcase = UpcaseTable::recommended();
        let model = build_model(
            source.into_entries(),
            &layout,
            &options.model_config(&upcase),
        )?;
        Ok(Self {
            layout,
            volume_bytes,
            options,
            model,
        })
    }

    /// The clusters the volume has that nothing occupies.
    #[must_use]
    pub const fn free_clusters(&self) -> u32 {
        self.layout.cluster_count - self.model.used_clusters
    }

    /// The geometry the bytes will realize — exact rather than estimated, because it is the
    /// same value the write uses.
    #[must_use]
    pub const fn layout(&self) -> &ExfatLayout {
        &self.layout
    }

    /// Bytes the destination will hold, which is the size the format was asked for.
    #[must_use]
    pub const fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }

    /// What the source offered that the format cannot hold, and what it will store more
    /// coarsely.
    #[must_use]
    pub fn fidelity(&self) -> &FidelityReport {
        &self.model.fidelity
    }

    /// The format as stages of pieces, for a caller that does its own I/O.
    ///
    /// The five stages come back in the order they must be applied, and each must be complete
    /// — written, and durable where the destination can lose a write — before the next
    /// begins. Within a stage the pieces never share a sector and may go down in any order.
    /// Applied that way, an interruption once the first stage is complete leaves either
    /// nothing a driver mounts or the whole volume: the first stage invalidates whatever the
    /// destination held, and the main boot sector, which every reader checks first, is the
    /// last sector written. An interruption during the first stage leaves what the destination
    /// held, part of it zeroed.
    ///
    /// The pieces cover every byte a reader or a prober could consult, so what the
    /// destination held before does not matter. [`write_to`](Self::write_to) is these stages
    /// applied to a seekable sink.
    ///
    /// # Example
    ///
    /// ```
    /// use ferrosys::exfat::{FormatOptions, FormatPlan, Piece};
    /// use ferrosys::{FileContent, Metadata, Timestamp, TreeBuilder};
    ///
    /// let meta = Metadata::new(0o644, Timestamp::from_secs(1_426_325_212));
    /// let source = TreeBuilder::new()
    ///     .file(b"/eflasher.conf".to_vec(), b"autostart=yes\n", meta)
    ///     // The image is the caller's to stream: the plan learns its length and nothing else.
    ///     .file(b"/os.img".to_vec(), FileContent::Declared { len: 300 << 20, key: 7 }, meta);
    /// let plan = FormatPlan::new(source, 1 << 30, FormatOptions::new(0x1234_abcd))?;
    ///
    /// let mut image = None;
    /// for stage in plan.stages() {
    ///     for piece in stage.pieces() {
    ///         match piece? {
    ///             // Write the caller's own bytes here, through whatever I/O it has.
    ///             Piece::Declared { offset, len, key, .. } => image = Some((offset, len, key)),
    ///             // Bytes, zeros, and ranges go down as they are.
    ///             _ => {}
    ///         }
    ///     }
    ///     // Flush here, so this stage is durable before the next begins.
    /// }
    /// let (offset, len, key) = image.expect("the image was placed");
    /// assert_eq!((len, key), (300 << 20, 7));
    /// assert_eq!(offset % u64::from(plan.layout().bytes_per_cluster), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn stages(&self) -> [Stage<'_>; 5] {
        StageKind::ORDER.map(|kind| Stage { plan: self, kind })
    }

    /// Write the planned volume to `sink`, returning the geometry it realizes.
    ///
    /// The [`stages`](Self::stages) are applied in order, with the sink flushed between
    /// them, so a sink whose flush makes its writes durable keeps the order across a power
    /// cut. Every byte a reader or a prober could consult is written, so what the sink held
    /// before does not matter: a reused medium or a file holding an earlier volume is
    /// formatted as a fresh one is. Nothing is read back.
    ///
    /// The sink is extended to [`volume_bytes`](Self::volume_bytes) — the size the format was
    /// asked for — and a file destination stays sparse across the free clusters of the heap,
    /// which on a fresh volume is all of it but the last mebibyte.
    ///
    /// The plan is not consumed, so the report is readable on either side of the write and one
    /// plan may be written more than once. Two writes of one plan produce the same bytes,
    /// unless a file a [`FileRange`] names changed in between.
    ///
    /// # Errors
    ///
    /// [`FormatError::ContentsNotHeld`] before the sink is touched, if the source declared a
    /// file of one byte or more by its length alone: there are no bytes here to put there, and
    /// [`stages`](Self::stages) is how such a plan is applied. A declared file of no bytes needs
    /// none, and is written as any empty file is. [`FormatError::Io`] if writing to `sink`
    /// fails, or if a file the source named by range cannot be read — which is what a file
    /// edited after the source was built looks like.
    pub fn write_to(&self, sink: impl Write + Seek) -> Result<ExfatLayout, FormatError> {
        if let Some(key) = self.declared_key() {
            return Err(FormatError::ContentsNotHeld { key });
        }
        let mut sink = ByteSink::new(sink);
        // The destination is the volume's length before the first stage, so the last stage is
        // the last write. A volume whose final cluster ends inside a file has no piece
        // reaching its end, and this is what makes the destination that long anyway.
        sink.extend_to(self.volume_bytes)?;
        let zeros = vec![0u8; ZERO_BATCH_BYTES];
        for stage in self.stages() {
            for piece in stage.pieces() {
                match piece? {
                    Piece::Bytes { offset, bytes } => sink.write_at(offset, &bytes)?,
                    Piece::Zeros { offset, len } => {
                        let mut done = 0u64;
                        while done < len {
                            let n = (len - done).min(ZERO_BATCH_BYTES as u64);
                            // Bounded by the batch, so the conversion cannot lose a value.
                            sink.write_at(offset + done, &zeros[..n as usize])?;
                            done += n;
                        }
                    }
                    Piece::Range { offset, range } => {
                        range.for_each_window(|at, window| sink.write_at(offset + at, window))?;
                    }
                    // Refused above, before the sink was touched; answered the same way here
                    // rather than assumed away.
                    Piece::Declared { key, .. } => {
                        return Err(FormatError::ContentsNotHeld { key });
                    }
                }
            }
            sink.flush()?;
        }
        Ok(self.layout)
    }

    /// The key of the first file the source declared by its length alone and gave bytes to,
    /// if it declared any.
    fn declared_key(&self) -> Option<u64> {
        self.model
            .contents
            .iter()
            .find_map(|content| match content {
                FileContent::Declared { len, key } if *len > 0 => Some(*key),
                _ => None,
            })
    }
}

/// Format an exFAT volume of `volume_bytes` populated from `source`, assembling the whole image
/// in memory.
///
/// The image is exactly `volume_bytes` long. Where the volume's size is not a whole number of
/// sectors the filesystem is the sectors it has and the remainder lies past its end, which is
/// what the slack at the end of a partition looks like; the boot sector's recorded length is
/// what says where the filesystem stops.
///
/// The image is held as one buffer of its full size, so this needs as much memory as the
/// volume is large. [`format_to`] writes the same bytes to a seekable destination without ever
/// holding them all.
///
/// An empty volume is [`TreeBuilder::new`](crate::TreeBuilder::new), which places nothing.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, the source names something the volume
/// cannot hold, or the image is larger than this platform addresses.
///
/// # Example
///
/// ```
/// use ferrosys::exfat::{FormatOptions, VolumeLabel, format};
/// use ferrosys::{Metadata, Timestamp, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_426_325_212);
/// let source = TreeBuilder::new()
///     .file(b"/READY.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));
///
/// let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
/// let image = format(source.clone(), 64 << 20, options)?;
/// assert_eq!(image.as_bytes().len(), 64 << 20);
/// assert_eq!(image.layout().bytes_per_cluster, 4 << 10);
///
/// // Root-owned, conventionally moded, and no links: nothing was lost putting it here.
/// assert!(image.fidelity().is_faithful());
///
/// // Two formats of the same tree are the same bytes.
/// assert_eq!(image.as_bytes(), format(source, 64 << 20, options)?.as_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn format(
    source: impl Source,
    volume_bytes: u64,
    options: FormatOptions,
) -> Result<Image, FormatError> {
    // Planned before the buffer is allocated, so a geometry or a source that cannot be
    // realized fails without first asking for the volume's worth of memory.
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    let size = usize::try_from(volume_bytes).map_err(|_| FormatError::ImageTooLargeInMemory {
        bytes: volume_bytes,
    })?;
    let mut image = Cursor::new(vec![0u8; size]);
    let layout = plan.write_to(&mut image)?;
    Ok(Image {
        bytes: image.into_inner(),
        layout,
        fidelity: plan.model.fidelity,
    })
}

/// Format an exFAT volume of `volume_bytes` populated from `source`, streaming its bytes into
/// `sink` and returning the plan they realize.
///
/// Every byte a reader or a prober could consult is written and nothing is read back, so what
/// the sink held before does not matter and the whole image never exists in memory. A file
/// destination stays sparse across the free clusters of the heap, and is extended to
/// `volume_bytes`, the size the format was asked for. [`FormatPlan::write_to`] says what is
/// written and in what order.
///
/// The [`FormatPlan`] comes back rather than the layout alone, because a format into a
/// filesystem that cannot hold everything a source offers owes the caller an account of what it
/// dropped: [`FormatPlan::fidelity`] is that account and [`FormatPlan::layout`] is the geometry.
///
/// # Memory
///
/// Four things are held while the image streams out, and none of them is the image:
///
/// - **The model.** Every entry's name, times, and cluster run, held until the last byte is
///   written. It grows with the number of entries, not with their size — an allocation is a
///   first cluster and a count, because a fresh volume has nothing to allocate around.
/// - **One window of a file's contents, while it is placed.** A
///   [`FileContent::Owned`] entry holds its bytes from the moment
///   the source is built, so a list of them costs the sum of every file. A
///   [`FileContent::Range`] is read at placement a mebibyte at a
///   time, so a list of them costs one mebibyte however large the files are.
/// - **One directory's clusters, while it is written**, one batch of the allocation table or
///   of the allocation bitmap, and one buffer of zeros. Only the first grows, with the
///   directory's entries and not with the volume.
/// - **One boot region and the up-case table**, both of them constants.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, the source names something the volume
/// cannot hold, or writing to `sink` fails.
pub fn format_to<W: Write + Seek>(
    sink: W,
    source: impl Source,
    volume_bytes: u64,
    options: FormatOptions,
) -> Result<FormatPlan, FormatError> {
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    plan.write_to(sink)?;
    Ok(plan)
}

/// Plan the geometry a format of `volume_bytes` realizes.
///
/// Both entry points come through here, so an input a format refuses is refused by both and is
/// refused before the destination is touched.
fn plan(volume_bytes: u64, options: &FormatOptions) -> Result<ExfatLayout, FormatError> {
    let mut request = options.plan;
    request.volume_bytes = volume_bytes;
    Ok(plan_layout(&request)?)
}

/// One boot region's twelve sectors, checksum sector included.
///
/// Built whole rather than sector by sector because the checksum is over the first eleven of
/// them in byte order, and the three offsets it steps over belong to the first — so the region
/// is one buffer and the skip applies once, rather than a per-sector rule that would have to
/// know which sector it was looking at.
fn boot_region(
    layout: &ExfatLayout,
    options: &FormatOptions,
    model: &ExfatModel,
) -> Result<Vec<u8>, FormatError> {
    let sector = layout.bytes_per_sector as usize;
    let mut region = vec![0u8; sector * BOOT_REGION_SECTORS as usize];

    boot_sector(layout, options, model).write_to(&mut region[..sector])?;

    for n in EXTENDED_BOOT_FIRST_SECTOR..EXTENDED_BOOT_FIRST_SECTOR + EXTENDED_BOOT_SECTORS {
        let at = n as usize * sector;
        write_extended_boot_sector(&mut region[at..at + sector]);
    }

    // The OEM parameters sector and the reserved sector behind it are left zero, which is what
    // the format defines as "no parameters recorded" — and they are inside the checksum, so
    // they are zero on purpose rather than by omission.

    let checksum_at = CHECKSUM_SECTOR as usize * sector;
    let checksum = boot_checksum(&region[..checksum_at]);
    write_checksum_sector(&mut region[checksum_at..checksum_at + sector], checksum);
    Ok(region)
}

/// The Main Boot Sector this layout, these options, and this tree describe.
fn boot_sector(
    layout: &ExfatLayout,
    options: &FormatOptions,
    model: &ExfatModel,
) -> MainBootSector {
    MainBootSector {
        jump_boot: MainBootSector::JUMP_BOOT,
        file_system_name: FILE_SYSTEM_NAME,
        // A volume this crate writes records nothing about where it sits on a medium. The
        // field is a hint for a boot loader that no driver consults, and a volume is read from
        // wherever it was found.
        partition_offset: 0,
        volume_length: layout.volume_length,
        fat_offset: layout.fat_offset,
        fat_length: layout.fat_length,
        cluster_heap_offset: layout.cluster_heap_offset,
        cluster_count: layout.cluster_count,
        first_cluster_of_root: layout.first_cluster_of_root,
        volume_serial: options.volume_serial,
        file_system_revision: FILE_SYSTEM_REVISION,
        // Clean: not the second allocation table, not open by a driver, no medium error, and
        // no claim about the bitmap's spare bits. The field is outside the region's checksum,
        // so it is the one place a wrong value costs nothing to write and everything to read.
        volume_flags: 0,
        bytes_per_sector_shift: layout.bytes_per_sector_shift(),
        sectors_per_cluster_shift: layout.sectors_per_cluster_shift(),
        number_of_fats: NUMBER_OF_FATS,
        drive_select: DRIVE_SELECT,
        percent_in_use: percent_in_use(model.used_clusters, layout.cluster_count),
        boot_code: options.boot_code,
    }
}

/// One stage of a format, in the order [`FormatPlan::stages`] hands them back.
///
/// Stages are applied one after another, each complete before the next begins. Within a
/// stage the pieces never share a sector, and they may be applied in any order. A sector is
/// written twice only across stages: the first zeroes what later ones fill.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum StageKind {
    /// Zeros over every byte before the cluster heap and over the end of the volume.
    ///
    /// This is what makes the destination's earlier contents irrelevant. Both boot regions of
    /// an earlier exFAT volume, and a signature another format keeps before the heap or in the
    /// volume's last mebibyte, are gone before anything new is written, so an interruption
    /// after this stage leaves nothing a driver mounts or a prober recognizes.
    Invalidate,
    /// The allocation table's head, the allocation bitmap, the up-case table, and every
    /// directory and file.
    Body,
    /// The backup boot region, sectors 12 through 23.
    BackupBootRegion,
    /// Sectors 1 through 11 of the main boot region: the extended boot sectors, the OEM
    /// parameters, the reserved sector, and the checksum over the region.
    MainBootTail,
    /// Sector 0, the main boot sector: the one every reader checks first, and so the last
    /// to be written.
    MainBootSector,
}

impl StageKind {
    /// Every stage, in the order a format applies them.
    const ORDER: [Self; 5] = [
        Self::Invalidate,
        Self::Body,
        Self::BackupBootRegion,
        Self::MainBootTail,
        Self::MainBootSector,
    ];
}

/// One stage of a planned format: which it is, and the pieces that make it.
///
/// Built by [`FormatPlan::stages`], which hands back every stage in the order they must be
/// applied.
#[derive(Clone, Copy)]
pub struct Stage<'p> {
    plan: &'p FormatPlan,
    kind: StageKind,
}

impl<'p> Stage<'p> {
    /// Which stage this is.
    #[must_use]
    pub const fn kind(&self) -> StageKind {
        self.kind
    }

    /// The stage's pieces, each built as it is asked for.
    #[must_use]
    pub fn pieces(&self) -> Pieces<'p> {
        match stage_runs(self.plan, self.kind) {
            Ok(runs) => Pieces {
                plan: self.plan,
                runs: runs.into_iter(),
                pending: None,
            },
            Err(e) => Pieces {
                plan: self.plan,
                runs: Vec::new().into_iter(),
                pending: Some(e),
            },
        }
    }
}

impl core::fmt::Debug for Stage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stage")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// One run of bytes a format puts on the destination: where it goes, and what it is.
///
/// Every piece starts on a sector boundary. A piece of a file's contents is the file's
/// length, a piece ending where the volume does ends there even inside a sector — which only
/// a size that is not whole sectors makes happen — and every other piece is a whole number
/// of sectors.
///
/// A byte no piece covers lies in a free cluster, or past the recorded length of the stream
/// that owns it, so nothing ever reads it. A caller writing whole sectors can therefore pad a
/// piece's last sector with anything.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Piece<'p> {
    /// Bytes the plan holds, or builds as the piece is asked for.
    #[non_exhaustive]
    Bytes {
        /// Where the bytes go, from the volume's start.
        offset: u64,
        /// The bytes.
        bytes: Cow<'p, [u8]>,
    },
    /// A run of zeros.
    #[non_exhaustive]
    Zeros {
        /// Where the run begins, from the volume's start.
        offset: u64,
        /// How many zero bytes it is.
        len: u64,
    },
    /// A file's contents, which are a range of a file on the host.
    #[non_exhaustive]
    Range {
        /// Where the contents go, from the volume's start.
        offset: u64,
        /// The range they are read from.
        range: &'p FileRange,
    },
    /// The contents of a file declared by its length alone, which the caller supplies.
    ///
    /// A hard link is written as a second copy of its file, so one key can name more than
    /// one piece.
    #[non_exhaustive]
    Declared {
        /// Where the contents go, from the volume's start.
        offset: u64,
        /// How many bytes they are.
        len: u64,
        /// The key the file was declared with.
        key: u64,
    },
}

impl Piece<'_> {
    /// Where the piece begins, in bytes from the volume's start.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        match self {
            Self::Bytes { offset, .. }
            | Self::Zeros { offset, .. }
            | Self::Range { offset, .. }
            | Self::Declared { offset, .. } => *offset,
        }
    }

    /// How many bytes the piece covers.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Bytes { bytes, .. } => bytes.len() as u64,
            Self::Zeros { len, .. } | Self::Declared { len, .. } => *len,
            Self::Range { range, .. } => range.len(),
        }
    }

    /// Whether the piece covers nothing, which no piece a plan hands back does.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The pieces of one stage, each built as it is asked for.
///
/// What is held at once is one directory's clusters, one batch of the allocation table or
/// the bitmap, or one boot region. A file's contents are named by a piece rather than held
/// by it. The sequence ends after the first error.
pub struct Pieces<'p> {
    plan: &'p FormatPlan,
    runs: std::vec::IntoIter<Run<'p>>,
    /// A failure deciding the stage's runs, handed out as the first item.
    pending: Option<FormatError>,
}

impl<'p> Iterator for Pieces<'p> {
    type Item = Result<Piece<'p>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.pending.take() {
            return Some(Err(e));
        }
        let run = self.runs.next()?;
        let piece = realize(self.plan, run);
        if piece.is_err() {
            self.runs = Vec::new().into_iter();
        }
        Some(piece)
    }
}

impl core::fmt::Debug for Pieces<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pieces")
            .field("remaining", &self.runs.len())
            .finish_non_exhaustive()
    }
}

/// A piece decided but not yet built: what [`Pieces`] holds between one item and the next.
enum Run<'p> {
    /// A piece known in full.
    Ready(Piece<'p>),
    /// Allocation table entries `first..first + count`, at `offset`, the last of the
    /// format's own chains ending at `last`.
    Table {
        offset: u64,
        first: u32,
        count: u32,
        last: u32,
    },
    /// Bytes `from..from + len` of the allocation bitmap, at `offset`.
    Bitmap { offset: u64, from: u64, len: u64 },
    /// The up-case table, padded to `len` bytes, at `offset`.
    Upcase { offset: u64, len: u64 },
    /// Directory `index`, all of its clusters, at `offset`.
    Directory { index: usize, offset: u64 },
    /// Sectors `from..to` of the boot region, at `offset`.
    Boot { offset: u64, from: u64, to: u64 },
}

/// Every run one stage is made of, in ascending order of offset.
fn stage_runs(plan: &FormatPlan, kind: StageKind) -> Result<Vec<Run<'_>>, FormatError> {
    let sector = u64::from(plan.layout.bytes_per_sector);
    Ok(match kind {
        StageKind::Invalidate => invalidate_runs(plan),
        StageKind::Body => body_runs(plan)?,
        StageKind::BackupBootRegion => vec![Run::Boot {
            offset: BOOT_REGION_SECTORS * sector,
            from: 0,
            to: BOOT_REGION_SECTORS,
        }],
        StageKind::MainBootTail => vec![Run::Boot {
            offset: sector,
            from: 1,
            to: BOOT_REGION_SECTORS,
        }],
        StageKind::MainBootSector => vec![Run::Boot {
            offset: 0,
            from: 0,
            to: 1,
        }],
    })
}

/// The zeros that come first: everything before the cluster heap, and the end of the volume.
///
/// The end runs from the first free cluster or a mebibyte before the volume's last sector,
/// whichever is later — but never from past the heap's end, so the clusters the heap has no
/// room for, and the remainder of a size that is not whole sectors, are always covered.
fn invalidate_runs(plan: &FormatPlan) -> Vec<Run<'_>> {
    let layout = &plan.layout;
    let heap_at = u64::from(layout.cluster_heap_offset) * u64::from(layout.bytes_per_sector);
    let heap_end = heap_at + layout.heap_bytes();
    // Allocation is one ascending pass with no gaps from the heap's first cluster, so the
    // clusters in use are exactly the first `used_clusters` of it.
    let free_from =
        heap_at + u64::from(plan.model.used_clusters) * u64::from(layout.bytes_per_cluster);
    let tail_from = free_from.max(heap_end.min(layout.total_bytes().saturating_sub(TAIL_BYTES)));
    [(0, heap_at), (tail_from, plan.volume_bytes)]
        .into_iter()
        .filter(|(from, to)| to > from)
        .map(|(offset, to)| {
            Run::Ready(Piece::Zeros {
                offset,
                len: to - offset,
            })
        })
        .collect()
}

/// Everything the volume holds: the allocation table's head, the bitmap, the up-case table,
/// and each directory followed by the files it names.
fn body_runs(plan: &FormatPlan) -> Result<Vec<Run<'_>>, FormatError> {
    let layout = &plan.layout;
    let model = &plan.model;
    let sector = u64::from(layout.bytes_per_sector);
    let cluster = u64::from(layout.bytes_per_cluster);
    let mut runs = Vec::new();

    // The table's head: the two reserved entries and the chains of the three residents. The
    // root's chain is as long as the root is, which the tree decides, and everything the
    // format itself allocated ends there. Every batch but the last is a whole number of
    // sectors, and the last is padded to one, so no two share a sector.
    let last = layout.first_cluster_of_root + model.dirs[ROOT_DIR].run.count - 1;
    let mut first = 0u32;
    while first <= last {
        let count = (last - first + 1).min(TABLE_BATCH_ENTRIES as u32);
        let offset = layout
            .fat_entry_byte(first)
            .ok_or(FormatError::ClusterOutsideVolume {
                region: "the allocation table's entry",
                cluster: first,
            })?;
        runs.push(Run::Table {
            offset,
            first,
            count,
            last,
        });
        first += count;
    }

    // The bitmap: the sectors holding a set bit in batches, and the rest as one run of zeros.
    // Allocation runs in one ascending pass with no gaps, so the set bits are a run at the
    // front — the tree is allocated from where the three residents end.
    let bitmap_at = cluster_start(layout, layout.bitmap_cluster, "the allocation bitmap")?;
    let set = u64::from(model.used_clusters)
        .div_ceil(8)
        .next_multiple_of(sector);
    let whole = layout.bitmap_bytes.next_multiple_of(sector);
    let mut from = 0u64;
    while from < set {
        let len = (set - from).min(BITMAP_BATCH_BYTES as u64);
        runs.push(Run::Bitmap {
            offset: bitmap_at + from,
            from,
            len,
        });
        from += len;
    }
    if whole > set {
        runs.push(Run::Ready(Piece::Zeros {
            offset: bitmap_at + set,
            len: whole - set,
        }));
    }

    // The up-case table padded to a sector, and zeros to the end of the clusters it takes.
    let upcase_at = cluster_start(layout, layout.upcase_cluster, "the up-case table")?;
    let table = RECOMMENDED_UPCASE_BYTES.next_multiple_of(sector);
    let clusters = layout.clusters_for(layout.upcase_bytes) * cluster;
    runs.push(Run::Upcase {
        offset: upcase_at,
        len: table,
    });
    if clusters > table {
        runs.push(Run::Ready(Piece::Zeros {
            offset: upcase_at + table,
            len: clusters - table,
        }));
    }

    // Each directory, whole, then the files it names — the order they were allocated in, so
    // the offsets ascend.
    for (index, dir) in model.dirs.iter().enumerate() {
        runs.push(Run::Directory {
            index,
            offset: cluster_start(layout, dir.run.first, "a directory")?,
        });
        for entry in &dir.entries {
            let Node::File { content, size, run } = entry.node else {
                continue;
            };
            if run.is_empty() {
                continue;
            }
            let content = &model.contents[content];
            // The length the entry records was taken from this content when the model was
            // built, and the content hands back exactly what it declares or fails — so the two
            // agree. Checked in every build: a content longer than its entry would run on into
            // the clusters placed after it, which is the direction nothing downstream can
            // notice.
            assert_eq!(
                content.len(),
                size,
                "a file's contents are not the length its entry records"
            );
            let offset = cluster_start(layout, run.first, "a file")?;
            runs.push(Run::Ready(match content {
                FileContent::Owned(bytes) => Piece::Bytes {
                    offset,
                    bytes: Cow::Borrowed(bytes),
                },
                FileContent::Range(range) => Piece::Range { offset, range },
                FileContent::Declared { len, key } => Piece::Declared {
                    offset,
                    len: *len,
                    key: *key,
                },
            }));
        }
    }
    Ok(runs)
}

/// Where cluster `n` begins, or the failure naming what needed it.
fn cluster_start(layout: &ExfatLayout, n: u32, region: &'static str) -> Result<u64, FormatError> {
    layout
        .cluster_start_byte(n)
        .ok_or(FormatError::ClusterOutsideVolume { region, cluster: n })
}

/// Build the piece a run describes.
fn realize<'p>(plan: &'p FormatPlan, run: Run<'p>) -> Result<Piece<'p>, FormatError> {
    let layout = &plan.layout;
    let sector = u64::from(layout.bytes_per_sector);
    let bytes = match run {
        Run::Ready(piece) => return Ok(piece),
        Run::Table {
            offset,
            first,
            count,
            last,
        } => {
            let mut batch = vec![0u8; (u64::from(count) * 4).next_multiple_of(sector) as usize];
            for i in 0..count {
                put_u32(
                    &mut batch,
                    i as usize * 4,
                    table_entry(layout, last, first + i),
                );
            }
            (offset, batch)
        }
        Run::Bitmap { offset, from, len } => {
            (offset, bitmap_bytes(plan.model.used_clusters, from, len))
        }
        Run::Upcase { offset, len } => {
            let mut table = vec![0u8; len as usize];
            write_upcase_table(
                &RECOMMENDED_UPCASE_TABLE,
                &mut table[..RECOMMENDED_UPCASE_BYTES as usize],
            )?;
            (offset, table)
        }
        Run::Directory { index, offset } => (offset, directory_clusters(plan, index)?),
        Run::Boot { offset, from, to } => {
            let region = boot_region(layout, &plan.options, &plan.model)?;
            let s = sector as usize;
            (offset, region[from as usize * s..to as usize * s].to_vec())
        }
    };
    Ok(Piece::Bytes {
        offset: bytes.0,
        bytes: Cow::Owned(bytes.1),
    })
}

/// Bytes `from..from + len` of an allocation bitmap whose first `used` bits are set.
///
/// The low bits of a byte are the earlier clusters: bit 0 of byte 0 is the heap's first
/// cluster, which is what makes the byte the run ends part way through a mask of its low
/// bits.
fn bitmap_bytes(used: u32, from: u64, len: u64) -> Vec<u8> {
    let whole = u64::from(used) / 8;
    let remainder = used % 8;
    (from..from + len)
        .map(|n| match n.cmp(&whole) {
            core::cmp::Ordering::Less => 0xFF,
            core::cmp::Ordering::Equal if remainder != 0 => 0xFF >> (8 - remainder),
            _ => 0,
        })
        .collect()
}

/// Directory `index`'s clusters: its entries, then zeros to the end of its last cluster.
///
/// The zeros are what end the directory. A reader stops at the first slot whose type byte is
/// zero and the format requires every slot behind it to be one, so the slots past the last
/// entry set are written rather than left to whatever the destination held.
fn directory_clusters(plan: &FormatPlan, index: usize) -> Result<Vec<u8>, FormatError> {
    let mut bytes = directory_bytes(&plan.model, &plan.layout, &plan.options, index)?;
    // What was planned and what is written are two computations of one number, and the bytes
    // hide a disagreement between them: a directory written past its own clusters lands on
    // whatever was placed after it. Checked here, where both numbers are in hand, and in
    // every build.
    let run = plan.model.dirs[index].run;
    let capacity = u64::from(run.count) * u64::from(plan.layout.bytes_per_cluster);
    if bytes.len() as u64 > capacity {
        return Err(FormatError::DirectoryOverflowsItsClusters {
            index,
            bytes: bytes.len() as u64,
            capacity,
        });
    }
    bytes.resize(capacity as usize, 0);
    Ok(bytes)
}

/// The allocation table entry for cluster `n`, for the clusters a format itself chains.
///
/// The three are laid down contiguously and in order, so each cluster chains to the next except
/// the last of each, which ends its chain. That is the whole of the arithmetic: the bitmap ends
/// where the up-case table begins, the up-case table ends where the root begins, and the root
/// ends at `last`.
fn table_entry(layout: &ExfatLayout, last: u32, n: u32) -> u32 {
    match n {
        0 => FAT_ENTRY_MEDIA,
        1 => FAT_ENTRY_RESERVED,
        _ if n + 1 == layout.upcase_cluster => END_OF_CHAIN,
        _ if n + 1 == layout.first_cluster_of_root => END_OF_CHAIN,
        _ if n == last => END_OF_CHAIN,
        _ => n + 1,
    }
}

/// One directory's entries, serialized in the order they are written.
///
/// The root leads with the four entries a format writes on every volume — the volume's name,
/// the slot reserved for a volume GUID, and the two describing the residents of the heap — and
/// every other directory leads with nothing at all: exFAT has no `.` and `..` entries, so a
/// directory is its file sets and only those.
///
/// The terminator behind the last set is the zero byte the rest of the directory's clusters
/// are filled with, which [`directory_clusters`] writes along with the entries.
fn directory_bytes(
    model: &ExfatModel,
    layout: &ExfatLayout,
    options: &FormatOptions,
    index: usize,
) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();

    if index == ROOT_DIR {
        out.resize(ROOT_LEADING_SLOTS as usize * DIR_ENTRY_SIZE, 0);
        options.label.entry().write_to(&mut out[..DIR_ENTRY_SIZE])?;
        // The slot for a volume GUID nobody supplied. It is written rather than skipped
        // because one entry alone can never hold a file set, so the alternative to reserving
        // the slot is ending the directory here — with the bitmap and the up-case table behind
        // it.
        DirEntry::reserved(EntryType::VOLUME_GUID).write_to(&mut out[DIR_ENTRY_SIZE..])?;
        AllocationBitmapEntry {
            bitmap_flags: 0,
            first_cluster: layout.bitmap_cluster,
            data_length: layout.bitmap_bytes,
        }
        .write_to(&mut out[2 * DIR_ENTRY_SIZE..])?;
        UpcaseTableEntry {
            table_checksum: RECOMMENDED_UPCASE_CHECKSUM,
            first_cluster: layout.upcase_cluster,
            data_length: layout.upcase_bytes,
        }
        .write_to(&mut out[3 * DIR_ENTRY_SIZE..])?;
    }

    for entry in &model.dirs[index].entries {
        push_entry_set(&mut out, model, layout, entry)?;
    }
    Ok(out)
}

/// Append one entry's whole set: the file entry, its stream extension, and its name.
///
/// The set is laid out first and checksummed second, because the checksum covers every byte of
/// it including the two entries behind the one that carries the answer. Patching the field
/// afterwards is what the format's own arithmetic requires — it steps over exactly those two
/// bytes — rather than a shortcut around building the set twice.
fn push_entry_set(
    out: &mut Vec<u8>,
    model: &ExfatModel,
    layout: &ExfatLayout,
    entry: &ModelEntry,
) -> Result<(), FormatError> {
    let start = out.len();
    let slots = entry.name.slots() as usize;
    out.resize(start + slots * DIR_ENTRY_SIZE, 0);
    let set = &mut out[start..];

    FileEntry {
        secondary_count: entry.name.secondary_count(),
        // Filled in below, once there is a set to checksum.
        set_checksum: 0,
        attributes: entry.attributes,
        create: pack_timestamp(entry.times.create),
        modify: pack_timestamp(entry.times.modify),
        access: pack_timestamp(entry.times.access),
        create_tenth: entry.times.create.tenth,
        modify_tenth: entry.times.modify.tenth,
        // The times this crate is given are instants, so the volume records that they are UTC
        // rather than leaving a reader to guess a locality it has no way to know.
        create_utc_offset: UTC_OFFSET,
        modify_utc_offset: UTC_OFFSET,
        access_utc_offset: UTC_OFFSET,
    }
    .write_to(set)?;

    let (run, data_length) = model.entry_target(entry.node, layout.bytes_per_cluster);
    StreamExtensionEntry {
        flags: stream_flags(run),
        // Bounded by the name module, which refuses anything past 255 units.
        name_length: entry.name.units.len() as u8,
        name_hash: entry.name.hash,
        // A format writes every byte it allocates, so there is no allocated tail whose
        // contents are undefined and the two lengths are one number.
        valid_data_length: data_length,
        first_cluster: run.first,
        data_length,
    }
    .write_to(&mut set[DIR_ENTRY_SIZE..])?;

    for (n, chunk) in entry.name.units.chunks(NAME_UNITS_PER_ENTRY).enumerate() {
        FileNameEntry::new(chunk).write_to(&mut set[(2 + n) * DIR_ENTRY_SIZE..])?;
    }

    let checksum = entry_set_checksum(&set[..slots * DIR_ENTRY_SIZE]);
    crate::bytes::put_u16(set, 2, checksum);
    Ok(())
}

/// The secondary flags a stream extension carries for `run`.
///
/// `AllocationPossible` is set on every stream extension, whether or not it currently addresses
/// anything — the format defines the entry that way. `NoFatChain` is set only where there are
/// clusters to describe: the flag says the allocation table holds no chain for this stream, and
/// a stream with no allocation has nothing for either to say.
const fn stream_flags(run: ClusterRun) -> u8 {
    if run.is_empty() {
        SECONDARY_ALLOCATION_POSSIBLE
    } else {
        SECONDARY_ALLOCATION_POSSIBLE | SECONDARY_NO_FAT_CHAIN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{get_u16, get_u32, get_u64};
    use crate::exfat::ClusterSize;
    use crate::exfat::geometry::FIRST_CLUSTER;
    use crate::exfat::ondisk::{
        BOOT_SIGNATURE, EXTENDED_BOOT_SIGNATURE, FileAttributes, MAX_NAME_UNITS,
        MUST_BE_ZERO_RANGE, checksum_sector_value, extended_boot_signature, upcase_checksum,
    };
    use crate::fidelity::{Direction, Property};
    use crate::source::{Metadata, TreeBuilder};
    use crate::time::Timestamp;

    /// An instant every field of an entry holds exactly, so nothing under test is also
    /// exercising a rounding.
    const TIME: Timestamp = Timestamp {
        secs: 1_426_325_212,
        nanos: 0,
    };

    /// A source that places nothing, which is what an empty volume is formatted from.
    fn empty() -> TreeBuilder {
        TreeBuilder::new()
    }

    /// A 64 MiB volume, which convention formats at four-kilobyte clusters and whose up-case
    /// table therefore spans two of them.
    fn image() -> Image {
        format(empty(), 64 << 20, FormatOptions::new(0x1234_5678)).expect("format")
    }

    #[test]
    fn the_image_is_the_size_it_was_asked_for() {
        let image = format(empty(), 64 << 20, FormatOptions::new(1)).expect("format");
        assert_eq!(image.as_bytes().len(), 64 << 20);

        // A size that is not whole sectors: the filesystem is the sectors it has and the
        // remainder lies past its end, but the destination is still the size that was named.
        let ragged = format(empty(), (64 << 20) + 511, FormatOptions::new(1)).expect("format");
        assert_eq!(ragged.as_bytes().len(), (64 << 20) + 511);
        assert_eq!(ragged.layout().volume_length, image.layout().volume_length);
    }

    #[test]
    fn two_formats_of_the_same_parameters_are_the_same_bytes() {
        // The whole of what reproducibility costs this family: one input. An empty volume
        // records no time anywhere, so there is nothing else for a clock to reach.
        let options = FormatOptions::new(0xDEAD_BEEF).label(VolumeLabel::new("CARD").unwrap());
        assert_eq!(
            format(empty(), 32 << 20, options)
                .expect("format")
                .into_bytes(),
            format(empty(), 32 << 20, options)
                .expect("format")
                .into_bytes()
        );

        // And the serial is what makes two volumes different, so it has to reach the bytes.
        assert_ne!(
            format(empty(), 32 << 20, FormatOptions::new(1))
                .expect("format")
                .into_bytes(),
            format(empty(), 32 << 20, FormatOptions::new(2))
                .expect("format")
                .into_bytes()
        );
    }

    #[test]
    fn both_boot_regions_are_written_and_each_carries_its_own_checksum() {
        let image = image();
        let layout = *image.layout();
        let bytes = image.as_bytes();
        let sector = layout.bytes_per_sector as usize;
        let region = BOOT_REGION_SECTORS as usize * sector;

        let main = &bytes[..region];
        let backup = &bytes[region..2 * region];
        assert_eq!(main, backup, "the backup region is a copy");

        for (which, region) in [main, backup].into_iter().enumerate() {
            let checksum_at = 11 * sector;
            assert_eq!(
                checksum_sector_value(&region[checksum_at..]),
                Some(boot_checksum(&region[..checksum_at])),
                "region {which}"
            );
            for n in 1..9 {
                assert_eq!(
                    extended_boot_signature(&region[n * sector..(n + 1) * sector]),
                    Some(EXTENDED_BOOT_SIGNATURE),
                    "region {which}, extended boot sector {n}"
                );
            }
            // The two sectors a format has nothing to put in are zero on purpose: they are
            // inside the checksum, so what is in them is part of the answer.
            assert!(
                region[9 * sector..11 * sector].iter().all(|b| *b == 0),
                "region {which}: the parameters and reserved sectors"
            );
        }
    }

    #[test]
    fn the_boot_sector_records_the_geometry_that_was_planned() {
        let image = image();
        let layout = *image.layout();
        let boot = MainBootSector::read_from(image.as_bytes()).expect("read");

        assert_eq!(boot.volume_length, layout.volume_length);
        assert_eq!(boot.fat_offset, layout.fat_offset);
        assert_eq!(boot.fat_length, layout.fat_length);
        assert_eq!(boot.cluster_heap_offset, layout.cluster_heap_offset);
        assert_eq!(boot.cluster_count, layout.cluster_count);
        assert_eq!(boot.first_cluster_of_root, layout.first_cluster_of_root);
        assert_eq!(boot.volume_serial, 0x1234_5678);
        assert_eq!(boot.file_system_revision, FILE_SYSTEM_REVISION);
        assert_eq!(boot.number_of_fats, NUMBER_OF_FATS);
        assert_eq!(boot.bytes_per_sector(), Some(layout.bytes_per_sector));
        assert_eq!(boot.bytes_per_cluster(), Some(layout.bytes_per_cluster));

        // A volume that has just been laid out is not dirty, is not on failing media, and has
        // no second allocation table to select between.
        assert_eq!(boot.volume_flags, 0);
        assert!(image.as_bytes()[MUST_BE_ZERO_RANGE].iter().all(|b| *b == 0));
        assert_eq!(&image.as_bytes()[510..512], &BOOT_SIGNATURE.to_le_bytes());
    }

    #[test]
    fn how_full_the_volume_is_is_computed_rather_than_left_at_zero() {
        // A fresh volume of any ordinary size rounds to zero, which is what makes this worth a
        // test of its own: a formatter that never wrote the field at all would look identical
        // on every volume anyone formats. These two geometries are the ones where the residents
        // are a large enough share of the heap for the difference to show.
        let coarse = format(
            empty(),
            4 << 20,
            FormatOptions::new(1)
                .plan(PlanRequest::new(0).cluster_size(ClusterSize::Bytes(32 << 10))),
        )
        .expect("format");
        // Three clusters of sixty-four: a bitmap, an up-case table, and a root directory.
        assert_eq!(coarse.layout().cluster_count, 64);
        assert_eq!(
            MainBootSector::read_from(coarse.as_bytes())
                .unwrap()
                .percent_in_use,
            4
        );

        let ordinary = image();
        assert_eq!(
            MainBootSector::read_from(ordinary.as_bytes())
                .unwrap()
                .percent_in_use,
            0,
            "a volume with room rounds down to nothing, and says so"
        );
    }

    #[test]
    fn the_allocation_table_chains_each_resident_and_stops() {
        for cluster in [ClusterSize::Bytes(512), ClusterSize::Bytes(4 << 10)] {
            let image = format(
                empty(),
                64 << 20,
                FormatOptions::new(1).plan(PlanRequest::new(0).cluster_size(cluster)),
            )
            .expect("format");
            let layout = *image.layout();
            let what = format!("{cluster:?}");
            let entry = |n: u32| {
                get_u32(
                    image.as_bytes(),
                    layout.fat_entry_byte(n).expect("in the table") as usize,
                )
            };

            assert_eq!(entry(0), FAT_ENTRY_MEDIA, "{what}");
            assert_eq!(entry(1), FAT_ENTRY_RESERVED, "{what}");

            // Each resident's clusters chain to the next and the last of each ends. Walking the
            // chain is what says so, rather than reading the entries the writer wrote.
            for (first, past) in [
                (layout.bitmap_cluster, layout.upcase_cluster),
                (layout.upcase_cluster, layout.first_cluster_of_root),
                (
                    layout.first_cluster_of_root,
                    layout.first_cluster_of_root + 1,
                ),
            ] {
                let mut at = first;
                let mut steps = 0;
                while entry(at) != END_OF_CHAIN {
                    assert_eq!(entry(at), at + 1, "{what}: cluster {at} chains forward");
                    at = entry(at);
                    steps += 1;
                    assert!(
                        steps < past - first + 1,
                        "{what}: chain from {first} runs on"
                    );
                }
                assert_eq!(
                    at,
                    past - 1,
                    "{what}: the chain from {first} ends where it should"
                );
            }

            // And nothing past the residents is allocated.
            assert_eq!(entry(layout.first_cluster_of_root + 1), 0, "{what}");
        }
    }

    #[test]
    fn the_bitmap_sets_a_bit_for_each_resident_cluster_and_no_others() {
        for cluster in [ClusterSize::Bytes(512), ClusterSize::Bytes(32 << 10)] {
            let image = format(
                empty(),
                64 << 20,
                FormatOptions::new(1).plan(PlanRequest::new(0).cluster_size(cluster)),
            )
            .expect("format");
            let layout = *image.layout();
            let what = format!("{cluster:?}");
            let at = layout.cluster_start_byte(layout.bitmap_cluster).unwrap() as usize;
            let bitmap = &image.as_bytes()[at..at + layout.bitmap_bytes as usize];

            // The three the format put in the heap, an empty volume having nothing else.
            let used = (layout.first_cluster_of_root + 1 - FIRST_CLUSTER) as usize;
            let set: usize = bitmap.iter().map(|b| b.count_ones() as usize).sum();
            assert_eq!(set, used, "{what}: one bit per resident cluster");

            // Not just the count — the right bits. The heap's first cluster is bit 0 of byte 0,
            // so the residents are a run at the front and the first free cluster is the first
            // clear bit.
            for n in 0..used {
                assert_eq!(bitmap[n / 8] >> (n % 8) & 1, 1, "{what}: bit {n} is set");
            }
            assert_eq!(bitmap[used / 8] >> (used % 8) & 1, 0, "{what}: bit {used}");
        }
    }

    #[test]
    fn the_up_case_table_lands_where_its_entry_says_and_checksums_to_what_it_advertises() {
        let image = image();
        let layout = *image.layout();
        let at = layout.cluster_start_byte(layout.upcase_cluster).unwrap() as usize;
        let table = &image.as_bytes()[at..at + layout.upcase_bytes as usize];
        assert_eq!(upcase_checksum(table), RECOMMENDED_UPCASE_CHECKSUM);

        // The padding from the table's end to the end of the cluster it occupies is zero, which
        // is the part a byte comparison against another implementation's output turns on.
        let span = layout.clusters_for(layout.upcase_bytes) * u64::from(layout.bytes_per_cluster);
        assert!(
            image.as_bytes()[at + table.len()..at + span as usize]
                .iter()
                .all(|b| *b == 0)
        );
    }

    #[test]
    fn the_root_directory_holds_the_slots_a_format_writes_in_the_order_it_writes_them() {
        let image = format(
            empty(),
            32 << 20,
            FormatOptions::new(1).label(VolumeLabel::new("FERROSYS").unwrap()),
        )
        .expect("format");
        let layout = *image.layout();
        let at = layout
            .cluster_start_byte(layout.first_cluster_of_root)
            .unwrap() as usize;
        let root = &image.as_bytes()[at..at + layout.bytes_per_cluster as usize];
        let slot = |n: usize| &root[n * DIR_ENTRY_SIZE..(n + 1) * DIR_ENTRY_SIZE];

        let label = VolumeLabelEntry::read_from(slot(0)).expect("a label entry");
        assert_eq!(label.character_count, 8);
        assert_eq!(
            &label.label[..8],
            &"FERROSYS".encode_utf16().collect::<Vec<_>>()[..]
        );

        // The reserved slot, which a reader steps over rather than stopping at.
        assert_eq!(slot(1)[0], EntryType::VOLUME_GUID.cleared().0);
        assert!(slot(1)[1..].iter().all(|b| *b == 0));

        let bitmap = AllocationBitmapEntry::read_from(slot(2)).expect("a bitmap entry");
        assert_eq!(bitmap.first_cluster, layout.bitmap_cluster);
        assert_eq!(bitmap.data_length, layout.bitmap_bytes);
        assert_eq!(bitmap.data_length, get_u64(slot(2), 24));

        let upcase = UpcaseTableEntry::read_from(slot(3)).expect("an up-case entry");
        assert_eq!(upcase.first_cluster, layout.upcase_cluster);
        assert_eq!(upcase.data_length, RECOMMENDED_UPCASE_BYTES);
        assert_eq!(upcase.table_checksum, RECOMMENDED_UPCASE_CHECKSUM);

        // The directory ends at the zero byte behind the last entry, and the rest of the
        // cluster is the zero it was never written with.
        assert!(root[4 * DIR_ENTRY_SIZE..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_volume_with_no_name_carries_the_label_entry_all_the_same() {
        let image = image();
        let layout = *image.layout();
        let at = layout
            .cluster_start_byte(layout.first_cluster_of_root)
            .unwrap() as usize;
        let label = VolumeLabelEntry::read_from(&image.as_bytes()[at..]).expect("a label entry");
        assert_eq!(label, VolumeLabelEntry::UNNAMED);
    }

    #[test]
    fn streaming_a_volume_and_holding_one_produce_the_same_bytes() {
        // The two entry points are one implementation, and this is what says so. It is also
        // what says the streaming path leaves nothing out: a sector the streaming writer never
        // touched has to be a sector the in-memory one left zero.
        let options = FormatOptions::new(0x0BAD_F00D).label(VolumeLabel::new("SD").unwrap());
        let held = format(empty(), 32 << 20, options).expect("format");
        let mut streamed = Cursor::new(Vec::new());
        let plan = format_to(&mut streamed, empty(), 32 << 20, options).expect("format");
        assert_eq!(plan.layout(), held.layout());
        assert_eq!(streamed.into_inner(), held.into_bytes());
    }

    #[test]
    fn the_boot_code_a_caller_supplies_reaches_the_sector_and_the_checksum() {
        let mut code = [0u8; BOOT_CODE_LEN];
        code[..4].copy_from_slice(b"\xEB\x3C\x90\x00");
        let plain = format(empty(), 32 << 20, FormatOptions::new(7)).expect("format");
        let booting =
            format(empty(), 32 << 20, FormatOptions::new(7).boot_code(code)).expect("format");

        assert_eq!(&booting.as_bytes()[120..124], b"\xEB\x3C\x90\x00");
        // Inside the checksum, so the two volumes differ in the checksum sector as well as in
        // the boot sector — which is the whole reason the code is an input rather than
        // something to patch in afterwards.
        let sector = plain.layout().bytes_per_sector as usize;
        assert_ne!(
            &plain.as_bytes()[11 * sector..12 * sector],
            &booting.as_bytes()[11 * sector..12 * sector]
        );
    }

    /// The entries of the directory beginning at `cluster`, as raw slots.
    fn slots_at(image: &Image, cluster: u32, count: usize) -> Vec<&[u8]> {
        let at = image
            .layout()
            .cluster_start_byte(cluster)
            .expect("a cluster") as usize;
        (0..count)
            .map(|n| &image.as_bytes()[at + n * DIR_ENTRY_SIZE..at + (n + 1) * DIR_ENTRY_SIZE])
            .collect()
    }

    #[test]
    fn a_file_becomes_a_set_whose_checksum_covers_every_entry_in_it() {
        let image = format(
            TreeBuilder::new().file(
                b"/README.TXT".to_vec(),
                b"hello\n",
                Metadata::new(0o644, TIME),
            ),
            32 << 20,
            FormatOptions::new(1),
        )
        .expect("format");
        let layout = *image.layout();
        // The four the format writes ahead of the tree, then the file's three.
        let slots = slots_at(&image, layout.first_cluster_of_root, 8);

        let file = FileEntry::read_from(slots[4]).expect("a file entry");
        assert_eq!(file.secondary_count, 2, "a stream extension and one name");
        assert_eq!(file.attributes, FileAttributes::ARCHIVE);
        assert_eq!(file.create, file.modify, "a creation time is derived");
        assert_eq!(file.create_utc_offset, UTC_OFFSET);
        assert_eq!(file.modify_utc_offset, UTC_OFFSET);
        assert_eq!(file.access_utc_offset, UTC_OFFSET);

        let stream = StreamExtensionEntry::read_from(slots[5]).expect("a stream extension");
        assert_eq!(stream.name_length, 10);
        assert_eq!(stream.data_length, 6);
        assert_eq!(
            stream.valid_data_length, 6,
            "a format writes what it allocates"
        );
        assert!(stream.no_fat_chain());

        let name = FileNameEntry::read_from(slots[6]).expect("a name entry");
        assert_eq!(
            &name.units[..10],
            &"README.TXT".encode_utf16().collect::<Vec<_>>()[..]
        );
        assert!(
            slots[7][0] == 0,
            "the directory ends at the zero byte behind it"
        );

        // The checksum is over the whole set with the field itself stepped over, so it is
        // recomputed here from the bytes on the image rather than read back through the field.
        let set: Vec<u8> = slots[4..7].concat();
        assert_eq!(file.set_checksum, entry_set_checksum(&set));
        assert_eq!(file.set_checksum, get_u16(slots[4], 2));

        // And the hash is over the *folded* name, which is what a driver looks a name up by.
        let folded = UpcaseTable::recommended().fold(&name.units[..10]);
        assert_eq!(stream.name_hash, crate::exfat::ondisk::name_hash(&folded));
    }

    #[test]
    fn a_files_bytes_land_where_its_stream_extension_says_they_do() {
        let contents: Vec<u8> = (0..9_000u32).map(|n| n as u8).collect();
        let image = format(
            TreeBuilder::new()
                .file(
                    b"/a.bin".to_vec(),
                    contents.clone(),
                    Metadata::new(0o644, TIME),
                )
                .file(b"/b.bin".to_vec(), b"second", Metadata::new(0o644, TIME)),
            32 << 20,
            FormatOptions::new(1),
        )
        .expect("format");
        let layout = *image.layout();

        // Read the volume the way a driver would: find the set, take its first cluster and its
        // length, and go there. That is what says the entry describes the bytes rather than that
        // two writers agreed.
        for (slot, expected) in [(5usize, &contents[..]), (8, b"second")] {
            let stream = StreamExtensionEntry::read_from(
                slots_at(&image, layout.first_cluster_of_root, slot + 1)[slot],
            )
            .expect("a stream extension");
            let at = layout
                .cluster_start_byte(stream.first_cluster)
                .expect("a cluster") as usize;
            assert_eq!(
                &image.as_bytes()[at..at + stream.data_length as usize],
                expected
            );
        }
    }

    #[test]
    fn a_subdirectory_holds_its_own_sets_and_no_dot_entries() {
        let image = format(
            TreeBuilder::new()
                .directory(b"/dir".to_vec(), Metadata::new(0o755, TIME))
                .file(b"/dir/inner.txt".to_vec(), b"x", Metadata::new(0o644, TIME)),
            32 << 20,
            FormatOptions::new(1),
        )
        .expect("format");
        let layout = *image.layout();

        let stream =
            StreamExtensionEntry::read_from(slots_at(&image, layout.first_cluster_of_root, 6)[5])
                .expect("a stream extension");
        // A directory's length is its whole allocation, which the format states as a number of
        // clusters — unlike a file's, which is its bytes.
        assert_eq!(stream.data_length, u64::from(layout.bytes_per_cluster));
        assert_eq!(stream.valid_data_length, stream.data_length);

        // exFAT has no `.` and `..`: a directory is its file sets and nothing else, so the
        // child's first slot is already the entry it holds.
        let inner = slots_at(&image, stream.first_cluster, 3);
        let file = FileEntry::read_from(inner[0]).expect("a file entry");
        assert_eq!(file.attributes, FileAttributes::ARCHIVE);
        let name = FileNameEntry::read_from(inner[2]).expect("a name entry");
        assert_eq!(
            &name.units[..9],
            &"inner.txt".encode_utf16().collect::<Vec<_>>()[..]
        );
    }

    #[test]
    fn a_name_too_long_for_one_entry_is_spread_across_as_many_as_it_needs() {
        let name = "n".repeat(MAX_NAME_UNITS);
        let image = format(
            TreeBuilder::new().file(
                format!("/{name}").into_bytes(),
                b"x",
                Metadata::new(0o644, TIME),
            ),
            32 << 20,
            FormatOptions::new(1),
        )
        .expect("format");
        let layout = *image.layout();
        let slots = slots_at(&image, layout.first_cluster_of_root, 4 + 19);

        let file = FileEntry::read_from(slots[4]).expect("a file entry");
        assert_eq!(
            file.secondary_count, 18,
            "a stream extension and seventeen names"
        );
        let stream = StreamExtensionEntry::read_from(slots[5]).expect("a stream extension");
        assert_eq!(stream.name_length, MAX_NAME_UNITS as u8);

        // Reassembled the way a reader will: fifteen units per entry, cut at the recorded
        // length, with the padding in the last entry unread.
        let mut units = Vec::new();
        for slot in &slots[6..4 + 19] {
            units.extend_from_slice(&FileNameEntry::read_from(slot).expect("a name").units);
        }
        assert_eq!(units.len(), 17 * NAME_UNITS_PER_ENTRY);
        units.truncate(usize::from(stream.name_length));
        assert_eq!(String::from_utf16(&units).expect("well-formed"), name);
    }

    #[test]
    fn a_root_directory_that_outgrows_one_cluster_is_chained_where_a_subdirectory_is_not() {
        // The one asymmetry in how this crate allocates: every stream a *set* describes declares
        // `NoFatChain`, and the root has no set to declare it in — so the root is the only part
        // of a populated volume whose chain the allocation table holds.
        let mut source = TreeBuilder::new();
        for n in 0..60u32 {
            source = source.file(
                format!("/file-{n:04}.txt").into_bytes(),
                b"x",
                Metadata::new(0o644, TIME),
            );
        }
        let image = format(source, 32 << 20, FormatOptions::new(1)).expect("format");
        let layout = *image.layout();
        let entry = |n: u32| {
            get_u32(
                image.as_bytes(),
                layout.fat_entry_byte(n).expect("in the table") as usize,
            )
        };

        // Sixty sets of three slots plus the four leading ones is 5888 bytes, which is two
        // four-kilobyte clusters.
        let root_first = layout.first_cluster_of_root;
        assert_eq!(entry(root_first), root_first + 1, "the root chains forward");
        assert_eq!(entry(root_first + 1), END_OF_CHAIN);

        // And the first file's clusters, which the tree allocated behind the root, have no table
        // entry at all: their stream extension says the table holds no chain for them.
        assert_eq!(entry(root_first + 2), 0);
        let stream =
            StreamExtensionEntry::read_from(slots_at(&image, root_first, 6)[5]).expect("a stream");
        assert!(stream.no_fat_chain());
        assert_eq!(stream.first_cluster, root_first + 2);
    }

    #[test]
    fn the_bitmap_marks_every_cluster_the_tree_holds_however_it_is_addressed() {
        // The allocation table says nothing about a `NoFatChain` stream, so the bitmap is the
        // only record that its clusters are in use. Both come out of one planned allocation,
        // which is what makes them agree — and `fsck.exfat` checks only one direction, so a
        // disagreement here would pass a check on most of a volume.
        let image = format(
            TreeBuilder::new()
                .directory(b"/d".to_vec(), Metadata::new(0o755, TIME))
                .file(
                    b"/d/big".to_vec(),
                    vec![0u8; 20_000],
                    Metadata::new(0o644, TIME),
                ),
            32 << 20,
            FormatOptions::new(1),
        )
        .expect("format");
        let layout = *image.layout();
        let at = layout.cluster_start_byte(layout.bitmap_cluster).unwrap() as usize;
        let bitmap = &image.as_bytes()[at..at + layout.bitmap_bytes as usize];

        // Three residents, the root, the subdirectory, and five clusters of contents.
        let used = (layout.first_cluster_of_root - FIRST_CLUSTER) + 1 + 1 + 5;
        assert_eq!(
            bitmap.iter().map(|b| b.count_ones()).sum::<u32>(),
            used,
            "one bit per cluster in use"
        );
        for n in 0..used as usize {
            assert_eq!(bitmap[n / 8] >> (n % 8) & 1, 1, "bit {n} is set");
        }
        assert_eq!(bitmap[used as usize / 8] >> (used % 8) & 1, 0);
    }

    #[test]
    fn how_full_the_volume_is_counts_the_tree_and_not_only_the_format() {
        // The field the differential gate is blind to, asserted at a geometry the matrix has no
        // row for: every row of it rounds to zero however the field is computed.
        let options =
            FormatOptions::new(1).plan(PlanRequest::new(0).cluster_size(ClusterSize::Bytes(512)));
        let bare = format(empty(), 4 << 20, options).expect("format");
        let filled = format(
            TreeBuilder::new().file(
                b"/big".to_vec(),
                vec![0u8; 1 << 20],
                Metadata::new(0o644, TIME),
            ),
            4 << 20,
            options,
        )
        .expect("format");

        let percent = |image: &Image| {
            MainBootSector::read_from(image.as_bytes())
                .expect("a boot sector")
                .percent_in_use
        };
        assert_eq!(percent(&bare), 0);
        // A mebibyte of file is 2048 of the heap's 4096 half-kilobyte clusters, and the
        // volume's own structures take fourteen more.
        assert_eq!(bare.layout().cluster_count, 4096);
        assert_eq!(percent(&filled), 50);
    }

    #[test]
    fn an_empty_source_writes_the_volume_the_family_wrote_before_it_had_a_tree() {
        // A populated writer that degenerates exactly to the one before it is the strongest
        // available evidence that it disturbed nothing already established. What the four
        // leading slots and the residents' chains are is settled by the byte comparison against
        // the baseline; what this says is that placing nothing reaches it.
        let options = FormatOptions::new(0x0BAD_F00D).label(VolumeLabel::new("SD").unwrap());
        let bare = format(empty(), 32 << 20, options).expect("format");
        let layout = *bare.layout();
        let root = layout
            .cluster_start_byte(layout.first_cluster_of_root)
            .unwrap() as usize;
        assert!(
            bare.as_bytes()[root + ROOT_LEADING_SLOTS as usize * DIR_ENTRY_SIZE..][..layout
                .bytes_per_cluster
                as usize
                - ROOT_LEADING_SLOTS as usize * DIR_ENTRY_SIZE]
                .iter()
                .all(|b| *b == 0),
            "nothing follows the four entries a format writes"
        );
        assert_eq!(
            bare.layout().first_cluster_of_root,
            layout.first_cluster_of_root
        );
        assert!(bare.fidelity().is_faithful());
    }

    #[test]
    fn two_formats_of_the_same_tree_are_the_same_bytes_and_stream_identically() {
        let source = TreeBuilder::new()
            .directory(b"/DCIM".to_vec(), Metadata::new(0o755, TIME))
            .file(
                b"/DCIM/IMG_0001.JPG".to_vec(),
                b"\xFF\xD8\xFF",
                Metadata::new(0o644, TIME),
            )
            .file(
                b"/README.TXT".to_vec(),
                b"hello\n",
                Metadata::new(0o644, TIME),
            );
        let options = FormatOptions::new(0x1234_5678).label(VolumeLabel::new("CARD").unwrap());

        let held = format(source.clone(), 32 << 20, options).expect("format");
        assert_eq!(
            held.as_bytes(),
            format(source.clone(), 32 << 20, options)
                .expect("format")
                .as_bytes()
        );

        // And the streaming path is the same implementation, which is also what says it leaves
        // nothing out: a sector it never touched has to be one the in-memory path left zero.
        let mut streamed = Cursor::new(Vec::new());
        let plan = format_to(&mut streamed, source, 32 << 20, options).expect("format");
        assert_eq!(plan.layout(), held.layout());
        assert_eq!(streamed.into_inner(), held.into_bytes());
    }

    #[test]
    fn a_source_the_volume_cannot_hold_is_refused_before_the_destination_is_touched() {
        let source = TreeBuilder::new().file(
            b"/owned".to_vec(),
            b"x",
            Metadata {
                uid: 1000,
                gid: 1000,
                ..Metadata::new(0o644, TIME)
            },
        );
        let mut sink = Cursor::new(Vec::new());
        assert!(matches!(
            format_to(&mut sink, source.clone(), 32 << 20, FormatOptions::new(1)),
            Err(FormatError::Model(ModelError::LossNotAccepted {
                property: Property::Ownership,
                ..
            }))
        ));
        assert!(sink.into_inner().is_empty());

        // And with the loss accepted, the build succeeds and the report names what it cost.
        let plan = FormatPlan::new(
            source,
            32 << 20,
            FormatOptions::new(1).accepted_loss(AcceptedLoss::NONE.and(Property::Ownership)),
        )
        .expect("accepted");
        assert_eq!(
            plan.fidelity()
                .count(Direction::Dropped, Property::Ownership),
            1
        );
        // The account is available before the destination is touched, which is the whole reason
        // a plan and a write are two halves.
        assert!(plan.free_clusters() > 0);
    }

    #[test]
    fn a_geometry_that_cannot_be_realized_fails_before_the_destination_is_touched() {
        // The planner's refusals reach the format, and they reach it before anything has been
        // written — which for a streaming format is the difference between a destination that
        // was left alone and one truncated for an image that never arrived.
        let mut sink = Cursor::new(Vec::new());
        assert!(matches!(
            format_to(&mut sink, empty(), 4096, FormatOptions::new(1)),
            Err(FormatError::Geometry(GeometryError::VolumeTooSmall { .. }))
        ));
        assert!(sink.into_inner().is_empty());
    }

    #[test]
    fn a_label_is_bounded_by_the_field_and_not_by_its_characters() {
        assert_eq!(VolumeLabel::new("ELEVENCHARS").unwrap().units().len(), 11);
        assert!(matches!(
            VolumeLabel::new("TWELVECHARSX"),
            Err(LabelError::TooLong { limit: 11, .. })
        ));

        // Eleven *units*: a character outside the Basic Multilingual Plane is a surrogate pair
        // and costs two of them, so six of those overrun a field eleven wide.
        assert_eq!(VolumeLabel::new("\u{1F600}").unwrap().units().len(), 2);
        assert!(VolumeLabel::new("\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}").is_ok());
        assert!(matches!(
            VolumeLabel::new("\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}"),
            Err(LabelError::TooLong { .. })
        ));

        // And the one character the field cannot hold, because it is what the padding is.
        assert!(matches!(
            VolumeLabel::new("A\u{0}B"),
            Err(LabelError::NulUnit { at: 1 })
        ));
    }

    #[test]
    fn a_label_reserves_the_characters_a_name_does() {
        // The control codes and the nine a path or a pattern gives a meaning to, as for a
        // name. Everything else a name may hold, a label may: punctuation, spaces, and any
        // character past ASCII.
        for bad in [
            "A/B", "A\\B", "A:B", "A*", "A?", "A\"B", "A<B", "A>B", "A|B", "A\u{1}",
        ] {
            assert!(
                matches!(
                    VolumeLabel::new(bad),
                    Err(LabelError::ForbiddenCharacter { .. })
                ),
                "{bad:?}"
            );
        }
        for good in ["A.B C", "Ferrosys ×", "x-y_z+1"] {
            assert!(VolumeLabel::new(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn a_label_keeps_the_case_and_the_characters_it_was_given() {
        // exFAT stores Unicode and folds only for comparison, so nothing here changes a
        // character — which is what separates this label from the eleven upper-case bytes the
        // format this one is named after holds.
        let label = VolumeLabel::new("Ferrosys ×").expect("a label");
        assert_eq!(
            label.units(),
            &"Ferrosys ×".encode_utf16().collect::<Vec<_>>()[..]
        );
        assert_eq!(format!("{label:?}"), "VolumeLabel(\"Ferrosys ×\")");
    }

    // --- the stages, and what the destination held ------------------------------------

    /// A tree with a subdirectory, an empty file, a file spanning clusters, and a name long
    /// enough for three name entries, so every kind of body piece is in it.
    fn populated() -> TreeBuilder {
        let meta = Metadata::new(0o644, TIME);
        TreeBuilder::new()
            .directory(b"/DCIM".to_vec(), Metadata::new(0o755, TIME))
            .file(b"/DCIM/EMPTY".to_vec(), Vec::new(), meta)
            .file(
                b"/DCIM/a name long enough to need three name entries.txt".to_vec(),
                b"named\n",
                meta,
            )
            .file(
                b"/big.bin".to_vec(),
                (0..20_000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
                meta,
            )
            .file(b"/eflasher.conf".to_vec(), b"autostart=yes\n", meta)
    }

    /// The bytes a caller supplies for the file it declared under `key`.
    fn declared_bytes(key: u64, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u64 ^ key) as u8).collect()
    }

    /// Every piece of every stage, built.
    fn every_piece(plan: &FormatPlan) -> Vec<(StageKind, Piece<'_>)> {
        plan.stages()
            .into_iter()
            .flat_map(|stage| {
                stage
                    .pieces()
                    .map(move |piece| (stage.kind(), piece.expect("every piece builds")))
            })
            .collect()
    }

    /// `plan` applied to `destination` by hand, the way a caller doing its own I/O applies it:
    /// stage by stage, and within a stage in the order given — reversed if `reverse`.
    fn apply(plan: &FormatPlan, mut destination: Vec<u8>, reverse: bool) -> Vec<u8> {
        for stage in plan.stages() {
            let mut pieces: Vec<Piece<'_>> = stage
                .pieces()
                .collect::<Result<_, _>>()
                .expect("every piece builds");
            if reverse {
                pieces.reverse();
            }
            for piece in pieces {
                let at = piece.offset() as usize;
                let slot = &mut destination[at..at + piece.len() as usize];
                match piece {
                    Piece::Bytes { bytes, .. } => slot.copy_from_slice(&bytes),
                    Piece::Zeros { .. } => slot.fill(0),
                    Piece::Range { range, .. } => range.read_at(0, slot).expect("the range reads"),
                    Piece::Declared { key, .. } => {
                        let len = slot.len();
                        slot.copy_from_slice(&declared_bytes(key, len));
                    }
                }
            }
        }
        destination
    }

    /// Four destinations a format may be handed: zeros, every bit set, bytes that resemble
    /// nothing, and an earlier volume holding more than the one about to be written over it.
    fn destinations(size: usize) -> Vec<(&'static str, Vec<u8>)> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let noise = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let meta = Metadata::new(0o644, TIME);
        let mut earlier =
            TreeBuilder::new().directory(b"/DCIM".to_vec(), Metadata::new(0o755, TIME));
        for i in 0..60 {
            let name = format!("/AN-EARLIER-FILE-WITH-A-LONG-NAME-{i:03}.TXT");
            earlier = earlier.file(name.into_bytes(), format!("old {i}\n").into_bytes(), meta);
        }
        for i in 0..40 {
            let name = format!("/DCIM/EARLIER-{i:03}.BIN");
            earlier = earlier.file(name.into_bytes(), vec![0xA5; 3000 + i * 100], meta);
        }
        let earlier = format(earlier, size as u64, FormatOptions::new(0x1111_1111))
            .expect("the earlier volume")
            .into_bytes();
        vec![
            ("zeros", vec![0; size]),
            ("every bit set", vec![0xFF; size]),
            ("noise", noise),
            ("an earlier volume", earlier),
        ]
    }

    /// Every path a strict read of `bytes` reaches, with each file's contents, after a scan of
    /// the whole volume found nothing to report.
    fn read_back(what: &str, bytes: &[u8]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut reader = crate::exfat::Reader::open(Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{what}: a strict open refused the volume: {e}"));
        let report = reader.scan();
        assert!(report.is_clean(), "{what}: the scan found {report:?}");
        let walk = reader.walk().expect("the walk succeeds");
        walk.into_iter()
            .map(|entry| {
                let contents = (!entry.node.is_dir())
                    .then(|| reader.read_data(&entry.node).expect("the file reads"));
                (entry.path, contents)
            })
            .collect()
    }

    #[test]
    fn a_format_is_five_stages_and_the_main_boot_sector_is_the_last_write() {
        let plan = FormatPlan::new(populated(), 8 << 20, FormatOptions::new(1)).expect("plan");
        let kinds: Vec<StageKind> = plan.stages().iter().map(Stage::kind).collect();
        assert_eq!(
            kinds,
            [
                StageKind::Invalidate,
                StageKind::Body,
                StageKind::BackupBootRegion,
                StageKind::MainBootTail,
                StageKind::MainBootSector,
            ]
        );
        let sector = u64::from(plan.layout().bytes_per_sector);
        let place = |kind: StageKind| -> Vec<(u64, u64)> {
            every_piece(&plan)
                .into_iter()
                .filter(|(k, _)| *k == kind)
                .map(|(_, p)| (p.offset(), p.len()))
                .collect()
        };
        // The first stage zeroes everything before the heap from the first byte, so both boot
        // regions of whatever the destination held are gone before anything new is written.
        let heap_at = u64::from(plan.layout().cluster_heap_offset) * sector;
        assert_eq!(place(StageKind::Invalidate)[0], (0, heap_at));
        assert_eq!(
            place(StageKind::BackupBootRegion),
            [(12 * sector, 12 * sector)]
        );
        assert_eq!(place(StageKind::MainBootTail), [(sector, 11 * sector)]);
        assert_eq!(place(StageKind::MainBootSector), [(0, sector)]);
    }

    #[test]
    fn every_piece_starts_on_a_sector_and_no_two_in_a_stage_share_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = dir.path().join("host");
        std::fs::write(&host, vec![7u8; 9_000]).expect("write the host file");
        let meta = Metadata::new(0o644, TIME);
        // A root long enough to chain through several clusters at the smallest cluster size,
        // and one of each kind of file content.
        let mut tree = populated()
            .file(
                b"/ranged".to_vec(),
                FileContent::Range(FileRange::at_path(&host, 100, 8_000)),
                meta,
            )
            .file(
                b"/declared".to_vec(),
                FileContent::Declared {
                    len: 12_345,
                    key: 3,
                },
                meta,
            );
        for i in 0..40 {
            tree = tree.file(format!("/ROOT-{i:02}.TXT").into_bytes(), b"x", meta);
        }
        let requests = [
            PlanRequest::new(0),
            PlanRequest::new(0).cluster_size(ClusterSize::Bytes(512)),
            PlanRequest::new(0).bytes_per_sector(4096),
            PlanRequest::new(0)
                .bytes_per_sector(4096)
                .cluster_size(ClusterSize::Bytes(4096)),
        ];
        for (size, request) in [8 << 20, (8 << 20) + 511, 16 << 20, 16 << 20]
            .into_iter()
            .zip(requests)
        {
            let options = FormatOptions::new(1).plan(request);
            let plan = FormatPlan::new(tree.clone(), size, options).expect("plan");
            let sector = u64::from(plan.layout().bytes_per_sector);
            let pieces = every_piece(&plan);
            for kind in StageKind::ORDER {
                let mut ends: Vec<(u64, u64)> = Vec::new();
                for (k, piece) in &pieces {
                    if *k != kind {
                        continue;
                    }
                    let (at, len) = (piece.offset(), piece.len());
                    assert!(len > 0, "{kind:?}: an empty piece at {at}");
                    assert_eq!(
                        at % sector,
                        0,
                        "{kind:?}: a piece at {at} is inside a sector"
                    );
                    let contents = matches!(piece, Piece::Range { .. } | Piece::Declared { .. })
                        || at + len == size;
                    let file_bytes = matches!(
                        piece,
                        Piece::Bytes {
                            bytes: Cow::Borrowed(_),
                            ..
                        }
                    );
                    assert!(
                        contents || file_bytes || len % sector == 0,
                        "{kind:?}: a piece at {at} of {len} bytes ends inside a sector"
                    );
                    assert!(
                        at + len <= size,
                        "{kind:?}: a piece at {at} runs past the volume"
                    );
                    ends.push((at, (at + len).next_multiple_of(sector)));
                }
                ends.sort_unstable();
                for pair in ends.windows(2) {
                    assert!(
                        pair[0].1 <= pair[1].0,
                        "{kind:?}: pieces at {} and {} share a sector",
                        pair[0].0,
                        pair[1].0
                    );
                }
            }
        }
    }

    #[test]
    fn what_the_destination_held_does_not_change_the_volume() {
        let size = 8 << 20;
        let options = FormatOptions::new(0x2222_2222);
        let plan = FormatPlan::new(populated(), size, options).expect("plan");
        let fresh = format(populated(), size, options)
            .expect("format")
            .into_bytes();
        let expected = read_back("a fresh destination", &fresh);
        let covered: Vec<std::ops::Range<usize>> = every_piece(&plan)
            .iter()
            .map(|(_, p)| p.offset() as usize..(p.offset() + p.len()) as usize)
            .collect();

        let layout = plan.layout();
        let heap_at = layout.cluster_heap_offset as usize * layout.bytes_per_sector as usize;
        for (what, destination) in destinations(size as usize) {
            let mut sink = Cursor::new(destination);
            plan.write_to(&mut sink).expect("write");
            let written = sink.into_inner();
            // Nothing before the heap is left to what the destination held, whether or not a
            // driver reads it: a prober does.
            assert!(
                written[..heap_at] == fresh[..heap_at],
                "{what}: a byte before the heap is not the fresh destination's"
            );
            // Every byte a piece covers is the byte a fresh destination gets...
            for range in &covered {
                let at = written[range.clone()]
                    .iter()
                    .zip(&fresh[range.clone()])
                    .position(|(a, b)| a != b);
                assert!(
                    at.is_none(),
                    "{what}: byte {:?} differs",
                    at.map(|a| a + range.start)
                );
            }
            // ...and what no piece covers is never read: a strict reader finds the same tree
            // with the same bytes in it, and a scan of the whole volume finds nothing at all.
            assert_eq!(read_back(what, &written), expected, "{what}");
        }
    }

    #[test]
    fn pieces_go_down_in_any_order_within_a_stage() {
        let size = 8 << 20;
        let plan = FormatPlan::new(populated(), size, FormatOptions::new(5)).expect("plan");
        let mut sink = Cursor::new(vec![0xFF; size as usize]);
        plan.write_to(&mut sink).expect("write");
        assert!(
            apply(&plan, vec![0xFF; size as usize], true) == sink.into_inner(),
            "pieces applied in reverse made other bytes than the write"
        );
    }

    #[test]
    fn a_declared_file_comes_back_as_a_piece_and_a_write_to_a_sink_refuses_it_untouched() {
        let size = 8 << 20;
        let meta = Metadata::new(0o644, TIME);
        let source = populated()
            .file(
                b"/os.img".to_vec(),
                FileContent::Declared {
                    len: 10_000,
                    key: 7,
                },
                meta,
            )
            .file(
                b"/none.img".to_vec(),
                FileContent::Declared { len: 0, key: 8 },
                meta,
            );
        let plan = FormatPlan::new(source, size, FormatOptions::new(1)).expect("plan");

        // No bytes to put there, so nothing is written at all.
        let mut sink = Cursor::new(Vec::new());
        assert!(matches!(
            plan.write_to(&mut sink),
            Err(FormatError::ContentsNotHeld { key: 7 })
        ));
        assert!(
            sink.into_inner().is_empty(),
            "the refused write touched its sink"
        );

        // One piece names the file, on a cluster boundary, by the key it was declared with. The
        // empty one occupies no cluster, so it has no piece.
        let declared: Vec<(u64, u64, u64)> = every_piece(&plan)
            .into_iter()
            .filter_map(|(_, p)| match p {
                Piece::Declared { offset, len, key } => Some((offset, len, key)),
                _ => None,
            })
            .collect();
        assert_eq!(declared.len(), 1);
        let (offset, len, key) = declared[0];
        assert_eq!((len, key), (10_000, 7));
        assert_eq!(offset % u64::from(plan.layout().bytes_per_cluster), 0);

        // The caller's bytes, put where the piece said, are the file a reader finds.
        let bytes = apply(&plan, vec![0xFF; size as usize], false);
        let files = read_back("the declared file filled in", &bytes);
        let image = files
            .iter()
            .find(|(p, _)| p == b"/os.img")
            .expect("the file is there");
        assert!(image.1.as_deref() == Some(&declared_bytes(7, 10_000)[..]));
        let none = files
            .iter()
            .find(|(p, _)| p == b"/none.img")
            .expect("the file is there");
        assert_eq!(none.1.as_deref(), Some(&[][..]));

        // A declared file with no bytes leaves a write nothing to supply, so it is accepted.
        let source = populated().file(
            b"/none".to_vec(),
            FileContent::Declared { len: 0, key: 9 },
            meta,
        );
        let plan = FormatPlan::new(source, size, FormatOptions::new(1)).expect("plan");
        plan.write_to(Cursor::new(Vec::new()))
            .expect("nothing to supply");
    }

    #[test]
    fn the_end_of_the_volume_is_zeroed_from_the_heaps_end_whatever_the_cluster_size() {
        // A mebibyte from the end, where the clusters there are free.
        let plan = FormatPlan::new(populated(), 64 << 20, FormatOptions::new(1)).expect("plan");
        let tail = every_piece(&plan)
            .into_iter()
            .filter(|(k, _)| *k == StageKind::Invalidate)
            .map(|(_, p)| (p.offset(), p.len()))
            .next_back()
            .expect("the end of the volume is a piece");
        assert_eq!(tail, ((64 << 20) - (1 << 20), 1 << 20));

        // With clusters larger than that mebibyte, the space the heap has no cluster for can be
        // larger too, and it is covered whole however large: from the heap's end at the latest
        // to the last byte of the size asked for, a sub-sector remainder included.
        let size = (300 << 20) + 12_345;
        let request = PlanRequest::new(0).cluster_size(ClusterSize::Bytes(32 << 20));
        let plan =
            FormatPlan::new(populated(), size, FormatOptions::new(1).plan(request)).expect("plan");
        let layout = plan.layout();
        let heap_end = u64::from(layout.cluster_heap_offset) * u64::from(layout.bytes_per_sector)
            + layout.heap_bytes();
        assert!(
            size - heap_end > 1 << 20,
            "the row must leave more than a mebibyte past the heap"
        );
        let (at, len) = every_piece(&plan)
            .into_iter()
            .filter(|(k, _)| *k == StageKind::Invalidate)
            .map(|(_, p)| (p.offset(), p.len()))
            .next_back()
            .expect("the end of the volume is a piece");
        assert!(
            at <= heap_end,
            "the end of the volume starts at {at}, past the heap's end at {heap_end}"
        );
        assert_eq!(at + len, size);
    }
}
