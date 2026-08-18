//! The materializer: turn a planned [`FatLayout`] into image bytes.
//!
//! Everything this layer writes was decided by the pure layers below it. It lays down the
//! reserved region — the boot sector, and on FAT32 the information sector, the backup boot
//! sector, and the backup information sector — then each copy of the file allocation table
//! with the entries the format reserves at its head, then the root directory.
//!
//! Bytes go to any seekable writer. [`format()`] collects them into an in-memory [`Image`];
//! [`format_to`] streams them straight out, touching only the sectors it writes, so a volume
//! far larger than memory can be created into a file that stays sparse. Nothing is ever read
//! back from the destination.
//!
//! # Reproducibility
//!
//! Two formats of the same parameters produce the same bytes. Every value a formatter would
//! conventionally draw from the clock or from a random source — the volume serial number and
//! the times on the volume label entry — is an input on [`FormatOptions`], and the date
//! conversion is UTC, so nothing about the machine reaches the image.

use std::io::{Seek, Write};

use crate::fidelity::{AcceptedLoss, FidelityReport, LossPolicy, Property, Synthesis};
use crate::io::ByteSink;
use crate::sizing::Slack;
use crate::source::Source;
use crate::time::{DosTimestamp, Timestamp};

use super::geometry::{FatLayout, FatType, GeometryError, PlanRequest, plan_layout};
use super::model::{EntryTimes, FatModel, ModelConfig, ModelError, Node, build_model, place_tree};
use super::ondisk::{
    Attributes, BootSector, BootSectorTail, DIR_ENTRY_SIZE, DirEntry, EXTENDED_BOOT_SIGNATURE,
    Fat32Params, FsInfo, ParseError, VolumeInfo,
};
use super::table;

/// The name this crate records in [`BootSector::oem_name`] when nothing else is asked for.
///
/// No driver interprets the field and Microsoft's own specification says not to, so what
/// goes here is a formatter naming itself. Exactly eight bytes, which is the field's width.
pub const DEFAULT_OEM_NAME: [u8; 8] = *b"ferrosys";

/// The media descriptor this crate writes by default: fixed, non-removable media.
pub const MEDIA_FIXED: u8 = 0xF8;

/// The media descriptor for removable media.
pub const MEDIA_REMOVABLE: u8 = 0xF0;

/// Whether `media` is a media descriptor the format defines: [`MEDIA_REMOVABLE`], or one of
/// the eight fixed and legacy floppy codes from `0xF8` up.
///
/// The one definition of the field's value set, applied by the writer before an image is
/// planned and by the reader before a volume is claimed, so neither end accepts what the
/// other refuses.
pub(super) const fn is_media_descriptor(media: u8) -> bool {
    media == MEDIA_REMOVABLE || media >= MEDIA_FIXED
}

/// The BIOS drive number a boot loader is handed for fixed media.
const DRIVE_FIXED: u8 = 0x80;

/// The BIOS drive number for removable media.
const DRIVE_REMOVABLE: u8 = 0x00;

/// Where the boot code begins on a FAT12 or FAT16 volume: directly after the volume
/// information record at byte 36.
const BOOT_CODE_OFFSET_FAT1216: usize = 62;

/// Where the boot code begins on a FAT32 volume, after its own parameters have pushed the
/// volume information record out to byte 64.
const BOOT_CODE_OFFSET_FAT32: usize = 90;

/// A volume label: eleven bytes in the OEM character set, as the boot sector and the root
/// directory both record it.
///
/// The label is stored twice in a FAT volume — once in the boot sector's volume information
/// record and once as a directory entry in the root — and the two must agree, which is the
/// first reason it is a value rather than a pair of byte arrays. The second is that the
/// eleven bytes are not free-form: the entry that carries the label is a directory entry, so
/// a label may not begin with the byte that marks an entry deleted, and the characters a
/// short name excludes are excluded here for the same reason.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VolumeLabel([u8; VolumeLabel::LEN]);

impl VolumeLabel {
    /// Bytes a label occupies, space-padded.
    pub const LEN: usize = 11;

    /// The label a volume with no name carries in its boot sector. It is a placeholder rather
    /// than a name: a volume carrying it has no label entry in its root directory, which is
    /// how a driver reports the volume as unnamed.
    pub const NO_NAME: Self = Self(*b"NO NAME    ");

    /// The label `name` states, upper-cased and space-padded to eleven bytes.
    ///
    /// Lower-case ASCII is folded up, because the label lives in a directory entry's name
    /// field and that field has no case: a driver reading a lower-case byte there gets a name
    /// no other tool will match. Every other byte is taken as it stands, so a label in a code
    /// page this crate does not interpret still reaches the image.
    ///
    /// # Errors
    ///
    /// [`LabelError::TooLong`] beyond eleven bytes, and [`LabelError::InvalidByte`] for a
    /// byte a directory entry's name field cannot hold.
    pub fn new(name: &str) -> Result<Self, LabelError> {
        Self::from_bytes(name.as_bytes())
    }

    /// The label `name`'s bytes state, upper-cased and space-padded, for a caller whose label
    /// is already in an OEM code page rather than in UTF-8.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn from_bytes(name: &[u8]) -> Result<Self, LabelError> {
        if name.len() > Self::LEN {
            return Err(LabelError::TooLong {
                bytes: name.len(),
                limit: Self::LEN,
            });
        }
        let mut label = [b' '; Self::LEN];
        for (at, &byte) in name.iter().enumerate() {
            let byte = byte.to_ascii_uppercase();
            if !byte_is_allowed(byte, at) {
                return Err(LabelError::InvalidByte { byte, at });
            }
            label[at] = byte;
        }
        Ok(Self(label))
    }

    /// The eleven bytes, space-padded, as both the boot sector and the root entry record
    /// them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Whether `byte` may appear at position `at` of a label.
///
/// The rules are the directory entry's, because that is where the label lives. A trailing
/// space is padding and an interior one is legal, so spaces are allowed anywhere; the
/// control characters, the separators DOS reserved, and the byte marking an entry deleted
/// are not.
fn byte_is_allowed(byte: u8, at: usize) -> bool {
    const RESERVED: &[u8] = b"\"*+,./:;<=>?[\\]|";
    if byte < 0x20 || RESERVED.contains(&byte) {
        return false;
    }
    // A first byte of 0xE5 marks a directory entry deleted. A short name encodes a genuine
    // leading 0xE5 as 0x05, but a label has no such escape — a driver reads the label's
    // eleven bytes as they stand — so it is refused instead.
    !(at == 0 && byte == super::ondisk::NAME_DELETED)
}

impl core::fmt::Debug for VolumeLabel {
    /// The label as text where it is text, so a failure quotes a name rather than eleven
    /// numbers.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match core::str::from_utf8(&self.0) {
            Ok(text) => write!(f, "VolumeLabel({:?})", text.trim_end()),
            Err(_) => write!(f, "VolumeLabel({:02x?})", self.0),
        }
    }
}

/// A label a FAT volume cannot carry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LabelError {
    /// The label is longer than the eleven bytes both places that store it hold.
    #[error("volume label of {bytes} bytes exceeds the {limit} the format holds")]
    #[non_exhaustive]
    TooLong {
        /// Bytes the label needs.
        bytes: usize,
        /// Bytes the format holds.
        limit: usize,
    },
    /// A byte a directory entry's name field cannot hold, which is where the label is
    /// stored.
    #[error("byte {byte:#04x} at position {at} is not one a volume label may contain")]
    #[non_exhaustive]
    InvalidByte {
        /// The byte, after upper-casing.
        byte: u8,
        /// Its position in the label.
        at: usize,
    },
}

/// The boot loader's own bytes, laid into the boot sector between the fields and the
/// signature.
///
/// Writing a boot loader is a layer above this crate, so what goes here is supplied rather
/// than generated: the value is a byte range a caller hands over, and the default is empty.
/// The region it fills runs from the end of the type's fields to the signature at byte 510 —
/// [`MAX_BYTES`](Self::MAX_BYTES) on FAT12 and FAT16, and twenty-eight fewer on FAT32, whose
/// own parameters occupy those bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BootCode {
    bytes: [u8; BootCode::MAX_BYTES],
    len: u16,
}

impl BootCode {
    /// The most boot code a boot sector holds: from the end of a FAT12 or FAT16 volume's
    /// fields at byte 62 to the signature at byte 510.
    pub const MAX_BYTES: usize = 448;

    /// The most boot code a FAT32 boot sector holds. Its own parameters push the volume
    /// information record from byte 36 out to byte 64, and those twenty-eight bytes come out
    /// of this region.
    pub const MAX_BYTES_FAT32: usize = 420;

    /// No boot code: the region between the fields and the signature is left zero.
    pub const NONE: Self = Self {
        bytes: [0; Self::MAX_BYTES],
        len: 0,
    };

    /// The boot code `code` states.
    ///
    /// # Errors
    ///
    /// [`FormatError::BootCodeTooLong`] beyond [`MAX_BYTES`](Self::MAX_BYTES). Code that fits
    /// a FAT12 or FAT16 sector but not a FAT32 one is accepted here and refused by the format
    /// that would have to write it, because which type a volume becomes is not known until it
    /// is planned.
    pub fn new(code: &[u8]) -> Result<Self, FormatError> {
        if code.len() > Self::MAX_BYTES {
            return Err(FormatError::BootCodeTooLong {
                bytes: code.len(),
                limit: Self::MAX_BYTES,
            });
        }
        let mut bytes = [0u8; Self::MAX_BYTES];
        bytes[..code.len()].copy_from_slice(code);
        Ok(Self {
            bytes,
            // The length was just checked against a limit that fits a `u16`.
            len: code.len() as u16,
        })
    }

    /// The bytes, without the padding that fills the rest of the region.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The most boot code `fat_type`'s boot sector holds.
    #[must_use]
    pub const fn capacity(fat_type: FatType) -> usize {
        match fat_type {
            FatType::Fat32 => Self::MAX_BYTES_FAT32,
            _ => Self::MAX_BYTES,
        }
    }
}

impl Default for BootCode {
    fn default() -> Self {
        Self::NONE
    }
}

impl core::fmt::Debug for BootCode {
    /// The length rather than the bytes: several hundred bytes of machine code in a failure
    /// message hides whatever else the message said.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BootCode({} bytes)", self.len)
    }
}

/// Options controlling a format that do not come from the volume's size.
///
/// Build one with [`new`](Self::new), which takes the two identity inputs an image needs and
/// defaults the rest, then set the fields a format departs from the default on.
///
/// Every value a formatter would conventionally take from the clock or from a random source
/// is here, which is what makes two formats of the same parameters produce the same bytes.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FormatOptions {
    /// The volume serial number, recorded in the boot sector. Conventionally derived from
    /// the moment of formatting; supplied here so that it is not.
    pub volume_id: u32,
    /// The instant the volume label entry records as its creation, write, and access time.
    ///
    /// A FAT directory entry represents 1980-01-01 through 2107-12-31 at a two-second
    /// granularity, and an instant outside that is refused rather than truncated into a
    /// plausible-looking one.
    pub time: Timestamp,
    /// The volume label, or `None` for an unnamed volume — which records
    /// [`VolumeLabel::NO_NAME`] in the boot sector and puts no entry in the root directory,
    /// exactly as a driver expects of a volume with no name.
    pub label: Option<VolumeLabel>,
    /// The eight-byte name recorded as the formatting system's. Defaults to
    /// [`DEFAULT_OEM_NAME`]. No driver interprets it.
    pub oem_name: [u8; 8],
    /// The media descriptor, repeated in the first entry of every file allocation table.
    /// Defaults to [`MEDIA_FIXED`]; [`MEDIA_REMOVABLE`] is the other value in use. It also
    /// selects the BIOS drive number the boot sector records, since the two describe the same
    /// medium.
    ///
    /// The format defines [`MEDIA_REMOVABLE`] and the eight codes from [`MEDIA_FIXED`] up,
    /// and a value outside that set is refused
    /// ([`FormatError::MediaDescriptorUndefined`]) rather than written into a volume no
    /// reader would accept.
    pub media: u8,
    /// Sectors of the medium before this volume begins — a partition's start offset, or zero
    /// for a volume that is the whole medium. Defaults to zero.
    pub hidden_sectors: u32,
    /// The boot loader's bytes, laid between the fields and the signature. Defaults to
    /// [`BootCode::NONE`], which leaves the region zero.
    pub boot_code: BootCode,
    /// What the volume's geometry must be. Defaults to a request for the volume's own size
    /// with every knob at the value convention selects; [`PlanRequest::volume_bytes`] is
    /// replaced by the size the format is asked for, so a size named twice cannot disagree.
    pub plan: PlanRequest,
    /// Which properties of a source the format may lose. Defaults to
    /// [`AcceptedLoss::NONE`], so a build that would drop something fails and names it.
    ///
    /// A FAT directory entry has no field for an owner, a group, permission bits, a symbolic
    /// link, a second name for a file, a device number, or an extended attribute. A tree
    /// carrying any of those loses it, and refusing until the caller has said so is what
    /// keeps a root filesystem from quietly becoming one where every file is world-writable
    /// and every setuid binary has lost its bit.
    pub accepted_loss: AcceptedLoss,
    /// What a read of this image would fill an owner and a mode with, which is the point a
    /// loss is measured against.
    ///
    /// The format records neither, so whether a value survives is the question of whether a
    /// read hands the same one back — a `0644` file owned by root goes into a FAT image and
    /// comes out of it unchanged, and nothing was lost. Set this to whatever the extraction
    /// will use, so the two ends agree about what a faithful build is.
    pub synthesis: Synthesis,
}

impl FormatOptions {
    /// Options for a volume identified by `volume_id` and stamped `time`, with every other
    /// knob at its default.
    #[must_use]
    pub const fn new(volume_id: u32, time: Timestamp) -> Self {
        Self {
            volume_id,
            time,
            label: None,
            oem_name: DEFAULT_OEM_NAME,
            media: MEDIA_FIXED,
            hidden_sectors: 0,
            boot_code: BootCode::NONE,
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
        self.label = Some(label);
        self
    }

    /// These options accepting the loss of `property`, on top of whatever they accepted
    /// already.
    ///
    /// Everything else still refuses: accepting that permission bits will not survive says
    /// nothing about whether a symbolic link may quietly disappear.
    #[must_use]
    pub const fn accept_loss(mut self, property: Property) -> Self {
        self.accepted_loss = self.accepted_loss.and(property);
        self
    }

    /// These options accepting the loss of anything the format cannot carry.
    ///
    /// The blunt answer, for a caller that has decided it does not need the accounting up
    /// front — the [`FidelityReport`] still says exactly what went, entry by entry.
    #[must_use]
    pub const fn accept_all_loss(mut self) -> Self {
        self.accepted_loss = AcceptedLoss::ALL;
        self
    }

    /// These options with the recovery point a loss is measured against replaced.
    #[must_use]
    pub const fn synthesis(mut self, synthesis: Synthesis) -> Self {
        self.synthesis = synthesis;
        self
    }

    /// What the model needs of these options, derived in one place so a format and a fit
    /// search over the same options cannot build two different trees from them.
    pub(crate) const fn model_config(&self) -> ModelConfig {
        ModelConfig {
            loss: LossPolicy {
                accepted: self.accepted_loss,
                synthesis: self.synthesis,
            },
            has_label: self.label.is_some(),
        }
    }

    /// These options with the geometry request replaced.
    ///
    /// The request's [`volume_bytes`](PlanRequest::volume_bytes) is ignored: the size a
    /// format is asked for is the size it plans against.
    #[must_use]
    pub const fn plan(mut self, plan: PlanRequest) -> Self {
        self.plan = plan;
        self
    }

    /// These options with the boot code replaced.
    #[must_use]
    pub const fn boot_code(mut self, boot_code: BootCode) -> Self {
        self.boot_code = boot_code;
        self
    }

    /// The BIOS drive number that goes with the media descriptor: a fixed disk is drive
    /// `0x80` and removable media is drive `0x00`. Nothing but boot code reads it.
    const fn drive_number(&self) -> u8 {
        if self.media == MEDIA_FIXED {
            DRIVE_FIXED
        } else {
            DRIVE_REMOVABLE
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
    /// The source names something the volume cannot hold.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// Serializing an on-disk structure failed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The boot code is longer than the region between the fields and the signature.
    #[error("boot code of {bytes} bytes exceeds the {limit} the boot sector holds")]
    #[non_exhaustive]
    BootCodeTooLong {
        /// Bytes the boot code needs.
        bytes: usize,
        /// Bytes the region holds.
        limit: usize,
    },
    /// The format time is outside the range a directory entry represents: 1980-01-01 through
    /// 2107-12-31. It is refused rather than truncated, because a year that overflowed the
    /// field's seven bits would land in the 1980s and look entirely plausible.
    #[error(
        "a format time of {secs} seconds past the epoch is outside the {min} to {max} a FAT \
         directory entry represents"
    )]
    #[non_exhaustive]
    TimeOutOfRange {
        /// The seconds requested.
        secs: i64,
        /// The earliest the format represents.
        min: i64,
        /// The latest the format represents.
        max: i64,
    },
    /// A directory's entries serialize to more bytes than the clusters the plan gave it.
    ///
    /// Nothing a caller passes reaches this. The plan sizes every directory from the entries
    /// it will hold and the write serializes those same entries, so the two agree, and
    /// reaching this is a defect in this crate rather than something to correct in a source
    /// or in a [`FormatOptions`].
    ///
    /// It is a returned failure rather than a debug assertion because of what the
    /// alternative looks like: a directory written past its own clusters lands on the file
    /// placed after it, that file is written second and covers the overflow, and the
    /// finished image then reads plausibly with a chain silently overwritten. No comparison
    /// of the bytes can find that afterwards, so it is checked before they are written.
    #[error("directory {index} serializes to {bytes} bytes and was planned {capacity}")]
    #[non_exhaustive]
    DirectoryOverflowsItsClusters {
        /// Which directory, in the order the volume places them; the root is zero.
        index: usize,
        /// Bytes the directory's entries serialize to.
        bytes: u64,
        /// Bytes the clusters the plan gave it hold.
        capacity: u64,
    },
    /// The media descriptor is not one the format defines, so the volume would be refused by
    /// this crate's own reader and by third-party tooling alike.
    ///
    /// The value set is [`MEDIA_REMOVABLE`] and the eight codes from [`MEDIA_FIXED`] up.
    #[error(
        "a media descriptor of {media:#04x} is not a value a FAT volume's parameter block \
         carries"
    )]
    #[non_exhaustive]
    MediaDescriptorUndefined {
        /// The descriptor requested.
        media: u8,
    },
    /// A fit search was asked to leave a larger share of the volume free than it will look
    /// for.
    ///
    /// At the limit the volume is ten times the tree it holds, and each further step toward
    /// an empty one multiplies the size again. A volume that far from what its contents need
    /// is a size to name rather than to search for.
    #[error("slack of {hundredths} hundredths of a percent is past the limit of {limit}")]
    #[non_exhaustive]
    SlackShareTooLarge {
        /// The share asked for, in hundredths of one percent.
        hundredths: u16,
        /// The largest share a search will look for.
        limit: u16,
    },
    /// No volume this family accepts holds the tree with the room the slack asked for.
    #[error("no volume up to {ceiling} bytes holds the tree with the room asked for")]
    #[non_exhaustive]
    DoesNotFit {
        /// The largest volume the search could have tried, in bytes.
        ceiling: u64,
    },
    /// The image is larger than this platform addresses in memory. Only [`format()`] can
    /// reach this; [`format_to`] never holds an image.
    #[error("an image of {bytes} bytes is larger than this platform addresses in memory")]
    #[non_exhaustive]
    ImageTooLargeInMemory {
        /// Bytes the image needs.
        bytes: u64,
    },
}

/// A finished volume image: the bytes, the geometry that produced them, and what the format
/// could not carry.
pub struct Image {
    bytes: Vec<u8>,
    layout: FatLayout,
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
    pub fn layout(&self) -> &FatLayout {
        &self.layout
    }

    /// What the source offered that the format could not hold.
    ///
    /// [`is_faithful`](FidelityReport::is_faithful) is the whole question for most callers:
    /// a tree owned by root with conventional modes and no links goes into a FAT image
    /// unchanged, and this says so.
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

/// Everything a format decides before a byte is written: the geometry, the tree placed on
/// it, and what the format could not carry.
///
/// This is the whole fallible half of a format, and holding it as a value is what lets a
/// caller find out whether a format will work — and what it will cost — **before** touching
/// the destination. That matters twice over here. A format's destination must read as zero
/// where the filesystem does not write, so creating or truncating it is part of formatting,
/// and a destination truncated for a format that then failed on its source would be a file
/// destroyed by a run that wrote no filesystem. And a FAT volume cannot hold everything a
/// source may offer, so [`fidelity`](Self::fidelity) is an answer worth having in advance:
/// a hard link is written as a second copy of its file, and the plan is where the size that
/// costs is a number a caller reads rather than discovers.
///
/// [`write_to`](Self::write_to) is the half that can only fail on I/O.
///
/// # Example
///
/// ```no_run
/// use ferrosys::fat::{FormatOptions, FormatPlan, Timestamp, VolumeLabel};
/// use ferrosys::{Metadata, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_426_325_212);
/// let source = TreeBuilder::new()
///     .directory(b"/EFI".to_vec(), Metadata::new(0o755, time))
///     .file(b"/EFI/README.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));
///
/// let options = FormatOptions::new(0x1234_abcd, time).label(VolumeLabel::new("ESP")?);
/// let plan = FormatPlan::new(source, 64 << 20, options)?;
///
/// // What it will be, and what it will cost, before the destination is touched.
/// println!("{} clusters of {}", plan.layout().clusters, plan.layout().bytes_per_cluster());
/// assert!(plan.fidelity().is_faithful());
///
/// let mut file = std::fs::File::create("esp.img")?;
/// plan.write_to(&mut file)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct FormatPlan {
    layout: FatLayout,
    /// The size the format was asked for, which is the size the destination becomes. It is
    /// held apart from the layout because the two are not always the same number: the
    /// planner shortens the *filesystem* out of the disputed FAT12/FAT16 cluster range, and
    /// the destination is still what the caller named.
    volume_bytes: u64,
    options: FormatOptions,
    model: FatModel,
}

impl FormatPlan {
    /// Plan a format of `volume_bytes` populated from `source`.
    ///
    /// Everything a format can fail on happens here.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] if the geometry cannot be realized, an option is outside what the
    /// format holds, or the source names something the volume cannot hold — including a
    /// property it would lose that [`FormatOptions::accepted_loss`] does not cover.
    pub fn new(
        source: impl Source,
        volume_bytes: u64,
        options: FormatOptions,
    ) -> Result<Self, FormatError> {
        let layout = plan(volume_bytes, &options)?;
        let model = build_model(source.into_entries(), &layout, &options.model_config())?;
        Ok(Self {
            layout,
            volume_bytes,
            options,
            model,
        })
    }

    /// The smallest volume that holds `source` with `slack` free, planned and ready to write.
    ///
    /// The size is searched for rather than computed. How many clusters a volume has depends
    /// on its cluster size, its table, and its reserved region, and all three follow from the
    /// size — so a candidate is planned and the tree is allocated into it, and what that
    /// leaves free judges the candidate. Nothing here estimates: the answer is a size that
    /// planned and placed, with the sector below it proven not to.
    ///
    /// The tree is placed once and re-allocated against each candidate, so a search costs
    /// arithmetic per candidate rather than a rebuild, and the candidate it settles on is
    /// allocated last — so the chains and directory cluster numbers the plan carries are the
    /// ones the layout it carries describes. No file is read at any point.
    ///
    /// [`volume_bytes`](Self::volume_bytes) is the size to create, and for a fitted plan it
    /// is exactly the filesystem's own extent: the smallest volume that holds a tree is one
    /// where the last cluster is used, which is never inside the range the planner shortens
    /// a volume out of.
    ///
    /// # Errors
    ///
    /// [`FormatError::SlackShareTooLarge`] for a share past the limit,
    /// [`FormatError::DoesNotFit`] when no volume this family accepts holds the tree with the
    /// room asked for, and otherwise the failure the search met — a geometry the request
    /// cannot have at any size, or a tree this family cannot carry.
    pub fn fit(
        source: impl Source,
        options: FormatOptions,
        slack: Slack,
    ) -> Result<Self, FormatError> {
        let mut tree = place_tree(source.into_entries(), &options.model_config())?;
        let fitted = crate::fat::fit::search(&mut tree, &options, slack)?;
        let volume_bytes =
            u64::from(fitted.layout.total_sectors) * u64::from(fitted.layout.bytes_per_sector);
        Ok(Self {
            layout: fitted.layout,
            volume_bytes,
            options,
            model: tree.finish(fitted.used_clusters, fitted.next_free),
        })
    }

    /// The clusters the volume has that the tree does not occupy.
    ///
    /// This is what [`Slack`] is measured in, and on FAT32 it is the number the information
    /// sector records. FAT12 and FAT16 have no on-disk free counter, so for those it is
    /// reachable only from the plan.
    #[must_use]
    pub const fn free_clusters(&self) -> u32 {
        self.layout.clusters - self.model.used_clusters
    }

    /// The geometry the bytes will realize — exact rather than estimated, because it is the
    /// same value the write uses.
    #[must_use]
    pub fn layout(&self) -> &FatLayout {
        &self.layout
    }

    /// Bytes the destination will hold, which is the size the format was asked for.
    ///
    /// This is not always
    /// [`FatLayout::total_bytes`](crate::fat::FatLayout::total_bytes): where the planner
    /// shortens the filesystem out of the disputed FAT12/FAT16 cluster range, the few
    /// sectors it gives up stay in the destination and lie outside the filesystem, exactly
    /// as the slack at the end of a partition does.
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

    /// Write the planned volume to `sink`, returning the geometry it realizes.
    ///
    /// Only the sectors the filesystem occupies are written, and nothing is read back, so a
    /// file destination stays sparse. The sink is extended to
    /// [`volume_bytes`](Self::volume_bytes) — the size the format was asked for — and every
    /// byte it holds that is not written must read back as zero; a freshly created file, or
    /// one truncated to zero length, satisfies that.
    ///
    /// Where the planner shortened the filesystem out of the disputed FAT12/FAT16 cluster
    /// range, the destination is still the size that was named and the sectors the
    /// filesystem gave up lie past its end, which is what the slack at the end of a
    /// partition looks like. The boot sector's `total_sectors` is where the filesystem
    /// stops, so no driver reads into them.
    ///
    /// The plan is not consumed, so the report is readable on either side of the write and
    /// one plan may be written more than once. Two writes of one plan produce the same
    /// bytes, unless a file a [`FileRange`](crate::FileRange) names changed in between.
    ///
    /// # Errors
    ///
    /// [`FormatError::Io`] if writing to `sink` fails, or if a file the source named by
    /// range cannot be read — which is what a file edited after the source was built looks
    /// like.
    pub fn write_to(&self, sink: impl Write + Seek) -> Result<FatLayout, FormatError> {
        write_volume(
            &self.layout,
            self.volume_bytes,
            &self.options,
            &self.model,
            sink,
        )?;
        Ok(self.layout)
    }
}

/// Format a FAT volume of `volume_bytes` populated from `source`, assembling the whole image
/// in memory.
///
/// The image is exactly `volume_bytes` long. Where the planner shortens the *filesystem* out
/// of the disputed FAT12/FAT16 cluster range, the sectors it gives up stay in the image and
/// lie past the filesystem's end, which is what the slack at the end of a partition looks
/// like; the boot sector's `total_sectors` is what says where the filesystem stops.
///
/// The image is held as one buffer of its full size, so this needs as much memory as the
/// volume is large. [`format_to`] writes the same bytes to a seekable destination without
/// ever holding them all.
///
/// An empty volume is [`TreeBuilder::new`](crate::TreeBuilder::new), which places nothing.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, an option is outside what the format
/// holds, the source names something the volume cannot hold, or the image is larger than this
/// platform addresses.
///
/// # Example
///
/// ```
/// use ferrosys::fat::{FatType, FormatOptions, Timestamp, VolumeLabel, format};
/// use ferrosys::{Metadata, TreeBuilder};
///
/// let time = Timestamp::from_secs(1_426_325_212);
/// let source = TreeBuilder::new()
///     .directory(b"/EFI".to_vec(), Metadata::new(0o755, time))
///     .file(b"/EFI/BOOTX64.EFI".to_vec(), b"MZ", Metadata::new(0o644, time));
///
/// let options = FormatOptions::new(0x1234_abcd, time).label(VolumeLabel::new("ESP")?);
/// let image = format(source.clone(), 64 << 20, options)?;
/// assert_eq!(image.layout().fat_type, FatType::Fat16);
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
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    let bytes = plan.volume_bytes.max(plan.layout.total_bytes());
    // The whole image is one buffer, so its size must be one this platform can address: a
    // cast would silently size the buffer to the low bits of the count and write a filesystem
    // into the wrong number of bytes.
    let len = usize::try_from(bytes).map_err(|_| FormatError::ImageTooLargeInMemory { bytes })?;
    let mut sink = std::io::Cursor::new(vec![0u8; len]);
    let layout = plan.write_to(&mut sink)?;
    Ok(Image {
        bytes: sink.into_inner(),
        layout,
        fidelity: plan.model.fidelity,
    })
}

/// Format a FAT volume of `volume_bytes` populated from `source`, streaming its bytes into
/// `sink` and returning the plan they realize.
///
/// Only the sectors the filesystem occupies are written, and nothing is read back, so a file
/// destination stays sparse and the whole image never exists in memory. The sink is extended
/// to `volume_bytes`, the size the format was asked for, and every byte it holds that is not
/// written must read back as zero — a freshly created file, or one truncated to zero length,
/// satisfies that.
///
/// Where the planner shortens the *filesystem* out of the disputed FAT12/FAT16 cluster
/// range, the destination is still the size that was named and the sectors the filesystem
/// gives up lie past its end. The boot sector's `total_sectors` is where the filesystem
/// stops, so no driver reads into them.
///
/// The [`FormatPlan`] comes back rather than the layout alone, because a format into a
/// filesystem that cannot hold everything a source offers owes the caller an account of what
/// it dropped: [`FormatPlan::fidelity`] is that account and
/// [`FormatPlan::layout`] is the geometry.
///
/// # Memory
///
/// Three things are held while the image streams out, and none of them is the image:
///
/// - **The model.** Every entry's name, times, and cluster run, held until the last byte is
///   written. It grows with the number of entries, not with their size — a chain is a first
///   cluster and a count, because a fresh volume has nothing to allocate around.
/// - **A file's contents, while it is placed.** A
///   [`FileContent::Owned`](crate::FileContent::Owned) entry holds its bytes from the moment
///   the source is built, so a list of them costs the sum of every file. A
///   [`FileContent::Range`](crate::FileContent::Range) is read at placement and dropped
///   after, so a list of them costs the largest single file.
/// - **One directory's entries, while it is written**, and one batch of the file allocation
///   table. Neither grows with the volume.
///
/// # Errors
///
/// A [`FormatError`] if the geometry cannot be realized, an option is outside what the format
/// holds, the source names something the volume cannot hold, or writing to `sink` fails.
pub fn format_to(
    source: impl Source,
    volume_bytes: u64,
    options: FormatOptions,
    sink: impl Write + Seek,
) -> Result<FormatPlan, FormatError> {
    let plan = FormatPlan::new(source, volume_bytes, options)?;
    plan.write_to(sink)?;
    Ok(plan)
}

/// Plan the geometry a format of `volume_bytes` realizes, and check the options against it.
///
/// Both entry points come through here, so an input a format refuses is refused by both and
/// is refused before the destination is touched.
fn plan(volume_bytes: u64, options: &FormatOptions) -> Result<FatLayout, FormatError> {
    // The media descriptor answers to the format's own value set rather than to any geometry,
    // so it is settled before a layout exists. It is checked against the set the reader
    // enforces, which is what makes "a strict read accepts every volume this writer produces"
    // a statement about the whole of `FormatOptions` and not only about the geometry.
    if !is_media_descriptor(options.media) {
        return Err(FormatError::MediaDescriptorUndefined {
            media: options.media,
        });
    }

    let mut request = options.plan;
    request.volume_bytes = volume_bytes;
    let layout = plan_layout(&request)?;

    // The boot-code check depends on the type, which is why it is here rather than on the
    // options: how much fits is a property of the type's boot sector.
    let capacity = BootCode::capacity(layout.fat_type);
    let code = options.boot_code.as_bytes().len();
    if code > capacity {
        return Err(FormatError::BootCodeTooLong {
            bytes: code,
            limit: capacity,
        });
    }
    // The format time must be one a directory entry represents, whether or not this volume
    // has a label entry to stamp with it. On an unlabelled volume nothing consumes the
    // value — but it is a stated input either way, and an instant accepted here that no
    // entry of the format could carry reads as one that was written.
    if DosTimestamp::encode(options.time).is_none() {
        return Err(FormatError::TimeOutOfRange {
            secs: options.time.secs,
            min: DosTimestamp::SECS_MIN,
            max: DosTimestamp::SECS_MAX,
        });
    }
    Ok(layout)
}

/// The sector count at or below which the small-media recommendation applies. It is 256 MiB
/// at a 512-byte sector, which is where the two published tables meet.
const CHS_SMALL_MEDIA_SECTORS: u32 = 524_288;

/// The legacy disk geometry a boot sector records, as sectors per track and heads, from the
/// volume's sector count.
///
/// Neither field affects a placement — no cluster moves if they change — but mtools and
/// DOS-era software read them, and the values are not arbitrary. Two published tables meet
/// at [`CHS_SMALL_MEDIA_SECTORS`]: at or below it the SD Card File System specification's
/// recommendation, and above it the geometry MS-DOS's own `FORMAT` writes, which fixes the
/// track at 63 sectors and doubles the head count through each cylinder limit that produces.
/// Reproducing both is what makes this crate's boot sector comparable to a conventional
/// formatter's byte for byte.
const fn chs(total_sectors: u32) -> (u16, u16) {
    if total_sectors <= CHS_SMALL_MEDIA_SECTORS {
        let heads: u16 = if total_sectors <= 32_768 {
            2
        } else if total_sectors <= 65_536 {
            4
        } else if total_sectors <= 262_144 {
            8
        } else {
            16
        };
        let sectors_per_track: u16 = if total_sectors <= 4096 { 16 } else { 32 };
        return (sectors_per_track, heads);
    }
    // Above the threshold the track is 63 sectors and the head count is whatever keeps the
    // cylinder count inside the 1024 a CHS address holds — 16 heads up to 16 * 63 * 1024
    // sectors, then doubling, and 255 once doubling has run out.
    const PER_HEAD: u32 = 63 * 1024;
    let heads: u16 = if total_sectors <= 16 * PER_HEAD {
        16
    } else if total_sectors <= 32 * PER_HEAD {
        32
    } else if total_sectors <= 64 * PER_HEAD {
        64
    } else if total_sectors <= 128 * PER_HEAD {
        128
    } else {
        255
    };
    (63, heads)
}

/// Entries of the file allocation table laid down in one write.
///
/// Even, so a FAT12 batch always begins on a whole byte and never splits the pair two
/// entries share — which is what lets each batch reuse [`table::write_entry`] against a
/// buffer of its own rather than reimplementing the packing.
const TABLE_BATCH: u32 = 4096;

/// Lay down every structure the volume has, in ascending offset order.
fn write_volume(
    layout: &FatLayout,
    volume_bytes: u64,
    options: &FormatOptions,
    model: &FatModel,
    sink: impl Write + Seek,
) -> Result<(), FormatError> {
    let mut sink = ByteSink::new(sink);
    let sector_bytes = layout.bytes_per_sector as usize;
    let at = |sector: u32| u64::from(sector) * u64::from(layout.bytes_per_sector);

    // The reserved region.
    let mut boot = vec![0u8; sector_bytes];
    boot_sector(layout, options).write_to(&mut boot)?;
    let code = options.boot_code.as_bytes();
    let code_offset = match layout.fat_type {
        FatType::Fat32 => BOOT_CODE_OFFSET_FAT32,
        _ => BOOT_CODE_OFFSET_FAT1216,
    };
    // `plan` has already established that the code fits between the fields and the signature.
    boot[code_offset..code_offset + code.len()].copy_from_slice(code);
    sink.write_at(0, &boot)?;

    if let Some(fat32) = layout.fat32 {
        let mut info = vec![0u8; sector_bytes];
        FsInfo {
            free_clusters: Some(layout.clusters - model.used_clusters),
            // Where a driver should begin looking, which is the first cluster this format
            // did not hand out. Allocation runs in one ascending pass with no gaps, so
            // everything below it is in use and everything from it up is free.
            //
            // On a volume with nothing left there is no such cluster, and the hint names
            // one past the highest the volume has — which this crate's own reader flags,
            // rightly, as a hint pointing at a cluster that does not exist. The field has an
            // honest encoding for not knowing, and a full volume is exactly the case it is
            // for. `FormatPlan::fit` with no slack produces one every time.
            next_free_cluster: (model.next_free < layout.clusters + 2).then_some(model.next_free),
        }
        .write_to(&mut info)?;
        sink.write_at(at(u32::from(fat32.fs_info_sector)), &info)?;

        if let Some(backup) = fat32.backup_boot_sector {
            sink.write_at(at(u32::from(backup)), &boot)?;
            if let Some(backup_info) = fat32.backup_fs_info_sector {
                sink.write_at(at(u32::from(backup_info)), &info)?;
            }
        }
    }

    write_tables(layout, options, model, &mut sink)?;
    write_tree(layout, options, model, &mut sink)?;

    // The destination is the size the caller named, not the size of the filesystem in it.
    // The two differ only where the planner stepped the filesystem down out of the disputed
    // cluster range, and there the few sectors it gave up belong to the destination all the
    // same: a caller writing a partition image gets a file that fills the partition it was
    // cut for, and the tail outside the filesystem is what the end of a partition looks like
    // anyway. `total_sectors` in the boot sector is what says where the filesystem stops, so
    // no driver reads past it.
    sink.extend_to(volume_bytes.max(layout.total_bytes()))?;
    Ok(())
}

/// Write every copy of the file allocation table.
///
/// Only the entries for clusters that were handed out are written. The rest is free, which is
/// zero, and is left untouched so a file destination stays sparse — which for a volume whose
/// filesystem is a fraction of its size is the difference between writing a few kilobytes and
/// writing the whole table.
///
/// The table goes down a batch at a time rather than whole, so the memory this costs is a
/// constant however large the volume is.
fn write_tables<W: Write + Seek>(
    layout: &FatLayout,
    options: &FormatOptions,
    model: &FatModel,
    sink: &mut ByteSink<W>,
) -> Result<(), FormatError> {
    let kind = layout.fat_type;
    let span = table::entry_span(kind);
    // Where each chain stops pointing forward, ascending — so one walk of the clusters can
    // decide every entry without holding a map of them.
    let ends = model.chain_ends();

    for start in (0..model.next_free.max(2)).step_by(TABLE_BATCH as usize) {
        let end = (start + TABLE_BATCH).min(model.next_free.max(2));
        // The bytes this batch's entries touch, from the first one's offset to the last
        // one's. A FAT12 batch begins on an even entry, so the offsets within it are the
        // offsets of the entries counted from zero and `write_entry` can be reused whole.
        let base = table::entry_offset(kind, start);
        let len = table::entry_offset(kind, end - 1 - start) + span;
        // The planner sizes a table for every cluster the volume has and allocation never
        // hands out one it does not, so a batch always lands inside its own copy. A batch
        // that ran past the end would write into the copy after it, which is the one place
        // where a mirror stops being a mirror. One comparison per batch, held in every
        // build: the class of defect it guards is one the finished bytes do not show.
        assert!(
            base + len <= u64::from(layout.fat_sectors) * u64::from(layout.bytes_per_sector),
            "a table batch ending at {} runs past a table of {} sectors",
            base + len,
            layout.fat_sectors
        );
        let mut batch = vec![0u8; len as usize];

        for cluster in start..end {
            let value = match cluster {
                // The first two entries name no cluster. One repeats the media descriptor,
                // as the coarse check that the table belongs to the volume; the other is all
                // ones, whose top two bits are the clean-shutdown and no-hard-error flags.
                0 => table::media_entry(kind, options.media),
                1 => table::tail_entry(kind),
                // Allocation is contiguous, so a cluster's successor is the next one unless
                // this is where its chain ends.
                _ if ends.binary_search(&cluster).is_ok() => table::end_of_chain(kind),
                _ => cluster + 1,
            };
            // A write that did not fit leaves the entry at its zero value, which reads as a
            // free cluster in the middle of a chain — so the return is checked rather than
            // discarded, in every build.
            let wrote = table::write_entry(kind, &mut batch, cluster - start, value);
            assert!(wrote, "entry {cluster} did not fit the batch sized for it");
        }

        for copy in 0..layout.fats {
            let table_start = layout
                .fat_start_sector(copy)
                .expect("every copy below the table count has a start sector");
            sink.write_at(at_sector(layout, table_start) + base, &batch)?;
        }
    }
    Ok(())
}

/// Write every directory and every file's bytes.
fn write_tree<W: Write + Seek>(
    layout: &FatLayout,
    options: &FormatOptions,
    model: &FatModel,
    sink: &mut ByteSink<W>,
) -> Result<(), FormatError> {
    for (index, dir) in model.dirs.iter().enumerate() {
        let bytes = directory_bytes(model, options, index)?;
        if !bytes.is_empty() {
            let (start, capacity) = match (index, layout.fat32) {
                // The fixed root region of a FAT12 or FAT16 volume, which is not a chain.
                (0, None) => (
                    layout
                        .root_dir_start_sector()
                        .expect("a volume that is not FAT32 has a root directory region"),
                    u64::from(layout.root_entries) * DIR_ENTRY_SIZE as u64,
                ),
                _ => (
                    layout
                        .cluster_start_sector(dir.run.first)
                        .expect("a planned directory cluster is one the volume has"),
                    u64::from(dir.run.count) * u64::from(layout.bytes_per_cluster()),
                ),
            };
            // What was planned and what is written are two computations of one number, and
            // the bytes hide a disagreement between them: a directory written past its own
            // clusters lands on the file placed after it, which is written second and covers
            // the overflow — so the image reads plausibly and a chain has been overwritten.
            // Checked here, where both numbers are in hand, and on every write rather than
            // only in a debug build: the failure this catches is the one a comparison of the
            // finished bytes cannot see.
            if bytes.len() as u64 > capacity {
                return Err(FormatError::DirectoryOverflowsItsClusters {
                    index,
                    bytes: bytes.len() as u64,
                    capacity,
                });
            }
            sink.write_at(at_sector(layout, start), &bytes)?;
        }

        for entry in &dir.entries {
            let Node::File { content, size, run } = entry.node else {
                continue;
            };
            if run.is_empty() {
                continue;
            }
            // Read when the file is placed rather than when the source was built, so a tree
            // of ranges costs the largest single file rather than the sum of them.
            let bytes = model.contents[content].read()?;
            // The length the entry records was taken from this content when the model was
            // built, and a read hands back exactly what it declared or fails — so the two
            // agree. Checked in every build: the slice below would panic on contents shorter
            // than the entry claims, and would silently write a truncated file on contents
            // longer than it, which is the direction nothing downstream can notice.
            assert_eq!(
                bytes.len() as u64,
                u64::from(size),
                "a file's contents are not the length its entry records"
            );
            let start = layout
                .cluster_start_sector(run.first)
                .expect("a planned file cluster is one the volume has");
            sink.write_at(at_sector(layout, start), &bytes[..size as usize])?;
        }
    }
    Ok(())
}

/// The byte offset of `sector`.
fn at_sector(layout: &FatLayout, sector: u32) -> u64 {
    u64::from(sector) * u64::from(layout.bytes_per_sector)
}

/// One directory's entries, serialized in the order they are written.
///
/// The volume label leads the root, `.` and `..` lead every other directory, and each entry
/// is preceded by the long-name entries carrying the name it was given. An entry whose first
/// name byte is zero ends the directory, and everything past what is written here reads as
/// zero — so nothing has to be written to terminate one.
fn directory_bytes(
    model: &FatModel,
    options: &FormatOptions,
    index: usize,
) -> Result<Vec<u8>, FormatError> {
    let dir = &model.dirs[index];
    let mut out = Vec::new();

    if index == 0 {
        if let Some(label) = options.label {
            push_entry(&mut out, &label_entry(label, options.time))?;
        }
    } else {
        // `.` is this directory and `..` is the one holding it. A parent that is the root
        // gets a zero here on every type, FAT32 included, where the root does have a cluster
        // of its own — the format states it as a zero and a checker verifies it.
        let parent = dir.parent.expect("only the root has no parent");
        let parent_cluster = if parent == 0 {
            0
        } else {
            model.dirs[parent].run.first
        };
        push_entry(
            &mut out,
            &dot_entry(b".          ", dir.run.first, dir.times),
        )?;
        push_entry(
            &mut out,
            &dot_entry(b"..         ", parent_cluster, dir.times),
        )?;
    }

    for entry in &dir.entries {
        for lfn in entry.name.lfn_entries() {
            let at = out.len();
            out.resize(at + DIR_ENTRY_SIZE, 0);
            lfn.write_to(&mut out[at..])?;
        }
        let (cluster, size) = model.entry_target(entry.node);
        push_entry(
            &mut out,
            &DirEntry {
                name: entry.name.short,
                attributes: entry.attributes,
                // The two case bits Windows NT puts here are left zero: the format's own
                // specification says this byte is reserved and must never be read, so a name
                // carried only in it is one some drivers do not see. A long name is written
                // instead, and every driver uses that.
                case_flags: 0,
                create_time_tenth: entry.times.create.tenth,
                create_time: entry.times.create.time,
                create_date: entry.times.create.date,
                access_date: entry.times.access_date,
                first_cluster_hi: (cluster >> 16) as u16,
                write_time: entry.times.write.time,
                write_date: entry.times.write.date,
                first_cluster_lo: cluster as u16,
                size,
            },
        )?;
    }
    Ok(out)
}

/// Append one entry's thirty-two bytes to a directory under construction.
fn push_entry(out: &mut Vec<u8>, entry: &DirEntry) -> Result<(), FormatError> {
    let at = out.len();
    out.resize(at + DIR_ENTRY_SIZE, 0);
    entry.write_to(&mut out[at..])?;
    Ok(())
}

/// The `.` or `..` entry of a subdirectory: a directory entry naming a cluster, with no
/// length of its own.
fn dot_entry(name: &[u8; 11], cluster: u32, times: EntryTimes) -> DirEntry {
    DirEntry {
        name: *name,
        attributes: Attributes::DIRECTORY,
        case_flags: 0,
        create_time_tenth: times.create.tenth,
        create_time: times.create.time,
        create_date: times.create.date,
        access_date: times.access_date,
        first_cluster_hi: (cluster >> 16) as u16,
        write_time: times.write.time,
        write_date: times.write.date,
        first_cluster_lo: cluster as u16,
        size: 0,
    }
}

/// The boot sector this layout and these options describe.
///
/// Every planned value narrows into a field the format sizes more tightly than the layout
/// holds it, and the planner is what keeps each in range. A count that did not fit would be
/// written truncated rather than refused — a reserved region 65536 sectors short puts a
/// driver's data region somewhere the formatter's is not, and every cluster on the volume
/// then resolves elsewhere — so the whole set is asserted here as well, where the narrowing
/// actually happens. Eight comparisons per format, held in every build: a truncation is
/// silent by construction, and there is nothing in the finished bytes to compare it against.
fn boot_sector(layout: &FatLayout, options: &FormatOptions) -> BootSector {
    assert!(
        u16::try_from(layout.bytes_per_sector).is_ok()
            && u8::try_from(layout.sectors_per_cluster).is_ok()
            && u16::try_from(layout.reserved_sectors).is_ok()
            && u8::try_from(layout.fats).is_ok()
            && u16::try_from(layout.root_entries).is_ok()
            && (layout.fat32.is_some() || u16::try_from(layout.fat_sectors).is_ok()),
        "a planned field does not fit the boot sector field that records it: {layout:?}"
    );
    let (sectors_per_track, heads) = chs(layout.total_sectors);
    let volume = VolumeInfo {
        drive_number: options.drive_number(),
        ext_boot_signature: EXTENDED_BOOT_SIGNATURE,
        volume_id: options.volume_id,
        label: *options.label.unwrap_or(VolumeLabel::NO_NAME).as_bytes(),
        fs_type: layout.fat_type.label(),
    };
    // A volume whose sector count fits sixteen bits records it there and leaves the 32-bit
    // field zero, and the other way round. Exactly one of the two is set, which is what every
    // driver expects and what keeps the two from disagreeing.
    let (total_16, total_32) = match u16::try_from(layout.total_sectors) {
        Ok(small) => (small, 0),
        Err(_) => (0, layout.total_sectors),
    };
    let (fat_sectors_16, tail) = match layout.fat32 {
        Some(fat32) => (
            0,
            BootSectorTail::Fat32 {
                params: Fat32Params {
                    fat_sectors: layout.fat_sectors,
                    // Zero means every copy of the table is kept identical, which is what
                    // this crate writes and what a checker compares them under.
                    ext_flags: 0,
                    version: 0,
                    root_cluster: fat32.root_cluster,
                    fs_info_sector: fat32.fs_info_sector,
                    backup_boot_sector: fat32.backup_boot_sector.unwrap_or(0),
                },
                volume,
            },
        ),
        // A table too large for sixteen bits is a volume too large for the smaller two types,
        // which the planner has already refused.
        None => (
            layout.fat_sectors as u16,
            BootSectorTail::Fat1216 { volume },
        ),
    };
    BootSector {
        // A short jump to where the boot code begins, then the no-op the form requires. The
        // target is the type's own boot-code offset, so a loader laid into the region is
        // entered at its first byte.
        jump: [
            0xEB,
            match layout.fat_type {
                FatType::Fat32 => (BOOT_CODE_OFFSET_FAT32 - 2) as u8,
                _ => (BOOT_CODE_OFFSET_FAT1216 - 2) as u8,
            },
            0x90,
        ],
        oem_name: options.oem_name,
        // The planner has already held every one of these to the range its field holds.
        bytes_per_sector: layout.bytes_per_sector as u16,
        sectors_per_cluster: layout.sectors_per_cluster as u8,
        reserved_sectors: layout.reserved_sectors as u16,
        fats: layout.fats as u8,
        root_entries: layout.root_entries as u16,
        total_sectors_16: total_16,
        media: options.media,
        fat_sectors_16,
        sectors_per_track,
        heads,
        hidden_sectors: options.hidden_sectors,
        total_sectors_32: total_32,
        tail,
    }
}

/// The root directory entry that carries the volume label.
///
/// It is a directory entry in every respect but meaning: the label occupies the name field,
/// the volume attribute says it is not a file, and it owns no cluster and has no length.
fn label_entry(label: VolumeLabel, time: Timestamp) -> DirEntry {
    // `plan` has already established that the time is one the fields represent.
    let stamp = DosTimestamp::encode(time).unwrap_or_default();
    DirEntry {
        name: *label.as_bytes(),
        attributes: Attributes::VOLUME_ID,
        case_flags: 0,
        create_time_tenth: stamp.tenth,
        create_time: stamp.time,
        create_date: stamp.date,
        access_date: stamp.date,
        first_cluster_hi: 0,
        write_time: stamp.time,
        write_date: stamp.date,
        first_cluster_lo: 0,
        size: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::ondisk::{BOOT_SIGNATURE, LfnEntry};
    use crate::fat::{ClusterSize, FatTypeRequest, ReservedSectors};
    use crate::source::TreeBuilder;

    /// The instant every fixture here stamps with: 2015-03-14T09:26:52Z, on a two-second
    /// boundary so that nothing under test is also exercising the hundredths field.
    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn options() -> FormatOptions {
        FormatOptions::new(0x1234_abcd, TIME)
    }

    /// A volume of `mib` mebibytes at the given type, formatted in memory.
    fn image(mib: u64, request: FatTypeRequest) -> Image {
        let opts = options().plan(PlanRequest::new(0).fat_type(request));
        format(TreeBuilder::new(), mib << 20, opts).expect("format")
    }

    #[test]
    fn a_formatted_volume_is_exactly_the_size_it_was_asked_for() {
        for mib in [1u64, 8, 64, 512] {
            let image = image(mib, FatTypeRequest::Auto);
            assert_eq!(
                image.as_bytes().len() as u64,
                mib << 20,
                "{mib} MiB: the image is not the size of the volume"
            );
            assert_eq!(image.layout().total_bytes(), mib << 20);
        }
    }

    #[test]
    fn a_shortened_filesystem_still_fills_the_destination_it_was_given() {
        // The one geometry where the filesystem is smaller than the volume: a FAT12 whose
        // count lands in the range two drivers read differently is stepped down out of it,
        // giving up a sector or two. The *destination* keeps them, so a caller writing a
        // partition image gets a file that fills the partition it was cut for, and the tail
        // sits past the filesystem exactly as a partition's slack does.
        let asked = 2_120_704u64;
        let opts = options().plan(PlanRequest::new(0).cluster_size(ClusterSize::Sectors(1)));
        let plan = FormatPlan::new(TreeBuilder::new(), asked, opts).expect("plan");
        assert_eq!(plan.volume_bytes(), asked);
        assert!(
            plan.layout().total_bytes() < asked,
            "the fixture is not in the step-down range: {} bytes",
            plan.layout().total_bytes()
        );

        // In memory and streamed alike, and the two are the same bytes.
        let image = format(TreeBuilder::new(), asked, opts).expect("format");
        assert_eq!(image.as_bytes().len() as u64, asked);
        let mut sink = std::io::Cursor::new(Vec::new());
        format_to(TreeBuilder::new(), asked, opts, &mut sink).expect("format_to");
        let streamed = sink.into_inner();
        assert_eq!(streamed.len() as u64, asked);
        assert_eq!(streamed, image.as_bytes());

        // The boot sector is what says where the filesystem stops, so the tail past it is
        // outside the volume a driver reads — and is zero.
        let boot = BootSector::read_from(image.as_bytes()).expect("read the boot sector");
        let described = u64::from(boot.total_sectors()) * u64::from(boot.bytes_per_sector);
        assert_eq!(described, plan.layout().total_bytes());
        assert!(
            image.as_bytes()[described as usize..]
                .iter()
                .all(|b| *b == 0)
        );

        // And a strict read still accepts it, which is the property the tail must not touch.
        let mut r = crate::fat::Reader::open(std::io::Cursor::new(image.as_bytes()))
            .expect("a strict open");
        assert_eq!(r.layout(), plan.layout());
        assert!(r.scan().is_clean());
    }

    #[test]
    fn the_boot_sector_reads_back_as_the_layout_it_describes() {
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let image = image(mib, request);
            let layout = *image.layout();
            let boot = BootSector::read_from(image.as_bytes()).expect("read the boot sector");
            let what = layout.fat_type;
            assert_eq!(u32::from(boot.bytes_per_sector), layout.bytes_per_sector);
            assert_eq!(
                u32::from(boot.sectors_per_cluster),
                layout.sectors_per_cluster
            );
            assert_eq!(u32::from(boot.reserved_sectors), layout.reserved_sectors);
            assert_eq!(u32::from(boot.fats), layout.fats);
            assert_eq!(u32::from(boot.root_entries), layout.root_entries);
            assert_eq!(boot.total_sectors(), layout.total_sectors, "{what}");
            assert_eq!(boot.fat_sectors(), layout.fat_sectors, "{what}");
            assert_eq!(boot.media, MEDIA_FIXED);
            // The count a driver derives from the sector's own fields, which is the only
            // count that decides anything.
            let root_sectors =
                (u32::from(boot.root_entries) * 32).div_ceil(layout.bytes_per_sector);
            let data = boot.total_sectors()
                - (u32::from(boot.reserved_sectors)
                    + u32::from(boot.fats) * boot.fat_sectors()
                    + root_sectors);
            assert_eq!(
                data / u32::from(boot.sectors_per_cluster),
                layout.clusters,
                "{what}: the written fields derive a different cluster count than was planned"
            );
            assert_eq!(FatType::of_cluster_count(layout.clusters), what, "{what}");
            // And the signature, which sits at byte 510 whatever the sector size is.
            assert_eq!(
                u16::from_le_bytes([image.as_bytes()[510], image.as_bytes()[511]]),
                BOOT_SIGNATURE
            );
        }
    }

    #[test]
    fn a_zero_16_bit_table_size_marks_exactly_the_fat32_volumes() {
        // It is how every mainstream driver recognizes FAT32, ahead of any cluster
        // arithmetic, so a volume that is one type by count and another by this test would be
        // read as a filesystem it is not.
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let image = image(mib, request);
            let boot = BootSector::read_from(image.as_bytes()).expect("read");
            let is_fat32 = image.layout().fat_type == FatType::Fat32;
            assert_eq!(boot.fat_sectors_16 == 0, is_fat32);
            assert_eq!(matches!(boot.tail, BootSectorTail::Fat32 { .. }), is_fat32);
            assert_eq!(boot.root_entries == 0, is_fat32);
        }
    }

    #[test]
    fn every_table_copy_carries_the_entries_the_format_reserves() {
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let image = image(mib, request);
            let layout = *image.layout();
            let kind = layout.fat_type;
            for copy in 0..layout.fats {
                let start = layout.fat_start_sector(copy).expect("a copy that exists") as usize
                    * layout.bytes_per_sector as usize;
                let table = &image.as_bytes()[start..start + layout.bytes_per_sector as usize];
                assert_eq!(
                    table::read_entry(kind, table, 0),
                    Some(table::media_entry(kind, MEDIA_FIXED)),
                    "{kind} copy {copy}: the media entry"
                );
                assert_eq!(
                    table::read_entry(kind, table, 1),
                    Some(table::tail_entry(kind)),
                    "{kind} copy {copy}: the reserved entry"
                );
                match layout.fat32 {
                    // FAT32's root is an ordinary chain of one cluster, so its entry ends the
                    // chain and nothing else is allocated.
                    Some(fat32) => {
                        assert_eq!(
                            table::read_entry(kind, table, fat32.root_cluster),
                            Some(table::end_of_chain(kind))
                        );
                        assert_eq!(
                            table::read_entry(kind, table, fat32.root_cluster + 1),
                            Some(table::FREE)
                        );
                    }
                    // The smaller two have a root region rather than a root chain, so no
                    // cluster is allocated at all.
                    None => assert_eq!(table::read_entry(kind, table, 2), Some(table::FREE)),
                }
            }
            // The copies are identical, which is what a checker compares them under.
            let copies: Vec<&[u8]> = (0..layout.fats)
                .map(|c| {
                    let start = layout.fat_start_sector(c).unwrap() as usize
                        * layout.bytes_per_sector as usize;
                    let len = layout.fat_sectors as usize * layout.bytes_per_sector as usize;
                    &image.as_bytes()[start..start + len]
                })
                .collect();
            assert!(copies.windows(2).all(|w| w[0] == w[1]), "{kind}");
        }
    }

    #[test]
    fn a_label_reaches_both_places_that_record_it() {
        let label = VolumeLabel::new("ferrosys").expect("a valid label");
        let opts = options()
            .label(label)
            .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat32)));
        let image = format(TreeBuilder::new(), 512 << 20, opts).expect("format");
        let layout = *image.layout();

        // The boot sector's copy.
        let boot = BootSector::read_from(image.as_bytes()).expect("read");
        let BootSectorTail::Fat32 { volume, .. } = boot.tail else {
            panic!("a FAT32 volume must carry the FAT32 tail")
        };
        assert_eq!(&volume.label, label.as_bytes());
        assert_eq!(volume.volume_id, 0x1234_abcd);

        // And the root directory's, which is where a driver actually reads it from.
        let root = layout
            .cluster_start_sector(layout.fat32.unwrap().root_cluster)
            .unwrap() as usize
            * layout.bytes_per_sector as usize;
        let entry = DirEntry::read_from(&image.as_bytes()[root..]).expect("read");
        assert_eq!(&entry.name, label.as_bytes());
        assert!(entry.attributes.contains(Attributes::VOLUME_ID));
        assert_eq!(entry.first_cluster_lo, 0);
        assert_eq!(entry.first_cluster_hi, 0);
        assert_eq!(entry.size, 0);
        // The entry after it begins with a zero, which is what ends a directory.
        assert_eq!(image.as_bytes()[root + DIR_ENTRY_SIZE], 0);
    }

    #[test]
    fn an_unnamed_volume_carries_the_placeholder_and_no_entry() {
        // A driver reports the volume as unnamed by finding no label entry, so writing one
        // that said `NO NAME` would be naming the volume that.
        let image = image(64, FatTypeRequest::Exactly(FatType::Fat16));
        let boot = BootSector::read_from(image.as_bytes()).expect("read");
        let BootSectorTail::Fat1216 { volume } = boot.tail else {
            panic!("a FAT16 volume must carry the smaller tail")
        };
        assert_eq!(volume.label, *VolumeLabel::NO_NAME.as_bytes());
        let root = image.layout().root_dir_start_sector().unwrap() as usize
            * image.layout().bytes_per_sector as usize;
        assert_eq!(image.as_bytes()[root], 0);
    }

    #[test]
    fn a_fat32_volume_carries_its_information_sector_and_both_backups() {
        let image = image(512, FatTypeRequest::Exactly(FatType::Fat32));
        let layout = *image.layout();
        let fat32 = layout.fat32.expect("a FAT32 layout");
        let sector = layout.bytes_per_sector as usize;
        let at = |n: u16| n as usize * sector;

        let info = FsInfo::read_from(&image.as_bytes()[at(fat32.fs_info_sector)..]).expect("read");
        // The root directory owns the one allocated cluster; everything else is free.
        assert_eq!(info.free_clusters, Some(layout.clusters - 1));
        // And the hint is the first cluster that is actually free, which on an empty volume
        // is the one after the root. A conventional formatter writes the root's own cluster
        // here — a value a driver has to scan past, since that cluster is in use.
        assert_eq!(info.next_free_cluster, Some(fat32.root_cluster + 1));

        let backup = fat32.backup_boot_sector.expect("room for a backup");
        assert_eq!(
            &image.as_bytes()[at(backup)..at(backup) + BootSector::SIZE],
            &image.as_bytes()[..BootSector::SIZE],
            "the backup boot sector is not a copy of the primary"
        );
        let backup_info = fat32.backup_fs_info_sector.expect("room for a backup");
        assert_eq!(
            &image.as_bytes()[at(backup_info)..at(backup_info) + FsInfo::SIZE],
            &image.as_bytes()[at(fat32.fs_info_sector)..at(fat32.fs_info_sector) + FsInfo::SIZE],
        );
        // Every backup is inside the reserved region: one written past it would land on the
        // first file allocation table and destroy the volume it was meant to protect.
        assert!(u32::from(backup) < layout.reserved_sectors);
        assert!(u32::from(backup_info) < layout.reserved_sectors);
    }

    #[test]
    fn a_reserved_region_with_no_room_for_a_backup_information_sector_writes_none() {
        // A reserved count of seven puts the backup boot sector at 6 and would put its
        // information sector at 7, which is the first sector of the first table. The layout
        // says there is no room, and the writer must leave the table intact.
        let opts = options().plan(
            PlanRequest::new(0)
                .fat_type(FatTypeRequest::Exactly(FatType::Fat32))
                .cluster_size(ClusterSize::Sectors(1))
                .reserved_sectors(ReservedSectors::Count(7)),
        );
        let image = format(TreeBuilder::new(), 64 << 20, opts).expect("format");
        let layout = *image.layout();
        let fat32 = layout.fat32.expect("a FAT32 layout");
        assert_eq!(layout.reserved_sectors, 7);
        assert_eq!(fat32.backup_boot_sector, Some(6));
        assert_eq!(fat32.backup_fs_info_sector, None);
        // Sector 7 is the head of the first table, and holds table entries rather than an
        // information sector's signature.
        let head = layout.fat_start_sector(0).unwrap() as usize * layout.bytes_per_sector as usize;
        assert_eq!(head, 7 * layout.bytes_per_sector as usize);
        let table = &image.as_bytes()[head..head + layout.bytes_per_sector as usize];
        assert_eq!(
            table::read_entry(FatType::Fat32, table, 0),
            Some(table::media_entry(FatType::Fat32, MEDIA_FIXED))
        );
    }

    #[test]
    fn the_streamed_image_is_the_in_memory_image() {
        // Two entry points that decided anything separately would be two entry points that
        // could disagree, and a disagreement between them is not a compile error.
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let opts = options()
                .label(VolumeLabel::new("STREAMED").unwrap())
                .plan(PlanRequest::new(0).fat_type(request));
            let whole = format(TreeBuilder::new(), mib << 20, opts).expect("format");
            let mut streamed = std::io::Cursor::new(Vec::new());
            let plan =
                format_to(TreeBuilder::new(), mib << 20, opts, &mut streamed).expect("format_to");
            assert_eq!(plan.layout(), whole.layout());
            assert_eq!(streamed.into_inner(), whole.as_bytes());
        }
    }

    #[test]
    fn only_the_sectors_the_filesystem_occupies_are_written() {
        // The property a sparse destination rests on: a volume far larger than its metadata
        // must not have its data region touched.
        let image = image(512, FatTypeRequest::Exactly(FatType::Fat32));
        let layout = *image.layout();
        let sector = layout.bytes_per_sector as usize;
        let after_root = (layout.cluster_start_sector(3).unwrap() as usize) * sector;
        assert!(
            image.as_bytes()[after_root..].iter().all(|&b| b == 0),
            "the data region past the root cluster is not empty"
        );
    }

    #[test]
    fn the_boot_code_is_laid_where_the_jump_points() {
        // A loader written into the region has to be entered at its first byte, so the jump's
        // target and the region's start are the same number by construction rather than by
        // coincidence.
        for (mib, request, offset) in [
            (64u64, FatTypeRequest::Exactly(FatType::Fat16), 62usize),
            (512, FatTypeRequest::Exactly(FatType::Fat32), 90),
        ] {
            let code: Vec<u8> = (0..64u8).collect();
            let opts = options()
                .boot_code(BootCode::new(&code).expect("a valid length"))
                .plan(PlanRequest::new(0).fat_type(request));
            let image = format(TreeBuilder::new(), mib << 20, opts).expect("format");
            let bytes = image.as_bytes();
            assert_eq!(bytes[0], 0xEB);
            assert_eq!(usize::from(bytes[1]) + 2, offset, "the jump's target");
            assert_eq!(bytes[2], 0x90);
            assert_eq!(&bytes[offset..offset + code.len()], &code[..]);
            // And the byte before the region still belongs to the fields, not to the code.
            assert_ne!(bytes[offset - 1], code[0]);
        }
    }

    #[test]
    fn boot_code_too_long_for_the_type_is_refused_rather_than_truncated() {
        // A FAT32 boot sector holds twenty-eight fewer bytes, so code that fits one type and
        // not the other is refused by the format that would have to write it.
        let code = vec![0x90u8; BootCode::MAX_BYTES];
        let fits = BootCode::new(&code).expect("the largest region's worth");
        assert!(
            format(
                TreeBuilder::new(),
                64 << 20,
                options()
                    .boot_code(fits)
                    .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16)))
            )
            .is_ok()
        );
        assert!(matches!(
            format(
                TreeBuilder::new(),
                512 << 20,
                options()
                    .boot_code(fits)
                    .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat32)))
            ),
            Err(FormatError::BootCodeTooLong { limit, .. }) if limit == BootCode::MAX_BYTES_FAT32
        ));
        // And code longer than any boot sector holds is refused where it is built.
        assert!(matches!(
            BootCode::new(&vec![0u8; BootCode::MAX_BYTES + 1]),
            Err(FormatError::BootCodeTooLong { .. })
        ));
    }

    #[test]
    fn a_time_the_format_cannot_hold_is_refused_before_anything_is_written() {
        let mut opts = options().label(VolumeLabel::new("EARLY").unwrap());
        opts.time = Timestamp::from_secs(0);
        assert!(matches!(
            format(TreeBuilder::new(), 64 << 20, opts),
            Err(FormatError::TimeOutOfRange { secs: 0, .. })
        ));
        // With no label nothing consumes the value — and it is refused all the same. The
        // time is a stated input either way, and an instant accepted that no entry of the
        // format could carry reads as one that was written. On the other side of the range
        // too, so the check is the field's range and not a lower bound alone.
        let mut unlabelled = options();
        unlabelled.time = Timestamp::from_secs(0);
        assert!(matches!(
            format(TreeBuilder::new(), 64 << 20, unlabelled),
            Err(FormatError::TimeOutOfRange { secs: 0, .. })
        ));
        let mut late = options();
        late.time = Timestamp::from_secs(7_258_118_400); // the year 2200
        assert!(matches!(
            format(TreeBuilder::new(), 64 << 20, late),
            Err(FormatError::TimeOutOfRange { .. })
        ));
    }

    #[test]
    fn the_size_a_format_is_asked_for_wins_over_the_one_in_the_request() {
        // The size is named in two places and they cannot disagree, because only one of them
        // is read.
        let opts = options().plan(PlanRequest::new(999 << 20));
        let image = format(TreeBuilder::new(), 64 << 20, opts).expect("format");
        assert_eq!(image.as_bytes().len() as u64, 64 << 20);
    }

    #[test]
    fn the_media_descriptor_reaches_the_boot_sector_the_tables_and_the_drive_number() {
        // The whole defined set, not only the two values with names: removable media and the
        // eight codes from fixed media up. Only fixed media is a fixed disk; the seven legacy
        // floppy codes above it describe removable media as much as `0xF0` does.
        let defined = (0xF8u8..=0xFF)
            .map(|m| {
                (
                    m,
                    if m == MEDIA_FIXED {
                        DRIVE_FIXED
                    } else {
                        DRIVE_REMOVABLE
                    },
                )
            })
            .chain([(MEDIA_REMOVABLE, DRIVE_REMOVABLE)]);
        for (media, drive) in defined {
            let mut opts = options();
            opts.media = media;
            let image = format(TreeBuilder::new(), 64 << 20, opts).expect("format");
            let boot = BootSector::read_from(image.as_bytes()).expect("read");
            assert_eq!(boot.media, media);
            let BootSectorTail::Fat1216 { volume } = boot.tail else {
                panic!("a FAT16 volume")
            };
            assert_eq!(volume.drive_number, drive);
            // The first table entry repeats it, which is the coarse check a driver makes that
            // the table belongs to the volume.
            let layout = image.layout();
            let head =
                layout.fat_start_sector(0).unwrap() as usize * layout.bytes_per_sector as usize;
            assert_eq!(
                table::read_entry(layout.fat_type, &image.as_bytes()[head..], 0),
                Some(table::media_entry(layout.fat_type, media))
            );
        }
    }

    #[test]
    fn a_media_descriptor_the_format_does_not_define_is_refused() {
        // The values between the two defined regions, the low sentinel, and an arbitrary
        // byte. Each is refused by the reader's geometry gate, so a writer that accepted one
        // would produce a volume it could not read back — and `fsck.fat` calls two of these
        // corrupt outright, so the output is not merely something this crate dislikes.
        for media in [0x00u8, 0x42, 0xEF, 0xF1, 0xF7] {
            let mut opts = options();
            opts.media = media;
            let err = format(TreeBuilder::new(), 64 << 20, opts)
                .err()
                .expect("an undefined media descriptor is refused");
            assert!(
                matches!(err, FormatError::MediaDescriptorUndefined { media: m } if m == media),
                "media {media:#04x}: {err}",
            );
            // And the same input refused by the streaming entry point, before its sink is
            // touched.
            let mut opts = options();
            opts.media = media;
            let mut sink = std::io::Cursor::new(Vec::new());
            assert!(format_to(TreeBuilder::new(), 64 << 20, opts, &mut sink).is_err());
            assert!(sink.into_inner().is_empty());
        }
    }

    #[test]
    fn the_legacy_geometry_follows_the_published_recommendation() {
        // Neither field moves a cluster, so what pins them is that a conventional formatter
        // writes exactly these — the SD Card File System recommendation below the threshold
        // and the geometry MS-DOS's own FORMAT writes above it.
        assert_eq!(chs(4096), (16, 2));
        assert_eq!(chs(4097), (32, 2));
        assert_eq!(chs(32_768), (32, 2));
        assert_eq!(chs(32_769), (32, 4));
        assert_eq!(chs(65_536), (32, 4));
        assert_eq!(chs(65_537), (32, 8));
        assert_eq!(chs(262_144), (32, 8));
        assert_eq!(chs(262_145), (32, 16));
        assert_eq!(chs(524_288), (32, 16));
        // And above the threshold, the track is fixed and the heads double through each
        // cylinder limit rather than jumping straight to the maximum.
        assert_eq!(chs(524_289), (63, 16));
        assert_eq!(chs(16 * 63 * 1024), (63, 16));
        assert_eq!(chs(16 * 63 * 1024 + 1), (63, 32));
        assert_eq!(chs(32 * 63 * 1024), (63, 32));
        assert_eq!(chs(32 * 63 * 1024 + 1), (63, 64));
        assert_eq!(chs(64 * 63 * 1024), (63, 64));
        assert_eq!(chs(64 * 63 * 1024 + 1), (63, 128));
        assert_eq!(chs(128 * 63 * 1024), (63, 128));
        assert_eq!(chs(128 * 63 * 1024 + 1), (63, 255));
        assert_eq!(chs(u32::MAX), (63, 255));
    }

    /// The entries of the directory beginning at `offset`, stopping where the directory
    /// does — an entry whose first name byte is zero.
    fn entries_at(image: &Image, offset: usize) -> Vec<DirEntry> {
        let mut out = Vec::new();
        let mut at = offset;
        while image.as_bytes()[at] != 0 {
            out.push(DirEntry::read_from(&image.as_bytes()[at..]).expect("read"));
            at += DIR_ENTRY_SIZE;
        }
        out
    }

    /// The entries of the directory at `offset` that name something, without the long-name
    /// entries carried in front of them.
    fn files_at(image: &Image, offset: usize) -> Vec<DirEntry> {
        entries_at(image, offset)
            .into_iter()
            .filter(|e| !e.attributes.is_long_name())
            .collect()
    }

    /// The cluster a directory entry names, joining the two halves the way the type does.
    fn first_cluster(entry: &DirEntry) -> u32 {
        u32::from(entry.first_cluster_lo) | u32::from(entry.first_cluster_hi) << 16
    }

    /// The byte offset of cluster `n`.
    fn cluster_at(layout: &FatLayout, n: u32) -> usize {
        layout
            .cluster_start_sector(n)
            .expect("a cluster the volume has") as usize
            * layout.bytes_per_sector as usize
    }

    /// A tree whose every entry the format carries whole, so nothing under test is also
    /// exercising the fidelity policy.
    fn tree() -> TreeBuilder {
        let meta = crate::source::Metadata::new(0o644, TIME);
        let dir = crate::source::Metadata::new(0o755, TIME);
        TreeBuilder::new()
            .directory(b"/EFI".to_vec(), dir)
            .directory(b"/EFI/BOOT".to_vec(), dir)
            .file(b"/EFI/BOOT/BOOTX64.EFI".to_vec(), b"MZ payload", meta)
            .file(b"/readme.txt".to_vec(), b"a long name\n", meta)
    }

    #[test]
    fn a_tree_reaches_the_image_with_its_names_clusters_and_lengths() {
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let opts = options().plan(PlanRequest::new(0).fat_type(request));
            let image = format(tree(), mib << 20, opts).expect("format");
            let layout = *image.layout();
            let what = layout.fat_type;

            let root = match layout.fat32 {
                Some(f) => cluster_at(&layout, f.root_cluster),
                None => {
                    layout.root_dir_start_sector().unwrap() as usize
                        * layout.bytes_per_sector as usize
                }
            };
            // Sorted, so the order is the tree's rather than the order it was built in. Two
            // names, three entries: `EFI` is already a short name and `readme.txt` is not,
            // so a long-name entry precedes the short one it belongs to.
            let entries = entries_at(&image, root);
            assert_eq!(entries.len(), 3, "{what}: EFI, then two entries for readme");
            assert_eq!(&entries[0].name, b"EFI        ");
            assert!(entries[0].attributes.contains(Attributes::DIRECTORY));
            assert_eq!(entries[0].size, 0, "{what}: a directory records no length");
            assert!(entries[1].attributes.is_long_name());
            assert_eq!(&entries[2].name, b"README  TXT");
            assert_eq!(entries[2].size, 12);
            // The long name is the name that was asked for, and it is tied to the short
            // entry by the checksum that stops it being orphaned onto another file.
            let lfn = LfnEntry::read_from(&image.as_bytes()[root + DIR_ENTRY_SIZE..])
                .expect("a long-name entry");
            assert_eq!(
                lfn.checksum,
                crate::fat::ondisk::lfn_checksum(&entries[2].name),
                "{what}: the long name is not tied to its short entry"
            );
            let units: Vec<u16> = lfn
                .name
                .iter()
                .copied()
                .take_while(|&u| u != 0 && u != 0xFFFF)
                .collect();
            assert_eq!(String::from_utf16(&units).expect("utf16"), "readme.txt");

            // The payload is where the entry says it is, and its length is the file's.
            let boot = layout
                .cluster_start_sector(u32::from(entries[0].first_cluster_lo))
                .expect("EFI's cluster");
            let efi = files_at(&image, boot as usize * layout.bytes_per_sector as usize);
            assert_eq!(&efi[0].name, b".          ", "{what}");
            assert_eq!(&efi[1].name, b"..         ", "{what}");
            // A `..` naming the root is a zero on every type, FAT32 included, where the root
            // does have a cluster of its own.
            assert_eq!(efi[1].first_cluster_lo, 0, "{what}");
            assert_eq!(efi[1].first_cluster_hi, 0, "{what}");
            assert_eq!(&efi[2].name, b"BOOT       ", "{what}");

            let boot_dir = files_at(&image, cluster_at(&layout, first_cluster(&efi[2])));
            // This one's parent is not the root, so `..` names a real cluster.
            assert_eq!(
                first_cluster(&boot_dir[1]),
                first_cluster(&efi[0]),
                "{what}: `..` does not name the directory that holds this one"
            );
            let payload = &boot_dir[2];
            assert_eq!(&payload.name, b"BOOTX64 EFI", "{what}");
            assert_eq!(payload.size, 10, "{what}");
            let at = cluster_at(&layout, first_cluster(payload));
            assert_eq!(&image.as_bytes()[at..at + 10], b"MZ payload", "{what}");
        }
    }

    #[test]
    fn every_chain_the_tree_needs_is_in_every_copy_of_the_table() {
        // A table that disagreed with the directory would send a driver somewhere else on
        // the volume, and a second copy that disagreed with the first is what a checker
        // reports.
        let bytes = 4096usize;
        let meta = crate::source::Metadata::new(0o644, TIME);
        let source = TreeBuilder::new()
            .file(b"/big".to_vec(), vec![9u8; bytes * 3], meta)
            .file(b"/small".to_vec(), b"x", meta);
        let opts =
            options().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat16)));
        let image = format(source, 64 << 20, opts).expect("format");
        let layout = *image.layout();
        let kind = layout.fat_type;
        let per_cluster = layout.bytes_per_cluster() as usize;
        let want = (bytes * 3).div_ceil(per_cluster) as u32;

        for copy in 0..layout.fats {
            let start =
                layout.fat_start_sector(copy).unwrap() as usize * layout.bytes_per_sector as usize;
            let table = &image.as_bytes()[start..];
            // The big file's chain: every cluster points at the next, and the last ends it.
            for n in 2..2 + want - 1 {
                assert_eq!(
                    table::read_entry(kind, table, n),
                    Some(n + 1),
                    "{kind} copy {copy}: cluster {n} does not point at its successor"
                );
            }
            let last = 2 + want - 1;
            assert!(table::is_end_of_chain(
                kind,
                table::read_entry(kind, table, last).expect("an entry the table holds")
            ));
            // The small file follows it, in one cluster of its own.
            assert!(table::is_end_of_chain(
                kind,
                table::read_entry(kind, table, last + 1).expect("an entry")
            ));
            // And nothing past the tree is claimed.
            assert_eq!(table::read_entry(kind, table, last + 2), Some(table::FREE));
        }
    }

    #[test]
    fn a_twelve_bit_table_packs_a_tree_across_its_shared_nibbles() {
        // FAT12 is the width where a batched write could split the byte two entries share,
        // so a tree long enough to walk many pairs is what proves the packing survives it.
        let meta = crate::source::Metadata::new(0o644, TIME);
        let mut source = TreeBuilder::new();
        for i in 0..60 {
            source = source.file(format!("/F{i}").into_bytes(), b"x", meta);
        }
        let opts = options().plan(
            PlanRequest::new(0)
                .fat_type(FatTypeRequest::Exactly(FatType::Fat12))
                .cluster_size(ClusterSize::Sectors(1)),
        );
        let image = format(source, 2 << 20, opts).expect("format");
        let layout = *image.layout();
        let start = layout.fat_start_sector(0).unwrap() as usize * layout.bytes_per_sector as usize;
        let table = &image.as_bytes()[start..];
        // Sixty single-cluster files, each its own chain of one, so every entry from 2 is an
        // end-of-chain mark — on both sides of every shared nibble.
        for n in 2..62 {
            let entry = table::read_entry(FatType::Fat12, table, n).expect("an entry");
            assert!(
                table::is_end_of_chain(FatType::Fat12, entry),
                "cluster {n} reads back as {entry:#05x} rather than an end of chain"
            );
        }
        assert_eq!(
            table::read_entry(FatType::Fat12, table, 62),
            Some(table::FREE)
        );
    }

    #[test]
    fn a_full_volume_records_no_next_free_hint_rather_than_one_past_the_end() {
        // When every cluster is handed out there is no next free one, and `used + 2` names
        // one past the highest the volume has. This crate's own reader flags exactly that as
        // a hint pointing at a cluster that does not exist, and `is_clean()` counts cosmetic
        // findings — so the writer produced output its own scanner would not call clean.
        //
        // `FormatPlan::fit` with no slack produces a full volume every time, so this is the
        // ordinary outcome of the ordinary call rather than a corner. The field has an honest
        // encoding for not knowing, and this is what it is for.
        // FAT32, because the information sector is the structure that carries the hint and
        // FAT12 and FAT16 have none. Its cluster minimum puts the smallest such volume at
        // about 33 MB, so the tree has to be that large for the fit to come out full.
        let options = options()
            .accept_all_loss()
            .plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat32)));
        let source = || {
            let meta = crate::source::Metadata::new(0o644, TIME);
            let mut b = TreeBuilder::new();
            for i in 0..8 {
                b = b.file(format!("/bulk{i}").into_bytes(), vec![0xAB; 5 << 20], meta);
            }
            b
        };
        let plan = FormatPlan::fit(source(), options, crate::Slack::None).expect("fit");
        assert_eq!(plan.free_clusters(), 0, "no slack leaves a full volume");
        let mut image = std::io::Cursor::new(vec![0u8; plan.volume_bytes() as usize]);
        plan.write_to(&mut image).expect("write");

        let mut r =
            crate::fat::Reader::open(std::io::Cursor::new(image.into_inner())).expect("open");
        let report = r.scan();
        assert!(
            report.is_clean(),
            "a volume this crate wrote is clean by its own scanner: {:#?}",
            report.anomalies()
        );
    }

    #[test]
    fn the_information_sector_counts_what_the_tree_took() {
        let meta = crate::source::Metadata::new(0o644, TIME);
        let source = TreeBuilder::new()
            .directory(b"/d".to_vec(), crate::source::Metadata::new(0o755, TIME))
            .file(b"/d/f".to_vec(), b"x", meta);
        let opts =
            options().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat32)));
        let image = format(source, 512 << 20, opts).expect("format");
        let layout = *image.layout();
        let fat32 = layout.fat32.expect("a FAT32 layout");
        let at = fat32.fs_info_sector as usize * layout.bytes_per_sector as usize;
        let info = FsInfo::read_from(&image.as_bytes()[at..]).expect("read");
        // The root, the subdirectory, and the one-byte file.
        assert_eq!(info.free_clusters, Some(layout.clusters - 3));
        assert_eq!(info.next_free_cluster, Some(5));
    }

    #[test]
    fn a_populated_format_is_reproducible_and_streams_the_same_bytes() {
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let opts = options()
                .label(VolumeLabel::new("TREE").unwrap())
                .plan(PlanRequest::new(0).fat_type(request));
            let whole = format(tree(), mib << 20, opts).expect("format");
            assert_eq!(
                whole.as_bytes(),
                format(tree(), mib << 20, opts).expect("format").as_bytes(),
                "two formats of one tree differ"
            );
            let mut streamed = std::io::Cursor::new(Vec::new());
            let plan = format_to(tree(), mib << 20, opts, &mut streamed).expect("format_to");
            assert_eq!(plan.layout(), whole.layout());
            assert_eq!(streamed.into_inner(), whole.as_bytes());
        }
    }

    #[test]
    fn a_loss_the_caller_has_not_accepted_stops_the_format_before_the_destination_is_touched() {
        let source = TreeBuilder::new().file(
            b"/setuid".to_vec(),
            b"x",
            crate::source::Metadata::new(0o4755, TIME),
        );
        // Nothing was written: the plan is where a format decides, and it failed there.
        let mut sink = std::io::Cursor::new(Vec::new());
        assert!(matches!(
            format_to(source.clone(), 64 << 20, options(), &mut sink),
            Err(FormatError::Model(_))
        ));
        assert!(sink.into_inner().is_empty());

        // Accepted, the build goes through and the report says what it cost.
        let opts = options().accept_all_loss();
        let image = format(source, 64 << 20, opts).expect("format");
        assert!(!image.fidelity().is_faithful());
        assert_eq!(
            image
                .fidelity()
                .count(crate::fidelity::Direction::Dropped, Property::SpecialBits),
            1
        );
    }

    #[test]
    fn a_hard_link_is_written_as_a_second_copy_of_its_file() {
        // The hard-link asymmetry at the byte level: the format has no second name for a
        // file, so a link goes in as a copy — two entries, two chains, the same bytes.
        let meta = crate::source::Metadata::new(0o644, TIME);
        let source = TreeBuilder::new()
            .file(b"/one".to_vec(), b"shared bytes", meta)
            .hardlink(b"/two".to_vec(), b"/one".to_vec(), meta);
        let opts = options().accept_loss(Property::Kind);
        let image = format(source, 64 << 20, opts).expect("format");
        let layout = *image.layout();
        let root =
            layout.root_dir_start_sector().unwrap() as usize * layout.bytes_per_sector as usize;
        let entries = files_at(&image, root);
        assert_eq!(entries.len(), 2);
        assert_ne!(first_cluster(&entries[0]), first_cluster(&entries[1]));
        for entry in &entries {
            assert_eq!(entry.size, 12);
            let at = cluster_at(&layout, first_cluster(entry));
            assert_eq!(&image.as_bytes()[at..at + 12], b"shared bytes");
        }
    }

    #[test]
    fn a_labelled_root_counts_the_label_among_the_entries_it_reserves_room_for() {
        // The label leads the root directory, so it is one of the entries the root's
        // clusters have to hold. A count that left it out would fit a root exactly and then
        // write one entry past it — onto the first file's cluster, which is the next one
        // allocated.
        let meta = crate::source::Metadata::new(0o644, TIME);
        let mut source = TreeBuilder::new();
        // Sixteen names that are already short names, so each costs exactly one entry and a
        // 512-byte cluster holds precisely these and nothing else.
        for i in 0..16 {
            source = source.file(format!("/F{i}").into_bytes(), b"payload", meta);
        }
        let opts = options().label(VolumeLabel::new("FULL").unwrap()).plan(
            PlanRequest::new(0)
                .fat_type(FatTypeRequest::Exactly(FatType::Fat32))
                .cluster_size(ClusterSize::Sectors(1)),
        );
        let image = format(source, 512 << 20, opts).expect("format");
        let layout = *image.layout();
        assert_eq!(
            layout.bytes_per_cluster(),
            512,
            "sixteen entries to a cluster"
        );
        let fat32 = layout.fat32.expect("a FAT32 layout");
        let root = fat32.root_cluster;

        // Asserted against the table rather than against the bytes, because the bytes hide
        // it: the directory is written before the files, so a file's contents land on top of
        // an entry that ran past the root and the listing reads plausibly either way. What
        // cannot be hidden is how many clusters the root was given.
        let head = layout.fat_start_sector(0).unwrap() as usize * layout.bytes_per_sector as usize;
        let table = &image.as_bytes()[head..];
        assert_eq!(
            table::read_entry(FatType::Fat32, table, root),
            Some(root + 1),
            "seventeen entries were placed in a root of one cluster"
        );
        assert!(table::is_end_of_chain(
            FatType::Fat32,
            table::read_entry(FatType::Fat32, table, root + 1).expect("an entry")
        ));

        // And every entry is inside the root's own two clusters, the label included.
        let at = cluster_at(&layout, root);
        assert_eq!(
            files_at(&image, at).len(),
            17,
            "the label and sixteen files"
        );
    }

    #[test]
    fn an_empty_source_writes_exactly_what_an_empty_volume_is() {
        // The populated writer has to degenerate to the empty one rather than merely
        // resemble it: the differential gate compares that image against a conventional
        // formatter's byte for byte.
        for (mib, request) in [
            (2u64, FatTypeRequest::Exactly(FatType::Fat12)),
            (64, FatTypeRequest::Exactly(FatType::Fat16)),
            (512, FatTypeRequest::Exactly(FatType::Fat32)),
        ] {
            let opts = options()
                .label(VolumeLabel::new("EMPTY").unwrap())
                .plan(PlanRequest::new(0).fat_type(request));
            let image = format(TreeBuilder::new(), mib << 20, opts).expect("format");
            let layout = *image.layout();
            let root = match layout.fat32 {
                Some(f) => cluster_at(&layout, f.root_cluster),
                None => {
                    layout.root_dir_start_sector().unwrap() as usize
                        * layout.bytes_per_sector as usize
                }
            };
            // The label entry and nothing after it.
            let entries = entries_at(&image, root);
            assert_eq!(entries.len(), 1, "{}", layout.fat_type);
            assert!(entries[0].attributes.contains(Attributes::VOLUME_ID));
        }
    }

    #[test]
    fn a_label_is_folded_up_padded_and_held_to_what_a_directory_entry_holds() {
        assert_eq!(VolumeLabel::new("esp").unwrap().as_bytes(), b"ESP        ");
        assert_eq!(
            VolumeLabel::new("ELEVEN CHRS").unwrap().as_bytes(),
            b"ELEVEN CHRS"
        );
        assert!(matches!(
            VolumeLabel::new("TWELVE CHARS"),
            Err(LabelError::TooLong { bytes: 12, .. })
        ));
        // The separators DOS reserved, and the control characters.
        for bad in ["A.B", "A/B", "A:B", "A*B", "A?B", "A\"B", "A|B", "A<B"] {
            assert!(
                matches!(VolumeLabel::new(bad), Err(LabelError::InvalidByte { .. })),
                "{bad} was accepted"
            );
        }
        assert!(matches!(
            VolumeLabel::from_bytes(&[0xE5, b'A']),
            Err(LabelError::InvalidByte { at: 0, .. })
        ));
        // The same byte anywhere else is a code page's business rather than this crate's, and
        // is carried through.
        assert!(VolumeLabel::from_bytes(&[b'A', 0xE5]).is_ok());
        // An empty label is all padding, which is a name a driver reads as blank rather than
        // an error to report.
        assert_eq!(VolumeLabel::new("").unwrap().as_bytes(), b"           ");
    }

    #[test]
    fn the_label_entry_stamps_every_time_the_entry_has() {
        // 2015-03-14T09:26:53Z: the odd second the two-second field cannot hold, which the
        // hundredths field carries instead. A conventional formatter drops it; this crate
        // records it, and the divergence is worth pinning rather than discovering.
        let mut opts = options().label(VolumeLabel::new("STAMPED").unwrap());
        opts.time = Timestamp::from_secs(1_426_325_213);
        let image = format(TreeBuilder::new(), 64 << 20, opts).expect("format");
        let layout = *image.layout();
        let root =
            layout.root_dir_start_sector().unwrap() as usize * layout.bytes_per_sector as usize;
        let entry = DirEntry::read_from(&image.as_bytes()[root..]).expect("read");
        let expected = DosTimestamp::encode(opts.time).expect("in range");
        assert_eq!(entry.create_date, expected.date);
        assert_eq!(entry.create_time, expected.time);
        assert_eq!(entry.create_time_tenth, 100);
        assert_eq!(entry.write_date, expected.date);
        assert_eq!(entry.write_time, expected.time);
        assert_eq!(entry.access_date, expected.date);
        // On the two-second boundary below it the hundredths field is empty, which is what a
        // conventional formatter writes at either instant.
        let mut even = opts;
        even.time = TIME;
        let image = format(TreeBuilder::new(), 64 << 20, even).expect("format");
        let entry = DirEntry::read_from(&image.as_bytes()[root..]).expect("read");
        assert_eq!(entry.create_time_tenth, 0);
        assert_eq!(entry.create_time, expected.time);
    }
}
