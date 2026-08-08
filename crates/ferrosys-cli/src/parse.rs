//! Value parsers: the text of one option into the typed value it names.
//!
//! Every function here is pure — a `&OsStr` in, a value or a [`ValueError`] out, no
//! I/O, no clock, no environment. A value is never classified as a flag, so `--offset
//! -1` reaches [`size`] as the text `-1` and is refused as a byte count rather than
//! mistaken for an option.
//!
//! A value that is not valid text is not a valid value for any option here — every one
//! of them names a number, a name, or a hex string — so the parsers work over `&str`
//! and report the offending text as the error's own subject. Only a *path* may be
//! arbitrary bytes, and paths do not come through this module.

use std::ffi::OsStr;
use std::num::NonZeroU64;

use ferrosys::Slack;
use ferrosys::ext::{
    Compat, ErrorBehavior, FeatureSet, GrowReservation, HashSignedness, HashVersion, Incompat,
    InodeCount, JournalSize, Profile, ReservedRatio, RoCompat, Severity,
};
use ferrosys::fat::{FatType, FatTypeRequest};
use ferrosys::{AcceptedLoss, Property};

/// Which filesystem a `-t` value names: the family, and which variant of it.
///
/// The two travel together because a variant only means anything inside its family, and
/// because the family is what decides which of a format's other options apply at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsType {
    /// An ext2, ext3, or ext4 filesystem.
    Ext(Profile),
    /// A FAT12, FAT16, or FAT32 volume.
    Fat(FatTypeRequest),
}

/// ext4 is what naming no type at all means, which is what keeps every command line that
/// named none writing exactly what it wrote before the value domain widened.
impl Default for FsType {
    fn default() -> Self {
        FsType::Ext(Profile::default())
    }
}

impl FsType {
    /// The family, as a message names it and as an option's own family is recorded.
    #[must_use]
    pub fn family(self) -> &'static str {
        match self {
            FsType::Ext(_) => "ext",
            FsType::Fat(_) => "fat",
        }
    }

    /// The variant, as it was named on the command line.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FsType::Ext(profile) => profile.name(),
            FsType::Fat(FatTypeRequest::Exactly(fat)) => fat.as_str(),
            // The value domain names one of the three outright, so nothing on a command
            // line reaches these. They are the family's own word, which is the honest
            // answer for a request that did not name a type.
            FsType::Fat(_) => "fat",
        }
    }
}

/// A value an option cannot take.
///
/// Each variant carries the offending text, rendered lossily, so the message names what
/// the user typed rather than only what was expected of it.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ValueError {
    /// The value is not a whole number.
    #[error("{0}: expected a whole number")]
    NotANumber(String),
    /// The value is a number, but not one the field holds.
    #[error("{0}: out of range")]
    OutOfRange(String),
    /// The value is not a byte count with an optional binary suffix.
    #[error("{0}: expected a byte count, optionally suffixed K, M, G, or T")]
    NotASize(String),
    /// The value is not sixteen bytes of hexadecimal.
    #[error("{0}: expected 16 bytes of hex (32 digits; dashes are ignored)")]
    NotHex16(String),
    /// The value is not one of a fixed set of names.
    #[error("{value}: expected one of {expected}")]
    NotOneOf {
        /// What was given.
        value: String,
        /// The names that would have been accepted.
        expected: &'static str,
    },
    /// The value is not a percentage the reserved-block ratio accepts.
    #[error("{0}: expected a percentage from 0 to 50, with at most two decimal places")]
    NotAPercent(String),
    /// A volume label longer than the sixteen-byte on-disk field.
    #[error("label is {len} bytes; the maximum is 16")]
    LabelTooLong {
        /// The label's length in bytes.
        len: usize,
    },
    /// A volume label a FAT volume cannot record: too long for the eleven-byte field, or
    /// holding a byte a directory entry's name field may not.
    ///
    /// The library's own refusal rides along, because it names both which byte and where.
    #[error(transparent)]
    NotAFatLabel(#[from] ferrosys::fat::LabelError),
    /// The value is not eight hexadecimal digits.
    #[error("{0}: expected 4 bytes of hex (8 digits; dashes are ignored)")]
    NotHex32(String),
    /// A property list held an empty element, so it names no property.
    #[error("{0}: a property list has an empty element")]
    EmptyProperty(String),
    /// The value is not an ownership pair.
    #[error("{0}: expected UID:GID, two whole numbers separated by a colon")]
    NotAnOwner(String),
    /// The value is not two octal permission modes separated by a colon.
    #[error("{0}: expected FILE:DIR, two octal permission modes (e.g. 644:755)")]
    NotAModePair(String),
    /// The value named a feature no ext feature word defines.
    #[error("{0}: not an ext feature name")]
    UnknownFeature(String),
    /// A feature list held an empty element, so it names no feature.
    #[error("{0}: a feature list has an empty element")]
    EmptyFeature(String),
    /// The value is neither one of the option's named choices nor the measurement it
    /// otherwise takes. Both halves are named, because an option whose value can be a
    /// word or a number has to say so — an error reporting only the number grammar
    /// leaves a caller no way to learn the word.
    #[error("{value}: expected {names}, or {measurement}")]
    NotNamedNor {
        /// What was given.
        value: String,
        /// The names the option accepts, as a phrase: `none or max`.
        names: &'static str,
        /// The measurement it takes instead, phrased as the other errors phrase theirs.
        measurement: &'static str,
    },
}

/// The value's text, rendered lossily — what an error message names it by.
fn shown(v: &OsStr) -> String {
    v.to_string_lossy().into_owned()
}

/// The value as text, or `None` when it is not text at all. A non-text value cannot be
/// any of the values this module parses, so the caller turns `None` into the same error
/// a wrong value would produce.
fn text(v: &OsStr) -> Option<&str> {
    v.to_str()
}

/// A byte count: a decimal number with an optional binary suffix — `K`, `M`, `G`, or
/// `T`, in either case, each a multiple of 1024 of the one before.
///
/// A leading `-` makes the number no longer a byte count, so a negative value is
/// rejected here rather than anywhere else.
///
/// # Errors
///
/// [`ValueError::NotASize`] if the text is not a number with an accepted suffix;
/// [`ValueError::OutOfRange`] if the suffix scales it past 64 bits.
pub fn size(v: &OsStr) -> Result<u64, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotASize(shown(v)))?;
    let (digits, scale) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1u64 << 40),
        _ => (s, 1),
    };
    // `str::parse::<u64>` accepts a leading `+` and rejects a leading `-`, whitespace,
    // and an empty string, which is exactly the set a byte count admits.
    let n: u64 = digits.parse().map_err(|_| ValueError::NotASize(shown(v)))?;
    n.checked_mul(scale)
        .ok_or_else(|| ValueError::OutOfRange(shown(v)))
}

/// A whole number that fits in 32 bits.
///
/// # Errors
///
/// [`ValueError::NotANumber`] if the text is not a decimal number;
/// [`ValueError::OutOfRange`] if it does not fit.
pub fn count_u32(v: &OsStr) -> Result<u32, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotANumber(shown(v)))?;
    s.parse().map_err(|_| {
        if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
            ValueError::OutOfRange(shown(v))
        } else {
            ValueError::NotANumber(shown(v))
        }
    })
}

/// An ownership pair, `UID:GID`, each a whole number the 32-bit on-disk fields hold.
///
/// Both halves are required: an image's ownership is two numbers, and taking one to mean
/// the other would guess at which.
///
/// # Errors
///
/// [`ValueError::NotAnOwner`] if the text is not two decimal numbers separated by a colon,
/// or if either does not fit in 32 bits.
pub fn owner(v: &OsStr) -> Result<(u32, u32), ValueError> {
    let bad = || ValueError::NotAnOwner(shown(v));
    let s = text(v).ok_or_else(bad)?;
    let (uid, gid) = s.split_once(':').ok_or_else(bad)?;
    let uid: u32 = uid.parse().map_err(|_| bad())?;
    let gid: u32 = gid.parse().map_err(|_| bad())?;
    Ok((uid, gid))
}

/// The two permission modes to assume where a filesystem records none, written
/// `FILE:DIR` in octal — `644:755`, `600:700`.
///
/// Octal without a prefix, because a permission mode is written that way everywhere else a
/// person meets one: `chmod 644`, `0644` in a source file, `rw-r--r--` in a listing. A
/// leading `0` is accepted and means nothing extra.
///
/// Only the permission and set-user/group/sticky bits are a mode here: the file-type bits
/// come from what the entry is, so a value past `07777` names bits this cannot set.
///
/// # Errors
///
/// [`ValueError::NotAModePair`] if the text is not two octal numbers separated by a colon,
/// and [`ValueError::OutOfRange`] if either names more than the permission bits.
pub fn modes(v: &OsStr) -> Result<(u16, u16), ValueError> {
    let bad = || ValueError::NotAModePair(shown(v));
    let s = text(v).ok_or_else(bad)?;
    let (file, dir) = s.split_once(':').ok_or_else(bad)?;
    let one = |part: &str| -> Result<u16, ValueError> {
        // A digit outside 0-7 is not an octal number at all, so it is the shape that is
        // wrong rather than the value: `8:755` has no reading, while `10000:755` has one
        // that names bits a permission mode does not hold.
        if part.is_empty() || !part.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return Err(bad());
        }
        u32::from_str_radix(part, 8)
            .ok()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|mode| *mode <= 0o7777)
            .ok_or_else(|| ValueError::OutOfRange(shown(v)))
    };
    Ok((one(file)?, one(dir)?))
}

/// A count of seconds since the Unix epoch, which may be negative: ext4 timestamps
/// reach back to 1901.
///
/// # Errors
///
/// [`ValueError::NotANumber`] if the text is not a decimal number, sign included;
/// [`ValueError::OutOfRange`] if it is one that does not fit in 64 bits.
pub fn seconds(v: &OsStr) -> Result<i64, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotANumber(shown(v)))?;
    s.parse().map_err(|_| {
        // A well-formed number the field cannot hold is a different mistake from text
        // that is not a number, and only one of them is fixed by writing digits.
        let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            ValueError::OutOfRange(shown(v))
        } else {
            ValueError::NotANumber(shown(v))
        }
    })
}

/// Sixteen bytes written as hexadecimal — the filesystem UUID and the directory-hash
/// seed are both this shape. Dashes are ignored wherever they fall, so the canonical
/// dashed form and a bare run of 32 digits both parse, in either case.
///
/// # Errors
///
/// [`ValueError::NotHex16`] if the text is not exactly 32 hex digits once dashes are
/// removed.
pub fn hex16(v: &OsStr) -> Result<[u8; 16], ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotHex16(shown(v)))?;
    let mut nibbles = Vec::with_capacity(32);
    for c in s.chars() {
        if c == '-' {
            continue;
        }
        let d = c
            .to_digit(16)
            .ok_or_else(|| ValueError::NotHex16(shown(v)))?;
        nibbles.push(d as u8);
    }
    if nibbles.len() != 32 {
        return Err(ValueError::NotHex16(shown(v)));
    }
    let mut out = [0u8; 16];
    for (byte, pair) in out.iter_mut().zip(nibbles.chunks_exact(2)) {
        *byte = (pair[0] << 4) | pair[1];
    }
    Ok(out)
}

/// One `-O` list applied to `base`, left to right: `extent,^has_journal`.
///
/// A bare name turns its feature on; a `^`-prefixed one turns it off; `none` clears all
/// three feature words at once, and leaves the block and inode sizes — which are not
/// features — as they are. Applying the list twice, or across two `-O` options, is the
/// same as applying the concatenation, because each element is a set operation on the
/// value it is given.
///
/// The result is not validated: a combination that must never reach disk is rejected by
/// [`FeatureSet::validate`], which names the exact conflict.
///
/// # Errors
///
/// [`ValueError::UnknownFeature`] if an element names no feature;
/// [`ValueError::EmptyFeature`] if an element is empty.
pub fn features(base: FeatureSet, v: &OsStr) -> Result<FeatureSet, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::UnknownFeature(shown(v)))?;
    let mut set = base;
    for element in s.split(',') {
        if element.is_empty() {
            return Err(ValueError::EmptyFeature(shown(v)));
        }
        if element == "none" {
            set.compat = Compat::NONE;
            set.incompat = Incompat::NONE;
            set.ro_compat = RoCompat::NONE;
            continue;
        }
        let (name, on) = match element.strip_prefix('^') {
            Some(rest) => (rest, false),
            None => (element, true),
        };
        set = set
            .with_feature(name, on)
            .ok_or_else(|| ValueError::UnknownFeature(name.to_string()))?;
    }
    Ok(set)
}

/// The grow reservation: `none`, `max`, or the byte size of the largest device the
/// image will be grown onto.
///
/// # Errors
///
/// [`ValueError::OutOfRange`] if a suffix scales the count past 64 bits;
/// [`ValueError::NotNamedNor`] if the text is neither name nor a byte count.
pub fn grow(v: &OsStr) -> Result<GrowReservation, ValueError> {
    match text(v) {
        Some("none") => Ok(GrowReservation::None),
        Some("max") => Ok(GrowReservation::Max),
        // A well-formed count the suffix pushed past 64 bits keeps its own error: the
        // caller wrote a byte count and the trouble is its magnitude, not the grammar.
        _ => size(v).map(GrowReservation::UpTo).map_err(|e| match e {
            ValueError::NotASize(value) => ValueError::NotNamedNor {
                value,
                names: "none or max",
                measurement: "a byte count, optionally suffixed K, M, G, or T",
            },
            other => other,
        }),
    }
}

/// The journal size: `auto` to size it from the filesystem, or a count of filesystem
/// blocks.
///
/// # Errors
///
/// [`ValueError::OutOfRange`] if the count does not fit in 32 bits;
/// [`ValueError::NotNamedNor`] if the text is neither `auto` nor a block count.
pub fn journal(v: &OsStr) -> Result<JournalSize, ValueError> {
    match text(v) {
        Some("auto") => Ok(JournalSize::Auto),
        // As for `grow`: a number too large for the field is a magnitude problem, and
        // saying so is more useful than re-offering the grammar.
        _ => count_u32(v).map(JournalSize::Blocks).map_err(|e| match e {
            ValueError::NotANumber(value) => ValueError::NotNamedNor {
                value,
                names: "auto",
                measurement: "a count of filesystem blocks",
            },
            other => other,
        }),
    }
}

/// The severity at which a scan's findings become a failing verdict, or `None` for
/// `never` — a scan that reports what it found and fails on none of it.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the text names no severity.
pub fn fail_on(v: &OsStr) -> Result<Option<Severity>, ValueError> {
    match text(v) {
        Some("cosmetic") => Ok(Some(Severity::Cosmetic)),
        Some("conformance") => Ok(Some(Severity::Conformance)),
        Some("integrity") => Ok(Some(Severity::Integrity)),
        Some("structural") => Ok(Some(Severity::Structural)),
        Some("never") => Ok(None),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "cosmetic, conformance, integrity, structural, never",
        }),
    }
}

/// The algorithm a hash-indexed directory orders its names by.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the text names no hash.
pub fn hash_version(v: &OsStr) -> Result<HashVersion, ValueError> {
    match text(v) {
        Some("half_md4") => Ok(HashVersion::HalfMd4),
        Some("tea") => Ok(HashVersion::Tea),
        Some("legacy") => Ok(HashVersion::Legacy),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "half_md4, tea, legacy",
        }),
    }
}

/// Whether a name's bytes are read as signed or unsigned when hashed.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the text names neither.
pub fn hash_signedness(v: &OsStr) -> Result<HashSignedness, ValueError> {
    match text(v) {
        Some("signed") => Ok(HashSignedness::Signed),
        Some("unsigned") => Ok(HashSignedness::Unsigned),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "signed, unsigned",
        }),
    }
}

/// The kernel's error-behavior policy (`s_errors`) by name. The names are the ones
/// `mke2fs -e` takes: `continue`, `remount-ro`, and `panic`.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the value is not one of the three.
pub fn error_behavior(v: &OsStr) -> Result<ErrorBehavior, ValueError> {
    match text(v) {
        Some("continue") => Ok(ErrorBehavior::Continue),
        Some("remount-ro") => Ok(ErrorBehavior::RemountReadOnly),
        Some("panic") => Ok(ErrorBehavior::Panic),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "continue, remount-ro, panic",
        }),
    }
}

/// Which filesystem `-t` names: the family, and which variant of it.
///
/// Both halves come from one value because they are one question. The variant seeds whatever
/// that family composes from — feature words for ext, the type a cluster count must derive to
/// for a FAT — and the family decides which of the remaining options apply at all.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the text names no filesystem this tool writes.
pub fn fs_type(v: &OsStr) -> Result<FsType, ValueError> {
    match text(v) {
        Some("ext2") => Ok(FsType::Ext(Profile::Ext2)),
        Some("ext3") => Ok(FsType::Ext(Profile::Ext3)),
        Some("ext4") => Ok(FsType::Ext(Profile::Ext4)),
        Some("fat12") => Ok(FsType::Fat(FatTypeRequest::Exactly(FatType::Fat12))),
        Some("fat16") => Ok(FsType::Fat(FatTypeRequest::Exactly(FatType::Fat16))),
        Some("fat32") => Ok(FsType::Fat(FatTypeRequest::Exactly(FatType::Fat32))),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "ext2, ext3, ext4, fat12, fat16, fat32",
        }),
    }
}

/// A 32-bit identifier written as hexadecimal: a FAT volume's serial number.
///
/// The dashed form every tool shows a serial in — `1A2B-3C4D` — is accepted alongside the
/// bare eight digits, so a serial read off one report can be typed straight back in.
///
/// # Errors
///
/// [`ValueError::NotHex32`] if the text is not eight hexadecimal digits once dashes are
/// removed.
pub fn hex32(v: &OsStr) -> Result<u32, ValueError> {
    let Some(s) = text(v) else {
        return Err(ValueError::NotHex32(shown(v)));
    };
    let digits: String = s.chars().filter(|&c| c != '-').collect();
    if digits.len() != 8 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValueError::NotHex32(shown(v)));
    }
    u32::from_str_radix(&digits, 16).map_err(|_| ValueError::NotHex32(shown(v)))
}

/// Which properties of a source a build may lose: a comma-separated list of property names,
/// or `all`.
///
/// The names are the properties themselves rather than one switch, because a caller who
/// accepted losing permission bits has not thereby accepted every symbolic link in the tree
/// disappearing. `all` is the deliberate exception, and it covers a property a later version
/// of the library names as well.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if an element names no property, and
/// [`ValueError::EmptyProperty`] if the list holds an empty element.
pub fn accepted_loss(v: &OsStr) -> Result<AcceptedLoss, ValueError> {
    let Some(s) = text(v) else {
        return Err(ValueError::NotOneOf {
            value: shown(v),
            expected: ACCEPTED_LOSS_NAMES,
        });
    };
    if s == "all" {
        return Ok(AcceptedLoss::ALL);
    }
    let mut set = AcceptedLoss::NONE;
    for element in s.split(',') {
        if element.is_empty() {
            return Err(ValueError::EmptyProperty(shown(v)));
        }
        let Some(property) = PROPERTY_NAMES
            .iter()
            .find(|(name, _)| *name == element)
            .map(|(_, property)| *property)
        else {
            return Err(ValueError::NotOneOf {
                value: element.to_string(),
                expected: ACCEPTED_LOSS_NAMES,
            });
        };
        set = set.and(property);
    }
    Ok(set)
}

/// The name of a property, as this tool writes it.
///
/// The same table [`accepted_loss`] reads, in the other direction — so a property a report
/// names is a property that can be typed straight back into `--accept-loss`. A tool that
/// printed one spelling and accepted another would be telling a caller a word it then
/// refuses.
#[must_use]
pub fn property_name(property: Property) -> &'static str {
    PROPERTY_NAMES
        .iter()
        .find(|(_, p)| *p == property)
        .map_or("unknown", |(name, _)| name)
}

/// This tool's one spelling for each property. Read by `--accept-loss` and written by every
/// report that names one.
///
/// The `unknown` fallback in [`property_name`] covers a property a newer library names and
/// this build does not; `--accept-loss all` is how such a property is accepted, since it
/// cannot be spelled.
const PROPERTY_NAMES: &[(&str, Property)] = &[
    ("ownership", Property::Ownership),
    ("permissions", Property::Permissions),
    ("special-bits", Property::SpecialBits),
    ("kind", Property::Kind),
    ("extended-attributes", Property::ExtendedAttributes),
    ("access-time", Property::AccessTime),
    ("change-time", Property::ChangeTime),
    ("modification-time", Property::ModificationTime),
    ("time-precision", Property::TimePrecision),
    ("name", Property::Name),
];

/// The names [`accepted_loss`] takes, for the message a refused one produces.
const ACCEPTED_LOSS_NAMES: &str = "all, or a comma-separated list of ownership, permissions, \
                                   special-bits, kind, extended-attributes, access-time, \
                                   change-time, modification-time, time-precision, name";

/// A volume label, packed NUL-padded into the sixteen-byte `s_volume_name` field.
///
/// A label is a byte field on disk, not text — the reader reports whatever bytes are
/// there — so it is taken as the argument's bytes rather than decoded through a character
/// encoding, exactly as a path inside the image is. A label longer than the field is
/// refused rather than truncated: the tool never writes a name the caller did not give it.
///
/// # Errors
///
/// [`ValueError::LabelTooLong`] if the label exceeds sixteen bytes.
pub fn label(bytes: &[u8]) -> Result<[u8; 16], ValueError> {
    if bytes.len() > 16 {
        return Err(ValueError::LabelTooLong { len: bytes.len() });
    }
    let mut name = [0u8; 16];
    name[..bytes.len()].copy_from_slice(bytes);
    Ok(name)
}

/// A bytes-per-inode ratio: one inode for every this many bytes of filesystem, a byte
/// count with an optional binary suffix. It must be positive.
///
/// # Errors
///
/// [`ValueError::NotASize`] if the text is not a byte count; [`ValueError::OutOfRange`]
/// if it scales past 64 bits or is zero.
pub fn bytes_per_inode(v: &OsStr) -> Result<InodeCount, ValueError> {
    let bytes = NonZeroU64::new(size(v)?).ok_or_else(|| ValueError::OutOfRange(shown(v)))?;
    Ok(InodeCount::BytesPerInode(bytes))
}

/// A reserved-block percentage from 0 to 50, with at most two decimal places, held as an
/// exact count of hundredths of one percent: `5` is 5%, `1.5` is 1.5%, `12.34` is 12.34%.
///
/// The two-place limit is what keeps the reservation exact integer arithmetic — a reserved
/// count is `blocks * ratio`, never floating point — while still admitting the fractional
/// percentages the field deserves.
///
/// # Errors
///
/// [`ValueError::NotAPercent`] if the text is not such a number; [`ValueError::OutOfRange`]
/// if it parses but exceeds 50.
pub fn reserved_percent(v: &OsStr) -> Result<ReservedRatio, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotAPercent(shown(v)))?;
    u16::try_from(hundredths_of_percent(s, v)?)
        .ok()
        .and_then(ReservedRatio::from_hundredths_of_percent)
        .ok_or_else(|| ValueError::OutOfRange(shown(v)))
}

/// The room a fitted filesystem must leave free: a percentage of the filesystem, or a
/// byte count.
///
/// `20%` and `1.5%` are shares of the finished filesystem; `64M` and `1G` are byte counts
/// with the same suffixes [`size`] takes. Which one a value is, is decided by the trailing
/// `%` alone.
///
/// # Errors
///
/// [`ValueError::NotAPercent`] or [`ValueError::NotASize`] if the text is neither form,
/// and [`ValueError::OutOfRange`] for a share past what a fit search will look for.
pub fn slack(v: &OsStr) -> Result<Slack, ValueError> {
    let Some(percent) = text(v).and_then(|s| s.strip_suffix('%')) else {
        return size(v).map(Slack::Bytes);
    };
    u16::try_from(hundredths_of_percent(percent, v)?)
        .ok()
        .filter(|&h| h <= Slack::MAX_SHARE)
        .map(Slack::Share)
        .ok_or_else(|| ValueError::OutOfRange(shown(v)))
}

/// A percentage as a whole number of hundredths of one percent: `5` is `500`, `1.5` is
/// `150`, `12.34` is `1234`, and `.5` is `50`.
///
/// `s` is the text without any `%`, and `v` is the whole value the caller was given, which
/// is what an error names.
fn hundredths_of_percent(s: &str, v: &OsStr) -> Result<u64, ValueError> {
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    // At most two fractional digits, so the value is a whole number of hundredths of a
    // percent. Every character on each side must be an ASCII digit, which admits no sign,
    // no whitespace, and no second point; and at least one digit must be present.
    let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if frac_part.len() > 2 || !digits(int_part) || !digits(frac_part) {
        return Err(ValueError::NotAPercent(shown(v)));
    }
    // Reject "" and ".", and a trailing dot like "5." whose empty fraction is vacuously
    // all-digits: a decimal point must be followed by a digit. A leading point (".5") is
    // allowed, so the guard is on the trailing dot specifically, not on any point.
    if (int_part.is_empty() && frac_part.is_empty()) || s.ends_with('.') {
        return Err(ValueError::NotAPercent(shown(v)));
    }
    let whole = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u64>()
            .map_err(|_| ValueError::OutOfRange(shown(v)))?
    };
    // The whole part in hundredths of a percent, plus the fraction scaled to two places.
    whole
        .checked_mul(100)
        .and_then(|h| h.checked_add(frac_to_hundredths(frac_part)))
        .ok_or_else(|| ValueError::OutOfRange(shown(v)))
}

/// A fractional-percent part, right-padded to two digits, as a count of hundredths of a
/// percent: "" -> 0, "5" -> 50, "50" -> 50, "05" -> 5. The caller has checked the part is
/// at most two ASCII digits.
fn frac_to_hundredths(frac: &str) -> u64 {
    let mut two = *b"00";
    for (slot, b) in two.iter_mut().zip(frac.bytes()) {
        *slot = b;
    }
    u64::from(two[0] - b'0') * 10 + u64::from(two[1] - b'0')
}

#[cfg(test)]
mod tests {
    /// The two modes a value names, or the error it is.
    #[test]
    fn modes_are_two_octal_permission_words() {
        use std::ffi::OsString;
        let m = |v: &str| super::modes(&OsString::from(v));

        assert_eq!(m("644:755").expect("parses"), (0o644, 0o755));
        // Octal without a prefix, as `chmod` takes it; a leading zero means nothing extra.
        assert_eq!(m("0600:0700").expect("parses"), (0o600, 0o700));
        // The set-user, set-group, and sticky bits are permission bits too.
        assert_eq!(m("4755:1777").expect("parses"), (0o4755, 0o1777));

        // Anything that is not two octal words separated by a colon.
        for bad in [
            "644",
            "644:",
            ":755",
            "644:755:1",
            "abc:755",
            "",
            "8:755",
            "-1:755",
        ] {
            assert!(
                matches!(m(bad), Err(super::ValueError::NotAModePair(_))),
                "{bad} should not parse as a mode pair"
            );
        }
        // Two octal words that name more than the permission bits.
        for out_of_range in ["10000:755", "644:10000", "7777777:755"] {
            assert!(
                matches!(m(out_of_range), Err(super::ValueError::OutOfRange(_))),
                "{out_of_range} names bits a mode cannot hold"
            );
        }
    }

    use super::*;

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    #[test]
    fn size_reads_a_byte_count_and_its_suffix() {
        assert_eq!(size(os("4096")).unwrap(), 4096);
        assert_eq!(size(os("512M")).unwrap(), 512 << 20);
        assert_eq!(size(os("512m")).unwrap(), 512 << 20);
        assert_eq!(size(os("1K")).unwrap(), 1024);
        assert_eq!(size(os("2G")).unwrap(), 2 << 30);
        assert_eq!(size(os("1T")).unwrap(), 1u64 << 40);
        assert_eq!(size(os("0")).unwrap(), 0);
    }

    #[test]
    fn size_refuses_what_is_not_a_byte_count() {
        // A value is never classified as a flag, so `--offset -1` arrives here as text
        // and is refused as a size — there is no negative-number special case anywhere.
        assert!(matches!(size(os("-1")), Err(ValueError::NotASize(_))));
        assert!(matches!(size(os("")), Err(ValueError::NotASize(_))));
        assert!(matches!(size(os("M")), Err(ValueError::NotASize(_))));
        assert!(matches!(size(os("1.5G")), Err(ValueError::NotASize(_))));
        assert!(matches!(size(os("4 K")), Err(ValueError::NotASize(_))));
        assert!(matches!(size(os("0x10")), Err(ValueError::NotASize(_))));
        // A suffix that scales past 64 bits is out of range, not unparseable.
        assert!(matches!(
            size(os("99999999999T")),
            Err(ValueError::OutOfRange(_))
        ));
        // The message names what was typed.
        assert_eq!(
            size(os("-1")).unwrap_err().to_string(),
            "-1: expected a byte count, optionally suffixed K, M, G, or T"
        );
    }

    #[test]
    fn counts_and_seconds() {
        assert_eq!(count_u32(os("256")).unwrap(), 256);
        assert!(matches!(
            count_u32(os("4294967296")),
            Err(ValueError::OutOfRange(_))
        ));
        assert!(matches!(
            count_u32(os("-1")),
            Err(ValueError::NotANumber(_))
        ));
        // Seconds carry a sign: ext4 timestamps reach back to 1901.
        assert_eq!(seconds(os("1700000000")).unwrap(), 1_700_000_000);
        assert_eq!(seconds(os("-2000000000")).unwrap(), -2_000_000_000);
        assert!(matches!(seconds(os("now")), Err(ValueError::NotANumber(_))));
    }

    #[test]
    fn hex16_reads_the_dashed_and_bare_forms() {
        let dashed = hex16(os("f0e17055-0000-4000-8000-000000000000")).unwrap();
        let bare = hex16(os("f0e1705500004000800000000000000")).ok();
        assert_eq!(
            dashed,
            [
                0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        // 31 digits is not 16 bytes.
        assert!(bare.is_none());
        assert_eq!(
            hex16(os("f0e170550000400080000000000000000")).ok(),
            None,
            "33 digits is not 16 bytes either"
        );
        assert_eq!(
            hex16(os("F0E17055000040008000000000000000")).unwrap(),
            dashed,
            "the case of a hex digit does not change its value"
        );
        assert!(matches!(
            hex16(os("f0e17055-0000-4000-8000-00000000000g")),
            Err(ValueError::NotHex16(_))
        ));
    }

    #[test]
    fn features_apply_left_to_right() {
        let base = FeatureSet::DEFAULT;
        // Off, then on again: the last element to name a feature wins.
        let set = features(base, os("^extent,extent")).unwrap();
        assert_eq!(set, base);
        let set = features(base, os("^has_journal,^orphan_file")).unwrap();
        assert!(!set.has_journal());
        assert!(!set.has_orphan_file());
        // `none` clears the feature words and leaves the sizes, which are not features.
        let set = features(base, os("none")).unwrap();
        assert!(set.compat.is_empty());
        assert!(set.incompat.is_empty());
        assert!(set.ro_compat.is_empty());
        assert_eq!(set.block_size, base.block_size);
        assert_eq!(set.inode_size, base.inode_size);
        // ...and a name after `none` builds back up from nothing.
        let set = features(base, os("none,extent")).unwrap();
        assert_eq!(set.incompat, Incompat::EXTENTS);
    }

    #[test]
    fn features_refuse_a_name_no_word_defines() {
        assert!(matches!(
            features(FeatureSet::DEFAULT, os("extents")),
            Err(ValueError::UnknownFeature(_))
        ));
        assert!(matches!(
            features(FeatureSet::DEFAULT, os("extent,,64bit")),
            Err(ValueError::EmptyFeature(_))
        ));
        // The Rust symbol is not the on-disk name.
        assert!(matches!(
            features(FeatureSet::DEFAULT, os("EXTENTS")),
            Err(ValueError::UnknownFeature(_))
        ));
    }

    #[test]
    fn the_named_choices() {
        assert_eq!(grow(os("none")).unwrap(), GrowReservation::None);
        assert_eq!(grow(os("max")).unwrap(), GrowReservation::Max);
        assert_eq!(grow(os("4G")).unwrap(), GrowReservation::UpTo(4 << 30));
        // An option whose value can be a word or a measurement names both when it
        // refuses one: offering only the byte-count grammar would leave `none` and
        // `max` undiscoverable from the error that most wants to mention them.
        assert_eq!(
            grow(os("huge")).unwrap_err().to_string(),
            "huge: expected none or max, or a byte count, optionally suffixed K, M, G, or T"
        );
        // A value that *is* a byte count, and only too large for the field, keeps the
        // error about its magnitude.
        assert!(matches!(
            grow(os("99999999T")),
            Err(ValueError::OutOfRange(_))
        ));

        assert_eq!(journal(os("auto")).unwrap(), JournalSize::Auto);
        assert_eq!(journal(os("4096")).unwrap(), JournalSize::Blocks(4096));
        assert_eq!(
            journal(os("fast")).unwrap_err().to_string(),
            "fast: expected auto, or a count of filesystem blocks"
        );
        assert!(matches!(
            journal(os("99999999999")),
            Err(ValueError::OutOfRange(_))
        ));

        assert_eq!(fail_on(os("never")).unwrap(), None);
        assert_eq!(fail_on(os("integrity")).unwrap(), Some(Severity::Integrity));

        assert_eq!(hash_version(os("tea")).unwrap(), HashVersion::Tea);
        assert_eq!(
            hash_signedness(os("signed")).unwrap(),
            HashSignedness::Signed
        );
        assert_eq!(
            hash_signedness(os("maybe")).unwrap_err().to_string(),
            "maybe: expected one of signed, unsigned"
        );
    }

    #[test]
    fn a_type_names_a_family_and_a_variant_of_it() {
        // The three ext baselines, which are the names `mke2fs -t` takes.
        assert_eq!(fs_type(os("ext2")).unwrap(), FsType::Ext(Profile::Ext2));
        assert_eq!(fs_type(os("ext3")).unwrap(), FsType::Ext(Profile::Ext3));
        assert_eq!(fs_type(os("ext4")).unwrap(), FsType::Ext(Profile::Ext4));
        // ...and the three FATs, which are what the cluster count must derive to rather
        // than what to write into the image: nothing in a FAT volume records its type.
        assert_eq!(
            fs_type(os("fat12")).unwrap(),
            FsType::Fat(FatTypeRequest::Exactly(FatType::Fat12))
        );
        assert_eq!(
            fs_type(os("fat32")).unwrap(),
            FsType::Fat(FatTypeRequest::Exactly(FatType::Fat32))
        );

        // Each answers which family it is and which variant, and the variant is the word
        // that was typed — the same word `ferrosys detect` prints back.
        assert_eq!(fs_type(os("ext3")).unwrap().family(), "ext");
        assert_eq!(fs_type(os("ext3")).unwrap().name(), "ext3");
        assert_eq!(fs_type(os("fat16")).unwrap().family(), "fat");
        assert_eq!(fs_type(os("fat16")).unwrap().name(), "fat16");
        // Naming no type is ext4, so a command line that named none writes what it always
        // wrote.
        assert_eq!(FsType::default(), FsType::Ext(Profile::Ext4));

        // A name outside every family is a usage error naming what would have been
        // accepted.
        assert!(matches!(
            fs_type(os("ext5")),
            Err(ValueError::NotOneOf { .. })
        ));
        assert_eq!(
            fs_type(os("xfs")).unwrap_err().to_string(),
            "xfs: expected one of ext2, ext3, ext4, fat12, fat16, fat32"
        );
    }

    #[test]
    fn a_serial_number_reads_in_the_form_a_report_prints_it() {
        // Eight hex digits, and the dashed form every tool shows a serial in — so one read
        // off a report can be typed straight back in.
        assert_eq!(hex32(os("1A2B3C4D")).unwrap(), 0x1a2b_3c4d);
        assert_eq!(hex32(os("1A2B-3C4D")).unwrap(), 0x1a2b_3c4d);
        assert_eq!(hex32(os("deadbeef")).unwrap(), 0xdead_beef);
        assert_eq!(hex32(os("00000000")).unwrap(), 0);
        // Anything that is not eight digits, or is not hex, is refused rather than padded
        // or truncated into something plausible.
        for bad in ["1A2B3C4", "1A2B3C4D5", "", "1A2B-3C4G", "0x1A2B3C4D"] {
            assert!(
                matches!(hex32(os(bad)), Err(ValueError::NotHex32(_))),
                "{bad} is not a serial number"
            );
        }
    }

    #[test]
    fn accepted_losses_are_named_one_by_one_or_all_at_once() {
        // Named individually, because a caller who accepted losing permission bits has not
        // thereby accepted every symbolic link in the tree disappearing.
        let one = accepted_loss(os("permissions")).unwrap();
        assert!(one.contains(Property::Permissions));
        assert!(!one.contains(Property::Kind));

        let several = accepted_loss(os("ownership,permissions,extended-attributes")).unwrap();
        for property in [
            Property::Ownership,
            Property::Permissions,
            Property::ExtendedAttributes,
        ] {
            assert!(several.contains(property), "{property:?} was named");
        }
        assert!(!several.contains(Property::Kind));

        // Every name round-trips: what a report prints is what this reads back.
        for (name, property) in PROPERTY_NAMES {
            assert_eq!(property_name(*property), *name);
            assert!(accepted_loss(os(name)).unwrap().contains(*property));
        }

        // `all` is the deliberate exception, and it covers a property a later version of
        // the library names as well.
        assert_eq!(accepted_loss(os("all")).unwrap(), AcceptedLoss::ALL);
        // Nothing named at all is the default, which refuses every loss.
        assert!(AcceptedLoss::NONE.is_empty());

        // A name no property defines, and an empty element, are each refused by name.
        assert!(matches!(
            accepted_loss(os("permissons")),
            Err(ValueError::NotOneOf { .. })
        ));
        assert!(matches!(
            accepted_loss(os("ownership,,kind")),
            Err(ValueError::EmptyProperty(_))
        ));
    }

    #[test]
    fn label_fits_the_field_or_is_refused() {
        assert_eq!(&label(b"root").unwrap()[..4], b"root");
        // Exactly sixteen bytes fills the field with no NUL terminator.
        assert_eq!(label(b"0123456789abcdef").unwrap(), *b"0123456789abcdef");
        // A shorter label is NUL-padded.
        assert_eq!(label(b"fs").unwrap(), *b"fs\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        // Seventeen bytes is one too many, and is refused rather than truncated.
        assert!(matches!(
            label(b"0123456789abcdefX"),
            Err(ValueError::LabelTooLong { len: 17 })
        ));
        assert_eq!(
            label(b"this label is much too long")
                .unwrap_err()
                .to_string(),
            "label is 27 bytes; the maximum is 16"
        );
    }

    #[test]
    fn reserved_percent_is_exact_hundredths() {
        // The default and the whole numbers around it.
        assert_eq!(
            reserved_percent(os("5")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(500).unwrap()
        );
        assert_eq!(
            reserved_percent(os("0")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(0).unwrap()
        );
        assert_eq!(
            reserved_percent(os("50")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(5000).unwrap()
        );
        // Fractional, to one and two places, and a leading point.
        assert_eq!(
            reserved_percent(os("1.5")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(150).unwrap()
        );
        assert_eq!(
            reserved_percent(os("12.34")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(1234).unwrap()
        );
        assert_eq!(
            reserved_percent(os(".5")).unwrap(),
            ReservedRatio::from_hundredths_of_percent(50).unwrap()
        );
        // Exactness: 1.5% of a filesystem is a whole number of blocks, no float.
        assert_eq!(reserved_percent(os("1.5")).unwrap().blocks(16384), 245);
        assert_eq!(reserved_percent(os("5")).unwrap().blocks(16384), 819);
    }

    #[test]
    fn reserved_percent_refuses_what_it_cannot_hold() {
        // Past the 50% ceiling: parses, but out of range.
        assert!(matches!(
            reserved_percent(os("50.01")),
            Err(ValueError::OutOfRange(_))
        ));
        assert!(matches!(
            reserved_percent(os("60")),
            Err(ValueError::OutOfRange(_))
        ));
        // A third decimal place is finer than the exact representation admits.
        assert!(matches!(
            reserved_percent(os("1.234")),
            Err(ValueError::NotAPercent(_))
        ));
        // Signs, letters, a bare point, and a trailing dot ("5.") are not percentages;
        // a leading point (".5") is, and is checked above.
        for bad in ["-1", "1.5%", "abc", ".", "", "1.2.3", "5.", "50."] {
            assert!(
                matches!(reserved_percent(os(bad)), Err(ValueError::NotAPercent(_))),
                "{bad:?} should not parse as a percent"
            );
        }
    }

    #[test]
    fn bytes_per_inode_is_a_positive_byte_count() {
        assert_eq!(
            bytes_per_inode(os("16384")).unwrap(),
            InodeCount::BytesPerInode(NonZeroU64::new(16384).unwrap())
        );
        // The size suffixes carry over from the byte-count parser.
        assert_eq!(
            bytes_per_inode(os("1M")).unwrap(),
            InodeCount::BytesPerInode(NonZeroU64::new(1 << 20).unwrap())
        );
        // Zero would divide the filesystem size by nothing, so it is refused.
        assert!(matches!(
            bytes_per_inode(os("0")),
            Err(ValueError::OutOfRange(_))
        ));
        assert!(matches!(
            bytes_per_inode(os("nonsense")),
            Err(ValueError::NotASize(_))
        ));
    }
}
