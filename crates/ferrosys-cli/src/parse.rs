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

use ferrosys::ext::feature::FeatureSet;
use ferrosys::ext::{
    Compat, ErrorBehavior, GrowReservation, HashSignedness, HashVersion, Incompat, InodeCount,
    JournalSize, Profile, ReservedRatio, RoCompat, Severity,
};

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
    /// The value named a feature no ext feature word defines.
    #[error("{0}: not an ext feature name")]
    UnknownFeature(String),
    /// A feature list held an empty element, so it names no feature.
    #[error("{0}: a feature list has an empty element")]
    EmptyFeature(String),
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

/// A count of seconds since the Unix epoch, which may be negative: ext4 timestamps
/// reach back to 1901.
///
/// # Errors
///
/// [`ValueError::NotANumber`] if the text is not a decimal number, sign included.
pub fn seconds(v: &OsStr) -> Result<i64, ValueError> {
    let s = text(v).ok_or_else(|| ValueError::NotANumber(shown(v)))?;
    s.parse().map_err(|_| ValueError::NotANumber(shown(v)))
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
/// [`ValueError::NotASize`] if the text is neither name nor a byte count.
pub fn grow(v: &OsStr) -> Result<GrowReservation, ValueError> {
    match text(v) {
        Some("none") => Ok(GrowReservation::None),
        Some("max") => Ok(GrowReservation::Max),
        _ => size(v).map(GrowReservation::UpTo),
    }
}

/// The journal size: `auto` to size it from the filesystem, or a count of filesystem
/// blocks.
///
/// # Errors
///
/// [`ValueError::NotANumber`] if the text is neither `auto` nor a block count.
pub fn journal(v: &OsStr) -> Result<JournalSize, ValueError> {
    match text(v) {
        Some("auto") => Ok(JournalSize::Auto),
        _ => count_u32(v).map(JournalSize::Blocks),
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

/// The base filesystem profile a format seeds from: `ext2`, `ext3`, or `ext4`. The names
/// are the ones `mke2fs -t` takes.
///
/// The profile sets the baseline feature words and the baseline block and inode sizes; the
/// `-O` list and the size options layer on top of it. The image is judged by the features
/// it ends up carrying, not the profile it started from.
///
/// # Errors
///
/// [`ValueError::NotOneOf`] if the text names no profile.
pub fn profile(v: &OsStr) -> Result<Profile, ValueError> {
    match text(v) {
        Some("ext2") => Ok(Profile::Ext2),
        Some("ext3") => Ok(Profile::Ext3),
        Some("ext4") => Ok(Profile::Ext4),
        _ => Err(ValueError::NotOneOf {
            value: shown(v),
            expected: "ext2, ext3, ext4",
        }),
    }
}

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
    // The whole part in hundredths of a percent, plus the fraction scaled to two places:
    // "5" -> 500, "1.5" -> 150, "12.34" -> 1234, ".5" -> 50.
    let hundredths = whole
        .checked_mul(100)
        .and_then(|h| h.checked_add(frac_to_hundredths(frac_part)))
        .and_then(|h| u16::try_from(h).ok())
        .and_then(ReservedRatio::from_hundredths_of_percent)
        .ok_or_else(|| ValueError::OutOfRange(shown(v)))?;
    Ok(hundredths)
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
        assert!(matches!(grow(os("huge")), Err(ValueError::NotASize(_))));

        assert_eq!(journal(os("auto")).unwrap(), JournalSize::Auto);
        assert_eq!(journal(os("4096")).unwrap(), JournalSize::Blocks(4096));

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
    fn profile_names_the_three_baselines() {
        assert_eq!(profile(os("ext2")).unwrap(), Profile::Ext2);
        assert_eq!(profile(os("ext3")).unwrap(), Profile::Ext3);
        assert_eq!(profile(os("ext4")).unwrap(), Profile::Ext4);
        // A name outside the family is a usage error naming what would have been accepted.
        assert!(matches!(
            profile(os("ext5")),
            Err(ValueError::NotOneOf { .. })
        ));
        assert_eq!(
            profile(os("xfs")).unwrap_err().to_string(),
            "xfs: expected one of ext2, ext3, ext4"
        );
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
