//! Image detection: read an image and report which filesystem family it holds.
//!
//! [`detect`] reads an image's on-disk identity and returns the [`Filesystem`] family it
//! advertises, matched against the backends this build compiles in. It is the crate's
//! family-agnostic entry point, above whichever family answers it. To read an image's
//! contents, open the matching family's reader directly.
//!
//! Detection is deliberately more forgiving than reading. A classifier answers "what is
//! this", and an image that is recognizably ext but not conformant is still ext — so a
//! quirk that a strict read refuses is not allowed to turn into "unrecognized", which
//! would be the one answer that is certainly wrong.
//!
//! # The order families are tried in
//!
//! The list is hardcoded and short, but the *rule* that orders it is written down so a
//! family added later inserts itself mechanically rather than by argument:
//!
//! - **Tier 1** is a family whose images carry a distinctive multi-byte magic at a fixed
//!   offset. Two such magics do not collide, so at most one tier-1 family claims any image
//!   and order within the tier does not matter.
//! - **Tier 2** is a family whose magic is weak enough to collide with something else, or
//!   that has none at all. Such a family is classified only by checking a whole header for
//!   internal consistency, and it runs after every tier-1 family — because a false positive
//!   there is the one detection failure that silently misidentifies a healthy filesystem.
//!
//! Within tier 2, order must not be relied on either: if that tier ever holds more than one
//! family, an ordered list is the wrong structure and each family should declare a probe of
//! its own.

use std::io::{Read, Seek};

/// The filesystem family an image holds, as [`detect`] classifies it.
///
/// This is the family-agnostic result of detection. Each variant names one family and
/// carries that family's own sub-classification.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Filesystem {
    /// An ext filesystem, labeled by the [`Profile`](crate::ext::Profile) its feature
    /// words classify to — ext2, ext3, or ext4.
    #[cfg(feature = "ext")]
    Ext(crate::feature::Profile),
    /// A FAT filesystem, labeled by the [`FatType`](crate::fat::FatType) its cluster count
    /// derives to — FAT12, FAT16, or FAT32. Nothing in a FAT image records which of the
    /// three it is, so this is computed rather than read.
    #[cfg(feature = "fat")]
    Fat(crate::fat::FatType),
}

/// Where to look for a filesystem, and anything else detection needs to be told.
///
/// Every input to [`detect_with`] is a field here rather than a parameter, so an input
/// detection grows arrives as a field a caller may ignore.
///
/// ```
/// # use ferrosys::DetectOptions;
/// // The filesystem in a partition that begins one mebibyte into a whole-disk image.
/// let options = DetectOptions::new().base(1 << 20);
/// # let _ = options;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct DetectOptions {
    /// Byte offset within the source at which the filesystem begins — zero for a bare
    /// image, the partition's start for one inside a disk image, and wherever a carver
    /// located a candidate region.
    ///
    /// Offset is a first-class concept everywhere a filesystem is read, and it is one here
    /// for the same reason: the question detection answers is "what is at this location",
    /// which a classifier fixed to the start of its source cannot be asked.
    pub base: u64,
}

impl DetectOptions {
    /// Detect at the start of the source.
    #[must_use]
    pub const fn new() -> Self {
        Self { base: 0 }
    }

    /// Detect a filesystem that begins `base` bytes into the source.
    #[must_use]
    pub const fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }
}

/// A failure detecting the filesystem in an image.
///
/// Detection answers which family an image holds, not what a specific family's reader
/// makes of it, so its failures are the two a classifier has: the source could not be
/// read, or nothing recognized it. A family's own reader reports the detail behind an
/// unrecognized image.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DetectError {
    /// The source could not be read or sought.
    ///
    /// The `kind` is [`std::io::Error`]'s own classification, carried separately so a
    /// caller can tell a truncated image from an environment failure without matching on
    /// the message text. It does not appear in the rendered message because `message` is
    /// the underlying error rendered by [`std::io::Error`], which opens with the kind's
    /// own description.
    #[error("i/o error: {message}")]
    #[non_exhaustive]
    Io {
        /// How the underlying [`std::io::Error`] classified itself.
        kind: std::io::ErrorKind,
        /// The error rendered as text, for a message a person reads.
        message: String,
    },
    /// The source is not a filesystem any family this build compiles in recognizes.
    #[error("unrecognized filesystem: no compiled-in family claims this image")]
    Unrecognized,
}

/// Detect the filesystem family at the start of an image.
///
/// Sugar for [`detect_with`] under the default [`DetectOptions`]. For a filesystem that
/// begins somewhere other than the start of the source — a partition, or a region a carver
/// located — name where with [`DetectOptions::base`].
///
/// # Errors
///
/// Returns [`DetectError::Io`] when the source cannot be read, or
/// [`DetectError::Unrecognized`] when no compiled-in family recognizes the image.
pub fn detect<R: Read + Seek>(src: R) -> Result<Filesystem, DetectError> {
    detect_with(src, &DetectOptions::new())
}

/// Detect the filesystem family an image holds under `options`.
///
/// Reads the image's on-disk identity at [`DetectOptions::base`] and returns the
/// [`Filesystem`] the compiled-in families classify it to. To read the image's contents,
/// open the matching family's reader over the same source at the same offset.
///
/// Classification is lenient: an image whose on-disk identity is readable is classified
/// even where a strict read of it would be refused, because the two questions are
/// different. Whether a filesystem is *sound* is what a family's reader and its scan
/// answer; whether it *is one* is this, and answering "unrecognized" for a real filesystem
/// with an unfamiliar feature bit would be the one answer that is certainly wrong.
///
/// # Errors
///
/// Returns [`DetectError::Io`] when the source cannot be read, or
/// [`DetectError::Unrecognized`] when no compiled-in family recognizes the image.
pub fn detect_with<R: Read + Seek>(
    #[allow(unused_mut)] mut src: R,
    options: &DetectOptions,
) -> Result<Filesystem, DetectError> {
    // Tier 1: every family whose images carry a distinctive multi-byte magic at a fixed
    // offset. Order within the tier does not matter and must not be relied on — two such
    // magics do not collide, so at most one claims any image.
    #[cfg(feature = "ext")]
    match ext_claim(&mut src, options) {
        Ok(Some(fs)) => return Ok(fs),
        Ok(None) => {}
        Err(e) => return Err(e),
    }

    // Tier 2: every family whose magic is weak enough to collide, or that has none at all,
    // and which is therefore classified only by checking a whole header for internal
    // consistency. A family in this tier runs after every tier-1 family precisely because it
    // can claim an image that is really something else, and if this tier ever holds more
    // than one family the list is the wrong structure — each family should declare a probe
    // instead.
    //
    // FAT is here because its only fixed marker is the boot signature, which every bootable
    // sector ever written carries.
    #[cfg(feature = "fat")]
    match crate::fat::claim(&mut src, options) {
        Ok(Some(fs)) => return Ok(fs),
        Ok(None) => {}
        Err(e) => return Err(e),
    }

    // Detection answers with one family rather than every family that might match. An image
    // that plausibly classifies two ways is a real forensic situation, and the answer is
    // that the caller re-runs detection against the families it wants to distinguish, not
    // that every caller pays for a list of maybes.
    let _ = (&mut src, options);
    Err(DetectError::Unrecognized)
}

/// Whether the ext family claims the image, and as what.
///
/// `Ok(None)` is "not ours"; an I/O failure is the source's rather than the image's and
/// stops detection rather than moving on, since every later probe would fail the same way.
///
/// Running out of source is the exception, and it has to be: this probe reads 1024 bytes at
/// `base + 1024`, and a source shorter than that is not a source that failed — it is a source
/// with no ext superblock in it. A later probe reading less may still recognize what it
/// holds, and a carved FAT fragment of one sector is exactly that shape, so an end of file
/// here is "not ours" rather than an answer for every family.
///
/// A lenient open is what asks the question: an image whose superblock reads is ext,
/// whatever a strict read would go on to refuse about it.
#[cfg(feature = "ext")]
fn ext_claim<R: Read + Seek>(
    src: R,
    options: &DetectOptions,
) -> Result<Option<Filesystem>, DetectError> {
    use crate::policy::ReadPolicy;
    use crate::read::{OpenOptions, ReadError, Reader};

    let open = OpenOptions::new()
        .base(options.base)
        .policy(ReadPolicy::Lenient);
    match Reader::open_with(src, &open) {
        Ok(reader) => Ok(Some(Filesystem::Ext(reader.profile()))),
        Err(ReadError::Io {
            kind: std::io::ErrorKind::UnexpectedEof,
            ..
        }) => Ok(None),
        Err(ReadError::Io { kind, message }) => Err(DetectError::Io { kind, message }),
        Err(_) => Ok(None),
    }
}

/// What the family-agnostic root answers on its own.
///
/// The base build — no family compiled in — is a configuration a consumer can select, and
/// every other test in this crate builds its fixtures with the ext formatter, so without
/// this the root would only ever be *compiled* without its families and never run. These
/// cases need no image, which is what lets them run in both builds.
#[cfg(test)]
mod agnostic_tests {
    use super::DetectOptions;

    #[test]
    fn options_carry_the_offset_they_were_given() {
        assert_eq!(DetectOptions::new().base, 0);
        assert_eq!(DetectOptions::new().base(1 << 20).base, 1 << 20);
        assert_eq!(DetectOptions::default(), DetectOptions::new());
    }

    /// With no family compiled in there is nothing to recognize an image, and the answer
    /// is the same for every source — which is the whole of what the base build promises,
    /// and is exactly what a build carrying a family cannot check.
    #[cfg(not(feature = "ext"))]
    #[test]
    fn a_build_with_no_family_recognizes_nothing() {
        use super::{DetectError, detect, detect_with};
        use std::io::Cursor;

        for bytes in [vec![0u8; 4096], b"not a filesystem".to_vec(), Vec::new()] {
            assert_eq!(
                detect(Cursor::new(bytes)).unwrap_err(),
                DetectError::Unrecognized
            );
        }
        // And the source is never read, so an offset past its end is the same answer
        // rather than an I/O failure.
        assert_eq!(
            detect_with(
                Cursor::new(vec![0u8; 1024]),
                &DetectOptions::new().base(1 << 30)
            )
            .unwrap_err(),
            DetectError::Unrecognized
        );
    }
}

#[cfg(all(test, feature = "ext"))]
mod tests {
    use std::io::Cursor;

    use super::{DetectOptions, Filesystem, detect, detect_with};
    use crate::feature::Profile;
    use crate::materialize::{FormatOptions, format};
    use crate::source::TreeBuilder;
    use crate::time::Timestamp;

    /// A formatted image's bytes at the default profile.
    fn image() -> Vec<u8> {
        let time = Timestamp::from_secs(1_700_000_000);
        let options = FormatOptions::new([7; 16], time, [0; 16]);
        format(TreeBuilder::new(), 32 << 20, options)
            .expect("format")
            .into_bytes()
    }

    #[test]
    #[cfg(feature = "fat")]
    fn a_source_too_short_for_an_ext_superblock_still_reaches_the_later_probes() {
        // The ext probe reads 1024 bytes at `base + 1024`, so a source shorter than 2048 is
        // one it cannot read at all. Reported as an I/O failure that ends detection, that
        // answer would stand for every family — and it is wrong for the very next one: the
        // FAT probe reads sector zero and nothing else, so a carved fragment of one sector
        // is a volume it recognizes.
        //
        // Running out of source is "not ours", not "nobody's".
        let mut fragment = vec![0u8; 512];
        // A boot sector minimal enough for the FAT probe to have an opinion about, which is
        // all this needs: what matters is that the probe was *reached*.
        fragment[510] = 0x55;
        fragment[511] = 0xAA;
        assert!(
            !matches!(
                detect(Cursor::new(fragment)),
                Err(super::DetectError::Io { .. })
            ),
            "a short source ended detection instead of failing the ext probe"
        );
    }

    #[test]
    fn detect_labels_a_formatted_image_by_its_family() {
        // detect classifies the image by its feature words: the default profile is ext4.
        assert_eq!(
            detect(Cursor::new(image())).expect("detect"),
            Filesystem::Ext(Profile::Ext4)
        );
    }

    #[test]
    fn detect_rejects_a_non_filesystem_source() {
        // A buffer with no ext superblock is not recognized rather than opened.
        let junk = vec![0u8; 64 << 10];
        assert!(matches!(
            detect(Cursor::new(junk)),
            Err(super::DetectError::Unrecognized)
        ));
    }

    #[test]
    fn detection_answers_at_the_offset_it_is_given() {
        // "What is at this location" is the question a carving pipeline asks, and it cannot
        // be asked of a classifier pinned to the start of its source. The same bytes are
        // unrecognized at offset zero and ext4 a mebibyte in.
        const BASE: u64 = 1 << 20;
        let mut disk = vec![0u8; BASE as usize];
        disk.extend_from_slice(&image());

        assert!(matches!(
            detect(Cursor::new(&disk)),
            Err(super::DetectError::Unrecognized)
        ));
        assert_eq!(
            detect_with(Cursor::new(&disk), &DetectOptions::new().base(BASE)).expect("detect"),
            Filesystem::Ext(Profile::Ext4)
        );
    }

    #[test]
    fn a_quirk_a_strict_read_refuses_is_still_a_filesystem() {
        // An `incompat` bit this reader does not interpret makes a strict open refuse the
        // image — correctly, since it cannot be sure it reads the format right. It is still
        // an ext filesystem, and a classifier that answered "unrecognized" would be wrong
        // about the only thing it was asked.
        let mut bytes = image();
        // s_feature_incompat is at offset 0x60 of the superblock, which begins at 1024.
        let off = 1024 + 0x60;
        let mut incompat =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        // A bit no ext feature defines, so no reader can claim to interpret it.
        incompat |= 0x8000_0000;
        bytes[off..off + 4].copy_from_slice(&incompat.to_le_bytes());

        assert!(
            crate::read::Reader::open(Cursor::new(&bytes)).is_err(),
            "a strict read must refuse an incompat feature it does not interpret"
        );
        assert_eq!(
            detect(Cursor::new(&bytes)).expect("detection is not strictness"),
            Filesystem::Ext(Profile::Ext4)
        );
    }
}
