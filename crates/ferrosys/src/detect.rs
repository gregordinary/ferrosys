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
    src: R,
    options: &DetectOptions,
) -> Result<Filesystem, DetectError> {
    #[cfg(feature = "ext")]
    {
        use crate::read::{OpenOptions, ReadError, ReadPolicy, Reader};
        let open = OpenOptions::new()
            .base(options.base)
            .policy(ReadPolicy::Lenient);
        match Reader::open_with(src, &open) {
            Ok(reader) => Ok(Filesystem::Ext(reader.profile())),
            Err(ReadError::Io { kind, message }) => Err(DetectError::Io { kind, message }),
            Err(_) => Err(DetectError::Unrecognized),
        }
    }
    #[cfg(not(feature = "ext"))]
    {
        let _ = (src, options);
        Err(DetectError::Unrecognized)
    }
}

#[cfg(all(test, feature = "ext"))]
mod tests {
    use std::io::Cursor;

    use super::{DetectOptions, Filesystem, detect, detect_with};
    use crate::feature::Profile;
    use crate::materialize::{FormatOptions, format};
    use crate::ondisk::Timestamp;
    use crate::source::TreeBuilder;

    /// A formatted image's bytes at the default profile.
    fn image() -> Vec<u8> {
        let time = Timestamp::from_secs(1_700_000_000);
        let options = FormatOptions::new([7; 16], time, [0; 16]);
        format(TreeBuilder::new(), 32 << 20, options)
            .expect("format")
            .into_bytes()
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
