//! Image detection: read an image and report which filesystem family it holds.
//!
//! [`detect`] reads an image's on-disk identity and returns the [`Filesystem`] family it
//! advertises, matched against the backends this build compiles in. It is the crate's
//! family-agnostic entry point, above whichever family answers it. To read an image's
//! contents, open the matching family's reader directly.

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
    #[error("i/o error: {0}")]
    Io(String),
    /// The source is not a filesystem any family this build compiles in recognizes.
    #[error("unrecognized filesystem: no compiled-in family claims this image")]
    Unrecognized,
}

/// Detect the filesystem family an image holds.
///
/// Reads the image's on-disk identity and returns the [`Filesystem`] the compiled-in
/// families classify it to. To read the image's contents, open the matching family's
/// reader over the same source.
///
/// # Errors
///
/// Returns [`DetectError::Io`] when the source cannot be read, or
/// [`DetectError::Unrecognized`] when no compiled-in family recognizes the image.
pub fn detect<R: Read + Seek>(src: R) -> Result<Filesystem, DetectError> {
    #[cfg(feature = "ext")]
    {
        use crate::read::{ReadError, Reader};
        match Reader::open(src) {
            Ok(reader) => Ok(Filesystem::Ext(reader.profile())),
            Err(ReadError::Io(e)) => Err(DetectError::Io(e)),
            Err(_) => Err(DetectError::Unrecognized),
        }
    }
    #[cfg(not(feature = "ext"))]
    {
        let _ = src;
        Err(DetectError::Unrecognized)
    }
}

#[cfg(all(test, feature = "ext"))]
mod tests {
    use std::io::Cursor;

    use super::{Filesystem, detect};
    use crate::feature::Profile;
    use crate::materialize::{FormatOptions, format};
    use crate::ondisk::Timestamp;
    use crate::source::TreeBuilder;

    #[test]
    fn detect_labels_a_formatted_image_by_its_family() {
        let time = Timestamp::from_secs(1_700_000_000);
        let options = FormatOptions::new([7; 16], time, [0; 16]);
        let bytes = format(TreeBuilder::new(), 32 << 20, options)
            .expect("format")
            .into_bytes();

        // detect classifies the image by its feature words: the default profile is ext4.
        assert_eq!(
            detect(Cursor::new(bytes)).expect("detect"),
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
}
