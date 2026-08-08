//! Opening an image without knowing what is in it: [`open`], and the [`FsReader`] it hands
//! back.
//!
//! [`detect`](fn@crate::detect) answers what an image *is*; this answers it and hands back the
//! reader for that family, already open over the same source at the same offset. The result
//! is an enum of concrete family readers rather than a trait, and deliberately: the
//! families' readers are genuinely not interchangeable — one has inode numbers and link
//! counts, another has neither — so a trait wide enough to be useful would be a lie about
//! the narrowest family, and one narrow enough to be true about it would be useless for the
//! widest. The enum preserves each family's whole surface and costs a caller one `match`.
//!
//! What *is* shared across the families is [`FsTree`](crate::FsTree), the four operations an
//! extraction needs of any of them.
//!
//! The module is compiled only where at least one family is, since with none there is
//! nothing an image could be opened as. The condition is the disjunction of every family
//! feature, not the default one: reaching a family's reader without naming the family is
//! exactly what a build carrying one non-default family needs.

use std::io::{Read, Seek};

use crate::policy::OpenOptions;

/// An open filesystem, as whichever family claimed the image.
///
/// Present only in a build that compiles in at least one family: with none, there is
/// nothing an image could be opened as, and [`detect`](fn@crate::detect) already answers
/// [`Unrecognized`](crate::DetectError::Unrecognized) for every source.
///
/// Each variant carries that family's own reader, whole: nothing is hidden behind a common
/// interface, so a caller that has matched its way to one has everything that family
/// offers. What every variant does share is [`FsTree`](crate::FsTree), so an extraction
/// need not match at all.
///
/// The enum is `#[non_exhaustive]`, and a build compiles in the variants of the families it
/// compiles in — so a `match` carries a wildcard arm, and adding a family is not a breaking
/// change.
#[non_exhaustive]
pub enum FsReader<R> {
    /// An ext2, ext3, or ext4 filesystem.
    #[cfg(feature = "ext")]
    Ext(crate::read::Reader<R>),
    /// A FAT12, FAT16, or FAT32 volume.
    #[cfg(feature = "fat")]
    Fat(crate::fat::Reader<R>),
}

impl<R> FsReader<R> {
    /// Which family this reader is for.
    #[must_use]
    pub fn family(&self) -> crate::finding::Family {
        // One arm per compiled-in family; this module is compiled only where there is at
        // least one.
        match self {
            #[cfg(feature = "ext")]
            FsReader::Ext(_) => crate::finding::Family::Ext,
            #[cfg(feature = "fat")]
            FsReader::Fat(_) => crate::finding::Family::Fat,
        }
    }
}

/// A failure opening an image whose family is not known in advance.
///
/// Detection and opening are one step here, so the failures are detection's plus the one a
/// family's own reader adds: it recognized the image and then refused it.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// No family this build compiles in recognized the image, or the source could not be
    /// read at all.
    #[error(transparent)]
    Detect(#[from] crate::detect::DetectError),
    /// A family recognized the image and its reader then refused it — under
    /// [`ReadPolicy::Strict`](crate::ReadPolicy::Strict), anything the family's writer would not
    /// have emitted.
    ///
    /// The `family` is what claimed the image, and `message` is that family's own reader
    /// rendered as text. The typed error is the family reader's to return, and a caller
    /// that needs it opens that reader directly.
    #[error("{family} image refused: {message}", family = .family.as_str())]
    #[non_exhaustive]
    Refused {
        /// The family that claimed the image.
        family: crate::finding::Family,
        /// The family reader's own error, rendered as text.
        message: String,
    },
}

/// Open the filesystem at the start of an image, whatever family it is.
///
/// Sugar for [`open_with`] under the default [`OpenOptions`]. For a filesystem that begins
/// somewhere other than the start of the source — a partition, or a region a carver located
/// — name where with [`OpenOptions::base`].
///
/// # Errors
///
/// [`OpenError::Detect`] when the source cannot be read or no compiled-in family recognizes
/// it, and [`OpenError::Refused`] when a family recognized the image and then refused to
/// read it.
pub fn open<R: Read + Seek>(src: R) -> Result<FsReader<R>, OpenError> {
    open_with(src, &OpenOptions::new())
}

/// Open the filesystem an image holds under `options`, whatever family it is.
///
/// The image is classified the way [`detect_with`](crate::detect_with) classifies it, and
/// the family that claimed it opens its own reader over the same source at the same offset.
///
/// [`OpenOptions`] carries the three inputs every family takes and no more, so a family's
/// own knob is at its default here — a FAT volume's short names are read as the bytes they
/// are, interpreting no code page. A caller who needs one opens `fat::Reader` directly.
///
/// # Errors
///
/// [`OpenError::Detect`] when the source cannot be read or no compiled-in family recognizes
/// it, and [`OpenError::Refused`] when a family recognized the image and then refused to
/// read it.
pub fn open_with<R: Read + Seek>(
    mut src: R,
    options: &OpenOptions,
) -> Result<FsReader<R>, OpenError> {
    let detect = crate::DetectOptions::new().base(options.base);
    // Classified through the same handle the reader will use, so the answer and the read
    // are about one source rather than two that might differ.
    match crate::detect_with(&mut src, &detect)? {
        #[cfg(feature = "ext")]
        crate::Filesystem::Ext(_) => {
            let ext = crate::read::OpenOptions::new()
                .base(options.base)
                .policy(options.policy)
                .limits(options.limits);
            crate::read::Reader::open_with(src, &ext)
                .map(FsReader::Ext)
                .map_err(|e| OpenError::Refused {
                    family: crate::finding::Family::Ext,
                    message: e.to_string(),
                })
        }
        #[cfg(feature = "fat")]
        crate::Filesystem::Fat(_) => {
            let fat = crate::fat::OpenOptions::new()
                .base(options.base)
                .policy(options.policy)
                .limits(options.limits);
            crate::fat::Reader::open_with(src, &fat)
                .map(FsReader::Fat)
                .map_err(|e| OpenError::Refused {
                    family: crate::finding::Family::Fat,
                    message: e.to_string(),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;
    use crate::tree::{FsTree, TreeError};
    use std::io::Cursor;

    /// The instant every fixture stamps with, so nothing here depends on a clock.
    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    /// One image per compiled-in family, as `(what it is, the bytes)`.
    ///
    /// The whole surface these cases exercise is family-agnostic, so the fixtures are the
    /// one place a family is named — and each is built only where its family is compiled
    /// in.
    fn images() -> Vec<(crate::finding::Family, Vec<u8>)> {
        let mut out = Vec::new();
        #[cfg(feature = "ext")]
        {
            use crate::ext::{FormatOptions, format};
            use crate::source::TreeBuilder;
            let options = FormatOptions::new([0x5a; 16], TIME, [0xa5; 16]);
            let image = format(TreeBuilder::new(), 8 << 20, options).expect("format an ext image");
            out.push((crate::finding::Family::Ext, image.into_bytes()));
        }
        #[cfg(feature = "fat")]
        {
            use crate::fat::{FormatOptions, format};
            use crate::source::TreeBuilder;
            let options = FormatOptions::new(0x1234_abcd, TIME);
            let image = format(TreeBuilder::new(), 8 << 20, options).expect("format a FAT image");
            out.push((crate::finding::Family::Fat, image.into_bytes()));
        }
        assert!(
            !out.is_empty(),
            "this module is compiled only where a family is",
        );
        out
    }

    /// Every path a reader walks to, in the order it yields them. Written once, generically,
    /// so the assertion below names no family — which is the property under test.
    fn paths<T: FsTree>(tree: &mut T) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        tree.walk_tree::<TreeError, _>(|_, entry| {
            names.push(entry.path.to_vec());
            Ok(())
        })
        .expect("walk");
        names
    }

    #[test]
    fn every_compiled_in_family_is_reachable_without_being_named() {
        // The seam's whole claim, and the one a build carrying a single non-default family
        // most needs: `open` reaches that family's reader, the reader says which family it
        // is, and `FsTree` walks it.
        for (family, bytes) in images() {
            let reader = open(Cursor::new(&bytes))
                .unwrap_or_else(|e| panic!("{}: open: {e}", family.as_str()));
            assert_eq!(reader.family(), family);
            // One arm per compiled-in family and no wildcard, so a family added without an
            // arm here is a compile error rather than a case this quietly skips.
            let names = match reader {
                #[cfg(feature = "ext")]
                FsReader::Ext(mut r) => paths(&mut r),
                #[cfg(feature = "fat")]
                FsReader::Fat(mut r) => paths(&mut r),
            };
            // What every family promises a walk, and all a caller that has not matched can
            // rely on: the root comes first under the empty path, and no name repeats.
            // What else a freshly formatted filesystem holds is the family's own business —
            // ext puts a `lost+found` in one and FAT has no such concept.
            assert_eq!(names.first(), Some(&Vec::new()), "{}", family.as_str());
            let mut distinct = names.clone();
            distinct.sort();
            distinct.dedup();
            assert_eq!(distinct.len(), names.len(), "{}", family.as_str());
        }
    }

    #[test]
    fn a_source_no_compiled_in_family_recognizes_is_reported_as_undetected() {
        // The negative half: `open`'s failure for an unrecognized image is detection's own,
        // not a family's refusal, so a caller can tell "nothing here" from "this family
        // read it and said no".
        match open(Cursor::new(vec![0u8; 1 << 20])) {
            Err(OpenError::Detect(_)) => {}
            Err(e) => panic!("expected a detection failure, got {e}"),
            Ok(_) => panic!("a megabyte of zeroes is not a filesystem"),
        }
    }
}
