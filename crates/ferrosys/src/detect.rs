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
    /// An exFAT filesystem.
    ///
    /// The variant carries nothing because the family has nothing to sub-classify: there is
    /// one revision of the format, a volume records it, and every volume in circulation
    /// records the same one. Where the other two families compute a label the image does not
    /// hold, this one has no label to compute.
    #[cfg(feature = "exfat")]
    ExFat,
    /// A btrfs filesystem.
    ///
    /// The variant carries nothing, because the family has nothing to sub-classify. Everything
    /// that varies between two btrfs filesystems — which features are on, how large a node is,
    /// how many subvolumes there are — is a property read out of the superblock rather than a
    /// label detection could compute from it.
    #[cfg(feature = "btrfs")]
    Btrfs,
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
    /// Carried as [`TreeError::Io`](crate::TreeError::Io) describes, which is where the rule
    /// this crate records an i/o failure by is written out: the kind beside the message, so a
    /// caller tells a truncated image from an environment failure without matching on text.
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

crate::io::io_error!(DetectError);

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

    // exFAT is in this tier on a magic that is not exclusively its own, which is the
    // exception the tier's rule has to name: `"EXFAT   "` sits at the offset a FAT boot
    // sector keeps eight bytes of arbitrary OEM text at, so the claim is the magic *and* the
    // 53 bytes the format requires to be zero — bytes a FAT parameter block uses and cannot
    // leave empty. Both, or the claim is not made and FAT gets its turn below.
    #[cfg(feature = "exfat")]
    match crate::exfat::claim(&mut src, options) {
        Ok(Some(fs)) => return Ok(fs),
        Ok(None) => {}
        Err(e) => return Err(e),
    }

    // btrfs is in this tier unambiguously: `_BHRfS_M` is eight bytes 64 kibibytes into the
    // filesystem, at an offset no other format here puts anything at, and the superblock
    // carrying it also carries a checksum over itself — so the claim is the format's own
    // answer rather than a signature that might be a coincidence.
    #[cfg(feature = "btrfs")]
    match crate::btrfs::claim(&mut src, options) {
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
    ///
    /// The condition is every family, not the default one: a build carrying a single
    /// non-default family does recognize images, so running this there would assert
    /// something the build does not promise and pass only because the fixtures happen not to
    /// be that family's.
    #[cfg(not(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs")))]
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

/// What detection promises whichever family answers it.
///
/// Every case here is written in the vocabulary of the classifier rather than of a format,
/// and each runs against one image per compiled-in family — so the fixtures are the one place
/// a family is named, and a claim is made once rather than once per family. Written the other
/// way it drifts: two copies of "detection answers at the offset it is given" is two places to
/// fix a rule that changed, and the second copy stops being read the day it is written.
#[cfg(all(
    test,
    any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs")
))]
mod every_family {
    use super::{DetectError, DetectOptions, Filesystem, detect, detect_with};
    use std::io::Cursor;

    /// One image per compiled-in family, as `(what detection must answer, the bytes)`.
    ///
    /// Each is built only where its family is compiled in, which is what lets the cases below
    /// run unchanged in a build carrying one family, two, or all of them.
    fn images() -> Vec<(Filesystem, Vec<u8>)> {
        let mut out = Vec::new();
        #[cfg(feature = "ext")]
        out.push((
            Filesystem::Ext(crate::feature::Profile::Ext4),
            super::tests::image(),
        ));
        #[cfg(feature = "fat")]
        {
            use crate::fat::{FormatOptions, format};
            // An instant inside the range the format's date fields hold: this family refuses
            // one outside it wherever the value is read, so a fixture cannot use the epoch.
            let options = FormatOptions::new(
                0x1234_abcd,
                crate::time::Timestamp::from_secs(1_426_325_212),
            );
            let image = format(crate::source::TreeBuilder::new(), 8 << 20, options)
                .expect("format a FAT volume");
            out.push((Filesystem::Fat(image.layout().fat_type), image.into_bytes()));
        }
        #[cfg(feature = "exfat")]
        out.push((
            Filesystem::ExFat,
            super::exfat_tests::image(&crate::exfat::PlanRequest::new(8 << 20)),
        ));
        #[cfg(feature = "btrfs")]
        {
            // The one family with no formatter to build a fixture with, so the fixture is a
            // filesystem assembled byte by byte. It carries the magic, and the superblock
            // carrying it carries a checksum over itself — which is what the claim checks.
            use std::io::Read;
            let mut src = crate::btrfs::forge::Forge::new().source();
            let mut bytes = Vec::new();
            src.read_to_end(&mut bytes).expect("the forged device");
            out.push((Filesystem::Btrfs, bytes));
        }
        assert!(
            !out.is_empty(),
            "this module is compiled only where a family is"
        );
        out
    }

    #[test]
    fn each_compiled_in_family_is_detected_as_itself() {
        // Which family, and which of that family's formats: an image is classified by what
        // is in it, so the label is part of the answer rather than a second question.
        for (want, bytes) in images() {
            assert_eq!(detect(Cursor::new(bytes)).expect("detect"), want);
        }
    }

    #[test]
    fn detection_answers_at_the_offset_it_is_given() {
        // "What is at this location" is the question a carving pipeline asks, and a
        // classifier pinned to the start of its source cannot be asked it. The same bytes
        // are unrecognized at zero and a filesystem a mebibyte in.
        const BASE: u64 = 1 << 20;
        for (want, bytes) in images() {
            let mut disk = vec![0u8; BASE as usize];
            disk.extend_from_slice(&bytes);

            assert!(
                matches!(detect(Cursor::new(&disk)), Err(DetectError::Unrecognized)),
                "{want:?} was claimed at an offset it does not begin at"
            );
            assert_eq!(
                detect_with(Cursor::new(&disk), &DetectOptions::new().base(BASE)).expect("detect"),
                want
            );
        }
    }

    #[test]
    fn a_source_that_is_not_a_filesystem_is_claimed_by_nobody() {
        // The negative every family owes. A false positive is the one detection failure that
        // silently misidentifies something, so what is asserted is that *no* compiled-in
        // family claimed the source, rather than that some particular one did not.
        for junk in [
            vec![0u8; 64 << 10],
            (0..64u32 << 10).map(|i| (i % 251) as u8).collect(),
        ] {
            assert!(matches!(
                detect(Cursor::new(junk)),
                Err(DetectError::Unrecognized)
            ));
        }
    }
}

/// What only the exFAT family can be asked, in a build carrying it.
///
/// What every family is asked is in [`every_family`] above, once. Here are the cases that
/// name this format: the geometries its own planner reaches, and the collision its magic
/// shares an offset with.
#[cfg(all(test, feature = "exfat"))]
mod exfat_tests {
    use super::{Filesystem, detect};
    use crate::exfat::ondisk::{FILE_SYSTEM_NAME, FILE_SYSTEM_REVISION, MainBootSector};
    use crate::exfat::{PlanRequest, plan_layout};
    use std::io::Cursor;

    /// A volume's worth of bytes with a planned boot sector at the front.
    ///
    /// Detection reads sector 0 and nothing else, so the rest is zeroes — but it is as long
    /// as the boot sector says the volume is, because a recorded length the source cannot
    /// hold is exactly what the classifier refuses.
    pub(super) fn image(request: &PlanRequest) -> Vec<u8> {
        let layout = plan_layout(request).expect("plan");
        let boot = MainBootSector {
            jump_boot: MainBootSector::JUMP_BOOT,
            file_system_name: FILE_SYSTEM_NAME,
            partition_offset: 0,
            volume_length: layout.volume_length,
            fat_offset: layout.fat_offset,
            fat_length: layout.fat_length,
            cluster_heap_offset: layout.cluster_heap_offset,
            cluster_count: layout.cluster_count,
            first_cluster_of_root: layout.first_cluster_of_root,
            volume_serial: 0x1234_5678,
            file_system_revision: FILE_SYSTEM_REVISION,
            volume_flags: 0,
            bytes_per_sector_shift: layout.bytes_per_sector_shift(),
            sectors_per_cluster_shift: layout.sectors_per_cluster_shift(),
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 0,
            boot_code: [0; 390],
        };
        let mut bytes =
            vec![0u8; usize::try_from(layout.total_bytes()).expect("a test-sized volume")];
        boot.write_to(&mut bytes).expect("write");
        bytes
    }

    #[test]
    fn a_volume_this_crate_plans_is_detected_as_this_family() {
        for request in [
            PlanRequest::new(8 << 20),
            PlanRequest::new(8 << 20).bytes_per_sector(4096),
            PlanRequest::new(8 << 20).cluster_size(crate::exfat::ClusterSize::Bytes(512)),
        ] {
            assert_eq!(
                detect(Cursor::new(image(&request))).expect("detect"),
                Filesystem::ExFat,
                "{request:?}"
            );
        }
    }

    /// The collision the ordering rule has to name, asserted where both families are
    /// present — which is the only build that can tell the two answers apart.
    #[test]
    #[cfg(feature = "fat")]
    fn a_fat_volume_whose_oem_name_spells_this_magic_is_still_detected_as_fat() {
        // `BS_OEMName` is eight bytes of arbitrary text at the offset this family's magic
        // sits at, and no FAT driver reads it — so a FAT volume can spell `EXFAT   ` and
        // still be a FAT volume. exFAT is tried first, so a claim on the magic alone would
        // mean FAT is never tried: a healthy filesystem silently misidentified, which is the
        // one detection failure the ordering exists to prevent.
        use crate::fat::{FormatOptions, format};
        use crate::source::TreeBuilder;

        let mut options = FormatOptions::new(
            0x1234_abcd,
            crate::time::Timestamp::from_secs(1_426_325_212),
        );
        options.oem_name = *b"EXFAT   ";
        let mut bytes = format(TreeBuilder::new(), 8 << 20, options)
            .expect("format a FAT volume")
            .into_bytes();
        assert_eq!(
            &bytes[3..11],
            b"EXFAT   ",
            "the fixture must carry the collision"
        );

        assert!(
            matches!(detect(Cursor::new(&bytes)), Ok(Filesystem::Fat(_))),
            "a FAT volume spelling this family's magic was claimed by this family"
        );

        // And the other direction: with the 53-byte run zeroed as well, the volume is no
        // longer a FAT one — its parameter block is gone — and this family may have it.
        bytes[11..64].fill(0);
        assert_eq!(detect(Cursor::new(&bytes)).ok(), None);
    }
}

/// What only the ext family can be asked, in a build carrying it.
///
/// What every family is asked is in [`every_family`] above, once.
#[cfg(all(test, feature = "ext"))]
mod tests {
    use std::io::Cursor;

    use super::{DetectError, Filesystem, detect};
    use crate::feature::Profile;
    use crate::materialize::{FormatOptions, format};
    use crate::source::TreeBuilder;
    use crate::time::Timestamp;

    /// A formatted image's bytes at the default profile.
    pub(super) fn image() -> Vec<u8> {
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
    fn a_quirk_a_strict_read_refuses_is_still_a_filesystem() {
        // An `incompat` bit this reader does not interpret makes a strict open refuse the
        // image — correctly, since it cannot be sure it reads the format right. It is still
        // an ext filesystem, and a classifier that answered "unrecognized" would be wrong
        // about the only thing it was asked.
        let mut bytes = image();
        // s_feature_incompat is at offset 0x60 of the superblock, which begins at 1024.
        let off = 1024 + 0x60;
        // A bit no ext feature defines, so no reader can claim to interpret it.
        let incompat = crate::bytes::get_u32(&bytes, off) | 0x8000_0000;
        crate::bytes::put_u32(&mut bytes, off, incompat);

        assert!(
            crate::read::Reader::open(Cursor::new(&bytes)).is_err(),
            "a strict read must refuse an incompat feature it does not interpret"
        );
        assert_eq!(
            detect(Cursor::new(&bytes)).expect("detection is not strictness"),
            Filesystem::Ext(Profile::Ext4)
        );
    }

    #[test]
    fn an_io_failure_records_its_kind_beside_its_message() {
        // The rule every error in this crate carrying an i/o failure is written by: the kind
        // is kept as a value, so a caller tells a truncated image from an environment failure
        // without matching on text. Reached here through `?`, which is what having the
        // conversion as a trait rather than a private constructor is for.
        let fault = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no");
        let err = DetectError::from(fault);
        let DetectError::Io { kind, message } = &err else {
            panic!("expected an i/o failure, got {err:?}");
        };
        assert_eq!(*kind, std::io::ErrorKind::PermissionDenied);
        assert!(message.contains("no"), "the message is carried: {message}");
    }
}
