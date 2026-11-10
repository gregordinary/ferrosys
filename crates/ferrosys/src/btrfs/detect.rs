//! Whether an image holds a btrfs, decided by the magic 64 kibibytes into it.
//!
//! btrfs is a tier-1 family, and the least ambiguous one here: `_BHRfS_M` is eight bytes of a
//! spelling nothing else uses, at a fixed offset inside the superblock, 65 536 bytes into the
//! filesystem. Nothing at that offset belongs to any other format in this crate — a FAT
//! parameter block and an exFAT boot region are both in the first sector, and an ext
//! superblock is at 1024 — so there is no collision to disambiguate and no second condition to
//! check.
//!
//! What the claim does check beyond the magic is that the superblock **parses and its checksum
//! covers it**. Detection is otherwise deliberately more forgiving than reading, and it stays
//! so: a feature bit this crate cannot read, a geometry it refuses, a filesystem spanning
//! devices — every one of those is still classified as btrfs, because it is, and the reader is
//! what says it cannot be read. A checksum is different in kind. It is the format's own answer
//! to "are these eight bytes a superblock or eight bytes that happen to spell one", and this
//! family is the only one here that carries one.
//!
//! This module is pure apart from reading the one superblock it classifies.

use std::io::{ErrorKind, Read, Seek};

use crate::detect::{DetectError, DetectOptions, Filesystem};
use crate::io::{offset_of, read_exact_at};

use super::ondisk::{MIRRORS, SUPER_INFO_SIZE, SuperBlock};

/// Whether the btrfs family claims the image.
///
/// `Ok(None)` is "not ours". An I/O failure is the source's rather than the image's and stops
/// detection rather than moving on, since every later probe would fail the same way — but a
/// source too short to reach the superblock is an answer about the image, so it is "not ours".
pub(crate) fn claim<R: Read + Seek>(
    mut src: R,
    options: &DetectOptions,
) -> Result<Option<Filesystem>, DetectError> {
    // The first location only. The other two exist so a filesystem survives damage to this
    // one, which is a repair question rather than a classification: an image whose primary
    // superblock is gone is one a caller opens the family's reader on, and that reader reads
    // every copy.
    let Some(at) = offset_of(options.base, MIRRORS[0], 1) else {
        return Ok(None);
    };
    let bytes = match read_exact_at(&mut src, at, SUPER_INFO_SIZE) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(classify(&bytes).then_some(Filesystem::Btrfs))
}

/// Whether these bytes are a btrfs superblock.
///
/// One function for the classifier, so that what detection claims and what the reader accepts
/// cannot drift apart in the direction that matters: an image claimed here and refused there is
/// a caller told "this is btrfs" and then handed nothing, which is worse than either answer
/// alone.
fn classify(bytes: &[u8]) -> bool {
    let Ok(superblock) = SuperBlock::read_from(bytes) else {
        return false;
    };
    // A superblock is held to its own checksum in whichever algorithm it names. A value the
    // format does not define names none, and a filesystem carrying one is still btrfs and is
    // still classified: the magic and a parse are what say so, and the reader is where the
    // value is named as the reason it cannot be read.
    if superblock.csum_type.digest_len().is_none() {
        return true;
    }
    superblock.csum_type.holds(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::forge::Forge;
    use crate::btrfs::ondisk;
    use std::io::Cursor;

    /// The bytes of the forged image's primary superblock.
    fn a_superblock() -> Vec<u8> {
        let forge = Forge::new();
        let mut src = forge.source();
        read_exact_at(&mut src, MIRRORS[0], SUPER_INFO_SIZE).expect("the forged superblock")
    }

    #[test]
    fn a_filesystem_this_crate_can_open_is_one_this_classifier_claims() {
        let forge = Forge::new();
        assert_eq!(
            claim(forge.source(), &DetectOptions::new()).expect("not a failure"),
            Some(Filesystem::Btrfs)
        );
        // And so is one inside a partition, since every location is relative to where the
        // caller says the filesystem begins.
        let mut disk = vec![0u8; 1 << 20];
        let mut src = forge.source();
        std::io::Read::read_to_end(&mut src, &mut disk).expect("the forged device");
        assert_eq!(
            claim(Cursor::new(disk), &DetectOptions::new().base(1 << 20)).expect("not a failure"),
            Some(Filesystem::Btrfs)
        );
    }

    #[test]
    fn eight_bytes_that_spell_the_magic_are_not_a_superblock() {
        // What the checksum is for here. The magic alone would classify any image that
        // happened to carry those eight bytes at that offset — a disk image holding a btrfs
        // *file*, for one — and this family is the only one with the format's own answer to
        // the question available at classification time.
        let mut bytes = vec![0u8; SUPER_INFO_SIZE];
        bytes[64..72].copy_from_slice(&ondisk::MAGIC);
        assert!(!classify(&bytes));
        // A real one, with one byte of it changed.
        let mut real = a_superblock();
        assert!(classify(&real));
        real[200] ^= 0xff;
        assert!(!classify(&real));
    }

    #[test]
    fn a_filesystem_beyond_this_reader_is_still_classified_as_what_it_is() {
        // Classification answers "what is this" and reading answers "can this be read", and
        // conflating them would report a healthy filesystem with an unfamiliar feature bit as
        // unrecognized — the one answer that is certainly wrong.
        let mut forge = Forge::new();
        forge.amend_superblock(0, |sb| {
            sb.incompat_flags = crate::btrfs::ondisk::IncompatFlags::from_bits(1 << 40);
            sb.num_devices = 4;
        });
        assert_eq!(
            claim(forge.source(), &DetectOptions::new()).expect("not a failure"),
            Some(Filesystem::Btrfs)
        );
        assert!(crate::btrfs::Volume::open(forge.source()).is_err());
    }

    #[test]
    fn a_checksum_the_format_does_not_define_is_not_held_against_the_image() {
        // A filesystem naming an algorithm the format has no digest for is still a btrfs.
        // Holding its field to some digest would answer "not ours" for it, where the reader
        // names the value as the reason it cannot be read.
        let mut bytes = a_superblock();
        let mut sb = SuperBlock::read_from(&bytes).expect("a superblock");
        sb.csum_type = ondisk::ChecksumType::from_value(0x7f);
        sb.write_to(&mut bytes);
        assert!(
            classify(&bytes),
            "the checksum no longer covers it, and it is still btrfs"
        );
    }

    #[test]
    fn a_superblock_is_held_to_whichever_algorithm_it_names() {
        // Sealed in each algorithm, a superblock classifies; naming another one than it was
        // sealed in, it does not, as a damaged crc32c one never has.
        for csum_type in [
            ondisk::ChecksumType::CRC32C,
            ondisk::ChecksumType::XXHASH64,
            ondisk::ChecksumType::SHA256,
            ondisk::ChecksumType::BLAKE2B,
        ] {
            let mut bytes = a_superblock();
            let mut sb = SuperBlock::read_from(&bytes).expect("a superblock");
            sb.csum_type = csum_type;
            sb.write_to(&mut bytes);
            let field = csum_type
                .field(&bytes[ondisk::CHECKSUM_COVERED_FROM..])
                .expect("a defined algorithm");
            bytes[..ondisk::CSUM_FIELD_LEN].copy_from_slice(&field);
            assert!(classify(&bytes), "{csum_type:?}");
            bytes[ondisk::CSUM_FIELD_LEN] ^= 1;
            assert!(
                !classify(&bytes),
                "{csum_type:?}, a byte past the field changed"
            );
        }
    }

    #[test]
    fn a_short_source_is_not_ours_rather_than_a_failure() {
        // The rule every probe in the ordered list follows. This family's superblock is 64
        // kibibytes in, so a great many sources are too short — including every FAT image
        // under that size, which must reach the probe behind this one.
        let options = DetectOptions::new();
        for len in [0usize, 512, 1 << 16] {
            assert_eq!(
                claim(Cursor::new(vec![0u8; len]), &options).expect("not a failure"),
                None,
                "a {len}-byte source"
            );
        }
        // And a base so far out that the location would wrap is the same answer.
        assert_eq!(
            claim(
                Cursor::new(vec![0u8; 1 << 20]),
                &DetectOptions::new().base(u64::MAX - 1)
            )
            .expect("not a failure"),
            None
        );
    }
}
