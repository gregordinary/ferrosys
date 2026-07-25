//! The metadata-checksum seam.
//!
//! ext4's `metadata_csum` feature protects every metadata object — the
//! superblock, group descriptors, inodes, bitmaps, extent-tree blocks, and
//! directory blocks — with a crc32c whose field lives inside the object. The
//! checksum algorithm sits behind the [`Checksummer`] trait, so the code that lays
//! objects out is independent of whether checksums are on.
//!
//! This module is pure and side-effect free. When the feature is on, [`Crc32c`] is
//! the active implementation: it reports [`CsumScheme::Crc32c`] and computes a real
//! crc32c seeded from the filesystem UUID. When it is off, [`NullCsum`] reports
//! [`CsumScheme::None`] and computes zero. Every checksum field is written through
//! this seam, so choosing between them is a change of implementation at one
//! construction site — the materializer picks the one the feature set calls for.

/// Which checksums a filesystem's metadata carries.
///
/// ext defines more than the two states "checksummed" and "not". `metadata_csum`
/// ([`Crc32c`](CsumScheme::Crc32c)) protects every metadata object with a crc32c; the
/// older `uninit_bg` (`GDT_CSUM`) protects the group descriptors alone with a crc16,
/// while carrying the same uninitialized-bitmap accounting; and a filesystem may have
/// neither. The two questions a caller asks — *is there a checksum field to fill in* and
/// *do the uninit descriptor flags mean anything* — have the same answer under the first
/// and the last scheme and different answers under the middle one, so they are asked
/// separately rather than through one flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum CsumScheme {
    /// No metadata checksums. Every checksum field is zero and the uninitialized-bitmap
    /// accounting does not apply.
    #[default]
    None,
    /// `metadata_csum`: a crc32c inside every metadata object, and the
    /// uninitialized-bitmap accounting.
    Crc32c,
}

impl CsumScheme {
    /// Whether metadata objects carry an in-object checksum field this crate fills in.
    ///
    /// Gates the per-object checksum writes: the superblock, inodes, extent nodes,
    /// directory blocks, bitmaps, and attribute blocks.
    #[must_use]
    pub const fn writes_object_checksums(self) -> bool {
        match self {
            Self::None => false,
            Self::Crc32c => true,
        }
    }

    /// Whether the `INODE_UNINIT` / `BLOCK_UNINIT` / `ITABLE_ZEROED` descriptor flags and
    /// the `bg_itable_unused` counts carry their meaning.
    ///
    /// A scheme without them writes `bg_flags` zero, because a flag no feature backs is
    /// one a checker faults.
    #[must_use]
    pub const fn uninit_bg_semantics(self) -> bool {
        match self {
            Self::None => false,
            Self::Crc32c => true,
        }
    }
}

/// Computes the checksums ext4 stores inside its metadata objects.
///
/// The one primitive is a seeded crc32c ([`crc32c`](Checksummer::crc32c)); each
/// metadata object seeds it from the filesystem seed and its own identity (inode
/// number, group number, block number) and feeds it the object's bytes. The
/// [`scheme`](Checksummer::scheme) an implementation reports says which checksums the
/// filesystem carries, and a caller gates every checksum field and every uninit
/// descriptor flag on it.
///
/// The trait is sealed: [`Crc32c`] and [`NullCsum`] are its implementations and no other
/// is possible. It is a seam so that laying objects out is independent of whether
/// checksums are on, not an extension point — a substitute that compiled but computed
/// the wrong value would produce an image this crate claims is checksummed and no
/// checker accepts.
pub trait Checksummer: crate::sealed::Sealed {
    /// Which checksums this filesystem carries.
    fn scheme(&self) -> CsumScheme;

    /// The base filesystem checksum seed — crc32c of the filesystem UUID — from
    /// which per-object seeds are derived. Zero when checksums are disabled.
    fn base_seed(&self) -> u32;

    /// crc32c of `data` continued from `seed`.
    ///
    /// Seeding lets a caller chain the filesystem seed and an object's identity
    /// before the object bytes, matching ext4's per-object checksum construction.
    /// Returns zero when checksums are disabled.
    fn crc32c(&self, seed: u32, data: &[u8]) -> u32;
}

/// The disabled checksummer: reports [`CsumScheme::None`] and computes zero.
///
/// This is the active implementation while `metadata_csum` is off. It writes no
/// checksum bytes and requests none of the uninit-bg descriptor semantics, so an
/// image built with it carries zeroed checksum fields — exactly what an external
/// checker expects when the feature bit is clear.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullCsum;

impl crate::sealed::Sealed for NullCsum {}

impl Checksummer for NullCsum {
    fn scheme(&self) -> CsumScheme {
        CsumScheme::None
    }

    fn base_seed(&self) -> u32 {
        0
    }

    fn crc32c(&self, _seed: u32, _data: &[u8]) -> u32 {
        0
    }
}

/// The active checksummer when `metadata_csum` is on: a real crc32c seeded from the
/// filesystem UUID.
///
/// The base seed is `crc32c(!0, uuid)`, the value ext4 derives when the separate
/// `metadata_csum_seed` feature is absent, and every per-object checksum a caller builds
/// continues from it. `crc32c` is the raw continuation primitive, so a caller folds
/// the object's identity (inode number, group number, block number) and then its
/// bytes on top of a seed of its choice — the base seed for most objects, or `!0`
/// for the superblock, whose checksum ext4 seeds from `!0` rather than the UUID.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c {
    base_seed: u32,
}

impl Crc32c {
    /// Build the checksummer for a filesystem with UUID `uuid`.
    #[must_use]
    pub fn new(uuid: &[u8; 16]) -> Self {
        Self {
            base_seed: crate::crc32c::crc32c(!0, uuid),
        }
    }

    /// Build the checksummer for a filesystem that stores its seed (`metadata_csum_seed`) rather
    /// than deriving it from the UUID. The stored seed is what its checksums were
    /// computed from, which the UUID need not agree with.
    #[must_use]
    pub fn with_seed(base_seed: u32) -> Self {
        Self { base_seed }
    }
}

impl crate::sealed::Sealed for Crc32c {}

impl Checksummer for Crc32c {
    fn scheme(&self) -> CsumScheme {
        CsumScheme::Crc32c
    }

    fn base_seed(&self) -> u32 {
        self.base_seed
    }

    fn crc32c(&self, seed: u32, data: &[u8]) -> u32 {
        crate::crc32c::crc32c(seed, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scheme_answers_the_two_questions_separately() {
        // The two questions agree under both schemes this crate writes; they are asked
        // separately because a third scheme — the crc16 `uninit_bg` group-descriptor
        // checksum, which a foreign image may carry — answers them differently, and a
        // single flag would have no way to say so.
        assert!(!CsumScheme::None.writes_object_checksums());
        assert!(!CsumScheme::None.uninit_bg_semantics());
        assert!(CsumScheme::Crc32c.writes_object_checksums());
        assert!(CsumScheme::Crc32c.uninit_bg_semantics());
        // A filesystem with no checksums is the default: a scheme is something a feature
        // set turns on.
        assert_eq!(CsumScheme::default(), CsumScheme::None);
    }

    #[test]
    fn null_csum_is_disabled_and_zero() {
        let c = NullCsum;
        assert_eq!(c.scheme(), CsumScheme::None);
        assert_eq!(c.base_seed(), 0);
        assert_eq!(c.crc32c(0, b"anything"), 0);
        assert_eq!(c.crc32c(0xdead_beef, &[1, 2, 3, 4]), 0);
    }

    #[test]
    fn null_csum_is_usable_as_a_trait_object() {
        // The seam is consumed dynamically by the materializer; make sure it is
        // object-safe so the construction site can hold `&dyn Checksummer`.
        let c: &dyn Checksummer = &NullCsum;
        assert_eq!(c.scheme(), CsumScheme::None);
        assert_eq!(c.crc32c(1, b""), 0);
    }

    #[test]
    fn crc32c_seeds_from_the_uuid() {
        // The base seed is crc32c(!0, uuid). This UUID is the one the host-tool
        // baseline uses, and the seed matches what e2fsprogs derives for it.
        let uuid = [
            0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
        ];
        let c = Crc32c::new(&uuid);
        assert_eq!(c.scheme(), CsumScheme::Crc32c);
        assert_eq!(c.base_seed(), 0x33D2_8425);
        // The primitive is the raw continuation, so an empty feed returns the seed.
        assert_eq!(c.crc32c(c.base_seed(), b""), 0x33D2_8425);
    }

    #[test]
    fn crc32c_is_usable_as_a_trait_object() {
        let uuid = [0u8; 16];
        let c: &dyn Checksummer = &Crc32c::new(&uuid);
        assert_eq!(c.scheme(), CsumScheme::Crc32c);
    }
}
