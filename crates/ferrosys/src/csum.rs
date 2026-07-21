//! The metadata-checksum seam.
//!
//! ext4's `metadata_csum` feature protects every metadata object — the
//! superblock, group descriptors, inodes, bitmaps, extent-tree blocks, and
//! directory blocks — with a crc32c whose field lives inside the object. The
//! checksum algorithm sits behind the [`Checksummer`] trait, so the code that lays
//! objects out is independent of whether checksums are on.
//!
//! This module is pure and side-effect free. When the feature is on, [`Crc32c`] is
//! the active implementation: it reports checksums enabled and computes a real
//! crc32c seeded from the filesystem UUID. When it is off, [`NullCsum`] reports
//! checksums disabled and computes zero. Every checksum field is written through
//! this seam, so choosing between them is a change of implementation at one
//! construction site — the materializer picks the one the feature set calls for.

/// Computes the checksums ext4 stores inside its metadata objects.
///
/// The one primitive is a seeded crc32c ([`crc32c`](Checksummer::crc32c)); each
/// metadata object seeds it from the filesystem seed and its own identity (inode
/// number, group number, block number) and feeds it the object's bytes. An
/// implementation that reports [`enabled`](Checksummer::enabled) as `false` leaves
/// every checksum field — and the uninit block-group descriptor flags that
/// `metadata_csum` co-governs — unwritten; a caller must consult `enabled` before
/// setting them.
pub trait Checksummer {
    /// Whether `metadata_csum` is active.
    ///
    /// Drives two things a caller must gate on: whether the in-object checksum
    /// fields are populated, and whether the `INODE_UNINIT` / `BLOCK_UNINIT` /
    /// `ITABLE_ZEROED` descriptor flags and `bg_itable_unused` counts carry their
    /// checksummed meaning.
    fn enabled(&self) -> bool;

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

/// The disabled checksummer: reports checksums off and computes zero.
///
/// This is the active implementation while `metadata_csum` is off. It writes no
/// checksum bytes and requests none of the uninit-bg descriptor semantics, so an
/// image built with it carries zeroed checksum fields — exactly what an external
/// checker expects when the feature bit is clear.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullCsum;

impl Checksummer for NullCsum {
    fn enabled(&self) -> bool {
        false
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

impl Checksummer for Crc32c {
    fn enabled(&self) -> bool {
        true
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
    fn null_csum_is_disabled_and_zero() {
        let c = NullCsum;
        assert!(!c.enabled());
        assert_eq!(c.base_seed(), 0);
        assert_eq!(c.crc32c(0, b"anything"), 0);
        assert_eq!(c.crc32c(0xdead_beef, &[1, 2, 3, 4]), 0);
    }

    #[test]
    fn null_csum_is_usable_as_a_trait_object() {
        // The seam is consumed dynamically by the materializer; make sure it is
        // object-safe so the construction site can hold `&dyn Checksummer`.
        let c: &dyn Checksummer = &NullCsum;
        assert!(!c.enabled());
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
        assert!(c.enabled());
        assert_eq!(c.base_seed(), 0x33D2_8425);
        // The primitive is the raw continuation, so an empty feed returns the seed.
        assert_eq!(c.crc32c(c.base_seed(), b""), 0x33D2_8425);
    }

    #[test]
    fn crc32c_is_usable_as_a_trait_object() {
        let uuid = [0u8; 16];
        let c: &dyn Checksummer = &Crc32c::new(&uuid);
        assert!(c.enabled());
    }
}
