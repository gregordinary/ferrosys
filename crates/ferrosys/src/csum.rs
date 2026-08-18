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

// -- the per-object recipes -------------------------------------------------------------
//
// The seam above standardizes the primitive and the on/off decision. What each object folds
// into it before its own bytes — the seed, the identity words, which field participates as
// zero — is the format, and it is stated here once rather than once per direction. A writer
// stamping an object and a reader verifying one call the same function, so a recipe cannot be
// corrected on one side alone.
//
// Two recipes are deliberately not here, and each says why at its site: the superblock's,
// which is seeded from `!0` rather than through this seam and so lives with the record's
// layout in `ondisk::superblock`; and a hash-tree index block's, where the writer folds a
// tail it wrote and the reader folds the tail it found, which is a real difference and not a
// transcription.

/// The seed every metadata object belonging to one inode continues from: the filesystem seed
/// folded with the inode's number and its generation.
///
/// An extent node's tail, a directory block's tail, and an orphan block's all chain from
/// this, which is what makes a block moved between two inodes fail its checksum rather than
/// verify under its new owner.
pub(crate) fn inode_seed(csum: &dyn Checksummer, ino: u32, generation: u32) -> u32 {
    let c = csum.crc32c(csum.base_seed(), &ino.to_le_bytes());
    csum.crc32c(c, &generation.to_le_bytes())
}

/// The 16-bit crc32c a group descriptor carries in `bg_checksum`: the filesystem seed folded
/// with the group number, then the descriptor's own bytes.
///
/// `bytes` is the descriptor as it sits on disk *with `bg_checksum` zeroed* — the field
/// participates in its own checksum as two zero bytes, and every other byte participates as
/// it is, including any this crate does not model.
pub(crate) fn group_descriptor(csum: &dyn Checksummer, group: u32, bytes: &[u8]) -> u16 {
    let c = csum.crc32c(csum.base_seed(), &group.to_le_bytes());
    (csum.crc32c(c, bytes) & 0xffff) as u16
}

/// The crc32c an inode carries: the filesystem seed folded with the inode's number and
/// generation, then the inode's own bytes with its checksum fields zeroed.
///
/// `has_hi` is whether the inode is large enough for `i_checksum_hi`. Without it the result
/// is sixteen bits wide — the kernel's `calculated &= 0xFFFF` — because there is no high half
/// stored to compare a full-width value against. `mke2fs` leaves the reserved inodes in
/// exactly that state, so on any filesystem it formatted, checking them at full width rejects
/// seven healthy inodes.
pub(crate) fn inode(
    csum: &dyn Checksummer,
    number: u32,
    generation: u32,
    bytes: &[u8],
    has_hi: bool,
) -> u32 {
    let c = csum.crc32c(inode_seed(csum, number, generation), bytes);
    if has_hi { c } else { c & 0xffff }
}

/// The crc32c a block or inode bitmap carries: the filesystem seed folded with the bytes the
/// kernel counts as covered.
///
/// How many bytes those are is [`block_bitmap_len`] and [`inode_bitmap_len`]; the two differ,
/// and getting either wrong produces a checksum no checker accepts.
pub(crate) fn bitmap(csum: &dyn Checksummer, covered: &[u8]) -> u32 {
    csum.crc32c(csum.base_seed(), covered)
}

/// The bytes of a block bitmap its checksum covers, as `ext4_block_bitmap_csum_set` measures
/// them: one bit per block, exactly, because a group's block count is always a multiple of
/// eight.
pub(crate) const fn block_bitmap_len(blocks_per_group: u32) -> usize {
    (blocks_per_group / 8) as usize
}

/// The bytes of an inode bitmap its checksum covers, as `ext4_inode_bitmap_csum_set` measures
/// them: one bit per inode, **rounded up**, so a count that is not a multiple of eight still
/// has its final partial byte covered.
///
/// The planner and `mke2fs` both round the inode count down to a multiple of eight, so this
/// and the exact form agree on every image either writes. The kernel's is used so that they
/// also agree on one that does not.
pub(crate) const fn inode_bitmap_len(inodes_per_group: u32) -> usize {
    inodes_per_group.div_ceil(8) as usize
}

/// The crc32c an orphan-file block's tail carries: the file's identity, then the block's own
/// number, then its entry array.
///
/// The block number is in the chain because the file is an array of identical zeroed entry
/// blocks — without it every block of a fresh orphan file would carry the same checksum, and
/// one copied over another would verify.
pub(crate) fn orphan_block(
    csum: &dyn Checksummer,
    ino: u32,
    generation: u32,
    block: u64,
    entries: &[u8],
) -> u32 {
    let c = csum.crc32c(inode_seed(csum, ino, generation), &block.to_le_bytes());
    csum.crc32c(c, entries)
}

/// The crc32c an external attribute block carries in `h_checksum`: the filesystem seed folded
/// with the block number as a little-endian 64-bit value, then the whole block.
///
/// `bytes` is the block as it sits on disk *with `h_checksum` zeroed*. The block number rather
/// than the owning inode is what identifies it, because one attribute block may be shared by
/// several inodes.
pub(crate) fn xattr_block(csum: &dyn Checksummer, block: u64, bytes: &[u8]) -> u32 {
    let c = csum.crc32c(csum.base_seed(), &block.to_le_bytes());
    csum.crc32c(c, bytes)
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

    #[test]
    fn a_recipe_binds_an_object_to_the_identity_it_was_written_under() {
        // The property every chain above exists for, checked on the two that carry the most
        // identity: the same bytes under a different owner, generation, group, or block are a
        // different checksum. Without it a metadata block moved or copied inside an image
        // would verify in its new place.
        let c = Crc32c::new(&[0u8; 16]);
        let bytes = b"the object's own bytes";

        assert_ne!(inode_seed(&c, 12, 7), inode_seed(&c, 13, 7));
        assert_ne!(inode_seed(&c, 12, 7), inode_seed(&c, 12, 8));
        assert_ne!(
            orphan_block(&c, 12, 7, 100, bytes),
            orphan_block(&c, 12, 7, 101, bytes)
        );
        assert_ne!(
            group_descriptor(&c, 0, bytes),
            group_descriptor(&c, 1, bytes)
        );
        assert_ne!(xattr_block(&c, 100, bytes), xattr_block(&c, 101, bytes));

        // An inode without the high half of its checksum field answers sixteen bits wide,
        // because there is no high half stored to compare a wider value against.
        assert_eq!(inode(&c, 12, 7, bytes, false) >> 16, 0);
        assert_eq!(
            inode(&c, 12, 7, bytes, false),
            inode(&c, 12, 7, bytes, true) & 0xffff
        );

        // With checksums off every recipe answers zero, because the primitive does.
        let off = NullCsum;
        assert_eq!(inode(&off, 12, 7, bytes, true), 0);
        assert_eq!(group_descriptor(&off, 0, bytes), 0);
        assert_eq!(orphan_block(&off, 12, 7, 100, bytes), 0);
    }

    #[test]
    fn a_bitmap_is_covered_the_way_the_kernel_measures_it() {
        // The block bitmap divides exactly; the inode bitmap rounds up, so a count that is
        // not a multiple of eight still has its final partial byte covered.
        assert_eq!(block_bitmap_len(32_768), 4096);
        assert_eq!(inode_bitmap_len(8192), 1024);
        assert_eq!(inode_bitmap_len(8185), 1024);
        assert_eq!(inode_bitmap_len(8193), 1025);
    }
}
