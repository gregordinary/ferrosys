//! The feature switchboard: a typed set of ext4 feature flags plus the derived
//! geometry knobs every other layer consults.
//!
//! This module is pure data. An ext4 superblock carries three independent feature
//! words — `compat`, `incompat`, and `ro_compat` — whose bits an implementation
//! must recognize before it may write, mount, or (for `ro_compat`) write to a
//! filesystem. [`FeatureSet`] models those three words as distinct typed sets so a
//! flag from one word cannot be confused for a flag of the same numeric value in
//! another, and pairs them with the block size and inode size that the same
//! planning step fixes.
//!
//! Enabling a feature is a data change here, not a control-flow change elsewhere:
//! the geometry planner, the on-disk serializers, and the checksum and directory
//! seams all branch on the values in a [`FeatureSet`] rather than on scattered
//! booleans.

use core::fmt;

/// The size at or past which a regular file requires the `large_file` feature: 2 GiB.
///
/// A file this large no longer fits the signed 31-bit size the original ext2 revision
/// stored, so the filesystem must advertise `large_file` for it. The kernel sets the
/// feature when it writes such a file, and `e2fsck` faults an image that carries one
/// without it. The bound is on regular files alone: a directory of any size, and every
/// other file type, leaves the feature unneeded.
pub const LARGE_FILE_MIN_SIZE: u64 = 0x8000_0000;

/// The size the resize inode declares on a filesystem of `block_size` bytes.
///
/// The resize inode maps the reserved group-descriptor blocks through a classic block
/// map, and its size field records the largest file that map's direct and double-indirect
/// reach addresses — twelve direct blocks, one single-indirect block's worth, and one
/// double-indirect block's worth — rather than the blocks it holds. That is the value
/// `mke2fs` writes, and it grows with the square of the block size: 64 MiB at a
/// 1024-byte block, 513 MiB at 2048, and 4 GiB at 4096.
pub(crate) const fn resize_inode_size(block_size: u32) -> u64 {
    let apb = block_size as u64 / 4; // block pointers one block holds
    block_size as u64 * (12 + apb + apb * apb)
}

/// Generates a typed feature-word newtype over a `u32` bitfield.
///
/// Each generated type wraps the little-endian on-disk feature word for one
/// superblock feature category. Flags are associated constants; set operations are
/// `BitOr`/`BitOrAssign`/[`without`](Self::without); [`contains`](Self::contains)
/// tests membership.
///
/// Each flag is declared with the on-disk name it is known by outside this crate —
/// `EXTENTS("extent")` — so one table carries both. The Rust symbol renders
/// [`Debug`](fmt::Debug), which keeps a diagnostic legible without a lookup table;
/// the on-disk name drives [`names`](Self::names) and
/// [`from_name`](Self::from_name), which is the vocabulary a user and every other
/// ext4 tool speak.
macro_rules! feature_word {
    (
        $(#[$ty_doc:meta])*
        $name:ident {
            $(
                $(#[$flag_doc:meta])*
                $flag:ident($on_disk:literal) = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$ty_doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
        // A feature word serializes as the raw on-disk word it wraps, which is what
        // `bits()` returns and what a superblock holds. The names are a projection of it
        // (`FeatureSet::names`), not a second encoding of the same fact.
        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
        pub struct $name(u32);

        impl $name {
            /// The empty set — no features present.
            pub const NONE: Self = Self(0);

            $(
                $(#[$flag_doc])*
                pub const $flag: Self = Self($value);
            )*

            /// The (Rust symbol, on-disk name, bit) table for every flag this type
            /// defines, in ascending bit order. It renders [`Debug`](fmt::Debug),
            /// resolves on-disk names, and detects bits outside the known set.
            const FLAGS: &'static [(&'static str, &'static str, u32)] = &[
                $((stringify!($flag), $on_disk, $value),)*
            ];

            /// The raw little-endian on-disk feature word.
            #[must_use]
            pub const fn bits(self) -> u32 {
                self.0
            }

            /// Wrap a raw on-disk feature word read from a superblock.
            #[must_use]
            pub const fn from_bits(bits: u32) -> Self {
                Self(bits)
            }

            /// True when every flag set in `other` is also set in `self`.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// True when no flags are set.
            #[must_use]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// `self` with every flag set in `other` cleared.
            #[must_use]
            pub const fn without(self, other: Self) -> Self {
                Self(self.0 & !other.0)
            }

            /// The bits set in `self` that this type does not name — features an
            /// implementation does not recognize. A non-empty result on an
            /// `incompat` word means the image cannot be safely handled.
            #[must_use]
            pub const fn unknown_bits(self) -> u32 {
                let mut known = 0u32;
                let mut i = 0;
                while i < Self::FLAGS.len() {
                    known |= Self::FLAGS[i].2;
                    i += 1;
                }
                self.0 & !known
            }

            /// The on-disk names of the flags set in `self`, in ascending bit order —
            /// the names every ext4 tool prints and accepts, and the ones
            /// [`FeatureSet::with_feature`] resolves.
            ///
            /// A bit this type does not name contributes no name;
            /// [`unknown_bits`](Self::unknown_bits) is what reports those, so a set
            /// carrying an unrecognized feature is never described as if it were
            /// understood.
            #[must_use]
            pub fn names(self) -> Vec<&'static str> {
                Self::FLAGS
                    .iter()
                    .filter(|(_, _, bit)| *bit != 0 && self.0 & bit == *bit)
                    .map(|(_, name, _)| *name)
                    .collect()
            }

            /// The single flag this word knows by the on-disk `name`, or `None` when the
            /// name is not one of its own. The match is exact and lowercase, as the name
            /// is written on disk and printed.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                Self::FLAGS
                    .iter()
                    .find(|(_, on_disk, _)| *on_disk == name)
                    .map(|(_, _, bit)| Self(*bit))
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                let mut first = true;
                for (name, _, bit) in Self::FLAGS {
                    if self.0 & bit == *bit && *bit != 0 {
                        if !first {
                            write!(f, " | ")?;
                        }
                        write!(f, "{name}")?;
                        first = false;
                    }
                }
                let unknown = self.unknown_bits();
                if unknown != 0 {
                    if !first {
                        write!(f, " | ")?;
                    }
                    write!(f, "{unknown:#x}")?;
                    first = false;
                }
                if first {
                    write!(f, "NONE")?;
                }
                write!(f, ")")
            }
        }
    };
}

feature_word! {
    /// The `compat` feature word (`s_feature_compat`, superblock offset `0x5C`).
    ///
    /// An implementation may read and write a filesystem carrying `compat` features
    /// it does not recognize; the flags advertise optional structures whose absence
    /// of support is harmless.
    Compat {
        /// `has_journal` (`0x0004`) — a jbd2 journal is present in the journal inode
        /// (inode 8), and `s_journal_inum` points at it.
        HAS_JOURNAL("has_journal") = 0x0004,
        /// `ext_attr` (`0x0008`) — extended attributes are present in inodes or in
        /// dedicated xattr blocks.
        EXT_ATTR("ext_attr") = 0x0008,
        /// `resize_inode` (`0x0010`) — reserved group-descriptor-table blocks are
        /// tracked through the resize inode (inode 7) so the filesystem can grow
        /// without relocating the descriptor table.
        RESIZE_INODE("resize_inode") = 0x0010,
        /// `dir_index` (`0x0020`) — directories may carry a hash index. A directory
        /// that does marks it with the `INDEX` inode flag; one that does not is an
        /// ordinary linear directory, so the flag permits an index rather than
        /// promising one.
        DIR_INDEX("dir_index") = 0x0020,
        /// `orphan_file` (`0x1000`) — inodes awaiting deletion are tracked in a
        /// dedicated file, pointed at by `s_orphan_file_inum`, rather than in a linked
        /// list threaded through the superblock. Its entries are written through the
        /// journal, so it requires `has_journal`. A freshly formatted filesystem has no
        /// orphans, so the file exists with every entry zero.
        ORPHAN_FILE("orphan_file") = 0x1000,
    }
}

feature_word! {
    /// The `incompat` feature word (`s_feature_incompat`, superblock offset `0x60`).
    ///
    /// An implementation must refuse to touch a filesystem carrying an `incompat`
    /// feature it does not recognize: these change the on-disk format in ways that
    /// make unaware access unsafe.
    Incompat {
        /// `filetype` (`0x0002`) — directory entries carry a file-type byte, so a
        /// reader need not fetch each inode to learn its type.
        FILETYPE("filetype") = 0x0002,
        /// `meta_bg` (`0x0010`) — group descriptors are stored in a distributed
        /// meta-block-group layout. This crate never writes it: it is the online
        /// group-descriptor conversion that reserved GDT blocks exist to avoid, so
        /// planning rejects it.
        META_BG("meta_bg") = 0x0010,
        /// `extent` (`0x0040`) — files map their blocks with extent trees rather
        /// than the classic indirect-block scheme.
        EXTENTS("extent") = 0x0040,
        /// `64bit` (`0x0080`) — block and inode counts may exceed 32 bits, and
        /// group descriptors take the 64-byte form with high halves present.
        SIXTY_FOUR_BIT("64bit") = 0x0080,
        /// `flex_bg` (`0x0200`) — the bitmaps and inode tables of the groups in a
        /// flex block group are packed together in the flex group's first group.
        FLEX_BG("flex_bg") = 0x0200,
        /// `metadata_csum_seed` (`0x2000`) — the seed every metadata checksum derives
        /// from is stored in the superblock (`s_checksum_seed`) instead of being
        /// recomputed from the UUID, so the UUID can be changed without rewriting every
        /// checksum. The stored seed is `crc32c(!0, uuid)`, so the checksums themselves
        /// are the same values either way. It requires `metadata_csum`, which is what
        /// defines those checksums.
        CSUM_SEED("metadata_csum_seed") = 0x2000,
    }
}

feature_word! {
    /// The `ro_compat` feature word (`s_feature_ro_compat`, superblock offset
    /// `0x64`).
    ///
    /// An implementation that does not recognize a `ro_compat` feature may still
    /// mount the filesystem read-only; writing without understanding the feature
    /// would corrupt the structures it governs.
    RoCompat {
        /// `sparse_super` (`0x0001`) — superblock and group-descriptor backups are
        /// kept only in group 0, group 1, and groups that are powers of 3, 5, or 7,
        /// rather than in every group.
        SPARSE_SUPER("sparse_super") = 0x0001,
        /// `large_file` (`0x0002`) — a file may be larger than 2 GiB, using the
        /// high half of the inode size field.
        LARGE_FILE("large_file") = 0x0002,
        /// `huge_file` (`0x0008`) — `i_blocks` may be counted in filesystem blocks
        /// rather than 512-byte sectors, allowing files past the sector-count limit.
        HUGE_FILE("huge_file") = 0x0008,
        /// `dir_nlink` (`0x0020`) — a directory's link count may exceed 65 000; an
        /// overflowed count is stored as 1 and treated as "unknown".
        DIR_NLINK("dir_nlink") = 0x0020,
        /// `extra_isize` (`0x0040`) — inodes larger than 128 bytes record the size
        /// of their extra area, enabling nanosecond timestamps and creation time.
        EXTRA_ISIZE("extra_isize") = 0x0040,
        /// `metadata_csum` (`0x0400`) — every metadata object carries a crc32c: the
        /// superblock, group descriptors, inodes, block and inode bitmaps,
        /// extent-tree blocks, directory blocks, and extended-attribute blocks. It
        /// also governs the `INODE_UNINIT` / `BLOCK_UNINIT` descriptor flags and the
        /// `bg_itable_unused` counts, and supersedes the older crc16 `uninit_bg`
        /// descriptor checksum, which this crate never sets.
        METADATA_CSUM("metadata_csum") = 0x0400,
    }
}

/// The complete feature configuration of one filesystem: the three on-disk feature
/// words together with the block and inode sizes fixed alongside them.
///
/// This is the single value the geometry planner, the on-disk serializers, and the
/// checksum and directory seams consult. Constructing it does not validate it;
/// [`FeatureSet::validate`] rejects combinations that must never reach the disk.
///
/// # Building one
///
/// Start from a baseline constant and modify it. [`DEFAULT`](Self::DEFAULT),
/// [`EXT2`](Self::EXT2), and [`EXT3`](Self::EXT3) are fixed family baselines,
/// [`LATEST`](Self::LATEST) tracks current `mke2fs`, and [`EMPTY`](Self::EMPTY) carries
/// no features at all — the base to replay a recorded list of feature names onto.
/// [`Profile::feature_set`] names a baseline by family. From there,
/// [`with_feature`](Self::with_feature) sets one feature by its on-disk name, and
/// [`with_block_size`](Self::with_block_size) and
/// [`with_inode_size`](Self::with_inode_size) set the two geometry values.
///
/// ```
/// # use ferrosys::ext::{FeatureSet, Profile};
/// let features = FeatureSet::DEFAULT
///     .with_feature("orphan_file", false)
///     .expect("orphan_file is a known feature")
///     .with_block_size(1024);
/// assert!(!features.has_orphan_file());
/// assert_eq!(Profile::of(features), Profile::Ext4);
/// ```
///
/// # Pinning an on-disk contract
///
/// A caller who needs the same bytes from a future release of this crate pins the whole
/// set, not a list of feature names: [`pin`](Self::pin) emits every field as one
/// canonical document to record and compare. See its documentation for why the feature
/// names alone are not enough.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FeatureSet {
    /// The `compat` feature word.
    pub compat: Compat,
    /// The `incompat` feature word.
    pub incompat: Incompat,
    /// The `ro_compat` feature word.
    pub ro_compat: RoCompat,
    /// Block size in bytes: 1024, 2048, or 4096. Defaults to 4096.
    ///
    /// A 1024-byte block moves the first data block from 0 to 1 and shrinks a group
    /// to 8 MiB, which changes where the backups and the packed tables of a flex
    /// block group land; the planner accounts for both.
    pub block_size: u32,
    /// Inode size in bytes (`s_inode_size`). 256 leaves room past the 128-byte
    /// classic inode for `i_extra_isize`, nanosecond timestamps, and creation time.
    pub inode_size: u16,
}

/// A feature combination that must never be written to disk.
///
/// Planning rejects these rather than emitting an image an external checker would
/// later fault, so the error names the exact conflict.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeatureError {
    /// `meta_bg` was requested. It is the distributed group-descriptor layout this
    /// crate exists to avoid; reserved GDT blocks via `resize_inode` are used in its
    /// place, so it is never planned.
    #[error(
        "meta_bg is never planned: it is the online group-descriptor layout that \
         reserved GDT blocks exist to avoid"
    )]
    MetaBg,
    /// A feature set without `extent` carries a feature from the ext4 layer. The
    /// block-mapped ext2/ext3 writer produces the classic indirect block map and none of
    /// the ext4-layer structures, so a non-extent set is defined as the `mke2fs -t
    /// ext2/ext3` feature words and nothing above them. The named feature — one of
    /// `flex_bg`, `64bit`, `metadata_csum`, `metadata_csum_seed`, `huge_file`,
    /// `dir_nlink`, `extra_isize`, or `orphan_file` — belongs to a filesystem the extent
    /// writer builds; a set carrying it is ext4 by classification and must advertise
    /// `extent` to match the bytes written.
    #[error(
        "{feature} requires extent mapping: it belongs to the ext4 feature layer, not the \
         block-mapped ext2/ext3 baseline"
    )]
    #[non_exhaustive]
    RequiresExtents {
        /// The on-disk name of the ext4-layer feature the non-extent set carries.
        feature: &'static str,
    },
    /// `flex_bg` was cleared on an extent-mapped set. The formatter packs each flex block
    /// group's bitmaps and inode tables together in the group's first member, so an
    /// extent-mapped image's physical layout is always a flex one; clearing the feature
    /// would advertise the per-group layout the extent writer does not produce. A set
    /// with neither `extent` nor `flex_bg` is the block-mapped family and is accepted.
    #[error(
        "flex_bg is required with extent mapping: the extent formatter packs each flex \
         block group's bitmaps and inode tables together"
    )]
    FlexBgRequired,
    /// `filetype` was cleared. The formatter records a file type in every directory
    /// entry, so clearing the feature would advertise the typeless directory encoding the
    /// formatter does not write.
    #[error("filetype is required: this formatter records a file type in every directory entry")]
    FiletypeRequired,
    /// `metadata_csum_seed` was requested without `metadata_csum`. The seed exists to serve
    /// metadata checksums, so storing one where there are none is a contradiction the
    /// kernel and `e2fsck` both reject.
    #[error(
        "metadata_csum_seed requires metadata_csum: the seed it stores has no checksums to serve"
    )]
    CsumSeedWithoutMetadataCsum,
    /// `orphan_file` was requested without `has_journal`. Deleting an inode records it
    /// in the orphan file and journals that record together with the deletion, so the
    /// file has no meaning on a filesystem with no journal.
    #[error("orphan_file requires has_journal: its entries are written through the journal")]
    OrphanFileWithoutJournal,
    /// `resize_inode` was requested without `large_file` at a block size whose resize
    /// inode is itself a large file. The resize inode is a regular file whose size field
    /// records the reach of the classic block map rather than the blocks it holds, and
    /// that reach grows with the square of the block size: at a 4096-byte block it is
    /// 4 GiB, past [`LARGE_FILE_MIN_SIZE`], so the filesystem must advertise `large_file`
    /// to describe its own resize inode. Smaller blocks put it under the bound and need no
    /// such feature.
    #[error(
        "resize_inode requires large_file at a {block_size}-byte block: its resize inode \
         declares {size} bytes, which is a large file"
    )]
    #[non_exhaustive]
    ResizeInodeRequiresLargeFile {
        /// The block size whose resize inode overruns the bound.
        block_size: u32,
        /// The size that resize inode declares.
        size: u64,
    },
    /// The block size is not a supported power-of-two byte count.
    #[error("unsupported block size {block_size}: expected 1024, 2048, or 4096")]
    #[non_exhaustive]
    BlockSize {
        /// The block size that was requested.
        block_size: u32,
    },
    /// The inode size is not a supported power-of-two byte count of at least 128,
    /// or does not divide the block size.
    #[error("unsupported inode size {inode_size}: expected a power of two in 128..=block_size")]
    #[non_exhaustive]
    InodeSize {
        /// The inode size that was requested.
        inode_size: u16,
    },
}

impl FeatureSet {
    /// A set carrying no features, with the default 4096-byte block and 256-byte inode.
    ///
    /// The base to build a set from a list of feature names: replay them through
    /// [`with_feature`](Self::with_feature) and the words come out exactly. That is how a
    /// caller verifies a recorded pin, so the empty base is part of the contract rather
    /// than a convenience.
    ///
    /// The block and inode sizes are geometry, not features, so they hold their defaults
    /// here; [`with_block_size`](Self::with_block_size) and
    /// [`with_inode_size`](Self::with_inode_size) set them. The set is not writable as it
    /// stands — it carries no `filetype`, which [`validate`](Self::validate) requires.
    ///
    /// ```
    /// # use ferrosys::ext::FeatureSet;
    /// let replayed = FeatureSet::DEFAULT
    ///     .names()
    ///     .iter()
    ///     .try_fold(FeatureSet::EMPTY, |set, name| set.with_feature(name, true))
    ///     .expect("every emitted name is a known feature");
    /// assert_eq!(replayed.compat, FeatureSet::DEFAULT.compat);
    /// assert_eq!(replayed.incompat, FeatureSet::DEFAULT.incompat);
    /// assert_eq!(replayed.ro_compat, FeatureSet::DEFAULT.ro_compat);
    /// ```
    pub const EMPTY: Self = Self {
        compat: Compat::NONE,
        incompat: Incompat::NONE,
        ro_compat: RoCompat::NONE,
        block_size: 4096,
        inode_size: 256,
    };

    /// The default feature profile: the configuration used when the caller does not
    /// choose otherwise, and the baseline [`Profile::Ext4`] names.
    ///
    /// On: `has_journal`, `ext_attr`, `resize_inode`, `dir_index`, `orphan_file`
    /// (compat); `filetype`, `extent`, `64bit`, `flex_bg`, `metadata_csum_seed` (incompat);
    /// `sparse_super`, `large_file`, `huge_file`, `dir_nlink`, `extra_isize`,
    /// `metadata_csum` (ro_compat). Inode size 256, and group descriptors take the
    /// 64-byte form. The block size is the default 4096; 1024 and 2048 are also valid.
    ///
    /// **This value is fixed.** It names one exact set of feature words and sizes, and it
    /// keeps naming them: a filesystem formatted from `DEFAULT` at one version of this
    /// crate is byte-identical to one formatted from `DEFAULT` at any other, given the
    /// same inputs. That is what makes it safe to pin an on-disk contract to. Callers who
    /// want the features a current `mke2fs` writes, whatever those become, name
    /// [`LATEST`](Self::LATEST) instead.
    pub const DEFAULT: Self = Self {
        compat: Compat(
            Compat::HAS_JOURNAL.0
                | Compat::EXT_ATTR.0
                | Compat::RESIZE_INODE.0
                | Compat::DIR_INDEX.0
                | Compat::ORPHAN_FILE.0,
        ),
        incompat: Incompat(
            Incompat::FILETYPE.0
                | Incompat::EXTENTS.0
                | Incompat::SIXTY_FOUR_BIT.0
                | Incompat::FLEX_BG.0
                | Incompat::CSUM_SEED.0,
        ),
        ro_compat: RoCompat(
            RoCompat::SPARSE_SUPER.0
                | RoCompat::LARGE_FILE.0
                | RoCompat::HUGE_FILE.0
                | RoCompat::DIR_NLINK.0
                | RoCompat::EXTRA_ISIZE.0
                | RoCompat::METADATA_CSUM.0,
        ),
        block_size: 4096,
        inode_size: 256,
    };

    /// The features a current `mke2fs` writes for ext4 — **a moving target, by design.**
    ///
    /// Equal to [`DEFAULT`](Self::DEFAULT) today. It tracks upstream `e2fsprogs`, so it
    /// may gain a feature in any release of this crate, and a filesystem formatted from it
    /// may therefore differ byte for byte between two versions of this crate. That is the
    /// point of it: a caller who wants parity with whatever `mke2fs` currently produces
    /// names this, and accepts that the answer changes when `mke2fs` does.
    ///
    /// It is **unsuitable for pinning an on-disk contract.** A caller who needs
    /// reproducible bytes across versions of this crate names [`DEFAULT`](Self::DEFAULT),
    /// which is fixed, and records the resolved set with [`pin`](Self::pin).
    pub const LATEST: Self = Self::DEFAULT;

    /// The ext2 baseline: the feature words `mke2fs -t ext2` writes, and the baseline
    /// [`Profile::Ext2`] names.
    ///
    /// On: `ext_attr`, `resize_inode`, `dir_index` (compat); `filetype` (incompat);
    /// `sparse_super`, `large_file` (ro_compat); inode size 256 and block size 4096. It
    /// carries no `extent` feature and no checksum, and the 256-byte inode's area past the
    /// 128-byte classic inode holds no `extra_isize`.
    ///
    /// Fixed, on the same terms as [`DEFAULT`](Self::DEFAULT): the ext2 feature layer is
    /// complete and this constant does not move.
    pub const EXT2: Self = Self {
        compat: Compat(Compat::EXT_ATTR.0 | Compat::RESIZE_INODE.0 | Compat::DIR_INDEX.0),
        incompat: Incompat(Incompat::FILETYPE.0),
        ro_compat: RoCompat(RoCompat::SPARSE_SUPER.0 | RoCompat::LARGE_FILE.0),
        block_size: 4096,
        inode_size: 256,
    };

    /// The ext3 baseline: the feature words `mke2fs -t ext3` writes, and the baseline
    /// [`Profile::Ext3`] names.
    ///
    /// Exactly [`EXT2`](Self::EXT2) plus `has_journal` (compat `0x04`) — a jbd2 journal in
    /// inode 8. Every other feature word and both sizes are ext2's. Fixed, on the same
    /// terms as [`DEFAULT`](Self::DEFAULT).
    pub const EXT3: Self = Self {
        compat: Compat(Self::EXT2.compat.0 | Compat::HAS_JOURNAL.0),
        ..Self::EXT2
    };

    /// This set with the block size replaced: 1024, 2048, or 4096 bytes.
    ///
    /// The size is not checked here; [`validate`](Self::validate) rejects an unsupported
    /// one with [`FeatureError::BlockSize`].
    #[must_use]
    pub const fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
        self
    }

    /// This set with the inode size replaced: a power of two from 128 up to the block
    /// size.
    ///
    /// The size is not checked here; [`validate`](Self::validate) rejects an unsupported
    /// one with [`FeatureError::InodeSize`].
    #[must_use]
    pub const fn with_inode_size(mut self, inode_size: u16) -> Self {
        self.inode_size = inode_size;
        self
    }

    /// The number of bytes one group descriptor occupies on disk (`s_desc_size`):
    /// 64 when `64bit` is set, otherwise 32.
    #[must_use]
    pub const fn desc_size(self) -> u16 {
        if self.incompat.contains(Incompat::SIXTY_FOUR_BIT) {
            64
        } else {
            32
        }
    }

    /// True when the `64bit` feature is set and group descriptors take the 64-byte
    /// form with high halves present.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.incompat.contains(Incompat::SIXTY_FOUR_BIT)
    }

    /// True when files map their data through extent trees.
    #[must_use]
    pub const fn has_extents(self) -> bool {
        self.incompat.contains(Incompat::EXTENTS)
    }

    /// True when superblock and descriptor backups follow the `sparse_super` rule
    /// rather than living in every group.
    #[must_use]
    pub const fn is_sparse_super(self) -> bool {
        self.ro_compat.contains(RoCompat::SPARSE_SUPER)
    }

    /// True when directory entries carry a file-type byte.
    #[must_use]
    pub const fn has_filetype(self) -> bool {
        self.incompat.contains(Incompat::FILETYPE)
    }

    /// True when the bitmaps and inode tables of the groups in a flex block group are
    /// packed together in the flex group's first group (`flex_bg`).
    #[must_use]
    pub const fn has_flex_bg(self) -> bool {
        self.incompat.contains(Incompat::FLEX_BG)
    }

    /// True when the filesystem carries a jbd2 journal in inode 8 (`has_journal`).
    #[must_use]
    pub const fn has_journal(self) -> bool {
        self.compat.contains(Compat::HAS_JOURNAL)
    }

    /// True when every metadata object carries a crc32c (`metadata_csum`). This
    /// selects the checksum seam's active implementation and turns on the
    /// `INODE_UNINIT` / `BLOCK_UNINIT` descriptor accounting.
    #[must_use]
    pub const fn has_metadata_csum(self) -> bool {
        self.ro_compat.contains(RoCompat::METADATA_CSUM)
    }

    /// True when a directory's link count may exceed 65 000 (`dir_nlink`). Past that a
    /// directory stores the `dir_nlink` sentinel `1` in `i_links_count`; without the
    /// feature that count is bounded, so a directory that would overrun it is not
    /// representable.
    #[must_use]
    pub const fn has_dir_nlink(self) -> bool {
        self.ro_compat.contains(RoCompat::DIR_NLINK)
    }

    /// True when the filesystem may carry extended attributes (`ext_attr`), inline in an
    /// inode or in a dedicated attribute block. Without it an inode's `i_file_acl` must be
    /// zero and no inode may carry an attribute, so a set of attributes is not
    /// representable.
    #[must_use]
    pub const fn has_ext_attr(self) -> bool {
        self.compat.contains(Compat::EXT_ATTR)
    }

    /// True when a regular file may reach [`LARGE_FILE_MIN_SIZE`] and beyond
    /// (`large_file`), using the high half of the inode's size field. Without it every
    /// regular file the filesystem holds must stay under that bound.
    #[must_use]
    pub const fn has_large_file(self) -> bool {
        self.ro_compat.contains(RoCompat::LARGE_FILE)
    }

    /// True when inode 7 maps the reserved group-descriptor-table blocks
    /// (`resize_inode`). Without it a filesystem carries no descriptor headroom and
    /// grows only offline, by relocating its descriptor table.
    #[must_use]
    pub const fn has_resize_inode(self) -> bool {
        self.compat.contains(Compat::RESIZE_INODE)
    }

    /// True when directories may carry a hash index (`dir_index`). This selects the
    /// directory-layout seam's active implementation.
    #[must_use]
    pub const fn has_dir_index(self) -> bool {
        self.compat.contains(Compat::DIR_INDEX)
    }

    /// True when inodes awaiting deletion are tracked in a dedicated file
    /// (`orphan_file`) whose inode number the superblock records. The file is
    /// allocated at format time, so it occupies the first inode past `/lost+found`
    /// and the entries a source supplies begin after it.
    #[must_use]
    pub const fn has_orphan_file(self) -> bool {
        self.compat.contains(Compat::ORPHAN_FILE)
    }

    /// True when the metadata-checksum seed is stored in the superblock
    /// (`metadata_csum_seed`) rather than recomputed from the UUID.
    #[must_use]
    pub const fn has_csum_seed(self) -> bool {
        self.incompat.contains(Incompat::CSUM_SEED)
    }

    /// The number of inodes stored per inode-table block: `block_size / inode_size`.
    /// Inode-table sizing rounds group inode counts to a whole number of these.
    ///
    /// A [`FeatureSet`] is `pub` with unvalidated fields, so a caller can construct one
    /// with a zero `inode_size`; that yields zero here rather than dividing by zero, the
    /// same degenerate-geometry answer the reader gives elsewhere.
    #[must_use]
    pub const fn inodes_per_block(self) -> u32 {
        if self.inode_size == 0 {
            return 0;
        }
        self.block_size / self.inode_size as u32
    }

    /// The on-disk names of every feature this set carries: the `compat` word's, then
    /// the `incompat` word's, then the `ro_compat` word's, each in ascending bit order.
    ///
    /// This is the vocabulary a user types and every ext4 tool prints, so it is the
    /// list to render and to compare against another implementation's. A bit no word
    /// names contributes nothing here; `unknown_bits` on the word reports those.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        let mut out = self.compat.names();
        out.extend(self.incompat.names());
        out.extend(self.ro_compat.names());
        out
    }

    /// Every field of this set as one canonical document, for a caller pinning the bytes
    /// a format produces.
    ///
    /// The document is the contract. A caller records what this emits — verbatim, as a
    /// blob — and compares it string-for-string on a later build; a difference is drift in
    /// the on-disk layout, surfaced as a diff a person reads rather than as changed image
    /// bytes nobody notices. Comparison is exactly string equality: the rendering is
    /// deterministic, ordered, and stable across releases of this crate under the version
    /// on its first line.
    ///
    /// ```text
    /// ferrosys-feature-pin 1
    /// compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
    /// incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
    /// ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
    /// block_size 4096
    /// inode_size 256
    /// ```
    ///
    /// Each feature word appears twice over, and both halves are load-bearing: the hex is
    /// exact and the names are readable, so a renamed feature fails on the half a person
    /// reads while a changed bit fails on the half a machine reads. A bit no word names is
    /// covered by the hex and reported as a trailing `unknown:0x…` so the readable half is
    /// never quietly short.
    ///
    /// **This is why the pin is the whole set and not
    /// [`names`](Self::names).** The feature names omit `block_size` and `inode_size`,
    /// which are not features and change the on-disk bytes comprehensively; a contract
    /// recorded from names alone would show no difference across a change to either.
    /// Every field is emitted here, and the projection is written as an exhaustive
    /// destructure so that a field added to [`FeatureSet`] is a compile error rather than
    /// a silent omission from every recorded pin.
    #[must_use]
    pub fn pin(self) -> String {
        // Exhaustive on purpose: see the note above. Do not replace with field accesses.
        let Self {
            compat,
            incompat,
            ro_compat,
            block_size,
            inode_size,
        } = self;

        let mut out = String::from("ferrosys-feature-pin 1\n");
        push_pin_word(
            &mut out,
            "compat",
            compat.bits(),
            &compat.names(),
            compat.unknown_bits(),
        );
        push_pin_word(
            &mut out,
            "incompat",
            incompat.bits(),
            &incompat.names(),
            incompat.unknown_bits(),
        );
        push_pin_word(
            &mut out,
            "ro_compat",
            ro_compat.bits(),
            &ro_compat.names(),
            ro_compat.unknown_bits(),
        );
        out.push_str("block_size ");
        out.push_str(&block_size.to_string());
        out.push_str("\ninode_size ");
        out.push_str(&inode_size.to_string());
        out.push('\n');
        out
    }

    /// This set with the feature named `name` turned on or off, or `None` when no word
    /// defines a feature by that name.
    ///
    /// The name is the on-disk one — `extent`, `64bit`, `metadata_csum_seed` — and the
    /// word it belongs to is a property of the name, not a caller's choice. The result
    /// is not checked: turning a feature off may leave a combination that must never
    /// reach disk, which is what [`validate`](Self::validate) is for.
    // Three symmetric branches dispatch the name to its feature word; collapsing the last
    // one to `?`, as the lint suggests, would break that parallel structure and read worse.
    #[allow(clippy::question_mark)]
    #[must_use]
    pub fn with_feature(mut self, name: &str, on: bool) -> Option<Self> {
        if let Some(flag) = Compat::from_name(name) {
            self.compat = if on {
                self.compat | flag
            } else {
                self.compat.without(flag)
            };
        } else if let Some(flag) = Incompat::from_name(name) {
            self.incompat = if on {
                self.incompat | flag
            } else {
                self.incompat.without(flag)
            };
        } else if let Some(flag) = RoCompat::from_name(name) {
            self.ro_compat = if on {
                self.ro_compat | flag
            } else {
                self.ro_compat.without(flag)
            };
        } else {
            return None;
        }
        Some(self)
    }

    /// Reject any feature combination or geometry knob that must never reach disk.
    /// Returns the first conflict found.
    ///
    /// # Errors
    ///
    /// - [`FeatureError::MetaBg`] if `meta_bg` is requested.
    /// - [`FeatureError::FiletypeRequired`] if `filetype` is cleared.
    /// - [`FeatureError::CsumSeedWithoutMetadataCsum`] if `metadata_csum_seed` is set without
    ///   `metadata_csum`.
    /// - [`FeatureError::OrphanFileWithoutJournal`] if `orphan_file` is set without
    ///   `has_journal`.
    /// - [`FeatureError::BlockSize`] if the block size is unsupported.
    /// - [`FeatureError::InodeSize`] if the inode size is unsupported or does not
    ///   divide the block size.
    /// - [`FeatureError::ResizeInodeRequiresLargeFile`] if `resize_inode` is set without
    ///   `large_file` at a block size whose resize inode reaches
    ///   [`LARGE_FILE_MIN_SIZE`].
    /// - [`FeatureError::FlexBgRequired`] if an extent-mapped set clears `flex_bg`.
    /// - [`FeatureError::RequiresExtents`] if a non-extent (ext2/ext3) set carries a
    ///   feature from the ext4 layer.
    pub const fn validate(self) -> Result<(), FeatureError> {
        // Universal, layout-independent rules the whole family obeys.
        if self.incompat.contains(Incompat::META_BG) {
            return Err(FeatureError::MetaBg);
        }
        // The formatter records a file type in every directory entry, whichever family it
        // writes, so `filetype` is required across ext2, ext3, and ext4 alike.
        if !self.has_filetype() {
            return Err(FeatureError::FiletypeRequired);
        }
        if self.has_csum_seed() && !self.has_metadata_csum() {
            return Err(FeatureError::CsumSeedWithoutMetadataCsum);
        }
        if self.has_orphan_file() && !self.has_journal() {
            return Err(FeatureError::OrphanFileWithoutJournal);
        }
        match self.block_size {
            1024 | 2048 | 4096 => {}
            other => return Err(FeatureError::BlockSize { block_size: other }),
        }
        let isize = self.inode_size as u32;
        if isize < 128
            || !isize.is_power_of_two()
            || isize > self.block_size
            || !self.block_size.is_multiple_of(isize)
        {
            return Err(FeatureError::InodeSize {
                inode_size: self.inode_size,
            });
        }

        // The resize inode is a regular file whose size records the classic block map's
        // reach, which the block size squares: at 4096 bytes that is 4 GiB, and a regular
        // file that large is what `large_file` exists to describe. The feature is required
        // exactly where the size crosses the bound, so the smaller block sizes — whose
        // resize inodes stay well under it — are left free of it.
        let resize_size = resize_inode_size(self.block_size);
        if self.has_resize_inode() && !self.has_large_file() && resize_size >= LARGE_FILE_MIN_SIZE {
            return Err(FeatureError::ResizeInodeRequiresLargeFile {
                block_size: self.block_size,
                size: resize_size,
            });
        }

        // Layout rules split on the extent discriminator — the same word [`Profile::of`]
        // classifies on, so the writer's family and the reader's label agree by
        // construction.
        if self.has_extents() {
            // The ext4 family: the extent writer packs flex block groups, so an
            // extent-mapped image always advertises `flex_bg`.
            if !self.has_flex_bg() {
                return Err(FeatureError::FlexBgRequired);
            }
        } else {
            // The ext2/ext3 family: the block-mapped writer produces the classic
            // indirect map and none of the ext4 layer. A set carrying any ext4-layer
            // feature is ext4 by classification, so the block-mapped path refuses it —
            // in the order the on-disk feature words fall.
            if self.has_flex_bg() {
                return Err(FeatureError::RequiresExtents { feature: "flex_bg" });
            }
            if self.is_64bit() {
                return Err(FeatureError::RequiresExtents { feature: "64bit" });
            }
            if self.has_metadata_csum() {
                return Err(FeatureError::RequiresExtents {
                    feature: "metadata_csum",
                });
            }
            if self.has_csum_seed() {
                return Err(FeatureError::RequiresExtents {
                    feature: "metadata_csum_seed",
                });
            }
            if self.ro_compat.contains(RoCompat::HUGE_FILE) {
                return Err(FeatureError::RequiresExtents {
                    feature: "huge_file",
                });
            }
            if self.has_dir_nlink() {
                return Err(FeatureError::RequiresExtents {
                    feature: "dir_nlink",
                });
            }
            if self.ro_compat.contains(RoCompat::EXTRA_ISIZE) {
                return Err(FeatureError::RequiresExtents {
                    feature: "extra_isize",
                });
            }
            if self.has_orphan_file() {
                return Err(FeatureError::RequiresExtents {
                    feature: "orphan_file",
                });
            }
        }
        Ok(())
    }
}

impl Default for FeatureSet {
    /// The profile in [`FeatureSet::DEFAULT`].
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Append one feature word to a pin document: its label, its exact bits, then its
/// feature names in ascending bit order, then any bit the word does not name.
///
/// The hex is zero-padded to eight digits so every word occupies the same width and a
/// diff of two documents lines up column for column.
fn push_pin_word(out: &mut String, label: &str, bits: u32, names: &[&str], unknown: u32) {
    out.push_str(label);
    out.push_str(" 0x");
    out.push_str(&format!("{bits:08x}"));
    for name in names {
        out.push(' ');
        out.push_str(name);
    }
    if unknown != 0 {
        out.push_str(" unknown:0x");
        out.push_str(&format!("{unknown:08x}"));
    }
    out.push('\n');
}

/// The ext filesystem family a [`FeatureSet`] presents: the profile a caller names when
/// formatting, and the label read back from any image.
///
/// A profile is a two-way lens over [`FeatureSet`], not a second source of truth.
/// [`feature_set`](Self::feature_set) turns a profile into the baseline feature words
/// `mke2fs -t` writes for it; [`of`](Self::of) classifies an arbitrary feature set back to
/// the family it belongs to. An image is judged by its feature words, so a set seeded from
/// [`Ext4`](Self::Ext4) with `extent` cleared classifies as [`Ext3`](Self::Ext3) — the same
/// result `mke2fs -t ext4 -O ^extent` produces. A profile seeds a format; it does not
/// constrain what the image becomes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Profile {
    /// ext2: files mapped through the classic indirect-block scheme, with no journal. Its
    /// baseline is [`FeatureSet::EXT2`].
    Ext2,
    /// ext3: ext2 plus a jbd2 journal (`has_journal`). Its baseline is
    /// [`FeatureSet::EXT3`].
    Ext3,
    /// ext4: extent-mapped files, 64-bit addressing, flex block groups, and metadata
    /// checksums. Its baseline is [`FeatureSet::DEFAULT`], and it is the default profile.
    #[default]
    Ext4,
}

impl Profile {
    /// The baseline feature words this profile seeds a format with — the set `mke2fs -t`
    /// writes for the same family. [`Ext2`](Self::Ext2) yields [`FeatureSet::EXT2`],
    /// [`Ext3`](Self::Ext3) [`FeatureSet::EXT3`], and [`Ext4`](Self::Ext4)
    /// [`FeatureSet::DEFAULT`].
    #[must_use]
    pub const fn feature_set(self) -> FeatureSet {
        match self {
            Profile::Ext2 => FeatureSet::EXT2,
            Profile::Ext3 => FeatureSet::EXT3,
            Profile::Ext4 => FeatureSet::DEFAULT,
        }
    }

    /// Classify a feature set into the family it belongs to, on the extent-then-journal
    /// discriminator: a set advertising `extent` is [`Ext4`](Self::Ext4); one without it is
    /// [`Ext3`](Self::Ext3) when it carries `has_journal` and [`Ext2`](Self::Ext2)
    /// otherwise.
    ///
    /// This inverts [`feature_set`](Self::feature_set) on the baselines and labels any set,
    /// including one no baseline produces. It reads the words, not the profile a format was
    /// seeded from, so an ext4 set with `extent` cleared classifies as the non-extent family
    /// it now describes.
    #[must_use]
    pub const fn of(features: FeatureSet) -> Self {
        if features.has_extents() {
            Profile::Ext4
        } else if features.has_journal() {
            Profile::Ext3
        } else {
            Profile::Ext2
        }
    }

    /// The `mke2fs -t` name for this profile: `"ext2"`, `"ext3"`, or `"ext4"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Profile::Ext2 => "ext2",
            Profile::Ext3 => "ext3",
            Profile::Ext4 => "ext4",
        }
    }
}

impl fmt::Display for Profile {
    /// The `mke2fs -t` name: `ext2`, `ext3`, or `ext4`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_set_is_frozen() {
        // DEFAULT is fixed: a caller pins an on-disk contract to it and expects the same
        // bytes from a later release of this crate. So these are not "the words today" —
        // they are the words, and a change to any of them changes image bytes for every
        // caller who never touched their configuration. Adding a feature to the default
        // profile means adding it to LATEST, not here.
        let fs = FeatureSet::default();
        assert_eq!(
            fs.compat.bits(),
            0x103c,
            "has_journal | ext_attr | resize_inode | dir_index | orphan_file"
        );
        assert_eq!(
            fs.incompat.bits(),
            0x22c2,
            "filetype | extents | 64bit | flex_bg | metadata_csum_seed"
        );
        assert_eq!(
            fs.ro_compat.bits(),
            0x46b,
            "sparse_super | large_file | huge_file | dir_nlink | extra_isize | metadata_csum"
        );
        assert_eq!(fs.block_size, 4096);
        assert_eq!(fs.inode_size, 256);
        assert_eq!(fs, FeatureSet::DEFAULT);
        assert_eq!(Profile::Ext4.feature_set(), FeatureSet::DEFAULT);
    }

    #[test]
    fn latest_still_matches_the_frozen_default() {
        // LATEST tracks the pinned `mke2fs`, whose defaults DEFAULT was frozen from, so
        // the two agree today. When upstream adds a feature this assertion is the one that
        // changes — deliberately, to record that the two have diverged — and DEFAULT stays
        // exactly where it is.
        assert_eq!(FeatureSet::LATEST, FeatureSet::DEFAULT);
    }

    #[test]
    fn the_empty_set_carries_no_features() {
        let empty = FeatureSet::EMPTY;
        assert_eq!(empty.compat.bits(), 0);
        assert_eq!(empty.incompat.bits(), 0);
        assert_eq!(empty.ro_compat.bits(), 0);
        assert!(empty.names().is_empty());
        // The sizes are geometry rather than features, so they hold their defaults.
        assert_eq!(empty.block_size, 4096);
        assert_eq!(empty.inode_size, 256);
        // And the set is not writable as it stands: `filetype` is required.
        assert!(matches!(
            empty.validate(),
            Err(FeatureError::FiletypeRequired)
        ));
    }

    #[test]
    fn the_geometry_builders_replace_one_value_each() {
        let fs = FeatureSet::DEFAULT
            .with_block_size(1024)
            .with_inode_size(128);
        assert_eq!(fs.block_size, 1024);
        assert_eq!(fs.inode_size, 128);
        // Neither touches the feature words.
        assert_eq!(fs.compat, FeatureSet::DEFAULT.compat);
        assert_eq!(fs.incompat, FeatureSet::DEFAULT.incompat);
        assert_eq!(fs.ro_compat, FeatureSet::DEFAULT.ro_compat);
    }

    #[test]
    fn the_pin_document_is_the_recorded_contract() {
        // A golden document. A consumer records this verbatim and compares it string for
        // string, so any change to the rendering — a reordered word, a dropped field, a
        // renamed feature — is a change to every recorded pin and must be deliberate. If
        // this assertion needs editing, the version on the first line needs raising.
        assert_eq!(
            FeatureSet::DEFAULT.pin(),
            "ferrosys-feature-pin 1\n\
             compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file\n\
             incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed\n\
             ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize \
             metadata_csum\n\
             block_size 4096\n\
             inode_size 256\n"
        );
        assert_eq!(
            FeatureSet::EXT2.pin(),
            "ferrosys-feature-pin 1\n\
             compat 0x00000038 ext_attr resize_inode dir_index\n\
             incompat 0x00000002 filetype\n\
             ro_compat 0x00000003 sparse_super large_file\n\
             block_size 4096\n\
             inode_size 256\n"
        );
        assert_eq!(
            FeatureSet::EMPTY.pin(),
            "ferrosys-feature-pin 1\n\
             compat 0x00000000\n\
             incompat 0x00000000\n\
             ro_compat 0x00000000\n\
             block_size 4096\n\
             inode_size 256\n"
        );
    }

    #[test]
    fn the_pin_records_geometry_the_feature_names_drop() {
        // The reason the pin is the whole set: two sets with identical feature names but
        // different geometry produce different images, and `names()` cannot tell them
        // apart. The pin can, which is what makes it usable as a contract.
        let a = FeatureSet::DEFAULT;
        let b = FeatureSet::DEFAULT
            .with_block_size(1024)
            .with_inode_size(128);
        assert_eq!(a.names(), b.names());
        assert_ne!(a.pin(), b.pin());
    }

    #[test]
    fn the_pin_names_replay_onto_an_empty_set() {
        // Two projections checking each other. The pin carries each word twice — exact
        // bits and readable names — and neither half is trusted alone: replaying the names
        // from EMPTY must reproduce the bits. A renamed feature breaks the replay; a
        // changed bit breaks the hex.
        for set in [FeatureSet::DEFAULT, FeatureSet::EXT2, FeatureSet::EXT3] {
            let replayed = set
                .names()
                .iter()
                .try_fold(FeatureSet::EMPTY, |acc, name| acc.with_feature(name, true))
                .expect("every name a set emits is a name a word resolves");
            assert_eq!(replayed.compat, set.compat);
            assert_eq!(replayed.incompat, set.incompat);
            assert_eq!(replayed.ro_compat, set.ro_compat);
        }
    }

    #[test]
    fn the_pin_reports_a_bit_no_word_names() {
        // A set read back from a foreign image can carry a feature this crate does not
        // name. The hex covers it either way; the trailing `unknown:` marker keeps the
        // readable half from being quietly short of the exact one.
        let mut fs = FeatureSet::EMPTY;
        fs.incompat = Incompat::from_bits(Incompat::FILETYPE.bits() | 0x0080_0000);
        let pinned = fs.pin();
        assert!(
            pinned.contains("incompat 0x00800002 filetype unknown:0x00800000\n"),
            "{pinned}"
        );
    }

    #[test]
    fn ext2_ext3_baselines_match_mke2fs() {
        // The feature words `mke2fs 1.47.0` writes for `-t ext2` and `-t ext3` under the
        // vendored configuration. The foreign-image gate builds those same images and reads
        // them back, so a drift here is a drift from the filesystems the reader is tested on.
        let ext2 = FeatureSet::EXT2;
        assert_eq!(
            ext2.compat.bits(),
            0x0038,
            "ext_attr | resize_inode | dir_index"
        );
        assert_eq!(ext2.incompat.bits(), 0x0002, "filetype");
        assert_eq!(ext2.ro_compat.bits(), 0x0003, "sparse_super | large_file");
        assert_eq!(ext2.block_size, 4096);
        assert_eq!(ext2.inode_size, 256);

        let ext3 = FeatureSet::EXT3;
        assert_eq!(ext3.compat.bits(), 0x003c, "ext2 plus has_journal");
        assert_eq!(ext3.incompat.bits(), 0x0002, "filetype");
        assert_eq!(ext3.ro_compat.bits(), 0x0003, "sparse_super | large_file");
        assert_eq!(ext3.block_size, 4096);
        assert_eq!(ext3.inode_size, 256);

        // ext3 is exactly ext2 plus the journal: identical in every other word and both
        // sizes.
        assert_eq!(
            ext3,
            FeatureSet {
                compat: ext2.compat | Compat::HAS_JOURNAL,
                ..ext2
            },
            "ext3 must differ from ext2 only by has_journal"
        );
    }

    #[test]
    fn profile_seeds_the_matching_baseline() {
        assert_eq!(Profile::Ext2.feature_set(), FeatureSet::EXT2);
        assert_eq!(Profile::Ext3.feature_set(), FeatureSet::EXT3);
        assert_eq!(Profile::Ext4.feature_set(), FeatureSet::DEFAULT);
        // The default profile is ext4, matching the default feature set.
        assert_eq!(Profile::default(), Profile::Ext4);
        assert_eq!(Profile::default().feature_set(), FeatureSet::default());
    }

    #[test]
    fn every_profile_round_trips_through_its_feature_set() {
        // Preset then classify is the identity on the baselines: the lens agrees with itself
        // in both directions.
        for profile in [Profile::Ext2, Profile::Ext3, Profile::Ext4] {
            assert_eq!(Profile::of(profile.feature_set()), profile);
        }
    }

    #[test]
    fn of_classifies_on_the_extent_then_journal_discriminator() {
        // extent present -> ext4, whatever else the set carries, journal or not.
        assert_eq!(Profile::of(FeatureSet::DEFAULT), Profile::Ext4);
        let extent_no_journal = FeatureSet::DEFAULT
            .with_feature("has_journal", false)
            .expect("a known name");
        assert!(extent_no_journal.has_extents() && !extent_no_journal.has_journal());
        assert_eq!(Profile::of(extent_no_journal), Profile::Ext4);

        // No extent: the journal splits ext3 from ext2.
        assert_eq!(Profile::of(FeatureSet::EXT3), Profile::Ext3);
        assert_eq!(Profile::of(FeatureSet::EXT2), Profile::Ext2);
    }

    #[test]
    fn of_reads_the_words_not_the_seed() {
        // A profile seeds, it does not constrain. Seed ext4, clear extent, and the set is
        // classified by what it now advertises — the non-extent family — not by the profile
        // it started from. It still carries has_journal, so that family is ext3.
        let downgraded = Profile::Ext4
            .feature_set()
            .with_feature("extent", false)
            .expect("a known name");
        assert_eq!(Profile::of(downgraded), Profile::Ext3);

        // Clear the journal too and it lands on ext2.
        let bare = downgraded
            .with_feature("has_journal", false)
            .expect("a known name");
        assert_eq!(Profile::of(bare), Profile::Ext2);
    }

    #[test]
    fn profile_names_are_the_mke2fs_t_vocabulary() {
        assert_eq!(Profile::Ext2.name(), "ext2");
        assert_eq!(Profile::Ext3.name(), "ext3");
        assert_eq!(Profile::Ext4.name(), "ext4");
        // Display renders the same name.
        assert_eq!(Profile::Ext4.to_string(), "ext4");
        assert_eq!(format!("{}", Profile::Ext2), "ext2");
    }

    #[test]
    fn a_feature_that_serves_another_is_rejected_without_it() {
        // The stored seed serves the metadata checksums and the orphan file's entries are
        // journalled, so neither means anything alone. mke2fs quietly drops such a
        // feature; this states the conflict instead of writing a profile the caller did
        // not ask for.
        let mut fs = FeatureSet::default();
        fs.ro_compat = RoCompat::from_bits(fs.ro_compat.bits() & !RoCompat::METADATA_CSUM.bits());
        assert_eq!(
            fs.validate(),
            Err(FeatureError::CsumSeedWithoutMetadataCsum)
        );

        let mut fs = FeatureSet::default();
        fs.compat = Compat::from_bits(fs.compat.bits() & !Compat::HAS_JOURNAL.bits());
        assert_eq!(fs.validate(), Err(FeatureError::OrphanFileWithoutJournal));

        // Dropping each pair together is valid.
        let mut fs = FeatureSet::default();
        fs.compat = Compat::from_bits(
            fs.compat.bits() & !(Compat::HAS_JOURNAL.bits() | Compat::ORPHAN_FILE.bits()),
        );
        fs.incompat = Incompat::from_bits(fs.incompat.bits() & !Incompat::CSUM_SEED.bits());
        fs.ro_compat = RoCompat::from_bits(fs.ro_compat.bits() & !RoCompat::METADATA_CSUM.bits());
        assert_eq!(fs.validate(), Ok(()));
    }

    #[test]
    fn default_derives_the_64bit_descriptor_width() {
        let fs = FeatureSet::default();
        assert!(fs.is_64bit());
        assert_eq!(fs.desc_size(), 64);
        assert_eq!(fs.inodes_per_block(), 16);
        assert!(fs.has_extents());
        assert!(fs.is_sparse_super());
        assert!(fs.has_filetype());
        assert!(fs.has_metadata_csum());
        assert!(fs.has_journal());
    }

    #[test]
    fn default_profile_validates() {
        assert_eq!(FeatureSet::default().validate(), Ok(()));
    }

    #[test]
    fn meta_bg_is_rejected() {
        let mut fs = FeatureSet::default();
        fs.incompat |= Incompat::META_BG;
        assert_eq!(fs.validate(), Err(FeatureError::MetaBg));
    }

    #[test]
    fn an_extent_set_still_requires_flex_bg_and_filetype() {
        // The extent writer packs flex block groups and types every directory entry, so
        // an extent-mapped set that clears `flex_bg` or `filetype` is refused: the bytes
        // would not match the layout the image advertises. Clearing `flex_bg` on an
        // extent set is the flex requirement, not the block-mapped family — that family
        // is the one with neither `extent` nor `flex_bg`.
        let fs = FeatureSet::DEFAULT
            .with_feature("flex_bg", false)
            .expect("a known name");
        assert_eq!(fs.validate(), Err(FeatureError::FlexBgRequired));

        let fs = FeatureSet::DEFAULT
            .with_feature("filetype", false)
            .expect("a known name");
        assert_eq!(fs.validate(), Err(FeatureError::FiletypeRequired));
    }

    #[test]
    fn the_non_extent_baselines_validate() {
        // The block-mapped writer produces the classic indirect map, so the ext2 and
        // ext3 baselines — which carry no `extent` and nothing from the ext4 layer — are
        // valid write targets. This is the contract WS5 turned on: a non-extent baseline
        // formats rather than being refused.
        assert_eq!(FeatureSet::EXT2.validate(), Ok(()));
        assert_eq!(FeatureSet::EXT3.validate(), Ok(()));
    }

    #[test]
    fn a_non_extent_set_refuses_every_ext4_layer_feature() {
        // A set without `extent` is the block-mapped family, defined as the ext2/ext3
        // words and nothing above them. Adding any ext4-layer feature to that baseline is
        // refused on that feature's own name: such a set is ext4 by classification and
        // must advertise `extent` to match the extent writer's bytes.
        for (name, present) in [
            ("flex_bg", "flex_bg"),
            ("64bit", "64bit"),
            ("metadata_csum", "metadata_csum"),
            ("huge_file", "huge_file"),
            ("dir_nlink", "dir_nlink"),
            ("extra_isize", "extra_isize"),
        ] {
            let fs = FeatureSet::EXT2
                .with_feature(name, true)
                .expect("a known name");
            assert_eq!(
                fs.validate(),
                Err(FeatureError::RequiresExtents { feature: present }),
                "ext2 + {name} is refused as an ext4-layer feature"
            );
        }

        // `metadata_csum_seed` needs `metadata_csum` to pass the universal seed rule, so
        // it reaches the layer check only alongside it — where `metadata_csum` is the
        // first ext4-layer feature the split reports.
        let fs = FeatureSet::EXT2
            .with_feature("metadata_csum", true)
            .expect("a known name")
            .with_feature("metadata_csum_seed", true)
            .expect("a known name");
        assert_eq!(
            fs.validate(),
            Err(FeatureError::RequiresExtents {
                feature: "metadata_csum"
            })
        );

        // `orphan_file` needs `has_journal`, so ext3-plus-orphan reaches the layer check;
        // it is an ext4-layer feature and refused there.
        let fs = FeatureSet::EXT3
            .with_feature("orphan_file", true)
            .expect("a known name");
        assert_eq!(
            fs.validate(),
            Err(FeatureError::RequiresExtents {
                feature: "orphan_file"
            })
        );
    }

    #[test]
    fn the_resize_inode_declares_the_size_mke2fs_writes() {
        // The values `mke2fs 1.47.0` records in inode 7 at each block size, read back with
        // `debugfs -R 'stat <7>'`. The formula squares the block size, so these are the
        // three points the supported sizes land on — and the 4096 one is what puts the
        // resize inode past the large-file bound.
        assert_eq!(resize_inode_size(1024), 67_383_296);
        assert_eq!(resize_inode_size(2048), 537_944_064);
        assert_eq!(resize_inode_size(4096), 4_299_210_752);
        assert!(resize_inode_size(1024) < LARGE_FILE_MIN_SIZE);
        assert!(resize_inode_size(2048) < LARGE_FILE_MIN_SIZE);
        assert!(resize_inode_size(4096) >= LARGE_FILE_MIN_SIZE);
    }

    #[test]
    fn the_resize_inode_requires_large_file_where_its_size_needs_it() {
        // The resize inode is a regular file, so at a 4096-byte block — where its declared
        // size is 4 GiB — the filesystem must advertise `large_file` to describe its own
        // reserved-descriptor map. `mke2fs -O ^large_file` sets the feature back for
        // exactly this reason; this states the conflict rather than writing a profile the
        // caller did not ask for.
        let fs = FeatureSet::EXT2
            .with_feature("large_file", false)
            .expect("a known name");
        assert_eq!(fs.block_size, 4096);
        assert_eq!(
            fs.validate(),
            Err(FeatureError::ResizeInodeRequiresLargeFile {
                block_size: 4096,
                size: 4_299_210_752,
            })
        );

        // The smaller block sizes put the resize inode well under the bound, so they
        // format without the feature — as `mke2fs -b 1024 -O ^large_file` does.
        for block_size in [1024, 2048] {
            let fs = FeatureSet { block_size, ..fs };
            assert_eq!(
                fs.validate(),
                Ok(()),
                "a {block_size}-byte block needs no large_file for its resize inode"
            );
        }

        // Dropping the resize inode drops the requirement with it: nothing else the
        // formatter writes reaches the bound on its own.
        let fs = FeatureSet {
            block_size: 4096,
            ..fs
        }
        .with_feature("resize_inode", false)
        .expect("a known name");
        assert_eq!(fs.validate(), Ok(()));
    }

    #[test]
    fn unsupported_sizes_are_rejected() {
        let fs = FeatureSet {
            block_size: 3000,
            ..FeatureSet::default()
        };
        assert_eq!(
            fs.validate(),
            Err(FeatureError::BlockSize { block_size: 3000 })
        );

        let fs = FeatureSet {
            inode_size: 100,
            ..FeatureSet::default()
        };
        assert_eq!(
            fs.validate(),
            Err(FeatureError::InodeSize { inode_size: 100 })
        );

        // 32-byte descriptors when 64bit is off.
        let mut fs = FeatureSet::default();
        fs.incompat = Incompat::from_bits(fs.incompat.bits() & !Incompat::SIXTY_FOUR_BIT.bits());
        assert_eq!(fs.desc_size(), 32);
        assert!(!fs.is_64bit());
    }

    #[test]
    fn inodes_per_block_survives_a_zero_inode_size() {
        // The fields are `pub` and construction is unvalidated, so a zero `inode_size` is
        // constructible; it yields zero rather than dividing by zero.
        let fs = FeatureSet {
            block_size: 4096,
            inode_size: 0,
            ..FeatureSet::default()
        };
        assert_eq!(fs.inodes_per_block(), 0);
        // A normal set still counts as before.
        let fs = FeatureSet {
            block_size: 4096,
            inode_size: 256,
            ..FeatureSet::default()
        };
        assert_eq!(fs.inodes_per_block(), 16);
    }

    #[test]
    fn contains_and_membership() {
        let f = Incompat::FILETYPE | Incompat::EXTENTS;
        assert!(f.contains(Incompat::FILETYPE));
        assert!(f.contains(Incompat::EXTENTS));
        assert!(!f.contains(Incompat::FLEX_BG));
        assert!(!f.is_empty());
        assert!(Incompat::NONE.is_empty());
    }

    #[test]
    fn unknown_bits_flags_unrecognized_features() {
        // A recognized set has no unknown bits; an unrecognized bit is reported.
        assert_eq!(FeatureSet::default().incompat.unknown_bits(), 0);
        let mystery = Incompat::from_bits(Incompat::FILETYPE.bits() | 0x8000_0000);
        assert_eq!(mystery.unknown_bits(), 0x8000_0000);
    }

    #[test]
    fn debug_renders_flag_names() {
        let f = Incompat::FILETYPE | Incompat::EXTENTS;
        assert_eq!(format!("{f:?}"), "Incompat(FILETYPE | EXTENTS)");
        assert_eq!(format!("{:?}", Incompat::NONE), "Incompat(NONE)");
    }

    #[test]
    fn the_default_profile_names_its_features_on_disk() {
        // The on-disk names, not the Rust symbols: `extent`, not `EXTENTS`. This is the
        // list `dumpe2fs` prints, in the order it prints it — compat, then incompat,
        // then ro_compat, each in ascending bit order.
        assert_eq!(
            FeatureSet::DEFAULT.names(),
            [
                "has_journal",
                "ext_attr",
                "resize_inode",
                "dir_index",
                "orphan_file",
                "filetype",
                "extent",
                "64bit",
                "flex_bg",
                "metadata_csum_seed",
                "sparse_super",
                "large_file",
                "huge_file",
                "dir_nlink",
                "extra_isize",
                "metadata_csum",
            ]
        );
    }

    #[test]
    fn every_name_round_trips_back_to_its_bit() {
        // Each word's names resolve within that word and nowhere else, so a name cannot
        // set a bit of the same value in the wrong feature word.
        for (name, bit) in [
            ("has_journal", Compat::HAS_JOURNAL),
            ("orphan_file", Compat::ORPHAN_FILE),
        ] {
            assert_eq!(Compat::from_name(name), Some(bit));
            assert_eq!(Incompat::from_name(name), None);
            assert_eq!(RoCompat::from_name(name), None);
        }
        assert_eq!(Incompat::from_name("extent"), Some(Incompat::EXTENTS));
        assert_eq!(Incompat::from_name("64bit"), Some(Incompat::SIXTY_FOUR_BIT));
        assert_eq!(
            Incompat::from_name("metadata_csum_seed"),
            Some(Incompat::CSUM_SEED)
        );
        assert_eq!(
            RoCompat::from_name("metadata_csum"),
            Some(RoCompat::METADATA_CSUM)
        );
        // The Rust symbol is not the on-disk name, and an unknown name resolves to
        // nothing rather than to an empty set that would silently do nothing.
        assert_eq!(Incompat::from_name("EXTENTS"), None);
        assert_eq!(Incompat::from_name("no_such_feature"), None);
    }

    #[test]
    fn with_feature_toggles_by_on_disk_name() {
        let fs = FeatureSet::DEFAULT;
        let off = fs.with_feature("extent", false).expect("a known name");
        assert!(!off.has_extents());
        assert!(!off.names().contains(&"extent"));
        // Every other feature is untouched.
        assert_eq!(off.compat, fs.compat);
        assert_eq!(off.ro_compat, fs.ro_compat);
        assert_eq!(
            off.with_feature("extent", true).expect("a known name"),
            fs,
            "turning a feature off and back on is the identity"
        );
        // Turning a feature off may leave a combination that must not reach disk; that
        // is validate's job, not this one's.
        let orphaned = fs.with_feature("has_journal", false).expect("a known name");
        assert_eq!(
            orphaned.validate(),
            Err(FeatureError::OrphanFileWithoutJournal)
        );
        // A name no word defines resolves to nothing, rather than silently doing
        // nothing.
        assert_eq!(fs.with_feature("no_such_feature", true), None);
    }

    #[test]
    fn an_unknown_bit_contributes_no_name() {
        // An image carrying a feature this crate does not know must not read as though
        // every bit it holds were understood: the name list omits it and `unknown_bits`
        // is what reports it.
        let mystery = Incompat::from_bits(Incompat::EXTENTS.bits() | 0x8000_0000);
        assert_eq!(mystery.names(), ["extent"]);
        assert_eq!(mystery.unknown_bits(), 0x8000_0000);
    }

    #[test]
    fn without_clears_only_the_named_flags() {
        let f = Incompat::FILETYPE | Incompat::EXTENTS | Incompat::FLEX_BG;
        let cleared = f.without(Incompat::EXTENTS);
        assert!(!cleared.contains(Incompat::EXTENTS));
        assert!(cleared.contains(Incompat::FILETYPE));
        assert!(cleared.contains(Incompat::FLEX_BG));
        // Clearing a flag that is not set changes nothing.
        assert_eq!(cleared.without(Incompat::EXTENTS), cleared);
    }
}
