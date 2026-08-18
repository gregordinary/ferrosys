//! Geometry: from a volume size and what the filesystem will hold to where every chunk sits
//! and how much metadata it may spend.
//!
//! [`plan_layout`] is the whole of it. It takes what a caller can state — how large the volume
//! is, how large a sector and a node are, how the two kinds of block group are replicated, what
//! features the filesystem carries, and how much content it will be given — and derives what
//! the format records: which chunks exist, how long each is, where it begins in the logical
//! address space, where each copy of it begins on the device, which superblock locations the
//! device has room for, and how many metadata blocks the whole of it may consume.
//!
//! This module is pure and deterministic: it computes numbers from numbers, performs no I/O,
//! reads no clock, and allocates nothing on a device. Planning before writing is what makes an
//! image reproducible — every placement is a value a caller can inspect, compare, and assert
//! against before a byte is emitted.
//!
//! # Two address spaces, advancing at different rates
//!
//! Every address above the chunk layer is logical, and a chunk maps a run of logical space onto
//! one or more copies on the device. A chunk therefore consumes **its length** of logical space
//! and **its length times its copy count** of the device, so the two cursors move apart as soon
//! as anything is mirrored. Both are laid out here, in one pass, so that a copy's physical
//! placement is a value rather than a thing a writer discovers as it goes.
//!
//! # The order chunks are laid down in, and the unallocated span before them
//!
//! The first mebibyte of the device holds no chunk. That much is the format: a superblock lives
//! at 64 KiB and the region around it is reserved.
//!
//! What follows the first mebibyte is not always a chunk either. A filesystem whose metadata is
//! mirrored has an unallocated span between the reserved head and its first chunk, because the
//! layout laid out here is the one the format's own tooling arrives at, and that tooling reaches
//! it by allocating unmirrored chunks first and replacing the ones whose replication turned out
//! wrong. The spans those replaced chunks occupied stay unallocated.
//!
//! Reproducing that is deliberate, and it costs nothing: an unallocated span is device space and
//! logical space that no chunk claims, which a driver allocates from later exactly as it
//! allocates from the space past the last chunk. What it buys is that an image planned here and
//! an image the format's own tooling produces put the same chunk at the same address, which is
//! what makes every record in both comparable one for one — and a record-level comparison is the
//! sharpest evidence a from-scratch writer can be held to.
//!
//! # What a chunk's length comes from
//!
//! Every length below is measured from the pinned baseline rather than transcribed, and the
//! rules have one shape: a preferred length per kind of block group, capped at a tenth of the
//! volume, floored at a minimum that depends on the kind, and rounded down to
//! [`STRIPE_LEN`]. The one surprise in them is that **the per-kind rule applies only where the
//! block group is replicated**: an unmirrored chunk of any kind takes one generic rule instead,
//! so an unmirrored data chunk is eight mebibytes where a mirrored one runs to a gibibyte.
//! [`chunk_length`] is where that is written down.

use super::MappedChunk;
use super::btree::levels_above;
use super::ondisk::{
    BlockGroupFlags, ChecksumType, Chunk, CompatRoFlags, DevItem, DirItem, Header, IncompatFlags,
    InodeItem, InodeRef, Item, KeyPtr, MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, MIRRORS, RootItem, Stripe,
    holds_mirror,
};

#[cfg(feature = "serde")]
use serde::Serialize;

/// Bytes at the start of the device that no chunk may claim.
///
/// The first superblock sits at 64 KiB, inside this span. Nothing else in it is addressed.
pub const RESERVED_HEAD: u64 = 1 << 20;

/// The granularity a chunk's length is rounded down to.
///
/// The format records it per chunk and every implementation writes this value; a length that is
/// not a whole number of them is one no driver's allocator produces.
pub const STRIPE_LEN: u64 = 64 << 10;

/// The length of the system chunk a filesystem is bootstrapped with.
///
/// Fixed rather than derived: it is laid down before there is a filesystem to take a share of.
pub const BOOTSTRAP_SYSTEM_CHUNK: u64 = 4 << 20;

/// The share of the volume no single chunk may exceed, as a divisor.
///
/// A tenth. It is what keeps a chunk on a small volume from being most of it.
pub const VOLUME_SHARE: u64 = 10;

/// The volume length above which a mirrored metadata chunk is allowed to reach a gibibyte
/// rather than a quarter of one.
pub const LARGE_VOLUME: u64 = 50 << 30;

/// The node size a filesystem takes where a caller names none and the sector is smaller.
pub const DEFAULT_NODE_SIZE: u32 = 16 << 10;

/// The sector size a filesystem takes where a caller names none.
///
/// The format's own tooling takes the page size of the machine it runs on, which makes its
/// output depend on where it ran. A planner whose contract is reproducibility cannot: the
/// default here is a value, so two runs on two architectures plan the same filesystem.
pub const DEFAULT_SECTOR_SIZE: u32 = 4096;

/// How a block group is replicated across the one device an image is.
///
/// The format defines striped and parity profiles besides, and each of them needs more than one
/// device to read — so they are absent here rather than refused: a layout that cannot be
/// expressed cannot be asked for by mistake.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub enum Profile {
    /// One copy.
    #[default]
    Single,
    /// Two copies on the one device, which is what protects metadata against a bad sector.
    Dup,
}

impl Profile {
    /// How many copies of each byte the device carries.
    #[must_use]
    pub const fn copies(self) -> u64 {
        match self {
            Self::Single => 1,
            Self::Dup => 2,
        }
    }

    /// The bit the format records this profile as, or an empty set for the unreplicated one.
    #[must_use]
    pub const fn flag(self) -> BlockGroupFlags {
        match self {
            Self::Single => BlockGroupFlags::from_bits(0),
            Self::Dup => BlockGroupFlags::DUP,
        }
    }
}

// The words the format's own tooling names these two by, so a profile read off a report is one
// a caller can ask for.
crate::naming::named_choice!(Profile {
    Profile::Single => "single",
    Profile::Dup => "dup",
});

/// The size of the smallest addressable unit of file data.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum SectorSize {
    /// [`DEFAULT_SECTOR_SIZE`].
    #[default]
    Auto,
    /// Exactly this many bytes: a power of two between [`MIN_BLOCK_SIZE`] and
    /// [`MAX_BLOCK_SIZE`].
    Bytes(u32),
}

/// The size of a tree block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum NodeSize {
    /// [`DEFAULT_NODE_SIZE`], or the sector size where that is larger.
    #[default]
    Auto,
    /// Exactly this many bytes: a power of two, at least the sector size, and at most
    /// [`MAX_BLOCK_SIZE`].
    Bytes(u32),
}

/// How much a filesystem will be given, in the counts a metadata bound is computed from.
///
/// Every field is a count of records rather than of bytes on a host, because what metadata
/// costs is records: a file of one byte and a file of one mebibyte differ by their extents and
/// their checksums, not by their inodes. [`Content::EMPTY`] is a filesystem with nothing in it
/// but its own root directory, which is what an empty image is planned from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub struct Content {
    /// Directories, the root of each subvolume included.
    pub directories: u64,
    /// Files, symbolic links, and device, FIFO, and socket nodes.
    pub files: u64,
    /// Names, counted across every directory. A file with two links contributes two.
    pub names: u64,
    /// The longest name any of them is, in bytes. A bound needs the worst case, not the mean.
    pub longest_name: u32,
    /// The largest single value a record must carry beside a name, in bytes.
    ///
    /// An extended attribute's value, a symbolic link's target, or a file small enough to be
    /// stored inside the metadata — whichever of them is longest. One field rather than three,
    /// because what the bound needs is the widest record any of them produces and the three
    /// produce records of the same shape.
    pub longest_value: u64,
    /// Extended attributes, counted across every object.
    pub xattrs: u64,
    /// Subvolumes beyond the one every filesystem has.
    pub subvolumes: u64,
    /// Bytes of file data that will be stored in data extents rather than inside the metadata.
    pub data_bytes: u64,
    /// Extents those bytes will be split into.
    pub data_extents: u64,
}

impl Content {
    /// A filesystem holding nothing but the root directory of its one subvolume.
    pub const EMPTY: Self = Self {
        directories: 1,
        files: 0,
        names: 0,
        longest_name: 0,
        longest_value: 0,
        xattrs: 0,
        subvolumes: 0,
        data_bytes: 0,
        data_extents: 0,
    };
}

/// How many metadata blocks a layout is allowed to consume, and how many the system chunk is.
///
/// The number is a **bound and not an estimate**. The tree that records every allocated extent
/// records its own blocks too, so its size depends on its content — a circular dependency that
/// is resolved here by reserving generously and holding the writer to it, rather than by
/// iterating to a fixpoint that might not converge. A bound that turns out too small is an
/// assertion through [`Reservation::account`]; blocks reserved and not spent are free space in
/// the finished filesystem, which is not a defect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub struct Reservation {
    /// Tree blocks the metadata block groups may hold.
    pub metadata_blocks: u64,
    /// Tree blocks the system block group may hold — the chunk tree, and nothing else.
    pub system_blocks: u64,
    /// The size of each of them, which is what turns either count into bytes.
    pub node_size: u32,
}

impl Reservation {
    /// Bytes of logical space the metadata blocks occupy.
    ///
    /// Saturating, for the reason the block count itself saturates: nothing bounds the content
    /// a caller describes, and a byte count that wrapped would be smaller than the blocks it is
    /// counting. What follows a saturated number is a volume that cannot hold it.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        self.metadata_blocks.saturating_mul(self.node_size as u64)
    }

    /// Bytes of logical space the system blocks occupy.
    #[must_use]
    pub const fn system_bytes(&self) -> u64 {
        self.system_blocks.saturating_mul(self.node_size as u64)
    }

    /// Hold a finished filesystem to what was reserved for it, and report the slack.
    ///
    /// This is the other half of reserving generously: a bound nobody checks is a guess. A
    /// writer calls this once it has emitted everything, and the answer is either how many
    /// blocks it did not need or the fact that the bound was wrong.
    ///
    /// **Both pools at once**, because there are two and either can be the one that was too
    /// small. The system pool holds the chunk tree alone, which is one leaf on a small
    /// filesystem and is not on a large one: a chunk record is a hundred and twelve bytes and a
    /// volume with tens of thousands of chunks has a chunk tree of megabytes, against a system
    /// block group whose ceiling is sixteen.
    ///
    /// # Errors
    ///
    /// [`ReservationExceeded`] where more blocks were spent than reserved from either pool,
    /// naming which pool and both counts. That is a defect in the bound rather than in the
    /// filesystem, and it is reported rather than absorbed because a bound that silently grows
    /// is not a bound.
    pub const fn account(
        &self,
        metadata_blocks_used: u64,
        system_blocks_used: u64,
    ) -> Result<Slack, ReservationExceeded> {
        let Some(metadata_blocks) = self.metadata_blocks.checked_sub(metadata_blocks_used) else {
            return Err(ReservationExceeded {
                pool: Pool::Metadata,
                reserved: self.metadata_blocks,
                used: metadata_blocks_used,
            });
        };
        let Some(system_blocks) = self.system_blocks.checked_sub(system_blocks_used) else {
            return Err(ReservationExceeded {
                pool: Pool::System,
                reserved: self.system_blocks,
                used: system_blocks_used,
            });
        };
        Ok(Slack {
            metadata_blocks,
            system_blocks,
        })
    }
}

/// Which of a [`Reservation`]'s two pools a count is about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub enum Pool {
    /// Every tree but the chunk tree.
    Metadata,
    /// The chunk tree, which lives in a block group of its own so that the map can be read
    /// before the map has been read.
    System,
}

impl Pool {
    /// The name this pool is known by.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::System => "system",
        }
    }
}

/// Blocks reserved and not spent, per pool.
///
/// Free space in the finished filesystem rather than waste: a driver allocates from a block
/// group's unused part exactly as it allocates from any other free space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub struct Slack {
    /// Metadata blocks reserved and not spent.
    pub metadata_blocks: u64,
    /// System blocks reserved and not spent.
    pub system_blocks: u64,
}

/// A filesystem that consumed more blocks than were reserved for it, from one of the two pools.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("the {} reservation of {reserved} blocks was exceeded: {used} were spent", pool.name())]
#[non_exhaustive]
pub struct ReservationExceeded {
    /// Which pool ran out.
    pub pool: Pool,
    /// Blocks the planner reserved from it.
    pub reserved: u64,
    /// Blocks the writer spent from it.
    pub used: u64,
}

/// A geometry that cannot be realized.
///
/// Not [`Copy`], where every other refusal this family produces from a request is: naming the
/// features a caller asked for and cannot have costs a string, and a refusal a person reads is
/// worth more than a value a caller can duplicate without saying so.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GeometryError {
    /// The sector size is not one the format defines.
    #[error(
        "sector size {bytes} is not a power of two between {MIN_BLOCK_SIZE} and {MAX_BLOCK_SIZE}"
    )]
    #[non_exhaustive]
    SectorSizeUnsupported {
        /// The size requested, in bytes.
        bytes: u32,
    },
    /// The node size is not one the format defines, or is smaller than a sector.
    ///
    /// A tree block smaller than the unit the device addresses cannot be written atomically,
    /// which is why the floor is the sector rather than the format's own minimum.
    #[error(
        "node size {bytes} is not a power of two between the {sector_size}-byte sector and \
         {MAX_BLOCK_SIZE}"
    )]
    #[non_exhaustive]
    NodeSizeUnsupported {
        /// The size requested, in bytes.
        bytes: u32,
        /// The sector size it has to be at least as large as.
        sector_size: u32,
    },
    /// The volume is too small to hold the chunks the requested profiles need.
    ///
    /// The two ways out are a larger volume and unreplicated metadata, and the difference
    /// between the two numbers says how much either would have to change: mirroring metadata
    /// costs a fixed sixty-four mebibytes more than not mirroring it, whatever the volume.
    #[error(
        "a volume of {volume_bytes} bytes is too small: {minimum} are needed for the chunks \
         these profiles require"
    )]
    #[non_exhaustive]
    VolumeTooSmall {
        /// The volume, in bytes.
        volume_bytes: u64,
        /// The fewest bytes these profiles can be laid out in.
        minimum: u64,
    },
    /// The content will not fit in the volume it was planned for.
    ///
    /// Distinct from [`VolumeTooSmall`](Self::VolumeTooSmall), which is about the empty
    /// filesystem's own overhead: this one is reached where the volume is large enough to be
    /// formatted and too small to hold what it was told it would be given.
    #[error(
        "a volume of {volume_bytes} bytes cannot hold this content: the chunks it needs span \
         {needed} bytes"
    )]
    #[non_exhaustive]
    ContentTooLarge {
        /// The volume, in bytes.
        volume_bytes: u64,
        /// Bytes of the device the planned chunks would occupy.
        needed: u64,
    },
    /// The chunk map outgrew the one system chunk that records it.
    ///
    /// Every chunk the layout keeps is a record in the chunk tree, and the chunk tree lives in
    /// the system block group — one chunk, laid down before the content's chunks exist, whose
    /// length is fixed by the volume and the metadata profile. Content large enough needs more
    /// chunk records than that chunk's blocks can hold, and the refusal is issued here, while
    /// the map is still arithmetic, rather than discovered by a writer that has already emitted
    /// the content. The ceiling grows with the volume and with metadata replication; within
    /// them, the way out is less content.
    #[error(
        "this content needs {chunks} chunks, whose records need {needed_blocks} tree blocks, \
         and the system chunk holds {available_blocks}"
    )]
    #[non_exhaustive]
    ChunkMapTooLarge {
        /// Chunks the layout would keep.
        chunks: u64,
        /// Tree blocks their records need.
        needed_blocks: u64,
        /// Tree blocks the system chunk holds.
        available_blocks: u64,
    },
    /// A feature was asked for that this crate does not write.
    ///
    /// The `incompat` word is the format telling a reader in advance that the on-disk form
    /// differs from what a reader without the bit expects, so writing a filesystem that claims
    /// one this crate does not implement would produce an image no reader could trust. The
    /// refusal names the bits rather than the first of them, because a caller that asked for
    /// three unsupported features should learn about three.
    ///
    /// Named as well as numbered, and both halves are load-bearing: the words are what a
    /// caller asked for and what they would have to stop asking for, and the bits cover the
    /// one a later release of the format defines and this one has no word for.
    #[error("this crate does not write {names} ({bits:#x})")]
    #[non_exhaustive]
    FeatureUnsupported {
        /// The bits of the word that have no implementation here.
        bits: u64,
        /// The same bits, named — each as the word this crate reads for it, and each the
        /// format has not defined as its position.
        names: String,
    },
    /// A feature was asked for whose own prerequisites were not.
    ///
    /// Recording block groups in a tree of their own is defined only for a filesystem that
    /// also keeps free space in a tree and records holes by their absence, so the three are
    /// asked for together or not at all. This is refused rather than quietly dropped: a
    /// filesystem built without a feature its caller named is a filesystem other than the one
    /// that was described.
    #[error("the {feature} feature also requires {requires}")]
    #[non_exhaustive]
    FeatureIncoherent {
        /// The feature that was asked for.
        feature: &'static str,
        /// What it rests on and did not get.
        requires: &'static str,
    },
}

/// Every `incompat` bit this crate writes.
///
/// Narrower than [`SUPPORTED_INCOMPAT`](super::SUPPORTED_INCOMPAT), which is what it *reads*,
/// and the two are named apart because they answer different questions: reading a filesystem
/// carrying a feature needs the feature's on-disk form to be understood, and writing one needs
/// it to be produced. A bit outside this set is [`GeometryError::FeatureUnsupported`].
pub const WRITABLE_INCOMPAT: IncompatFlags = IncompatFlags::from_bits(
    IncompatFlags::MIXED_BACKREF.bits()
        | IncompatFlags::DEFAULT_SUBVOL.bits()
        | IncompatFlags::BIG_METADATA.bits()
        | IncompatFlags::EXTENDED_IREF.bits()
        | IncompatFlags::SKINNY_METADATA.bits()
        | IncompatFlags::NO_HOLES.bits()
        | IncompatFlags::METADATA_UUID.bits(),
);

/// Every `compat_ro` bit this crate writes.
pub const WRITABLE_COMPAT_RO: CompatRoFlags = CompatRoFlags::from_bits(
    CompatRoFlags::FREE_SPACE_TREE.bits()
        | CompatRoFlags::FREE_SPACE_TREE_VALID.bits()
        | CompatRoFlags::BLOCK_GROUP_TREE.bits(),
);

/// The `incompat` word a filesystem takes where a caller names none.
///
/// `BIG_METADATA` is absent here and set by the planner instead: the format defines it as
/// tree blocks being larger than the four kibibytes they were originally fixed at, so it is a
/// consequence of the node size rather than a choice.
pub const DEFAULT_INCOMPAT: IncompatFlags = IncompatFlags::from_bits(
    IncompatFlags::MIXED_BACKREF.bits()
        | IncompatFlags::EXTENDED_IREF.bits()
        | IncompatFlags::SKINNY_METADATA.bits()
        | IncompatFlags::NO_HOLES.bits(),
);

/// The `compat_ro` word a filesystem takes where a caller names none.
pub const DEFAULT_COMPAT_RO: CompatRoFlags = WRITABLE_COMPAT_RO;

/// How metadata and system block groups are replicated where a caller names nothing.
pub const DEFAULT_METADATA_PROFILE: Profile = Profile::Dup;

/// How data block groups are replicated where a caller names nothing.
pub const DEFAULT_DATA_PROFILE: Profile = Profile::Single;

/// What a caller states about the filesystem to be planned.
///
/// Built from a volume length and refined by the methods below, each of which consumes and
/// returns the request so a call reads as one expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PlanRequest {
    /// The device the filesystem will occupy the whole of, in bytes.
    pub volume_bytes: u64,
    /// The smallest addressable unit of file data.
    pub sector_size: SectorSize,
    /// The size of a tree block.
    pub node_size: NodeSize,
    /// How metadata and system block groups are replicated. One choice covers both: the
    /// format's own tooling replicates the chunk tree exactly as it replicates the rest of the
    /// metadata, and a filesystem whose chunk tree is less protected than its inodes is
    /// protected by neither.
    pub metadata_profile: Profile,
    /// How data block groups are replicated.
    pub data_profile: Profile,
    /// Features whose on-disk form a reader must understand.
    pub incompat_flags: IncompatFlags,
    /// Features a reader may ignore as long as it never writes.
    pub compat_ro_flags: CompatRoFlags,
    /// What the filesystem will be given.
    pub content: Content,
}

impl PlanRequest {
    /// A request for a volume this many bytes long, at every default.
    #[must_use]
    pub const fn new(volume_bytes: u64) -> Self {
        Self {
            volume_bytes,
            sector_size: SectorSize::Auto,
            node_size: NodeSize::Auto,
            metadata_profile: DEFAULT_METADATA_PROFILE,
            data_profile: DEFAULT_DATA_PROFILE,
            incompat_flags: DEFAULT_INCOMPAT,
            compat_ro_flags: DEFAULT_COMPAT_RO,
            content: Content::EMPTY,
        }
    }

    /// Name the sector size.
    #[must_use]
    pub const fn sector_size(mut self, size: SectorSize) -> Self {
        self.sector_size = size;
        self
    }

    /// Name the node size.
    #[must_use]
    pub const fn node_size(mut self, size: NodeSize) -> Self {
        self.node_size = size;
        self
    }

    /// Name how metadata and system block groups are replicated.
    #[must_use]
    pub const fn metadata_profile(mut self, profile: Profile) -> Self {
        self.metadata_profile = profile;
        self
    }

    /// Name how data block groups are replicated.
    #[must_use]
    pub const fn data_profile(mut self, profile: Profile) -> Self {
        self.data_profile = profile;
        self
    }

    /// Name the two feature words.
    #[must_use]
    pub const fn features(mut self, incompat: IncompatFlags, compat_ro: CompatRoFlags) -> Self {
        self.incompat_flags = incompat;
        self.compat_ro_flags = compat_ro;
        self
    }

    /// Name what the filesystem will be given.
    #[must_use]
    pub const fn content(mut self, content: Content) -> Self {
        self.content = content;
        self
    }
}

/// Everything about a filesystem that is decided before a byte of it is written.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct BtrfsLayout {
    /// The device the filesystem occupies the whole of, in bytes.
    pub volume_bytes: u64,
    /// The smallest addressable unit of file data.
    pub sector_size: u32,
    /// The size of a tree block.
    pub node_size: u32,
    /// Features whose on-disk form a reader must understand, the ones the geometry implies
    /// included.
    pub incompat_flags: IncompatFlags,
    /// Features a reader may ignore as long as it never writes.
    pub compat_ro_flags: CompatRoFlags,
    /// Every chunk, in ascending logical order, with the device offset of each copy.
    ///
    /// The same shape the reader builds its map out of, so a plan can be translated through
    /// the one address-translation path this crate has rather than through a second one.
    pub chunks: Vec<MappedChunk>,
    /// Where each superblock copy the device has room for begins, in ascending order.
    pub superblock_mirrors: Vec<u64>,
    /// How much metadata the filesystem may spend.
    pub reservation: Reservation,
}

impl BtrfsLayout {
    /// Bytes of the device the chunks occupy, every copy counted.
    ///
    /// This is what a device record's used-bytes field holds: a mirrored chunk consumes twice
    /// its length, and the unallocated spans between chunks are not counted at all.
    #[must_use]
    pub fn device_bytes_used(&self) -> u64 {
        self.chunks
            .iter()
            .map(|chunk| chunk.length * chunk.copies.len() as u64)
            .sum()
    }

    /// One past the highest logical address any chunk covers.
    #[must_use]
    pub fn logical_end(&self) -> u64 {
        self.chunks
            .last()
            .map_or(RESERVED_HEAD, MappedChunk::logical_end)
    }

    /// Every chunk holding this kind of block group, in ascending logical order.
    pub fn chunks_of(&self, kind: BlockGroupFlags) -> impl Iterator<Item = &MappedChunk> {
        self.chunks
            .iter()
            .filter(move |chunk| chunk.flags.contains(kind))
    }
}

/// Plan a filesystem.
///
/// # Errors
///
/// [`GeometryError`], for a sector or node size the format does not define, a volume too small
/// for the profiles asked of it, content too large for the volume, a feature this crate does
/// not write, or a feature asked for without what it rests on.
pub fn plan_layout(request: &PlanRequest) -> Result<BtrfsLayout, GeometryError> {
    let (sector_size, node_size) = block_sizes(request)?;

    let incompat = validated_features(request, node_size)?;
    let compat_ro = request.compat_ro_flags;

    let minimum = minimum_volume_bytes(request.metadata_profile, request.data_profile);
    if request.volume_bytes < minimum {
        return Err(GeometryError::VolumeTooSmall {
            volume_bytes: request.volume_bytes,
            minimum,
        });
    }

    let metadata_blocks = reserve_metadata(request, sector_size, node_size, compat_ro);
    let pending = pending_chunks(
        request,
        metadata_blocks.saturating_mul(u64::from(node_size)),
    )?;
    let reservation = Reservation {
        metadata_blocks,
        system_blocks: reserve_system(&pending, node_size)?,
        node_size,
    };
    let chunks = place_pending(pending, request.volume_bytes);

    let superblock_mirrors = MIRRORS
        .iter()
        .copied()
        .filter(|&at| holds_mirror(request.volume_bytes, at))
        .collect();

    Ok(BtrfsLayout {
        volume_bytes: request.volume_bytes,
        sector_size,
        node_size,
        incompat_flags: incompat,
        compat_ro_flags: compat_ro,
        chunks,
        superblock_mirrors,
        reservation,
    })
}

/// The sector and node sizes a request resolves to, each validated.
///
/// Separate from [`plan_layout`] because a populated format needs both **before** it has a
/// layout: which files are small enough to live inside the metadata depends on the sector, and
/// what one record may weigh depends on the node — and those decisions are what the planner is
/// then told about. Two derivations of the defaulting rule would be two rules.
///
/// # Errors
///
/// [`GeometryError::SectorSizeUnsupported`] or [`GeometryError::NodeSizeUnsupported`] for a size
/// the format does not define, or a node smaller than a sector.
pub fn block_sizes(request: &PlanRequest) -> Result<(u32, u32), GeometryError> {
    let sector_size = match request.sector_size {
        SectorSize::Auto => DEFAULT_SECTOR_SIZE,
        SectorSize::Bytes(bytes) => bytes,
    };
    if !is_block_size(sector_size) {
        return Err(GeometryError::SectorSizeUnsupported { bytes: sector_size });
    }
    let node_size = match request.node_size {
        NodeSize::Auto => DEFAULT_NODE_SIZE.max(sector_size),
        NodeSize::Bytes(bytes) => bytes,
    };
    if !is_block_size(node_size) || node_size < sector_size {
        return Err(GeometryError::NodeSizeUnsupported {
            bytes: node_size,
            sector_size,
        });
    }
    Ok((sector_size, node_size))
}

/// Whether a size is one the format accepts for a sector or a node.
const fn is_block_size(bytes: u32) -> bool {
    bytes.is_power_of_two() && bytes >= MIN_BLOCK_SIZE && bytes <= MAX_BLOCK_SIZE
}

/// The feature words a filesystem will carry, with what the geometry implies folded in.
///
/// Two things happen here that a caller cannot state. `BIG_METADATA` is set exactly where a
/// tree block exceeds the four kibibytes the format originally fixed them at, so it follows
/// from the node size rather than from a request — a word written per request would be wrong
/// on the one node size where the bit does not belong and right by transcription everywhere
/// else. And a feature whose prerequisites were not asked for is refused rather than dropped.
fn validated_features(
    request: &PlanRequest,
    node_size: u32,
) -> Result<IncompatFlags, GeometryError> {
    let unsupported = request.incompat_flags.without(WRITABLE_INCOMPAT);
    if !unsupported.is_empty() {
        let mut names = String::new();
        unsupported.describe(&mut names);
        return Err(GeometryError::FeatureUnsupported {
            bits: unsupported.bits(),
            names,
        });
    }
    let unsupported_ro = request.compat_ro_flags.without(WRITABLE_COMPAT_RO);
    if !unsupported_ro.is_empty() {
        let mut names = String::new();
        unsupported_ro.describe(&mut names);
        return Err(GeometryError::FeatureUnsupported {
            bits: unsupported_ro.bits(),
            names,
        });
    }

    if request
        .compat_ro_flags
        .contains(CompatRoFlags::BLOCK_GROUP_TREE)
    {
        if !request
            .compat_ro_flags
            .contains(CompatRoFlags::FREE_SPACE_TREE)
        {
            return Err(GeometryError::FeatureIncoherent {
                feature: "block-group-tree",
                requires: "free-space-tree",
            });
        }
        if !request.incompat_flags.contains(IncompatFlags::NO_HOLES) {
            return Err(GeometryError::FeatureIncoherent {
                feature: "block-group-tree",
                requires: "no-holes",
            });
        }
    }

    // The wide-block bit is what a node size larger than the four kibibytes the format
    // originally fixed tree blocks at *means*, so it is set from the geometry rather than from
    // the request. A caller that asked for it at the one node size where it does not belong
    // asked for something the format does not define, and is told so — clearing it quietly
    // would be the same silent drop this function refuses a paragraph above.
    let mut incompat = request.incompat_flags;
    if node_size > MIN_BLOCK_SIZE {
        incompat |= IncompatFlags::BIG_METADATA;
    } else if incompat.contains(IncompatFlags::BIG_METADATA) {
        return Err(GeometryError::FeatureIncoherent {
            feature: "big-metadata",
            requires: "a node larger than four kibibytes",
        });
    }
    Ok(incompat)
}

/// The fewest bytes a volume can be and still hold these profiles' chunks.
///
/// Conservative by construction: it charges for every chunk laid down on the way to the
/// finished filesystem, including the ones whose replication turns out wrong and are replaced,
/// and it charges each at the largest length its rule can produce. A volume that clears this
/// bound is one the layout fits in with room to spare.
#[must_use]
pub const fn minimum_volume_bytes(metadata: Profile, data: Profile) -> u64 {
    // The reserved head, the bootstrap system chunk, and the two unmirrored chunks that are
    // laid down before any profile is known — eight mebibytes each.
    let bootstrap = RESERVED_HEAD + BOOTSTRAP_SYSTEM_CHUNK + 2 * (8 << 20);
    // A mirrored metadata chunk cannot be smaller than thirty-two mebibytes, and each of its
    // two copies costs that; an unmirrored one is eight.
    let metadata_bytes = match metadata {
        Profile::Dup => 2 * ((8 << 20) + (32 << 20)),
        Profile::Single => (8 << 20) + (8 << 20),
    };
    // A mirrored data chunk cannot be smaller than sixty-four mebibytes a copy.
    let data_bytes = match data {
        Profile::Dup => 2 * (64 << 20),
        Profile::Single => 8 << 20,
    };
    bootstrap + metadata_bytes + data_bytes
}

/// The length of one chunk, as the format's own allocator derives it.
///
/// A preferred length, capped at a share of the volume, floored at a minimum, and rounded down
/// to whole stripes. The preferences and both bounds depend on what the chunk holds — but
/// **only where it is replicated**: an unreplicated chunk of any kind takes the generic rule,
/// which is why an unreplicated data chunk is eight mebibytes on a volume where a replicated
/// one is a gibibyte.
#[must_use]
pub const fn chunk_length(kind: BlockGroupFlags, profile: Profile, volume_bytes: u64) -> u64 {
    // The generic rule, and the whole of the rule for an unreplicated chunk.
    let mut preferred: u64 = 8 << 20;
    let mut min_length: u64 = 1 << 20;
    let mut max_length: u64 = 32 << 20;

    if matches!(profile, Profile::Dup) {
        if kind.contains(BlockGroupFlags::SYSTEM) {
            max_length = 16 << 20;
        } else if kind.contains(BlockGroupFlags::DATA) {
            preferred = 1 << 30;
            max_length = 10 << 30;
            min_length = 64 << 20;
        } else if kind.contains(BlockGroupFlags::METADATA) {
            max_length = if volume_bytes > LARGE_VOLUME {
                1 << 30
            } else {
                256 << 20
            };
            preferred = max_length;
            min_length = 32 << 20;
        }
    }

    let share = volume_bytes / VOLUME_SHARE;
    if share < max_length {
        max_length = share;
    }
    let mut length = preferred;
    if length > max_length {
        length = round_down(max_length / profile.copies(), STRIPE_LEN);
    }
    if length < min_length {
        length = min_length;
    }
    round_down(length, STRIPE_LEN)
}

/// `value` rounded down to a whole number of `unit`s.
const fn round_down(value: u64, unit: u64) -> u64 {
    value - value % unit
}

/// One chunk to be laid down, before its address is known.
struct Pending {
    kind: BlockGroupFlags,
    profile: Profile,
    length: u64,
    /// Whether the finished filesystem keeps it. A chunk laid down to bootstrap the filesystem
    /// and replaced once its replication is known is placed — it moves both cursors — and then
    /// dropped, which is what leaves an unallocated span where it was.
    keep: bool,
}

/// Every chunk to be laid down, in the order the format's own tooling arrives at, before any
/// has an address.
///
/// This list is what the system reservation is derived from as well as what placement consumes:
/// the metadata bound decides how many extra chunks the content appends here, and the chunks
/// appended here decide how large the chunk tree recording them must be. Computing the list
/// once, ahead of placement, is what lets both read the same count.
fn pending_chunks(
    request: &PlanRequest,
    metadata_bytes: u64,
) -> Result<Vec<Pending>, GeometryError> {
    let volume = request.volume_bytes;
    let metadata = request.metadata_profile;
    let data = request.data_profile;
    let keeps_bootstrap_metadata = matches!(metadata, Profile::Single);
    let keeps_bootstrap_data = matches!(data, Profile::Single);

    let system = BlockGroupFlags::SYSTEM;
    let meta = BlockGroupFlags::METADATA;
    let dat = BlockGroupFlags::DATA;

    let mut pending = Vec::new();
    // The filesystem is bootstrapped through unreplicated chunks, because there is no tree to
    // record a replicated one in until there is somewhere to put the tree.
    pending.push(Pending {
        kind: system,
        profile: Profile::Single,
        length: BOOTSTRAP_SYSTEM_CHUNK,
        keep: keeps_bootstrap_metadata,
    });
    pending.push(Pending {
        kind: meta,
        profile: Profile::Single,
        length: chunk_length(meta, Profile::Single, volume),
        keep: keeps_bootstrap_metadata,
    });
    pending.push(Pending {
        kind: dat,
        profile: Profile::Single,
        length: chunk_length(dat, Profile::Single, volume),
        keep: keeps_bootstrap_data,
    });
    // Then the replicated ones, for whichever of the two kinds asked for replication. Each
    // replaces the bootstrap chunk of its kind rather than joining it.
    if !keeps_bootstrap_metadata {
        pending.push(Pending {
            kind: system,
            profile: metadata,
            length: chunk_length(system, metadata, volume),
            keep: true,
        });
        pending.push(Pending {
            kind: meta,
            profile: metadata,
            length: chunk_length(meta, metadata, volume),
            keep: true,
        });
    }
    if !keeps_bootstrap_data {
        pending.push(Pending {
            kind: dat,
            profile: data,
            length: chunk_length(dat, data, volume),
            keep: true,
        });
    }

    // What the content needs beyond the one chunk of each kind laid down above. An empty
    // filesystem needs none of it, which is what makes its layout the baseline's exactly.
    //
    // How many are needed is worked out as arithmetic and the device space they would take is
    // checked **before** any of them exists. Doing it the other way — appending chunks and
    // measuring afterwards — means a caller who names more content than any device could hold
    // gets an answer only after the planner has tried to build a chunk for every gibibyte of
    // it, and the refusal it was owed is a computation that does not end.
    let held = |kind: BlockGroupFlags| -> u64 {
        pending
            .iter()
            .filter(|entry| entry.keep && entry.kind.contains(kind))
            .map(|entry| entry.length)
            .sum()
    };
    let metadata_each = chunk_length(meta, metadata, volume);
    let extra_metadata = shortfall(metadata_bytes, held(meta), metadata_each);
    let data_each = chunk_length(dat, data, volume);
    let extra_data = shortfall(request.content.data_bytes, held(dat), data_each);

    let placed: u64 = pending
        .iter()
        .map(|entry| entry.length * entry.profile.copies())
        .sum();
    let needed = extra_metadata
        .checked_mul(metadata_each * metadata.copies())
        .and_then(|bytes| bytes.checked_add(extra_data.checked_mul(data_each * data.copies())?))
        .and_then(|bytes| bytes.checked_add(placed + RESERVED_HEAD));
    match needed {
        Some(needed) if needed <= volume => {}
        // An overflow is the same answer as a span past the end of the device, and saying so
        // needs a number: the volume is what the content did not fit in either way.
        _ => {
            return Err(GeometryError::ContentTooLarge {
                volume_bytes: volume,
                needed: needed.unwrap_or(u64::MAX),
            });
        }
    }

    for (count, kind, profile, length) in [
        (extra_metadata, meta, metadata, metadata_each),
        (extra_data, dat, data, data_each),
    ] {
        for _ in 0..count {
            pending.push(Pending {
                kind,
                profile,
                length,
                keep: true,
            });
        }
    }
    Ok(pending)
}

/// Lay every pending chunk out, advancing the logical and device cursors together.
fn place_pending(pending: Vec<Pending>, volume: u64) -> Vec<MappedChunk> {
    let mut chunks = Vec::with_capacity(pending.len());
    let mut logical = RESERVED_HEAD;
    let mut physical = RESERVED_HEAD;
    for entry in pending {
        let copies = entry.profile.copies();
        if entry.keep {
            chunks.push(MappedChunk {
                logical,
                length: entry.length,
                flags: entry.kind | entry.profile.flag(),
                copies: (0..copies).map(|n| physical + n * entry.length).collect(),
            });
        }
        logical += entry.length;
        physical += entry.length * copies;
    }
    debug_assert!(
        physical <= volume,
        "the span was checked before it was placed"
    );
    chunks
}

/// How many chunks of `each` bytes it takes to cover what `held` leaves of `needed`.
///
/// Zero where what is held already covers it, which is every empty filesystem.
const fn shortfall(needed: u64, held: u64, each: u64) -> u64 {
    match needed.checked_sub(held) {
        Some(0) | None => 0,
        Some(short) => short.div_ceil(each),
    }
}

// ---------------------------------------------------------------------------
// The metadata bound
//
// Every tree is bounded the same way: count the records it will hold and the largest each can
// be, divide into leaves, and add the internal nodes above them. The extent tree is the one
// exception and it has a section of its own below.

/// Records of `record_bytes` each, in blocks of `node_size`, leaves and internal nodes both.
fn blocks_for(records: u64, record_bytes: u64, node_size: u32) -> u64 {
    if records == 0 {
        // A tree with nothing in it is still a tree: it has a root, and the root is a block.
        return 1;
    }
    let capacity = u64::from(node_size) - Header::SIZE as u64;
    let per_leaf = (capacity / (Item::SIZE as u64 + record_bytes)).max(1);
    let leaves = records.div_ceil(per_leaf);
    levels_above(leaves, capacity / KeyPtr::SIZE as u64)
        .iter()
        .fold(leaves, |blocks, level| blocks.saturating_add(*level))
}

/// How many metadata blocks the filesystem may spend — every tree but the chunk tree, whose
/// pool is [`reserve_system`]'s.
///
/// The counts below are bounds rather than predictions, and each names the records it is
/// counting. Two of them are worth reading twice: the fs tree, because a name appears in three
/// records and a bound that counted it once would be short on every directory; and the extent
/// tree, because it records its own blocks.
///
/// Every sum here saturates. A count a caller states is a `u64` and nothing bounds one, so an
/// absurd content description has to produce an absurd bound rather than a wrapped one — a
/// bound that wrapped would be *small*, which is the one way a reservation can be wrong that
/// nothing downstream would notice until a writer had run out of room. What follows a saturated
/// bound is a volume that cannot hold it, which is a typed refusal.
fn reserve_metadata(
    request: &PlanRequest,
    sector_size: u32,
    node_size: u32,
    compat_ro: CompatRoFlags,
) -> u64 {
    let content = &request.content;
    let name_bytes = u64::from(content.longest_name);
    let subvolumes = content.subvolumes.saturating_add(1);

    // The root tree: a record naming every tree, plus the directory that names the subvolumes.
    // Six trees are always there — the extent, device, filesystem, checksum, uuid, and data
    // relocation trees — and the two that follow are the ones a feature bit adds. A subvolume
    // costs three records rather than one: its own root record, the name the root directory
    // holds for it, and the position that name sits at.
    let trees = 6
        + u64::from(compat_ro.contains(CompatRoFlags::FREE_SPACE_TREE))
        + u64::from(compat_ro.contains(CompatRoFlags::BLOCK_GROUP_TREE));
    // Four more: the root tree has a directory of its own, whose inode, name for its parent, and
    // entry naming the default subvolume are three records, and the top-level subvolume's
    // reference back to it is a fourth.
    let root_records = trees
        .saturating_add(subvolumes.saturating_mul(3))
        .saturating_add(4);
    let root_tree = blocks_for(root_records, RootItem::SIZE as u64, node_size);

    // Every filesystem tree together. An object costs one inode record, and each of its names
    // costs three: the reference the inode carries, a record keyed by the name's hash for
    // lookup, and a record keyed by its position for reading a directory in order. A bound that
    // charged a name once would be short by two thirds on every directory, and short is the
    // direction that fails.
    //
    // Each object is charged **twice**, because a file's bytes are a record of their own wherever
    // they are small enough to live in the metadata — and so is a symbolic link's target, always.
    // Neither is in `data_extents`, which counts only what reaches a data block group, so a tree
    // of small files holds a record in five that counting once does not reach. What has kept
    // that from mattering is the size each record is charged at, which is the widest any of them
    // can be and is several times what an inode record actually weighs — a bound short in its
    // *count* and long in its *size* still holds, until a tree turns up where the sizes are even.
    // Counting what is there is the bound the derivation was supposed to be.
    let fs_records = content
        .directories
        .saturating_add(content.files.saturating_mul(2))
        .saturating_add(content.names.saturating_mul(3))
        .saturating_add(content.xattrs)
        .saturating_add(content.data_extents);
    let fs_trees = blocks_for(
        fs_records,
        (InodeItem::SIZE as u64)
            .max(InodeRef::SIZE as u64 + name_bytes)
            .max(DirItem::SIZE as u64 + name_bytes + content.longest_value),
        node_size,
    )
    .saturating_add(subvolumes);

    // The checksum tree: four bytes for every sector of data, packed into as few records as the
    // leaves will hold.
    let csum_bytes = content
        .data_bytes
        .div_ceil(u64::from(sector_size))
        .saturating_mul(CSUM_BYTES_PER_SECTOR);
    let csum_tree = blocks_for(
        csum_bytes.div_ceil(MAX_CSUM_RECORD),
        MAX_CSUM_RECORD,
        node_size,
    );

    // The device tree, the block-group tree, the free-space tree, and the uuid tree are each
    // bounded by the chunk count or the subvolume count, both small.
    let small_trees =
        (3 * blocks_for(64, 64, node_size)).saturating_add(blocks_for(subvolumes, 32, node_size));

    let outside_extent_tree = root_tree
        .saturating_add(fs_trees)
        .saturating_add(csum_tree)
        .saturating_add(small_trees);

    // The extent tree records every allocated extent, its own blocks included, so its size
    // depends on its content. There is no fixpoint to iterate towards: if the rest of the
    // metadata is `outside` blocks and one leaf holds `per_leaf` records, a tree of `e` blocks
    // must record `outside + e` extents, so `e >= outside / (per_leaf - 1)` and the smallest
    // bound is that quotient rounded up. Charging each extent twice covers its back-reference.
    let capacity = u64::from(node_size) - Header::SIZE as u64;
    let per_leaf = (capacity / (Item::SIZE as u64 + EXTENT_RECORD_BYTES)).max(2);
    let outside_records = outside_extent_tree
        .saturating_add(content.data_extents)
        .saturating_mul(2);
    let extent_tree = blocks_for(
        outside_records.saturating_add(outside_records.div_ceil(per_leaf - 1)),
        EXTENT_RECORD_BYTES,
        node_size,
    );

    let total = outside_extent_tree.saturating_add(extent_tree);
    // The bound is deliberately loose rather than exact, which is what makes it a bound: the
    // margin covers a tree gaining a level from an unlucky split and the extent records the
    // extent tree's own internal nodes need. Blocks reserved and not spent are free space.
    total.saturating_add(total / 8).saturating_add(8)
}

/// How many system blocks the filesystem may spend — the chunk tree, and nothing else.
///
/// Derived from the chunks actually planned rather than fixed: the chunk tree holds one record
/// per kept chunk plus the device record, and the extra data chunks a populated filesystem
/// appends grow that count with the content. A bound fixed here would be the one kind of bound
/// that fails exactly when the content is large — after every block of it has been written.
///
/// The bound is also checked against the system chunk's own capacity while the map is still
/// arithmetic. That chunk is planned before the content's chunks exist, its length fixed by the
/// volume and the metadata profile, so a chunk map that outgrows it is refused as
/// [`GeometryError::ChunkMapTooLarge`] here rather than surfacing from the writer as an
/// exceeded reservation.
fn reserve_system(pending: &[Pending], node_size: u32) -> Result<u64, GeometryError> {
    let kept = || pending.iter().filter(|entry| entry.keep);
    // One record per kept chunk and one for the device, each charged at the widest record the
    // chunk tree will hold: a chunk record is a fixed head plus one stripe per copy.
    let chunks = kept().count() as u64;
    let record_bytes = kept()
        .map(|entry| Chunk::SIZE as u64 + entry.profile.copies() * Stripe::SIZE as u64)
        .max()
        .unwrap_or(Chunk::SIZE as u64)
        .max(DevItem::SIZE as u64);
    let needed_blocks = blocks_for(chunks.saturating_add(1), record_bytes, node_size);

    let available_blocks = kept()
        .find(|entry| entry.kind.contains(BlockGroupFlags::SYSTEM))
        .map_or(0, |entry| entry.length / u64::from(node_size));
    if needed_blocks > available_blocks {
        return Err(GeometryError::ChunkMapTooLarge {
            chunks,
            needed_blocks,
            available_blocks,
        });
    }
    Ok(needed_blocks)
}

/// Bytes of checksum a sector of data costs.
///
/// Read off the algorithm rather than written down, so a filesystem checksummed some other way
/// moves this number by moving the algorithm.
pub(crate) const CSUM_BYTES_PER_SECTOR: u64 =
    ChecksumType::CRC32C.digest_len().expect("crc32c has one") as u64;

/// The largest checksum record the writer emits, in bytes of checksum.
///
/// Checksums for consecutive sectors pack into one record, and a record is capped so that a leaf
/// holds more than one of them — at the smallest tree block the format defines, which is what
/// makes this a constant rather than a function of the node size. It is the writer's cap as well
/// as the bound's, so the reservation counts the records that are actually emitted.
pub(crate) const MAX_CSUM_RECORD: u64 = 2048;

/// The bytes an extent record and its back-reference occupy together.
const EXTENT_RECORD_BYTES: u64 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    /// The layout the pinned baseline writes to a one-gibibyte volume at its own defaults, read
    /// out of such an image. Every number here is a measurement rather than a derivation, which
    /// is what makes it worth asserting a derivation against.
    const BASELINE_1G_DEFAULT: &[(u64, u64, &[u64])] = &[
        (13_631_488, 8_388_608, &[13_631_488]),
        (22_020_096, 8_388_608, &[22_020_096, 30_408_704]),
        (30_408_704, 53_673_984, &[38_797_312, 92_471_296]),
    ];

    /// The same volume with nothing replicated, where the chunks laid down to bootstrap the
    /// filesystem are the ones it keeps.
    const BASELINE_1G_SINGLE: &[(u64, u64, &[u64])] = &[
        (1_048_576, 4_194_304, &[1_048_576]),
        (5_242_880, 8_388_608, &[5_242_880]),
        (13_631_488, 8_388_608, &[13_631_488]),
    ];

    fn shape(layout: &BtrfsLayout) -> Vec<(u64, u64, Vec<u64>)> {
        layout
            .chunks
            .iter()
            .map(|chunk| (chunk.logical, chunk.length, chunk.copies.clone()))
            .collect()
    }

    fn expected(rows: &[(u64, u64, &[u64])]) -> Vec<(u64, u64, Vec<u64>)> {
        rows.iter()
            .map(|&(logical, length, copies)| (logical, length, copies.to_vec()))
            .collect()
    }

    #[test]
    fn a_default_volume_is_laid_out_the_way_the_baseline_lays_one_out() {
        let layout = plan_layout(&PlanRequest::new(GIB)).expect("a gibibyte is formattable");
        assert_eq!(shape(&layout), expected(BASELINE_1G_DEFAULT));
        // What a device record's used-bytes field holds: every copy of every chunk, and none of
        // the unallocated space between them.
        assert_eq!(layout.device_bytes_used(), 132_513_792);
    }

    #[test]
    fn nothing_replicated_keeps_the_chunks_the_bootstrap_laid_down() {
        let layout = plan_layout(
            &PlanRequest::new(GIB)
                .metadata_profile(Profile::Single)
                .data_profile(Profile::Single),
        )
        .expect("a gibibyte is formattable");
        assert_eq!(shape(&layout), expected(BASELINE_1G_SINGLE));
        assert_eq!(layout.device_bytes_used(), 20_971_520);
        // Nothing was replaced, so the first chunk begins where the reserved head ends and
        // there is no unallocated span at all.
        assert_eq!(layout.chunks[0].logical, RESERVED_HEAD);
    }

    #[test]
    fn replicating_metadata_leaves_the_span_the_replaced_chunks_occupied() {
        let layout = plan_layout(&PlanRequest::new(GIB)).expect("a gibibyte is formattable");
        let first = layout.chunks[0].logical;
        // The reserved head, the bootstrap system chunk, and the bootstrap metadata chunk: the
        // last of those is replaced, and the span it held stays unallocated.
        assert_eq!(
            first,
            RESERVED_HEAD
                + BOOTSTRAP_SYSTEM_CHUNK
                + chunk_length(BlockGroupFlags::METADATA, Profile::Single, GIB,)
        );
        assert!(first > RESERVED_HEAD);
    }

    #[test]
    fn an_unreplicated_chunk_takes_the_generic_rule_whatever_it_holds() {
        // The one genuinely surprising rule in the allocator: the per-kind preference applies
        // only to a replicated chunk. An unreplicated data chunk is eight mebibytes on a volume
        // where a replicated one is a gibibyte, and reading the per-kind rule as though it
        // applied to both would size it a hundred and twenty-eight times too large.
        let volume = 64 * GIB;
        assert_eq!(
            chunk_length(BlockGroupFlags::DATA, Profile::Single, volume),
            8 * MIB
        );
        assert_eq!(
            chunk_length(BlockGroupFlags::DATA, Profile::Dup, volume),
            GIB
        );
    }

    #[test]
    fn a_replicated_metadata_chunk_reaches_a_gibibyte_only_past_the_volume_that_earns_it() {
        let kind = BlockGroupFlags::METADATA;
        // The threshold is exact and it is a strict comparison: a volume of exactly fifty
        // gibibytes takes the lower ceiling and one byte more takes the higher. Both are below
        // the volume's own tenth here, so the ceiling is what binds in each case and the step
        // between them is the whole of the difference.
        assert_eq!(chunk_length(kind, Profile::Dup, LARGE_VOLUME), 256 * MIB);
        assert_eq!(chunk_length(kind, Profile::Dup, LARGE_VOLUME + 1), GIB);
        // A tenth of a hundred gibibytes is ten of them, so past the threshold the ceiling binds.
        assert_eq!(chunk_length(kind, Profile::Dup, 100 * GIB), GIB);
    }

    #[test]
    fn no_chunk_takes_more_than_its_share_of_the_volume_once_the_volume_can_afford_a_floor() {
        for volume in [GIB, 4 * GIB, 40 * GIB, 400 * GIB, 4000 * GIB] {
            for kind in [
                BlockGroupFlags::DATA,
                BlockGroupFlags::METADATA,
                BlockGroupFlags::SYSTEM,
            ] {
                for profile in [Profile::Single, Profile::Dup] {
                    let length = chunk_length(kind, profile, volume);
                    assert!(
                        length <= volume / VOLUME_SHARE,
                        "{kind:?} {profile:?} on {volume}: {length}"
                    );
                    assert_eq!(length % STRIPE_LEN, 0, "{kind:?} {profile:?} on {volume}");
                }
            }
        }
    }

    #[test]
    fn the_two_address_spaces_advance_by_different_amounts_and_neither_overlaps() {
        for volume in [110 * MIB, 256 * MIB, GIB, 17 * GIB, 300 * GIB] {
            for metadata in [Profile::Single, Profile::Dup] {
                for data in [Profile::Single, Profile::Dup] {
                    if volume < minimum_volume_bytes(metadata, data) {
                        continue;
                    }
                    let layout = plan_layout(
                        &PlanRequest::new(volume)
                            .metadata_profile(metadata)
                            .data_profile(data),
                    )
                    .expect("a volume past the minimum");
                    let mut logical = RESERVED_HEAD;
                    let mut physical = RESERVED_HEAD;
                    for chunk in &layout.chunks {
                        assert!(chunk.logical >= logical, "{volume} {metadata:?} {data:?}");
                        assert!(chunk.copies[0] >= physical);
                        for pair in chunk.copies.windows(2) {
                            assert_eq!(pair[1] - pair[0], chunk.length, "copies are adjacent");
                        }
                        logical = chunk.logical_end();
                        physical = chunk.copies[chunk.copies.len() - 1] + chunk.length;
                        assert!(physical <= volume, "a copy is placed past the device");
                    }
                }
            }
        }
    }

    #[test]
    fn a_volume_too_small_for_its_profiles_is_refused_with_the_size_that_would_do() {
        // The four minima, measured against the pinned baseline: it accepts each of these to the
        // byte and refuses a mebibyte less.
        for (metadata, data, minimum) in [
            (Profile::Single, Profile::Single, 45 * MIB),
            (Profile::Dup, Profile::Single, 109 * MIB),
            (Profile::Single, Profile::Dup, 165 * MIB),
            (Profile::Dup, Profile::Dup, 229 * MIB),
        ] {
            assert_eq!(minimum_volume_bytes(metadata, data), minimum);
            let request = PlanRequest::new(minimum - 1)
                .metadata_profile(metadata)
                .data_profile(data);
            assert_eq!(
                plan_layout(&request),
                Err(GeometryError::VolumeTooSmall {
                    volume_bytes: minimum - 1,
                    minimum,
                })
            );
            let request = PlanRequest::new(minimum)
                .metadata_profile(metadata)
                .data_profile(data);
            assert!(plan_layout(&request).is_ok(), "{metadata:?} {data:?}");
        }
    }

    #[test]
    fn a_sector_or_node_size_the_format_does_not_define_is_refused() {
        for bytes in [0, 1, 512, 2048, 6144, 128 << 10] {
            assert_eq!(
                plan_layout(&PlanRequest::new(GIB).sector_size(SectorSize::Bytes(bytes))),
                Err(GeometryError::SectorSizeUnsupported { bytes })
            );
        }
        for bytes in [512, 2048, 24576, 128 << 10] {
            assert_eq!(
                plan_layout(&PlanRequest::new(GIB).node_size(NodeSize::Bytes(bytes))),
                Err(GeometryError::NodeSizeUnsupported {
                    bytes,
                    sector_size: DEFAULT_SECTOR_SIZE,
                })
            );
        }
        // A node smaller than the sector cannot be written atomically, whatever the format says
        // about the size on its own.
        assert_eq!(
            plan_layout(
                &PlanRequest::new(GIB)
                    .sector_size(SectorSize::Bytes(16384))
                    .node_size(NodeSize::Bytes(4096))
            ),
            Err(GeometryError::NodeSizeUnsupported {
                bytes: 4096,
                sector_size: 16384,
            })
        );
    }

    #[test]
    fn a_node_takes_the_sector_size_where_that_is_the_larger_of_the_two() {
        for (sector, node) in [
            (4096, 16384),
            (16384, 16384),
            (32768, 32768),
            (65536, 65536),
        ] {
            let layout = plan_layout(&PlanRequest::new(GIB).sector_size(SectorSize::Bytes(sector)))
                .expect("a gibibyte is formattable");
            assert_eq!(layout.node_size, node, "sector {sector}");
        }
    }

    #[test]
    fn a_feature_this_crate_does_not_write_is_refused_naming_every_bit_at_once() {
        let asked = DEFAULT_INCOMPAT | IncompatFlags::ZONED | IncompatFlags::RAID56;
        assert_eq!(
            plan_layout(&PlanRequest::new(GIB).features(asked, DEFAULT_COMPAT_RO)),
            Err(GeometryError::FeatureUnsupported {
                bits: IncompatFlags::ZONED.bits() | IncompatFlags::RAID56.bits(),
                // In the words `format -O` takes, so a caller told a feature cannot be
                // written is told it in the word they asked for it by.
                names: "raid56, zoned".to_string(),
            })
        );
    }

    #[test]
    fn a_feature_asked_for_without_what_it_rests_on_is_refused_rather_than_dropped() {
        // The baseline drops the feature, says so on the standard error, and exits zero — so a
        // caller that asked for it gets a filesystem other than the one it described and no
        // failure to notice. Refusing is the difference.
        let ro = CompatRoFlags::BLOCK_GROUP_TREE;
        assert_eq!(
            plan_layout(&PlanRequest::new(GIB).features(DEFAULT_INCOMPAT, ro)),
            Err(GeometryError::FeatureIncoherent {
                feature: "block-group-tree",
                requires: "free-space-tree",
            })
        );
        let ro = CompatRoFlags::BLOCK_GROUP_TREE | CompatRoFlags::FREE_SPACE_TREE;
        assert_eq!(
            plan_layout(
                &PlanRequest::new(GIB)
                    .features(DEFAULT_INCOMPAT.without(IncompatFlags::NO_HOLES), ro)
            ),
            Err(GeometryError::FeatureIncoherent {
                feature: "block-group-tree",
                requires: "no-holes",
            })
        );
    }

    #[test]
    fn asking_for_wide_blocks_at_a_four_kilobyte_node_is_refused_rather_than_cleared() {
        // The bit *is* the node size being larger, so asking for both at once asks for
        // something the format does not define. Clearing it quietly would be the silent drop
        // this crate refuses the baseline for.
        let asked = DEFAULT_INCOMPAT | IncompatFlags::BIG_METADATA;
        assert_eq!(
            plan_layout(
                &PlanRequest::new(GIB)
                    .node_size(NodeSize::Bytes(4096))
                    .features(asked, DEFAULT_COMPAT_RO)
            ),
            Err(GeometryError::FeatureIncoherent {
                feature: "big-metadata",
                requires: "a node larger than four kibibytes",
            })
        );
    }

    #[test]
    fn big_metadata_is_set_exactly_where_a_tree_block_exceeds_four_kibibytes() {
        for (sector, node, set) in [
            (4096u32, 4096u32, false),
            (4096, 16384, true),
            (4096, 8192, true),
            (65536, 65536, true),
        ] {
            let layout = plan_layout(
                &PlanRequest::new(GIB)
                    .sector_size(SectorSize::Bytes(sector))
                    .node_size(NodeSize::Bytes(node)),
            )
            .expect("a gibibyte is formattable");
            assert_eq!(
                layout.incompat_flags.contains(IncompatFlags::BIG_METADATA),
                set,
                "sector {sector} node {node}"
            );
        }
    }

    #[test]
    fn a_volume_is_planned_with_every_superblock_location_it_has_room_for() {
        // The boundary at each location is that offset plus a whole superblock, so a volume of
        // exactly the location's own size carries one fewer than a volume a superblock longer.
        // The two smallest volumes here are below what replicated metadata can be laid out in,
        // which is why they are planned unreplicated: the count is a property of the device's
        // length and of nothing else, so any layout that fits proves it.
        for (volume, expected) in [
            ((64 << 20) - 1, 1),
            (64 << 20, 1),
            ((64 << 20) + 4096, 2),
            (GIB, 2),
            (256 << 30, 2),
            ((256 << 30) + 4096, 3),
        ] {
            let request = PlanRequest::new(volume)
                .metadata_profile(Profile::Single)
                .data_profile(Profile::Single);
            let layout = plan_layout(&request).expect("past the minimum");
            assert_eq!(
                layout.superblock_mirrors.len(),
                expected,
                "a volume of {volume} bytes"
            );
            assert_eq!(layout.superblock_mirrors[0], MIRRORS[0]);
        }
    }

    #[test]
    fn an_empty_filesystem_is_reserved_more_metadata_than_one_costs() {
        // The pinned baseline spends nine tree blocks on an empty filesystem at a sixteen-
        // kibibyte node and eleven at a four-kibibyte one, the root tree having gained a level.
        // A bound below either would be a bound that is wrong on the simplest filesystem there
        // is.
        for (node, spent) in [(4096u32, 11u64), (16384, 9), (65536, 9)] {
            let layout = plan_layout(&PlanRequest::new(GIB).node_size(NodeSize::Bytes(node)))
                .expect("a gibibyte is formattable");
            assert!(
                layout.reservation.metadata_blocks >= spent,
                "node {node}: reserved {}, the baseline spends {spent}",
                layout.reservation.metadata_blocks
            );
            assert_eq!(layout.reservation.node_size, node);
            assert!(layout.reservation.system_blocks >= 1);
        }
    }

    #[test]
    fn the_reservation_always_fits_the_metadata_chunks_planned_for_it() {
        for volume in [110 * MIB, GIB, 17 * GIB, 300 * GIB] {
            for content in [
                Content::EMPTY,
                Content {
                    directories: 4_000,
                    files: 40_000,
                    names: 44_000,
                    longest_name: 255,
                    xattrs: 8_000,
                    subvolumes: 3,
                    data_bytes: 64 * MIB,
                    data_extents: 900,
                    ..Content::EMPTY
                },
            ] {
                let Ok(layout) = plan_layout(&PlanRequest::new(volume).content(content)) else {
                    continue;
                };
                let planned: u64 = layout
                    .chunks_of(BlockGroupFlags::METADATA)
                    .map(|chunk| chunk.length)
                    .sum();
                assert!(
                    planned >= layout.reservation.metadata_bytes(),
                    "a volume of {volume} bytes reserves more metadata than it plans room for"
                );
            }
        }
    }

    #[test]
    fn the_system_reservation_grows_with_the_chunks_the_content_appends() {
        // Every kept chunk is a record in the chunk tree, and a populated filesystem appends
        // one data chunk per eight mebibytes of content at the default pairing — so at two
        // gibibytes of content the records outgrow the single leaf an empty filesystem needs
        // and the chunk tree gains a level.
        let empty = plan_layout(&PlanRequest::new(4 * GIB)).expect("formattable");
        assert_eq!(empty.reservation.system_blocks, 1);

        let populated = plan_layout(&PlanRequest::new(4 * GIB).content(Content {
            files: 1,
            names: 1,
            longest_name: 16,
            data_bytes: 2 * GIB,
            data_extents: 2048,
            ..Content::EMPTY
        }))
        .expect("two gibibytes of content fit a four-gibibyte volume");
        assert!(
            populated.reservation.system_blocks >= 3,
            "reserved {} system blocks for {} chunks",
            populated.reservation.system_blocks,
            populated.chunks.len()
        );
        assert!(populated.chunks.len() > empty.chunks.len());
    }

    #[test]
    fn a_chunk_map_the_system_chunk_cannot_record_is_refused_with_both_numbers() {
        // With nothing replicated the kept system chunk is the four-mebibyte bootstrap one,
        // and a terabyte volume holds more eight-mebibyte data chunks than four mebibytes of
        // chunk records can name. The refusal carries the ask and the ceiling, and it is issued
        // while the map is still arithmetic rather than after the content has been written.
        let request = PlanRequest::new(1024 * GIB)
            .metadata_profile(Profile::Single)
            .data_profile(Profile::Single)
            .content(Content {
                files: 1,
                names: 1,
                longest_name: 16,
                data_bytes: 300 * GIB,
                data_extents: 4096,
                ..Content::EMPTY
            });
        match plan_layout(&request) {
            Err(GeometryError::ChunkMapTooLarge {
                chunks,
                needed_blocks,
                available_blocks,
            }) => {
                assert!(chunks > 30_000, "{chunks} chunks");
                assert!(needed_blocks > available_blocks);
                assert_eq!(available_blocks, BOOTSTRAP_SYSTEM_CHUNK / 16384);
            }
            other => panic!("expected the chunk-map refusal, got {other:?}"),
        }
    }

    #[test]
    fn content_larger_than_the_volume_is_refused_rather_than_placed_past_its_end() {
        let request = PlanRequest::new(GIB).content(Content {
            longest_value: 0,
            data_bytes: 8 * GIB,
            data_extents: 8192,
            files: 1,
            ..Content::EMPTY
        });
        assert!(matches!(
            plan_layout(&request),
            Err(GeometryError::ContentTooLarge { .. })
        ));
    }

    #[test]
    fn content_no_device_could_hold_is_refused_rather_than_planned_a_chunk_at_a_time() {
        // The refusal has to be arithmetic. Appending a chunk per gibibyte first and measuring
        // afterwards would mean this call built two thousand million of them before answering,
        // which is a computation that does not end rather than the error it is owed.
        for data_bytes in [u64::MAX, u64::MAX / 2, 1 << 60] {
            let request = PlanRequest::new(GIB).content(Content {
                longest_value: 0,
                data_bytes,
                data_extents: 1 << 20,
                files: 1,
                ..Content::EMPTY
            });
            assert!(
                matches!(
                    plan_layout(&request),
                    Err(GeometryError::ContentTooLarge { .. })
                ),
                "{data_bytes} bytes of data on a gibibyte"
            );
        }
    }

    #[test]
    fn a_bound_too_large_to_represent_saturates_rather_than_wrapping() {
        // Nothing bounds a count a caller states, and a bound that wrapped would come out
        // *small* — the one way a reservation can be wrong that nothing downstream notices
        // until a writer has run out of room. What follows a saturated bound is a volume that
        // cannot hold it, which is a refusal.
        let request = PlanRequest::new(GIB).content(Content {
            longest_value: 0,
            directories: u64::MAX,
            files: u64::MAX,
            names: u64::MAX,
            longest_name: 255,
            xattrs: u64::MAX,
            subvolumes: u64::MAX,
            data_bytes: u64::MAX,
            data_extents: u64::MAX,
        });
        assert!(matches!(
            plan_layout(&request),
            Err(GeometryError::ContentTooLarge { .. })
        ));
    }

    #[test]
    fn a_name_costs_the_three_records_a_directory_entry_actually_is() {
        // A name is an inode reference, a record keyed by its hash, and a record keyed by its
        // position. A bound that charged one would be short by two thirds on every directory,
        // and short is the direction that fails.
        let base = plan_layout(&PlanRequest::new(17 * GIB).content(Content {
            directories: 1_000,
            files: 10_000,
            names: 0,
            longest_name: 255,
            ..Content::EMPTY
        }))
        .expect("plannable");
        let named = plan_layout(&PlanRequest::new(17 * GIB).content(Content {
            directories: 1_000,
            files: 10_000,
            names: 11_000,
            longest_name: 255,
            ..Content::EMPTY
        }))
        .expect("plannable");
        assert!(named.reservation.metadata_blocks > base.reservation.metadata_blocks);
    }

    #[test]
    fn a_reservation_that_was_exceeded_says_so_rather_than_absorbing_it() {
        let reservation = Reservation {
            metadata_blocks: 40,
            system_blocks: 2,
            node_size: 16384,
        };
        assert_eq!(
            reservation.account(24, 1),
            Ok(Slack {
                metadata_blocks: 16,
                system_blocks: 1,
            })
        );
        assert_eq!(
            reservation.account(40, 2),
            Ok(Slack {
                metadata_blocks: 0,
                system_blocks: 0,
            })
        );
        assert_eq!(
            reservation.account(41, 1),
            Err(ReservationExceeded {
                pool: Pool::Metadata,
                reserved: 40,
                used: 41,
            })
        );
        // Either pool can be the one that ran out, and the message says which. A chunk tree
        // grows with the chunk count, so the system pool is the one a very large volume
        // exhausts while the metadata pool has room to spare.
        assert_eq!(
            reservation.account(1, 3),
            Err(ReservationExceeded {
                pool: Pool::System,
                reserved: 2,
                used: 3,
            })
        );
        assert_eq!(
            reservation.account(1, 3).unwrap_err().to_string(),
            "the system reservation of 2 blocks was exceeded: 3 were spent"
        );
        assert_eq!(reservation.metadata_bytes(), 40 * 16384);
        assert_eq!(reservation.system_bytes(), 2 * 16384);
    }
}
