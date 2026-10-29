//! Opening a container and reaching its objects: the live checkpoint, every object read and
//! verified, the object map, and the volumes it lists.
//!
//! This is the layer the volume view stands on. It knows about blocks, objects and trees, and
//! nothing about files.
//!
//! # What opening does, in order
//!
//! The procedure is the one Apple File System Reference gives on pp. 26-27, less the ephemeral
//! objects a reader has no use for, and with one departure from its fifth step: a candidate's
//! space manager is read to decide whether macOS loads the checkpoint (step 3 below), and a
//! space manager that cannot be read or does not verify passes no checkpoint over, where the
//! reference's step would mount from an older one. A scan reports such a space manager.
//!
//! 1. Read block zero, a copy of the container superblock, for the block size and where the
//!    checkpoint descriptor area is. It may be stale; it is not the live superblock.
//! 2. Refuse a block size the format does not define, and a descriptor area that is a tree
//!    rather than a range, that is empty, that runs past the container's last block, or that is
//!    larger than [`MAX_DESCRIPTOR_BYTES`].
//! 3. Read every block of the descriptor area once, and take the container superblock with the
//!    highest transaction whose checksum covers it and whose checkpoint is whole: the
//!    checkpoint-mapping blocks before it in the ring, as many as it says it has, each at its
//!    transaction, and each object of it recording the identity it is written with; and its
//!    space manager giving each free queue the node limit a container of its size is formatted
//!    with. An incomplete newer checkpoint is passed over for the one before it, which is what
//!    the procedure prescribes after a write was cut short. So is one recording another
//!    container's identifier than block zero's: block zero names the container. And so is one
//!    whose space manager gives a queue another limit, which macOS 15, 26 and 27 pass over for
//!    the checkpoint before it as well, though `fsck_apfs` passes it.
//! 4. Refuse a live superblock carrying an incompatible feature this crate does not implement,
//!    Fusion among them, and under a strict policy one recording no format version.
//! 5. Read the container's object map, and through it each volume's superblock, setting aside
//!    one that cannot be read.
//!
//! # What makes bytes a container
//!
//! Detection and opening ask one question, answered in one place ([`is_container`]): block
//! zero's copy of the superblock parses at a block size the format defines, and either its
//! checksum covers it or the descriptor area it names holds a whole checkpoint. The second half
//! is what a lenient open of a container whose block zero alone is damaged reads through, so
//! detection claims every container a lenient open reads. Four bytes at offset 32 that spell
//! the signature are no answer by themselves: offset 32 of a FAT boot sector is its sector
//! count.
//!
//! # Block zero against the live checkpoint
//!
//! Block zero is written after a checkpoint when the container is unmounted cleanly, so it may
//! hold an older transaction than the live superblock and otherwise holds the same one
//! (reference p. 26). On every image macOS 15, 26 and 27 wrote, the two hold the same
//! transaction and the same bytes outside their check words and the counters at offset 984,
//! which an implementation updates as it writes. Opening holds the two to that and reports how
//! they stand as a [`BlockZero`]: the same, older, or one of the two ways neither copy can be
//! shown right from the image alone, the same transaction with other bytes or a newer
//! transaction than any whole checkpoint. The read follows the live superblock either way, and
//! a strict open refuses the last two. A newer transaction whose checkpoint opening passed over
//! for its space manager is neither: block zero holds the checkpoint macOS does not load, and
//! the live one is what macOS mounts.
//!
//! # What every object read checks
//!
//! A block whose checksum covers it can still be the wrong block, so every object is held
//! against what led to it: its type, its subtype where the caller knows one, how it is stored,
//! its identifier (a physical object's is its own address; a virtual one's is the identifier
//! looked up), and its transaction — no newer than the reference to it, and for a virtual
//! object exactly the transaction its map record names. All of these were observed to hold
//! for every object of every image macOS 15, 26 and 27 wrote.
//!
//! This module does I/O.

use std::io::{Read, Seek};
use std::sync::Arc;

use crate::cache::BlockCache;
use crate::io::{Bounded, io_error, offset_of, read_exact_at};
use crate::{Limits, OpenOptions, ReadPolicy};

use super::btree::{self, TreeRoot};
use super::geometry::{ChunkGeometry, QueueNodeLimits};
use super::ondisk::{
    CHECKPOINT_AREA_IS_TREE, COUNTERS, CRYPTO_GENERATION, CheckpointMap, CheckpointMapping,
    ContainerSuperblock, MAP_CRYPTO_CHANGING, MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, MapKey, MapValue,
    NodeFault, ObjectHeader, ObjectMap, ParseError, SpaceManager, Storage, VolumeSuperblock,
    container_incompat, kind, verify, volume_incompat,
};

/// Every container incompatible bit this crate reads a container carrying: the second format
/// version, the one macOS 10.13 and later implement (Apple File System Reference, p. 38), and
/// the only bit macOS 15, 26 and 27 were observed to set.
pub const SUPPORTED_CONTAINER_INCOMPAT: u64 = container_incompat::VERSION2;

/// Every volume incompatible bit this crate reads a volume carrying: case-insensitive and
/// normalization-insensitive names, the two kinds macOS formats, and keys rolled at least once.
/// Each kind of name has directory entries keyed by a hash of the name, which is the key form
/// this crate reads. macOS 14, 15, 26 and 27 set the rolled bit when they first encrypt a volume
/// and leave it set through every decryption after, and whether the volume is encrypted is its
/// own flag.
pub const SUPPORTED_VOLUME_INCOMPAT: u64 = volume_incompat::CASE_INSENSITIVE
    | volume_incompat::NORMALIZATION_INSENSITIVE
    | volume_incompat::ENCRYPTION_ROLLED;

/// What one checksum-covered block held, as an object.
pub(crate) type Object = Arc<[u8]>;

/// How much of the container's object blocks a container holds once read: 1 MiB, which at the
/// default 4 KiB block is 256 objects. A search passes through the same upper nodes of the same
/// few trees, and every object map lookup through its root.
const OBJECT_CACHE_BYTES: usize = 1 << 20;

/// One volume the container lists.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct VolumeEntry {
    /// Its slot in the container's list, which its superblock records as well.
    pub slot: usize,
    /// The virtual identifier of its superblock.
    pub oid: u64,
    /// The block its superblock was read from.
    pub address: u64,
    /// The superblock.
    pub superblock: VolumeSuperblock,
}

impl VolumeEntry {
    /// The volume's name, as the bytes are stored.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.superblock.name_bytes()
    }

    /// Why this crate does not read the volume, or [`None`] where it does: an encrypted
    /// volume or one whose encryption is being changed, a revert pending, an incompatible
    /// feature outside [`SUPPORTED_VOLUME_INCOMPAT`], or directory entries keyed without a
    /// hash.
    #[must_use]
    pub fn refusal(&self) -> Option<ReadError> {
        let sb = &self.superblock;
        if !sb.is_unencrypted() {
            return Some(ReadError::Encrypted { slot: self.slot });
        }
        // A change of encryption in progress leaves some of the volume's runs in the one form
        // and some in the other, whatever the volume's flags say.
        if sb.encryption_rolling_oid != 0 {
            return Some(ReadError::EncryptionChanging { slot: self.slot });
        }
        // A revert to a snapshot's transaction, or else to a superblock, is carried out when the
        // volume is mounted (reference p. 55), so what the superblock names is discarded then.
        if sb.revert_to_xid != 0 || sb.revert_to_superblock != 0 {
            return Some(ReadError::RevertPending { slot: self.slot });
        }
        let unknown = sb.incompatible_features & !SUPPORTED_VOLUME_INCOMPAT;
        if unknown != 0 {
            return Some(ReadError::UnsupportedFeatures {
                scope: "volume",
                bits: unknown,
                names: volume_incompat_names(unknown),
            });
        }
        if sb.incompatible_features
            & (volume_incompat::CASE_INSENSITIVE | volume_incompat::NORMALIZATION_INSENSITIVE)
            == 0
        {
            return Some(ReadError::UnhashedNames { slot: self.slot });
        }
        None
    }
}

/// A volume the container lists whose superblock could not be read, and why.
///
/// A container's volumes share nothing a read of one of them needs from another, so one whose
/// superblock is damaged is set aside rather than refusing the others: a read selecting it is
/// refused with this error, and a scan reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct UnreadableVolume {
    /// Its slot in the container's list.
    pub slot: usize,
    /// The virtual identifier the list records for its superblock.
    pub oid: u64,
    /// Why the superblock could not be read.
    pub error: ReadError,
}

/// What an object read expects of the object it reaches.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Expect {
    /// The object types acceptable here.
    pub(crate) kinds: &'static [u16],
    /// The subtype, where the caller knows one.
    pub(crate) subtype: Option<u16>,
    /// How the object is stored.
    pub(crate) storage: Storage,
    /// The identifier it must record as its own.
    pub(crate) oid: u64,
    /// The transaction it must record: at most this one, or exactly it.
    pub(crate) xid: Xid,
}

/// A transaction an object must record.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Xid {
    /// No newer than this one.
    AtMost(u64),
    /// Exactly this one.
    Exactly(u64),
}

/// A container opened over a seekable source.
///
/// ```no_run
/// use ferrosys::apfs::Container;
///
/// let container = Container::open(std::fs::File::open("disk.img")?)?;
/// for volume in container.volumes() {
///     println!("{}: {}", volume.slot, String::from_utf8_lossy(volume.name()));
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Container<R> {
    /// The source, ending where the caller's region does.
    src: Bounded<R>,
    base: u64,
    superblock: Box<ContainerSuperblock>,
    checkpoint_address: u64,
    object_map: ObjectMap,
    volumes: Vec<VolumeEntry>,
    unreadable: Vec<UnreadableVolume>,
    passed_over: Vec<PassedOver>,
    block_zero: BlockZero,
    policy: ReadPolicy,
    limits: Limits,
    cache: BlockCache<Object>,
    /// The live checkpoint's mappings of its ephemeral objects, read when first asked for.
    ephemeral: Option<Arc<[CheckpointMapping]>>,
}

/// A container superblock in the descriptor area newer than the live one, which opening did not
/// take, and why.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PassedOver {
    /// The block it is in.
    pub address: u64,
    /// The transaction it records.
    pub xid: u64,
    /// Why it is not live.
    pub reason: &'static str,
}

/// How block zero's copy of the container superblock stands to the live one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum BlockZero {
    /// The same transaction, and the same bytes outside the check words and the counters.
    Current,
    /// An older transaction: the container was not unmounted cleanly after the live
    /// checkpoint was written.
    Older {
        /// The transaction block zero records.
        xid: u64,
    },
    /// The same transaction, and other bytes outside the check words and the counters.
    Differs {
        /// How many bytes differ.
        bytes: usize,
        /// The offset of the first.
        offset: usize,
        /// The field that offset is in.
        field: &'static str,
    },
    /// A newer transaction than any whole checkpoint in the descriptor area holds, so the
    /// checkpoint block zero was written after is not among them.
    Newer {
        /// The transaction block zero records.
        xid: u64,
    },
    /// A newer transaction than the live checkpoint's, that of a checkpoint opening passed over
    /// because its space manager gives a free queue another node limit than a container of its
    /// size has. macOS does not load that checkpoint either, and mounts the live one.
    NotLoaded {
        /// The transaction block zero records.
        xid: u64,
    },
    /// Its checksum does not cover it, so nothing it records is known to be what was written.
    Unverified,
}

impl BlockZero {
    /// Whether neither copy can be shown right: the same transaction with other bytes, a newer
    /// transaction than any whole checkpoint, or a block zero that does not verify.
    #[must_use]
    pub const fn disagrees(self) -> bool {
        matches!(
            self,
            BlockZero::Differs { .. } | BlockZero::Newer { .. } | BlockZero::Unverified
        )
    }
}

impl std::fmt::Display for BlockZero {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockZero::Current => write!(f, "block zero holds the live superblock"),
            BlockZero::Older { xid } => {
                write!(f, "block zero holds the superblock of transaction {xid}")
            }
            BlockZero::Differs {
                bytes,
                offset,
                field,
            } => write!(
                f,
                "block zero holds the live transaction and differs from the live superblock in \
                 {bytes} byte{}, the first at offset {offset} ({field})",
                if *bytes == 1 { "" } else { "s" }
            ),
            BlockZero::Newer { xid } => write!(
                f,
                "block zero holds transaction {xid}, which no whole checkpoint in the \
                 descriptor area holds"
            ),
            BlockZero::NotLoaded { xid } => write!(
                f,
                "block zero holds transaction {xid}, whose checkpoint macOS does not load"
            ),
            BlockZero::Unverified => write!(f, "block zero's checksum does not cover it"),
        }
    }
}

/// Why opening records a second whole checkpoint of the live one's transaction.
pub(crate) const SAME_TRANSACTION: &str = "another whole checkpoint records the same transaction";

/// Why a value that shapes the container is refused, where the format gives it no meaning.
const UNDEFINED: &str = "which the format does not define";

/// Why opening passes over a checkpoint recording another container's identifier than block
/// zero's.
pub(crate) const FOREIGN: &str = "it belongs to another container than block zero";

/// Why opening passes over a checkpoint whose space manager macOS does not load.
pub(crate) const QUEUE_LIMITS: &str =
    "its space manager gives a free queue another node limit than a container of its size has";

/// The most bytes of one ephemeral object this crate reads: the space manager of the largest
/// container the format describes lists a few thousand addresses.
const MAX_EPHEMERAL_BYTES: u64 = 16 << 20;

/// The most bytes of checkpoint descriptor area this crate reads: 16 MiB.
///
/// The area grows with the container. On every container macOS 15, 26 and 27 formatted at
/// 4 KiB, from 1 MiB to 16 TiB, it is 8 to 292 blocks, 1.2 MiB at the most, and on the 1 GiB
/// containers formatted at 8, 16 and 64 KiB it is 8 blocks. Its length is block zero's word,
/// which may be damaged, so this is what keeps an open, and detection, from reading as much of a
/// source as that word says.
pub(crate) const MAX_DESCRIPTOR_BYTES: u64 = 16 << 20;

/// Block zero's copy of the container superblock, parsed and held to the block sizes the format
/// defines, and the block's bytes at that size, verified or not.
///
/// # Errors
///
/// [`ReadError::NotApfs`] where the source is too short for block zero or block zero holds no
/// container superblock, and [`ReadError::BadGeometry`] for a block size the format does not
/// define.
fn read_block_zero<R: Read + Seek>(
    src: &mut R,
    base: u64,
) -> Result<(ContainerSuperblock, Vec<u8>), ReadError> {
    let short = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadError::NotApfs
        } else {
            ReadError::from(e)
        }
    };
    let head = read_exact_at(src, base, MIN_BLOCK_SIZE as usize).map_err(short)?;
    let first = ContainerSuperblock::read_from(&head).map_err(|_| ReadError::NotApfs)?;
    let block_size = first.block_size;
    if !block_size.is_power_of_two() || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
        return Err(ReadError::BadGeometry {
            field: "block size",
            value: u64::from(block_size),
            why: UNDEFINED,
        });
    }
    let bytes = if block_size == MIN_BLOCK_SIZE {
        head
    } else {
        read_exact_at(src, base, block_size as usize).map_err(short)?
    };
    Ok((first, bytes))
}

/// Whether the bytes `base` bytes into `src` are an APFS container: block zero parses at a block
/// size the format defines, and its checksum covers it or the descriptor area it names holds a
/// whole checkpoint. Detection asks this, and it is what a lenient open reads through.
///
/// # Errors
///
/// [`ReadError::Io`] where the source fails other than by ending; an image too short for what
/// it names is an answer, `false`.
pub(crate) fn is_container<R: Read + Seek>(mut src: R, base: u64) -> Result<bool, ReadError> {
    let (first, block_zero) = match read_block_zero(&mut src, base) {
        Ok(found) => found,
        Err(ReadError::Io { kind, message }) => return Err(ReadError::Io { kind, message }),
        Err(_) => return Ok(false),
    };
    if verify(&block_zero) {
        return Ok(true);
    }
    let options = OpenOptions::new().policy(ReadPolicy::Lenient);
    // Detection has bounded the source already, so this adds no end of its own.
    let mut container = Container::unread(Bounded::new(src, base, None), base, first, &options);
    match container.find_checkpoint() {
        Ok(_) => Ok(true),
        Err(ReadError::Io {
            kind: std::io::ErrorKind::UnexpectedEof,
            ..
        }) => Ok(false),
        Err(ReadError::Io { kind, message }) => Err(ReadError::Io { kind, message }),
        Err(_) => Ok(false),
    }
}

/// Where the counters a container superblock keeps begin and end: bytes an implementation
/// updates as it writes, which block zero and the live superblock need not share.
const COUNTERS_AT: std::ops::Range<usize> = 984..984 + 8 * COUNTERS;

/// The fields of a container superblock by where they begin (reference pp. 27-36), and the
/// rest of the block after them.
const SUPERBLOCK_FIELDS: &[(usize, &str)] = &[
    (0, "the check words"),
    (8, "the object identifier"),
    (16, "the transaction"),
    (24, "the object type"),
    (32, "the signature"),
    (36, "the block size"),
    (40, "the block count"),
    (48, "the compatible features"),
    (56, "the read-only compatible features"),
    (64, "the incompatible features"),
    (72, "the container identifier"),
    (88, "the next object identifier"),
    (96, "the next transaction"),
    (104, "the checkpoint areas"),
    (152, "the space manager"),
    (160, "the object map"),
    (168, "the reaper"),
    (176, "the test type"),
    (180, "the maximum volume count"),
    (184, "the volume list"),
    (COUNTERS_AT.start, "the counters"),
    (COUNTERS_AT.end, "the blocked-out range"),
    (1256, "the eviction mapping tree"),
    (1264, "the container flags"),
    (1272, "the boot driver"),
    (1280, "the Fusion identifier"),
    (1296, "the keybag"),
    (1312, "the ephemeral information"),
    (1344, "the test object"),
    (1352, "the Fusion middle tree"),
    (1360, "the Fusion cache state"),
    (1368, "the Fusion cache"),
    (1384, "the newest mounted version"),
    (1392, "the media keybag"),
    (ContainerSuperblock::SIZE, "the rest of the block"),
];

/// The field of a container superblock offset `offset` is in.
fn superblock_field(offset: usize) -> &'static str {
    SUPERBLOCK_FIELDS
        .iter()
        .take_while(|(start, _)| *start <= offset)
        .last()
        .map_or("the check words", |(_, name)| name)
}

/// How block zero's bytes stand to the live superblock's, both verified.
fn compare_block_zero(block_zero: &[u8], live: &[u8]) -> BlockZero {
    let xid = |b: &[u8]| ObjectHeader::read_from(b).map_or(0, |h| h.xid);
    let (zero, current) = (xid(block_zero), xid(live));
    if zero < current {
        return BlockZero::Older { xid: zero };
    }
    if zero > current {
        return BlockZero::Newer { xid: zero };
    }
    let mut differing = (8..block_zero.len().min(live.len()))
        .filter(|at| !COUNTERS_AT.contains(at) && block_zero[*at] != live[*at]);
    let Some(offset) = differing.next() else {
        return BlockZero::Current;
    };
    BlockZero::Differs {
        bytes: 1 + differing.count(),
        offset,
        field: superblock_field(offset),
    }
}

impl<R: Read + Seek> Container<R> {
    /// Open the container at the start of `src`, strictly, with the default limits.
    ///
    /// # Errors
    ///
    /// See [`open_with`](Self::open_with).
    pub fn open(src: R) -> Result<Self, ReadError> {
        Self::open_with(src, &OpenOptions::new())
    }

    /// Open the container `options.base` bytes into `src`.
    ///
    /// # Errors
    ///
    /// [`ReadError::NotApfs`] where block zero holds no container superblock;
    /// [`ReadError::BadGeometry`] for a block size or checkpoint area this crate does not read,
    /// and under [`ReadPolicy::Strict`] for a container recording no format version;
    /// [`ReadError::UnsupportedFeatures`] for an incompatible bit outside
    /// [`SUPPORTED_CONTAINER_INCOMPAT`]; [`ReadError::UnsupportedCheckpoint`] for a checkpoint
    /// area described by a tree; [`ReadError::NoCheckpoint`] where no superblock in the
    /// descriptor area verifies with a whole checkpoint, or every one that does is passed over,
    /// as of another container or geometry or as a checkpoint macOS does not load; under [`ReadPolicy::Strict`], [`ReadError::BadChecksum`] where
    /// block zero does not verify and [`ReadError::BlockZeroDisagrees`] where it and the live
    /// superblock cannot both be right; and whatever reading the object map fails on, which under
    /// a strict policy is a read of every node of it. A volume superblock that cannot be read is
    /// no error here, short of the source failing: it is one of
    /// [`unreadable_volumes`](Self::unreadable_volumes).
    pub fn open_with(src: R, options: &OpenOptions) -> Result<Self, ReadError> {
        let base = options.base;
        let mut src = Bounded::new(src, base, options.len);
        let (first, block_zero) = read_block_zero(&mut src, base)?;
        if !verify(&block_zero) && options.policy == ReadPolicy::Strict {
            return Err(ReadError::BadChecksum {
                object: "container superblock",
                block: 0,
            });
        }
        let mut container = Self::unread(src, base, first, options);
        let live = container.find_checkpoint()?;
        container.check_live()?;
        if verify(&block_zero) {
            container.block_zero = compare_block_zero(&block_zero, &live);
            if let BlockZero::Newer { xid } = container.block_zero
                && container
                    .passed_over
                    .iter()
                    .any(|passed| passed.xid == xid && passed.reason == QUEUE_LIMITS)
            {
                container.block_zero = BlockZero::NotLoaded { xid };
            }
        }
        if container.block_zero.disagrees() && options.policy == ReadPolicy::Strict {
            return Err(ReadError::BlockZeroDisagrees {
                block_zero: container.block_zero,
                live: container.xid(),
            });
        }
        container.read_object_map()?;
        container.read_volumes()?;
        Ok(container)
    }

    /// A container over `src` of which only block zero, `first`, has been read: its superblock
    /// stands in for the live one until the descriptor area is.
    fn unread(
        src: Bounded<R>,
        base: u64,
        first: ContainerSuperblock,
        options: &OpenOptions,
    ) -> Self {
        let block_size = first.block_size as usize;
        Self {
            src,
            base,
            superblock: Box::new(first),
            checkpoint_address: 0,
            object_map: empty_map(),
            volumes: Vec::new(),
            unreadable: Vec::new(),
            passed_over: Vec::new(),
            block_zero: BlockZero::Unverified,
            policy: options.policy,
            limits: options.limits,
            cache: BlockCache::within(OBJECT_CACHE_BYTES, block_size, 64),
            ephemeral: None,
        }
    }

    /// The live container superblock: the newest whole checkpoint's.
    #[must_use]
    pub fn superblock(&self) -> &ContainerSuperblock {
        &self.superblock
    }

    /// The block the live superblock was read from, in the checkpoint descriptor area.
    #[must_use]
    pub fn checkpoint_address(&self) -> u64 {
        self.checkpoint_address
    }

    /// The transaction of the live checkpoint: the newest state every read here sees.
    #[must_use]
    pub fn xid(&self) -> u64 {
        self.superblock.header.xid
    }

    /// Bytes in every block of the container.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    /// Every volume the container lists whose superblock was read, in slot order.
    #[must_use]
    pub fn volumes(&self) -> &[VolumeEntry] {
        &self.volumes
    }

    /// Every volume the container lists whose superblock could not be read, in slot order.
    #[must_use]
    pub fn unreadable_volumes(&self) -> &[UnreadableVolume] {
        &self.unreadable
    }

    /// Container superblocks in the descriptor area newer than the live one that opening passed
    /// over, newest first — the record of a checkpoint a write did not finish, of another
    /// container's, or of one whose space manager macOS does not load — and any other whole
    /// checkpoint of the live one's transaction.
    #[must_use]
    pub fn passed_over(&self) -> &[PassedOver] {
        &self.passed_over
    }

    /// How block zero's copy of the container superblock stands to the live one.
    #[must_use]
    pub fn block_zero(&self) -> BlockZero {
        self.block_zero
    }

    /// How strictly the container is being read.
    #[must_use]
    pub fn policy(&self) -> ReadPolicy {
        self.policy
    }

    /// How many bytes of the source lie at and after the container's start, as far as the
    /// caller's region runs where it named one.
    pub(crate) fn source_bytes(&mut self) -> Result<u64, ReadError> {
        let end = self.src.seek(std::io::SeekFrom::End(0))?;
        Ok(end.saturating_sub(self.base))
    }

    /// Read from here on under `policy`.
    pub(crate) fn set_policy(&mut self, policy: ReadPolicy) {
        self.policy = policy;
    }

    /// The caps this read is held to.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Fill `buf` from the container's bytes beginning at block `block`.
    ///
    /// A file's bytes carry nothing that identifies them, no header and no checksum, so this
    /// hands back what is at the address and says nothing about whether it is the right data.
    ///
    /// # Errors
    ///
    /// [`ReadError::OutOfRange`] where the run leaves the container, and [`ReadError::Io`]
    /// where the source does not reach that far.
    pub fn read_blocks(&mut self, block: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        self.read_within(block, 0, buf)
    }

    /// Fill `buf` from the container's bytes beginning `skip` bytes into block `block`, a
    /// number of bytes smaller than a block, every block the run meets inside the container.
    pub(crate) fn read_within(
        &mut self,
        block: u64,
        skip: u64,
        buf: &mut [u8],
    ) -> Result<(), ReadError> {
        let bs = u64::from(self.block_size());
        let blocks = (skip + buf.len() as u64).div_ceil(bs);
        if block
            .checked_add(blocks)
            .is_none_or(|end| end > self.superblock.block_count)
        {
            return Err(ReadError::OutOfRange { block });
        }
        let offset = offset_of(self.base, block, bs)
            .and_then(|at| at.checked_add(skip))
            .ok_or(ReadError::OutOfRange { block })?;
        crate::io::read_exact_into(&mut self.src, offset, buf)?;
        Ok(())
    }

    /// The object at block `address`, verified and held against `expect`.
    pub(crate) fn read_object(
        &mut self,
        address: u64,
        expect: &Expect,
    ) -> Result<Object, ReadError> {
        let object = match self.cache.get(address) {
            Some(held) => Arc::clone(held),
            None => {
                let mut bytes = vec![0u8; self.block_size() as usize];
                self.read_blocks(address, &mut bytes)?;
                if !verify(&bytes) {
                    return Err(ReadError::BadChecksum {
                        object: object_name(expect.kinds),
                        block: address,
                    });
                }
                let object: Object = bytes.into();
                self.cache.insert(address, Arc::clone(&object));
                object
            }
        };
        let header = ObjectHeader::read_from(&object)?;
        let fault = if !expect.kinds.contains(&header.kind()) {
            Some("an object of another type")
        } else if expect
            .subtype
            .is_some_and(|subtype| header.subtype != u32::from(subtype))
        {
            Some("an object of another subtype")
        } else if header.storage() != expect.storage {
            Some("an object stored another way")
        } else if header.oid != expect.oid {
            Some("an object recording another identifier")
        } else if header.xid == 0
            || match expect.xid {
                Xid::AtMost(xid) => header.xid > xid,
                Xid::Exactly(xid) => header.xid != xid,
            }
        {
            // Zero is no transaction, and the format keeps it off the disk (reference p. 12).
            Some("an object from another transaction")
        } else if header.other_flags() != 0 {
            Some("an object carrying flags this crate does not read")
        } else {
            None
        };
        if let Some(fault) = fault {
            return Err(ReadError::WrongObject {
                block: address,
                fault,
            });
        }
        Ok(object)
    }

    /// The newest version of virtual object `oid` no later than transaction `xid`, in the object
    /// map whose mapping tree is `map`.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingObject`] where the map holds no such version,
    /// [`ReadError::BadMapValue`] where the version it holds carries a flag other than its
    /// encryption generation, and [`ReadError::BadGeometry`] where it maps an object of another
    /// size than one block.
    pub(crate) fn resolve(
        &mut self,
        map: &TreeRoot,
        oid: u64,
        xid: u64,
    ) -> Result<(MapKey, MapValue), ReadError> {
        let target = MapKey { oid, xid };
        let found = btree::find_at_or_before(self, map, &|key: &[u8]| {
            MapKey::read_from(key).map(|k| k.cmp(&target))
        })?;
        let Some((key, value)) = found else {
            return Err(ReadError::MissingObject { oid, xid });
        };
        let key = MapKey::read_from(&key)?;
        if key.oid != oid {
            return Err(ReadError::MissingObject { oid, xid });
        }
        let value = MapValue::read_from(&value)?;
        // The generation names which configuration's keys an encrypted object takes; whether the
        // object is encrypted is a flag of its own, so the generation alone leaves the read as it
        // is (reference p. 48).
        if value.flags & !CRYPTO_GENERATION != 0 {
            return Err(ReadError::BadMapValue {
                oid,
                flags: value.flags,
            });
        }
        if value.size != self.block_size() {
            return Err(ReadError::BadGeometry {
                field: "a mapped object's size",
                value: u64::from(value.size),
                why: "an object of more than a block, which this crate does not read",
            });
        }
        Ok((key, value))
    }

    /// The virtual object `oid` at the newest version no later than `xid`, read and verified.
    pub(crate) fn read_virtual(
        &mut self,
        map: &TreeRoot,
        oid: u64,
        xid: u64,
        kinds: &'static [u16],
        subtype: Option<u16>,
    ) -> Result<(u64, Object), ReadError> {
        let (key, value) = self.resolve(map, oid, xid)?;
        let object = self.read_object(
            value.address,
            &Expect {
                kinds,
                subtype,
                storage: Storage::Virtual,
                oid,
                xid: Xid::Exactly(key.xid),
            },
        )?;
        Ok((value.address, object))
    }

    /// The mapping tree of the object map at physical address `address`, written no later
    /// than `xid`, and the map's header.
    pub(crate) fn object_map_at(
        &mut self,
        address: u64,
        xid: u64,
    ) -> Result<(ObjectMap, TreeRoot), ReadError> {
        let object = self.read_object(
            address,
            &Expect {
                kinds: &[kind::OBJECT_MAP],
                subtype: None,
                storage: Storage::Physical,
                oid: address,
                xid: Xid::AtMost(xid),
            },
        )?;
        let map = ObjectMap::read_from(&object)?;
        let tree = TreeRoot::object_map(map.tree_oid, map.header.xid);
        Ok((map, tree))
    }

    /// The live checkpoint's mappings of its ephemeral objects: those of every mapping block
    /// before its superblock in the ring, in order.
    pub(crate) fn checkpoint_mappings(&mut self) -> Result<Arc<[CheckpointMapping]>, ReadError> {
        if let Some(held) = &self.ephemeral {
            return Ok(Arc::clone(held));
        }
        let mappings: Vec<CheckpointMapping> = self
            .checkpoint_maps()?
            .into_iter()
            .flat_map(|(_, _, mappings)| mappings)
            .collect();
        let held: Arc<[CheckpointMapping]> = mappings.into();
        self.ephemeral = Some(Arc::clone(&held));
        Ok(held)
    }

    /// Each mapping block of the live checkpoint, before its superblock in the ring, in order:
    /// its address, its header, and its mappings. The checkpoint's blocks begin at the
    /// superblock's descriptor index and number its descriptor length, the superblock among
    /// them (reference p. 31). Opening held each of those blocks to the checkpoint's
    /// transaction, so only their contents are read here.
    pub(crate) fn checkpoint_maps(
        &mut self,
    ) -> Result<Vec<(u64, CheckpointMap, Vec<CheckpointMapping>)>, ReadError> {
        let areas = self.superblock.checkpoint;
        let ring = u64::from(self.superblock.desc_area_blocks());
        let mut maps = Vec::new();
        let mut block = vec![0u8; self.block_size() as usize];
        for k in 0..u64::from(areas.desc_len.saturating_sub(1)) {
            let address = areas.desc_base + (u64::from(areas.desc_index) + k) % ring;
            self.read_blocks(address, &mut block)?;
            let (map, mappings) = CheckpointMap::read_from(&block)?;
            maps.push((address, map, mappings));
        }
        Ok(maps)
    }

    /// The block the live checkpoint keeps ephemeral object `oid` at.
    ///
    /// # Errors
    ///
    /// [`ReadError::MissingObject`] where no mapping of the live checkpoint names it, and
    /// [`ReadError::WrongObject`] where two do: an identifier names one object.
    pub(crate) fn ephemeral_address(&mut self, oid: u64) -> Result<u64, ReadError> {
        let xid = self.xid();
        let mappings = self.checkpoint_mappings()?;
        let mut naming = mappings.iter().filter(|mapping| mapping.oid == oid);
        let first = naming.next().ok_or(ReadError::MissingObject { oid, xid })?;
        if let Some(second) = naming.next() {
            return Err(ReadError::WrongObject {
                block: second.address,
                fault: "an identifier another mapping of the checkpoint names",
            });
        }
        Ok(first.address)
    }

    /// The ephemeral object `mapping` names, read whole, verified, and held to being of `kind`
    /// and written no later than `live`.
    pub(crate) fn read_ephemeral(
        &mut self,
        mapping: &CheckpointMapping,
        kind: u16,
        live: u64,
    ) -> Result<Vec<u8>, ReadError> {
        let bs = u64::from(self.block_size());
        let size = u64::from(mapping.size);
        if size == 0 || size % bs != 0 || size > MAX_EPHEMERAL_BYTES {
            return Err(ReadError::BadGeometry {
                field: "an ephemeral object's size",
                value: size,
                why: "not whole blocks, or more than this crate reads",
            });
        }
        let mut bytes = vec![0u8; size as usize];
        self.read_blocks(mapping.address, &mut bytes)?;
        if !verify(&bytes) {
            return Err(ReadError::BadChecksum {
                object: "ephemeral object",
                block: mapping.address,
            });
        }
        let header = ObjectHeader::read_from(&bytes)?;
        // A mapping's type is the whole 32-bit type word, flags included (reference p. 40). A
        // subtype other than the mapping's is read past here, and graded by the scan.
        let fault = if header.kind() != kind || header.type_word != mapping.type_word {
            Some("an object of another type than its mapping says")
        } else if header.storage() != Storage::Ephemeral {
            Some("an object stored another way")
        } else if header.oid != mapping.oid {
            Some("an object recording another identifier")
        } else if header.xid == 0 || header.xid > live {
            Some("an object from another transaction")
        } else {
            None
        };
        match fault {
            Some(fault) => Err(ReadError::WrongObject {
                block: mapping.address,
                fault,
            }),
            None => Ok(bytes),
        }
    }

    /// Whether macOS loads the checkpoint `sb` ends, a whole one, as far as its space manager
    /// decides it: the space manager gives each free queue, the internal pool's and the main
    /// device's, the node limit a container of `sb`'s size is formatted with
    /// ([`QueueNodeLimits`]). `managers` is each ring block's mappings of a space manager.
    ///
    /// macOS 15, 26 and 27 load no checkpoint whose space manager gives either queue another
    /// limit, and mount the container at the checkpoint before it: every other limit tried was
    /// refused, from zero to 65,535, either side of the one given and of two mebibytes of nodes,
    /// at 4 and 64 KiB blocks, while `fsck_apfs` passed each. A container `diskutil` shrinks or
    /// grows is given the limits of its new size. A space manager this does not find, of
    /// another size than a container of `sb`'s size has, or that does not read or verify passes
    /// no checkpoint over; a scan reports it. That size bounds what each candidate costs to one
    /// or two blocks.
    fn space_manager_loads(
        &mut self,
        sb: &ContainerSuperblock,
        managers: &[Vec<CheckpointMapping>],
    ) -> Result<(), &'static str> {
        let ring = managers.len() as u64;
        let c = &sb.checkpoint;
        let found = (0..u64::from(c.desc_len.saturating_sub(1)))
            .flat_map(|k| &managers[((u64::from(c.desc_index) + k) % ring) as usize])
            .find(|mapping| mapping.oid == sb.space_manager_oid)
            .copied();
        let bs = u64::from(sb.block_size);
        let size = ChunkGeometry::of(sb.block_count, sb.block_size)
            .manager_layout()
            .1
            .div_ceil(bs)
            .saturating_mul(bs);
        let Some(mapping) = found.filter(|mapping| u64::from(mapping.size) == size) else {
            return Ok(());
        };
        let Some(sm) = self
            .read_ephemeral(&mapping, kind::SPACE_MANAGER, sb.header.xid)
            .ok()
            .and_then(|object| SpaceManager::read_from(&object).ok())
        else {
            return Ok(());
        };
        let given = QueueNodeLimits::of(sb.block_count, sb.block_size);
        let recorded = (
            sm.free_queues[SpaceManager::INTERNAL_POOL].tree_node_limit,
            sm.free_queues[SpaceManager::MAIN_QUEUE].tree_node_limit,
        );
        if recorded == (given.pool, given.main) {
            Ok(())
        } else {
            Err(QUEUE_LIMITS)
        }
    }

    /// The container's own object map's mapping tree.
    pub(crate) fn container_map(&self) -> TreeRoot {
        TreeRoot::object_map(self.object_map.tree_oid, self.object_map.header.xid)
    }

    /// Steps 2 and 3 of opening: the descriptor area block zero names, held to the container
    /// and to [`MAX_DESCRIPTOR_BYTES`], and the newest whole checkpoint in it, with the bytes of
    /// its superblock.
    fn find_checkpoint(&mut self) -> Result<Vec<u8>, ReadError> {
        let first = self.superblock.as_ref().clone();
        let area = &first.checkpoint;
        if (area.desc_blocks | area.data_blocks) & CHECKPOINT_AREA_IS_TREE != 0 {
            return Err(ReadError::UnsupportedCheckpoint);
        }
        let ring = u64::from(first.desc_area_blocks());
        let why = if ring == 0 {
            Some(UNDEFINED)
        } else if ring.saturating_mul(u64::from(first.block_size)) > MAX_DESCRIPTOR_BYTES {
            Some("more than the 16 MiB of descriptor area this crate reads")
        } else if area
            .desc_base
            .checked_add(ring)
            .is_none_or(|end| end > first.block_count)
        {
            Some("which runs past the container's last block")
        } else {
            None
        };
        if let Some(why) = why {
            return Err(ReadError::BadGeometry {
                field: "the checkpoint descriptor area, in blocks,",
                value: ring,
                why,
            });
        }
        // One pass over the area: each block's type and transaction where its checksum covers
        // it, and whether it records the identity a checkpoint-mapping block is written with,
        // which is all wholeness asks of a mapping block, and of a mapping block its mappings of
        // a space manager, which are all a candidate's space manager is found by, so no block is
        // read twice.
        let bs = self.block_size() as usize;
        let mut slots: Vec<Option<Slot>> = Vec::with_capacity(ring as usize);
        let mut managers: Vec<Vec<CheckpointMapping>> = Vec::with_capacity(ring as usize);
        let mut candidates = Vec::new();
        let mut bytes = vec![0u8; bs];
        for i in 0..ring {
            self.read_blocks(area.desc_base + i, &mut bytes)?;
            let header = verify(&bytes)
                .then(|| ObjectHeader::read_from(&bytes).ok())
                .flatten();
            slots.push(header.map(|h| Slot {
                kind: h.kind(),
                xid: h.xid,
                mapping: written_as(&h, Storage::Physical, area.desc_base + i),
            }));
            managers.push(match header {
                Some(h) if h.kind() == kind::CHECKPOINT_MAP => CheckpointMap::read_from(&bytes)
                    .map(|(_, mappings)| {
                        mappings
                            .into_iter()
                            .filter(|m| m.kind() == kind::SPACE_MANAGER)
                            .collect()
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            });
            if header.is_some_and(|h| h.kind() == kind::CONTAINER_SUPERBLOCK)
                && let Ok(sb) = ContainerSuperblock::read_from(&bytes)
            {
                candidates.push((sb.header.xid, i, sb, bytes.clone()));
            }
        }
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
        // The newest whole checkpoint, the lower slot of two at one transaction, and the other
        // of those two recorded beside the ones passed over: which one the container is at is
        // not known.
        let mut live: Option<(u64, u64, ContainerSuperblock, Vec<u8>)> = None;
        for (xid, index, sb, bytes) in candidates {
            if live.as_ref().is_some_and(|found| xid < found.0) {
                break;
            }
            let whole = self
                .checkpoint_is_whole(&sb, index, &slots)
                .and_then(|()| self.space_manager_loads(&sb, &managers));
            match (whole, &live) {
                (Ok(()), None) => live = Some((xid, index, sb, bytes)),
                (Ok(()), Some(_)) => self.passed_over.push(PassedOver {
                    address: area.desc_base + index,
                    xid,
                    reason: SAME_TRANSACTION,
                }),
                (Err(reason), None) => self.passed_over.push(PassedOver {
                    address: area.desc_base + index,
                    xid,
                    reason,
                }),
                (Err(_), Some(_)) => {}
            }
        }
        let (_, index, sb, bytes) = live.ok_or(ReadError::NoCheckpoint)?;
        self.checkpoint_address = area.desc_base + index;
        *self.superblock = sb;
        Ok(bytes)
    }

    /// Whether the checkpoint whose superblock sits at `index` of the ring is whole: it is the
    /// container's own, the last block of the checkpoint it describes, and every mapping block
    /// before it verifies at its transaction. `slots` is what each ring block holds, or [`None`]
    /// where its checksum does not cover it.
    ///
    /// Block zero names the container and where its ring is, so a checkpoint is held to block
    /// zero's identifier as well as to its geometry. A container written over an older one of
    /// the same geometry, by anything that writes only the blocks the newer one uses, leaves the
    /// older one's checkpoints in the slots the newer has not reached, whole and at later
    /// transactions; Apple's own formatters zero the ring first (observed on every way macOS 14,
    /// 15, 26 and 27 offer, the whole-disk and the partitioned alike). Block zero is held to under a lenient
    /// read too, where it does not verify, as its geometry is: it is what says where the ring
    /// is at all.
    fn checkpoint_is_whole(
        &self,
        sb: &ContainerSuperblock,
        index: u64,
        slots: &[Option<Slot>],
    ) -> Result<(), &'static str> {
        let ring = slots.len() as u64;
        let c = &sb.checkpoint;
        // The checkpoint's first block and its length, the superblock last (reference p. 31).
        let (start, len) = (u64::from(c.desc_index), u64::from(c.desc_len));
        // A container superblock is an ephemeral object with the one reserved identifier
        // (reference p. 13).
        if !written_as(&sb.header, Storage::Ephemeral, OID_NX_SUPERBLOCK) {
            return Err("it records another identity than a container superblock's");
        }
        if sb.uuid != self.superblock.uuid {
            return Err(FOREIGN);
        }
        // Block zero's descriptor area is one range, so the word is compared whole, its tree
        // bit with it.
        if sb.block_size != self.superblock.block_size
            || sb.checkpoint.desc_base != self.superblock.checkpoint.desc_base
            || sb.checkpoint.desc_blocks != self.superblock.checkpoint.desc_blocks
        {
            return Err("it describes another geometry than block zero");
        }
        if sb.checkpoint.data_blocks & CHECKPOINT_AREA_IS_TREE != 0 {
            return Err("its data area is described by a tree, which this crate does not read");
        }
        if len == 0 || len > ring || start >= ring || (start + len - 1) % ring != index {
            return Err("it is not the last block of the checkpoint it describes");
        }
        for k in 0..len - 1 {
            match slots[((start + k) % ring) as usize] {
                None => return Err("a checkpoint-mapping block of it does not verify"),
                Some(slot) if slot.kind != kind::CHECKPOINT_MAP || slot.xid != sb.header.xid => {
                    return Err("a checkpoint-mapping block of it is from another transaction");
                }
                Some(slot) if !slot.mapping => {
                    return Err(
                        "a checkpoint-mapping block of it records another identity than its own",
                    );
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// Refuse the live superblock where it describes a container this crate does not read.
    fn check_live(&self) -> Result<(), ReadError> {
        let sb = &self.superblock;
        let unknown = sb.incompatible_features & !SUPPORTED_CONTAINER_INCOMPAT;
        if unknown != 0 {
            return Err(ReadError::UnsupportedFeatures {
                scope: "container",
                bits: unknown,
                names: container_incompat_names(unknown),
            });
        }
        if sb.block_count == 0 {
            return Err(ReadError::BadGeometry {
                field: "block count",
                value: 0,
                why: UNDEFINED,
            });
        }
        // The second format version is the one macOS 10.13 and later implement (reference
        // p. 38), and every container macOS 15, 26 and 27 wrote records it. A container
        // recording none is read as one by a lenient read, which a scan reports.
        if sb.incompatible_features & container_incompat::VERSION2 == 0
            && self.policy == ReadPolicy::Strict
        {
            return Err(ReadError::BadGeometry {
                field: "the container's format version",
                value: 0,
                why: UNDEFINED,
            });
        }
        Ok(())
    }

    /// Step 5's first half: the container's object map, read whole under a strict policy
    /// before any lookup through it is trusted.
    fn read_object_map(&mut self) -> Result<(), ReadError> {
        let (map, tree) = self.object_map_at(self.superblock.object_map_oid, self.xid())?;
        self.object_map = map;
        self.check_map(&tree)
    }

    /// Read the mapping tree `tree` whole under a strict policy, so that every lookup through
    /// it answers what the tree holds.
    ///
    /// A lookup checks the nodes it enters and the node after its answer, and steers by keys
    /// it checks no further, and an object map holds older versions of an object beside the
    /// newest: a map whose keys disagree with its nodes can answer with an older version of a
    /// node, verified and real, as the one asked for. A walk of every node holds every key to
    /// what it leads to. A lenient read reads through the map without it, and a scan walks it
    /// whatever the policy.
    pub(crate) fn check_map(&mut self, tree: &TreeRoot) -> Result<(), ReadError> {
        if self.policy == ReadPolicy::Strict {
            btree::check_whole(self, tree)?;
        }
        Ok(())
    }

    /// Step 5's second half: each volume's superblock, through the container's object map. One
    /// that cannot be read is set aside with why, and the source failing fails the open.
    fn read_volumes(&mut self) -> Result<(), ReadError> {
        let slots: Vec<(usize, u64)> = self.superblock.volumes().collect();
        for (slot, oid) in slots {
            match self.read_volume(slot, oid) {
                Ok(entry) => self.volumes.push(entry),
                Err(ReadError::Io { kind, message }) => {
                    return Err(ReadError::Io { kind, message });
                }
                Err(error) => self.unreadable.push(UnreadableVolume { slot, oid, error }),
            }
        }
        Ok(())
    }

    /// The superblock of the volume in slot `slot`, virtual object `oid`.
    fn read_volume(&mut self, slot: usize, oid: u64) -> Result<VolumeEntry, ReadError> {
        let map = self.container_map();
        let xid = self.xid();
        let (address, object) =
            self.read_virtual(&map, oid, xid, &[kind::VOLUME_SUPERBLOCK], None)?;
        let superblock = VolumeSuperblock::read_from(&object)?;
        if superblock.index as usize != slot {
            return Err(ReadError::WrongObject {
                block: address,
                fault: "a volume superblock recording another slot as its own",
            });
        }
        Ok(VolumeEntry {
            slot,
            oid,
            address,
            superblock,
        })
    }
}

/// What one block of the checkpoint descriptor area holds, where its checksum covers it.
#[derive(Clone, Copy)]
struct Slot {
    /// Its object type.
    kind: u16,
    /// The transaction it records.
    xid: u64,
    /// Whether it records the identity a checkpoint-mapping block is written with: physical,
    /// at its own address.
    mapping: bool,
}

/// The identifier of the container superblock, the one object a container reserves one for
/// (reference p. 13).
const OID_NX_SUPERBLOCK: u64 = 1;

/// Whether `header` records the identity of an object stored as `storage` with identifier `oid`,
/// with no subtype and no flag this crate does not read, as every checkpoint object macOS wrote
/// does.
fn written_as(header: &ObjectHeader, storage: Storage, oid: u64) -> bool {
    header.storage() == storage
        && header.oid == oid
        && header.subtype == 0
        && header.other_flags() == 0
}

/// An object map header with nothing in it, which a container holds until it has read its own.
const fn empty_map() -> ObjectMap {
    ObjectMap {
        header: ObjectHeader {
            checksum: 0,
            oid: 0,
            xid: 0,
            type_word: 0,
            subtype: 0,
        },
        flags: 0,
        snapshot_count: 0,
        tree_type: 0,
        snapshot_tree_type: 0,
        tree_oid: 0,
        snapshot_tree_oid: 0,
        most_recent_snapshot: 0,
        pending_revert_min: 0,
        pending_revert_max: 0,
    }
}

/// What an object of the first of these types is called in an error.
fn object_name(kinds: &[u16]) -> &'static str {
    match kinds.first().copied() {
        Some(kind::CONTAINER_SUPERBLOCK) => "container superblock",
        Some(kind::BTREE_ROOT | kind::BTREE_NODE) => "tree node",
        Some(kind::OBJECT_MAP) => "object map",
        Some(kind::VOLUME_SUPERBLOCK) => "volume superblock",
        Some(kind::SNAPSHOT_EXTENSION) => "snapshot extension",
        _ => "object",
    }
}

/// The names the reference gives the container incompatible bits in `bits`.
fn container_incompat_names(bits: u64) -> String {
    named_bits(
        bits,
        &[
            (container_incompat::VERSION1, "the first format version"),
            (container_incompat::VERSION2, "the second format version"),
            (container_incompat::FUSION, "Fusion"),
        ],
    )
}

/// The names the reference gives the volume incompatible bits in `bits`.
fn volume_incompat_names(bits: u64) -> String {
    named_bits(
        bits,
        &[
            (volume_incompat::CASE_INSENSITIVE, "case-insensitive names"),
            (volume_incompat::DATALESS_SNAPSHOTS, "dataless snapshots"),
            (volume_incompat::ENCRYPTION_ROLLED, "rolled encryption keys"),
            (
                volume_incompat::NORMALIZATION_INSENSITIVE,
                "normalization-insensitive names",
            ),
            (volume_incompat::INCOMPLETE_RESTORE, "an incomplete restore"),
            (volume_incompat::SEALED, "a sealed volume"),
        ],
    )
}

/// `bits` as a comma-separated list of the names in `table`, an unnamed bit as its value.
fn named_bits(bits: u64, table: &[(u64, &str)]) -> String {
    let mut out = Vec::new();
    let mut rest = bits;
    for (bit, name) in table {
        if bits & bit != 0 {
            out.push((*name).to_string());
            rest &= !bit;
        }
    }
    let mut bit = 1u64;
    while rest != 0 {
        if rest & bit != 0 {
            out.push(format!("{bit:#x}"));
            rest &= !bit;
        }
        bit = bit.wrapping_shl(1);
    }
    out.join(", ")
}

/// Whether an object map says a change of its volume's encryption is in progress (reference
/// p. 49).
pub(crate) const fn map_is_changing_encryption(map: &ObjectMap) -> bool {
    map.flags & MAP_CRYPTO_CHANGING != 0
}

/// Whether an object map records the transactions a revert in progress is undoing
/// (reference p. 46).
pub(crate) const fn map_is_reverting(map: &ObjectMap) -> bool {
    map.pending_revert_min != 0 || map.pending_revert_max != 0
}

/// A failure opening or reading an APFS container.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The source could not be read.
    #[error("i/o error ({kind:?}): {message}")]
    #[non_exhaustive]
    Io {
        /// How the error classified itself.
        kind: std::io::ErrorKind,
        /// What it said.
        message: String,
    },
    /// Block zero holds no container superblock.
    #[error("no APFS container superblock at block zero")]
    NotApfs,
    /// A structure was too short, unsigned, or unterminated.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// An object's checksum does not cover it.
    #[error("{object} at block {block}: the checksum does not cover it")]
    #[non_exhaustive]
    BadChecksum {
        /// What the object was read as.
        object: &'static str,
        /// The block it was read from.
        block: u64,
    },
    /// A value that shapes the container is one the format does not define, or one this crate
    /// does not read.
    #[error("{field} is {value}, {why}")]
    #[non_exhaustive]
    BadGeometry {
        /// What the value is.
        field: &'static str,
        /// The value.
        value: u64,
        /// Why it is refused.
        why: &'static str,
    },
    /// A checkpoint area, the descriptor area or the data area, is a tree of ranges rather than
    /// one range.
    #[error("a checkpoint area described by a tree, which this crate does not read")]
    UnsupportedCheckpoint,
    /// No container superblock in the descriptor area verifies with a whole checkpoint.
    #[error("no whole checkpoint in the checkpoint descriptor area")]
    NoCheckpoint,
    /// Block zero and the live checkpoint's superblock cannot both be right, which a strict
    /// open refuses: see [`BlockZero::disagrees`].
    #[error("{block_zero}; the live checkpoint is transaction {live}")]
    #[non_exhaustive]
    BlockZeroDisagrees {
        /// How block zero stands to the live superblock.
        block_zero: BlockZero,
        /// The live checkpoint's transaction.
        live: u64,
    },
    /// The container or a volume carries an incompatible feature this crate does not read.
    #[error("unsupported {scope} features: {names} ({bits:#x})")]
    #[non_exhaustive]
    UnsupportedFeatures {
        /// `"container"` or `"volume"`.
        scope: &'static str,
        /// The bits outside what this crate reads.
        bits: u64,
        /// Their names, where the format gives them.
        names: String,
    },
    /// A volume is encrypted.
    #[error("volume {slot} is encrypted")]
    #[non_exhaustive]
    Encrypted {
        /// The volume's slot.
        slot: usize,
    },
    /// A volume's encryption is being changed: its superblock names the state of a change in
    /// progress, or its object map flags one.
    #[error("volume {slot}'s encryption is being changed")]
    #[non_exhaustive]
    EncryptionChanging {
        /// The volume's slot.
        slot: usize,
    },
    /// A volume records a revert to an earlier state that has not been carried out. A mount
    /// carries it out first, deleting the volume's current state (Apple File System Reference,
    /// pp. 46 and 55), so the tree the volume names is a state macOS discards.
    #[error("volume {slot} has a revert pending, which discards the state it holds")]
    #[non_exhaustive]
    RevertPending {
        /// The volume's slot.
        slot: usize,
    },
    /// A volume's directory entries are keyed without a hash, which no image this crate is held
    /// to carries.
    #[error("volume {slot} keys its directory entries by name without a hash")]
    #[non_exhaustive]
    UnhashedNames {
        /// The volume's slot.
        slot: usize,
    },
    /// A block address leaves the container.
    #[error("block {block} is outside the container")]
    #[non_exhaustive]
    OutOfRange {
        /// The block.
        block: u64,
    },
    /// An object that verifies is not the object that was asked for.
    #[error("the object at block {block} is {fault}")]
    #[non_exhaustive]
    WrongObject {
        /// The block it was read from.
        block: u64,
        /// How it differs from what was asked for.
        fault: &'static str,
    },
    /// An object map holds no version of an object at or before a transaction.
    #[error("no version of object {oid} at or before transaction {xid}")]
    #[non_exhaustive]
    MissingObject {
        /// The virtual identifier.
        oid: u64,
        /// The transaction.
        xid: u64,
    },
    /// An object map's record for an object carries a flag this crate does not read an object
    /// under: deleted, saved, encrypted, or stored without a header.
    #[error("object {oid}'s map record carries flags {flags:#x}")]
    #[non_exhaustive]
    BadMapValue {
        /// The virtual identifier.
        oid: u64,
        /// The flags.
        flags: u32,
    },
    /// A tree node does not frame.
    #[error("the tree node at block {block}: {fault}")]
    #[non_exhaustive]
    BadNode {
        /// The block.
        block: u64,
        /// What does not fit.
        fault: NodeFault,
    },
    /// A tree's shape is not a tree's: a level that does not step down by one, keys out of
    /// order or not matching the entry that leads to them, a node reached twice.
    #[error("the tree node at block {block}: {fault}")]
    #[non_exhaustive]
    BadTree {
        /// The block.
        block: u64,
        /// What is wrong with it.
        fault: &'static str,
    },
    /// A walk visited more records than the limit allows.
    #[error("a walk reached the limit of {limit} records")]
    #[non_exhaustive]
    TooManyEntries {
        /// The limit.
        limit: usize,
    },
    /// No volume answers to the selection.
    #[error("the container holds no volume {selector}")]
    #[non_exhaustive]
    NoSuchVolume {
        /// The selection, as given.
        selector: String,
    },
    /// More than one volume carries the name a selection gives, so the name identifies none of
    /// them. Which of the volumes was meant is the caller's to say, by slot or by identifier.
    #[error(
        "the volumes in slots {} are each named {}, so the name names none of them",
        .slots.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        crate::escape::printable(.name)
    )]
    #[non_exhaustive]
    AmbiguousVolume {
        /// The name, as given.
        name: Vec<u8>,
        /// The slots of the volumes that carry it, in order.
        slots: Vec<usize>,
    },
    /// The volume has no snapshot of that name.
    #[error("the volume holds no snapshot {}", crate::escape::printable(.name))]
    #[non_exhaustive]
    NoSuchSnapshot {
        /// The name, as given.
        name: Vec<u8>,
    },
    /// A record of the file-system tree does not parse.
    #[error("a record of object {id} (kind {kind}): {fault}")]
    #[non_exhaustive]
    BadRecord {
        /// The object the record belongs to.
        id: u64,
        /// The record's kind.
        kind: u8,
        /// What does not parse.
        fault: String,
    },
    /// The volume holds no inode of that number.
    #[error("the volume holds no inode {inode}")]
    #[non_exhaustive]
    MissingInode {
        /// The inode.
        inode: u64,
    },
    /// A path names nothing.
    #[error("no such path: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotFound {
        /// The path.
        path: Vec<u8>,
    },
    /// A path passes through something that is not a directory.
    #[error("not a directory: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    NotADirectory {
        /// The path.
        path: Vec<u8>,
    },
    /// An inode is not a symbolic link.
    #[error("inode {inode} is not a symbolic link")]
    #[non_exhaustive]
    NotASymlink {
        /// The inode.
        inode: u64,
    },
    /// Resolving a path met more symbolic links than the budget allows.
    #[error("too many symbolic links resolving {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    SymlinkLoop {
        /// The path.
        path: Vec<u8>,
    },
    /// A directory entry carries a name no directory can hold: empty, `.`, `..`, or holding a
    /// slash or a NUL.
    #[error("{} is not a name a directory can hold", crate::escape::printable(.name))]
    #[non_exhaustive]
    HostileName {
        /// The name.
        name: Vec<u8>,
    },
    /// A directory entry names a directory the tree already reaches by another name, or one
    /// of its own ancestors. An APFS directory has one name and one parent, so the volume
    /// contradicts itself. A walk never descends into such a directory twice; a strict read
    /// refuses the volume for it, and a lenient one passes the repeat over.
    #[error(
        "a directory entry names directory inode {inode}, which the tree reaches by another \
         name as well"
    )]
    #[non_exhaustive]
    RepeatedDirectory {
        /// The directory inode named twice.
        inode: u64,
    },
    /// A directory entry names a directory from a directory other than the one it records as
    /// its parent. An APFS directory has one name, in its parent, so the volume contradicts
    /// itself, and the directory's subtree would be read where it does not belong. A strict
    /// read refuses it where a walk or a lookup meets it, and a lenient one reads through it.
    #[error(
        "directory inode {inode} is named in directory inode {named_in} and records inode \
         {parent} as its parent"
    )]
    #[non_exhaustive]
    MisplacedDirectory {
        /// The directory inode.
        inode: u64,
        /// The directory whose entry names it.
        named_in: u64,
        /// The parent it records.
        parent: u64,
    },
    /// A file's content is compressed with a method this build does not decode.
    #[error(
        "inode {inode} is compressed with decmpfs type {method}, which this build does not decode"
    )]
    #[non_exhaustive]
    UnsupportedCompression {
        /// The inode.
        inode: u64,
        /// The compression type its header records.
        method: u32,
    },
    /// A compressed file's header or data does not decode as its type describes.
    #[error("inode {inode}'s compressed data: {fault}")]
    #[non_exhaustive]
    BadCompressed {
        /// The inode.
        inode: u64,
        /// What does not decode.
        fault: String,
    },
    /// A file extent does not describe a run of the container.
    #[error("the extent at byte {logical} of stream {stream}: {fault}")]
    #[non_exhaustive]
    BadExtent {
        /// The data stream.
        stream: u64,
        /// The extent's logical offset.
        logical: u64,
        /// The leaf of the file-system tree holding the extent record at fault, where the fault
        /// is one record's.
        block: Option<u64>,
        /// What is wrong with it.
        fault: &'static str,
    },
    /// A file is larger than the read is allowed to hand out.
    #[error("inode {inode} is {size} bytes, more than the {limit}-byte cap this read is held to")]
    #[non_exhaustive]
    FileTooLarge {
        /// The inode.
        inode: u64,
        /// Its size.
        size: u64,
        /// The cap.
        limit: u64,
    },
    /// An attribute is larger than the read is allowed to hand out, or than the container
    /// holds: every byte of an attribute's stream is in a block of the container, each block
    /// at most once.
    #[error(
        "attribute {} of inode {inode} is {size} bytes, more than the {limit}-byte cap this read \
         is held to",
        crate::escape::printable(name)
    )]
    #[non_exhaustive]
    AttributeTooLarge {
        /// The inode it belongs to.
        inode: u64,
        /// Its name, as the bytes are stored.
        name: Vec<u8>,
        /// Its size.
        size: u64,
        /// The cap: [`Limits::max_file_bytes`](crate::Limits::max_file_bytes), or the
        /// container's size in bytes where that is smaller.
        limit: u64,
    },
    /// A walk of the volume reached more names than the limit allows.
    #[error("a walk of this volume reached the limit of {limit} names")]
    #[non_exhaustive]
    WalkTooLarge {
        /// The limit.
        limit: usize,
    },
    /// A path longer than this crate builds.
    #[error("a path longer than this crate builds: {}", crate::escape::printable(.path))]
    #[non_exhaustive]
    PathTooLong {
        /// The path, as far as it was built.
        path: Vec<u8>,
    },
}

io_error!(ReadError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unnamed_bits_are_named_by_their_value() {
        assert_eq!(
            container_incompat_names(container_incompat::FUSION | 0x40),
            "Fusion, 0x40"
        );
        assert_eq!(
            volume_incompat_names(volume_incompat::SEALED),
            "a sealed volume"
        );
    }

    #[test]
    fn a_source_too_short_for_a_superblock_is_not_a_container() {
        let err = Container::open(std::io::Cursor::new(vec![0u8; 100]));
        assert!(matches!(err, Err(ReadError::NotApfs)));
    }

    #[test]
    fn zeros_are_not_a_container() {
        let err = Container::open(std::io::Cursor::new(vec![0u8; 8192]));
        assert!(matches!(err, Err(ReadError::NotApfs)));
    }
}
