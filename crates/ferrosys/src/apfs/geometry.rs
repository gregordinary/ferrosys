//! Geometry: from a container's size and block size to the block every object of a newly
//! formatted container occupies.
//!
//! [`plan_layout`] is the whole of it. It takes what a caller can state — how large the
//! container is, how large a block is, and how many volumes it begins with — and derives what
//! the format records and where: the two checkpoint areas, the space manager and its internal
//! pool, the limits of the two free queues, how many volumes the container may ever hold, and
//! for each of the two checkpoints a new container is formatted with, the block of every
//! object it writes.
//!
//! This module is pure and deterministic: it computes numbers from numbers, performs no I/O,
//! reads no clock, and allocates nothing on a device. A plan is a value a caller can inspect
//! and compare before a byte is written.
//!
//! # Two transactions
//!
//! A container is formatted in two transactions, and both checkpoints stay in the checkpoint
//! areas. The first commits the container alone: its space manager, its reaper and an object
//! map with nothing in it. The second adds the volumes, each with an object map, its
//! extent-reference, snapshot and file-system trees and its superblock, and gives the container
//! a second object map that lists them. Each checkpoint has its own copy of every ephemeral
//! object, and the second writes a new chunk-info block and bitmap for every chunk it changed.
//! What the second supersedes it frees: the first's object map to the main free queue, and the
//! first's chunk-info, address and bitmap blocks to the internal pool's queue.
//!
//! That is the shape `newfs_apfs` gives a container, and a plan reproduces it block for block:
//! for one volume, every object [`plan_layout`] places is at the block where `newfs_apfs` puts
//! it when it formats a file of that size at that block size. A container planned here and one
//! Apple's tool formats can therefore be compared one block at a time.
//!
//! # Where the rules come from
//!
//! Every rule here was measured on the 7,508 empty containers `newfs_apfs` and `hdiutil create`
//! formatted on macOS 14, 15, 26 and 27, at 1,781 sizes: from 1 MiB to 16 TiB at 4 KiB blocks,
//! from 64 MiB to 16 TiB at 8, 16 and 64 KiB, and from 4 GiB to 16 TiB at 32 KiB, on Apple
//! silicon and on Intel. Where a rule changes with size, the sizes on either side of the change
//! were formatted, so each boundary below is exact. The four releases place every object at the
//! same block. The rules that size the checkpoint areas,
//! the space manager and the pool hold as well on every container macOS formatted and then
//! wrote to that this crate's corpus holds, at all five block sizes.
//!
//! The rules are stated as arithmetic, and most of it reads plainly: a chunk is the blocks one
//! bitmap block has a bit for, a chunk-info block describes as many chunks as fit after its
//! header, and the checkpoint descriptor area has room for enough checkpoint-mapping blocks to
//! map a full data area, rounded up to four, and four more. A few constants have no account
//! beyond the measurement: the data area's terms, the queue limits' divisors, and where the
//! objects outside the checkpoint areas go in a large container. Each is written where it is
//! used, with what fixes it.
//!
//! # Where the objects outside the checkpoint areas go
//!
//! A container's object maps, its volumes' superblocks and their trees' roots are allocated
//! from the main space. In a container of up to [`LAST_CONTIGUOUS_BLOCK_COUNT`] blocks they
//! follow the internal pool: the first checkpoint's object map, then each volume's object map
//! and its four other objects, then the second checkpoint's object map. In a larger container
//! they start further in, the volumes' objects at one place and the object maps at about twice
//! that, by a piecewise rule [`far_placement`] carries.

use super::ondisk::{
    BlockRange, CheckpointMap, CheckpointMapping, ChunkInfo, ChunkList, FreeQueueKey, MAX_VOLUMES,
    NODE_DATA_START, TREE_INFO_SIZE,
};

/// The fewest blocks a container is planned with.
///
/// `fsck_apfs` on macOS 14, 15 and 26 opens a container of 1,024 blocks of 4 KiB and refuses
/// each one measured of 861 blocks or fewer; macOS 27's reads the smaller ones too, and
/// `newfs_apfs` formats down to 1 MiB. The checker's limit was measured at 4 KiB alone, so the
/// floor is a block count, which holds whether the limit counts blocks or bytes: at 4 KiB it is
/// the four mebibytes measured, at a larger block size it is more bytes than that, and 64 MiB
/// at 64 KiB was measured to pass.
pub const MIN_BLOCK_COUNT: u64 = 1024;

/// The largest container planned, in bytes.
///
/// The largest container measured, at every block size: 16 TiB.
pub const MAX_CONTAINER_BYTES: u64 = 16 << 40;

/// The most blocks a container may have for its objects outside the checkpoint areas to
/// follow the internal pool.
///
/// One block short of 3 × 2^19 at every block size: at each of the five, a container of
/// 1,572,863 blocks keeps them after the pool and one of 1,572,864 places them further in, and
/// every size measured on either side agrees.
pub const LAST_CONTIGUOUS_BLOCK_COUNT: u64 = 1_572_863;

/// The space manager's fixed structure, in bytes: where the arrays past its fields begin.
///
/// Every space manager observed records this at offset 340, and `fsck_apfs` refuses another
/// value.
pub(crate) const SPACE_MANAGER_STRUCT_SIZE: u32 = 2520;

/// Slots the pool-bitmap area keeps per pool bitmap block, which the slot free list hands out
/// in order (observed). Every space manager observed records this at offset 148.
pub(crate) const POOL_BITMAP_SLOTS: u32 = 16;

/// The first transaction a container is formatted in, which a chunk nothing has been allocated
/// from records as its own.
pub(crate) const FIRST_XID: u64 = 1;

/// The transaction that adds the volumes and everything they hold.
pub(crate) const SECOND_XID: u64 = 2;

/// The bytes one entry of a free-queue node takes: its table entry, its key and its value.
const QUEUE_ENTRY_BYTES: u64 = 4 + FreeQueueKey::SIZE as u64 + 8;

/// Bytes of a free-queue node a queue's limit counts no entry in, past its header and its
/// footer.
///
/// Measured, with no account beyond the measurement: a node is counted 142 entries at 4 KiB,
/// 288 at 8, 580 at 16, 1,166 at 32 and 2,336 at 64. Any value from 21 to 24 gives every limit
/// measured, at all five block sizes; 24 is the bytes of one entry's key and value.
const QUEUE_NODE_UNCOUNTED: u64 = 24;

/// The most bytes of nodes either free queue is limited to.
const QUEUE_LIMIT_BYTES: u64 = 2 << 20;

/// Bytes of container per volume slot it is given, up to [`MAX_VOLUMES`].
const BYTES_PER_VOLUME_SLOT: u64 = 512 << 20;

/// An address in a space manager's list, or in an address block.
const ADDRESS_BYTES: u64 = 8;

/// The block sizes a container can have: every power of two from 4 to 64 KiB.
///
/// Measured fresh at 4, 8, 16 and 64 KiB; the rules that size a container hold at 32 KiB on
/// every container of that block size the corpus holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BlockSize {
    /// 4096 bytes, the size `newfs_apfs` takes by default.
    #[default]
    K4,
    /// 8192 bytes.
    K8,
    /// 16384 bytes.
    K16,
    /// 32768 bytes.
    K32,
    /// 65536 bytes.
    K64,
}

impl BlockSize {
    /// Every block size, smallest first.
    pub const ALL: [Self; 5] = [Self::K4, Self::K8, Self::K16, Self::K32, Self::K64];

    /// The block size of `bytes` bytes, or `None` where a container has no such block size.
    ///
    /// ```
    /// # use ferrosys::apfs::BlockSize;
    /// assert_eq!(BlockSize::new(16384), Some(BlockSize::K16));
    /// assert_eq!(BlockSize::new(2048), None);
    /// ```
    #[must_use]
    pub const fn new(bytes: u32) -> Option<Self> {
        let mut at = 0;
        while at < Self::ALL.len() {
            if Self::ALL[at].bytes() == bytes {
                return Some(Self::ALL[at]);
            }
            at += 1;
        }
        None
    }

    /// The size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::K4 => 4096,
            Self::K8 => 8192,
            Self::K16 => 16384,
            Self::K32 => 32768,
            Self::K64 => 65536,
        }
    }
}

/// What a caller states about the container to be planned.
///
/// Built from a size and refined by the methods below, each of which consumes and returns the
/// request so a call reads as one expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct PlanRequest {
    /// The bytes the container may occupy. It occupies the whole blocks they hold; a remainder
    /// smaller than a block is left out of it.
    pub container_bytes: u64,
    /// The size of every block.
    pub block_size: BlockSize,
    /// How many volumes the container is formatted with.
    pub volumes: u32,
}

impl PlanRequest {
    /// A request for a container of this many bytes, of 4 KiB blocks, with one volume.
    #[must_use]
    pub const fn new(container_bytes: u64) -> Self {
        Self {
            container_bytes,
            block_size: BlockSize::K4,
            volumes: 1,
        }
    }

    /// Name the block size.
    #[must_use]
    pub const fn block_size(mut self, size: BlockSize) -> Self {
        self.block_size = size;
        self
    }

    /// Name how many volumes the container is formatted with.
    #[must_use]
    pub const fn volumes(mut self, volumes: u32) -> Self {
        self.volumes = volumes;
        self
    }
}

/// A container that cannot be planned.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GeometryError {
    /// The container has fewer blocks than [`MIN_BLOCK_COUNT`].
    #[error(
        "a container of {bytes} bytes holds {block_count} blocks of {block_size} bytes, and \
         one needs at least {MIN_BLOCK_COUNT}"
    )]
    #[non_exhaustive]
    ContainerTooSmall {
        /// The bytes requested.
        bytes: u64,
        /// The block size requested.
        block_size: u32,
        /// The whole blocks the bytes hold.
        block_count: u64,
    },
    /// The container is larger than [`MAX_CONTAINER_BYTES`].
    #[error("a container of {bytes} bytes is larger than the {MAX_CONTAINER_BYTES} planned")]
    #[non_exhaustive]
    ContainerTooLarge {
        /// The bytes the container would occupy.
        bytes: u64,
    },
    /// No volume was asked for.
    ///
    /// A container is formatted with at least one: the second transaction is the one that adds
    /// them, and a container without one has nothing a mount can open.
    #[error("a container is formatted with at least one volume")]
    NoVolumes,
    /// More volumes were asked for than the container has slots for.
    ///
    /// A container has one slot per 512 MiB, up to 100, fixed when it is formatted.
    #[error("a container of {bytes} bytes holds at most {max_volumes} volumes, not {volumes}")]
    #[non_exhaustive]
    TooManyVolumes {
        /// The bytes the container occupies.
        bytes: u64,
        /// The volumes asked for.
        volumes: u32,
        /// The slots the container has.
        max_volumes: u32,
    },
    /// The container has too few free blocks for what its volumes hold.
    #[error(
        "a container of {bytes} bytes has {free} blocks free past its own objects, too few for \
         what its volumes hold"
    )]
    #[non_exhaustive]
    ContainerFull {
        /// The bytes the container occupies.
        bytes: u64,
        /// The blocks it had free for content, past every object a container of its size is
        /// formatted with.
        free: u64,
    },
}

/// How a container's blocks divide into chunks, and how many blocks describe them.
///
/// A chunk is the blocks one bitmap block has a bit for. Its state is a chunk-info entry, a
/// chunk-info block holds as many entries as fit after its header, and once there are more
/// chunk-info blocks than one address block can list, address blocks list them in turn. The
/// space manager records each count, and the scan holds a container read back to them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ChunkGeometry {
    /// Blocks in a chunk: eight per byte of a bitmap block.
    pub blocks_per_chunk: u64,
    /// Chunk-info entries one chunk-info block holds.
    pub chunks_per_cib: u64,
    /// Chunk-info block addresses one address block holds.
    pub cibs_per_cab: u64,
    /// Chunks the container's blocks divide into, the last possibly short.
    pub chunk_count: u64,
    /// Chunk-info blocks describing them.
    pub cib_count: u64,
    /// Address blocks listing those, or zero where the space manager's own list holds every
    /// chunk-info block's address.
    pub cab_count: u64,
}

impl ChunkGeometry {
    /// The chunk geometry of a container of `block_count` blocks of `block_size` bytes.
    ///
    /// Address blocks appear once the chunk-info blocks outnumber what one address block lists:
    /// 507 at 4 KiB. A container of 504 chunk-info blocks was measured with none, and one of 512
    /// with two.
    ///
    /// Every count is as wide as the block count, so a block count no container has, read from
    /// a damaged superblock, gives counts a space manager's fields cannot hold rather than a
    /// failure.
    ///
    /// # Panics
    ///
    /// Where `block_size` is too small to hold a chunk-info block's header, which no block size
    /// the format defines is.
    #[must_use]
    pub fn of(block_count: u64, block_size: u32) -> Self {
        let bs = u64::from(block_size);
        assert!(
            bs > ChunkList::ENTRIES_AT as u64,
            "a {bs}-byte block holds no chunk-info block"
        );
        let blocks_per_chunk = bs * 8;
        let chunks_per_cib = (bs - ChunkList::ENTRIES_AT as u64) / ChunkInfo::SIZE as u64;
        let cibs_per_cab = (bs - ChunkList::ENTRIES_AT as u64) / ADDRESS_BYTES;
        let chunk_count = block_count.div_ceil(blocks_per_chunk);
        let cib_count = chunk_count.div_ceil(chunks_per_cib);
        let cab_count = if cib_count > cibs_per_cab {
            cib_count.div_ceil(cibs_per_cab)
        } else {
            0
        };
        Self {
            blocks_per_chunk,
            chunks_per_cib,
            cibs_per_cab,
            chunk_count,
            cib_count,
            cab_count,
        }
    }

    /// The addresses the space manager's own list holds: one per address block where there
    /// are any, else one per chunk-info block.
    #[must_use]
    pub const fn listed(&self) -> u64 {
        if self.cab_count > 0 {
            self.cab_count
        } else {
            self.cib_count
        }
    }

    /// The blocks of the internal pool, which holds every chunk-info, address and bitmap block
    /// three times over: the size every container `newfs_apfs` formats gives it (observed).
    pub(crate) const fn pool_blocks(&self) -> u64 {
        3 * (self.chunk_count + self.cib_count + self.cab_count)
    }

    /// The bitmap blocks the internal pool's blocks lie under, each written into one of sixteen
    /// slots kept for it.
    pub(crate) const fn pool_bitmaps(&self) -> u64 {
        self.pool_blocks().div_ceil(self.blocks_per_chunk)
    }

    /// The arrays of the space manager a container of this geometry is formatted with, and the
    /// offset its last array, the second device's empty list, begins at: the bytes the object
    /// needs.
    pub(crate) fn manager_layout(&self) -> (ManagerArrays, u64) {
        let bitmaps = self.pool_bitmaps();
        let arrays = manager_arrays(
            u64::from(SPACE_MANAGER_STRUCT_SIZE),
            bitmaps,
            u64::from(POOL_BITMAP_SLOTS) * bitmaps,
        );
        (arrays, second_list_offset(arrays.addresses, self.listed()))
    }

    /// The chunk a block belongs to.
    const fn chunk_of(&self, block: u64) -> u64 {
        block / self.blocks_per_chunk
    }
}

/// The first block of `chunk` of a container of `block_count` blocks cut into chunks of
/// `blocks_per_chunk`, and how many blocks it has: every chunk is whole but the last.
pub(crate) const fn chunk_span(blocks_per_chunk: u64, block_count: u64, chunk: u64) -> (u64, u64) {
    let first = chunk * blocks_per_chunk;
    let left = block_count - first;
    (
        first,
        if blocks_per_chunk < left {
            blocks_per_chunk
        } else {
            left
        },
    )
}

/// Where the arrays past a space manager's fields begin, in bytes from the object's start.
///
/// They follow one another from the end of the fixed structure, in the order every space
/// manager observed keeps them: the transaction of each pool bitmap block, the slot each
/// occupies (padded to eight bytes), the free list of the slots (two bytes for each of a
/// bitmap block's sixteen, so whole eight-byte words), and the main device's address list.
/// The second device's list, which a container on one device keeps empty, begins where the
/// main device's ends ([`second_list_offset`]), as on every container macOS formats
/// (observed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ManagerArrays {
    pub(crate) xids: u64,
    pub(crate) slots: u64,
    pub(crate) free_list: u64,
    pub(crate) addresses: u64,
}

/// The arrays of a space manager whose structure ends at `struct_size`, keeping `bitmaps`
/// pool bitmap blocks in `slots` slots.
pub(crate) const fn manager_arrays(struct_size: u64, bitmaps: u64, slots: u64) -> ManagerArrays {
    let xids = struct_size;
    let slot_array = xids + 8 * bitmaps;
    let free_list = slot_array + (2 * bitmaps).div_ceil(8) * 8;
    ManagerArrays {
        xids,
        slots: slot_array,
        free_list,
        addresses: free_list + (2 * slots).div_ceil(8) * 8,
    }
}

/// Where the second device's address list begins: past the `listed` addresses of the main
/// device's list, which begins at `addresses`.
pub(crate) const fn second_list_offset(addresses: u64, listed: u64) -> u64 {
    addresses + ADDRESS_BYTES * listed
}

/// The space manager's size and where its arrays begin.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SpaceManagerShape {
    /// Blocks the object takes: its structure and its arrays, rounded up to the block. Two at
    /// 4 KiB from about 2.8 TiB, until address blocks shorten its list.
    pub blocks: u32,
    /// Where the transaction of each pool bitmap block is kept.
    pub bitmap_xid_offset: u32,
    /// Where the slot each pool bitmap block occupies is kept.
    pub bitmap_slot_offset: u32,
    /// Where the free list of the pool bitmap slots is kept.
    pub bitmap_free_list_offset: u32,
    /// Where the main device's list of chunk-info or address block addresses begins.
    pub address_offset: u32,
    /// Where the second device's list begins: where the main device's ends.
    pub second_address_offset: u32,
}

/// How many nodes each free queue's tree may grow to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct QueueNodeLimits {
    /// The internal pool's queue.
    pub pool: u16,
    /// The main device's queue.
    pub main: u16,
}

impl QueueNodeLimits {
    /// The limits a container of `block_count` blocks of `block_size` bytes is formatted with.
    ///
    /// A queue's node limit is the nodes its entries would need, one node's worth of entries at
    /// a time, where a queue that would need two is given three, as `newfs_apfs` gives either
    /// queue (observed: the limits of the containers it formats are not met without that step);
    /// at most [`cap`](Self::cap).
    /// The main queue is sized for a share of the container that shrinks as the container
    /// grows, the pool's for an eighth of the pool. The share steps at 2^18 and 2^20 blocks
    /// exactly, at all five block sizes: one block either side of each was measured at each.
    /// Above 2^20 blocks every main queue measured is at its cap, so the eighth there is the
    /// simplest value that fits rather than one any container shows.
    pub(crate) fn of(block_count: u64, block_size: u32) -> Self {
        let bs = u64::from(block_size);
        let per_node = (bs - NODE_DATA_START as u64 - TREE_INFO_SIZE as u64 - QUEUE_NODE_UNCOUNTED)
            / QUEUE_ENTRY_BYTES;
        let cap = u64::from(Self::cap(block_size));
        let nodes = |entries: u64| -> u16 {
            let needed = entries.div_ceil(per_node).max(1);
            let needed = if needed == 2 { 3 } else { needed };
            narrow(needed.min(cap))
        };
        let share = match block_count {
            n if n < 1 << 18 => 32,
            n if n < 1 << 20 => 16,
            _ => 8,
        };
        let pool_blocks = ChunkGeometry::of(block_count, block_size).pool_blocks();
        Self {
            pool: nodes(pool_blocks.div_ceil(8)),
            main: nodes(block_count.div_ceil(share)),
        }
    }

    /// The most nodes either queue of a container of blocks of `block_size` bytes is limited
    /// to: two mebibytes of them.
    pub(crate) fn cap(block_size: u32) -> u16 {
        narrow(QUEUE_LIMIT_BYTES / u64::from(block_size))
    }
}

/// An object map's two blocks: the object, and its tree's one node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MapPlace {
    /// The object map.
    pub object: u64,
    /// Its tree's root, a leaf.
    pub root: u64,
}

/// Where one volume's objects are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct VolumePlace {
    /// The volume's object map.
    pub object_map: MapPlace,
    /// The extent-reference tree's root.
    pub extent_ref_tree: u64,
    /// The snapshot tree's root.
    pub snapshot_tree: u64,
    /// The file-system tree's root.
    pub root_tree: u64,
    /// The volume's superblock.
    pub superblock: u64,
}

impl VolumePlace {
    /// Every block the volume's objects occupy, in the order they are allocated.
    pub(crate) const fn blocks(&self) -> [u64; 6] {
        [
            self.object_map.object,
            self.object_map.root,
            self.extent_ref_tree,
            self.snapshot_tree,
            self.root_tree,
            self.superblock,
        ]
    }
}

/// The free queues' root nodes, in the checkpoint data area.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct QueueRoots {
    /// The internal pool's queue.
    pub pool: u64,
    /// The main device's queue.
    pub main: u64,
}

/// A chunk's bitmap block, in the internal pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ChunkBitmap {
    /// The chunk.
    pub chunk: u64,
    /// The block holding its bitmap.
    pub block: u64,
}

/// Where everything one checkpoint writes or keeps is.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Checkpoint {
    /// The transaction that writes it: 1 for the container alone, 2 for its volumes.
    pub xid: u64,
    /// Its checkpoint-mapping block, in the descriptor area.
    pub map: u64,
    /// Its copy of the container superblock, in the descriptor area.
    pub superblock: u64,
    /// The first block of its space manager, in the data area.
    pub space_manager: u64,
    /// Its reaper, in the data area.
    pub reaper: u64,
    /// The free queues' roots, in the data area: the second checkpoint has them, holding what
    /// it freed, and the first has none.
    pub queues: Option<QueueRoots>,
    /// The container's object map.
    pub object_map: MapPlace,
    /// The volumes, by slot: none in the first checkpoint.
    pub volumes: Vec<VolumePlace>,
    /// The address blocks the space manager lists, by index; empty where it lists chunk-info
    /// blocks itself.
    pub cab_blocks: Vec<u64>,
    /// The chunk-info blocks, by index.
    pub cib_blocks: Vec<u64>,
    /// The bitmap block of every chunk that has one, by chunk. A chunk with no block in use
    /// has none.
    pub bitmaps: Vec<ChunkBitmap>,
    /// The slot in the pool-bitmap area each pool bitmap block occupies, by bitmap block.
    pub pool_bitmap_slots: Vec<u32>,
    /// The pool blocks this checkpoint freed, one at a time, in the order it freed them: what
    /// the internal pool's queue holds. The queue keeps a block freed beside a run it already
    /// holds as part of that run, so the order is what decides how its node is laid out.
    pub freed_pool: Vec<BlockRange>,
    /// The main-device runs this checkpoint freed, in the order it freed them: what the main
    /// queue holds.
    pub freed_main: Vec<BlockRange>,
    /// The main-device runs this checkpoint allocated past the objects every container of its
    /// size has, in the order it allocated them: what its volumes hold, their files' data and
    /// attributes and the nodes of their trees past each root. Empty in a container formatted
    /// with nothing in it.
    pub content: Vec<BlockRange>,
}

/// Everything about a container that is decided before a byte of it is written.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ApfsLayout {
    /// The size of every block.
    pub block_size: u32,
    /// Blocks in the container.
    pub block_count: u64,
    /// How many volumes the container may ever hold: one per 512 MiB, at most 100.
    pub max_volumes: u32,
    /// The checkpoint descriptor area, from block 1.
    pub descriptor_area: BlockRange,
    /// The checkpoint data area, right after it.
    pub data_area: BlockRange,
    /// How the blocks divide into chunks.
    pub chunks: ChunkGeometry,
    /// The space manager's size and arrays.
    pub space_manager: SpaceManagerShape,
    /// The pool-bitmap area, right after the data area: sixteen slots per pool bitmap block.
    pub pool_bitmap_area: BlockRange,
    /// Pool bitmap blocks: one bit per pool block.
    pub pool_bitmaps: u32,
    /// The internal pool, right after the pool-bitmap area: room for every chunk-info, address
    /// and bitmap block three times over.
    pub pool: BlockRange,
    /// How many nodes each free queue may grow to.
    pub queue_node_limits: QueueNodeLimits,
    /// The fewest blocks of the checkpoint data area each ephemeral structure is given, as the
    /// container superblock records it.
    pub ephemeral_min_blocks: u32,
    /// The two checkpoints a container is formatted with, the first holding the container
    /// alone and the second, the newest, its volumes too.
    pub checkpoints: [Checkpoint; 2],
}

/// The most blocks a write of up to a mebibyte asks for beside its data: the ask of an insert
/// is 100 blocks and nine for each record it changes, and such a write changes at most eight.
const LARGEST_WRITE_ASK: u64 = 100 + 9 * 8;

/// The most room macOS gives a growing file ahead of it in one change, in blocks.
const LARGEST_STEP: u64 = 4095;

/// The most blocks a transaction held beside a change macOS refused.
const MOST_HELD: u64 = 143;

/// A mebibyte: the largest write [`ApfsLayout::writable_blocks`] counts room for.
const MEBIBYTE: u64 = 1 << 20;

/// What macOS keeps free before a write of up to a mebibyte by a process of any user, in a
/// container of `blocks` blocks of `block_size` bytes: the most such a write asks for, its data's
/// blocks among it, the margin beside the ask, and the largest room a growing file is given
/// ahead of it with what a transaction holds beside that.
pub(crate) const fn macos_reserve(blocks: u64, block_size: u64) -> u64 {
    const fn held(x: u64, low: u64, high: u64) -> u64 {
        if x < low {
            low
        } else if x > high {
            high
        } else {
            x
        }
    }
    let hundredth = blocks / 100;
    LARGEST_WRITE_ASK
        + MEBIBYTE.div_ceil(block_size)
        + held(hundredth, 100, 4000)
        + held(hundredth, 25, 4096)
        + LARGEST_STEP
        + MOST_HELD
}

impl ApfsLayout {
    /// The newest checkpoint: the one block zero copies.
    #[must_use]
    pub const fn newest(&self) -> &Checkpoint {
        &self.checkpoints[1]
    }

    /// The blocks of the container the newest checkpoint's space manager records free.
    ///
    /// The two blocks of the first checkpoint's object map are in the main free queue, which
    /// holds them until a later transaction takes them out of it, so they are not counted here.
    /// macOS reports them as free capacity beside these.
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        let [_, newest] = self.in_use();
        self.block_count - newest.iter().map(|run| run.count).sum::<u64>()
    }

    /// The blocks a process of any user can write into once macOS mounts the container, in
    /// writes of up to a mebibyte: the [free blocks](Self::free_blocks) less what macOS keeps
    /// free before the last of them.
    ///
    /// What [`FormatPlan::fit`](super::FormatPlan::fit) measures the room it leaves in. macOS 15,
    /// 26 and 27 refuse a change where fewer blocks are free than it asks for, what its
    /// transaction already holds, and a margin. A write of up to a mebibyte into a file asks for
    /// its data's blocks and at most 172 more, and the margin for a process of any user is a
    /// hundredth of the container's blocks counted twice, once held to 100 to 4,000 and once to
    /// 25 to 4,096. A file that grows is given room ahead of it, once it is large as much as
    /// 4,095 blocks in one change, which asks for those and 256 more with no margin, and a
    /// transaction held at most 143 blocks at any change refused.
    ///
    /// All of it is kept out of this count, so a writer that writes this many blocks with no write
    /// larger than a mebibyte has every write taken, however its files are written and synced.
    #[must_use]
    pub fn writable_blocks(&self) -> u64 {
        self.free_blocks()
            .saturating_sub(macos_reserve(self.block_count, u64::from(self.block_size)))
    }

    /// The main-device blocks each checkpoint holds in use, as runs.
    ///
    /// The first holds everything up to the end of the internal pool and its object map. The
    /// second holds those too, since its free queues still hold what it freed, and beside them
    /// its volumes' objects, its own object map and everything its volumes hold.
    pub(crate) fn in_use(&self) -> [Vec<BlockRange>; 2] {
        let [first, second] = &self.checkpoints;
        let pool_end = self.pool.start + self.pool.count;
        let mut first_main = vec![
            BlockRange {
                start: 0,
                count: pool_end,
            },
            BlockRange {
                start: first.object_map.object,
                count: 2,
            },
        ];
        first_main.sort_by_key(|run| run.start);
        let mut second_main = first_main.clone();
        for volume in &second.volumes {
            second_main.extend(
                volume
                    .blocks()
                    .into_iter()
                    .map(|start| BlockRange { start, count: 1 }),
            );
        }
        second_main.push(BlockRange {
            start: second.object_map.object,
            count: 2,
        });
        second_main.extend(second.content.iter().copied());
        [first_main, second_main]
    }
}

/// Plan a container.
///
/// # Errors
///
/// [`GeometryError`], for a container smaller than [`MIN_BLOCK_COUNT`] blocks or larger than
/// [`MAX_CONTAINER_BYTES`], for no volume, or for more volumes than the container has slots
/// for.
pub fn plan_layout(request: &PlanRequest) -> Result<ApfsLayout, GeometryError> {
    let block_size = request.block_size.bytes();
    let block_count = request.container_bytes / u64::from(block_size);
    let bytes = block_count * u64::from(block_size);
    if block_count < MIN_BLOCK_COUNT {
        return Err(GeometryError::ContainerTooSmall {
            bytes: request.container_bytes,
            block_size,
            block_count,
        });
    }
    if bytes > MAX_CONTAINER_BYTES {
        return Err(GeometryError::ContainerTooLarge { bytes });
    }
    if request.volumes == 0 {
        return Err(GeometryError::NoVolumes);
    }
    let sizing = Sizing::of(block_count, block_size);
    if request.volumes > sizing.max_volumes {
        return Err(GeometryError::TooManyVolumes {
            bytes,
            volumes: request.volumes,
            max_volumes: sizing.max_volumes,
        });
    }
    let places = Places::of(&sizing, request.volumes);
    Ok(sizing.layout(&places, &[]))
}

/// A plan in the making, handing out the main-device blocks the second transaction allocates
/// for what its volumes hold.
///
/// Every block is taken first-fit from the end of the internal pool, in the order asked for,
/// passing over the blocks of the objects every container of its size has. A run those objects
/// interrupt goes on past them, so one request may come back as two runs or more.
pub(crate) struct ContentPlanner {
    sizing: Sizing,
    places: Places,
    /// The blocks of `places`, in ascending order.
    planned: Vec<u64>,
    /// The next block a request may take.
    next: u64,
    /// Every run taken, in the order it was taken.
    content: Vec<BlockRange>,
}

impl ContentPlanner {
    /// A planner for the container `request` describes.
    ///
    /// # Errors
    ///
    /// The [`GeometryError`] [`plan_layout`] gives for the same request.
    pub(crate) fn new(request: &PlanRequest) -> Result<Self, GeometryError> {
        let layout = plan_layout(request)?;
        let sizing = Sizing::of(layout.block_count, layout.block_size);
        let places = Places::of(&sizing, request.volumes);
        let mut planned: Vec<u64> = places
            .volumes
            .iter()
            .flat_map(VolumePlace::blocks)
            .chain([places.first_map.object, places.first_map.root])
            .chain([places.second_map.object, places.second_map.root])
            .collect();
        planned.sort_unstable();
        Ok(Self {
            next: sizing.pool_end(),
            sizing,
            places,
            planned,
            content: Vec::new(),
        })
    }

    /// The size of every block.
    pub(crate) const fn block_size(&self) -> u32 {
        self.sizing.block_size
    }

    /// Where the objects every container of its size has put the volume in `slot`.
    pub(crate) fn volume_place(&self, slot: u64) -> VolumePlace {
        self.places.volumes[usize::try_from(slot).expect("a slot fits memory")]
    }

    /// `blocks` blocks, as the runs they were found in.
    ///
    /// # Errors
    ///
    /// [`GeometryError::ContainerFull`] where the container has fewer free blocks than that.
    pub(crate) fn take(&mut self, blocks: u64) -> Result<Vec<BlockRange>, GeometryError> {
        let mut runs: Vec<BlockRange> = Vec::new();
        let mut wanted = blocks;
        while wanted > 0 {
            // Past any planned block the cursor is on, then up to the next planned block.
            let at = self.planned.partition_point(|&b| b < self.next);
            if self.planned.get(at) == Some(&self.next) {
                self.next += 1;
                continue;
            }
            let limit = self
                .planned
                .get(at)
                .copied()
                .unwrap_or(self.sizing.block_count);
            if self.next >= self.sizing.block_count {
                return Err(GeometryError::ContainerFull {
                    bytes: self.sizing.block_count * u64::from(self.sizing.block_size),
                    free: self.free(),
                });
            }
            let count = wanted.min(limit - self.next);
            match runs.last_mut() {
                Some(run) if run.start + run.count == self.next => run.count += count,
                _ => runs.push(BlockRange {
                    start: self.next,
                    count,
                }),
            }
            self.next += count;
            wanted -= count;
        }
        self.content.extend(runs.iter().copied());
        Ok(runs)
    }

    /// Every block free for content in an empty container of this size.
    fn free(&self) -> u64 {
        let start = self.sizing.pool_end();
        let in_range = self.planned.iter().filter(|&&b| b >= start).count() as u64;
        self.sizing.block_count - start - in_range
    }

    /// Keep every `every`th block from here on from the content, as though a planned object
    /// were there, so every run a request takes is broken: for the gates that hold the writer
    /// to streams and trees of many runs at a size a test can hold.
    #[cfg(test)]
    pub(crate) fn keep_every(&mut self, every: u64) {
        self.planned.extend(
            (self.next..self.sizing.block_count)
                .step_by(to_index(every))
                .skip(1),
        );
        self.planned.sort_unstable();
        self.planned.dedup();
    }

    /// The layout of the container, holding every run taken.
    pub(crate) fn finish(self) -> ApfsLayout {
        self.sizing.layout(&self.places, &self.content)
    }
}

/// The layout of a container of `block_count` blocks with no floor or ceiling applied: what the
/// rules give a container smaller than [`MIN_BLOCK_COUNT`], which `newfs_apfs` formats and
/// `fsck_apfs` refuses, for the gates that hold the rules there.
#[cfg(test)]
pub(crate) fn layout_of(block_count: u64, block_size: u32, volumes: u32) -> ApfsLayout {
    let sizing = Sizing::of(block_count, block_size);
    sizing.layout(&Places::of(&sizing, volumes), &[])
}

/// Everything about a container that follows from its block count and block size alone.
#[derive(Clone, Copy, Debug)]
struct Sizing {
    block_size: u32,
    block_count: u64,
    chunks: ChunkGeometry,
    manager: SpaceManagerShape,
    pool_bitmaps: u32,
    pool_bitmap_area: BlockRange,
    pool: BlockRange,
    limits: QueueNodeLimits,
    max_volumes: u32,
    ephemeral_min_blocks: u32,
    descriptor_area: BlockRange,
    data_area: BlockRange,
}

impl Sizing {
    fn of(block_count: u64, block_size: u32) -> Self {
        let bs = u64::from(block_size);
        let chunks = ChunkGeometry::of(block_count, block_size);

        let pool_blocks = chunks.pool_blocks();
        let pool_bitmaps = chunks.pool_bitmaps();
        let slots = u64::from(POOL_BITMAP_SLOTS) * pool_bitmaps;
        let (arrays, list_end) = chunks.manager_layout();
        let manager_blocks = list_end.div_ceil(bs);

        let limits = QueueNodeLimits::of(block_count, block_size);
        let ephemeral_min_blocks = u32::from(limits.main).min(8);
        // At most 100, so it fits its field.
        let max_volumes: u32 = narrow(
            (block_count * bs)
                .div_ceil(BYTES_PER_VOLUME_SLOT)
                .min(MAX_VOLUMES as u64),
        );

        // The data area is four fitted terms: four blocks, eight per space-manager block,
        // thirty-two per ephemeral-minimum block per volume slot, and four per queue node either
        // queue may grow to. The descriptor area holds enough mapping blocks to map all of it,
        // rounded up to four, and four more: a data area that needs one mapping block gives
        // eight, and one that needs 252 gives 256, which pins the four exactly.
        let data_blocks = 4
            + 8 * manager_blocks
            + 32 * u64::from(ephemeral_min_blocks) * u64::from(max_volumes)
            + 4 * (u64::from(limits.pool) + u64::from(limits.main));
        let per_map = (bs - CheckpointMap::MAPPINGS_AT as u64) / CheckpointMapping::SIZE as u64;
        let map_blocks = data_blocks.div_ceil(per_map);
        let descriptor_blocks = 4 * map_blocks.div_ceil(4) + 4;

        let descriptor_area = BlockRange {
            start: 1,
            count: descriptor_blocks,
        };
        let data_area = BlockRange {
            start: descriptor_area.start + descriptor_blocks,
            count: data_blocks,
        };
        let pool_bitmap_area = BlockRange {
            start: data_area.start + data_blocks,
            count: slots,
        };
        let pool = BlockRange {
            start: pool_bitmap_area.start + slots,
            count: pool_blocks,
        };
        Self {
            block_size,
            block_count,
            chunks,
            manager: SpaceManagerShape {
                blocks: narrow(manager_blocks),
                bitmap_xid_offset: narrow(arrays.xids),
                bitmap_slot_offset: narrow(arrays.slots),
                bitmap_free_list_offset: narrow(arrays.free_list),
                address_offset: narrow(arrays.addresses),
                second_address_offset: narrow(list_end),
            },
            pool_bitmaps: narrow(pool_bitmaps),
            pool_bitmap_area,
            pool,
            limits,
            max_volumes,
            ephemeral_min_blocks,
            descriptor_area,
            data_area,
        }
    }

    /// The first block past the internal pool: where the main space's objects begin in a
    /// container small enough for them to follow it.
    const fn pool_end(&self) -> u64 {
        self.pool.start + self.pool.count
    }

    /// The layout of a container whose objects outside the checkpoint areas are at `places`,
    /// whose second transaction allocates the runs of `content` past them, in that order.
    fn layout(&self, places: &Places, content: &[BlockRange]) -> ApfsLayout {
        let manager_blocks = u64::from(self.manager.blocks);
        let desc = self.descriptor_area.start;
        let data = self.data_area.start;
        let mut pool = PoolCursor {
            next: self.pool.start,
        };

        // The first transaction writes every chunk-info block, each address block before the
        // chunk-info blocks it lists, then a bitmap for every chunk holding a block in use, in
        // chunk order: the blocks up to the pool's end, and the first object map.
        let cibs = to_index(self.chunks.cib_count);
        let per_cab = to_index(self.chunks.cibs_per_cab);
        let mut cab_blocks = Vec::with_capacity(to_index(self.chunks.cab_count));
        let mut cib_blocks = Vec::with_capacity(cibs);
        if self.chunks.cab_count > 0 {
            for cab in 0..to_index(self.chunks.cab_count) {
                cab_blocks.push(pool.take());
                for _ in 0..per_cab.min(cibs - cab * per_cab) {
                    cib_blocks.push(pool.take());
                }
            }
        } else {
            cib_blocks.extend((0..cibs).map(|_| pool.take()));
        }
        let first_map = places.first_map;
        let mut touched: Vec<u64> = (0..=self.chunks.chunk_of(self.pool_end() - 1))
            .chain([first_map.object, first_map.root].map(|block| self.chunks.chunk_of(block)))
            .collect();
        touched.sort_unstable();
        touched.dedup();
        let first_bitmaps: Vec<ChunkBitmap> = touched
            .into_iter()
            .map(|chunk| ChunkBitmap {
                chunk,
                block: pool.take(),
            })
            .collect();
        let first_pool_end = pool.next;
        let first = Checkpoint {
            xid: FIRST_XID,
            map: desc,
            superblock: desc + 1,
            space_manager: data,
            reaper: data + manager_blocks,
            queues: None,
            object_map: first_map,
            volumes: Vec::new(),
            cab_blocks: cab_blocks.clone(),
            cib_blocks: cib_blocks.clone(),
            bitmaps: first_bitmaps.clone(),
            pool_bitmap_slots: (0..self.pool_bitmaps).collect(),
            freed_pool: Vec::new(),
            freed_main: Vec::new(),
            content: Vec::new(),
        };

        // The second transaction allocates each volume's objects, then the second object map,
        // then what the volumes hold, and for every chunk that changes, in the order its first
        // block is allocated, writes the chunk's address block (if any, and not yet), its
        // chunk-info block (if not yet) and its bitmap to the next pool blocks, freeing the
        // blocks they supersede.
        let allocated = places
            .volumes
            .iter()
            .flat_map(VolumePlace::blocks)
            .chain([places.second_map.object, places.second_map.root])
            .map(|start| BlockRange { start, count: 1 })
            .chain(content.iter().copied());
        let chunk_count = to_index(self.chunks.chunk_count);
        let mut seen = vec![false; chunk_count];
        let mut dirty: Vec<u64> = Vec::new();
        for run in allocated {
            let last = self.chunks.chunk_of(run.start + run.count - 1);
            for chunk in self.chunks.chunk_of(run.start)..=last {
                if !std::mem::replace(&mut seen[to_index(chunk)], true) {
                    dirty.push(chunk);
                }
            }
        }
        let per_cib = self.chunks.chunks_per_cib;
        let mut freed = Vec::new();
        let mut cab_done = vec![false; to_index(self.chunks.cab_count)];
        let mut cib_done = vec![false; cibs];
        let mut bitmap_of: Vec<Option<usize>> = vec![None; chunk_count];
        let mut bitmaps = first_bitmaps;
        for (i, bitmap) in bitmaps.iter().enumerate() {
            bitmap_of[to_index(bitmap.chunk)] = Some(i);
        }
        for chunk in dirty {
            let cib = chunk / per_cib;
            if self.chunks.cab_count > 0 {
                let cab = cib / self.chunks.cibs_per_cab;
                let at = to_index(cab);
                if !std::mem::replace(&mut cab_done[at], true) {
                    freed.push(cab_blocks[at]);
                    cab_blocks[at] = pool.take();
                }
            }
            let at = to_index(cib);
            if !std::mem::replace(&mut cib_done[at], true) {
                freed.push(cib_blocks[at]);
                cib_blocks[at] = pool.take();
            }
            match bitmap_of[to_index(chunk)] {
                Some(i) => {
                    freed.push(bitmaps[i].block);
                    bitmaps[i].block = pool.take();
                }
                None => bitmaps.push(ChunkBitmap {
                    chunk,
                    block: pool.take(),
                }),
            }
        }
        bitmaps.sort_unstable_by_key(|bitmap| bitmap.chunk);

        // A pool bitmap block whose blocks the second transaction allocated from is written
        // again, into the next free slot past the ones the first used; the rest keep theirs.
        // The second transaction always allocates: its object map changes a chunk.
        let per_bitmap = self.chunks.blocks_per_chunk;
        let first_bitmap = (first_pool_end - self.pool.start) / per_bitmap;
        let last_bitmap = (pool.next - 1 - self.pool.start) / per_bitmap;
        let mut slots: Vec<u32> = (0..self.pool_bitmaps).collect();
        for (slot, bitmap) in (self.pool_bitmaps..).zip(first_bitmap..=last_bitmap) {
            slots[to_index(bitmap)] = slot;
        }

        let second_manager = data + manager_blocks + 1;
        let reaper = second_manager + manager_blocks;
        let second = Checkpoint {
            xid: SECOND_XID,
            map: desc + 2,
            superblock: desc + 3,
            space_manager: second_manager,
            reaper,
            queues: Some(QueueRoots {
                pool: reaper + 1,
                main: reaper + 2,
            }),
            object_map: places.second_map,
            volumes: places.volumes.clone(),
            cab_blocks,
            cib_blocks,
            bitmaps,
            pool_bitmap_slots: slots,
            freed_pool: freed
                .into_iter()
                .map(|start| BlockRange { start, count: 1 })
                .collect(),
            freed_main: vec![BlockRange {
                start: first_map.object,
                count: 2,
            }],
            content: content.to_vec(),
        };

        ApfsLayout {
            block_size: self.block_size,
            block_count: self.block_count,
            max_volumes: self.max_volumes,
            descriptor_area: self.descriptor_area,
            data_area: self.data_area,
            chunks: self.chunks,
            space_manager: self.manager,
            pool_bitmap_area: self.pool_bitmap_area,
            pool_bitmaps: self.pool_bitmaps,
            pool: self.pool,
            queue_node_limits: self.limits,
            ephemeral_min_blocks: self.ephemeral_min_blocks,
            checkpoints: [first, second],
        }
    }
}

/// Where the objects outside the checkpoint areas are.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Places {
    first_map: MapPlace,
    volumes: Vec<VolumePlace>,
    second_map: MapPlace,
}

impl Places {
    /// Where a plan puts them in a container of `sizing` with `volumes` volumes.
    ///
    /// For one volume this is where `newfs_apfs` put them in every container measured. A
    /// second volume and more take the places the first's take, one after another, and the
    /// second object map moves past them all.
    fn of(sizing: &Sizing, volumes: u32) -> Self {
        let volumes = u64::from(volumes);
        let map = |at: u64| MapPlace {
            object: at,
            root: at + 1,
        };
        let volume = |map_at: u64, objects_at: u64| VolumePlace {
            object_map: map(map_at),
            extent_ref_tree: objects_at,
            snapshot_tree: objects_at + 1,
            root_tree: objects_at + 2,
            superblock: objects_at + 3,
        };
        let places = if sizing.block_count <= LAST_CONTIGUOUS_BLOCK_COUNT {
            let start = sizing.pool_end();
            Self {
                first_map: map(start),
                volumes: (0..volumes)
                    .map(|i| volume(start + 2 + 6 * i, start + 4 + 6 * i))
                    .collect(),
                second_map: map(start + 2 + 6 * volumes),
            }
        } else {
            let (objects, maps) = far_placement(sizing.block_count, sizing.block_size);
            Self {
                first_map: map(maps),
                volumes: (0..volumes)
                    .map(|i| volume(maps + 2 + 2 * i, objects + 4 * i))
                    .collect(),
                second_map: map(maps + 2 + 2 * volumes),
            }
        };
        // Every place is in the main space and inside the container: the smallest container
        // planned has 1,024 blocks and its pool ends by block 83, so the 10 blocks one volume
        // takes fit, and each further volume needs 512 MiB of container for its 6. Far
        // placements start at 65,536 blocks or past in a container of 1,572,864 or more, and the
        // second object map stays below twice the first place, at most a quarter of the way in.
        let pool_end = sizing.pool_end();
        let blocks = places
            .volumes
            .iter()
            .flat_map(VolumePlace::blocks)
            .chain([places.first_map.object, places.first_map.root])
            .chain([places.second_map.object, places.second_map.root]);
        for block in blocks {
            assert!(
                (pool_end..sizing.block_count).contains(&block),
                "block {block} is outside the main space of a {}-block container",
                sizing.block_count
            );
        }
        places
    }
}

/// Where a container too large for its objects to follow the pool keeps them: the block its
/// volumes' objects begin at, and the block its object maps begin at.
///
/// Both follow one measured quantity, `x`: the lesser of an eighth of the container's blocks and
/// a piecewise-linear function of its size counted in 4 KiB units, which is 65,536, plus a
/// sixty-fourth of the units between 2^22 and 2^24, an eightieth of those between 2^24 and 2^25,
/// a 256th of those between 2^25 and 2^26, and a 320th of those past 2^26. Where the two are
/// equal the piecewise value is the one taken. The eighth is the lesser at 64 KiB alone, from
/// the first container placed this way to 5,242,880 blocks.
///
/// The volumes' objects begin at `x`, and the object maps at `2x` less a gap of an eighth of
/// `x`, at most 2^27 bytes' worth of blocks. Each is rounded down, except that a piecewise value
/// past 2^26 units gives the largest whole number below it, which every container measured
/// where that value is whole shows. Exact on every container measured with its objects placed
/// this way, from 1,572,864 blocks to 16 TiB, at all five block sizes.
fn far_placement(block_count: u64, block_size: u32) -> (u64, u64) {
    // x in units of 1/1280: the common denominator of 8, 64, 80, 256 and 320.
    const SCALE: u64 = 1280;
    let units = block_count * u64::from(block_size) / 4096;
    let span = |from: u64, to: u64| units.min(to).saturating_sub(from);
    let piecewise = 65_536 * SCALE
        + span(1 << 22, 1 << 24) * (SCALE / 64)
        + span(1 << 24, 1 << 25) * (SCALE / 80)
        + span(1 << 25, 1 << 26) * (SCALE / 256)
        + units.saturating_sub(1 << 26) * (SCALE / 320);
    let eighth = block_count * (SCALE / 8);
    let (x, below_whole) = if eighth < piecewise {
        (eighth, false)
    } else {
        (piecewise, units > 1 << 26)
    };
    let gap = (x / (8 * SCALE)).min((1 << 27) / u64::from(block_size));
    if below_whole {
        ((x - 1) / SCALE, (2 * x - 1) / SCALE - gap)
    } else {
        (x / SCALE, 2 * x / SCALE - gap)
    }
}

/// The next block of the internal pool each allocation takes.
struct PoolCursor {
    next: u64,
}

impl PoolCursor {
    fn take(&mut self) -> u64 {
        let block = self.next;
        self.next += 1;
        block
    }
}

/// A count the planner derived, in the width the format records it in.
///
/// # Panics
///
/// Where it does not fit, which no container within the planned sizes reaches: each call site
/// says why its value is bounded.
pub(crate) fn narrow<T: TryFrom<u64>>(value: u64) -> T {
    T::try_from(value)
        .unwrap_or_else(|_| panic!("{value} does not fit the field the format records it in"))
}

/// A position in one of the plan's lists, a chunk-info or address block's index among them,
/// each a list held in memory.
pub(crate) fn to_index(index: u64) -> usize {
    usize::try_from(index).expect("a position in a list held in memory")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where `newfs_apfs` placed every object, read back from the containers it formatted.
    const NEWFS: &str = include_str!("fixtures/newfs-placements.txt");

    /// The same for every other size measured, each listing as its CRC-32C.
    const NEWFS_DIGESTS: &str = include_str!("fixtures/newfs-digests.txt");

    /// The containers each fixture holds, and the distinct listings they gave: a fixture that
    /// lost a record is a gate that compares less.
    const CONTAINERS: u64 = 1168;
    const RECORDS: usize = 212;
    const DIGEST_CONTAINERS: u64 = 6340;
    const DIGESTS: usize = 1582;

    fn runs(blocks: impl IntoIterator<Item = u64>) -> String {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for block in blocks {
            match out.last_mut() {
                Some((start, count)) if *start + *count == block => *count += 1,
                _ => out.push((block, 1)),
            }
        }
        if out.is_empty() {
            return "-".to_string();
        }
        let parts: Vec<String> = out.iter().map(|(s, n)| format!("{s}+{n}")).collect();
        parts.join(",")
    }

    /// What a checkpoint freed, as the ascending runs the fixture records, adjacent ones
    /// joined.
    fn freed(xid: u64, frees: &[BlockRange]) -> String {
        let mut blocks: Vec<u64> = frees
            .iter()
            .flat_map(|run| run.start..run.start + run.count)
            .collect();
        blocks.sort_unstable();
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for block in blocks {
            match runs.last_mut() {
                Some((start, count)) if *start + *count == block => *count += 1,
                _ => runs.push((block, 1)),
            }
        }
        if runs.is_empty() {
            return "-".to_string();
        }
        let parts: Vec<String> = runs
            .iter()
            .map(|(start, count)| format!("{xid}:{start}+{count}"))
            .collect();
        parts.join(",")
    }

    /// The plan in the form the fixture records `newfs_apfs`'s placements in, one fact a line.
    fn listing(layout: &ApfsLayout) -> Vec<String> {
        let c = &layout.chunks;
        let m = &layout.space_manager;
        let mut out = vec![
            format!("blocks {} {}", layout.block_count, layout.block_size),
            format!(
                "descriptor {} {}",
                layout.descriptor_area.start, layout.descriptor_area.count
            ),
            format!("data {} {}", layout.data_area.start, layout.data_area.count),
            format!(
                "chunks {} {} {} {} {} {}",
                c.blocks_per_chunk,
                c.chunks_per_cib,
                c.cibs_per_cab,
                c.chunk_count,
                c.cib_count,
                c.cab_count
            ),
            format!(
                "manager {} {} {} {} {} {}",
                m.blocks,
                m.address_offset,
                m.second_address_offset,
                m.bitmap_xid_offset,
                m.bitmap_slot_offset,
                m.bitmap_free_list_offset
            ),
            format!(
                "pool-bitmaps {} {} {}",
                layout.pool_bitmaps, layout.pool_bitmap_area.start, layout.pool_bitmap_area.count
            ),
            format!("pool {} {}", layout.pool.start, layout.pool.count),
            format!(
                "queue-limits {} {}",
                layout.queue_node_limits.pool, layout.queue_node_limits.main
            ),
            format!("max-volumes {}", layout.max_volumes),
            format!("ephemeral-min {}", layout.ephemeral_min_blocks),
        ];
        for cp in &layout.checkpoints {
            out.push(format!("tx {}", cp.xid));
            out.push(format!(" descriptor {} {}", cp.map, cp.superblock));
            out.push(format!(" manager {}", cp.space_manager));
            out.push(format!(" reaper {}", cp.reaper));
            if let Some(q) = cp.queues {
                out.push(format!(" queues {} {}", q.pool, q.main));
            }
            out.push(format!(
                " object-map {} {}",
                cp.object_map.object, cp.object_map.root
            ));
            for (slot, v) in cp.volumes.iter().enumerate() {
                out.push(format!(
                    " volume {slot} {} {} {} {} {} {}",
                    v.object_map.object,
                    v.object_map.root,
                    v.extent_ref_tree,
                    v.snapshot_tree,
                    v.root_tree,
                    v.superblock
                ));
            }
            out.push(format!(
                " address-blocks {}",
                runs(cp.cab_blocks.iter().copied())
            ));
            out.push(format!(
                " info-blocks {}",
                runs(cp.cib_blocks.iter().copied())
            ));
            let bitmaps: Vec<String> = cp
                .bitmaps
                .iter()
                .map(|b| format!("{}:{}", b.chunk, b.block))
                .collect();
            out.push(format!(
                " bitmaps {}",
                if bitmaps.is_empty() {
                    "-".to_string()
                } else {
                    bitmaps.join(",")
                }
            ));
            out.push(format!(
                " pool-bitmap-slots {}",
                runs(cp.pool_bitmap_slots.iter().map(|&s| u64::from(s)))
            ));
            if cp.queues.is_some() {
                out.push(format!(" freed-pool {}", freed(cp.xid, &cp.freed_pool)));
                out.push(format!(" freed-main {}", freed(cp.xid, &cp.freed_main)));
            }
        }
        out
    }

    /// One record of the fixture.
    struct Record<'a> {
        hows: Vec<&'a str>,
        containers: u64,
        lines: Vec<&'a str>,
    }

    fn records() -> Vec<Record<'static>> {
        let mut out: Vec<Record<'static>> = Vec::new();
        for line in NEWFS.lines() {
            if line.starts_with('#') {
                continue;
            }
            if let Some(head) = line.strip_prefix("@ ") {
                let mut words = head.split(' ');
                let hows = words
                    .next()
                    .expect("a record names how")
                    .split('+')
                    .collect();
                let containers = words
                    .next()
                    .and_then(|n| n.parse().ok())
                    .expect("a record counts its containers");
                out.push(Record {
                    hows,
                    containers,
                    lines: Vec::new(),
                });
            } else {
                out.last_mut()
                    .expect("a listing follows a record's head")
                    .lines
                    .push(line);
            }
        }
        out
    }

    fn numbers(line: &str, after: &str) -> Vec<u64> {
        line.strip_prefix(after)
            .unwrap_or_else(|| panic!("{line:?} begins {after:?}"))
            .split(' ')
            .map(|n| n.parse().expect("a number"))
            .collect()
    }

    /// The sizing of a record's container, from its first line, below the floor or not: the
    /// floor is about what `fsck_apfs` opens, and the rules hold under it.
    fn sizing(record: &Record<'_>) -> Sizing {
        let head = numbers(record.lines[0], "blocks ");
        Sizing::of(head[0], u32::try_from(head[1]).expect("a block size"))
    }

    /// The places a record's listing names: its two object maps and its one volume.
    fn measured_places(record: &Record<'_>) -> Places {
        let at = |prefix: &str, nth: usize| -> Vec<u64> {
            let line = record
                .lines
                .iter()
                .filter(|l| l.starts_with(prefix))
                .nth(nth)
                .unwrap_or_else(|| panic!("the listing has {prefix:?}"));
            numbers(line, prefix)
        };
        let first = at(" object-map ", 0);
        let second = at(" object-map ", 1);
        let v = at(" volume 0 ", 0);
        Places {
            first_map: MapPlace {
                object: first[0],
                root: first[1],
            },
            volumes: vec![VolumePlace {
                object_map: MapPlace {
                    object: v[0],
                    root: v[1],
                },
                extent_ref_tree: v[2],
                snapshot_tree: v[3],
                root_tree: v[4],
                superblock: v[5],
            }],
            second_map: MapPlace {
                object: second[0],
                root: second[1],
            },
        }
    }

    fn assert_same(label: &str, planned: &[String], measured: &[&str]) {
        for (i, (p, m)) in planned.iter().zip(measured).enumerate() {
            assert_eq!(p, m, "{label}: line {i} differs");
        }
        assert_eq!(planned.len(), measured.len(), "{label}: listing length");
    }

    #[test]
    fn every_object_is_planned_where_newfs_apfs_placed_it() {
        let records = records();
        assert_eq!(records.len(), RECORDS, "the fixture's records");
        assert_eq!(
            records.iter().map(|r| r.containers).sum::<u64>(),
            CONTAINERS,
            "the containers the fixture holds"
        );
        let mut far_devices = 0;
        for record in &records {
            let sizing = sizing(record);
            let label = format!("{} ({})", record.lines[0], record.hows.join("+"));
            let planned = listing(&sizing.layout(&Places::of(&sizing, 1), &[]));
            if record.hows.contains(&"file") {
                assert_same(&label, &planned, &record.lines);
            } else if record.hows == ["container-only"] {
                // The first transaction alone: everything to the second.
                let first = planned
                    .iter()
                    .position(|l| l == "tx 2")
                    .expect("a plan has two transactions");
                assert_same(&label, &planned[..first], &record.lines);
            } else {
                // `newfs_apfs` on an attached disk puts the second transaction's objects
                // elsewhere in a container too large for them to follow the pool, and nowhere
                // else differs: the first transaction, and every block the second places once
                // its objects are where that disk's were, are where a plan puts them.
                assert_eq!(record.hows, ["device"], "{label}");
                assert!(
                    sizing.block_count > LAST_CONTIGUOUS_BLOCK_COUNT,
                    "{label}: an attached disk diverges only past the contiguous limit"
                );
                far_devices += 1;
                let second = planned
                    .iter()
                    .position(|l| l == "tx 2")
                    .expect("a plan has two transactions");
                assert_same(&label, &planned[..second], &record.lines[..second]);
                assert_ne!(
                    planned[second..],
                    record.lines[second..],
                    "{label}: the attached disk's placement is its own"
                );
                let placed = listing(&sizing.layout(&measured_places(record), &[]));
                assert_same(&label, &placed, &record.lines);
            }
        }
        assert_eq!(
            far_devices, 12,
            "the attached disks past the contiguous limit"
        );
    }

    #[test]
    fn every_other_size_measured_is_planned_as_newfs_apfs_laid_it_out() {
        let mut digests = 0;
        let mut containers = 0;
        for line in NEWFS_DIGESTS.lines().filter(|l| !l.starts_with('#')) {
            let words: Vec<&str> = line.split(' ').collect();
            let number = |i: usize| -> u64 { words[i].parse().expect("a number") };
            let sizing = Sizing::of(number(0), u32::try_from(number(1)).expect("a block size"));
            let measured = u32::from_str_radix(words[2], 16).expect("a checksum");
            let planned = listing(&sizing.layout(&Places::of(&sizing, 1), &[])).join("\n");
            assert_eq!(
                !crate::crc32c(!0, planned.as_bytes()),
                measured,
                "{} blocks of {}: the plan's listing is not newfs_apfs's; the plan's is\n{planned}",
                words[0],
                words[1]
            );
            digests += 1;
            containers += number(3);
        }
        assert_eq!(digests, DIGESTS, "the fixture's listings");
        assert_eq!(
            containers, DIGEST_CONTAINERS,
            "the containers the fixture holds"
        );
    }

    #[test]
    fn a_container_below_the_floor_or_above_the_ceiling_is_refused() {
        let below = PlanRequest::new(MIN_BLOCK_COUNT * 4096 - 1);
        assert_eq!(
            plan_layout(&below),
            Err(GeometryError::ContainerTooSmall {
                bytes: MIN_BLOCK_COUNT * 4096 - 1,
                block_size: 4096,
                block_count: MIN_BLOCK_COUNT - 1,
            })
        );
        assert!(plan_layout(&PlanRequest::new(MIN_BLOCK_COUNT * 4096)).is_ok());
        // The floor counts blocks: four mebibytes of 64 KiB blocks is 64 of them.
        let large_blocks = PlanRequest::new(4 << 20).block_size(BlockSize::K64);
        assert!(matches!(
            plan_layout(&large_blocks),
            Err(GeometryError::ContainerTooSmall {
                block_count: 64,
                ..
            })
        ));
        assert!(plan_layout(&PlanRequest::new(64 << 20).block_size(BlockSize::K64)).is_ok());
        assert!(plan_layout(&PlanRequest::new(MAX_CONTAINER_BYTES)).is_ok());
        assert_eq!(
            plan_layout(&PlanRequest::new(MAX_CONTAINER_BYTES + 4096)),
            Err(GeometryError::ContainerTooLarge {
                bytes: MAX_CONTAINER_BYTES + 4096
            })
        );
        // A remainder smaller than a block is left out before the ceiling is applied.
        assert!(plan_layout(&PlanRequest::new(MAX_CONTAINER_BYTES + 4095)).is_ok());
    }

    #[test]
    fn a_container_diskutil_resized_is_sized_as_one_formatted_at_its_new_size() {
        // What each container `diskutil apfs resizeContainer` left recorded, at 4 KiB, on macOS
        // 15, 26 and 27 alike, shrunk and grown: block count, then the free queues' node limits,
        // the internal pool's blocks and the checkpoint data area's.
        let resized: [(u64, u16, u16, u64, u64); 4] = [
            (244_140, 1, 54, 27, 744),
            (488_281, 1, 215, 48, 1_900),
            (488_282, 1, 215, 48, 1_900),
            (16_726_006, 3, 512, 1_548, 27_672),
        ];
        for (block_count, pool, main, pool_blocks, data_blocks) in resized {
            let layout = layout_of(block_count, 4096, 1);
            assert_eq!(
                layout.queue_node_limits,
                QueueNodeLimits { pool, main },
                "{block_count}"
            );
            assert_eq!(
                (layout.pool.count, layout.data_area.count),
                (pool_blocks, data_blocks),
                "{block_count}"
            );
        }
    }

    #[test]
    fn a_container_holds_one_volume_per_512_mib_up_to_100() {
        assert_eq!(
            plan_layout(&PlanRequest::new(64 << 20).volumes(0)),
            Err(GeometryError::NoVolumes)
        );
        assert_eq!(
            plan_layout(&PlanRequest::new(512 << 20).volumes(2)),
            Err(GeometryError::TooManyVolumes {
                bytes: 512 << 20,
                volumes: 2,
                max_volumes: 1,
            })
        );
        let two = plan_layout(&PlanRequest::new((512 << 20) + 4096).volumes(2)).expect("two fit");
        assert_eq!(two.max_volumes, 2);
        assert_eq!(two.newest().volumes.len(), 2);
        let full = plan_layout(&PlanRequest::new(1 << 40).volumes(100)).expect("a hundred fit");
        assert_eq!(full.max_volumes, 100);
        assert!(matches!(
            plan_layout(&PlanRequest::new(1 << 40).volumes(101)),
            Err(GeometryError::TooManyVolumes {
                max_volumes: 100,
                ..
            })
        ));
    }

    /// Every block a plan places: the area it belongs in, and what it is.
    fn placed_blocks(layout: &ApfsLayout) -> Vec<(u64, &'static str, String)> {
        let mut out = Vec::new();
        let mut put = |block: u64, area: &'static str, what: String| out.push((block, area, what));
        put(0, "zero", "block zero".into());
        for cp in &layout.checkpoints {
            let x = cp.xid;
            put(cp.map, "descriptor", format!("map {x}"));
            put(cp.superblock, "descriptor", format!("superblock {x}"));
            for i in 0..u64::from(layout.space_manager.blocks) {
                put(cp.space_manager + i, "data", format!("space manager {x}"));
            }
            put(cp.reaper, "data", format!("reaper {x}"));
            if let Some(q) = cp.queues {
                put(q.pool, "data", format!("pool queue {x}"));
                put(q.main, "data", format!("main queue {x}"));
            }
            put(cp.object_map.object, "main", format!("object map {x}"));
            put(cp.object_map.root, "main", format!("object map root {x}"));
            for (slot, v) in cp.volumes.iter().enumerate() {
                for (i, block) in v.blocks().into_iter().enumerate() {
                    put(block, "main", format!("volume {slot} object {i} {x}"));
                }
            }
            // What the second checkpoint keeps of the first's is named alike in both, so the
            // one block it is at is one object.
            for (bitmap, slot) in cp.pool_bitmap_slots.iter().enumerate() {
                let block = layout.pool_bitmap_area.start + u64::from(*slot);
                put(
                    block,
                    "pool bitmaps",
                    format!("pool bitmap {bitmap} in slot {slot}"),
                );
            }
            for (i, &b) in cp.cab_blocks.iter().enumerate() {
                put(b, "pool", format!("address block {i} at {b}"));
            }
            for (i, &b) in cp.cib_blocks.iter().enumerate() {
                put(b, "pool", format!("chunk-info block {i} at {b}"));
            }
            for b in &cp.bitmaps {
                put(
                    b.block,
                    "pool",
                    format!("bitmap of chunk {} at {}", b.chunk, b.block),
                );
            }
        }
        out
    }

    #[test]
    fn every_plan_keeps_each_object_in_its_area_and_apart_from_every_other() {
        // Sizes across both placements and every block size, each with one volume and with as
        // many as it has slots for. What the first checkpoint keeps and the second keeps again
        // is one block; anything else at one block twice is two objects in one place.
        let mut sizes: Vec<u64> = Vec::new();
        let mut bytes: u64 = 4 << 20;
        while bytes <= MAX_CONTAINER_BYTES {
            sizes.push(bytes);
            sizes.push(bytes / 7 * 5);
            bytes = bytes * 3 / 2;
        }
        sizes.push(MAX_CONTAINER_BYTES);
        let mut planned = 0;
        for block in [
            BlockSize::K4,
            BlockSize::K8,
            BlockSize::K16,
            BlockSize::K32,
            BlockSize::K64,
        ] {
            for &size in &sizes {
                let Ok(one) = plan_layout(&PlanRequest::new(size).block_size(block)) else {
                    continue;
                };
                for volumes in [1, one.max_volumes] {
                    let layout =
                        plan_layout(&PlanRequest::new(size).block_size(block).volumes(volumes))
                            .expect("as many volumes as there are slots");
                    check_apart(&layout);
                    planned += 1;
                }
            }
        }
        assert!(planned > 600, "{planned} plans checked");
    }

    fn check_apart(layout: &ApfsLayout) {
        let label = format!("{} blocks of {}", layout.block_count, layout.block_size);
        let mut seen: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
        for (block, expected, what) in placed_blocks(layout) {
            assert!(block < layout.block_count, "{label}: {what} at {block}");
            let area = if block == 0 {
                "zero"
            } else if block < layout.data_area.start {
                "descriptor"
            } else if block < layout.pool_bitmap_area.start {
                "data"
            } else if block < layout.pool.start {
                "pool bitmaps"
            } else if block < layout.pool.start + layout.pool.count {
                "pool"
            } else {
                "main"
            };
            assert_eq!(area, expected, "{label}: {what} at {block}");
            match seen.get(&block) {
                Some(before) => assert_eq!(
                    before, &what,
                    "{label}: {before} and {what} are both at {block}"
                ),
                None => {
                    seen.insert(block, what);
                }
            }
        }
    }

    #[test]
    fn a_hundred_volumes_take_the_places_one_does_one_after_another() {
        for size in [64u64 << 30, 4 << 40] {
            let one = plan_layout(&PlanRequest::new(size)).expect("one volume");
            let many = plan_layout(&PlanRequest::new(size).volumes(100)).expect("a hundred");
            assert_eq!(one.newest().volumes[0], many.newest().volumes[0]);
            assert_eq!(one.checkpoints[0], many.checkpoints[0]);
            let volumes = &many.newest().volumes;
            for pair in volumes.windows(2) {
                assert!(pair[0].object_map.object < pair[1].object_map.object);
                assert!(pair[0].superblock < pair[1].extent_ref_tree);
            }
            assert!(many.newest().object_map.object > volumes[99].object_map.root);
        }
    }

    #[test]
    fn the_chunk_geometry_lists_address_blocks_past_what_one_holds() {
        // 507 chunk-info block addresses fit one 4 KiB address block.
        let fits = ChunkGeometry::of(507 * 126 * 32768, 4096);
        assert_eq!(
            (fits.cib_count, fits.cab_count, fits.listed()),
            (507, 0, 507)
        );
        let over = ChunkGeometry::of(507 * 126 * 32768 + 1, 4096);
        assert_eq!((over.cib_count, over.cab_count, over.listed()), (508, 2, 2));
        let large = ChunkGeometry::of(1 << 20, 65536);
        assert_eq!(
            (
                large.blocks_per_chunk,
                large.chunks_per_cib,
                large.cibs_per_cab
            ),
            (524_288, 2046, 8187)
        );
        // A block count no container has: the counts are wider than the fields a space
        // manager keeps them in, and computed all the same.
        let huge = ChunkGeometry::of(u64::MAX, 4096);
        assert_eq!(huge.chunk_count, u64::MAX.div_ceil(32768));
        assert!(huge.cib_count > u64::from(u32::MAX));
    }
}
