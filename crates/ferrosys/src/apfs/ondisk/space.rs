//! What a container keeps about which of its blocks are in use: the checkpoint's mappings of
//! its ephemeral objects, the space manager with its chunk-info blocks and bitmaps, the free
//! queues, and the reaper.
//!
//! Every layout here is documented in Apple File System Reference (pp. 40-42 for the checkpoint
//! mapping, pp. 159-165 for the space manager and the reaper), which gives no account of most
//! of these fields beyond their place, and observed on the containers macOS writes. What each
//! holds on such a container is said where a layer relies on it.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};

use super::{ObjectHeader, ParseError};

/// The flag marking the last checkpoint-mapping block of a checkpoint (Apple File System
/// Reference, p. 42).
pub const CHECKPOINT_MAP_LAST: u32 = 0x1;

/// One ephemeral object of a checkpoint: what it is and where in the checkpoint data area it
/// is kept (Apple File System Reference, p. 40).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointMapping {
    /// Offset 0. The object's type word, storage bits included.
    pub type_word: u32,
    /// Offset 4. The object's subtype.
    pub subtype: u32,
    /// Offset 8. The object's size in bytes.
    pub size: u32,
    /// Offset 12. Reserved.
    pub pad: u32,
    /// Offset 16. The virtual identifier of the volume the object belongs to, or zero.
    pub volume_oid: u64,
    /// Offset 24. The object's ephemeral identifier.
    pub oid: u64,
    /// Offset 32. The block in the checkpoint data area where the object begins.
    pub address: u64,
}

impl CheckpointMapping {
    /// Bytes on disk.
    pub const SIZE: usize = 40;

    /// Recover a mapping from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a mapping.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("checkpoint mapping", Self::SIZE, buf)?;
        Ok(Self {
            type_word: get_u32(buf, 0),
            subtype: get_u32(buf, 4),
            size: get_u32(buf, 8),
            pad: get_u32(buf, 12),
            volume_oid: get_u64(buf, 16),
            oid: get_u64(buf, 24),
            address: get_u64(buf, 32),
        })
    }

    /// Write the mapping into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a mapping.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a checkpoint mapping needs 40 bytes"
        );
        put_u32(buf, 0, self.type_word);
        put_u32(buf, 4, self.subtype);
        put_u32(buf, 8, self.size);
        put_u32(buf, 12, self.pad);
        put_u64(buf, 16, self.volume_oid);
        put_u64(buf, 24, self.oid);
        put_u64(buf, 32, self.address);
    }

    /// The object's type, the low 16 bits of its type word.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        (self.type_word & 0xFFFF) as u16
    }
}

/// A checkpoint-mapping block: its header, its flags and how many mappings it holds (Apple File
/// System Reference, p. 41). The mappings follow, from [`MAPPINGS_AT`](Self::MAPPINGS_AT).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointMap {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. The block's flags: [`CHECKPOINT_MAP_LAST`] on the last block of a checkpoint.
    pub flags: u32,
    /// Offset 36. How many mappings the block holds.
    pub count: u32,
}

impl CheckpointMap {
    /// Where the first mapping begins.
    pub const MAPPINGS_AT: usize = 40;

    /// Recover a mapping block's header and its mappings from `block`, one whole block.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `block` is shorter than the mappings its count names.
    pub fn read_from(block: &[u8]) -> Result<(Self, Vec<CheckpointMapping>), ParseError> {
        ParseError::need("checkpoint-mapping block", Self::MAPPINGS_AT, block)?;
        let map = Self {
            header: ObjectHeader::read_from(block)?,
            flags: get_u32(block, 32),
            count: get_u32(block, 36),
        };
        let need = (map.count as usize)
            .checked_mul(CheckpointMapping::SIZE)
            .and_then(|n| n.checked_add(Self::MAPPINGS_AT))
            .unwrap_or(usize::MAX);
        ParseError::need("checkpoint-mapping block", need, block)?;
        let mappings = (0..map.count as usize)
            .map(|i| {
                CheckpointMapping::read_from(
                    &block[Self::MAPPINGS_AT + i * CheckpointMapping::SIZE..],
                )
            })
            .collect::<Result<_, _>>()?;
        Ok((map, mappings))
    }

    /// Write the header and `mappings` into `block`.
    ///
    /// # Panics
    ///
    /// Where `block` cannot hold them.
    pub fn write_to(&self, mappings: &[CheckpointMapping], block: &mut [u8]) {
        let need = Self::MAPPINGS_AT + mappings.len() * CheckpointMapping::SIZE;
        assert!(
            block.len() >= need,
            "a checkpoint-mapping block needs {need} bytes"
        );
        self.header.write_to(block);
        put_u32(block, 32, self.flags);
        put_u32(block, 36, self.count);
        for (i, mapping) in mappings.iter().enumerate() {
            mapping.write_to(&mut block[Self::MAPPINGS_AT + i * CheckpointMapping::SIZE..]);
        }
    }
}

/// The space manager's account of one device (Apple File System Reference, p. 160). A
/// container that is not a Fusion set uses the first, [`SpaceManager::MAIN`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SpaceDevice {
    /// Offset 0. Blocks on the device.
    pub block_count: u64,
    /// Offset 8. Chunks the blocks are divided into.
    pub chunk_count: u64,
    /// Offset 16. Chunk-info blocks describing the chunks.
    pub cib_count: u32,
    /// Offset 20. Chunk-info address blocks listing those, or zero where the space manager
    /// lists the chunk-info blocks itself.
    pub cab_count: u32,
    /// Offset 24. Blocks not in use.
    pub free_count: u64,
    /// Offset 32. Where in the space manager the list of chunk-info blocks, or of address
    /// blocks, begins.
    pub addr_offset: u32,
    /// Offset 36. Reserved.
    pub reserved: u32,
    /// Offset 40. Reserved.
    pub reserved2: u64,
}

impl SpaceDevice {
    /// Bytes on disk.
    pub const SIZE: usize = 48;

    fn read(buf: &[u8], at: usize) -> Self {
        Self {
            block_count: get_u64(buf, at),
            chunk_count: get_u64(buf, at + 8),
            cib_count: get_u32(buf, at + 16),
            cab_count: get_u32(buf, at + 20),
            free_count: get_u64(buf, at + 24),
            addr_offset: get_u32(buf, at + 32),
            reserved: get_u32(buf, at + 36),
            reserved2: get_u64(buf, at + 40),
        }
    }

    fn write(&self, buf: &mut [u8], at: usize) {
        put_u64(buf, at, self.block_count);
        put_u64(buf, at + 8, self.chunk_count);
        put_u32(buf, at + 16, self.cib_count);
        put_u32(buf, at + 20, self.cab_count);
        put_u64(buf, at + 24, self.free_count);
        put_u32(buf, at + 32, self.addr_offset);
        put_u32(buf, at + 36, self.reserved);
        put_u64(buf, at + 40, self.reserved2);
    }
}

/// One free queue: blocks freed and not yet available, kept in a tree keyed by the
/// transaction that freed them (Apple File System Reference, p. 160).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FreeQueue {
    /// Offset 0. Blocks the queue holds.
    pub count: u64,
    /// Offset 8. The queue's tree, an ephemeral object.
    pub tree_oid: u64,
    /// Offset 16. The oldest transaction that freed a block the queue holds.
    pub oldest_xid: u64,
    /// Offset 24. The most nodes the queue's tree may grow to.
    pub tree_node_limit: u16,
    /// Offset 26. Padding.
    pub pad16: u16,
    /// Offset 28. Padding.
    pub pad32: u32,
    /// Offset 32. Reserved.
    pub reserved: u64,
}

impl FreeQueue {
    /// Bytes on disk.
    pub const SIZE: usize = 40;

    fn read(buf: &[u8], at: usize) -> Self {
        Self {
            count: get_u64(buf, at),
            tree_oid: get_u64(buf, at + 8),
            oldest_xid: get_u64(buf, at + 16),
            tree_node_limit: get_u16(buf, at + 24),
            pad16: get_u16(buf, at + 26),
            pad32: get_u32(buf, at + 28),
            reserved: get_u64(buf, at + 32),
        }
    }

    fn write(&self, buf: &mut [u8], at: usize) {
        put_u64(buf, at, self.count);
        put_u64(buf, at + 8, self.tree_oid);
        put_u64(buf, at + 16, self.oldest_xid);
        put_u16(buf, at + 24, self.tree_node_limit);
        put_u16(buf, at + 26, self.pad16);
        put_u32(buf, at + 28, self.pad32);
        put_u64(buf, at + 32, self.reserved);
    }
}

/// The space manager (Apple File System Reference, pp. 161-162): the fields up to its
/// allocation zones. The arrays it keeps about the internal pool, and its list of chunk-info or
/// address blocks, sit at the offsets these fields give, past
/// [`struct_size`](Self::struct_size); [`ip_bitmap_xids`](Self::ip_bitmap_xids) and the methods
/// beside it read them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpaceManager {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. Bytes per block.
    pub block_size: u32,
    /// Offset 36. Blocks in a chunk: one bitmap block's bits.
    pub blocks_per_chunk: u32,
    /// Offset 40. Chunks one chunk-info block describes.
    pub chunks_per_cib: u32,
    /// Offset 44. Chunk-info blocks one address block lists.
    pub cibs_per_cab: u32,
    /// Offset 48. The two devices, main and tier 2.
    pub devices: [SpaceDevice; 2],
    /// Offset 144. The space manager's flags.
    pub flags: u32,
    /// Offset 148. Bitmap blocks the internal pool keeps per bitmap.
    pub ip_bm_tx_multiplier: u32,
    /// Offset 152. Blocks in the internal pool.
    pub ip_block_count: u64,
    /// Offset 160. Blocks one internal-pool bitmap takes.
    pub ip_bm_size_in_blocks: u32,
    /// Offset 164. Blocks kept for internal-pool bitmaps.
    pub ip_bm_block_count: u32,
    /// Offset 168. The first of those.
    pub ip_bm_base: u64,
    /// Offset 176. The internal pool's first block.
    pub ip_base: u64,
    /// Offset 184. Blocks reserved for volumes.
    pub fs_reserve_block_count: u64,
    /// Offset 192. Of those, blocks allocated.
    pub fs_reserve_alloc_count: u64,
    /// Offset 200. The three free queues: the internal pool's, the main device's and tier 2's.
    pub free_queues: [FreeQueue; 3],
    /// Offset 320. The first internal-pool bitmap block free for the next bitmap.
    pub ip_bm_free_head: u16,
    /// Offset 322. The last.
    pub ip_bm_free_tail: u16,
    /// Offset 324. Where the transaction each internal-pool bitmap was written in is kept.
    pub ip_bm_xid_offset: u32,
    /// Offset 328. Where the index of each internal-pool bitmap's block is kept.
    pub ip_bitmap_offset: u32,
    /// Offset 332. Where the free list of internal-pool bitmap blocks is kept.
    pub ip_bm_free_next_offset: u32,
    /// Offset 336. The structure's version.
    pub version: u32,
    /// Offset 340. The bytes the structure takes, up to the arrays past it.
    pub struct_size: u32,
}

impl SpaceManager {
    /// The bytes up to the allocation zones.
    pub const SIZE: usize = 344;
    /// The main device, [`devices`](Self::devices)`[MAIN]`.
    pub const MAIN: usize = 0;
    /// The internal pool's free queue, [`free_queues`](Self::free_queues)`[INTERNAL_POOL]`.
    pub const INTERNAL_POOL: usize = 0;
    /// The main device's free queue.
    pub const MAIN_QUEUE: usize = 1;

    /// Recover a space manager from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("space manager", Self::SIZE, buf)?;
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            block_size: get_u32(buf, 32),
            blocks_per_chunk: get_u32(buf, 36),
            chunks_per_cib: get_u32(buf, 40),
            cibs_per_cab: get_u32(buf, 44),
            devices: [SpaceDevice::read(buf, 48), SpaceDevice::read(buf, 96)],
            flags: get_u32(buf, 144),
            ip_bm_tx_multiplier: get_u32(buf, 148),
            ip_block_count: get_u64(buf, 152),
            ip_bm_size_in_blocks: get_u32(buf, 160),
            ip_bm_block_count: get_u32(buf, 164),
            ip_bm_base: get_u64(buf, 168),
            ip_base: get_u64(buf, 176),
            fs_reserve_block_count: get_u64(buf, 184),
            fs_reserve_alloc_count: get_u64(buf, 192),
            free_queues: [
                FreeQueue::read(buf, 200),
                FreeQueue::read(buf, 240),
                FreeQueue::read(buf, 280),
            ],
            ip_bm_free_head: get_u16(buf, 320),
            ip_bm_free_tail: get_u16(buf, 322),
            ip_bm_xid_offset: get_u32(buf, 324),
            ip_bitmap_offset: get_u32(buf, 328),
            ip_bm_free_next_offset: get_u32(buf, 332),
            version: get_u32(buf, 336),
            struct_size: get_u32(buf, 340),
        })
    }

    /// Write the fields into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a space manager needs {} bytes",
            Self::SIZE
        );
        self.header.write_to(buf);
        put_u32(buf, 32, self.block_size);
        put_u32(buf, 36, self.blocks_per_chunk);
        put_u32(buf, 40, self.chunks_per_cib);
        put_u32(buf, 44, self.cibs_per_cab);
        self.devices[0].write(buf, 48);
        self.devices[1].write(buf, 96);
        put_u32(buf, 144, self.flags);
        put_u32(buf, 148, self.ip_bm_tx_multiplier);
        put_u64(buf, 152, self.ip_block_count);
        put_u32(buf, 160, self.ip_bm_size_in_blocks);
        put_u32(buf, 164, self.ip_bm_block_count);
        put_u64(buf, 168, self.ip_bm_base);
        put_u64(buf, 176, self.ip_base);
        put_u64(buf, 184, self.fs_reserve_block_count);
        put_u64(buf, 192, self.fs_reserve_alloc_count);
        for (i, queue) in self.free_queues.iter().enumerate() {
            queue.write(buf, 200 + i * FreeQueue::SIZE);
        }
        put_u16(buf, 320, self.ip_bm_free_head);
        put_u16(buf, 322, self.ip_bm_free_tail);
        put_u32(buf, 324, self.ip_bm_xid_offset);
        put_u32(buf, 328, self.ip_bitmap_offset);
        put_u32(buf, 332, self.ip_bm_free_next_offset);
        put_u32(buf, 336, self.version);
        put_u32(buf, 340, self.struct_size);
    }

    /// The transaction each internal-pool bitmap was written in, one per bitmap block it takes,
    /// from `object`, the whole space manager.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the array runs past `object`.
    pub fn ip_bitmap_xids(&self, object: &[u8]) -> Result<Vec<u64>, ParseError> {
        let n = self.ip_bm_size_in_blocks as usize;
        array(
            object,
            self.ip_bm_xid_offset,
            n,
            8,
            "internal-pool bitmap transactions",
        )
        .map(|at| at.map(|off| get_u64(object, off)).collect())
    }

    /// The index, among the blocks kept for internal-pool bitmaps, of each block of the
    /// current internal-pool bitmap, from `object`, the whole space manager.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the array runs past `object`.
    pub fn ip_bitmap_indices(&self, object: &[u8]) -> Result<Vec<u16>, ParseError> {
        let n = self.ip_bm_size_in_blocks as usize;
        array(
            object,
            self.ip_bitmap_offset,
            n,
            2,
            "internal-pool bitmap indices",
        )
        .map(|at| at.map(|off| get_u16(object, off)).collect())
    }

    /// The free list of the blocks kept for internal-pool bitmaps: the next free block after
    /// each, from `object`, the whole space manager.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the array runs past `object`.
    pub fn ip_bitmap_free_next(&self, object: &[u8]) -> Result<Vec<u16>, ParseError> {
        let n = self.ip_bm_block_count as usize;
        array(
            object,
            self.ip_bm_free_next_offset,
            n,
            2,
            "internal-pool bitmap free list",
        )
        .map(|at| at.map(|off| get_u16(object, off)).collect())
    }

    /// The addresses device `device` lists at its address offset, from `object`, the whole
    /// space manager: its address blocks where it has any, its chunk-info blocks otherwise.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where the list runs past `object`.
    pub fn addresses(&self, device: usize, object: &[u8]) -> Result<Vec<u64>, ParseError> {
        let dev = &self.devices[device];
        let n = if dev.cab_count != 0 {
            dev.cab_count
        } else {
            dev.cib_count
        } as usize;
        array(object, dev.addr_offset, n, 8, "space manager address list")
            .map(|at| at.map(|off| get_u64(object, off)).collect())
    }
}

/// The offsets of `n` elements of `width` bytes from `at`, all inside `object`.
fn array(
    object: &[u8],
    at: u32,
    n: usize,
    width: usize,
    structure: &'static str,
) -> Result<impl Iterator<Item = usize>, ParseError> {
    let at = at as usize;
    let need = n
        .checked_mul(width)
        .and_then(|len| len.checked_add(at))
        .unwrap_or(usize::MAX);
    ParseError::need(structure, need, object)?;
    Ok((0..n).map(move |i| at + i * width))
}

/// The bits of a chunk-info count that hold the count (Apple File System Reference, p. 163).
pub const CI_COUNT_MASK: u32 = 0x000F_FFFF;

/// One chunk: its blocks, how many are free, and the bitmap saying which (Apple File System
/// Reference, p. 159).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ChunkInfo {
    /// Offset 0. The transaction the chunk's bitmap was last written in.
    pub xid: u64,
    /// Offset 8. The chunk's first block.
    pub address: u64,
    /// Offset 16. Blocks in the chunk, in the low bits [`CI_COUNT_MASK`] names.
    pub block_count: u32,
    /// Offset 20. Blocks of it not in use, in the same bits.
    pub free_count: u32,
    /// Offset 24. The block holding its bitmap, or zero where none of its blocks is in use.
    pub bitmap: u64,
}

impl ChunkInfo {
    /// Bytes on disk.
    pub const SIZE: usize = 32;

    /// Recover a chunk's information from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("chunk information", Self::SIZE, buf)?;
        Ok(Self {
            xid: get_u64(buf, 0),
            address: get_u64(buf, 8),
            block_count: get_u32(buf, 16),
            free_count: get_u32(buf, 20),
            bitmap: get_u64(buf, 24),
        })
    }

    /// Write it into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "chunk information needs 32 bytes");
        put_u64(buf, 0, self.xid);
        put_u64(buf, 8, self.address);
        put_u32(buf, 16, self.block_count);
        put_u32(buf, 20, self.free_count);
        put_u64(buf, 24, self.bitmap);
    }
}

/// A block of chunk information, or a block of the addresses of such blocks: its header, its
/// place in the sequence, and how many entries it holds (Apple File System Reference, p. 159).
/// The entries follow from [`ENTRIES_AT`](Self::ENTRIES_AT): [`ChunkInfo`] in a chunk-info
/// block, a block address in an address block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkList {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. Its place among the blocks of its kind.
    pub index: u32,
    /// Offset 36. Entries it holds.
    pub count: u32,
}

impl ChunkList {
    /// Where the first entry begins.
    pub const ENTRIES_AT: usize = 40;

    /// Recover the header of a chunk-info or address block from `block`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `block` is shorter than the header.
    pub fn read_from(block: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("chunk list", Self::ENTRIES_AT, block)?;
        Ok(Self {
            header: ObjectHeader::read_from(block)?,
            index: get_u32(block, 32),
            count: get_u32(block, 36),
        })
    }

    /// Write the header into `block`.
    ///
    /// # Panics
    ///
    /// Where `block` is shorter than the header.
    pub fn write_to(&self, block: &mut [u8]) {
        assert!(
            block.len() >= Self::ENTRIES_AT,
            "a chunk list needs 40 bytes"
        );
        self.header.write_to(block);
        put_u32(block, 32, self.index);
        put_u32(block, 36, self.count);
    }

    /// The chunk information a chunk-info block holds.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where its count runs past `block`.
    pub fn chunks(&self, block: &[u8]) -> Result<Vec<ChunkInfo>, ParseError> {
        array(
            block,
            Self::ENTRIES_AT as u32,
            self.count as usize,
            ChunkInfo::SIZE,
            "chunk-info block",
        )?
        .map(|off| ChunkInfo::read_from(&block[off..]))
        .collect()
    }

    /// The block addresses an address block holds.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where its count runs past `block`.
    pub fn addresses(&self, block: &[u8]) -> Result<Vec<u64>, ParseError> {
        array(
            block,
            Self::ENTRIES_AT as u32,
            self.count as usize,
            8,
            "chunk-info address block",
        )
        .map(|at| at.map(|off| get_u64(block, off)).collect())
    }
}

/// A free queue's key: the transaction that freed a run of blocks, and the run's first block
/// (Apple File System Reference, p. 160). The value is the run's length in blocks.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FreeQueueKey {
    /// Offset 0. The transaction that freed the run.
    pub xid: u64,
    /// Offset 8. The run's first block.
    pub address: u64,
}

impl FreeQueueKey {
    /// Bytes on disk.
    pub const SIZE: usize = 16;

    /// Recover a key from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a key.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("free queue key", Self::SIZE, buf)?;
        Ok(Self {
            xid: get_u64(buf, 0),
            address: get_u64(buf, 8),
        })
    }

    /// Write the key into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a key.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "a free queue key needs 16 bytes");
        put_u64(buf, 0, self.xid);
        put_u64(buf, 8, self.address);
    }
}

/// The reaper's state (Apple File System Reference, p. 164): what it is deleting over several
/// transactions, and its list of what is queued.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reaper {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. The identifier the next object queued will take.
    pub next_reap_id: u64,
    /// Offset 40. The last identifier reaped.
    pub completed_id: u64,
    /// Offset 48. The first block of the reap list, or zero.
    pub head: u64,
    /// Offset 56. The last.
    pub tail: u64,
    /// Offset 64. The reaper's flags.
    pub flags: u32,
    /// Offset 68. Reap-list blocks.
    pub list_count: u32,
    /// Offset 72. The type of the object being reaped.
    pub kind: u32,
    /// Offset 76. Its size.
    pub size: u32,
    /// Offset 80. The volume it belongs to.
    pub volume_oid: u64,
    /// Offset 88. Its identifier.
    pub oid: u64,
    /// Offset 96. Its transaction.
    pub xid: u64,
    /// Offset 104. Its reap-list entry's flags.
    pub entry_flags: u32,
    /// Offset 108. Bytes of the state buffer that follows.
    pub state_buffer_size: u32,
}

impl Reaper {
    /// Bytes up to the state buffer.
    pub const SIZE: usize = 112;

    /// Recover the reaper from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("reaper", Self::SIZE, buf)?;
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            next_reap_id: get_u64(buf, 32),
            completed_id: get_u64(buf, 40),
            head: get_u64(buf, 48),
            tail: get_u64(buf, 56),
            flags: get_u32(buf, 64),
            list_count: get_u32(buf, 68),
            kind: get_u32(buf, 72),
            size: get_u32(buf, 76),
            volume_oid: get_u64(buf, 80),
            oid: get_u64(buf, 88),
            xid: get_u64(buf, 96),
            entry_flags: get_u32(buf, 104),
            state_buffer_size: get_u32(buf, 108),
        })
    }

    /// Write the fields into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a reaper needs {} bytes",
            Self::SIZE
        );
        self.header.write_to(buf);
        put_u64(buf, 32, self.next_reap_id);
        put_u64(buf, 40, self.completed_id);
        put_u64(buf, 48, self.head);
        put_u64(buf, 56, self.tail);
        put_u32(buf, 64, self.flags);
        put_u32(buf, 68, self.list_count);
        put_u32(buf, 72, self.kind);
        put_u32(buf, 76, self.size);
        put_u64(buf, 80, self.volume_oid);
        put_u64(buf, 88, self.oid);
        put_u64(buf, 96, self.xid);
        put_u32(buf, 104, self.entry_flags);
        put_u32(buf, 108, self.state_buffer_size);
    }
}

/// The reaper flag the reference says is always set (Apple File System Reference, p. 165).
pub const REAPER_ALWAYS: u32 = 0x1;

/// The reaper flag saying the object it names is being reaped (Apple File System Reference,
/// p. 165).
pub const REAPER_CONTINUE: u32 = 0x2;

/// A block of the reaper's list: what is queued to be reaped (Apple File System Reference,
/// p. 164). Its entries follow from offset 64.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReapList {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. The next block of the list, or zero.
    pub next: u64,
    /// Offset 40. The list's flags.
    pub flags: u32,
    /// Offset 44. The most entries the block holds.
    pub max: u32,
    /// Offset 48. Entries it holds.
    pub count: u32,
    /// Offset 52. The first entry in use.
    pub first: u32,
    /// Offset 56. The last.
    pub last: u32,
    /// Offset 60. The first entry free.
    pub free: u32,
}

impl ReapList {
    /// Bytes up to the entries.
    pub const SIZE: usize = 64;

    /// Recover a reap list's header from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("reap list", Self::SIZE, buf)?;
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            next: get_u64(buf, 32),
            flags: get_u32(buf, 40),
            max: get_u32(buf, 44),
            count: get_u32(buf, 48),
            first: get_u32(buf, 52),
            last: get_u32(buf, 56),
            free: get_u32(buf, 60),
        })
    }

    /// Write the header into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a reap list needs {} bytes",
            Self::SIZE
        );
        self.header.write_to(buf);
        put_u64(buf, 32, self.next);
        put_u32(buf, 40, self.flags);
        put_u32(buf, 44, self.max);
        put_u32(buf, 48, self.count);
        put_u32(buf, 52, self.first);
        put_u32(buf, 56, self.last);
        put_u32(buf, 60, self.free);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_manager_reads_back_as_written() {
        let sm = SpaceManager {
            header: ObjectHeader {
                checksum: 0,
                oid: 1024,
                xid: 2,
                type_word: 0x8000_0005,
                subtype: 0,
            },
            block_size: 4096,
            blocks_per_chunk: 32768,
            chunks_per_cib: 126,
            cibs_per_cab: 507,
            devices: [
                SpaceDevice {
                    block_count: 16384,
                    chunk_count: 1,
                    cib_count: 1,
                    cab_count: 0,
                    free_count: 16183,
                    addr_offset: 2568,
                    reserved: 0,
                    reserved2: 0,
                },
                SpaceDevice::default(),
            ],
            flags: 1,
            ip_bm_tx_multiplier: 16,
            ip_block_count: 6,
            ip_bm_size_in_blocks: 1,
            ip_bm_block_count: 16,
            ip_bm_base: 169,
            ip_base: 185,
            fs_reserve_block_count: 0,
            fs_reserve_alloc_count: 0,
            free_queues: [
                FreeQueue {
                    count: 2,
                    tree_oid: 1027,
                    oldest_xid: 2,
                    tree_node_limit: 1,
                    ..FreeQueue::default()
                },
                FreeQueue {
                    count: 2,
                    tree_oid: 1029,
                    oldest_xid: 2,
                    tree_node_limit: 4,
                    ..FreeQueue::default()
                },
                FreeQueue::default(),
            ],
            ip_bm_free_head: 2,
            ip_bm_free_tail: 0,
            ip_bm_xid_offset: 2520,
            ip_bitmap_offset: 2528,
            ip_bm_free_next_offset: 2536,
            version: 1,
            struct_size: 2520,
        };
        let mut object = vec![0u8; 4096];
        sm.write_to(&mut object);
        put_u64(&mut object, 2520, 2);
        put_u16(&mut object, 2528, 1);
        put_u64(&mut object, 2568, 187);
        let back = SpaceManager::read_from(&object).expect("a space manager");
        assert_eq!(back, sm);
        assert_eq!(back.ip_bitmap_xids(&object), Ok(vec![2]));
        assert_eq!(back.ip_bitmap_indices(&object), Ok(vec![1]));
        assert_eq!(back.addresses(SpaceManager::MAIN, &object), Ok(vec![187]));
        assert_eq!(
            back.ip_bitmap_free_next(&object).map(|list| list.len()),
            Ok(16)
        );
    }

    #[test]
    fn an_array_past_the_object_is_refused() {
        let mut object = vec![0u8; SpaceManager::SIZE];
        put_u32(&mut object, 160, 1);
        put_u32(&mut object, 324, 4000);
        let sm = SpaceManager::read_from(&object).expect("a space manager");
        assert!(matches!(
            sm.ip_bitmap_xids(&object),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn a_mapping_block_reads_every_mapping_its_count_names() {
        let mappings = [
            CheckpointMapping {
                type_word: 0x8000_0005,
                subtype: 0,
                size: 4096,
                pad: 0,
                volume_oid: 0,
                oid: 1024,
                address: 11,
            },
            CheckpointMapping {
                type_word: 0x8000_0002,
                subtype: 9,
                size: 4096,
                pad: 0,
                volume_oid: 0,
                oid: 1027,
                address: 13,
            },
        ];
        let map = CheckpointMap {
            header: ObjectHeader {
                checksum: 0,
                oid: 3,
                xid: 2,
                type_word: 0x4000_000C,
                subtype: 0,
            },
            flags: CHECKPOINT_MAP_LAST,
            count: 2,
        };
        let mut block = vec![0u8; 4096];
        map.write_to(&mappings, &mut block);
        let (back, read) = CheckpointMap::read_from(&block).expect("a mapping block");
        assert_eq!(back, map);
        assert_eq!(read, mappings);
        assert_eq!(read[0].kind(), super::super::kind::SPACE_MANAGER);
        // A count past the block is refused rather than read into what follows.
        put_u32(&mut block, 36, 200);
        assert!(CheckpointMap::read_from(&block).is_err());
    }

    #[test]
    fn a_chunk_info_block_reads_its_chunks() {
        let list = ChunkList {
            header: ObjectHeader {
                checksum: 0,
                oid: 187,
                xid: 2,
                type_word: 0x4000_0007,
                subtype: 0,
            },
            index: 0,
            count: 1,
        };
        let chunk = ChunkInfo {
            xid: 2,
            address: 0,
            block_count: 16384,
            free_count: 16183,
            bitmap: 188,
        };
        let mut block = vec![0u8; 4096];
        list.write_to(&mut block);
        chunk.write_to(&mut block[ChunkList::ENTRIES_AT..]);
        let back = ChunkList::read_from(&block).expect("a chunk list");
        assert_eq!(back, list);
        assert_eq!(back.chunks(&block), Ok(vec![chunk]));
    }
}
