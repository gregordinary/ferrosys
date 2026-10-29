//! The container superblock: where a container begins, and what it holds.
//!
//! A container is one partition's worth of blocks, shared by every volume in it. Its superblock
//! records the block size and count, the feature words, the two checkpoint areas, the object
//! map that finds each volume, and the list of volumes (Apple File System Reference, pp. 26-39).
//! Block zero holds a copy; the live one is the newest valid copy in the checkpoint descriptor
//! area, which is the opening procedure the reference gives on p. 26.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_arr, get_u32, get_u64, put_arr, put_u32, put_u64};

use super::{ObjectHeader, ParseError};

/// The four bytes at offset 32 of every container superblock: `NXSB`.
pub const CONTAINER_MAGIC: [u8; 4] = *b"NXSB";

/// The most volumes one container lists (Apple File System Reference, p. 28).
pub const MAX_VOLUMES: usize = 100;

/// The counters a container superblock keeps.
pub const COUNTERS: usize = 32;

/// The smallest block size the format defines.
pub const MIN_BLOCK_SIZE: u32 = 4096;

/// The largest block size the format defines.
pub const MAX_BLOCK_SIZE: u32 = 65536;

/// The high bit of the descriptor area's block count: set where the area is a tree of block
/// ranges rather than one contiguous range (Apple File System Reference, p. 30).
pub const CHECKPOINT_AREA_IS_TREE: u32 = 0x8000_0000;

/// The container's incompatible feature bits this crate names (Apple File System Reference,
/// p. 38).
pub mod incompat {
    /// The format of the first release, which this crate does not read.
    pub const VERSION1: u64 = 0x1;
    /// The format every container since carries, and the one bit every container macOS 15, 26
    /// and 27 was observed to set.
    pub const VERSION2: u64 = 0x2;
    /// A container spanning two devices.
    pub const FUSION: u64 = 0x100;
}

/// A run of blocks: a first block address and a count.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BlockRange {
    /// The first block.
    pub start: u64,
    /// How many blocks.
    pub count: u64,
}

impl BlockRange {
    fn read(buf: &[u8], off: usize) -> Self {
        Self {
            start: get_u64(buf, off),
            count: get_u64(buf, off + 8),
        }
    }

    fn write(&self, buf: &mut [u8], off: usize) {
        put_u64(buf, off, self.start);
        put_u64(buf, off + 8, self.count);
    }
}

/// Where the two checkpoint areas are, and which part of each the newest checkpoint uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CheckpointAreas {
    /// Offset 104. The descriptor area's length in blocks, with
    /// [`CHECKPOINT_AREA_IS_TREE`] as its high bit.
    pub desc_blocks: u32,
    /// Offset 108. The data area's length in blocks, with the same high bit.
    pub data_blocks: u32,
    /// Offset 112. The descriptor area's first block, or the tree describing it.
    pub desc_base: u64,
    /// Offset 120. The data area's first block, or the tree describing it.
    pub data_base: u64,
    /// Offset 128. The next descriptor block a checkpoint would use.
    pub desc_next: u32,
    /// Offset 132. The next data block a checkpoint would use.
    pub data_next: u32,
    /// Offset 136. The first descriptor block the newest checkpoint uses.
    pub desc_index: u32,
    /// Offset 140. How many descriptor blocks it uses.
    pub desc_len: u32,
    /// Offset 144. The first data block it uses.
    pub data_index: u32,
    /// Offset 148. How many data blocks it uses.
    pub data_len: u32,
}

/// A container superblock (Apple File System Reference, pp. 27-36).
///
/// Every field the reference lays out is carried, so a value read and written back is the
/// same bytes up to offset [`SIZE`](Self::SIZE).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContainerSuperblock {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 36. Bytes per block, every block of the container.
    pub block_size: u32,
    /// Offset 40. Blocks in the container.
    pub block_count: u64,
    /// Offset 48. Compatible features: a reader that does not know one may still read.
    pub features: u64,
    /// Offset 56. Read-only compatible features: a reader may read; a writer may not write.
    pub readonly_compatible_features: u64,
    /// Offset 64. Incompatible features: a reader that does not know one must not read.
    pub incompatible_features: u64,
    /// Offset 72. The container's identifier.
    pub uuid: [u8; 16],
    /// Offset 88. The next identifier a virtual or ephemeral object would take.
    pub next_oid: u64,
    /// Offset 96. The next transaction's identifier.
    pub next_xid: u64,
    /// Offsets 104 to 151. The checkpoint areas.
    pub checkpoint: CheckpointAreas,
    /// Offset 152. The space manager, an ephemeral object.
    pub space_manager_oid: u64,
    /// Offset 160. The container's object map, a physical object.
    pub object_map_oid: u64,
    /// Offset 168. The reaper, an ephemeral object.
    pub reaper_oid: u64,
    /// Offset 176. Reserved for testing; zero.
    pub test_type: u32,
    /// Offset 180. How many volumes the container may hold.
    pub max_volumes: u32,
    /// Offset 184. The virtual identifier of each volume's superblock; zero in an unused slot.
    pub volume_oids: [u64; MAX_VOLUMES],
    /// Offset 984. Counters the implementation keeps.
    pub counters: [u64; COUNTERS],
    /// Offset 1240. Blocks a shrink is moving data out of.
    pub blocked_out: BlockRange,
    /// Offset 1256. The tree that maps blocks out of that range.
    pub evict_mapping_tree_oid: u64,
    /// Offset 1264. Container flags.
    pub flags: u64,
    /// Offset 1272. The block holding the embedded boot driver's description, or zero.
    pub efi_jumpstart: u64,
    /// Offset 1280. The Fusion set's identifier.
    pub fusion_uuid: [u8; 16],
    /// Offset 1296. Where the container's keybag is.
    pub keylocker: BlockRange,
    /// Offset 1312. Values the implementation keeps about ephemeral objects.
    pub ephemeral_info: [u64; 4],
    /// Offset 1344. Reserved for testing; zero.
    pub test_oid: u64,
    /// Offset 1352. A Fusion container's middle tree.
    pub fusion_middle_tree_oid: u64,
    /// Offset 1360. A Fusion container's write-back cache state.
    pub fusion_cache_oid: u64,
    /// Offset 1368. A Fusion container's write-back cache.
    pub fusion_cache: BlockRange,
    /// Offset 1384. The newest implementation version that has mounted the container.
    pub newest_mounted_version: u64,
    /// Offset 1392. Where the container's media keybag is.
    pub media_keybag: BlockRange,
}

impl ContainerSuperblock {
    /// Bytes the reference lays out.
    pub const SIZE: usize = 1408;

    /// Recover a container superblock from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE), and
    /// [`ParseError::BadMagic`] where offset 32 does not hold [`CONTAINER_MAGIC`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("container superblock", Self::SIZE, buf)?;
        let magic: [u8; 4] = get_arr(buf, 32);
        if magic != CONTAINER_MAGIC {
            return Err(ParseError::BadMagic {
                structure: "container superblock",
                found: magic,
            });
        }
        let mut volume_oids = [0u64; MAX_VOLUMES];
        for (i, slot) in volume_oids.iter_mut().enumerate() {
            *slot = get_u64(buf, 184 + 8 * i);
        }
        let mut counters = [0u64; COUNTERS];
        for (i, slot) in counters.iter_mut().enumerate() {
            *slot = get_u64(buf, 984 + 8 * i);
        }
        let mut ephemeral_info = [0u64; 4];
        for (i, slot) in ephemeral_info.iter_mut().enumerate() {
            *slot = get_u64(buf, 1312 + 8 * i);
        }
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            block_size: get_u32(buf, 36),
            block_count: get_u64(buf, 40),
            features: get_u64(buf, 48),
            readonly_compatible_features: get_u64(buf, 56),
            incompatible_features: get_u64(buf, 64),
            uuid: get_arr(buf, 72),
            next_oid: get_u64(buf, 88),
            next_xid: get_u64(buf, 96),
            checkpoint: CheckpointAreas {
                desc_blocks: get_u32(buf, 104),
                data_blocks: get_u32(buf, 108),
                desc_base: get_u64(buf, 112),
                data_base: get_u64(buf, 120),
                desc_next: get_u32(buf, 128),
                data_next: get_u32(buf, 132),
                desc_index: get_u32(buf, 136),
                desc_len: get_u32(buf, 140),
                data_index: get_u32(buf, 144),
                data_len: get_u32(buf, 148),
            },
            space_manager_oid: get_u64(buf, 152),
            object_map_oid: get_u64(buf, 160),
            reaper_oid: get_u64(buf, 168),
            test_type: get_u32(buf, 176),
            max_volumes: get_u32(buf, 180),
            volume_oids,
            counters,
            blocked_out: BlockRange::read(buf, 1240),
            evict_mapping_tree_oid: get_u64(buf, 1256),
            flags: get_u64(buf, 1264),
            efi_jumpstart: get_u64(buf, 1272),
            fusion_uuid: get_arr(buf, 1280),
            keylocker: BlockRange::read(buf, 1296),
            ephemeral_info,
            test_oid: get_u64(buf, 1344),
            fusion_middle_tree_oid: get_u64(buf, 1352),
            fusion_cache_oid: get_u64(buf, 1360),
            fusion_cache: BlockRange::read(buf, 1368),
            newest_mounted_version: get_u64(buf, 1384),
            media_keybag: BlockRange::read(buf, 1392),
        })
    }

    /// Write the superblock into the first [`SIZE`](Self::SIZE) bytes of `buf`, magic
    /// included. The checksum field is written as [`header`](Self::header) holds it.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a container superblock needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.header.write_to(buf);
        put_arr(buf, 32, &CONTAINER_MAGIC);
        put_u32(buf, 36, self.block_size);
        put_u64(buf, 40, self.block_count);
        put_u64(buf, 48, self.features);
        put_u64(buf, 56, self.readonly_compatible_features);
        put_u64(buf, 64, self.incompatible_features);
        put_arr(buf, 72, &self.uuid);
        put_u64(buf, 88, self.next_oid);
        put_u64(buf, 96, self.next_xid);
        let c = &self.checkpoint;
        put_u32(buf, 104, c.desc_blocks);
        put_u32(buf, 108, c.data_blocks);
        put_u64(buf, 112, c.desc_base);
        put_u64(buf, 120, c.data_base);
        put_u32(buf, 128, c.desc_next);
        put_u32(buf, 132, c.data_next);
        put_u32(buf, 136, c.desc_index);
        put_u32(buf, 140, c.desc_len);
        put_u32(buf, 144, c.data_index);
        put_u32(buf, 148, c.data_len);
        put_u64(buf, 152, self.space_manager_oid);
        put_u64(buf, 160, self.object_map_oid);
        put_u64(buf, 168, self.reaper_oid);
        put_u32(buf, 176, self.test_type);
        put_u32(buf, 180, self.max_volumes);
        for (i, oid) in self.volume_oids.iter().enumerate() {
            put_u64(buf, 184 + 8 * i, *oid);
        }
        for (i, counter) in self.counters.iter().enumerate() {
            put_u64(buf, 984 + 8 * i, *counter);
        }
        self.blocked_out.write(buf, 1240);
        put_u64(buf, 1256, self.evict_mapping_tree_oid);
        put_u64(buf, 1264, self.flags);
        put_u64(buf, 1272, self.efi_jumpstart);
        put_arr(buf, 1280, &self.fusion_uuid);
        self.keylocker.write(buf, 1296);
        for (i, info) in self.ephemeral_info.iter().enumerate() {
            put_u64(buf, 1312 + 8 * i, *info);
        }
        put_u64(buf, 1344, self.test_oid);
        put_u64(buf, 1352, self.fusion_middle_tree_oid);
        put_u64(buf, 1360, self.fusion_cache_oid);
        self.fusion_cache.write(buf, 1368);
        put_u64(buf, 1384, self.newest_mounted_version);
        self.media_keybag.write(buf, 1392);
    }

    /// The descriptor area's length in blocks, without its tree bit.
    #[must_use]
    pub const fn desc_area_blocks(&self) -> u32 {
        self.checkpoint.desc_blocks & !CHECKPOINT_AREA_IS_TREE
    }

    /// Every volume slot that names a volume, as `(slot, virtual identifier)`, in slot order.
    pub fn volumes(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.volume_oids
            .iter()
            .enumerate()
            .filter(|(_, oid)| **oid != 0)
            .map(|(slot, oid)| (slot, *oid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ContainerSuperblock {
        let mut volume_oids = [0u64; MAX_VOLUMES];
        volume_oids[0] = 1026;
        volume_oids[3] = 1100;
        let mut counters = [0u64; COUNTERS];
        counters[0] = 21;
        ContainerSuperblock {
            header: ObjectHeader {
                checksum: 0xAABB,
                oid: 1,
                xid: 9,
                type_word: 0x8000_0001,
                subtype: 0,
            },
            block_size: 4096,
            block_count: 16384,
            features: 0,
            readonly_compatible_features: 0,
            incompatible_features: incompat::VERSION2,
            uuid: [0x5A; 16],
            next_oid: 1100,
            next_xid: 10,
            checkpoint: CheckpointAreas {
                desc_blocks: 8,
                data_blocks: 52,
                desc_base: 1,
                data_base: 9,
                desc_next: 4,
                data_next: 12,
                desc_index: 2,
                desc_len: 2,
                data_index: 8,
                data_len: 4,
            },
            space_manager_oid: 1024,
            object_map_oid: 77,
            reaper_oid: 1025,
            test_type: 0,
            max_volumes: 1,
            volume_oids,
            counters,
            blocked_out: BlockRange::default(),
            evict_mapping_tree_oid: 0,
            flags: 0,
            efi_jumpstart: 0,
            fusion_uuid: [0; 16],
            keylocker: BlockRange { start: 3, count: 4 },
            ephemeral_info: [5, 0, 0, 0],
            test_oid: 0,
            fusion_middle_tree_oid: 0,
            fusion_cache_oid: 0,
            fusion_cache: BlockRange::default(),
            newest_mounted_version: 0x0009_0000_0000_0001,
            media_keybag: BlockRange { start: 6, count: 1 },
        }
    }

    #[test]
    fn a_superblock_round_trips() {
        let sb = sample();
        let mut buf = vec![0u8; 4096];
        sb.write_to(&mut buf);
        assert_eq!(&buf[32..36], b"NXSB");
        assert_eq!(ContainerSuperblock::read_from(&buf), Ok(sb));
    }

    #[test]
    fn fields_sit_at_the_offsets_the_reference_gives() {
        let sb = sample();
        let mut buf = vec![0u8; 4096];
        sb.write_to(&mut buf);
        assert_eq!(get_u64(&buf, 160), 77, "the object map at 160");
        assert_eq!(get_u32(&buf, 180), 1, "the volume count at 180");
        assert_eq!(get_u64(&buf, 184), 1026, "the first volume slot at 184");
        assert_eq!(get_u64(&buf, 984), 21, "the counters at 984");
        assert_eq!(get_u64(&buf, 1384), 0x0009_0000_0000_0001);
    }

    #[test]
    fn another_signature_is_not_a_container() {
        let mut buf = vec![0u8; 4096];
        sample().write_to(&mut buf);
        buf[32] = b'X';
        assert!(matches!(
            ContainerSuperblock::read_from(&buf),
            Err(ParseError::BadMagic { found, .. }) if found == *b"XXSB"
        ));
    }

    #[test]
    fn only_named_volume_slots_are_volumes() {
        let sb = sample();
        assert_eq!(sb.volumes().collect::<Vec<_>>(), [(0, 1026), (3, 1100)]);
    }

    #[test]
    fn the_tree_bit_is_not_part_of_the_count() {
        let mut sb = sample();
        sb.checkpoint.desc_blocks = CHECKPOINT_AREA_IS_TREE | 8;
        assert_eq!(sb.desc_area_blocks(), 8);
    }
}
