//! An APFS container assembled byte by byte, for the gates that need one to be wrong in a
//! stated way.
//!
//! Every guard in [`btree`](super::btree) and [`container`](super::container) exists for an
//! image that describes something that is not a container, and macOS writes no such image.
//! The foreign corpus is what the reader is held to; this is for the gates that must run in a
//! build with no corpus at all, and for the faults no image macOS wrote carries.
//!
//! What it builds is small and real: one container of 256 blocks, one checkpoint, a container
//! object map, one volume with its own object map, a file-system tree of records the caller
//! states — in one leaf, or split across leaves under an index node — and the extent-reference
//! tree recording the run of blocks each extent uses. Every object is
//! checksummed the way the format checksums one, so a gate that damages an object and expects
//! a refusal is damaging something that would otherwise have been accepted, which is what
//! makes a negative control mean anything.
//!
//! It is test scaffolding and is compiled only under `cfg(test)`.

use std::collections::BTreeMap;
use std::io::Cursor;

use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u32_be, put_u64};

use super::geometry::QueueNodeLimits;
use super::ondisk::{
    BlockRange, CHECKPOINT_MAP_LAST, CheckpointAreas, CheckpointMap, CheckpointMapping, ChunkInfo,
    ChunkList, ContainerSuperblock, EntryKey, EntryValue, ExtendedField, FreeQueue, FreeQueueKey,
    INTERNAL_WITH_RESOURCE_FORK, INTERNAL_WITHOUT_RESOURCE_FORK, InodeValue, MAP_VALUE_DELETED,
    MODIFIED_BY_ENTRIES, MapKey, MapValue, ModifiedBy, NO_VALUE, NODE_DATA_START, NodeHeader,
    ObjectHeader, ObjectMap, REAPER_ALWAYS, Reaper, SpaceDevice, SpaceManager, TREE_ALLOW_GHOSTS,
    TREE_EPHEMERAL, TREE_INFO_SIZE, TREE_PHYSICAL, TREE_SEQUENTIAL_INSERT, TreeInfo,
    VOLUME_NAME_LEN, VolumeSuperblock, container_incompat, extended_field_blob, inode_field,
    inode_number, kind, node_flags, record_kind, seal, volume_flags, volume_incompat, xattr_flags,
};

/// Bytes in every block of a forged container.
pub const BLOCK: usize = 4096;

/// Blocks in a forged container.
pub const BLOCKS: u64 = 256;

/// The transaction every forged object records.
pub const XID: u64 = 8;

/// Where the checkpoint descriptor area begins, and how long it is.
pub const DESC_BASE: u64 = 1;
/// Blocks in the descriptor area.
pub const DESC_BLOCKS: u32 = 4;

/// The container's object map, and its mapping tree.
pub const CONTAINER_MAP_AT: u64 = 10;
/// The container's mapping tree.
pub const CONTAINER_MAP_TREE_AT: u64 = 11;

/// The volume superblock's block and virtual identifier.
pub const VOLUME_AT: u64 = 20;
/// The volume superblock's virtual identifier.
pub const VOLUME_OID: u64 = 1026;

/// The volume's object map, and its mapping tree.
pub const VOLUME_MAP_AT: u64 = 21;
/// The volume's mapping tree.
pub const VOLUME_MAP_TREE_AT: u64 = 22;

/// The file-system tree's root block, and the blocks of any leaves after it.
pub const FS_ROOT_AT: u64 = 30;

/// The extent-reference tree's root block.
pub const EXTENT_REF_AT: u64 = 50;
/// The file-system tree root's virtual identifier; leaves take the ones after it.
pub const FS_ROOT_OID: u64 = 1028;

/// The first block file data is placed at.
pub const DATA_AT: u64 = 64;

/// Every time a forged inode records, in nanoseconds since 1970.
pub const TIME: i64 = 1_600_000_000_123_456_789;

/// The flags macOS writes on a file-system tree: entries inserted in order, keys and values
/// unaligned (every file-system tree of the corpus).
const FS_TREE_FLAGS: u32 = 0x42;

/// The flags macOS writes on an extent-reference tree and a snapshot tree: a file-system tree's,
/// and children found by address.
const PHYSICAL_TREE_FLAGS: u32 = 0x52;

/// The flags macOS writes on an object map's tree: entries inserted in order and children found
/// by address. Its keys and values are of fixed sizes, which the tree's information gives.
const MAP_TREE_FLAGS: u32 = 0x12;

/// One record of a tree: its key and its value.
pub(crate) type Record = (Vec<u8>, Vec<u8>);

/// A forged container, as its parts, which a gate changes before asking for the bytes.
#[derive(Clone)]
pub(crate) struct Forge {
    /// The container superblock written at block zero and in the descriptor area.
    pub container: ContainerSuperblock,
    /// The volume superblock.
    pub volume: VolumeSuperblock,
    /// The file-system tree's records, in any order; they are sorted when laid out.
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    /// Blocks of file data, by address.
    pub data: BTreeMap<u64, Vec<u8>>,
    /// Records per leaf where the tree is split under an index node, or [`None`] for one
    /// leaf.
    pub per_leaf: Option<usize>,
    /// A snapshot of the volume, by name, keeping these records as the volume's tree at
    /// transaction [`SNAPSHOT_XID`].
    pub snapshot: Option<(Vec<u8>, Vec<Record>)>,
    /// The record each stream's runs are recorded as written by, where it is not the stream
    /// itself: an attribute stream's is the inode the attribute belongs to.
    pub owners: BTreeMap<u64, u64>,
    /// The volume's extent-reference tree, where it is not
    /// [`derived_references`](Self::derived_references).
    pub references: Option<Vec<Reference>>,
    /// The extent-reference tree the snapshot keeps, where it keeps one.
    pub snapshot_references: Option<Vec<Reference>>,
    /// The flags the snapshot's metadata record carries: none, on every snapshot macOS keeps.
    pub snapshot_flags: u32,
    /// The key the root of a split tree records for one leaf, by the leaf's place, where it is
    /// not that leaf's first key.
    pub separator: Option<(usize, Vec<u8>)>,
    /// A second volume, holding the root and the private directory alone, in the slot its
    /// superblock records; [`second_volume`] makes one.
    pub second: Option<VolumeSuperblock>,
    /// The runs the main free queue holds, each as the transaction that freed it, its first
    /// block and its length; a run of one block is kept as its key alone.
    pub main_queue: Vec<(u64, u64, u64)>,
    /// The runs the internal pool's free queue holds, as [`main_queue`](Self::main_queue) holds
    /// its own. Where any is given the pool takes [`POOL_SPARE`] blocks past its chunk bitmap,
    /// which the runs are in.
    pub pool_queue: Vec<(u64, u64, u64)>,
    /// Records of the volume's object map standing for a deleted object, each as its
    /// identifier, its transaction and the block its last version was at.
    pub deleted: Vec<(u64, u64, u64)>,
}

/// One record of an extent-reference tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reference {
    /// The run's first block.
    pub start: u64,
    /// Its length in blocks.
    pub blocks: u64,
    /// `1` a run and its count, `2` a change to a count an earlier tree holds.
    pub kind: u8,
    /// The record that wrote it, or all ones on a change.
    pub owner: u64,
    /// Its count, or the change.
    pub count: i32,
}

impl Reference {
    /// A run of `blocks` at `start` that `owner` wrote, with reference count `count`.
    pub(crate) fn run(start: u64, blocks: u64, owner: u64, count: i32) -> Self {
        Self {
            start,
            blocks,
            kind: 1,
            owner,
            count,
        }
    }

    /// A change of `count` to the count an earlier tree holds for the blocks at `start`.
    pub(crate) fn change(start: u64, blocks: u64, count: i32) -> Self {
        Self {
            start,
            blocks,
            kind: 2,
            owner: u64::MAX,
            count,
        }
    }
}

/// The transaction a forged snapshot keeps the volume at.
pub const SNAPSHOT_XID: u64 = XID - 2;
/// The block holding the snapshot's version of the file-system tree's root.
pub const SNAPSHOT_FS_AT: u64 = 40;
/// The snapshot tree's root block.
pub const SNAPSHOT_TREE_AT: u64 = 41;
/// The block holding the snapshot's copy of the volume superblock.
pub const SNAPSHOT_SUPERBLOCK_AT: u64 = 42;
/// The block holding the snapshot extension object's version at the snapshot.
pub const SNAPSHOT_EXTENSION_AT: u64 = 43;
/// The snapshot extension object's virtual identifier.
pub const SNAPSHOT_EXTENSION_OID: u64 = 1090;
/// The forged snapshot's identifier.
pub const SNAPSHOT_UUID: [u8; 16] = [0x77; 16];
/// The block holding the extent-reference tree the snapshot keeps, where it keeps one.
pub const SNAPSHOT_EXTENT_REF_AT: u64 = 44;
/// The block holding the volume's object map's tree of the snapshots it keeps versions for.
pub const MAP_SNAPSHOTS_AT: u64 = 45;

/// The second volume's superblock, where the forge holds one, and its virtual identifier.
pub const SECOND_VOLUME_AT: u64 = 230;
/// The second volume superblock's virtual identifier.
pub const SECOND_VOLUME_OID: u64 = 1092;
/// The second volume's object map, and its mapping tree.
pub const SECOND_MAP_AT: u64 = 231;
/// The second volume's mapping tree.
pub const SECOND_MAP_TREE_AT: u64 = 232;
/// The second volume's file-system tree, one leaf, and its virtual identifier.
pub const SECOND_FS_AT: u64 = 233;
/// The second volume's file-system tree's virtual identifier.
pub const SECOND_FS_OID: u64 = 1093;
/// The second volume's extent-reference tree, which holds nothing.
pub const SECOND_EXTENT_REF_AT: u64 = 234;

impl Forge {
    /// A container whose one volume holds an empty root directory and the private directory.
    pub(crate) fn new() -> Self {
        let mut forge = Self {
            container: container(),
            volume: volume(),
            records: Vec::new(),
            data: BTreeMap::new(),
            per_leaf: None,
            snapshot: None,
            owners: BTreeMap::new(),
            references: None,
            snapshot_references: None,
            snapshot_flags: 0,
            separator: None,
            second: None,
            main_queue: Vec::new(),
            pool_queue: Vec::new(),
            deleted: Vec::new(),
        };
        forge.add(inode(
            inode_number::ROOT,
            inode_number::ROOT_PARENT,
            0o040_755,
            0,
            None,
            &[],
        ));
        forge.add(inode(
            inode_number::PRIVATE,
            inode_number::ROOT_PARENT,
            0o040_755,
            0,
            None,
            &[],
        ));
        forge
    }

    /// A container whose volume holds one of each kind of thing the reader reads.
    ///
    /// | Path | Inode | What |
    /// |---|---|---|
    /// | `/hello` | 16 | 5000 bytes of [`pattern`] over two blocks; an embedded and a stream attribute |
    /// | `/dir` | 17 | a directory |
    /// | `/dir/nested` | 18 | an empty file with no data stream |
    /// | `/link` | 19 | a symbolic link to `hello` |
    /// | `/hard1`, `/dir/hard2` | 20 | one file under two names, one block |
    /// | `/fifo` | 21 | a named pipe |
    /// | `/cdev` | 22 | a character device, major 3 minor 4 |
    /// | `/sparse` | 23 | three blocks long, only the middle one stored, the others holes |
    pub(crate) fn populated() -> Self {
        let mut f = Self::new();
        let root = inode_number::ROOT;
        f.entry(root, b"hello", 16, DT_REG, None);
        f.add(inode(16, root, 0o100_644, 16, Some(5000), &[]));
        f.extent(16, 0, 2, DATA_AT);
        f.data_blocks(DATA_AT, &pattern(5000, 1));
        f.add(xattr(16, b"user.small", xattr_flags::EMBEDDED, b"tiny"));
        f.stream_xattr(16, b"user.big", 40, &pattern(6000, 2), DATA_AT + 4);

        f.entry(root, b"dir", 17, DT_DIR, None);
        f.add(inode(17, root, 0o040_755, 0, None, &[]));
        f.entry(17, b"nested", 18, DT_REG, None);
        f.add(inode(18, 17, 0o100_600, 0, None, &[]));

        f.entry(root, b"link", 19, DT_LNK, None);
        f.add(inode(19, root, 0o120_755, 0, None, &[]));
        f.add(xattr(19, b"com.apple.fs.symlink", 0x6, b"hello\0"));

        f.entry(root, b"hard1", 20, DT_REG, Some(30));
        f.entry(17, b"hard2", 20, DT_REG, Some(31));
        let mut hard = inode(20, root, 0o100_644, 20, Some(100), &[]);
        put_u32(&mut hard.1, 56, 2);
        f.add(hard);
        f.extent(20, 0, 1, DATA_AT + 2);
        f.data_blocks(DATA_AT + 2, &pattern(100, 3));

        f.entry(root, b"fifo", 21, DT_FIFO, None);
        f.add(inode(21, root, 0o010_644, 0, None, &[]));
        f.entry(root, b"cdev", 22, DT_CHR, None);
        f.add(inode(
            22,
            root,
            0o020_644,
            0,
            None,
            &[(inode_field::DEVICE, 0x0300_0004u32.to_le_bytes().to_vec())],
        ));

        f.entry(root, b"sparse", 23, DT_REG, None);
        f.add(inode(23, root, 0o100_644, 23, Some(3 * BLOCK as u64), &[]));
        // A hole is an extent at block zero, as macOS writes one.
        f.extent(23, 0, 1, 0);
        f.extent(23, BLOCK as u64, 1, DATA_AT + 3);
        f.extent(23, 2 * BLOCK as u64, 1, 0);
        f.data_blocks(DATA_AT + 3, &pattern(BLOCK, 4));

        for stream in [16, 20, 23] {
            f.add(stream_reference(stream, 1));
        }
        f.settle();
        f
    }

    /// [`populated`](Self::populated), with a snapshot, `before`, taken when the volume did not
    /// yet hold `/hello`.
    pub(crate) fn with_snapshot() -> Self {
        let mut forge = Self::populated();
        let hello_entry = entry(inode_number::ROOT, b"hello", 16, DT_REG, None).0;
        let hello = inode(16, 1, 0, 0, None, &[]).0;
        let kept = forge
            .records
            .iter()
            .filter(|(k, _)| *k != hello_entry && k[..8] != hello[..8])
            .cloned()
            .collect();
        forge.snapshot = Some((b"before".to_vec(), kept));
        forge
    }

    /// Add a compressed file of every type and layout this reader reads, at `/zlib-inline` and
    /// so on, inodes 80 to 89, each compressed form in blocks of its own from block `at`: its
    /// compression attribute's own stream, or its resource fork. A checksum covers a record and
    /// no file's blocks, so a change to these reaches the decoder rather than a checksum. Each
    /// fork holds two chunks, so its table holds three offsets. Answers the block after the
    /// last one used.
    pub(crate) fn every_compression(&mut self, mut at: u64) -> u64 {
        type Encode = fn(&[u8]) -> Vec<u8>;
        let blocks = |len: usize| len.div_ceil(BLOCK) as u64;
        let inline: [(&[u8], u32, Encode); 5] = [
            (b"zlib-inline", 3, zlib_stored),
            (b"lzvn-inline", 7, lzvn_literals),
            (b"stored-inline", 9, stored),
            (b"lzfse-inline", 11, lzfse_raw),
            (b"lzbitmap-inline", 13, lzbitmap_raw),
        ];
        for (i, (name, method, encode)) in inline.into_iter().enumerate() {
            let content = pattern(3000, 40 + i as u8);
            let form = encode(&content);
            let id = 80 + i as u64;
            self.inline_compressed_file(name, id, method, content.len() as u64, &form, Some(at));
            at += blocks(super::decmpfs::HEADER_LEN + form.len());
        }
        let forked: [(&[u8], u32, Encode); 5] = [
            (b"zlib-forked", 4, zlib_stored),
            (b"lzvn-forked", 8, lzvn_literals),
            (b"stored-forked", 10, stored),
            (b"lzfse-forked", 12, lzfse_raw),
            (b"lzbitmap-forked", 14, lzbitmap_raw),
        ];
        for (i, (name, method, encode)) in forked.into_iter().enumerate() {
            let chunk = super::decmpfs::CHUNK as usize;
            let content = pattern(chunk + 1000, 50 + i as u8);
            let chunks: Vec<Vec<u8>> = content.chunks(chunk).map(encode).collect();
            let fork = if method == 4 {
                classic_fork(&chunks)
            } else {
                offset_fork(&chunks, chunks.len() + 1)
            };
            let id = 85 + i as u64;
            self.compressed_file(name, id, method, content.len() as u64, &fork, at);
            at += blocks(fork.len());
        }
        at
    }

    /// Make the counts the volume keeps about itself agree with the records: each directory's
    /// child count, and the volume superblock's counts of inodes by kind.
    pub(crate) fn settle(&mut self) {
        let counts = settle(&mut self.records);
        set_counts(&mut self.volume, counts);
    }

    /// Store every directory entry under the hash of its name as the volume compares names,
    /// after a gate changes whether they fold case: an entry is added under the folded hash.
    pub(crate) fn rehash(&mut self) {
        let fold = self.volume.is_case_insensitive();
        for (key, _) in &mut self.records {
            if (get_u64(key, 0) >> 60) as u8 != record_kind::DIR_ENTRY {
                continue;
            }
            let len = (get_u32(key, 8) & 0x3FF) as usize;
            let name = &key[12..12 + len - 1];
            let form = super::names::key(name, fold).expect("a forged name is UTF-8");
            let packed = (super::names::hash(&form) << 10) | len as u32;
            put_u32(key, 8, packed);
        }
    }

    /// Add one record.
    pub(crate) fn add(&mut self, record: (Vec<u8>, Vec<u8>)) {
        self.records.push(record);
    }

    /// Add a directory entry of `parent` naming `file_id`.
    pub(crate) fn entry(
        &mut self,
        parent: u64,
        name: &[u8],
        file_id: u64,
        entry_type: u16,
        sibling: Option<u64>,
    ) {
        self.add(entry(parent, name, file_id, entry_type, sibling));
    }

    /// Add a file extent of stream `stream` at `logical`, `blocks` long, at block `physical`.
    pub(crate) fn extent(&mut self, stream: u64, logical: u64, blocks: u64, physical: u64) {
        self.add(extent(stream, logical, blocks * BLOCK as u64, physical));
    }

    /// Place `bytes` from block `at` onward, zero-padded to whole blocks.
    pub(crate) fn data_blocks(&mut self, at: u64, bytes: &[u8]) {
        for (i, chunk) in bytes.chunks(BLOCK).enumerate() {
            let mut block = vec![0u8; BLOCK];
            block[..chunk.len()].copy_from_slice(chunk);
            self.data.insert(at + i as u64, block);
        }
    }

    /// Add a stream attribute of inode `id` whose bytes, `value`, are stream `stream` at block
    /// `at`.
    pub(crate) fn stream_xattr(
        &mut self,
        id: u64,
        name: &[u8],
        stream: u64,
        value: &[u8],
        at: u64,
    ) {
        let blocks = value.len().div_ceil(BLOCK) as u64;
        let mut data = vec![0u8; 48];
        put_u64(&mut data, 0, stream);
        put_u64(&mut data, 8, value.len() as u64);
        put_u64(&mut data, 16, blocks * BLOCK as u64);
        self.add(xattr(id, name, xattr_flags::STREAM | 0x10, &data));
        self.extent(stream, 0, blocks, at);
        self.data_blocks(at, value);
        self.owners.insert(stream, id);
    }

    /// The container's bytes.
    pub(crate) fn image(&self) -> Vec<u8> {
        let mut canvas = Canvas {
            image: vec![0u8; BLOCKS as usize * BLOCK],
            written: Vec::new(),
        };

        // The file-system tree, and the map entries for its nodes.
        let mut records = self.records.clone();
        records.sort_by_key(|record| sort_key(&record.0));
        let mut volume_map = Vec::new();
        let groups: Vec<&[(Vec<u8>, Vec<u8>)]> = match self.per_leaf {
            None => vec![&records[..]],
            Some(n) => records.chunks(n.max(1)).collect(),
        };
        let info = |key_count: u64, node_count: u64| TreeInfo {
            key_count,
            node_count,
            ..tree_info(&records, FS_TREE_FLAGS)
        };
        if groups.len() == 1 {
            let node = node(
                groups[0],
                virtual_header(FS_ROOT_OID, kind::BTREE_ROOT, kind::FS_TREE),
                0,
                true,
                None,
                Some(info(records.len() as u64, 1)),
            );
            canvas.put(FS_ROOT_AT, &sealed(node));
            volume_map.push((FS_ROOT_OID, XID, FS_ROOT_AT));
        } else {
            let mut index = Vec::new();
            for (i, group) in groups.iter().enumerate() {
                let oid = FS_ROOT_OID + 1 + i as u64;
                let at = FS_ROOT_AT + 1 + i as u64;
                let leaf = node(
                    group,
                    virtual_header(oid, kind::BTREE_NODE, kind::FS_TREE),
                    0,
                    false,
                    None,
                    None,
                );
                canvas.put(at, &sealed(leaf));
                volume_map.push((oid, XID, at));
                let key = match &self.separator {
                    Some((leaf, key)) if *leaf == i => key.clone(),
                    _ => group[0].0.clone(),
                };
                index.push((key, oid.to_le_bytes().to_vec()));
            }
            let root = node(
                &index,
                virtual_header(FS_ROOT_OID, kind::BTREE_ROOT, kind::FS_TREE),
                1,
                true,
                None,
                Some(info(records.len() as u64, groups.len() as u64 + 1)),
            );
            canvas.put(FS_ROOT_AT, &sealed(root));
            volume_map.push((FS_ROOT_OID, XID, FS_ROOT_AT));
        }
        if let Some((name, kept)) = &self.snapshot {
            self.lay_out_snapshot(name, kept, &mut volume_map, &mut |at, block| {
                canvas.put(at, block);
            });
        }
        volume_map.sort_unstable();
        let references = self
            .references
            .clone()
            .unwrap_or_else(|| self.derived_references());
        canvas.put(
            EXTENT_REF_AT,
            &sealed(extent_reference_tree(EXTENT_REF_AT, &references)),
        );

        // The volume's object map, then the volume.
        canvas.put(
            VOLUME_MAP_TREE_AT,
            &sealed(map_tree_flagged(
                VOLUME_MAP_TREE_AT,
                &volume_map
                    .iter()
                    .map(|(oid, xid, block)| (*oid, *xid, *block, 0))
                    .chain(
                        self.deleted
                            .iter()
                            .map(|(oid, xid, block)| (*oid, *xid, *block, MAP_VALUE_DELETED)),
                    )
                    .collect::<Vec<_>>(),
            )),
        );
        let mut map = map_header(VOLUME_MAP_AT, VOLUME_MAP_TREE_AT, 0);
        if self.snapshot.is_some() {
            // The map's tree of the snapshots it keeps versions for, as macOS keeps one: a
            // physical leaf keyed by each snapshot's transaction, each value zero.
            let record = (SNAPSHOT_XID.to_le_bytes().to_vec(), vec![0u8; 16]);
            let tree = node(
                &[record],
                ObjectHeader {
                    checksum: 0,
                    oid: MAP_SNAPSHOTS_AT,
                    xid: XID,
                    type_word: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
                    subtype: u32::from(kind::OBJECT_MAP_SNAPSHOT),
                },
                0,
                true,
                Some((8, 16)),
                Some(TreeInfo {
                    flags: TREE_PHYSICAL,
                    node_size: BLOCK as u32,
                    key_size: 8,
                    value_size: 16,
                    longest_key: 8,
                    longest_value: 16,
                    key_count: 1,
                    node_count: 1,
                }),
            );
            canvas.put(MAP_SNAPSHOTS_AT, &sealed(tree));
            let mut header = ObjectMap::read_from(&map).expect("an object map");
            header.snapshot_count = 1;
            header.snapshot_tree_oid = MAP_SNAPSHOTS_AT;
            header.most_recent_snapshot = SNAPSHOT_XID;
            header.write_to(&mut map);
        }
        canvas.put(VOLUME_MAP_AT, &sealed(map));
        // What the volume counts as its own: every block it has written but its snapshot's copy
        // of its superblock, and the runs its extent-reference trees record.
        let data = runs(
            references
                .iter()
                .chain(self.snapshot_references.iter().flatten()),
        );
        let own = canvas
            .written
            .iter()
            .filter(|at| self.snapshot.is_none() || **at != SNAPSHOT_SUPERBLOCK_AT)
            .count() as u64
            + data
                .iter()
                .map(|(start, end)| end.min(&BLOCKS).saturating_sub(*start))
                .sum::<u64>();
        let mut volume = vec![0u8; BLOCK];
        let mut live = self.volume.clone();
        live.extent_ref_tree_oid = EXTENT_REF_AT;
        live.allocated_blocks = own;
        if self.snapshot.is_some() {
            live.snapshot_tree_oid = SNAPSHOT_TREE_AT;
            live.snapshot_extension_oid = SNAPSHOT_EXTENSION_OID;
            live.snapshot_count = 1;
        }
        live.write_to(&mut volume);
        canvas.put(VOLUME_AT, &sealed(volume));

        // The container's object map, the checkpoint, and block zero.
        let mut container = self.container.clone();
        let mut volumes = vec![(VOLUME_OID, XID, VOLUME_AT)];
        if let Some(second) = &self.second {
            lay_out_second(second, &mut |at, block| canvas.put(at, block));
            container.volume_oids[second.index as usize] = SECOND_VOLUME_OID;
            volumes.push((SECOND_VOLUME_OID, XID, SECOND_VOLUME_AT));
        }
        canvas.put(
            CONTAINER_MAP_TREE_AT,
            &sealed(map_tree(CONTAINER_MAP_TREE_AT, &volumes)),
        );
        canvas.put(
            CONTAINER_MAP_AT,
            &sealed(map_header(CONTAINER_MAP_AT, CONTAINER_MAP_TREE_AT, 1)),
        );
        let mut used: Vec<(u64, u64)> = canvas.written.iter().map(|at| (*at, at + 1)).collect();
        used.extend(data);
        lay_out_space(
            &mut canvas,
            &mut container,
            used,
            &self.main_queue,
            &self.pool_queue,
        );
        let mut superblock = vec![0u8; BLOCK];
        container.write_to(&mut superblock);
        let superblock = sealed(superblock);
        canvas.put(DESC_BASE + 1, &superblock);
        canvas.put(0, &superblock);

        let mut image = canvas.image;
        for (at, block) in &self.data {
            let at = *at as usize * BLOCK;
            image[at..at + block.len()].copy_from_slice(block);
        }
        image
    }

    /// The snapshot's blocks: its version of the tree's root, the snapshot tree, the
    /// superblock copy and the extension object, and the map entries for the two virtual ones.
    fn lay_out_snapshot(
        &self,
        name: &[u8],
        kept: &[(Vec<u8>, Vec<u8>)],
        volume_map: &mut Vec<(u64, u64, u64)>,
        put: &mut impl FnMut(u64, &[u8]),
    ) {
        let mut kept = kept.to_vec();
        let counts = settle(&mut kept);
        kept.sort_by_key(|record| sort_key(&record.0));
        let mut header = virtual_header(FS_ROOT_OID, kind::BTREE_ROOT, kind::FS_TREE);
        header.xid = SNAPSHOT_XID;
        let info = tree_info(&kept, FS_TREE_FLAGS);
        put(
            SNAPSHOT_FS_AT,
            &sealed(node(&kept, header, 0, true, None, Some(info))),
        );
        volume_map.push((FS_ROOT_OID, SNAPSHOT_XID, SNAPSHOT_FS_AT));

        // The snapshot tree: the metadata record keyed by the transaction, and the name record.
        let mut meta = vec![0u8; 50];
        if let Some(references) = &self.snapshot_references {
            put(
                SNAPSHOT_EXTENT_REF_AT,
                &sealed(extent_reference_tree(SNAPSHOT_EXTENT_REF_AT, references)),
            );
            put_u64(&mut meta, 0, SNAPSHOT_EXTENT_REF_AT);
        }
        put_u64(&mut meta, 8, SNAPSHOT_SUPERBLOCK_AT);
        put_u64(&mut meta, 16, TIME as u64);
        put_u64(&mut meta, 24, TIME as u64);
        put_u32(&mut meta, 40, 0x4000_0002);
        put_u32(&mut meta, 44, self.snapshot_flags);
        put_u16(&mut meta, 48, name.len() as u16 + 1);
        meta.extend_from_slice(name);
        meta.push(0);
        let mut name_key = key_header(super::ondisk::SNAPSHOT_NAME_ID, record_kind::SNAPSHOT_NAME);
        name_key.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
        name_key.extend_from_slice(name);
        name_key.push(0);
        let records = vec![
            (key_header(SNAPSHOT_XID, record_kind::SNAPSHOT_META), meta),
            (name_key, SNAPSHOT_XID.to_le_bytes().to_vec()),
        ];
        let tree_info = tree_info(&records, PHYSICAL_TREE_FLAGS);
        let tree_header = ObjectHeader {
            checksum: 0,
            oid: SNAPSHOT_TREE_AT,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
            subtype: u32::from(kind::SNAPSHOT_TREE),
        };
        put(
            SNAPSHOT_TREE_AT,
            &sealed(node(&records, tree_header, 0, true, None, Some(tree_info))),
        );

        // The superblock copy: the volume as the snapshot found it, its three tree addresses
        // zero.
        let mut copy = self.volume.clone();
        copy.header = ObjectHeader {
            checksum: 0,
            oid: SNAPSHOT_SUPERBLOCK_AT,
            xid: SNAPSHOT_XID,
            type_word: 0x4000_0000 | u32::from(kind::VOLUME_SUPERBLOCK),
            subtype: 0,
        };
        copy.object_map_oid = 0;
        copy.extent_ref_tree_oid = 0;
        copy.snapshot_tree_oid = 0;
        set_counts(&mut copy, counts);
        let mut block = vec![0u8; BLOCK];
        copy.write_to(&mut block);
        put(SNAPSHOT_SUPERBLOCK_AT, &sealed(block));

        // The extension object's version at the snapshot, holding its identifier.
        let mut ext = vec![0u8; BLOCK];
        ObjectHeader {
            checksum: 0,
            oid: SNAPSHOT_EXTENSION_OID,
            xid: SNAPSHOT_XID,
            type_word: u32::from(kind::SNAPSHOT_EXTENSION),
            subtype: 0,
        }
        .write_to(&mut ext);
        put_u32(&mut ext, 32, 1);
        put_u64(&mut ext, 40, SNAPSHOT_XID);
        ext[48..64].copy_from_slice(&SNAPSHOT_UUID);
        put(SNAPSHOT_EXTENSION_AT, &sealed(ext));
        volume_map.push((SNAPSHOT_EXTENSION_OID, SNAPSHOT_XID, SNAPSHOT_EXTENSION_AT));
    }

    /// The extent-reference tree a volume holding these records and no snapshot keeps: a run for
    /// every extent at a nonzero block, recorded as its stream's owner's with a count of one,
    /// and one for each block where two extents begin.
    pub(crate) fn derived_references(&self) -> Vec<Reference> {
        let mut runs: Vec<Reference> = self
            .records
            .iter()
            .filter_map(|(key, value)| {
                let word = u64::from_le_bytes(key[..8].try_into().expect("a key header"));
                if (word >> 60) as u8 != record_kind::FILE_EXTENT {
                    return None;
                }
                let stream = word & 0x0FFF_FFFF_FFFF_FFFF;
                let length = u64::from_le_bytes(value[..8].try_into().expect("a length"));
                let block = u64::from_le_bytes(value[8..16].try_into().expect("a block"));
                let owner = self.owners.get(&stream).copied().unwrap_or(stream);
                (block != 0).then(|| Reference::run(block, length.div_ceil(BLOCK as u64), owner, 1))
            })
            .collect();
        runs.sort_by_key(|run| run.start);
        runs.dedup_by_key(|run| run.start);
        runs
    }

    /// The container's bytes as a source.
    pub(crate) fn cursor(&self) -> Cursor<Vec<u8>> {
        Cursor::new(self.image())
    }
}

/// The image being laid out, and every block written into it, which is what the space manager
/// records in use beside the runs of data.
struct Canvas {
    image: Vec<u8>,
    written: Vec<u64>,
}

impl Canvas {
    fn put(&mut self, at: u64, block: &[u8]) {
        let off = at as usize * BLOCK;
        self.image[off..off + block.len()].copy_from_slice(block);
        self.written.push(at);
    }
}

/// The runs of data extent-reference records name, merged, as first block and the block after.
fn runs<'r>(references: impl Iterator<Item = &'r Reference>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = references
        .filter(|r| r.start != 0)
        .map(|r| (r.start, r.start + r.blocks))
        .collect();
    runs.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in runs {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Where the internal pool's bitmap is kept, and where the pool itself begins: its chunk-info
/// block, then the chunk's bitmap.
pub const POOL_BITMAP_AT: u64 = 12;
/// The internal pool's first block, the chunk-info block.
pub const CHUNK_INFO_AT: u64 = 13;
/// The one chunk's bitmap.
pub const CHUNK_BITMAP_AT: u64 = 14;
/// Blocks of the internal pool past its chunk bitmap where the forge holds a pool queue.
pub const POOL_SPARE: u64 = 4;
/// The space manager's block in the checkpoint data area, then the reaper's, then the main free
/// queue's tree and the internal pool's, each where the forge holds one.
pub const SPACE_MANAGER_AT: u64 = DESC_BASE + DESC_BLOCKS as u64;
/// The main free queue's tree's ephemeral identifier.
pub const MAIN_QUEUE_OID: u64 = 1029;
/// The internal pool's free queue's tree's ephemeral identifier.
pub const POOL_QUEUE_OID: u64 = 1030;

/// Write the space manager, the reaper, the tree of each free queue holding runs, `queue` the
/// main one's and `pool_queue` the internal pool's, and the checkpoint's mappings of them, with
/// one chunk whose bitmap marks `used`, every fixed area, and the pool's own blocks in use, the way
/// `newfs_apfs` lays out the same structures: the arrays after the space manager's fields, the
/// second device's list beginning where the main device's ends.
fn lay_out_space(
    canvas: &mut Canvas,
    container: &mut ContainerSuperblock,
    mut used: Vec<(u64, u64)>,
    queue: &[(u64, u64, u64)],
    pool_queue: &[(u64, u64, u64)],
) {
    let areas = &mut container.checkpoint;
    let objects = 2 + u32::from(!queue.is_empty()) + u32::from(!pool_queue.is_empty());
    let pool_blocks = if pool_queue.is_empty() {
        2
    } else {
        2 + POOL_SPARE
    };
    areas.data_index = 0;
    areas.data_len = objects;
    areas.data_next = objects;
    used.extend(
        queue
            .iter()
            .map(|(_, start, blocks)| (*start, start + blocks)),
    );
    let desc = (
        areas.desc_base,
        areas.desc_base + u64::from(areas.desc_blocks),
    );
    let data = (
        areas.data_base,
        areas.data_base + u64::from(areas.data_blocks),
    );
    used.extend([
        (0, 1),
        desc,
        data,
        (POOL_BITMAP_AT, POOL_BITMAP_AT + 1),
        (CHUNK_INFO_AT, CHUNK_INFO_AT + pool_blocks),
    ]);
    let mut bitmap = vec![0u8; BLOCK];
    let mut in_use = 0u64;
    // A gate may describe blocks past the container's end; what it holds is all a bitmap marks.
    for (start, end) in used {
        for block in start.min(BLOCKS)..end.min(BLOCKS) {
            let byte = &mut bitmap[(block / 8) as usize];
            if *byte >> (block % 8) & 1 == 0 {
                in_use += 1;
            }
            *byte |= 1 << (block % 8);
        }
    }
    let free = BLOCKS.saturating_sub(in_use);
    canvas.put(CHUNK_BITMAP_AT, &bitmap);
    let mut pool_bitmap = vec![0u8; BLOCK];
    pool_bitmap[0] = 0b11;
    for (_, start, blocks) in pool_queue {
        for bit in start - CHUNK_INFO_AT..start - CHUNK_INFO_AT + blocks {
            pool_bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
        }
    }
    canvas.put(POOL_BITMAP_AT, &pool_bitmap);
    let mut cib = vec![0u8; BLOCK];
    ChunkList {
        header: ObjectHeader {
            checksum: 0,
            oid: CHUNK_INFO_AT,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::SPACE_MANAGER_CIB),
            subtype: 0,
        },
        index: 0,
        count: 1,
    }
    .write_to(&mut cib);
    ChunkInfo {
        xid: XID,
        address: 0,
        block_count: BLOCKS as u32,
        free_count: free as u32,
        bitmap: CHUNK_BITMAP_AT,
    }
    .write_to(&mut cib[ChunkList::ENTRIES_AT..]);
    canvas.put(CHUNK_INFO_AT, &sealed(cib));

    let mut sm = vec![0u8; BLOCK];
    let main_list = 2544;
    let limits = QueueNodeLimits::of(BLOCKS, BLOCK as u32);
    SpaceManager {
        header: ObjectHeader {
            checksum: 0,
            oid: container.space_manager_oid,
            xid: XID,
            type_word: 0x8000_0000 | u32::from(kind::SPACE_MANAGER),
            subtype: 0,
        },
        block_size: BLOCK as u32,
        blocks_per_chunk: BLOCK as u32 * 8,
        chunks_per_cib: (BLOCK as u32 - 40) / ChunkInfo::SIZE as u32,
        cibs_per_cab: (BLOCK as u32 - 40) / 8,
        devices: [
            SpaceDevice {
                block_count: BLOCKS,
                chunk_count: 1,
                cib_count: 1,
                cab_count: 0,
                free_count: free,
                addr_offset: main_list,
                reserved: 0,
                reserved2: 0,
            },
            SpaceDevice {
                addr_offset: main_list + 8,
                ..SpaceDevice::default()
            },
        ],
        flags: 1,
        ip_bm_tx_multiplier: 16,
        ip_block_count: pool_blocks,
        ip_bm_size_in_blocks: 1,
        ip_bm_block_count: 1,
        ip_bm_base: POOL_BITMAP_AT,
        ip_base: CHUNK_INFO_AT,
        fs_reserve_block_count: 0,
        fs_reserve_alloc_count: 0,
        // Each queue has the node limit a container of its size is formatted with, which macOS
        // loads no checkpoint without.
        free_queues: [
            FreeQueue {
                count: pool_queue.iter().map(|q| q.2).sum(),
                tree_oid: if pool_queue.is_empty() {
                    0
                } else {
                    POOL_QUEUE_OID
                },
                oldest_xid: pool_queue.iter().map(|q| q.0).min().unwrap_or(0),
                tree_node_limit: limits.pool,
                ..FreeQueue::default()
            },
            if queue.is_empty() {
                FreeQueue {
                    tree_node_limit: limits.main,
                    ..FreeQueue::default()
                }
            } else {
                FreeQueue {
                    count: queue.iter().map(|q| q.2).sum(),
                    tree_oid: MAIN_QUEUE_OID,
                    oldest_xid: queue.iter().map(|q| q.0).min().unwrap_or(0),
                    tree_node_limit: limits.main,
                    ..FreeQueue::default()
                }
            },
            FreeQueue::default(),
        ],
        ip_bm_free_head: 0xFFFF,
        ip_bm_free_tail: 0xFFFF,
        ip_bm_xid_offset: 2520,
        ip_bitmap_offset: 2528,
        ip_bm_free_next_offset: 2536,
        version: 1,
        struct_size: 2520,
    }
    .write_to(&mut sm);
    put_u64(&mut sm, 2520, XID);
    put_u16(&mut sm, 2528, 0);
    put_u16(&mut sm, 2536, 0xFFFF);
    put_u64(&mut sm, main_list as usize, CHUNK_INFO_AT);
    canvas.put(SPACE_MANAGER_AT, &sealed(sm));

    let mut reaper = vec![0u8; BLOCK];
    Reaper {
        header: ObjectHeader {
            checksum: 0,
            oid: container.reaper_oid,
            xid: XID,
            type_word: 0x8000_0000 | u32::from(kind::REAPER),
            subtype: 0,
        },
        next_reap_id: 1,
        completed_id: 0,
        head: 0,
        tail: 0,
        flags: REAPER_ALWAYS,
        list_count: 0,
        kind: 0,
        size: 0,
        volume_oid: 0,
        oid: 0,
        xid: 0,
        entry_flags: 0,
        state_buffer_size: 0,
    }
    .write_to(&mut reaper);
    canvas.put(SPACE_MANAGER_AT + 1, &sealed(reaper));

    let mapping = |type_word: u32, oid: u64, address: u64| CheckpointMapping {
        type_word,
        subtype: 0,
        size: BLOCK as u32,
        pad: 0,
        volume_oid: 0,
        oid,
        address,
    };
    let mut mappings = vec![
        mapping(
            0x8000_0000 | u32::from(kind::SPACE_MANAGER),
            container.space_manager_oid,
            SPACE_MANAGER_AT,
        ),
        mapping(
            0x8000_0000 | u32::from(kind::REAPER),
            container.reaper_oid,
            SPACE_MANAGER_AT + 1,
        ),
    ];
    let queues = [(queue, MAIN_QUEUE_OID), (pool_queue, POOL_QUEUE_OID)];
    for (at, (runs, oid)) in
        (SPACE_MANAGER_AT + 2..).zip(queues.into_iter().filter(|q| !q.0.is_empty()))
    {
        canvas.put(at, &queue_tree(runs, oid));
        let mut queue_mapping = mapping(0x8000_0000 | u32::from(kind::BTREE_ROOT), oid, at);
        queue_mapping.subtype = u32::from(kind::SPACE_MANAGER_FREE_QUEUE);
        mappings.push(queue_mapping);
    }
    let mut map = vec![0u8; BLOCK];
    CheckpointMap {
        header: ObjectHeader {
            checksum: 0,
            oid: DESC_BASE,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::CHECKPOINT_MAP),
            subtype: 0,
        },
        flags: CHECKPOINT_MAP_LAST,
        count: mappings.len() as u32,
    }
    .write_to(&mappings, &mut map);
    canvas.put(DESC_BASE, &sealed(map));
}

/// The one node of a free queue's tree `oid`, holding `queue`'s runs: each the transaction that
/// freed it, its first block and its length, a run of one block kept as its key alone.
fn queue_tree(queue: &[(u64, u64, u64)], oid: u64) -> Vec<u8> {
    let mut runs: Vec<(Vec<u8>, Vec<u8>)> = queue
        .iter()
        .map(|(xid, start, blocks)| {
            let mut key = vec![0u8; FreeQueueKey::SIZE];
            FreeQueueKey {
                xid: *xid,
                address: *start,
            }
            .write_to(&mut key);
            let value = if *blocks == 1 {
                Vec::new()
            } else {
                blocks.to_le_bytes().to_vec()
            };
            (key, value)
        })
        .collect();
    runs.sort();
    let mut tree = node(
        &runs,
        ObjectHeader {
            checksum: 0,
            oid,
            xid: XID,
            type_word: 0x8000_0000 | u32::from(kind::BTREE_ROOT),
            subtype: u32::from(kind::SPACE_MANAGER_FREE_QUEUE),
        },
        0,
        true,
        Some((FreeQueueKey::SIZE, 8)),
        Some(TreeInfo {
            flags: TREE_SEQUENTIAL_INSERT | TREE_ALLOW_GHOSTS | TREE_EPHEMERAL,
            node_size: BLOCK as u32,
            key_size: FreeQueueKey::SIZE as u32,
            value_size: 8,
            longest_key: FreeQueueKey::SIZE as u32,
            longest_value: 8,
            key_count: runs.len() as u64,
            node_count: 1,
        }),
    );
    // A key alone has no value: its value offset is the format's marker for none.
    for (i, (_, value)) in runs.iter().enumerate() {
        if value.is_empty() {
            put_u16(&mut tree, NODE_DATA_START + 4 * i + 2, NO_VALUE);
        }
    }
    sealed(tree)
}

/// A second volume named `name`, in slot `slot`, for [`Forge::second`].
pub(crate) fn second_volume(name: &[u8], slot: u32) -> VolumeSuperblock {
    let mut second = volume();
    second.name = [0u8; VOLUME_NAME_LEN];
    second.name[..name.len()].copy_from_slice(name);
    second.index = slot;
    second.uuid = [0x44; 16];
    second
}

/// The second volume's blocks: its tree of the root and the private directory, its object map,
/// an extent-reference tree holding nothing, and its superblock.
fn lay_out_second(second: &VolumeSuperblock, put: &mut impl FnMut(u64, &[u8])) {
    let mut records = Forge::new().records;
    let counts = settle(&mut records);
    records.sort_by_key(|record| sort_key(&record.0));
    let header = virtual_header(SECOND_FS_OID, kind::BTREE_ROOT, kind::FS_TREE);
    put(
        SECOND_FS_AT,
        &sealed(node(
            &records,
            header,
            0,
            true,
            None,
            Some(tree_info(&records, FS_TREE_FLAGS)),
        )),
    );
    put(
        SECOND_MAP_TREE_AT,
        &sealed(map_tree(
            SECOND_MAP_TREE_AT,
            &[(SECOND_FS_OID, XID, SECOND_FS_AT)],
        )),
    );
    put(
        SECOND_MAP_AT,
        &sealed(map_header(SECOND_MAP_AT, SECOND_MAP_TREE_AT, 0)),
    );
    put(
        SECOND_EXTENT_REF_AT,
        &sealed(extent_reference_tree(SECOND_EXTENT_REF_AT, &[])),
    );
    let mut sb = second.clone();
    sb.header.oid = SECOND_VOLUME_OID;
    // Its object map and mapping tree, its tree's one node, and its extent-reference tree.
    sb.allocated_blocks = 4;
    sb.object_map_oid = SECOND_MAP_AT;
    sb.root_tree_oid = SECOND_FS_OID;
    sb.extent_ref_tree_oid = SECOND_EXTENT_REF_AT;
    set_counts(&mut sb, counts);
    let mut block = vec![0u8; BLOCK];
    sb.write_to(&mut block);
    put(SECOND_VOLUME_AT, &sealed(block));
}

/// Make each directory's child count among `records` agree with the entries they hold, and
/// count the inodes by kind: regular files, directories, symbolic links, and every other kind.
fn settle(records: &mut [Record]) -> [u64; 4] {
    let mut children: BTreeMap<u64, u32> = BTreeMap::new();
    let mut counts = [0u64; 4];
    for (key, value) in records.iter() {
        let word = u64::from_le_bytes(key[..8].try_into().expect("a key header"));
        match (word >> 60) as u8 {
            record_kind::DIR_ENTRY => {
                *children.entry(word & 0x0FFF_FFFF_FFFF_FFFF).or_default() += 1;
            }
            record_kind::INODE => {
                let mode = get_u16(value, 80);
                counts[match mode & 0o170_000 {
                    0o100_000 => 0,
                    0o040_000 => 1,
                    0o120_000 => 2,
                    _ => 3,
                }] += 1;
            }
            _ => {}
        }
    }
    for (key, value) in records.iter_mut() {
        let word = u64::from_le_bytes(key[..8].try_into().expect("a key header"));
        if (word >> 60) as u8 != record_kind::INODE {
            continue;
        }
        let mode = get_u16(value, 80);
        if mode & 0o170_000 == 0o040_000 {
            let id = word & 0x0FFF_FFFF_FFFF_FFFF;
            put_u32(value, 56, children.get(&id).copied().unwrap_or(0));
        }
    }
    counts
}

/// Give `volume` the inode counts `counts`, by kind; the root and the private directory are not
/// counted.
fn set_counts(volume: &mut VolumeSuperblock, counts: [u64; 4]) {
    volume.file_count = counts[0];
    volume.directory_count = counts[1].saturating_sub(2);
    volume.symlink_count = counts[2];
    volume.other_count = counts[3];
}

/// An extent-reference tree at block `at`, one leaf holding `references`.
fn extent_reference_tree(at: u64, references: &[Reference]) -> Vec<u8> {
    let mut records: Vec<Record> = references
        .iter()
        .map(|reference| {
            let mut value = vec![0u8; 20];
            put_u64(
                &mut value,
                0,
                reference.blocks | (u64::from(reference.kind) << 60),
            );
            put_u64(&mut value, 8, reference.owner);
            put_u32(&mut value, 16, reference.count as u32);
            (
                key_header(reference.start, record_kind::PHYSICAL_EXTENT),
                value,
            )
        })
        .collect();
    records.sort_by_key(|record| sort_key(&record.0));
    node(
        &records,
        ObjectHeader {
            checksum: 0,
            oid: at,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
            subtype: u32::from(kind::EXTENT_REF_TREE),
        },
        0,
        true,
        None,
        Some(tree_info(&records, PHYSICAL_TREE_FLAGS)),
    )
}

/// The information a one-leaf root of `records` carries, with tree flags `flags`: its record
/// count, one node, and its longest key and value.
fn tree_info(records: &[Record], flags: u32) -> TreeInfo {
    TreeInfo {
        flags,
        node_size: BLOCK as u32,
        key_size: 0,
        value_size: 0,
        longest_key: records.iter().map(|r| r.0.len()).max().unwrap_or(0) as u32,
        longest_value: records.iter().map(|r| r.1.len()).max().unwrap_or(0) as u32,
        key_count: records.len() as u64,
        node_count: 1,
    }
}

/// `n` bytes of a pattern seeded by `seed`, so two forged files never hold the same bytes.
pub(crate) fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            (i as u32)
                .wrapping_mul(31)
                .wrapping_add(u32::from(seed) * 7) as u8
        })
        .collect()
}

/// The `DT_*` type of a regular file.
pub const DT_REG: u16 = 8;
/// The `DT_*` type of a directory.
pub const DT_DIR: u16 = 4;
/// The `DT_*` type of a symbolic link.
pub const DT_LNK: u16 = 10;
/// The `DT_*` type of a named pipe.
pub const DT_FIFO: u16 = 1;
/// The `DT_*` type of a character device.
pub const DT_CHR: u16 = 2;

/// A key header's eight bytes.
fn key_header(id: u64, kind: u8) -> Vec<u8> {
    ((u64::from(kind) << 60) | id).to_le_bytes().to_vec()
}

/// What a forged tree sorts its records by: identifier, kind, then the kind's own order — a
/// directory entry's hash and then its name, an extent's logical offset, an attribute's name
/// byte by byte, as macOS orders them.
fn sort_key(key: &[u8]) -> (u64, u8, Vec<u8>) {
    let word = u64::from_le_bytes(key[..8].try_into().expect("a key header"));
    let kind = (word >> 60) as u8;
    let tail = match kind {
        // Numbers sort as numbers, which their little-endian bytes do not.
        record_kind::FILE_EXTENT | record_kind::SIBLING_LINK => {
            key[8..16].iter().rev().copied().collect()
        }
        record_kind::DIR_ENTRY => {
            let word = u32::from_le_bytes(key[8..12].try_into().expect("a hashed name"));
            let mut tail = (word >> 10).to_be_bytes().to_vec();
            tail.extend_from_slice(&key[12..]);
            tail
        }
        // The name, not its length before it.
        record_kind::XATTR => key[10..].to_vec(),
        _ => key[8..].to_vec(),
    };
    (word & 0x0FFF_FFFF_FFFF_FFFF, kind, tail)
}

/// An extended-field blob of `fields`, each with no flags.
pub(crate) fn blob(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let fields: Vec<ExtendedField<'_>> = fields
        .iter()
        .map(|(kind, data)| ExtendedField {
            kind: *kind,
            flags: 0,
            data,
        })
        .collect();
    extended_field_blob(&fields)
}

/// An inode record: `size` bytes of data stream where the inode has one.
pub(crate) fn inode(
    id: u64,
    parent: u64,
    mode: u16,
    private_id: u64,
    size: Option<u64>,
    extra: &[(u8, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>) {
    let mut value = vec![0u8; InodeValue::SIZE];
    InodeValue {
        parent_id: parent,
        private_id,
        create_time: TIME,
        modify_time: TIME,
        change_time: TIME,
        access_time: TIME,
        internal_flags: 0x8000,
        links_or_children: 1,
        protection_class: 0,
        write_generation: 0,
        bsd_flags: 0,
        owner: 501,
        group: 20,
        mode,
        pad: 0,
        uncompressed_size: 0,
    }
    .write_to(&mut value);
    let mut fields: Vec<(u8, Vec<u8>)> = extra.to_vec();
    if let Some(size) = size {
        let mut stream = vec![0u8; 40];
        put_u64(&mut stream, 0, size);
        put_u64(&mut stream, 8, size.next_multiple_of(BLOCK as u64));
        fields.push((inode_field::DATA_STREAM, stream));
    }
    fields.sort_by_key(|(kind, _)| *kind);
    value.extend_from_slice(&blob(&fields));
    (key_header(id, record_kind::INODE), value)
}

/// The 22-bit hash a name is stored under on a volume whose names fold case, which a forged
/// volume is until a gate changes it and calls [`Forge::rehash`].
pub(crate) fn name_hash(name: &[u8]) -> u32 {
    super::names::hash(&super::names::key(name, true).expect("a forged name is UTF-8"))
}

/// A directory entry record.
pub(crate) fn entry(
    parent: u64,
    name: &[u8],
    file_id: u64,
    entry_type: u16,
    sibling: Option<u64>,
) -> (Vec<u8>, Vec<u8>) {
    let key = EntryKey {
        hash: name_hash(name),
        name,
    }
    .to_key(parent);
    let mut value = vec![0u8; EntryValue::SIZE];
    EntryValue {
        file_id,
        date_added: TIME,
        flags: entry_type,
    }
    .write_to(&mut value);
    if let Some(sibling) = sibling {
        value.extend_from_slice(&blob(&[(1, sibling.to_le_bytes().to_vec())]));
    }
    (key, value)
}

/// An extended attribute record.
pub(crate) fn xattr(id: u64, name: &[u8], flags: u16, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut key = key_header(id, record_kind::XATTR);
    key.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
    key.extend_from_slice(name);
    key.push(0);
    let mut value = vec![0u8; 4];
    put_u16(&mut value, 0, flags);
    put_u16(&mut value, 2, data.len() as u16);
    value.extend_from_slice(data);
    (key, value)
}

/// `content` as an LZVN stream of literal runs alone, closed by the end marker: the simplest
/// stream the encoding has, and enough to hold a decoder to a resource fork's framing.
pub(crate) fn lzvn_literals(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for run in content.chunks(271) {
        if run.len() >= 16 {
            out.extend_from_slice(&[0xE0, (run.len() - 16) as u8]);
        } else {
            out.push(0xE0 | run.len() as u8);
        }
        out.extend_from_slice(run);
    }
    out.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
    out
}

/// `content` as an LZFSE stream of raw blocks alone, closed by the end block: the simplest
/// stream the encoding has, and enough to hold a decoder to a compressed file's framing.
pub(crate) fn lzfse_raw(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for block in content.chunks(1000) {
        out.extend_from_slice(b"bvx-");
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(b"bvx$");
    out
}

/// `content` as an LZBITMAP stream of raw blocks alone, closed by the end block: the simplest
/// stream the encoding has, and enough to hold a decoder to a compressed file's framing.
pub(crate) fn lzbitmap_raw(content: &[u8]) -> Vec<u8> {
    let mut out = b"ZBM\x09".to_vec();
    for block in content.chunks(32 * 1024) {
        out.extend_from_slice(&(block.len() as u32 + 6).to_le_bytes()[..3]);
        out.extend_from_slice(&(block.len() as u32).to_le_bytes()[..3]);
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
    out
}

/// `content` as a chunk of type 9 or 10 keeps it: the marker byte, then the content unchanged.
pub(crate) fn stored(content: &[u8]) -> Vec<u8> {
    let mut out = vec![crate::apfs::decmpfs::STORED];
    out.extend_from_slice(content);
    out
}

/// A resource fork holding `content` the way a compressed file of type 8 keeps it: a table of
/// one offset per 64 KiB chunk and one for the end, then each chunk as an LZVN stream.
pub(crate) fn resource_fork(content: &[u8]) -> Vec<u8> {
    let chunks: Vec<Vec<u8>> = content.chunks(64 * 1024).map(lzvn_literals).collect();
    offset_fork(&chunks, chunks.len() + 1)
}

/// A resource fork holding `chunks` the way types 8, 12 and 14 keep them: a table with room for
/// `room` offsets, the first holding where the first chunk begins and the next one each where
/// the chunk before ends, then the chunks.
pub(crate) fn offset_fork(chunks: &[Vec<u8>], room: usize) -> Vec<u8> {
    let mut fork = vec![0u8; 4 * room];
    let mut at = fork.len() as u32;
    put_u32(&mut fork, 0, at);
    for (i, chunk) in chunks.iter().enumerate() {
        at += chunk.len() as u32;
        put_u32(&mut fork, 4 * (i + 1), at);
    }
    for chunk in chunks {
        fork.extend_from_slice(chunk);
    }
    fork
}

/// A resource fork holding `chunks` the way type 4 keeps them: a classic resource fork, whose
/// header's first word says where its resource data begins, and whose one resource is a
/// little-endian chunk count and each chunk's offset and length from the resource's first byte,
/// then the chunks. The map after the data is never read, and is zeros.
pub(crate) fn classic_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
    const DATA_AT: u32 = 256;
    const MAP_LEN: u32 = 50;
    let mut resource = vec![0u8; 4 + 8 * chunks.len()];
    put_u32(&mut resource, 0, chunks.len() as u32);
    let mut at = resource.len() as u32;
    for (i, chunk) in chunks.iter().enumerate() {
        put_u32(&mut resource, 4 + 8 * i, at);
        put_u32(&mut resource, 8 + 8 * i, chunk.len() as u32);
        at += chunk.len() as u32;
    }
    for chunk in chunks {
        resource.extend_from_slice(chunk);
    }
    let data_len = 4 + resource.len() as u32;
    let mut fork = vec![0u8; DATA_AT as usize];
    put_u32_be(&mut fork, 0, DATA_AT);
    put_u32_be(&mut fork, 4, DATA_AT + data_len);
    put_u32_be(&mut fork, 8, data_len);
    put_u32_be(&mut fork, 12, MAP_LEN);
    fork.extend_from_slice(&(resource.len() as u32).to_be_bytes());
    fork.extend_from_slice(&resource);
    fork.resize(fork.len() + MAP_LEN as usize, 0);
    fork
}

/// `content` as a zlib stream of stored DEFLATE blocks, the simplest stream the encoding has:
/// the two-byte header, blocks of at most 65,535 bytes each with its length and that length's
/// complement, and the content's Adler-32.
pub(crate) fn zlib_stored(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = if content.is_empty() {
        vec![&[]]
    } else {
        content.chunks(65_535).collect()
    };
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in content {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

impl Forge {
    /// Add a compressed file of type `method` at `/name`, inode `id`, whose content is
    /// `content` and whose resource fork is `fork`, a stream at block `at`.
    /// Give inode `id` the internal flag of an inode holding a resource fork, in place of the
    /// one of an inode without, as macOS 15 and later write one.
    pub(crate) fn held_fork(&mut self, id: u64) {
        let key = key_header(id, record_kind::INODE);
        let record = self
            .records
            .iter_mut()
            .find(|(k, _)| *k == key)
            .expect("the inode");
        let flags = get_u64(&record.1, 48);
        put_u64(
            &mut record.1,
            48,
            (flags & !INTERNAL_WITHOUT_RESOURCE_FORK) | INTERNAL_WITH_RESOURCE_FORK,
        );
    }

    pub(crate) fn compressed_file(
        &mut self,
        name: &[u8],
        id: u64,
        method: u32,
        content_len: u64,
        fork: &[u8],
        at: u64,
    ) {
        let header = self.compressed_inode(name, id, method, content_len);
        self.add(xattr(
            id,
            b"com.apple.decmpfs",
            xattr_flags::EMBEDDED,
            &header,
        ));
        self.stream_xattr(id, b"com.apple.ResourceFork", id + 100, fork, at);
        self.held_fork(id);
        self.settle();
    }

    /// Add a compressed file of type `method` at `/name`, inode `id`, of `content_len` bytes,
    /// whose compressed form `stored` follows the header in its compression attribute: in the
    /// attribute's record, or with `stream_at`, a stream of its own at that block, as macOS
    /// keeps a longer compression attribute: in the record up to 113 bytes, and as a stream
    /// from 132 (observed).
    pub(crate) fn inline_compressed_file(
        &mut self,
        name: &[u8],
        id: u64,
        method: u32,
        content_len: u64,
        stored: &[u8],
        stream_at: Option<u64>,
    ) {
        let mut header = self.compressed_inode(name, id, method, content_len);
        header.extend_from_slice(stored);
        match stream_at {
            None => self.add(xattr(
                id,
                b"com.apple.decmpfs",
                xattr_flags::EMBEDDED,
                &header,
            )),
            Some(at) => self.stream_xattr(id, b"com.apple.decmpfs", id + 100, &header, at),
        }
        self.settle();
    }

    /// The entry and the inode flagged compressed, and the compression header to put in its
    /// attribute.
    fn compressed_inode(&mut self, name: &[u8], id: u64, method: u32, content_len: u64) -> Vec<u8> {
        self.entry(inode_number::ROOT, name, id, DT_REG, None);
        let mut record = inode(id, inode_number::ROOT, 0o100_644, id, None, &[]);
        put_u32(&mut record.1, 68, 0x20);
        put_u64(&mut record.1, 84, content_len);
        self.add(record);
        let mut header = b"fpmc".to_vec();
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&content_len.to_le_bytes());
        header
    }
}

/// A data stream's reference record: how many inodes name it as their content.
pub(crate) fn stream_reference(stream: u64, count: u32) -> (Vec<u8>, Vec<u8>) {
    (
        key_header(stream, record_kind::DATA_STREAM_ID),
        count.to_le_bytes().to_vec(),
    )
}

/// A file extent record.
pub(crate) fn extent(stream: u64, logical: u64, length: u64, physical: u64) -> (Vec<u8>, Vec<u8>) {
    let mut key = key_header(stream, record_kind::FILE_EXTENT);
    key.extend_from_slice(&logical.to_le_bytes());
    let mut value = vec![0u8; 24];
    put_u64(&mut value, 0, length);
    put_u64(&mut value, 8, physical);
    (key, value)
}

/// A virtual node's object header.
fn virtual_header(oid: u64, node_kind: u16, subtype: u16) -> ObjectHeader {
    ObjectHeader {
        checksum: 0,
        oid,
        xid: XID,
        type_word: u32::from(node_kind),
        subtype: u32::from(subtype),
    }
}

/// A node holding `entries`: the table first, keys packed after it, values packed back from
/// the end of the value area.
pub(crate) fn node(
    entries: &[(Vec<u8>, Vec<u8>)],
    header: ObjectHeader,
    level: u16,
    is_root: bool,
    fixed: Option<(usize, usize)>,
    info: Option<TreeInfo>,
) -> Vec<u8> {
    let mut block = vec![0u8; BLOCK];
    let entry_size = if fixed.is_some() { 4 } else { 8 };
    let table_len = entries.len() * entry_size;
    let key_area = NODE_DATA_START + table_len;
    let value_end = if is_root {
        BLOCK - TREE_INFO_SIZE
    } else {
        BLOCK
    };
    let (mut k, mut v) = (0usize, 0usize);
    for (i, (key, value)) in entries.iter().enumerate() {
        block[key_area + k..key_area + k + key.len()].copy_from_slice(key);
        v += value.len();
        block[value_end - v..value_end - v + value.len()].copy_from_slice(value);
        let at = NODE_DATA_START + entry_size * i;
        if fixed.is_some() {
            put_u16(&mut block, at, k as u16);
            put_u16(&mut block, at + 2, v as u16);
        } else {
            put_u16(&mut block, at, k as u16);
            put_u16(&mut block, at + 2, key.len() as u16);
            put_u16(&mut block, at + 4, v as u16);
            put_u16(&mut block, at + 6, value.len() as u16);
        }
        k += key.len();
    }
    let mut flags = 0;
    if is_root {
        flags |= node_flags::ROOT;
    }
    if level == 0 {
        flags |= node_flags::LEAF;
    }
    if fixed.is_some() {
        flags |= node_flags::FIXED_SIZE;
    }
    NodeHeader {
        header,
        flags,
        level,
        key_count: entries.len() as u32,
        table: (0, table_len as u16),
        free_space: (k as u16, (value_end - v - key_area - k) as u16),
        key_free_list: (0xFFFF, 0),
        value_free_list: (0xFFFF, 0),
    }
    .write_to(&mut block);
    if let Some(info) = info {
        info.write_to(&mut block[BLOCK - TREE_INFO_SIZE..]);
    }
    block
}

/// An object map's mapping tree, one leaf at block `at`, mapping each `(oid, xid, block)`.
fn map_tree(at: u64, mappings: &[(u64, u64, u64)]) -> Vec<u8> {
    let flagged: Vec<_> = mappings
        .iter()
        .map(|(oid, xid, block)| (*oid, *xid, *block, 0))
        .collect();
    map_tree_flagged(at, &flagged)
}

/// [`map_tree`], each record carrying the flags beside its block, sorted as a map keeps them.
fn map_tree_flagged(at: u64, mappings: &[(u64, u64, u64, u32)]) -> Vec<u8> {
    let mut mappings = mappings.to_vec();
    mappings.sort_unstable();
    let entries: Vec<(Vec<u8>, Vec<u8>)> = mappings
        .iter()
        .map(|(oid, xid, block, flags)| {
            let (mut key, mut value) = (vec![0u8; 16], vec![0u8; 16]);
            MapKey {
                oid: *oid,
                xid: *xid,
            }
            .write_to(&mut key);
            MapValue {
                flags: *flags,
                size: BLOCK as u32,
                address: *block,
            }
            .write_to(&mut value);
            (key, value)
        })
        .collect();
    node(
        &entries,
        ObjectHeader {
            checksum: 0,
            oid: at,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
            subtype: u32::from(kind::OBJECT_MAP),
        },
        0,
        true,
        Some((16, 16)),
        Some(TreeInfo {
            flags: MAP_TREE_FLAGS,
            node_size: BLOCK as u32,
            key_size: 16,
            value_size: 16,
            longest_key: 16,
            longest_value: 16,
            key_count: entries.len() as u64,
            node_count: 1,
        }),
    )
}

/// An object map header at block `at` whose mapping tree is at `tree`.
fn map_header(at: u64, tree: u64, flags: u32) -> Vec<u8> {
    let mut block = vec![0u8; BLOCK];
    ObjectMap {
        header: ObjectHeader {
            checksum: 0,
            oid: at,
            xid: XID,
            type_word: 0x4000_0000 | u32::from(kind::OBJECT_MAP),
            subtype: 0,
        },
        flags,
        snapshot_count: 0,
        tree_type: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
        snapshot_tree_type: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
        tree_oid: tree,
        snapshot_tree_oid: 0,
        most_recent_snapshot: 0,
        pending_revert_min: 0,
        pending_revert_max: 0,
    }
    .write_to(&mut block);
    block
}

/// `block` with its checksum written.
pub(crate) fn sealed(mut block: Vec<u8>) -> Vec<u8> {
    seal(&mut block);
    block
}

/// The forged container superblock.
fn container() -> ContainerSuperblock {
    let mut volume_oids = [0u64; 100];
    volume_oids[0] = VOLUME_OID;
    ContainerSuperblock {
        header: ObjectHeader {
            checksum: 0,
            oid: 1,
            xid: XID,
            type_word: 0x8000_0000 | u32::from(kind::CONTAINER_SUPERBLOCK),
            subtype: 0,
        },
        block_size: BLOCK as u32,
        block_count: BLOCKS,
        features: 0,
        readonly_compatible_features: 0,
        incompatible_features: container_incompat::VERSION2,
        uuid: [0x5A; 16],
        next_oid: 1100,
        next_xid: XID + 1,
        checkpoint: CheckpointAreas {
            desc_blocks: DESC_BLOCKS,
            data_blocks: 4,
            desc_base: DESC_BASE,
            data_base: DESC_BASE + u64::from(DESC_BLOCKS),
            desc_next: 2,
            data_next: 0,
            desc_index: 0,
            desc_len: 2,
            data_index: 0,
            data_len: 0,
        },
        space_manager_oid: 1024,
        object_map_oid: CONTAINER_MAP_AT,
        reaper_oid: 1025,
        test_type: 0,
        max_volumes: 1,
        volume_oids,
        counters: [0; 32],
        blocked_out: BlockRange::default(),
        evict_mapping_tree_oid: 0,
        flags: 0,
        efi_jumpstart: 0,
        fusion_uuid: [0; 16],
        keylocker: BlockRange::default(),
        ephemeral_info: [0; 4],
        test_oid: 0,
        fusion_middle_tree_oid: 0,
        fusion_cache_oid: 0,
        fusion_cache: BlockRange::default(),
        newest_mounted_version: 0,
        media_keybag: BlockRange::default(),
    }
}

/// The forged volume superblock.
fn volume() -> VolumeSuperblock {
    let mut name = [0u8; VOLUME_NAME_LEN];
    name[..6].copy_from_slice(b"Forged");
    let unused = ModifiedBy {
        id: [0; 32],
        timestamp: 0,
        last_xid: 0,
    };
    let mut modified_by = [unused; MODIFIED_BY_ENTRIES];
    modified_by[0].id[..5].copy_from_slice(b"forge");
    modified_by[0].timestamp = TIME as u64;
    modified_by[0].last_xid = XID;
    VolumeSuperblock {
        header: ObjectHeader {
            checksum: 0,
            oid: VOLUME_OID,
            xid: XID,
            type_word: u32::from(kind::VOLUME_SUPERBLOCK),
            subtype: 0,
        },
        index: 0,
        features: 0x2,
        readonly_compatible_features: 0,
        incompatible_features: volume_incompat::CASE_INSENSITIVE,
        unmount_time: 0,
        reserve_blocks: 0,
        quota_blocks: 0,
        allocated_blocks: 0,
        meta_crypto: [0; 20],
        root_tree_type: u32::from(kind::BTREE_ROOT),
        extent_ref_tree_type: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
        snapshot_tree_type: 0x4000_0000 | u32::from(kind::BTREE_ROOT),
        object_map_oid: VOLUME_MAP_AT,
        root_tree_oid: FS_ROOT_OID,
        extent_ref_tree_oid: 0,
        snapshot_tree_oid: 0,
        revert_to_xid: 0,
        revert_to_superblock: 0,
        // Past every identifier a gate gives a record.
        next_object_id: 1024,
        file_count: 0,
        directory_count: 0,
        symlink_count: 0,
        other_count: 0,
        snapshot_count: 0,
        total_blocks_allocated: 0,
        total_blocks_freed: 0,
        uuid: [0x33; 16],
        last_modified: 0,
        flags: volume_flags::UNENCRYPTED,
        formatted_by: unused,
        modified_by,
        name,
        next_document_id: 0,
        role: 0,
        reserved: 0,
        root_to_xid: 0,
        encryption_rolling_oid: 0,
        // Below every inode a gate forges, and the newest writer's transaction: the clone
        // information is exact, as macOS keeps it.
        clone_info_epoch: 15,
        clone_info_xid: XID,
        snapshot_extension_oid: 0,
        volume_group: [0; 16],
        integrity_meta_oid: 0,
        file_extent_tree_oid: 0,
        file_extent_tree_type: 0,
        reserved_type: 0,
        reserved_oid: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{BLOCK, DATA_AT, Forge, second_volume};

    /// Each image committed beside the crate that the forge makes, by its path from the crate's
    /// directory, and the image the forge makes for it: the fuzz target's seeds and the command
    /// line's fixtures, which keep it in the form [`sparse`] writes.
    fn committed() -> Vec<(&'static str, Vec<u8>)> {
        let mut split = Forge::with_snapshot();
        split.per_leaf = Some(8);
        let mut compressed = Forge::with_snapshot();
        compressed.every_compression(DATA_AT + 10);
        compressed.per_leaf = Some(16);
        // Two volumes: the populated one in slot 0, and an empty one, `Second`, in slot 1. A
        // container of 1 MiB holds one, so it says it holds two and its scan says so.
        let mut two = Forge::populated();
        two.second = Some(second_volume(b"Second", 1));
        two.container.max_volumes = 2;
        vec![
            (
                "fuzz/seeds/apfs_reader/apfs-populated.img",
                Forge::with_snapshot().image(),
            ),
            ("fuzz/seeds/apfs_reader/apfs-split.img", split.image()),
            (
                "fuzz/seeds/apfs_reader/apfs-compressed.img",
                compressed.image(),
            ),
            (
                "../ferrosys-cli/tests/fixtures/apfs-forged.sparse",
                Forge::with_snapshot().image(),
            ),
            (
                "../ferrosys-cli/tests/fixtures/apfs-two.sparse",
                two.image(),
            ),
        ]
    }

    /// `image` as the command line's fixtures keep it: a line naming the form, the image's
    /// length and its block size, then each block that is not all zeros after its index.
    fn sparse(image: &[u8]) -> Vec<u8> {
        let mut out = b"ferrosys-sparse\n".to_vec();
        out.extend_from_slice(&(image.len() as u64).to_le_bytes());
        out.extend_from_slice(&(BLOCK as u32).to_le_bytes());
        for (index, block) in image.chunks(BLOCK).enumerate() {
            if block.iter().any(|b| *b != 0) {
                out.extend_from_slice(&(index as u32).to_le_bytes());
                out.extend_from_slice(block);
            }
        }
        out
    }

    #[test]
    fn every_image_committed_beside_the_crate_is_the_one_the_forge_makes() {
        // A committed image the forge has moved on from is a seed the fuzzer starts from, or a
        // fixture the command line is held to, that no longer says what its description does.
        // `FERROSYS_BLESS_APFS_IMAGES=1` writes them again, for a change that means to move them.
        let bless = std::env::var_os("FERROSYS_BLESS_APFS_IMAGES").is_some();
        let mut moved = Vec::new();
        for (path, image) in committed() {
            let made = if path.ends_with(".sparse") {
                sparse(&image)
            } else {
                image
            };
            let at = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
            if bless {
                std::fs::write(&at, &made).expect("write the image");
                continue;
            }
            let held = std::fs::read(&at)
                .unwrap_or_else(|e| panic!("{path}: the committed image is unreadable: {e}"));
            if held != made {
                moved.push(path);
            }
        }
        assert!(
            moved.is_empty(),
            "the forge no longer makes {moved:?}; FERROSYS_BLESS_APFS_IMAGES=1 writes them again"
        );
    }

    #[cfg(all(
        feature = "zlib",
        feature = "lzvn",
        feature = "lzfse",
        feature = "lzbitmap"
    ))]
    #[test]
    fn every_image_the_forge_commits_reads_whole_and_scans_clean() {
        use crate::apfs::Reader;
        use std::io::Cursor;
        // A seed is where the fuzzer starts, so one a read refuses starts every run at the
        // refusal, and a fixture is what the command line is held to: each opens strictly,
        // scans clean, and reads every file, attribute and target, live and at each snapshot.
        for (path, image) in committed() {
            let mut reader = Reader::open(Cursor::new(image.clone())).expect(path);
            let found = reader.scan();
            // A container of two volumes in the forge's one mebibyte holds more than its size
            // gives it room for, which is the one finding it carries.
            let expected = usize::from(path.ends_with("apfs-two.sparse"));
            assert_eq!(found.anomalies().len(), expected, "{path}: {found:?}");
            let snapshots = reader.snapshots().expect(path);
            let views = std::iter::once(None).chain(snapshots.into_iter().map(|s| Some(s.name)));
            for view in views {
                let mut reader = Reader::open(Cursor::new(image.clone())).expect(path);
                if let Some(name) = &view {
                    reader = reader.at_snapshot(name).expect(path);
                }
                let mut files = 0;
                for entry in reader.walk().expect(path) {
                    let node = &entry.node;
                    reader.xattrs(node).expect(path);
                    if node.is_symlink() {
                        reader.link_target(node).expect(path);
                    }
                    if node.is_file() {
                        let data = reader.read_data(node).expect(path);
                        assert_eq!(data.len() as u64, node.size(), "{path}");
                        files += 1;
                    }
                }
                assert!(files > 0, "{path}");
            }
        }
    }
}
