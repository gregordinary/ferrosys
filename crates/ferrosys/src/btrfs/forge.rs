//! A btrfs assembled byte by byte, for the gates that need one to be wrong in a stated way.
//!
//! Every guard in [`btree`](super::btree) and [`volume`](super::volume) exists for an image
//! that describes a tree that is not one, and no formatter produces such an image. The pinned
//! baseline's corruptor damages a *structure* on a real filesystem, which is the right tool
//! for the tier that has one; this is for the gates that must run in a build with no host
//! tools at all, and for the faults no tool has a switch for.
//!
//! What it builds is small and real: one device, one system chunk, a chunk tree of one leaf,
//! and a root tree the caller shapes. Every block is checksummed the way the format
//! checksums one, so a gate that damages a block and expects a refusal is damaging something
//! that would otherwise have been accepted — which is the property that makes a negative
//! control mean anything.
//!
//! It is test scaffolding and is compiled only under `cfg(test)`.

use std::collections::BTreeMap;
use std::io::{Read, Result as IoResult, Seek, SeekFrom, Write};

use crate::Timestamp;
use crate::bytes::put_arr;

use super::ondisk::{
    self, BlockGroupFlags, CSUM_FIELD_LEN, ChecksumType, Chunk, CompatFlags, CompatRoFlags,
    Compression, DevItem, DirEntryType, DirItem, DiskKey, ExtentKind, FileExtentItem, Header,
    IncompatFlags, InodeFlags, InodeItem, InodeRef, Item, ItemType, KeyPtr, LABEL_SIZE, MAGIC,
    MIRRORS, RootFlags, RootItem, SUPER_INFO_SIZE, SYS_CHUNK_ARRAY_SIZE, Stripe, SuperBlock,
    SuperFlags, objectid,
};

/// How long every block of a forged filesystem is, and its sector size.
pub const NODE_SIZE: usize = 4096;

/// How long a forged device is unless a gate says otherwise. Large enough for the primary
/// superblock and the one chunk, and small enough that the format writes no other copy of the
/// superblock — which is what a device this size gets.
pub const DEVICE_BYTES: u64 = 1 << 20;

/// Where the one chunk's logical space begins. Unrelated to where it sits on the device, which
/// is the point: a forged image whose mapping were the identity would not exercise the
/// translation every read goes through.
pub const CHUNK_LOGICAL: u64 = 1 << 20;

/// How much logical space it covers.
pub const CHUNK_LENGTH: u64 = 256 << 10;

/// Where on the device that space lives.
pub const CHUNK_PHYSICAL: u64 = 128 << 10;

/// The filesystem id every forged image carries.
pub const FSID: [u8; 16] = [0x5b; 16];

/// The transaction every forged block records.
pub const GENERATION: u64 = 8;

/// The logical address of the chunk tree's one leaf.
pub const CHUNK_TREE_AT: u64 = CHUNK_LOGICAL;

/// The logical address of the root tree's top block.
pub const ROOT_TREE_AT: u64 = CHUNK_LOGICAL + NODE_SIZE as u64;

/// The first logical address a caller's own blocks may use, so that nothing it places
/// collides with the two the forge needs.
pub const FIRST_FREE_AT: u64 = CHUNK_LOGICAL + 2 * NODE_SIZE as u64;

/// A device whose written pages are held and whose unwritten ones read as zeros.
///
/// A btrfs of any size carries a few megabytes of metadata and nothing else, so a device is
/// almost entirely holes — and the format puts a superblock a quarter of a terabyte in. Held
/// densely, a gate over the third copy would need a quarter-terabyte allocation; held this
/// way it costs the pages it writes. That is what makes the mirror thresholds testable in a
/// build with no host tools, where the tier that has them needs a sparse file the host
/// filesystem may refuse to create.
///
/// It is a device in both directions. A formatter is handed one as a destination and a reader
/// opens the same value afterwards, so the threshold the reader's half of that rule is
/// asserted at is asserted for the writer at the same cost — the pages a format actually
/// writes, which for an empty filesystem is a few hundred kibibytes whatever the device's
/// declared length.
#[derive(Clone, Debug)]
pub struct Sparse {
    len: u64,
    pages: BTreeMap<u64, [u8; PAGE]>,
    pos: u64,
}

/// How much of a sparse device one held page covers.
const PAGE: usize = 4096;

impl Sparse {
    /// A device of `len` bytes, entirely holes.
    pub fn new(len: u64) -> Self {
        Self {
            len,
            pages: BTreeMap::new(),
            pos: 0,
        }
    }

    /// Take `bytes` at `offset`.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) {
        assert!(
            offset + bytes.len() as u64 <= self.len,
            "a forged write stays on the device"
        );
        let mut at = offset;
        let mut rest = bytes;
        while !rest.is_empty() {
            let page = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let take = rest.len().min(PAGE - within);
            self.pages.entry(page).or_insert([0; PAGE])[within..within + take]
                .copy_from_slice(&rest[..take]);
            at += take as u64;
            rest = &rest[take..];
        }
    }

    /// The `len` bytes at `offset`, holes reading as zeros.
    pub fn read_at(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut at = offset;
        let mut written = 0usize;
        while written < len {
            let page = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let take = (len - written).min(PAGE - within);
            if let Some(held) = self.pages.get(&page) {
                out[written..written + take].copy_from_slice(&held[within..within + take]);
            }
            at += take as u64;
            written += take;
        }
        out
    }
}

impl Read for Sparse {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let take = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        buf[..take].copy_from_slice(&self.read_at(self.pos, take));
        self.pos += take as u64;
        Ok(take)
    }
}

impl Write for Sparse {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // A write past the declared length is what a sink that ran off its device would do, and
        // the assertion inside `write_at` is what says so. Nothing here clamps: a formatter
        // that wrote past the end of the device it was given is a defect, not a short write.
        self.write_at(self.pos, buf);
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl Seek for Sparse {
    fn seek(&mut self, to: SeekFrom) -> IoResult<u64> {
        self.pos = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(from) => self.len.saturating_add_signed(from),
            SeekFrom::Current(from) => self.pos.saturating_add_signed(from),
        };
        Ok(self.pos)
    }
}

/// A filesystem being assembled.
pub struct Forge {
    device: Sparse,
    device_bytes: u64,
    root_level: u8,
}

impl Forge {
    /// A device with the one chunk mapped and the chunk tree written, and nothing else.
    ///
    /// The root tree is left for [`root_leaf`](Self::root_leaf) or
    /// [`root_node`](Self::root_node), so a caller decides whether the filesystem's trees are
    /// one level deep or two.
    pub fn new() -> Self {
        Self::of_size(DEVICE_BYTES)
    }

    /// The same, on a device of `device_bytes` — which is what decides how many copies of the
    /// superblock the format puts on it.
    pub fn of_size(device_bytes: u64) -> Self {
        let mut forge = Self {
            device: Sparse::new(device_bytes),
            device_bytes,
            root_level: 0,
        };
        let chunk_leaf = leaf(
            CHUNK_TREE_AT,
            objectid::CHUNK_TREE,
            &[(
                DiskKey::new(
                    objectid::FIRST_CHUNK_TREE,
                    ItemType::CHUNK_ITEM,
                    CHUNK_LOGICAL,
                ),
                chunk_record(),
            )],
        );
        forge.place(CHUNK_TREE_AT, &chunk_leaf);
        forge.root_leaf(&[]);
        forge
    }

    /// Write the superblock describing the filesystem as it now stands, to every location the
    /// device has room for — which is the format's own rule: how many copies a device carries
    /// is a property of its size and of nothing else.
    fn write_superblock(&mut self) -> &mut Self {
        let holds: Vec<u64> = MIRRORS
            .iter()
            .copied()
            .filter(|&at| self.holds_mirror(at))
            .collect();
        for at in holds {
            let mut bytes = vec![0u8; SUPER_INFO_SIZE];
            let mut sb = superblock(self.root_level, self.device_bytes);
            sb.bytenr = at;
            sb.write_to(&mut bytes);
            seal(&mut bytes);
            self.device.write_at(at, &bytes);
        }
        self
    }

    /// Whether the device holds all of a superblock at `at`.
    ///
    /// Asked through the shared rule rather than restated: a forge that wrote copies by a
    /// boundary of its own would build the fixtures that prove the reader's boundary right
    /// however wrong either was.
    fn holds_mirror(&self, at: u64) -> bool {
        ondisk::holds_mirror(self.device_bytes, at)
    }

    /// Write the root tree as one leaf holding `items`.
    pub fn root_leaf(&mut self, items: &[(DiskKey, Vec<u8>)]) -> &mut Self {
        let block = leaf(ROOT_TREE_AT, objectid::ROOT_TREE, items);
        self.place(ROOT_TREE_AT, &block);
        self.root_level = 0;
        self.write_superblock()
    }

    /// Write the root tree as an internal node at `level` whose children are `children`.
    pub fn root_node(&mut self, level: u8, children: &[(DiskKey, u64)]) -> &mut Self {
        let block = node(ROOT_TREE_AT, objectid::ROOT_TREE, level, children);
        self.place(ROOT_TREE_AT, &block);
        self.root_level = level;
        self.write_superblock()
    }

    /// Write a block of the caller's own at `logical`, which must be within the one chunk.
    pub fn block(&mut self, logical: u64, block: &[u8]) -> &mut Self {
        self.place(logical, block);
        self
    }

    /// Write `bytes` at `logical` as a file's data rather than as a tree block.
    ///
    /// No header and no checksum, which is what a data extent is: the bytes are what an
    /// `EXTENT_DATA` record addresses, and nothing about them says where they belong.
    pub fn data(&mut self, logical: u64, bytes: &[u8]) -> &mut Self {
        self.place(logical, bytes);
        self
    }

    /// Rewrite the bytes of the block at `logical` through `edit`, and re-checksum it.
    ///
    /// This is how a gate produces a block that is wrong in exactly one stated way: the
    /// checksum is recomputed afterwards, so what the reader refuses is the fault the gate
    /// introduced and never the checksum that would otherwise have given it away.
    pub fn amend(&mut self, logical: u64, edit: impl FnOnce(&mut [u8])) -> &mut Self {
        let at = self.physical(logical);
        let mut block = self.device.read_at(at, NODE_SIZE);
        edit(&mut block);
        seal(&mut block);
        self.device.write_at(at, &block);
        self
    }

    /// Damage the block at `logical` so its checksum no longer covers it.
    pub fn break_checksum(&mut self, logical: u64) -> &mut Self {
        let at = self.physical(logical) + Header::SIZE as u64;
        let mut byte = self.device.read_at(at, 1);
        byte[0] ^= 0xff;
        self.device.write_at(at, &byte);
        self
    }

    /// Rewrite the superblock at `mirror` through `edit`, and re-checksum it.
    pub fn amend_superblock(
        &mut self,
        mirror: usize,
        edit: impl FnOnce(&mut SuperBlock),
    ) -> &mut Self {
        let at = MIRRORS[mirror];
        let mut bytes = self.device.read_at(at, SUPER_INFO_SIZE);
        let mut sb =
            SuperBlock::read_from(&bytes).expect("the forge wrote a superblock at this mirror");
        edit(&mut sb);
        sb.write_to(&mut bytes);
        seal(&mut bytes);
        self.device.write_at(at, &bytes);
        self
    }

    /// Damage the superblock at `mirror` so its checksum no longer covers it.
    pub fn break_superblock(&mut self, mirror: usize) -> &mut Self {
        let at = MIRRORS[mirror] + SuperBlock::GENERATION_OFFSET as u64;
        let mut byte = self.device.read_at(at, 1);
        byte[0] ^= 0xff;
        self.device.write_at(at, &byte);
        self
    }

    /// Write the superblock at `from` over the one at `to`, bytes and all.
    ///
    /// What an image carved out of a disk at the wrong offset looks like: the copy verifies
    /// perfectly and records a location that is not the one it is at.
    pub fn copy_superblock(&mut self, from: usize, to: usize) -> &mut Self {
        let bytes = self.device.read_at(MIRRORS[from], SUPER_INFO_SIZE);
        self.device.write_at(MIRRORS[to], &bytes);
        self
    }

    /// The finished device, as a source a volume can be opened over.
    ///
    /// The superblock is already in it: it is rewritten whenever the root tree's shape changes
    /// and never at the end, so an [`amend_superblock`](Self::amend_superblock) a gate made is
    /// still there. A forge that wrote it last would silently discard exactly the edits the
    /// superblock gates exist to make.
    pub fn source(&self) -> Sparse {
        self.device.clone()
    }

    /// The same, truncated to `len` bytes — a device whose own recorded length reaches
    /// further than the image in hand does.
    pub fn truncated(&self, len: u64) -> Sparse {
        let mut short = self.device.clone();
        short.len = len;
        short
    }

    fn physical(&self, logical: u64) -> u64 {
        assert!(
            (CHUNK_LOGICAL..CHUNK_LOGICAL + CHUNK_LENGTH).contains(&logical),
            "a forged block sits inside the one chunk"
        );
        CHUNK_PHYSICAL + (logical - CHUNK_LOGICAL)
    }

    fn place(&mut self, logical: u64, block: &[u8]) {
        let at = self.physical(logical);
        self.device.write_at(at, block);
    }
}

/// The chunk record the bootstrap array and the chunk tree both carry: one copy of the one
/// chunk, on the one device.
fn chunk_record() -> Vec<u8> {
    let chunk = Chunk {
        length: CHUNK_LENGTH,
        owner: objectid::EXTENT_TREE,
        stripe_len: 64 << 10,
        ty: BlockGroupFlags::SYSTEM,
        io_align: 4096,
        io_width: 4096,
        sector_size: 4096,
        num_stripes: 1,
        sub_stripes: 1,
    };
    let mut record = vec![0u8; chunk.encoded_len()];
    chunk.write_to(&mut record);
    Stripe {
        devid: 1,
        offset: CHUNK_PHYSICAL,
        dev_uuid: [0xec; 16],
    }
    .write_to(&mut record[Chunk::SIZE..]);
    record
}

/// A superblock describing the forged filesystem, its root tree at `root_level` on a device
/// of `device_bytes`.
fn superblock(root_level: u8, device_bytes: u64) -> SuperBlock {
    let record = chunk_record();
    let mut array = [0u8; SYS_CHUNK_ARRAY_SIZE];
    DiskKey::new(
        objectid::FIRST_CHUNK_TREE,
        ItemType::CHUNK_ITEM,
        CHUNK_LOGICAL,
    )
    .write_to(&mut array);
    array[DiskKey::SIZE..DiskKey::SIZE + record.len()].copy_from_slice(&record);
    SuperBlock {
        csum: [0; CSUM_FIELD_LEN],
        fsid: FSID,
        bytenr: MIRRORS[0],
        flags: SuperFlags::NONE,
        magic: MAGIC,
        generation: GENERATION,
        root: ROOT_TREE_AT,
        chunk_root: CHUNK_TREE_AT,
        log_root: 0,
        total_bytes: device_bytes,
        bytes_used: CHUNK_LENGTH,
        root_dir_objectid: objectid::ROOT_TREE_DIR,
        num_devices: 1,
        sectorsize: NODE_SIZE as u32,
        nodesize: NODE_SIZE as u32,
        stripesize: NODE_SIZE as u32,
        sys_chunk_array_size: (DiskKey::SIZE + record.len()) as u32,
        chunk_root_generation: GENERATION,
        compat_flags: CompatFlags::NONE,
        compat_ro_flags: CompatRoFlags::NONE,
        incompat_flags: IncompatFlags::MIXED_BACKREF
            | IncompatFlags::BIG_METADATA
            | IncompatFlags::EXTENDED_IREF
            | IncompatFlags::SKINNY_METADATA
            | IncompatFlags::NO_HOLES,
        csum_type: ChecksumType::CRC32C,
        root_level,
        chunk_root_level: 0,
        log_root_level: 0,
        dev_item: DevItem {
            devid: 1,
            total_bytes: device_bytes,
            bytes_used: CHUNK_LENGTH,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            ty: 0,
            generation: 0,
            start_offset: 0,
            dev_group: 0,
            seek_speed: 0,
            bandwidth: 0,
            uuid: [0xec; 16],
            fsid: FSID,
        },
        label: [0; LABEL_SIZE],
        cache_generation: 0,
        uuid_tree_generation: 0,
        metadata_uuid: [0; 16],
        nr_global_roots: 0,
        remap_root: 0,
        remap_root_generation: 0,
        remap_root_level: 0,
        sys_chunk_array: array,
    }
}

/// A leaf of `items`, laid out the way the format lays one out: the array growing forward from
/// the header and the data growing backward from the end of the block.
pub fn leaf(logical: u64, owner: u64, items: &[(DiskKey, Vec<u8>)]) -> Vec<u8> {
    let mut block = vec![0u8; NODE_SIZE];
    let mut data_end = NODE_SIZE;
    for (index, (key, data)) in items.iter().enumerate() {
        data_end -= data.len();
        block[data_end..data_end + data.len()].copy_from_slice(data);
        Item {
            key: *key,
            offset: (data_end - Header::SIZE) as u32,
            size: data.len() as u32,
        }
        .write_to(&mut block[Header::SIZE + index * Item::SIZE..]);
    }
    assert!(
        Header::SIZE + items.len() * Item::SIZE <= data_end,
        "a forged leaf's array and its data do not meet"
    );
    header(logical, owner, 0, items.len() as u32).write_to(&mut block);
    seal(&mut block);
    block
}

/// An internal node at `level` whose children are `(lowest key, address)` pairs.
pub fn node(logical: u64, owner: u64, level: u8, children: &[(DiskKey, u64)]) -> Vec<u8> {
    assert!(level > 0, "an internal node is above the leaves");
    let mut block = vec![0u8; NODE_SIZE];
    for (index, &(key, blockptr)) in children.iter().enumerate() {
        KeyPtr {
            key,
            blockptr,
            generation: GENERATION,
        }
        .write_to(&mut block[Header::SIZE + index * KeyPtr::SIZE..]);
    }
    header(logical, owner, level, children.len() as u32).write_to(&mut block);
    seal(&mut block);
    block
}

fn header(logical: u64, owner: u64, level: u8, nritems: u32) -> Header {
    Header {
        csum: [0; CSUM_FIELD_LEN],
        fsid: FSID,
        bytenr: logical,
        flags: ondisk::HEADER_FLAG_WRITTEN
            | (u64::from(ondisk::BACKREF_REV_MIXED) << ondisk::BACKREF_REV_SHIFT),
        chunk_tree_uuid: [0xc7; 16],
        generation: GENERATION,
        owner,
        nritems,
        level,
    }
}

/// The inode a subvolume's root directory has, which is the first number the format leaves
/// free.
pub const ROOT_DIR: u64 = objectid::FIRST_FREE;

/// Where the top-level subvolume's tree sits in a forged filesystem.
pub const FS_TREE_AT: u64 = FIRST_FREE_AT;

/// Where a forged file's data extent sits.
pub const DATA_AT: u64 = FIRST_FREE_AT + 2 * NODE_SIZE as u64;

/// The byte every forged data extent is filled with.
pub const DATA_BYTE: u8 = 0xab;

/// Both records a directory entry is written as: the hashed copy a lookup finds and the indexed
/// copy a listing walks.
///
/// A filesystem holding one and not the other is one where a name is findable and not listable,
/// or the other way round — so a fixture that wrote a single copy would be testing something no
/// filesystem is.
pub fn entry(
    dir: u64,
    index: u64,
    name: &[u8],
    location: DiskKey,
    kind: DirEntryType,
) -> Vec<(DiskKey, Vec<u8>)> {
    let record = dir_item(location, kind, name);
    vec![
        (
            DiskKey::new(dir, ItemType::DIR_ITEM, ondisk::name_hash(name)),
            record.clone(),
        ),
        (DiskKey::new(dir, ItemType::DIR_INDEX, index), record),
    ]
}

/// A filesystem tree of `items`, at `at`.
///
/// The items are sorted rather than taken as given: a tree's items are in key order, which the
/// format requires and a walk checks, and a fixture written out in the order a person thinks of
/// them is not in the order the key tuple gives.
pub fn fs_tree(at: u64, owner: u64, mut items: Vec<(DiskKey, Vec<u8>)>) -> Vec<u8> {
    items.sort_by_key(|(key, _)| *key);
    leaf(at, owner, &items)
}

impl Forge {
    /// A small filesystem with something of every kind in it: a root directory, a file whose
    /// bytes are inside its own record, a file whose bytes are an extent, a symbolic link, a
    /// subdirectory with a child, and an extended attribute.
    ///
    /// The fixture more than one module needs, so there is one of it. What each gate then
    /// builds for itself is the filesystem that is wrong in the way that gate is about.
    pub fn populated() -> Self {
        let mut items = vec![
            (
                DiskKey::new(ROOT_DIR, ItemType::INODE_ITEM, 0),
                inode_item(0o040_755, 0, 1),
            ),
            (
                DiskKey::new(ROOT_DIR, ItemType::INODE_REF, ROOT_DIR),
                inode_ref(0, b".."),
            ),
            (
                DiskKey::new(257, ItemType::INODE_ITEM, 0),
                inode_item(0o100_644, 6, 1),
            ),
            (
                DiskKey::new(257, ItemType::EXTENT_DATA, 0),
                inline_extent(b"hello\n"),
            ),
            (
                DiskKey::new(257, ItemType::XATTR_ITEM, ondisk::name_hash(b"user.note")),
                xattr_item(b"user.note", b"a value"),
            ),
            (
                DiskKey::new(258, ItemType::INODE_ITEM, 0),
                inode_item(0o100_644, 4096, 1),
            ),
            (
                DiskKey::new(258, ItemType::EXTENT_DATA, 0),
                addressed_extent(ExtentKind::Regular, DATA_AT, 4096, 0, 4096),
            ),
            (
                DiskKey::new(259, ItemType::INODE_ITEM, 0),
                inode_item(0o120_777, 9, 1),
            ),
            (
                DiskKey::new(259, ItemType::EXTENT_DATA, 0),
                inline_extent(b"hello.txt"),
            ),
            (
                DiskKey::new(260, ItemType::INODE_ITEM, 0),
                inode_item(0o040_755, 0, 1),
            ),
            (
                DiskKey::new(261, ItemType::INODE_ITEM, 0),
                inode_item(0o100_600, 3, 1),
            ),
            (
                DiskKey::new(261, ItemType::EXTENT_DATA, 0),
                inline_extent(b"in\n"),
            ),
        ];
        for (dir, index, name, at, kind) in [
            (ROOT_DIR, 2, &b"hello.txt"[..], 257, DirEntryType::RegFile),
            (ROOT_DIR, 3, b"big", 258, DirEntryType::RegFile),
            (ROOT_DIR, 4, b"link", 259, DirEntryType::Symlink),
            (ROOT_DIR, 5, b"sub", 260, DirEntryType::Dir),
            (260, 2, b"inner", 261, DirEntryType::RegFile),
        ] {
            items.extend(entry(
                dir,
                index,
                name,
                DiskKey::new(at, ItemType::INODE_ITEM, 0),
                kind,
            ));
        }

        let mut forge = Self::new();
        forge.block(FS_TREE_AT, &fs_tree(FS_TREE_AT, objectid::FS_TREE, items));
        forge.data(DATA_AT, &[DATA_BYTE; 4096]);
        forge.root_leaf(&[(
            DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0),
            root_item(FS_TREE_AT, 0, ROOT_DIR),
        )]);
        forge
    }
}

/// A root item naming the tree at `bytenr`, whose root directory is `root_dirid`.
pub fn root_item(bytenr: u64, level: u8, root_dirid: u64) -> Vec<u8> {
    let mut record = vec![0u8; RootItem::SIZE];
    RootItem {
        generation: GENERATION,
        root_dirid,
        bytenr,
        byte_limit: 0,
        bytes_used: NODE_SIZE as u64,
        last_snapshot: 0,
        flags: RootFlags::NONE,
        refs: 1,
        drop_progress: DiskKey::MIN,
        drop_level: 0,
        level,
        generation_v2: GENERATION,
        uuid: [0; 16],
        parent_uuid: [0; 16],
        received_uuid: [0; 16],
        ctransid: GENERATION,
        otransid: GENERATION,
        stransid: 0,
        rtransid: 0,
        ctime: TIME,
        otime: TIME,
        stime: Timestamp::from_secs(0),
        rtime: Timestamp::from_secs(0),
    }
    .write_to(&mut record);
    record
}

/// The instant every forged inode and root item records, so nothing here depends on a clock.
pub const TIME: Timestamp = Timestamp {
    secs: 1_786_392_177,
    nanos: 123_000_000,
};

/// An inode item of `mode`, `size` bytes long, with `nlink` names.
pub fn inode_item(mode: u32, size: u64, nlink: u32) -> Vec<u8> {
    let mut record = vec![0u8; InodeItem::SIZE];
    InodeItem {
        generation: GENERATION,
        transid: GENERATION,
        size,
        nbytes: size,
        block_group: 0,
        nlink,
        uid: 0,
        gid: 0,
        mode,
        rdev: 0,
        flags: InodeFlags::NONE,
        sequence: 0,
        atime: TIME,
        ctime: TIME,
        mtime: TIME,
        otime: TIME,
    }
    .write_to(&mut record);
    record
}

/// A directory record naming `location` under `name`: what a `DIR_ITEM` and a `DIR_INDEX` each
/// hold, since the two are the same record keyed twice.
pub fn dir_item(location: DiskKey, kind: DirEntryType, name: &[u8]) -> Vec<u8> {
    packed_record(location, kind, name, b"")
}

/// An extended-attribute record: the same shape, with the value in the bytes an entry leaves
/// empty.
pub fn xattr_item(name: &[u8], value: &[u8]) -> Vec<u8> {
    packed_record(DiskKey::MIN, DirEntryType::Xattr, name, value)
}

fn packed_record(location: DiskKey, kind: DirEntryType, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; DirItem::SIZE];
    DirItem {
        location,
        transid: GENERATION,
        data_len: value.len() as u16,
        name_len: name.len() as u16,
        kind,
    }
    .write_to(&mut record);
    record.extend_from_slice(name);
    record.extend_from_slice(value);
    record
}

/// One name an inode has in a directory.
pub fn inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; InodeRef::SIZE];
    InodeRef {
        index,
        name_len: name.len() as u16,
    }
    .write_to(&mut record);
    record.extend_from_slice(name);
    record
}

/// The `EXTENT_CSUM` record covering `bytes`: one crc32c per `sector` bytes of them, in the
/// seeding and finalization this filesystem checksums with.
///
/// The digest is four bytes wide and the field a record reserves for one is the same four here,
/// which is what a filesystem checksummed with crc32c writes — a wider algorithm's record is
/// wider per sector, and this forge writes the one the pin's default produces.
pub fn csum_item(bytes: &[u8], sector: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(sector) {
        out.extend_from_slice(&ondisk::crc32c_over(chunk).to_le_bytes());
    }
    out
}

/// An extent record holding the file's bytes inside itself.
pub fn inline_extent(bytes: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; FileExtentItem::INLINE_DATA_START];
    FileExtentItem {
        generation: GENERATION,
        ram_bytes: bytes.len() as u64,
        compression: Compression::None,
        encryption: 0,
        other_encoding: 0,
        kind: ExtentKind::Inline,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        num_bytes: 0,
    }
    .write_to(&mut record);
    record.extend_from_slice(bytes);
    record
}

/// An inline extent record whose bytes are a compressed stream expanding to `ram_bytes`.
///
/// Separate from [`inline_extent`] because the two lengths that make a record compressed are
/// exactly the ones that agree in an uncompressed one: what the item holds is the stream, and
/// what the record declares is what the stream stands for.
pub fn compressed_extent(compression: Compression, stream: &[u8], ram_bytes: u64) -> Vec<u8> {
    let mut record = vec![0u8; FileExtentItem::INLINE_DATA_START];
    FileExtentItem {
        generation: GENERATION,
        ram_bytes,
        compression,
        encryption: 0,
        other_encoding: 0,
        kind: ExtentKind::Inline,
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        num_bytes: 0,
    }
    .write_to(&mut record);
    record.extend_from_slice(stream);
    record
}

/// An extent record addressing a run of logical space, in the shape `kind` names.
pub fn addressed_extent(
    kind: ExtentKind,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
) -> Vec<u8> {
    let mut record = vec![0u8; FileExtentItem::SIZE];
    FileExtentItem {
        generation: GENERATION,
        ram_bytes: disk_num_bytes,
        compression: Compression::None,
        encryption: 0,
        other_encoding: 0,
        kind,
        disk_bytenr,
        disk_num_bytes,
        offset,
        num_bytes,
    }
    .write_to(&mut record);
    record
}

/// Write an object's own checksum over it, which is the last thing done to every block and
/// every superblock the format writes.
pub fn seal(object: &mut [u8]) {
    let digest = ondisk::checksum(object);
    put_arr(object, 0, &digest.to_le_bytes());
    object[4..CSUM_FIELD_LEN].fill(0);
}
