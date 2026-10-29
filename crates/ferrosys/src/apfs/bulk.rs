//! B-trees built whole: records in key order packed into nodes, and index nodes over them.
//!
//! A tree a writer builds from nothing holds every record it will hold before its first node is
//! written, so it is laid out once rather than grown by insertion. Each node takes records in
//! key order until the next would not fit, which is also what a tree grown by inserting in key
//! order leaves behind: the file-system trees macOS writes, filled that way, have leaves with a
//! few bytes free. A level whose nodes do not all fit in one root gets a level of index nodes above
//! it, each entry its child's first key and the child's identifier, until one node holds the
//! level.
//!
//! [`shape`] decides which records each node holds from the records' sizes alone, so the number
//! of nodes a tree needs is known before any node has an identifier or a block. [`render`] then
//! writes each node, given the identifier and block of each, from the leaves up.
//!
//! # A node's layout
//!
//! A node's table comes first, then its keys in key order from the start of the key area, then
//! free space, then its values, the first entry's value at the end of the value area and each
//! later one before it. The value area of a root ends where the tree's information begins. Both
//! free lists are empty.
//!
//! The table of a tree whose entries vary in size takes 8 bytes an entry, rounded up to a
//! multiple of 64; every node of every file-system and extent-reference tree observed has a
//! table of that length for the entries it holds. The table of a tree of fixed-size entries is
//! as long in every leaf of the tree: four bytes for each entry the node would hold were every
//! byte past the node's header a table slot, a key and a value, rounded down to eight bytes.
//! That length is held byte for byte against the empty containers `newfs_apfs` formats, at
//! every block size. An index node's table is as long in every index node, counted with a
//! child's 8-byte identifier for the value: observed in an object map's index root at 4 KiB
//! blocks, and applied by the same rule at the other block sizes and to other trees of
//! fixed-size entries.
//!
//! This module is pure: it lays out bytes and does no I/O.

use std::ops::Range;

use crate::bytes::put_u16;

use super::ondisk::{
    NO_VALUE, NODE_DATA_START, NodeHeader, ObjectHeader, Storage, TREE_INFO_SIZE, TreeInfo, kind,
    node_flags,
};

/// The bytes of a table slot in a node of entries that vary in size: the key's offset and
/// length, and the value's.
const VARIABLE_SLOT: usize = 8;

/// The bytes a variable node's table grows by.
const VARIABLE_TABLE_STEP: usize = 64;

/// The bytes of a table slot in a node of fixed-size entries: the key's offset and the value's.
const FIXED_SLOT: usize = 4;

/// The bytes of an index entry's value: a child's identifier.
const CHILD_BYTES: usize = 8;

/// A key and its value.
pub(crate) type Record = (Vec<u8>, Vec<u8>);

/// How a tree's entries are sized.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Entries {
    /// Each key and value is as long as it is, and the table records both lengths.
    Variable,
    /// Every leaf key and value has these sizes, and the table records offsets alone.
    Fixed {
        /// Bytes in every key.
        key: usize,
        /// Bytes in every leaf value.
        value: usize,
    },
}

/// What a tree is, as every node of it records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TreeKind {
    /// The tree's subtype: what its records are.
    pub(crate) subtype: u16,
    /// How a node is found from its identifier: through an object map, or at its address.
    pub(crate) storage: Storage,
    /// The flags the root's tree information records.
    pub(crate) tree_flags: u32,
    /// How its entries are sized.
    pub(crate) entries: Entries,
}

/// Which records each node of a tree holds, level by level, leaves first.
///
/// `levels[0]` divides the records among the leaves; each later level divides the nodes of the
/// level below among its nodes. The last level is the root's, and holds one node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Shape {
    levels: Vec<Vec<Range<usize>>>,
}

impl Shape {
    /// Every node the tree has.
    pub(crate) fn node_count(&self) -> usize {
        self.levels.iter().map(Vec::len).sum()
    }

    /// The nodes of each level, leaves first.
    #[cfg(test)]
    pub(crate) fn level_sizes(&self) -> impl Iterator<Item = usize> + '_ {
        self.levels.iter().map(Vec::len)
    }

    /// Whether the tree is one root leaf.
    pub(crate) fn is_one_leaf(&self) -> bool {
        self.levels.len() == 1
    }
}

/// The bytes past the node header and before any tree information that a node's table, keys
/// and values share.
const fn room(node_size: usize, is_root: bool) -> usize {
    node_size - NODE_DATA_START - if is_root { TREE_INFO_SIZE } else { 0 }
}

/// The most bytes of key and value one entry of a tree of entries that vary in size may take:
/// what a node other than the root holds beside a table of one entry.
pub(crate) const fn largest_entry(node_size: usize) -> usize {
    room(node_size, false) - variable_table_bytes(1)
}

/// The longest key an entry of a tree of entries that vary in size may have: the longest of
/// which a node other than the root holds two index entries, so that each level of index nodes
/// has fewer nodes than the level below it has entries, and a root holds the last one.
#[cfg(test)]
pub(crate) const fn longest_key(node_size: usize) -> usize {
    (room(node_size, false) - variable_table_bytes(2)) / 2 - CHILD_BYTES
}

/// The table of a node of fixed-size entries: four bytes per entry the node would hold were
/// every byte past its header a slot, a key and a value, rounded down to eight bytes. That is
/// the length measured on object maps and free queues at all five block sizes, and held
/// byte for byte against the containers `newfs_apfs` formats (observed).
pub(crate) const fn fixed_table_bytes(node_size: usize, key: usize, value: usize) -> usize {
    (FIXED_SLOT * ((node_size - NODE_DATA_START) / (FIXED_SLOT + key + value))) & !7
}

/// The table of a variable node of `entries` entries: eight bytes each, rounded up to 64, and
/// 64 for a node with none.
const fn variable_table_bytes(entries: usize) -> usize {
    let bytes = entries * VARIABLE_SLOT;
    if bytes == 0 {
        VARIABLE_TABLE_STEP
    } else {
        bytes.div_ceil(VARIABLE_TABLE_STEP) * VARIABLE_TABLE_STEP
    }
}

/// How the entries of one level are sized: the leaves' as the tree says, an index level's with
/// a child's identifier for a value. The index level's sizing is observed in an object map's
/// index root at 4 KiB blocks; other block sizes and other trees of fixed-size entries are held
/// to the same rule.
#[derive(Clone, Copy)]
enum LevelEntries {
    Variable,
    Fixed { key: usize, value: usize },
}

impl LevelEntries {
    const fn of(entries: Entries, level: usize) -> Self {
        match entries {
            Entries::Variable => Self::Variable,
            Entries::Fixed { key, value } => Self::Fixed {
                key,
                value: if level == 0 { value } else { CHILD_BYTES },
            },
        }
    }

    /// Whether `count` entries whose keys and values take `bytes` together fit a node of
    /// `room` bytes.
    fn fits(self, node_size: usize, room: usize, count: usize, bytes: usize) -> bool {
        match self {
            Self::Variable => variable_table_bytes(count) + bytes <= room,
            Self::Fixed { key, value } => {
                let table = fixed_table_bytes(node_size, key, value);
                count * FIXED_SLOT <= table && table + bytes <= room
            }
        }
    }

    /// The table length of a node of `count` entries.
    fn table_bytes(self, node_size: usize, count: usize) -> usize {
        match self {
            Self::Variable => variable_table_bytes(count),
            Self::Fixed { key, value } => fixed_table_bytes(node_size, key, value),
        }
    }
}

/// Which records each node of a tree holds, with nodes of `node_size` bytes and entries sized
/// as `entries` says.
///
/// # Panics
///
/// Where a record of entries that vary in size is longer than [`largest_entry`], or its key
/// longer than the longest of which a node other than the root holds two index entries, which
/// no record this crate makes is: a tree of such records has a node no record fits, or levels
/// of index nodes that never narrow to a root.
pub(crate) fn shape(records: &[Record], node_size: usize, entries: Entries) -> Shape {
    let mut sizes: Vec<usize> = records.iter().map(|(k, v)| k.len() + v.len()).collect();
    let mut first_keys: Vec<usize> = records.iter().map(|(k, _)| k.len()).collect();
    let mut levels = Vec::new();
    loop {
        let level = LevelEntries::of(entries, levels.len());
        let total: usize = sizes.iter().sum();
        if level.fits(node_size, room(node_size, true), sizes.len(), total) {
            levels.push(std::iter::once(0..sizes.len()).collect());
            return Shape { levels };
        }
        let nodes = pack(&sizes, |count, bytes| {
            level.fits(node_size, room(node_size, false), count, bytes)
        });
        // A level of index nodes is fewer than the entries it holds, or no root is reached.
        assert!(
            levels.is_empty() || nodes.len() < sizes.len(),
            "a level of {} index entries takes {} nodes",
            sizes.len(),
            nodes.len()
        );
        // The level above holds one entry per node: the node's first key and an identifier.
        sizes = nodes
            .iter()
            .map(|node| first_keys[node.start] + CHILD_BYTES)
            .collect();
        first_keys = nodes.iter().map(|node| first_keys[node.start]).collect();
        levels.push(nodes);
    }
}

/// Divide entries of `sizes` bytes into runs, each as long as `fits` allows.
fn pack(sizes: &[usize], fits: impl Fn(usize, usize) -> bool) -> Vec<Range<usize>> {
    let mut nodes = Vec::new();
    let mut start = 0;
    while start < sizes.len() {
        let (mut end, mut bytes) = (start, 0);
        while end < sizes.len() && fits(end - start + 1, bytes + sizes[end]) {
            bytes += sizes[end];
            end += 1;
        }
        assert!(
            end > start,
            "a record of {} bytes fits no node",
            sizes[start]
        );
        nodes.push(start..end);
        start = end;
    }
    nodes
}

/// Where one node of a tree goes: its identifier, and the block it is written to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Placed {
    /// The identifier its parent records and its header carries: its block for a physical
    /// tree, a number its object map resolves for a virtual one.
    pub(crate) oid: u64,
    /// The block it is written to.
    pub(crate) block: u64,
}

/// Every node of a tree of `kind` holding `records` as `shape` divides them, written in
/// transaction `xid`, each with the identifier and block `places` gives it: the leaves first,
/// in key order, then each level above, the root last. Each node is returned with its block,
/// unchecksummed.
///
/// # Panics
///
/// Where `places` does not hold one place per node of `shape`.
pub(crate) fn render(
    records: &[Record],
    shape: &Shape,
    kind: TreeKind,
    node_size: usize,
    xid: u64,
    places: &[Placed],
) -> Vec<(u64, Vec<u8>)> {
    assert_eq!(places.len(), shape.node_count(), "one place per node");
    let info = tree_info(records, kind, node_size, shape.node_count());

    let mut out = Vec::with_capacity(shape.node_count());
    let mut next_place = places.iter();
    // The level below's entries: for the leaves the records, for each level above one entry
    // per node of the level below, its first key and its identifier.
    let mut below: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (level, nodes) in shape.levels.iter().enumerate() {
        let is_root_level = level + 1 == shape.levels.len();
        let entries: Vec<(&[u8], &[u8])> = if level == 0 {
            records
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect()
        } else {
            below
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect()
        };
        let mut above = Vec::with_capacity(nodes.len());
        for range in nodes {
            let place = next_place.next().expect("one place per node");
            let held = &entries[range.clone()];
            let object = ObjectHeader {
                checksum: 0,
                oid: place.oid,
                xid,
                type_word: kind.storage.type_bits()
                    | u32::from(if is_root_level {
                        kind::BTREE_ROOT
                    } else {
                        kind::BTREE_NODE
                    }),
                subtype: u32::from(kind.subtype),
            };
            let in_key_order: Vec<usize> = (0..held.len()).collect();
            let bytes = node(
                held,
                &in_key_order,
                object,
                narrow(level),
                is_root_level.then_some(info),
                LevelEntries::of(kind.entries, level),
                node_size,
            );
            let first_key = held.first().map_or_else(Vec::new, |(k, _)| k.to_vec());
            above.push((first_key, place.oid));
            out.push((place.block, bytes));
        }
        below = above
            .into_iter()
            .map(|(key, oid)| (key, oid.to_le_bytes().to_vec()))
            .collect();
    }
    out
}

/// A root leaf of a tree of `kind` holding `records`, laid out as one node grown from nothing
/// by inserting them in the order `records` gives: keys from the start of the key area and
/// values back from the end of the value area in that order, and the table listing them in key
/// order, `key_order` naming the record each slot holds in turn. The node is returned
/// unchecksummed.
///
/// # Panics
///
/// Where `key_order` is not an ordering of `records`.
pub(crate) fn inserted_root_leaf(
    records: &[Record],
    key_order: &[usize],
    kind: TreeKind,
    node_size: usize,
    object: ObjectHeader,
) -> Vec<u8> {
    assert_eq!(key_order.len(), records.len(), "one slot per record");
    let entries: Vec<(&[u8], &[u8])> = key_order
        .iter()
        .map(|&i| (records[i].0.as_slice(), records[i].1.as_slice()))
        .collect();
    let mut laid_out = vec![usize::MAX; records.len()];
    for (slot, &record) in key_order.iter().enumerate() {
        laid_out[record] = slot;
    }
    assert!(!laid_out.contains(&usize::MAX), "every record has its slot");
    node(
        &entries,
        &laid_out,
        object,
        0,
        Some(tree_info(records, kind, node_size, 1)),
        LevelEntries::of(kind.entries, 0),
        node_size,
    )
}

/// The information the root of a tree of `kind` records, for a tree of `node_count` nodes of
/// `node_size` bytes holding `records`.
fn tree_info(records: &[Record], kind: TreeKind, node_size: usize, node_count: usize) -> TreeInfo {
    let (longest_key, longest_value) = match kind.entries {
        Entries::Variable => (
            records.iter().map(|(k, _)| k.len()).max().unwrap_or(0),
            records.iter().map(|(_, v)| v.len()).max().unwrap_or(0),
        ),
        Entries::Fixed { key, value } if !records.is_empty() => (key, value),
        Entries::Fixed { .. } => (0, 0),
    };
    TreeInfo {
        flags: kind.tree_flags,
        node_size: narrow(node_size),
        key_size: match kind.entries {
            Entries::Variable => 0,
            Entries::Fixed { key, .. } => narrow(key),
        },
        value_size: match kind.entries {
            Entries::Variable => 0,
            Entries::Fixed { value, .. } => narrow(value),
        },
        longest_key: narrow(longest_key),
        longest_value: narrow(longest_value),
        key_count: records.len() as u64,
        node_count: node_count as u64,
    }
}

/// One node holding `entries` in key order, at `level`, with the tree's information where it
/// is the root. The table lists `entries` in turn; their keys and values are laid out in the
/// order `laid_out` gives, each a slot of the table.
fn node(
    entries: &[(&[u8], &[u8])],
    laid_out: &[usize],
    object: ObjectHeader,
    level: u16,
    info: Option<TreeInfo>,
    sizes: LevelEntries,
    node_size: usize,
) -> Vec<u8> {
    let mut bytes = vec![0u8; node_size];
    let table = sizes.table_bytes(node_size, entries.len());
    let key_area = NODE_DATA_START + table;
    let value_end = node_size - if info.is_some() { TREE_INFO_SIZE } else { 0 };
    let mut placed = vec![(0usize, 0usize); entries.len()];
    let (mut keys, mut values) = (0usize, 0usize);
    for &slot in laid_out {
        let (key, value) = entries[slot];
        bytes[key_area + keys..key_area + keys + key.len()].copy_from_slice(key);
        values += value.len();
        bytes[value_end - values..value_end - values + value.len()].copy_from_slice(value);
        placed[slot] = (keys, values);
        keys += key.len();
    }
    for (i, ((key, value), (key_at, value_at))) in entries.iter().zip(&placed).enumerate() {
        match sizes {
            LevelEntries::Variable => {
                let at = NODE_DATA_START + VARIABLE_SLOT * i;
                put_u16(&mut bytes, at, narrow(*key_at));
                put_u16(&mut bytes, at + 2, narrow(key.len()));
                put_u16(&mut bytes, at + 4, narrow(*value_at));
                put_u16(&mut bytes, at + 6, narrow(value.len()));
            }
            LevelEntries::Fixed { .. } => {
                let at = NODE_DATA_START + FIXED_SLOT * i;
                put_u16(&mut bytes, at, narrow(*key_at));
                put_u16(&mut bytes, at + 2, narrow(*value_at));
            }
        }
    }
    let mut flags = 0;
    if info.is_some() {
        flags |= node_flags::ROOT;
    }
    if level == 0 {
        flags |= node_flags::LEAF;
    }
    if matches!(sizes, LevelEntries::Fixed { .. }) {
        flags |= node_flags::FIXED_SIZE;
    }
    NodeHeader {
        header: object,
        flags,
        level,
        key_count: narrow(entries.len()),
        table: (0, narrow(table)),
        free_space: (narrow(keys), narrow(value_end - key_area - keys - values)),
        key_free_list: (NO_VALUE, 0),
        value_free_list: (NO_VALUE, 0),
    }
    .write_to(&mut bytes);
    if let Some(info) = info {
        info.write_to(&mut bytes[value_end..]);
    }
    bytes
}

/// A size this module derived, in the width a node records it in.
///
/// # Panics
///
/// Where it does not fit, which no node of a size the format defines reaches.
fn narrow<T: TryFrom<usize>>(value: usize) -> T {
    T::try_from(value)
        .unwrap_or_else(|_| panic!("{value} does not fit the field a node records it in"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::apfs::ondisk::{EntrySizes, Node, child_oid};

    const FS: TreeKind = TreeKind {
        subtype: kind::FS_TREE,
        storage: Storage::Virtual,
        tree_flags: 0x42,
        entries: Entries::Variable,
    };

    const MAP: TreeKind = TreeKind {
        subtype: kind::OBJECT_MAP,
        storage: Storage::Physical,
        tree_flags: 0x12,
        entries: Entries::Fixed { key: 16, value: 16 },
    };

    /// `n` records of sizes that vary with a seed, in key order: each key is its index, big
    /// endian, padded to a length that varies, so byte order is key order.
    fn variable(n: usize, seed: usize) -> Vec<Record> {
        (0..n)
            .map(|i| {
                let mut key = (i as u64).to_be_bytes().to_vec();
                key.resize(8 + (i * 7 + seed) % 40, 0xA5);
                let value = vec![(i % 251) as u8; (i * 13 + seed) % 300];
                (key, value)
            })
            .collect()
    }

    fn fixed(n: usize) -> Vec<Record> {
        (0..n)
            .map(|i| {
                let mut key = vec![0u8; 16];
                key[..8].copy_from_slice(&(i as u64).to_be_bytes());
                (key, vec![(i % 251) as u8; 16])
            })
            .collect()
    }

    /// Places for every node of `shape`: identifiers from 1028 for a virtual tree, blocks from
    /// 1000.
    fn places(shape: &Shape, kind: TreeKind) -> Vec<Placed> {
        (0..shape.node_count() as u64)
            .map(|i| Placed {
                oid: if kind.storage == Storage::Virtual {
                    1028 + i
                } else {
                    1000 + i
                },
                block: 1000 + i,
            })
            .collect()
    }

    fn sizes(kind: TreeKind) -> EntrySizes {
        match kind.entries {
            Entries::Variable => EntrySizes { key: 0, value: 0 },
            Entries::Fixed { key, value } => EntrySizes {
                key: key as u32,
                value: value as u32,
            },
        }
    }

    /// The tree's leaf records, read from the root down through each index entry's child, with
    /// each index key held to its child's first key.
    fn read_back(nodes: &[(u64, Vec<u8>)], kind: TreeKind, root: u64) -> Vec<Record> {
        let by_oid: BTreeMap<u64, &Vec<u8>> = nodes
            .iter()
            .map(|(_, bytes)| (u64::from_le_bytes(bytes[8..16].try_into().unwrap()), bytes))
            .collect();
        let mut out = Vec::new();
        let mut todo = vec![(root, None::<Vec<u8>>)];
        while let Some((oid, first)) = todo.pop() {
            let bytes = by_oid[&oid];
            let node = Node::frame(bytes, sizes(kind)).expect("a node frames");
            node.check_layout().expect("a node's layout holds");
            let mut children = Vec::new();
            for i in 0..node.len() {
                let (key, value) = node.entry(i).expect("an entry");
                if i == 0
                    && let Some(first) = &first
                {
                    assert_eq!(key, first.as_slice(), "an index key is its child's first");
                }
                if node.header().is_leaf() {
                    out.push((key.to_vec(), value.unwrap().to_vec()));
                } else {
                    children.push((child_oid(value.unwrap()).unwrap(), Some(key.to_vec())));
                }
            }
            todo.extend(children.into_iter().rev());
        }
        out
    }

    fn root_of(nodes: &[(u64, Vec<u8>)]) -> &Vec<u8> {
        &nodes.last().expect("a root").1
    }

    fn info(nodes: &[(u64, Vec<u8>)]) -> TreeInfo {
        let root = root_of(nodes);
        TreeInfo::read_from(&root[root.len() - TREE_INFO_SIZE..]).expect("tree information")
    }

    #[test]
    fn a_tree_built_whole_reads_back_record_for_record() {
        for (kind, records) in [
            (FS, variable(0, 0)),
            (FS, variable(3, 1)),
            (FS, variable(400, 2)),
            (FS, variable(30_000, 3)),
            (MAP, fixed(0)),
            (MAP, fixed(111)),
            (MAP, fixed(112)),
            (MAP, fixed(20_000)),
        ] {
            for node_size in [4096, 16384, 65536] {
                let tree = shape(&records, node_size, kind.entries);
                let placed = places(&tree, kind);
                let nodes = render(&records, &tree, kind, node_size, 2, &placed);
                let root = placed.last().unwrap().oid;
                assert_eq!(read_back(&nodes, kind, root), records);
                let held = info(&nodes);
                assert_eq!(held.key_count, records.len() as u64);
                assert_eq!(held.node_count, tree.node_count() as u64);
            }
        }
    }

    #[test]
    fn every_node_but_a_levels_last_takes_records_until_the_next_would_not_fit() {
        let records = variable(5_000, 7);
        let tree = shape(&records, 4096, Entries::Variable);
        let leaves = &tree.levels[0];
        assert!(leaves.len() > 10);
        for node in &leaves[..leaves.len() - 1] {
            let take = |end: usize| {
                let bytes: usize = records[node.start..end]
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum();
                variable_table_bytes(end - node.start) + bytes <= room(4096, false)
            };
            assert!(take(node.end));
            assert!(
                !take(node.end + 1),
                "leaf {node:?} had room for the next record"
            );
        }
    }

    #[test]
    fn the_largest_entry_and_longest_key_are_what_a_node_holds_at_every_block_size() {
        let level = LevelEntries::Variable;
        for node_size in [4096, 8192, 16384, 32768, 65536] {
            let (inner, root) = (room(node_size, false), room(node_size, true));
            let largest = largest_entry(node_size);
            assert!(level.fits(node_size, inner, 1, largest));
            assert!(!level.fits(node_size, inner, 1, largest + 1));
            // Two index entries of the longest key share a node, a byte more each does not, and
            // a root holds one.
            let index = longest_key(node_size) + CHILD_BYTES;
            assert!(level.fits(node_size, inner, 2, 2 * index));
            assert!(!level.fits(node_size, inner, 2, 2 * (index + 1)));
            assert!(level.fits(node_size, root, 1, index));

            // Records of the largest entry, each with the longest key, narrow to one root and read
            // back.
            for n in [1, 2, 3, 40] {
                let records: Vec<Record> = (0..n as u32)
                    .map(|i| {
                        let mut key = i.to_be_bytes().to_vec();
                        key.resize(longest_key(node_size), 0xA5);
                        let value = vec![1; largest - key.len()];
                        (key, value)
                    })
                    .collect();
                let tree = shape(&records, node_size, FS.entries);
                let placed = places(&tree, FS);
                let nodes = render(&records, &tree, FS, node_size, 2, &placed);
                let root = placed.last().unwrap().oid;
                assert_eq!(read_back(&nodes, FS, root), records, "{n} at {node_size}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "index entries takes 1 nodes")]
    fn a_key_two_of_which_share_no_index_node_is_refused_rather_than_levelled_forever() {
        // A record a node other than the root holds, whose key with an identifier does not fit a
        // root: each level above it would be one node of one entry.
        let key = vec![0xA5; longest_key(4096) * 2];
        let value = vec![1; largest_entry(4096) - key.len()];
        let _ = shape(&[(key, value)], 4096, Entries::Variable);
    }

    #[test]
    fn a_variable_table_grows_by_64_bytes_and_a_fixed_one_is_the_trees_own() {
        assert_eq!(variable_table_bytes(0), 64);
        assert_eq!(variable_table_bytes(8), 64);
        assert_eq!(variable_table_bytes(9), 128);
        assert_eq!(variable_table_bytes(51), 448);
        assert_eq!(variable_table_bytes(68), 576);
        // The object map's leaves and the free queue's nodes at each block size, and an index
        // node's of the object map at 4 KiB.
        let map: Vec<usize> = [4096, 8192, 16384, 32768, 65536]
            .iter()
            .map(|&size| fixed_table_bytes(size, 16, 16))
            .collect();
        assert_eq!(map, [448, 904, 1808, 3632, 7272]);
        let queue: Vec<usize> = [4096, 8192, 16384, 32768, 65536]
            .iter()
            .map(|&size| fixed_table_bytes(size, 16, 8))
            .collect();
        assert_eq!(queue, [576, 1160, 2328, 4672, 9352]);
    }

    #[test]
    fn a_fixed_root_leaf_holds_111_mappings_at_4_kib_and_a_non_root_leaf_112() {
        assert!(shape(&fixed(111), 4096, MAP.entries).is_one_leaf());
        let split = shape(&fixed(112), 4096, MAP.entries);
        assert_eq!(split.level_sizes().collect::<Vec<_>>(), [1, 1]);
        let two = shape(&fixed(113), 4096, MAP.entries);
        assert_eq!(two.level_sizes().collect::<Vec<_>>(), [2, 1]);
        let placed = places(&two, MAP);
        let nodes = render(&fixed(113), &two, MAP, 4096, 2, &placed);
        let root = Node::frame(root_of(&nodes), sizes(MAP)).unwrap();
        assert_eq!(
            root.header().table,
            (0, 576),
            "an index node's values are identifiers"
        );
    }

    #[test]
    fn a_root_records_the_longest_key_and_value_it_holds_and_an_empty_fixed_root_none() {
        let records = variable(1_000, 5);
        let tree = shape(&records, 4096, FS.entries);
        let nodes = render(&records, &tree, FS, 4096, 2, &places(&tree, FS));
        let held = info(&nodes);
        assert_eq!(
            held.longest_key as usize,
            records.iter().map(|(k, _)| k.len()).max().unwrap()
        );
        assert_eq!(
            held.longest_value as usize,
            records.iter().map(|(_, v)| v.len()).max().unwrap()
        );
        let empty = shape(&[], 4096, MAP.entries);
        let nodes = render(&[], &empty, MAP, 4096, 1, &places(&empty, MAP));
        let held = info(&nodes);
        assert_eq!((held.longest_key, held.longest_value), (0, 0));
        assert_eq!((held.key_size, held.value_size), (16, 16));
    }
}
