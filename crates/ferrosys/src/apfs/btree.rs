//! The B-tree engine: one descent, one ordered iteration, and the bounds that make both
//! terminate on an image that was crafted rather than formatted.
//!
//! Every tree in a container has the same node format, so there is one engine and every tree
//! is read through it: the object maps, each volume's file-system tree, and its snapshot tree,
//! and the space manager's free queues. What a record means is decided by whoever asked for it;
//! this module knows that records have keys, that keys are ordered, and how a node reaches its
//! children — by physical address, by a virtual identifier looked up in an object map at a
//! transaction, or by an ephemeral identifier the live checkpoint maps.
//!
//! # What bounds a walk
//!
//! - **A location outside its node.** Every key and value is checked against the node's areas
//!   when it is read, and every node's entries are placed together when it is reached, so no
//!   two keys and no two values share a byte ([`Node`]).
//! - **A child at the wrong height.** A child must be exactly one level below its parent, and a
//!   root no higher than [`MAX_LEVEL`], so a descent has a decreasing measure whatever the
//!   addresses say.
//! - **A node reached twice.** Every node one iteration reaches is remembered, so a tree whose
//!   index entries share a child is refused rather than read twice.
//! - **The wrong node.** Each node is read as an object of its tree's subtype, root or not as
//!   its place says, recording its own identifier, and from a transaction no later than what
//!   led to it.
//! - **Keys out of order, repeated, or out of place.** A node's keys are held to each other:
//!   each is before the next in the order its tree keeps ([`compare_records`] for a file-system
//!   tree), so no key is stored twice. They are held to the parent's as well: a node's first key
//!   is the parent's key for it, observed byte for byte in every tree of every image macOS wrote,
//!   and its last is below the parent's key for the node after it. A search steers by those
//!   keys, so one that does not match its node would hide records a walk of every node would
//!   still meet: a point lookup holds the node after its answer as well, where its answer is
//!   the last record of its node ([`find_at_or_before`]), and an object map is read whole
//!   before a strict read trusts a lookup through it ([`check_whole`]).
//! - **A tree larger than the caller will hold.** An iteration visits no more records than the
//!   limit its caller passes: [`Limits::max_walk_entries`](crate::Limits) for a whole-tree
//!   walk, a directory listing, and a file's extents or attributes, and none for a lookup,
//!   which stops at the name it is after.
//!
//! This module does I/O, through the container it borrows.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::{Read, Seek};

use super::container::{Container, Expect, Object, ReadError, Xid};
use super::ondisk::{
    EntryKey, EntrySizes, FileExtent, FreeQueueKey, KeyHeader, MapKey, Node, NodeHeader,
    ObjectHeader, ParseError, Storage, TREE_ALLOW_GHOSTS, TREE_EPHEMERAL, TREE_HASHED,
    TREE_KV_NONALIGNED, TREE_NO_HEADER, TREE_PHYSICAL, TREE_SEQUENTIAL_INSERT, TreeInfo, Unused,
    child_oid, key_u64, kind, node_flags, record_kind, xattr_name,
};

/// The highest level a root may have. A container's block count is below 2^64, so a tree in
/// which every index node has at least two children has fewer levels than this. The format
/// does not require two, and a walk is bounded either way: each step down lowers the level by
/// one, and no node is reached twice.
pub const MAX_LEVEL: u16 = 63;

/// How a tree's index nodes reach their children.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Children {
    /// By block address.
    Physical,
    /// By ephemeral identifier, found through the live checkpoint's mappings.
    Ephemeral,
    /// By virtual identifier, looked up at transaction `xid` in the object map whose mapping
    /// tree is at block `map_tree`, written no later than `map_xid`.
    Virtual {
        /// The mapping tree's root block.
        map_tree: u64,
        /// The transaction the map's header records.
        map_xid: u64,
        /// The transaction every child is resolved at.
        xid: u64,
    },
}

/// How a tree's keys are ordered, which is a property of what it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Order {
    /// An object map: by identifier, then by transaction.
    ObjectMap,
    /// A file-system or snapshot tree: by identifier and record kind, then by a part of the key
    /// that is the kind's own.
    FileSystem,
    /// A free queue: by the transaction that freed a run, then by the run's first block.
    FreeQueue,
    /// An object map's tree of the snapshots it keeps: by transaction.
    Transaction,
}

/// Where a tree begins, and how to read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeRoot {
    /// The root node's identifier: its block for a physical tree, its virtual identifier
    /// otherwise.
    pub oid: u64,
    /// How index nodes reach their children.
    pub children: Children,
    /// The subtype every node of the tree carries.
    pub subtype: u16,
    /// How the tree's keys are ordered.
    pub order: Order,
    /// The newest transaction the root may record.
    pub max_xid: u64,
}

impl TreeRoot {
    /// An object map's mapping tree, rooted at `oid` and written no later than `max_xid`.
    pub(crate) const fn object_map(oid: u64, max_xid: u64) -> Self {
        TreeRoot {
            oid,
            children: Children::Physical,
            subtype: kind::OBJECT_MAP,
            order: Order::ObjectMap,
            max_xid,
        }
    }

    /// The mapping tree a virtual tree's children are resolved through.
    fn map(&self) -> Option<(TreeRoot, u64)> {
        match self.children {
            Children::Physical | Children::Ephemeral => None,
            Children::Virtual {
                map_tree,
                map_xid,
                xid,
            } => Some((TreeRoot::object_map(map_tree, map_xid), xid)),
        }
    }
}

/// A comparison of a key against a target: [`Ordering::Less`] where the key sorts before it.
pub(crate) type Target<'t> = &'t dyn Fn(&[u8]) -> Result<Ordering, ParseError>;

/// One record taken out of a tree: its key and its value.
pub(crate) type Record = (Vec<u8>, Vec<u8>);

/// What an iteration hands each record to: its key and value, answering whether to go on.
pub(crate) type Visit<'v> = dyn FnMut(&[u8], &[u8]) -> Result<bool, ReadError> + 'v;

/// One node, read and held, with where it sits.
struct Frame {
    object: Object,
    block: u64,
    sizes: EntrySizes,
    level: u16,
    /// The next entry to visit.
    next: u32,
    /// The parent's key for the node after this one, which bounds this node's keys.
    bound: Option<Vec<u8>>,
    /// The bytes of its key and value areas no entry holds.
    unused: Unused,
}

impl Frame {
    fn node(&self) -> Result<Node<'_>, ReadError> {
        Node::frame(&self.object, self.sizes).map_err(|fault| ReadError::BadNode {
            block: self.block,
            fault,
        })
    }
}

/// Read a tree's root node and frame it.
fn read_root<R: Read + Seek>(
    container: &mut Container<R>,
    root: &TreeRoot,
) -> Result<Frame, ReadError> {
    let (block, object) = read_node(container, root, root.oid, true, root.max_xid)?;
    let header = NodeHeader::read_from(&object)?;
    if !header.is_root() {
        return Err(ReadError::BadTree {
            block,
            fault: "a root without its tree information",
        });
    }
    // A node is one block, of 4 KiB at the least, so its last bytes hold the information.
    let info = TreeInfo::read_from(&object[object.len() - TreeInfo::SIZE..])?;
    check_info(block, &info, container.block_size(), root)?;
    if header.level > MAX_LEVEL {
        return Err(ReadError::BadTree {
            block,
            fault: "a root higher than any tree the container could hold",
        });
    }
    let mut frame = Frame {
        object,
        block,
        sizes: EntrySizes {
            key: info.key_size,
            value: info.value_size,
        },
        level: header.level,
        next: 0,
        bound: None,
        unused: Unused::default(),
    };
    frame.unused = check_node(&frame.node()?, block, root.order, true)?;
    Ok(frame)
}

/// The tree flags a tree this crate reads may carry: the hint that it be kept compact under
/// sequential insertion, the one saying its keys and values need not be aligned to eight
/// bytes, the one allowing a key with no value, and the two saying its children are found by
/// address or through the checkpoint's mappings, which exclude each other (reference
/// pp. 129-131).
const READ_FLAGS: u32 = TREE_SEQUENTIAL_INSERT
    | TREE_ALLOW_GHOSTS
    | TREE_KV_NONALIGNED
    | TREE_PHYSICAL
    | TREE_EPHEMERAL;

/// Refuse a tree whose information says its nodes are read some other way: flags this crate
/// does not read (reference pp. 129-131), or children found otherwise than `tree`'s are.
fn check_info(
    block: u64,
    info: &TreeInfo,
    block_size: u32,
    tree: &TreeRoot,
) -> Result<(), ReadError> {
    if info.flags & (TREE_HASHED | TREE_NO_HEADER) != 0 {
        return Err(ReadError::BadTree {
            block,
            fault: "a tree whose nodes are hashed or headerless",
        });
    }
    if info.flags & !READ_FLAGS != 0 {
        return Err(ReadError::BadTree {
            block,
            fault: "a tree flagged as keyed by 64-bit integers, as not persisted, or with a bit \
                    the format does not define",
        });
    }
    if (info.flags & TREE_PHYSICAL != 0) != matches!(tree.children, Children::Physical)
        || (info.flags & TREE_EPHEMERAL != 0) != matches!(tree.children, Children::Ephemeral)
    {
        return Err(ReadError::BadTree {
            block,
            fault: "a tree whose root says its children are found otherwise than they are",
        });
    }
    if info.node_size != block_size {
        return Err(ReadError::BadTree {
            block,
            fault: "a tree whose nodes are not one block",
        });
    }
    Ok(())
}

/// Read the node `oid` of `tree`: at its address for a physical tree, through the checkpoint's
/// mappings for an ephemeral one, through the map for a virtual one. A physical or ephemeral
/// node may be no newer than `max_xid`, what led to it.
fn read_node<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    oid: u64,
    is_root: bool,
    max_xid: u64,
) -> Result<(u64, Object), ReadError> {
    let kinds: &'static [u16] = if is_root {
        &[kind::BTREE_ROOT]
    } else {
        &[kind::BTREE_NODE]
    };
    let (address, storage) = match tree.children {
        Children::Physical => (oid, Storage::Physical),
        Children::Ephemeral => (container.ephemeral_address(oid)?, Storage::Ephemeral),
        Children::Virtual { .. } => {
            let (map, xid) = tree.map().expect("a virtual tree has a map");
            return container.read_virtual(&map, oid, xid, kinds, Some(tree.subtype));
        }
    };
    let object = container.read_object(
        address,
        &Expect {
            kinds,
            subtype: Some(tree.subtype),
            storage,
            oid,
            xid: Xid::AtMost(max_xid),
        },
    )?;
    Ok((address, object))
}

/// Hold a node's flags, layout and keys to what its place in the tree says, and say how many
/// bytes of its two areas no entry holds.
fn check_node(
    node: &Node<'_>,
    block: u64,
    order: Order,
    is_root: bool,
) -> Result<Unused, ReadError> {
    let header = node.header();
    if header.flags & !node_flags::UNDERSTOOD != 0 {
        return Err(ReadError::BadTree {
            block,
            fault: "a node carrying flags this crate does not read",
        });
    }
    if header.is_root() != is_root {
        return Err(ReadError::BadTree {
            block,
            fault: "a node whose root flag disagrees with its place",
        });
    }
    if header.is_leaf() != (header.level == 0) {
        return Err(ReadError::BadTree {
            block,
            fault: "a node whose leaf flag disagrees with its level",
        });
    }
    if node.is_empty() && !is_root {
        return Err(ReadError::BadTree {
            block,
            fault: "a node other than the root holding nothing",
        });
    }
    // An empty tree is a root leaf with no entries; an index node with none names no child to
    // descend to.
    if node.is_empty() && header.level > 0 {
        return Err(ReadError::BadTree {
            block,
            fault: "an index node holding nothing",
        });
    }
    let unused = node
        .check_layout()
        .map_err(|fault| ReadError::BadNode { block, fault })?;
    let mut previous: Option<&[u8]> = None;
    for i in 0..node.len() {
        let (key, value) = node
            .entry(i)
            .map_err(|fault| ReadError::BadNode { block, fault })?;
        // A key with no value is a ghost, which a tree flagged as allowing ghosts may hold; in
        // a free queue it is a free extent one block long (reference p. 130). A free queue's
        // tree is so flagged, observed on every queue macOS wrote; no other tree this crate
        // reads holds one.
        if value.is_none() && !(order == Order::FreeQueue && header.is_leaf()) {
            return Err(ReadError::BadTree {
                block,
                fault: "a key without a value",
            });
        }
        if let Some(previous) = previous
            && !in_order(order, previous, key, block)?
        {
            return Err(ReadError::BadTree {
                block,
                fault: "keys out of order",
            });
        }
        // Every key of two or more is parsed against its neighbour; a lone key against itself.
        if node.len() == 1 {
            in_order(order, key, key, block)?;
        }
        previous = Some(key);
    }
    Ok(unused)
}

/// Whether `a` may come before `b` in a tree of this order: before it, and never the same key,
/// so that no key repeats. A key that does not parse is a fault of the node at `block` that holds
/// it.
fn in_order(order: Order, a: &[u8], b: &[u8], block: u64) -> Result<bool, ReadError> {
    let ordered = match order {
        Order::ObjectMap => MapKey::read_from(a).and_then(|a| Ok(a < MapKey::read_from(b)?)),
        Order::FileSystem => {
            compare_records(a, b).map(|o| matches!(o, Some(Ordering::Less) | None))
        }
        Order::FreeQueue => {
            FreeQueueKey::read_from(a).and_then(|a| Ok(a < FreeQueueKey::read_from(b)?))
        }
        Order::Transaction => key_u64(a, 0).and_then(|a| Ok(a < key_u64(b, 0)?)),
    };
    ordered.map_err(|_| ReadError::BadTree {
        block,
        fault: "a key that does not parse",
    })
}

/// Two file-system keys compared as macOS orders them, or [`None`] for two keys that differ in a
/// part whose order this crate does not hold.
///
/// Keys sort by identifier and kind, then by the kind's own third part: a file extent's logical
/// offset and a sibling link's identifier as numbers, a directory entry's name hash and then its
/// name byte by byte, and an attribute's name byte by byte, each order observed on every tree of
/// every image macOS wrote (an attribute's name over 132 pairs whose byte order and length order
/// disagree, the resource fork before the compression header among them). Two entries of one
/// directory under one hash sort by their stored bytes on macOS 15, 26 and 27, on both kinds of
/// volume, whichever was created first: not by length, not case-folded and not decomposed, each
/// set against byte order by a pair where it disagrees. Two snapshot names and the keys of a kind
/// this crate does not read have no observed order, so those are only held to differ. A kind
/// with no third part — an inode, a stream's reference count, a physical extent, a snapshot's
/// metadata — has one record per identifier, and two of them are [`Ordering::Equal`].
pub(crate) fn compare_records(a: &[u8], b: &[u8]) -> Result<Option<Ordering>, ParseError> {
    let (ha, hb) = (KeyHeader::read_from(a)?, KeyHeader::read_from(b)?);
    let first = (ha.id, ha.kind).cmp(&(hb.id, hb.kind));
    if first != Ordering::Equal {
        return Ok(Some(first));
    }
    let distinct = |a: &[u8], b: &[u8]| (a == b).then_some(Ordering::Equal);
    Ok(match ha.kind {
        record_kind::FILE_EXTENT => {
            Some(FileExtentKey::logical(a)?.cmp(&FileExtentKey::logical(b)?))
        }
        record_kind::SIBLING_LINK => Some(key_u64(a, 8)?.cmp(&key_u64(b, 8)?)),
        record_kind::XATTR => Some(xattr_name(a)?.cmp(xattr_name(b)?)),
        record_kind::DIR_ENTRY => {
            let (ea, eb) = (EntryKey::read_from(a)?, EntryKey::read_from(b)?);
            Some(ea.hash.cmp(&eb.hash).then_with(|| ea.name.cmp(eb.name)))
        }
        record_kind::INODE
        | record_kind::DATA_STREAM_ID
        | record_kind::CRYPTO_STATE
        | record_kind::DIR_STATS
        | record_kind::SIBLING_MAP
        | record_kind::SNAPSHOT_META
        | record_kind::PHYSICAL_EXTENT => Some(Ordering::Equal),
        _ => distinct(&a[8..], &b[8..]),
    })
}

/// The logical offset a file extent's key carries.
struct FileExtentKey;

impl FileExtentKey {
    fn logical(key: &[u8]) -> Result<u64, ParseError> {
        key_u64(key, 8)
    }
}

/// Read the child entry `index` of `parent` leads to, and check it against the parent.
fn descend<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    parent: &Frame,
    index: u32,
    seen: &mut HashSet<u64>,
) -> Result<Frame, ReadError> {
    let node = parent.node()?;
    let (separator, value) = node.entry(index).map_err(|fault| ReadError::BadNode {
        block: parent.block,
        fault,
    })?;
    let value = value.ok_or(ReadError::BadTree {
        block: parent.block,
        fault: "an index entry without a child",
    })?;
    let child = child_oid(value)?;
    let bound = if index + 1 < node.len() {
        let (next, _) = node.entry(index + 1).map_err(|fault| ReadError::BadNode {
            block: parent.block,
            fault,
        })?;
        Some(next.to_vec())
    } else {
        parent.bound.clone()
    };
    let parent_xid = ObjectHeader::read_from(&parent.object)?.xid;
    let (block, object) = read_node(container, tree, child, false, parent_xid)?;
    if !seen.insert(block) {
        return Err(ReadError::BadTree {
            block,
            fault: "a node reached twice",
        });
    }
    let mut frame = Frame {
        object,
        block,
        sizes: parent.sizes,
        level: parent.level - 1,
        next: 0,
        bound,
        unused: Unused::default(),
    };
    let framed = frame.node()?;
    if framed.header().level != frame.level {
        return Err(ReadError::BadTree {
            block,
            fault: "a node not one level below its parent",
        });
    }
    let unused = check_node(&framed, block, tree.order, false)?;
    let (first, _) = framed
        .entry(0)
        .map_err(|fault| ReadError::BadNode { block, fault })?;
    if first != separator {
        return Err(ReadError::BadTree {
            block,
            fault: "a node whose first key is not its parent's key for it",
        });
    }
    if let Some(bound) = &frame.bound {
        let (last, _) = framed
            .entry(framed.len() - 1)
            .map_err(|fault| ReadError::BadNode { block, fault })?;
        if !in_order(tree.order, last, bound, block)? || last == bound.as_slice() {
            return Err(ReadError::BadTree {
                block,
                fault: "a node whose keys reach past its parent's key for the next node",
            });
        }
    }
    frame.unused = unused;
    Ok(frame)
}

/// The index of the last entry of `node` not after `target`, or [`None`] where every entry is.
fn last_not_after(
    node: &Node<'_>,
    block: u64,
    target: Target<'_>,
) -> Result<Option<u32>, ReadError> {
    let after = first_where(node, block, &|key| Ok(target(key)? == Ordering::Greater))?;
    Ok(after.checked_sub(1))
}

/// The index of the first entry of `node` for which `past` holds, or the node's length where it
/// holds for none: a search by halves, which is sound because every node a read reaches has
/// had its keys held to their order, and `past` is a target's comparison, false and then true
/// across that order.
fn first_where(
    node: &Node<'_>,
    block: u64,
    past: &dyn Fn(&[u8]) -> Result<bool, ParseError>,
) -> Result<u32, ReadError> {
    let (mut lo, mut hi) = (0u32, node.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (key, _) = node
            .entry(mid)
            .map_err(|fault| ReadError::BadNode { block, fault })?;
        if past(key)? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

/// The record with the greatest key not after `target`, or [`None`] where every record is
/// after it: the lookup an object map, an inode and a file's extents are read by.
///
/// A descent checks the nodes it enters, and steers by keys in the nodes above them that it
/// does not otherwise check, so two more steps hold those keys to what they lead to. A target
/// before every key of an index node still descends into its first child, which holds the
/// node's first key to the record it leads to. And an answer that is the last record of its
/// node, where the tree goes on past that node, is held to the record after it
/// ([`confirm_last`]).
///
/// # Errors
///
/// Whatever reading a node does, and the tree-shape refusals this module's documentation lists.
pub(crate) fn find_at_or_before<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    target: Target<'_>,
) -> Result<Option<Record>, ReadError> {
    let mut seen = HashSet::new();
    let mut frame = read_root(container, tree)?;
    seen.insert(frame.block);
    loop {
        let index = {
            let node = frame.node()?;
            let found = last_not_after(&node, frame.block, target)?;
            if frame.level > 0 {
                found.unwrap_or(0)
            } else {
                let Some(index) = found else {
                    return Ok(None);
                };
                let (key, value) = node.entry(index).map_err(|fault| ReadError::BadNode {
                    block: frame.block,
                    fault,
                })?;
                let answer = (key.to_vec(), value.unwrap_or_default().to_vec());
                if index + 1 == node.len() && frame.bound.is_some() {
                    confirm_last(container, tree, target)?;
                }
                return Ok(Some(answer));
            }
        };
        frame = descend(container, tree, &frame, index, &mut seen)?;
    }
}

/// Hold an answer to `target` that is the last record of its node, where the tree goes on past
/// that node, to the record after it.
///
/// A parent's key for the node after the one a descent entered, sitting above that node's own
/// first key, steers a search for a target between the two into the node before, and the
/// answer is that node's last record: a real record, verified, and not the last at or before
/// the target. In an object map that is an older version of an object, read as the one asked
/// for. Stepping on past the answer enters the node after through every check a descent
/// applies, which holds its first key to the key its parent records for it. Only an answer that
/// is the last record of its node can have been steered that way, so only that answer pays for
/// the step.
fn confirm_last<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    target: Target<'_>,
) -> Result<(), ReadError> {
    for_each_from(container, tree, target, usize::MAX, &mut |key, _| {
        Ok(target(key)? != Ordering::Greater)
    })?;
    Ok(())
}

/// Read every node of the tree, holding each to every check this module's documentation lists,
/// and visit no record: what makes every later lookup through the tree as sound as a walk of
/// it. Bounded by the nodes the tree has, since none is read twice, rather than by a walk
/// limit, since it gathers nothing.
///
/// # Errors
///
/// Whatever reading a node does, and the tree-shape refusals this module's documentation lists.
pub(crate) fn check_whole<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
) -> Result<(), ReadError> {
    walk(
        container,
        tree,
        &|_| Ok(Ordering::Greater),
        usize::MAX,
        &mut |_, _| Ok(true),
        &mut |_, _| Ok(()),
    )?;
    Ok(())
}

/// Visit every record at or after `target`, in key order, until `visit` answers `false`.
///
/// The descent goes straight to the first record not before the target rather than walking
/// from the tree's start, which is what makes "the records of this object" one descent and a
/// short walk. Answers the block of the leaf holding the record `visit` answered `false` to, or
/// [`None`] for a walk that ran to the tree's end.
///
/// # Errors
///
/// Whatever reading a node or `visit` does, the tree-shape refusals this module's
/// documentation lists, and [`ReadError::TooManyEntries`] once `visit` has taken more than
/// `limit` records.
pub(crate) fn for_each_from<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    target: Target<'_>,
    limit: usize,
    visit: &mut Visit<'_>,
) -> Result<Option<u64>, ReadError> {
    walk(container, tree, target, limit, visit, &mut |_, _| Ok(()))
}

/// What an iteration hands each node it reaches to: the node and the bytes of its two areas no
/// entry holds.
type Reached<'v> = dyn FnMut(&Frame, Unused) -> Result<(), ReadError> + 'v;

/// [`for_each_from`], handing each node to `reached` as it is reached, the root first.
fn walk<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    target: Target<'_>,
    limit: usize,
    visit: &mut Visit<'_>,
    reached: &mut Reached<'_>,
) -> Result<Option<u64>, ReadError> {
    let mut visited = 0usize;
    let mut seen = HashSet::new();
    let root = read_root(container, tree)?;
    seen.insert(root.block);
    reached(&root, root.unused)?;
    let mut stack = vec![root];
    // The first descent steers by the target; every later one takes each node from its start.
    let mut steering = true;
    while let Some(top) = stack.last() {
        if top.level == 0 {
            let node = top.node()?;
            let mut i = top.next;
            if steering {
                i = first_where(&node, top.block, &|key| Ok(target(key)? != Ordering::Less))?;
                steering = false;
            }
            while i < node.len() {
                let (key, value) = node.entry(i).map_err(|fault| ReadError::BadNode {
                    block: top.block,
                    fault,
                })?;
                if !visit(key, value.unwrap_or_default())? {
                    return Ok(Some(top.block));
                }
                // Counted once taken: the record that ends a range — the first one past a
                // directory, to a listing of it — is read to find the end and is not one the
                // range holds, so a range of exactly the cap is inside it.
                visited += 1;
                if visited > limit {
                    return Err(ReadError::TooManyEntries { limit });
                }
                i += 1;
            }
            stack.pop();
            continue;
        }
        let (index, len) = {
            let node = top.node()?;
            let index = if steering {
                last_not_after(&node, top.block, target)?.unwrap_or(0)
            } else {
                top.next
            };
            (index, node.len())
        };
        if index >= len {
            stack.pop();
            continue;
        }
        let child = descend(container, tree, top, index, &mut seen)?;
        reached(&child, child.unused)?;
        if let Some(top) = stack.last_mut() {
            top.next = index + 1;
        }
        stack.push(child);
    }
    Ok(None)
}

/// Visit every record of the tree, in key order, under the walk limit.
///
/// # Errors
///
/// As [`for_each_from`].
pub(crate) fn for_each<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    visit: &mut Visit<'_>,
) -> Result<(), ReadError> {
    let limit = container.limits().max_walk_entries;
    for_each_from(container, tree, &|_| Ok(Ordering::Greater), limit, visit)?;
    Ok(())
}

/// What a whole tree holds, counted by a walk of every node and every record of it, beside what
/// its root says it holds.
#[derive(Clone, Debug)]
pub(crate) struct Census {
    /// The root's information about the tree.
    pub(crate) info: TreeInfo,
    /// The root's block.
    pub(crate) root: u64,
    /// Nodes reached.
    pub(crate) nodes: u64,
    /// Records visited.
    pub(crate) records: u64,
    /// The longest key, and the longest value, of any record.
    pub(crate) longest: (usize, usize),
    /// Each node whose free lists do not total the bytes its areas leave unused: its block,
    /// the area, the total its list records, and the bytes unused.
    pub(crate) free_lists: Vec<(u64, &'static str, u16, usize)>,
}

/// Visit every record of the tree, in key order, under the walk limit, and count what it
/// holds.
///
/// # Errors
///
/// As [`for_each_from`].
pub(crate) fn census<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    visit: &mut Visit<'_>,
) -> Result<Census, ReadError> {
    census_nodes(container, tree, visit, &mut |_| {})
}

/// [`census`], handing `node` the block of each node reached, the root first.
///
/// # Errors
///
/// As [`for_each_from`].
pub(crate) fn census_nodes<R: Read + Seek>(
    container: &mut Container<R>,
    tree: &TreeRoot,
    visit: &mut Visit<'_>,
    node: &mut dyn FnMut(u64),
) -> Result<Census, ReadError> {
    let limit = container.limits().max_walk_entries;
    let mut census = Census {
        info: TreeInfo::default(),
        root: 0,
        nodes: 0,
        records: 0,
        longest: (0, 0),
        free_lists: Vec::new(),
    };
    let tally = std::cell::RefCell::new(&mut census);
    walk(
        container,
        tree,
        &|_| Ok(Ordering::Greater),
        limit,
        &mut |key, value| {
            let mut tally = tally.borrow_mut();
            tally.records += 1;
            tally.longest.0 = tally.longest.0.max(key.len());
            tally.longest.1 = tally.longest.1.max(value.len());
            drop(tally);
            visit(key, value)
        },
        &mut |frame, unused| {
            node(frame.block);
            let node = frame.node()?;
            let header = node.header();
            let mut tally = tally.borrow_mut();
            if let Some(info) = node.tree_info() {
                tally.info = info;
                tally.root = frame.block;
            }
            tally.nodes += 1;
            for (area, (_, said), held) in [
                ("key", header.key_free_list, unused.key),
                ("value", header.value_free_list, unused.value),
            ] {
                if usize::from(said) != held {
                    tally.free_lists.push((frame.block, area, said, held));
                }
            }
            Ok(())
        },
    )?;
    Ok(census)
}

/// A target that sorts before every key of object `id` and kind `kind`, and after every key of
/// any earlier object or kind: where the records of one object's kind begin.
pub(crate) fn records_of(id: u64, kind: u8) -> impl Fn(&[u8]) -> Result<Ordering, ParseError> {
    move |key: &[u8]| {
        let header = KeyHeader::read_from(key)?;
        Ok(match (header.id, header.kind).cmp(&(id, kind)) {
            Ordering::Equal => Ordering::Greater,
            other => other,
        })
    }
}

/// A target at file extent `logical` of stream `stream`: a key before it sorts
/// [`Ordering::Less`], the extent at exactly that offset [`Ordering::Equal`].
pub(crate) fn extent_at(
    stream: u64,
    logical: u64,
) -> impl Fn(&[u8]) -> Result<Ordering, ParseError> {
    move |key: &[u8]| {
        let header = KeyHeader::read_from(key)?;
        let first = (header.id, header.kind).cmp(&(stream, record_kind::FILE_EXTENT));
        if first != Ordering::Equal {
            return Ok(first);
        }
        Ok(FileExtentKey::logical(key)?.cmp(&logical))
    }
}

/// Recover the extent a file-extent record holds.
pub(crate) fn extent(key: &[u8], value: &[u8]) -> Result<FileExtent, ParseError> {
    FileExtent::read_from(key, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::put_u64;

    fn key(id: u64, kind: u8, tail: &[u8]) -> Vec<u8> {
        let mut k = vec![0u8; 8];
        KeyHeader { id, kind }.write_to(&mut k);
        k.extend_from_slice(tail);
        k
    }

    fn extent_key(id: u64, logical: u64) -> Vec<u8> {
        let mut tail = [0u8; 8];
        put_u64(&mut tail, 0, logical);
        key(id, record_kind::FILE_EXTENT, &tail)
    }

    /// A directory entry's key: `name` under `hash`.
    fn entry_key(dir: u64, hash: u32, name: &[u8]) -> Vec<u8> {
        let mut tail = ((hash << 10) | (name.len() as u32 + 1))
            .to_le_bytes()
            .to_vec();
        tail.extend_from_slice(name);
        tail.push(0);
        key(dir, record_kind::DIR_ENTRY, &tail)
    }

    /// A key of `kind` whose third part is `name` after its length, as an attribute's and a
    /// snapshot name's are.
    fn named_key(id: u64, kind: u8, name: &[u8]) -> Vec<u8> {
        let mut tail = (name.len() as u16 + 1).to_le_bytes().to_vec();
        tail.extend_from_slice(name);
        tail.push(0);
        key(id, kind, &tail)
    }

    #[test]
    fn records_order_by_identifier_kind_then_offset() {
        let a = key(16, record_kind::INODE, &[]);
        let b = entry_key(16, 7, b"zzz");
        let c = key(17, record_kind::INODE, &[]);
        assert_eq!(compare_records(&a, &b), Ok(Some(Ordering::Less)));
        assert_eq!(compare_records(&b, &c), Ok(Some(Ordering::Less)));
        assert_eq!(
            compare_records(&extent_key(5, 8192), &extent_key(5, 4096)),
            Ok(Some(Ordering::Greater))
        );
    }

    #[test]
    fn every_kind_holds_one_record_per_key_and_its_observed_order() {
        let fs = |a: &[u8], b: &[u8]| in_order(Order::FileSystem, a, b, 0).expect("keys parse");
        // Entries of one directory by hash, whatever their names.
        assert!(fs(&entry_key(2, 5, b"zz"), &entry_key(2, 6, b"aa")));
        assert!(!fs(&entry_key(2, 6, b"aa"), &entry_key(2, 5, b"zz")));
        // Under one hash, two names by their bytes, and never one name twice: a shorter name
        // greater in bytes after a longer one, and a capital before a small letter.
        assert!(fs(&entry_key(2, 5, b"a"), &entry_key(2, 5, b"b")));
        assert!(!fs(&entry_key(2, 5, b"b"), &entry_key(2, 5, b"a")));
        assert!(fs(&entry_key(2, 5, b"aaahapa"), &entry_key(2, 5, b"z610")));
        assert!(fs(&entry_key(2, 5, b"Bpk99"), &entry_key(2, 5, b"aaaav")));
        assert!(!fs(&entry_key(2, 5, b"a"), &entry_key(2, 5, b"a")));
        // An attribute's name byte by byte, where its length would say otherwise.
        let fork = named_key(16, record_kind::XATTR, b"com.apple.ResourceFork");
        let header = named_key(16, record_kind::XATTR, b"com.apple.decmpfs");
        assert!(fs(&fork, &header));
        assert!(!fs(&header, &fork));
        assert!(!fs(&header, &header));
        // A snapshot's name is held only to differ.
        let (one, two) = (
            named_key(7, record_kind::SNAPSHOT_NAME, b"one"),
            named_key(7, record_kind::SNAPSHOT_NAME, b"two"),
        );
        assert!(fs(&one, &two) && fs(&two, &one) && !fs(&one, &one));
        // Offsets and sibling identifiers as numbers, each once.
        assert!(!fs(&extent_key(5, 4096), &extent_key(5, 4096)));
        let sibling = |n: u64| key(16, record_kind::SIBLING_LINK, &n.to_le_bytes());
        assert!(fs(&sibling(255), &sibling(256)) && !fs(&sibling(256), &sibling(256)));
        // A kind with no third part: one record per identifier.
        for kind in [
            record_kind::INODE,
            record_kind::DATA_STREAM_ID,
            record_kind::DIR_STATS,
            record_kind::PHYSICAL_EXTENT,
            record_kind::SNAPSHOT_META,
        ] {
            assert!(!fs(&key(16, kind, &[]), &key(16, kind, &[])), "kind {kind}");
        }
        // A kind this crate does not read: differing keys pass, a repeat does not.
        assert!(fs(&key(16, 14, b"a"), &key(16, 14, b"b")));
        assert!(!fs(&key(16, 14, b"a"), &key(16, 14, b"a")));
    }

    #[test]
    fn a_target_for_one_objects_records_sorts_before_all_of_them() {
        let target = records_of(16, record_kind::DIR_ENTRY);
        assert_eq!(
            target(&key(16, record_kind::INODE, &[])),
            Ok(Ordering::Less)
        );
        assert_eq!(
            target(&key(16, record_kind::DIR_ENTRY, b"x")),
            Ok(Ordering::Greater)
        );
        assert_eq!(
            target(&key(17, record_kind::INODE, &[])),
            Ok(Ordering::Greater)
        );
    }

    #[test]
    fn an_extent_target_is_equal_to_its_own_offset_only() {
        let target = extent_at(9, 4096);
        assert_eq!(target(&extent_key(9, 0)), Ok(Ordering::Less));
        assert_eq!(target(&extent_key(9, 4096)), Ok(Ordering::Equal));
        assert_eq!(target(&extent_key(9, 8192)), Ok(Ordering::Greater));
        assert_eq!(target(&extent_key(10, 0)), Ok(Ordering::Greater));
    }
}
