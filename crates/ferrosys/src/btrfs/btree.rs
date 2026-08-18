//! The B-tree engine: one descent, one iteration, and the bounds that make both terminate on
//! an image that was crafted rather than formatted.
//!
//! Every tree in a btrfs is the same shape — internal nodes of `(key, child address)` pairs
//! over leaves of `(key, data)` items, sorted by the key tuple — so there is one engine and
//! every tree is read through it. What an item *means* is decided by whoever asked for it;
//! this module knows only that items have keys and that keys are ordered.
//!
//! # What bounds a walk
//!
//! An untrusted image can describe a tree that is not one, and each way of doing so has its
//! own guard:
//!
//! - **A count larger than the block holds.** Checked against the room the block has, in the
//!   units the block's own level says it holds — 25 bytes per item, 33 per child pointer.
//! - **An item whose data escapes its leaf.** Checked in two directions, because a leaf fills
//!   from both ends: the data must begin past the array describing it and end within the
//!   block. The arithmetic is 64-bit whatever the target's pointer width is, so a crafted
//!   offset and length behave the same on a 32-bit machine as on the one this is developed
//!   on.
//! - **A leaf whose data is not packed.** Every item's data abuts its neighbour's, so a leaf
//!   whose data has been moved with its offsets moved to match — every item still inside the
//!   block, every item pointing at bytes that are not its own — is refused. Nothing about a
//!   bound sees that one, and what a reader would otherwise hand back is one record's bytes
//!   under another record's key.
//! - **A child pointer that leads back up.** Every address a descent visits is remembered, and
//!   meeting one twice is a refusal rather than a loop.
//! - **A child at the wrong height.** A child must be exactly one level below its parent, so a
//!   descent has a decreasing measure independent of the visited set and terminates whatever
//!   the addresses say.
//! - **Keys out of order.** A tree that is not sorted is not a tree, and a search over one
//!   silently misses items rather than failing. Every key a walk visits is held against the
//!   one before it.
//! - **A tree larger than the caller will hold.** [`Limits::max_walk_entries`](crate::Limits::max_walk_entries) caps the items
//!   one walk visits.
//!
//! This module does I/O, through the volume it borrows.

use std::collections::BTreeSet;
use std::io::{Read, Seek};

use super::ondisk::DiskKey;
use super::volume::{ReadError, TreeBlock, TreeRoot, Volume};

/// One item, taken out of the tree that held it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Located {
    /// The key it was found under.
    pub key: DiskKey,
    /// Its bytes, which are as long as the item said and no longer.
    pub data: Vec<u8>,
}

/// How many blocks stand above `leaves`, level by level, in a tree of this fan-out.
///
/// The first entry is the level directly above the leaves and the last is always one — the
/// root. A tree whose leaves are one block has nothing above them, and the answer is empty:
/// that leaf *is* the root.
///
/// The arithmetic is the same whether it is being asked in advance as a bound
/// ([`geometry`](super::geometry)) or exactly of records already packed
/// ([`materialize`](super::materialize)), so it is asked in one place. `fan_out` is floored at
/// two, because a level whose blocks hold one child each never narrows and the stack would not
/// end — a floor rather than an error, since the only caller that could reach it derives the
/// fan-out from a node size the format has already accepted.
pub(super) fn levels_above(leaves: u64, fan_out: u64) -> Vec<u64> {
    let fan_out = fan_out.max(2);
    let mut levels = Vec::new();
    let mut width = leaves;
    while width > 1 {
        width = width.div_ceil(fan_out);
        levels.push(width);
    }
    levels
}

/// A handle on one tree of a volume, for searching or iterating it.
///
/// Borrowed from the [`Volume`] rather than owning anything, so a caller moves between trees
/// without reopening the filesystem — and so that every block either reads goes through the
/// one chunk map and the one checksum check.
pub struct Tree<'a, R> {
    volume: &'a mut Volume<R>,
    root: TreeRoot,
}

impl<'a, R: Read + Seek> Tree<'a, R> {
    /// A handle on the tree `root` names.
    pub(super) fn new(volume: &'a mut Volume<R>, root: TreeRoot) -> Self {
        Self { volume, root }
    }

    /// Which tree this is, and where it begins.
    #[must_use]
    pub fn root(&self) -> TreeRoot {
        self.root
    }

    /// Visit every item, in key order.
    ///
    /// The closure answers whether to keep going, so a caller looking for one thing stops
    /// where it finds it rather than reading the rest of the tree.
    ///
    /// # Errors
    ///
    /// Whatever reading a block does, and the tree-shape refusals this module's documentation
    /// lists.
    pub fn for_each_item<F>(&mut self, mut visit: F) -> Result<(), ReadError>
    where
        F: FnMut(&DiskKey, &[u8]) -> bool,
    {
        self.drive(DiskKey::MIN, &mut |_| true, &mut visit)
    }

    /// Visit every item at or after `from`, in key order.
    ///
    /// The descent goes straight to the first item at or after the key rather than walking the
    /// tree from its start, which is what makes "the entries of this directory" one descent
    /// instead of a scan.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn for_each_item_from<F>(&mut self, from: DiskKey, mut visit: F) -> Result<(), ReadError>
    where
        F: FnMut(&DiskKey, &[u8]) -> bool,
    {
        self.drive(from, &mut |_| true, &mut visit)
    }

    /// Visit every block of the tree, in the order a depth-first descent meets them.
    ///
    /// Every block is fetched through the chunk map and its checksum verified before the
    /// closure sees it, so a walk that completes is a statement that every block of the tree
    /// verified. The items are bounds-checked on the way past whether or not the closure looks
    /// at them, which is what makes this a verification pass rather than a header read.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn for_each_block<F>(&mut self, mut visit: F) -> Result<(), ReadError>
    where
        F: FnMut(&TreeBlock) -> bool,
    {
        self.drive(DiskKey::MIN, &mut visit, &mut |_, _| true)
    }

    /// The first item at or after `key`, or [`None`] where the tree holds none.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn find_first(&mut self, key: DiskKey) -> Result<Option<Located>, ReadError> {
        let mut found = None;
        self.for_each_item_from(key, |key, data| {
            found = Some(Located {
                key: *key,
                data: data.to_vec(),
            });
            false
        })?;
        Ok(found)
    }

    /// The item stored under exactly `key`, or [`None`] where there is none.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn find_exact(&mut self, key: DiskKey) -> Result<Option<Located>, ReadError> {
        Ok(self.find_first(key)?.filter(|found| found.key == key))
    }

    /// The last item at or before `key`, or [`None`] where every item in the tree is above it.
    ///
    /// The search a *range* needs, where [`find_first`](Self::find_first) is the one a *point*
    /// needs. A record keyed by where a run begins covers everything up to the next one, so the
    /// record covering a position is the last one at or before it — and asking for the first at
    /// or after would find the record covering the *next* position and skip the one wanted.
    /// That is how a file's extents are keyed, and reading from an offset in the middle of one
    /// is the case that makes the difference visible.
    ///
    /// One descent, so it costs the height of the tree rather than a scan.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn find_at_or_before(&mut self, key: DiskKey) -> Result<Option<Located>, ReadError> {
        let mut visited = BTreeSet::new();
        visited.insert(self.root.bytenr);
        let mut block = self.read_root()?;
        block.check_leaf_packing()?;
        loop {
            if block.header().is_leaf() {
                let at = partition(&block, &key, true)?;
                let Some(index) = at.checked_sub(1) else {
                    return Ok(None);
                };
                return Ok(Some(Located {
                    key: block.item(index)?.key,
                    data: block.item_data(index)?.to_vec(),
                }));
            }
            let index = start_index(&block, &key)?;
            block = self.child_of(&block, index, &mut visited)?;
        }
    }

    /// The child at `index` of `parent`, with every guard a descent applies to one.
    ///
    /// Three of them, and each catches something the others cannot: an address already visited
    /// is a tree that is not one, a child that is not exactly one level below its parent is a
    /// descent with no decreasing measure, and a leaf whose items are not packed hands back one
    /// record's bytes under another record's key. Every descent in this module goes through
    /// here so that none of the three can be forgotten in one of them.
    fn child_of(
        &mut self,
        parent: &TreeBlock,
        index: usize,
        visited: &mut BTreeSet<u64>,
    ) -> Result<TreeBlock, ReadError> {
        let level = parent.header().level;
        let child_at = parent.key_ptr(index)?.blockptr;
        if !visited.insert(child_at) {
            return Err(ReadError::TreeCycle { logical: child_at });
        }
        let child = self.volume.read_block(child_at)?;
        // A child exactly one level below its parent is what makes a descent terminate
        // whatever the addresses say, and it is a separate guard from the visited set rather
        // than a cheaper version of it: a crafted tree can point at a fresh block at every step
        // and still never reach a leaf.
        if u16::from(child.header().level) + 1 != u16::from(level) {
            return Err(ReadError::BadTreeLevel {
                logical: child_at,
                level: child.header().level,
                parent: level,
            });
        }
        child.check_leaf_packing()?;
        Ok(child)
    }

    /// How many items the tree holds, having read and verified every block on the way.
    ///
    /// # Errors
    ///
    /// As [`for_each_item`](Self::for_each_item).
    pub fn count_items(&mut self) -> Result<u64, ReadError> {
        let mut items = 0u64;
        self.for_each_item(|_, _| {
            items += 1;
            true
        })?;
        Ok(items)
    }

    /// The tree's top block, checked against what the root item said it would be.
    ///
    /// The level is recorded in two places — the root item and the block's own header — and
    /// holding them against each other is what catches a root item pointing at a block that is
    /// not the one it describes.
    fn read_root(&mut self) -> Result<TreeBlock, ReadError> {
        let block = self.volume.read_block(self.root.bytenr)?;
        if block.header().level != self.root.level {
            return Err(ReadError::BadTreeLevel {
                logical: self.root.bytenr,
                level: block.header().level,
                parent: self.root.level,
            });
        }
        Ok(block)
    }

    /// The one descent, which every public form above is a wrapper over.
    ///
    /// A depth-first walk with an explicit stack: each frame is a block and how far through it
    /// the walk has got. A block enters the stack at the entry `from` selects, so a walk from
    /// a key descends straight to it and a walk from [`DiskKey::MIN`] starts every block at
    /// zero.
    fn drive(
        &mut self,
        from: DiskKey,
        on_block: &mut dyn FnMut(&TreeBlock) -> bool,
        on_item: &mut dyn FnMut(&DiskKey, &[u8]) -> bool,
    ) -> Result<(), ReadError> {
        let limit = self.volume.walk_limit();
        let mut visited = BTreeSet::new();
        visited.insert(self.root.bytenr);

        let root = self.read_root()?;
        root.check_leaf_packing()?;
        if !on_block(&root) {
            return Ok(());
        }
        let start = start_index(&root, &from)?;
        let mut stack = vec![(root, start)];
        let mut visits = 0usize;
        let mut previous: Option<DiskKey> = None;

        while let Some(top) = stack.len().checked_sub(1) {
            let count = stack[top].0.count()?;
            let index = stack[top].1;
            if index >= count {
                stack.pop();
                continue;
            }
            stack[top].1 += 1;

            if stack[top].0.header().is_leaf() {
                visits += 1;
                if visits > limit {
                    return Err(ReadError::TooManyEntries {
                        objectid: self.root.objectid,
                        limit,
                    });
                }
                let key = stack[top].0.item(index)?.key;
                if previous.is_some_and(|last| key <= last) {
                    return Err(ReadError::BadTreeBlock {
                        logical: stack[top].0.header().bytenr,
                        fault: "an item's key is not above the one before it",
                    });
                }
                previous = Some(key);
                let data = stack[top].0.item_data(index)?;
                if !on_item(&key, data) {
                    return Ok(());
                }
                continue;
            }

            let child = {
                let (parent, _) = &stack[top];
                self.child_of(parent, index, &mut visited)?
            };
            if !on_block(&child) {
                return Ok(());
            }
            let start = start_index(&child, &from)?;
            stack.push((child, start));
        }
        Ok(())
    }
}

/// Where in `block` a walk from `from` begins.
///
/// For a **leaf** it is the first item at or after the key, so items below it are skipped. For
/// a **node** it is the last child whose key is at or below it, since that child's subtree is
/// where the key would be — and a node whose every key is above `from` starts at its first
/// child.
///
/// Computed for every block rather than only for the leftmost path, which is the same answer
/// and one fewer piece of state: a block entirely above `from` has no key at or below it, so
/// the binary search lands on zero on its own.
///
/// The search is bounded whatever the block holds, so a block whose keys are not sorted
/// answers with a wrong index and never with one outside the block. That a tree is sorted is
/// checked where a walk passes each key, which is where the check is free.
fn start_index(block: &TreeBlock, from: &DiskKey) -> Result<usize, ReadError> {
    if *from == DiskKey::MIN {
        return Ok(0);
    }
    // A leaf counts the entries strictly below the key, since that is the first one to visit.
    // A node counts those at or below it and steps back one, to the child whose subtree is
    // where the key would be — and a node whose every key is above `from` steps back from
    // zero, which is its first child.
    let leaf = block.header().is_leaf();
    let at = partition(block, from, !leaf)?;
    Ok(if leaf { at } else { at.saturating_sub(1) })
}

/// How many of `block`'s entries sort below `from`, counting one equal to it where `inclusive`.
///
/// The one binary search over a block, in the two readings a descent needs of it. It is bounded
/// whatever the block holds, so a block whose keys are not sorted answers with a wrong index
/// and never with one outside the block. That a tree is sorted is checked where a walk passes
/// each key, which is where the check is free.
fn partition(block: &TreeBlock, from: &DiskKey, inclusive: bool) -> Result<usize, ReadError> {
    let leaf = block.header().is_leaf();
    let (mut lo, mut hi) = (0usize, block.count()?);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let key = if leaf {
            block.item(mid)?.key
        } else {
            block.key_ptr(mid)?.key
        };
        let below = if inclusive { key <= *from } else { key < *from };
        if below { lo = mid + 1 } else { hi = mid }
    }
    Ok(lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::forge::{
        CHUNK_LENGTH, CHUNK_LOGICAL, FIRST_FREE_AT, Forge, NODE_SIZE, ROOT_TREE_AT, leaf, node,
        seal,
    };
    use crate::btrfs::ondisk::{Header, Item, ItemType, objectid};
    use crate::{Limits, OpenOptions};

    /// A key in the root tree's own namespace, so a forged tree sorts the way a real one does.
    fn key(n: u64) -> DiskKey {
        DiskKey::new(n, ItemType::ROOT_ITEM, 0)
    }

    /// A leaf of `n` items, each carrying its own number as a byte.
    fn items(range: std::ops::Range<u64>) -> Vec<(DiskKey, Vec<u8>)> {
        range.map(|n| (key(n), vec![n as u8; 8])).collect()
    }

    /// Every key a walk of `forge`'s root tree visits.
    fn walk(forge: &Forge) -> Result<Vec<DiskKey>, ReadError> {
        let mut volume = Volume::open(forge.source())?;
        let root = volume.root_tree();
        let mut keys = Vec::new();
        volume.tree(root).for_each_item(|k, _| {
            keys.push(*k);
            true
        })?;
        Ok(keys)
    }

    #[test]
    fn a_walk_visits_every_item_of_a_tree_in_key_order() {
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..40));
        assert_eq!(
            walk(&forge).expect("a well-formed tree"),
            items(1..40).iter().map(|(k, _)| *k).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_walk_descends_through_a_node_and_reaches_every_leaf_below_it() {
        // Two leaves under one node, which is the smallest tree that exercises a descent at
        // all — a one-leaf tree never reads a child pointer.
        let mut forge = Forge::new();
        let (left, right) = (FIRST_FREE_AT, FIRST_FREE_AT + NODE_SIZE as u64);
        forge
            .block(left, &leaf(left, objectid::ROOT_TREE, &items(1..10)))
            .block(right, &leaf(right, objectid::ROOT_TREE, &items(10..20)))
            .root_node(1, &[(key(1), left), (key(10), right)]);
        assert_eq!(walk(&forge).expect("a well-formed tree").len(), 19);
    }

    #[test]
    fn a_seek_lands_where_a_walk_of_the_whole_tree_would_have_reached() {
        // The property the descent's start index exists for, over a tree deep enough that the
        // choice of child matters. Every key present is probed, and so is one below and one
        // above each — the three places an off-by-one in the binary search would show.
        let mut forge = Forge::new();
        let (left, right) = (FIRST_FREE_AT, FIRST_FREE_AT + NODE_SIZE as u64);
        forge
            .block(left, &leaf(left, objectid::ROOT_TREE, &items(10..20)))
            .block(right, &leaf(right, objectid::ROOT_TREE, &items(20..30)))
            .root_node(1, &[(key(10), left), (key(20), right)]);

        let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
        let root = volume.root_tree();
        let all: Vec<DiskKey> = (10..30).map(key).collect();
        for probe in (5..35).map(key) {
            let expected: Vec<DiskKey> = all.iter().copied().filter(|k| *k >= probe).collect();
            let mut got = Vec::new();
            volume
                .tree(root)
                .for_each_item_from(probe, |k, _| {
                    got.push(*k);
                    true
                })
                .expect("a well-formed tree");
            assert_eq!(got, expected, "seeking to {probe:?}");
            assert_eq!(
                volume
                    .tree(root)
                    .find_first(probe)
                    .expect("search")
                    .map(|f| f.key),
                expected.first().copied()
            );
        }
        // And the exact form answers only where the key is genuinely there.
        assert!(
            volume
                .tree(root)
                .find_exact(key(15))
                .expect("search")
                .is_some()
        );
        assert!(
            volume
                .tree(root)
                .find_exact(key(35))
                .expect("search")
                .is_none()
        );
    }

    #[test]
    fn a_block_reached_twice_is_a_tree_that_is_not_one() {
        // Two child pointers naming one leaf. Not a cycle in the strict sense and the same
        // defect: a walk would visit its items twice, and the key-order check would then fire
        // for a reason that says nothing about what is wrong.
        let mut forge = Forge::new();
        let leaf_at = FIRST_FREE_AT;
        forge
            .block(leaf_at, &leaf(leaf_at, objectid::ROOT_TREE, &items(1..10)))
            .root_node(1, &[(key(1), leaf_at), (key(10), leaf_at)]);
        assert!(matches!(
            walk(&forge),
            Err(ReadError::TreeCycle { logical }) if logical == leaf_at
        ));

        // And a node naming itself, which the same guard catches before the block is read at
        // all — the root's own address is in the visited set from the start.
        let mut forge = Forge::new();
        forge.root_node(1, &[(key(1), ROOT_TREE_AT)]);
        assert!(matches!(
            walk(&forge),
            Err(ReadError::TreeCycle { logical }) if logical == ROOT_TREE_AT
        ));
    }

    #[test]
    fn a_child_that_is_not_one_level_below_its_parent_is_refused() {
        // The guard that makes a descent terminate whatever the addresses say: a crafted tree
        // can name a fresh block at every step, so the visited set alone is not a bound.
        for child_level in [0u8, 2, 3] {
            if child_level == 1 {
                continue;
            }
            let mut forge = Forge::new();
            let child = FIRST_FREE_AT;
            let block = if child_level == 0 {
                leaf(child, objectid::ROOT_TREE, &items(1..4))
            } else {
                node(
                    child,
                    objectid::ROOT_TREE,
                    child_level,
                    &[(key(1), FIRST_FREE_AT + NODE_SIZE as u64)],
                )
            };
            forge.block(child, &block).root_node(2, &[(key(1), child)]);
            match walk(&forge) {
                Err(ReadError::BadTreeLevel { level, parent, .. }) => {
                    assert_eq!((level, parent), (child_level, 2));
                }
                other => panic!("a level-{child_level} child under a level-2 node: {other:?}"),
            }
        }
    }

    #[test]
    fn a_root_block_that_is_not_the_height_its_root_item_claimed_is_refused() {
        // The level is recorded twice — in the root item and in the block's own header — and
        // holding them against each other is what catches a root item pointing at a block
        // that is not the one it describes.
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..4));
        forge.amend_superblock(0, |sb| sb.root_level = 1);
        assert!(matches!(
            walk(&forge),
            Err(ReadError::BadTreeLevel {
                level: 0,
                parent: 1,
                ..
            })
        ));
    }

    #[test]
    fn a_header_that_does_not_describe_the_block_it_sits_in_is_refused() {
        // Three claims a header makes about its own block, each checked against something
        // outside the header. None is a fault a checksum can catch: every one of these fields
        // is inside what the checksum covers, so a block written correctly somewhere else, or
        // for another filesystem, verifies perfectly.
        //
        // They are one gate because the damage differs and nothing else does — the crafted
        // block, the walk, and the shape of the refusal are the same three lines in each.
        /// What a row damages about a header, and the word its refusal must carry.
        type Fault = (&'static str, Box<dyn Fn(&mut Header)>);

        let faults: [Fault; 3] = [
            (
                "room",
                Box::new(|header: &mut Header| {
                    header.nritems = (NODE_SIZE / Item::SIZE + 1) as u32;
                }),
            ),
            (
                "logical address",
                Box::new(|header: &mut Header| header.bytenr = CHUNK_LOGICAL),
            ),
            (
                "another filesystem",
                Box::new(|header: &mut Header| header.fsid = [0x99; 16]),
            ),
        ];
        for (expected, damage) in faults {
            let mut forge = Forge::new();
            forge.root_leaf(&items(1..4));
            forge.amend(ROOT_TREE_AT, |block| {
                let mut header = Header::read_from(block).expect("a header");
                damage(&mut header);
                header.write_to(block);
            });
            match walk(&forge) {
                Err(ReadError::BadTreeBlock { fault, .. }) => {
                    assert!(fault.contains(expected), "{fault}");
                }
                other => panic!("a header claiming the wrong {expected}: {other:?}"),
            }
        }
    }

    #[test]
    fn an_item_whose_data_escapes_its_leaf_is_refused_in_both_directions() {
        // Asked of the block directly rather than through a walk, and deliberately: a walk
        // checks the leaf's packing before it reads an item, and packing already implies an
        // item cannot end past the block. What it does not imply is that the data stays out
        // of the array describing it — and a caller holding a block from `read_block` has had
        // neither check made for it, which is the path these two guards are on.
        /// What a row damages about an item, and the word its refusal must carry.
        type Escape = (&'static str, Box<dyn Fn(&mut Item)>);

        let cases: [Escape; 3] = [
            ("array", Box::new(|item: &mut Item| item.offset = 0)),
            (
                "block",
                Box::new(|item: &mut Item| item.size = NODE_SIZE as u32),
            ),
            (
                "block",
                Box::new(|item: &mut Item| {
                    item.offset = u32::MAX;
                    item.size = u32::MAX;
                }),
            ),
        ];
        for (expected, damage) in cases {
            let mut forge = Forge::new();
            forge.root_leaf(&items(1..4));
            forge.amend(ROOT_TREE_AT, |block| {
                let mut item = Item::read_from(&block[Header::SIZE..]).expect("an item");
                damage(&mut item);
                item.write_to(&mut block[Header::SIZE..]);
            });
            let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
            let block = volume.read_block(ROOT_TREE_AT).expect("the block verifies");
            match block.item_data(0) {
                Err(ReadError::BadItem {
                    fault, index: 0, ..
                }) => {
                    assert!(fault.contains(expected), "{fault}");
                }
                other => panic!("an item escaping its leaf toward the {expected}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_leaf_whose_data_has_been_moved_with_its_offsets_is_refused() {
        // Every item stays inside the block and every item points at bytes that are not its
        // own, so no bound notices — what does is the format's own packing rule, that one
        // item's data ends where the next one's begins. The baseline's corruptor has a switch
        // for exactly this shape, and it is what found the check missing.
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..6));
        forge.amend(ROOT_TREE_AT, |block| {
            let at = Header::SIZE + 2 * Item::SIZE;
            let mut third = Item::read_from(&block[at..]).expect("an item");
            third.offset -= 16;
            third.write_to(&mut block[at..]);
        });
        assert!(matches!(
            walk(&forge),
            Err(ReadError::BadItem { fault, index: 2, .. })
                if fault.contains("does not end where the item before it begins")
        ));

        // And the first item is bounded by the end of the block rather than by a neighbour,
        // which is the case a rule written only about neighbours would miss.
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..6));
        forge.amend(ROOT_TREE_AT, |block| {
            let mut first = Item::read_from(&block[Header::SIZE..]).expect("an item");
            first.size -= 1;
            first.write_to(&mut block[Header::SIZE..]);
        });
        assert!(matches!(
            walk(&forge),
            Err(ReadError::BadItem { index: 0, .. })
        ));
    }

    #[test]
    fn a_tree_whose_keys_are_not_in_order_is_refused_rather_than_searched_wrongly() {
        // A binary search over unsorted keys silently misses items instead of failing, so a
        // tree that is not sorted is refused where a walk passes each key — which is the one
        // place the check is free.
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..6));
        forge.amend(ROOT_TREE_AT, |block| {
            let mut second = Item::read_from(&block[Header::SIZE + Item::SIZE..]).expect("an item");
            second.key = key(0);
            second.write_to(&mut block[Header::SIZE + Item::SIZE..]);
        });
        assert!(matches!(
            walk(&forge),
            Err(ReadError::BadTreeBlock { fault, .. }) if fault.contains("above the one before")
        ));

        // Two items under one key is the same defect at its boundary: a tree's keys are
        // unique, and a search that found one of them would never see the other.
        let mut forge = Forge::new();
        forge.root_leaf(&[(key(1), vec![1; 8]), (key(1), vec![2; 8])]);
        assert!(matches!(walk(&forge), Err(ReadError::BadTreeBlock { .. })));
    }

    #[test]
    fn a_block_whose_checksum_no_longer_covers_it_is_refused_wherever_it_sits() {
        for at in [ROOT_TREE_AT, CHUNK_LOGICAL] {
            let mut forge = Forge::new();
            forge.root_leaf(&items(1..4));
            forge.break_checksum(at);
            let opened = Volume::open(forge.source()).and_then(|mut v| {
                let root = v.root_tree();
                v.tree(root).count_items()
            });
            assert!(
                matches!(
                    &opened,
                    Err(ReadError::BadChecksum {
                        object: "tree block",
                        ..
                    })
                ),
                "a damaged block at {at}: {opened:?}"
            );
        }
    }

    #[test]
    fn a_block_at_an_address_no_chunk_maps_is_refused_rather_than_read_from_nowhere() {
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..4));
        // Past the end of the one chunk, which is the address space this filesystem has.
        forge.amend_superblock(0, |sb| sb.root = CHUNK_LOGICAL + CHUNK_LENGTH);
        assert!(matches!(
            walk(&forge),
            Err(ReadError::UnmappedLogical { .. })
        ));
    }

    #[test]
    fn a_walk_stops_at_the_cap_the_caller_set_rather_than_gathering_past_it() {
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..40));
        let options = OpenOptions::new().limits(Limits::new().max_walk_entries(10));
        let mut volume =
            Volume::open_with(forge.source(), options).expect("a well-formed filesystem");
        let root = volume.root_tree();
        assert!(matches!(
            volume.tree(root).count_items(),
            Err(ReadError::TooManyEntries { limit: 10, .. })
        ));
        // Exactly at the cap is inside it: a bound that refused the last entry it allowed
        // would be off by one in the direction that refuses healthy filesystems.
        let options = OpenOptions::new().limits(Limits::new().max_walk_entries(39));
        let mut volume =
            Volume::open_with(forge.source(), options).expect("a well-formed filesystem");
        let root = volume.root_tree();
        assert_eq!(volume.tree(root).count_items().expect("within the cap"), 39);
    }

    #[test]
    fn a_visit_that_says_to_stop_stops_where_it_said() {
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..40));
        let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
        let root = volume.root_tree();
        let mut seen = 0;
        volume
            .tree(root)
            .for_each_item(|_, _| {
                seen += 1;
                seen < 3
            })
            .expect("a well-formed tree");
        assert_eq!(seen, 3);
    }

    #[test]
    fn every_block_of_a_tree_is_offered_to_a_block_walk_including_its_nodes() {
        let mut forge = Forge::new();
        let (left, right) = (FIRST_FREE_AT, FIRST_FREE_AT + NODE_SIZE as u64);
        forge
            .block(left, &leaf(left, objectid::ROOT_TREE, &items(1..10)))
            .block(right, &leaf(right, objectid::ROOT_TREE, &items(10..20)))
            .root_node(1, &[(key(1), left), (key(10), right)]);
        let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
        let root = volume.root_tree();
        let mut blocks = Vec::new();
        volume
            .tree(root)
            .for_each_block(|block| {
                blocks.push((block.header().bytenr, block.header().level));
                true
            })
            .expect("a well-formed tree");
        assert_eq!(blocks, vec![(ROOT_TREE_AT, 1), (left, 0), (right, 0)]);
    }

    #[test]
    fn a_forged_filesystem_is_one_the_reader_accepts_before_it_is_damaged() {
        // What makes every gate above a negative control rather than a test of a broken
        // fixture: the same filesystem, undamaged, opens and reads.
        let mut forge = Forge::new();
        forge.root_leaf(&items(1..40));
        let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
        assert_eq!(volume.superblock().nodesize as usize, NODE_SIZE);
        assert_eq!(volume.chunk_map().len(), 1);
        let root = volume.root_tree();
        assert_eq!(
            volume.tree(root).count_items().expect("a well-formed tree"),
            39
        );
        // And the seal the forge applies is the format's own recipe, not a second spelling of
        // it: a block resealed by hand verifies exactly as one the forge wrote does.
        let mut block = leaf(FIRST_FREE_AT, objectid::ROOT_TREE, &items(1..4));
        block[Header::SIZE] ^= 0xff;
        seal(&mut block);
        forge.block(FIRST_FREE_AT, &block);
        let mut volume = Volume::open(forge.source()).expect("a well-formed filesystem");
        assert!(volume.read_block(FIRST_FREE_AT).is_ok());
    }
}
