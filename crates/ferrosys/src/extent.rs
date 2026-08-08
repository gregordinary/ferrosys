//! The extent tree: mapping a file's logical blocks to physical runs.
//!
//! This module is pure — it turns allocated block ranges into extent leaves and
//! assembles them into a tree, with no I/O. An extent tree is a header followed by
//! entries: leaves at depth zero, index entries above. The root lives inline in the
//! inode's sixty-byte block area, where four entries fit; when the leaves outgrow it
//! the tree spills into external node blocks and the root becomes an index node.
//!
//! A run longer than a single leaf can address ([`MAX_EXTENT_LEN`] blocks) is split
//! across leaves; physically and logically adjacent runs coalesce.
//!
//! Building a tree is two steps, because the external nodes occupy blocks the caller
//! must allocate. [`plan_tree`] reports the shape — its depth and how many node
//! blocks it needs — and [`build_tree`] fills that shape in once the caller has the
//! blocks. Under `metadata_csum` each external node reserves a four-byte checksum at
//! [`tail_offset`]; the entry capacity is unchanged, because the tail occupies the
//! bytes left over after the last entry that fits.

use crate::geometry::BlockRange;
use crate::ondisk::{EXTENT_ENTRY_SIZE, ExtentHeader, ExtentIdx, ExtentLeaf, ParseError};

/// Largest block run a single extent leaf can map.
pub const MAX_EXTENT_LEN: u32 = 32768;

/// Deepest extent tree ext4 defines. A root at this depth indexes nodes one level
/// shallower, down to the leaves at depth zero.
pub const MAX_EXTENT_DEPTH: u16 = 5;

/// Logical blocks an extent tree can address: `ee_block` is a 32-bit field, so a
/// file spans at most this many blocks.
const MAX_LOGICAL_BLOCKS: u64 = 1 << 32;

/// A failure building or serializing an extent tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtentError {
    /// More entries than the target node holds.
    #[error("{entries} extent entries exceed the {capacity} that fit in the node")]
    #[non_exhaustive]
    TooManyEntries {
        /// Entries the node was asked to hold.
        entries: usize,
        /// Entries the node can hold.
        capacity: usize,
    },
    /// The node buffer is too small to hold an extent header.
    #[error("extent node buffer of {bytes} bytes cannot hold a header")]
    #[non_exhaustive]
    NodeTooSmall {
        /// Bytes the buffer holds.
        bytes: usize,
    },
    /// The leaves need a tree deeper than ext4 defines.
    #[error("extent tree of depth {depth} exceeds the maximum depth {MAX_EXTENT_DEPTH}")]
    #[non_exhaustive]
    TooDeep {
        /// Depth the leaves would need.
        depth: u16,
    },
    /// The file spans more logical blocks than a 32-bit `ee_block` addresses.
    #[error("file of {blocks} blocks exceeds the {MAX_LOGICAL_BLOCKS} an extent tree addresses")]
    #[non_exhaustive]
    FileTooLarge {
        /// Logical blocks the file needs.
        blocks: u64,
    },
    /// The supplied node blocks do not match the planned shape.
    #[error("extent tree needs {need} node blocks but {got} were supplied")]
    #[non_exhaustive]
    NodeBlockCount {
        /// Node blocks the shape requires.
        need: usize,
        /// Node blocks supplied.
        got: usize,
    },
    /// A leaf holds a run the on-disk `ee_len` field does not encode. The runs this
    /// module builds are always encodable, so this reaches a caller only for leaves it
    /// assembled itself.
    #[error(transparent)]
    Leaf(#[from] ParseError),
}

/// The parsed contents of one extent-tree node: its leaves at depth zero, or its
/// index entries above.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExtentNode {
    /// A depth-zero node: the leaves that map logical runs to physical runs.
    Leaves(Vec<ExtentLeaf>),
    /// A node above depth zero: index entries pointing at deeper nodes.
    Index {
        /// Depth of this node.
        depth: u16,
        /// Index entries.
        entries: Vec<ExtentIdx>,
    },
}

impl ExtentNode {
    /// Depth of this node: zero for leaves.
    #[must_use]
    pub fn depth(&self) -> u16 {
        match self {
            Self::Leaves(_) => 0,
            Self::Index { depth, .. } => *depth,
        }
    }

    /// Number of entries the node holds.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Leaves(leaves) => leaves.len(),
            Self::Index { entries, .. } => entries.len(),
        }
    }

    /// Whether the node holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An external node and the physical block it occupies.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtentNodeBlock {
    /// Physical block holding this node.
    pub block: u64,
    /// The node's contents.
    pub node: ExtentNode,
}

/// A complete extent tree: the root that lives inline in the inode, and the external
/// nodes it points at.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ExtentTree {
    /// The inode's inline root. Holds the leaves directly for a depth-zero tree.
    pub root: ExtentNode,
    /// External node blocks, ordered from the leaf level upward. Empty for a
    /// depth-zero tree.
    pub nodes: Vec<ExtentNodeBlock>,
}

/// The shape of the tree a set of leaves needs.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TreeShape {
    /// Depth of the root: zero when the leaves fit inline in the inode.
    pub depth: u16,
    /// Node count at each level, from the leaf level upward. Empty at depth zero.
    pub level_nodes: Vec<usize>,
    /// Total external node blocks the tree occupies.
    pub node_blocks: usize,
}

/// The number of entries that fit in a node of `node_bytes` bytes: one 12-byte
/// header plus 12-byte entries.
///
/// `node_bytes` is a size the caller supplies, and a node smaller than its own header
/// holds no entries — so anything below [`EXTENT_ENTRY_SIZE`] is zero rather than a
/// length that overruns the node it describes.
#[must_use]
pub const fn node_capacity(node_bytes: usize) -> usize {
    node_bytes.saturating_sub(EXTENT_ENTRY_SIZE) / EXTENT_ENTRY_SIZE
}

/// Byte offset of an external node's checksum tail: past the header and every entry
/// the node can hold. The bytes a full node leaves over are exactly where ext4 keeps
/// the tail, so reserving it costs no entry capacity.
///
/// A node with no room for entries has none for a tail either, and the offset is then
/// past the node's own end — which the write it is handed to rejects, as it does any
/// offset a buffer does not reach.
#[must_use]
pub const fn tail_offset(node_bytes: usize) -> usize {
    EXTENT_ENTRY_SIZE * (node_capacity(node_bytes) + 1)
}

/// Turn a file's allocated ranges into extent leaves.
///
/// The ranges are the file's blocks in logical order: the first range maps logical
/// block 0 onward. Runs longer than [`MAX_EXTENT_LEN`] split across leaves;
/// logically and physically adjacent runs coalesce into one.
///
/// # Errors
///
/// [`ExtentError::FileTooLarge`] if the ranges span more logical blocks than a
/// 32-bit logical block number addresses.
pub fn build_leaves(ranges: &[BlockRange]) -> Result<Vec<ExtentLeaf>, ExtentError> {
    let total: u64 = ranges.iter().map(|r| r.len).sum();
    if total > MAX_LOGICAL_BLOCKS {
        return Err(ExtentError::FileTooLarge { blocks: total });
    }

    let mut leaves: Vec<ExtentLeaf> = Vec::new();
    let mut logical: u64 = 0;
    for range in ranges {
        let mut phys = range.start;
        let mut left = range.len;
        while left > 0 {
            let take = left.min(u64::from(MAX_EXTENT_LEN)) as u32;
            // Coalesce with the previous leaf when the runs abut on both axes and
            // the result still fits in one leaf.
            if let Some(last) = leaves.last_mut()
                && last.initialized
                && u64::from(last.block) + u64::from(last.len) == logical
                && last.start + u64::from(last.len) == phys
                && u32::from(last.len) + take <= MAX_EXTENT_LEN
            {
                last.len += take as u16;
            } else {
                leaves.push(ExtentLeaf {
                    block: logical as u32,
                    len: take as u16,
                    start: phys,
                    initialized: true,
                });
            }
            logical += u64::from(take);
            phys += u64::from(take);
            left -= u64::from(take);
        }
    }
    Ok(leaves)
}

/// Work out the tree `leaves` leaves need: `inline_capacity` entries fit in the
/// inode's root, `node_capacity` in each external node.
///
/// A tree that fits inline has depth zero and needs no blocks. Otherwise the leaves
/// fill leaf-level node blocks, those blocks are indexed by a level above, and so on
/// until one level fits in the root.
///
/// # Errors
///
/// [`ExtentError::TooManyEntries`] if a node could hold fewer than two entries, so
/// no tree can converge; [`ExtentError::TooDeep`] if the leaves need a tree deeper
/// than [`MAX_EXTENT_DEPTH`].
pub fn plan_tree(
    leaves: usize,
    inline_capacity: usize,
    node_capacity: usize,
) -> Result<TreeShape, ExtentError> {
    if leaves <= inline_capacity {
        return Ok(TreeShape {
            depth: 0,
            level_nodes: Vec::new(),
            node_blocks: 0,
        });
    }
    // A node that holds one entry never reduces the level's width, so the tree
    // would grow without bound.
    if node_capacity < 2 || inline_capacity < 1 {
        return Err(ExtentError::TooManyEntries {
            entries: leaves,
            capacity: inline_capacity,
        });
    }

    let mut level_nodes = Vec::new();
    let mut width = leaves.div_ceil(node_capacity);
    level_nodes.push(width);
    while width > inline_capacity {
        width = width.div_ceil(node_capacity);
        level_nodes.push(width);
    }

    let depth = level_nodes.len() as u16;
    if depth > MAX_EXTENT_DEPTH {
        return Err(ExtentError::TooDeep { depth });
    }
    Ok(TreeShape {
        depth,
        node_blocks: level_nodes.iter().sum(),
        level_nodes,
    })
}

/// Assemble `leaves` into a tree rooted in the inode, spilling into `node_blocks` —
/// the physical blocks [`plan_tree`] asked for, consumed from the leaf level upward.
///
/// # Errors
///
/// [`ExtentError::NodeBlockCount`] if `node_blocks` does not match the planned
/// shape; the errors of [`plan_tree`].
pub fn build_tree(
    leaves: &[ExtentLeaf],
    inline_capacity: usize,
    node_capacity: usize,
    node_blocks: &[u64],
) -> Result<ExtentTree, ExtentError> {
    let shape = plan_tree(leaves.len(), inline_capacity, node_capacity)?;
    if node_blocks.len() != shape.node_blocks {
        return Err(ExtentError::NodeBlockCount {
            need: shape.node_blocks,
            got: node_blocks.len(),
        });
    }
    if shape.depth == 0 {
        return Ok(ExtentTree {
            root: ExtentNode::Leaves(leaves.to_vec()),
            nodes: Vec::new(),
        });
    }

    let mut nodes: Vec<ExtentNodeBlock> = Vec::with_capacity(shape.node_blocks);
    let mut taken = 0usize;

    // The leaf level: each node block holds a run of leaves, and the level above
    // indexes it by the first logical block that run covers.
    let mut children: Vec<ExtentIdx> = Vec::with_capacity(shape.level_nodes[0]);
    for chunk in leaves.chunks(node_capacity) {
        let block = node_blocks[taken];
        taken += 1;
        children.push(ExtentIdx {
            block: chunk[0].block,
            leaf: block,
        });
        nodes.push(ExtentNodeBlock {
            block,
            node: ExtentNode::Leaves(chunk.to_vec()),
        });
    }

    // Interior levels, each indexing the one below it.
    for depth in 1..shape.depth {
        let mut parents: Vec<ExtentIdx> = Vec::with_capacity(shape.level_nodes[depth as usize]);
        for chunk in children.chunks(node_capacity) {
            let block = node_blocks[taken];
            taken += 1;
            parents.push(ExtentIdx {
                block: chunk[0].block,
                leaf: block,
            });
            nodes.push(ExtentNodeBlock {
                block,
                node: ExtentNode::Index {
                    depth,
                    entries: chunk.to_vec(),
                },
            });
        }
        children = parents;
    }

    Ok(ExtentTree {
        root: ExtentNode::Index {
            depth: shape.depth,
            entries: children,
        },
        nodes,
    })
}

/// Serialize `node` into the front of `buf` — the inode's inline block area or an
/// external node block — declaring a capacity of `eh_max` entries. `buf` beyond the
/// header and entries is left as the caller set it, which is where an external
/// node's checksum tail sits.
///
/// # Errors
///
/// [`ExtentError::NodeTooSmall`] if `buf` cannot hold a header;
/// [`ExtentError::TooManyEntries`] if the node's entries exceed `eh_max` or overrun
/// `buf`.
pub fn write_node(node: &ExtentNode, eh_max: usize, buf: &mut [u8]) -> Result<(), ExtentError> {
    if buf.len() < EXTENT_ENTRY_SIZE {
        return Err(ExtentError::NodeTooSmall { bytes: buf.len() });
    }
    let entries = node.len();
    if entries > eh_max || EXTENT_ENTRY_SIZE * (eh_max + 1) > buf.len() {
        return Err(ExtentError::TooManyEntries {
            entries,
            capacity: eh_max.min(node_capacity(buf.len())),
        });
    }
    let header = ExtentHeader {
        entries: entries as u16,
        max: eh_max as u16,
        depth: node.depth(),
        generation: 0,
    };
    buf[0..EXTENT_ENTRY_SIZE].copy_from_slice(&header.to_bytes());
    let mut put = |i: usize, bytes: [u8; EXTENT_ENTRY_SIZE]| {
        let off = EXTENT_ENTRY_SIZE * (i + 1);
        buf[off..off + EXTENT_ENTRY_SIZE].copy_from_slice(&bytes);
    };
    match node {
        ExtentNode::Leaves(leaves) => {
            for (i, leaf) in leaves.iter().enumerate() {
                put(i, leaf.to_bytes()?);
            }
        }
        ExtentNode::Index { entries, .. } => {
            for (i, idx) in entries.iter().enumerate() {
                put(i, idx.to_bytes());
            }
        }
    }
    Ok(())
}

/// Parse one extent-tree node from the front of `buf`, returning its leaves (depth
/// zero) or its index entries (above). The header's entry count bounds the parse,
/// so trailing bytes — an inode's unused inline area, or a node's checksum tail —
/// are ignored.
///
/// The header's counts must agree with each other and with the node they describe.
/// `eh_max` is the capacity the node was built with, so it holds at least one entry
/// and no more than [`node_capacity`] of `buf`; `eh_entries` is what that capacity
/// actually holds. Either relation broken is the corrupt header the kernel and
/// `e2fsck` both refuse to walk, and it is refused here for the same reason: the
/// entries beyond it are not a mapping any ext4 driver would follow.
///
/// # Errors
///
/// [`crate::ondisk::ParseError`] if the node is shorter than a header, its magic is
/// wrong, or its counts disagree with each other or with `buf`.
pub fn parse_node(buf: &[u8]) -> Result<ExtentNode, crate::ondisk::ParseError> {
    use crate::ondisk::ParseError;
    if buf.len() < EXTENT_ENTRY_SIZE {
        return Err(ParseError::TooShort {
            structure: "ExtentHeader",
            need: EXTENT_ENTRY_SIZE,
            got: buf.len(),
        });
    }
    let header_bytes: &[u8; EXTENT_ENTRY_SIZE] = buf[0..EXTENT_ENTRY_SIZE]
        .try_into()
        .expect("header slice is exactly EXTENT_ENTRY_SIZE bytes");
    let header = ExtentHeader::from_bytes(header_bytes)?;
    let capacity = node_capacity(buf.len());
    let max = header.max as usize;
    let entries = header.entries as usize;
    // A node declaring room for nothing has no entries to hold, and one declaring room
    // past its own capacity places entries in bytes it does not reach.
    if max == 0 || max > capacity {
        return Err(ParseError::InvalidField {
            structure: "ExtentHeader",
            field: "eh_max",
            value: u64::from(header.max),
        });
    }
    // Bounding the entries by the declared capacity bounds them by the node too, since
    // that capacity is the node's own.
    if entries > max {
        return Err(ParseError::InvalidField {
            structure: "ExtentHeader",
            field: "eh_entries",
            value: u64::from(header.entries),
        });
    }
    let entry = |i: usize| -> [u8; EXTENT_ENTRY_SIZE] {
        let off = EXTENT_ENTRY_SIZE * (i + 1);
        buf[off..off + EXTENT_ENTRY_SIZE]
            .try_into()
            .expect("entry slice is exactly EXTENT_ENTRY_SIZE bytes")
    };
    if header.depth == 0 {
        let leaves = (0..entries)
            .map(|i| ExtentLeaf::from_bytes(&entry(i)))
            .collect();
        Ok(ExtentNode::Leaves(leaves))
    } else {
        let idxs = (0..entries)
            .map(|i| ExtentIdx::from_bytes(&entry(i)))
            .collect();
        Ok(ExtentNode::Index {
            depth: header.depth,
            entries: idxs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::Inode;

    /// Entries in the inode's sixty-byte inline area.
    const INLINE: usize = node_capacity(Inode::BLOCK_BYTES);
    /// Entries in a 4096-byte external node.
    const NODE: usize = node_capacity(4096);

    fn leaves_of(n: usize) -> Vec<ExtentLeaf> {
        // Physically disjoint single-block runs, so nothing coalesces.
        (0..n)
            .map(|i| ExtentLeaf {
                block: i as u32,
                len: 1,
                start: 100 + (i as u64) * 2,
                initialized: true,
            })
            .collect()
    }

    #[test]
    fn single_contiguous_run_is_one_leaf() {
        // lost+found: four contiguous blocks at 7 -> one leaf (0-3):7-10.
        let leaves = build_leaves(&[BlockRange { start: 7, len: 4 }]).unwrap();
        assert_eq!(
            leaves,
            vec![ExtentLeaf {
                block: 0,
                len: 4,
                start: 7,
                initialized: true,
            }]
        );
    }

    #[test]
    fn separate_ranges_stay_separate_leaves() {
        let leaves = build_leaves(&[
            BlockRange { start: 100, len: 2 },
            BlockRange { start: 200, len: 3 },
        ])
        .unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[1].block, 2);
        assert_eq!(leaves[1].start, 200);
    }

    #[test]
    fn contiguous_ranges_coalesce() {
        let leaves = build_leaves(&[
            BlockRange { start: 50, len: 4 },
            BlockRange { start: 54, len: 6 },
        ])
        .unwrap();
        assert_eq!(
            leaves,
            vec![ExtentLeaf {
                block: 0,
                len: 10,
                start: 50,
                initialized: true
            }]
        );
    }

    #[test]
    fn runs_longer_than_a_leaf_split() {
        // A run of 40000 blocks splits into 32768 + 7232.
        let leaves = build_leaves(&[BlockRange {
            start: 1000,
            len: 40000,
        }])
        .unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].len, 32768);
        assert_eq!(leaves[1].block, 32768);
        assert_eq!(leaves[1].len, 7232);
        assert_eq!(leaves[1].start, 1000 + 32768);
    }

    #[test]
    fn a_file_past_the_logical_limit_is_rejected() {
        // 2^32 blocks is the most a 32-bit ee_block addresses; one more is not.
        let ok = build_leaves(&[BlockRange {
            start: 0,
            len: MAX_LOGICAL_BLOCKS,
        }]);
        assert!(ok.is_ok());
        assert_eq!(
            build_leaves(&[BlockRange {
                start: 0,
                len: MAX_LOGICAL_BLOCKS + 1,
            }]),
            Err(ExtentError::FileTooLarge {
                blocks: MAX_LOGICAL_BLOCKS + 1
            })
        );
    }

    #[test]
    fn the_inline_area_holds_four_entries_and_a_node_holds_three_hundred_and_forty() {
        assert_eq!(INLINE, 4);
        assert_eq!(NODE, 340);
        // A full 4096-byte node ends its last entry exactly where the checksum tail
        // begins, and the tail's four bytes close the block.
        assert_eq!(tail_offset(4096), 4092);
        assert_eq!(tail_offset(4096) + 4, 4096);
    }

    #[test]
    fn a_node_smaller_than_its_header_holds_no_entries() {
        // `node_bytes` is a size the caller supplies, and one below a single header
        // describes no node at all. The capacity is zero, not a length that would
        // overrun the bytes it was measured against.
        assert_eq!(node_capacity(0), 0);
        assert_eq!(node_capacity(EXTENT_ENTRY_SIZE - 1), 0);
        assert_eq!(node_capacity(EXTENT_ENTRY_SIZE), 0);
        assert_eq!(node_capacity(2 * EXTENT_ENTRY_SIZE), 1);
        // With no entries there is nowhere in the node for a tail either, so the offset
        // lands past its end — where the write that takes it refuses, as it does any
        // offset the buffer does not reach.
        assert_eq!(tail_offset(0), EXTENT_ENTRY_SIZE);
        assert!(matches!(
            write_node(
                &ExtentNode::Leaves(Vec::new()),
                node_capacity(4),
                &mut [0u8; 4]
            ),
            Err(ExtentError::NodeTooSmall { .. })
        ));
    }

    #[test]
    fn leaves_that_fit_inline_need_no_tree() {
        let shape = plan_tree(INLINE, INLINE, NODE).unwrap();
        assert_eq!(shape.depth, 0);
        assert_eq!(shape.node_blocks, 0);

        let leaves = leaves_of(INLINE);
        let tree = build_tree(&leaves, INLINE, NODE, &[]).unwrap();
        assert_eq!(tree.root, ExtentNode::Leaves(leaves));
        assert!(tree.nodes.is_empty());
    }

    #[test]
    fn a_fifth_leaf_spills_into_one_external_node() {
        // Five leaves do not fit the inode's four slots, so the tree spills.
        let shape = plan_tree(INLINE + 1, INLINE, NODE).unwrap();
        assert_eq!(shape.depth, 1);
        assert_eq!(shape.level_nodes, vec![1]);
        assert_eq!(shape.node_blocks, 1);

        let leaves = leaves_of(INLINE + 1);
        let tree = build_tree(&leaves, INLINE, NODE, &[900]).unwrap();
        assert_eq!(
            tree.root,
            ExtentNode::Index {
                depth: 1,
                entries: vec![ExtentIdx {
                    block: 0,
                    leaf: 900
                }],
            }
        );
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.nodes[0].block, 900);
        assert_eq!(tree.nodes[0].node, ExtentNode::Leaves(leaves));
    }

    #[test]
    fn a_depth_one_tree_fills_its_leaf_nodes_in_order() {
        let leaves = leaves_of(NODE + 1);
        let shape = plan_tree(leaves.len(), INLINE, NODE).unwrap();
        assert_eq!(shape.depth, 1);
        assert_eq!(shape.level_nodes, vec![2]);

        let tree = build_tree(&leaves, INLINE, NODE, &[900, 901]).unwrap();
        let ExtentNode::Index { entries, depth } = &tree.root else {
            panic!("root indexes the leaf nodes");
        };
        assert_eq!(*depth, 1);
        // Each index entry names the first logical block of the node it points at.
        assert_eq!(
            entries[0],
            ExtentIdx {
                block: 0,
                leaf: 900
            }
        );
        assert_eq!(
            entries[1],
            ExtentIdx {
                block: NODE as u32,
                leaf: 901
            }
        );
        assert_eq!(tree.nodes[0].node.len(), NODE);
        assert_eq!(tree.nodes[1].node.len(), 1);
    }

    #[test]
    fn a_tree_grows_to_depth_two_when_the_root_cannot_index_the_leaf_level() {
        // More leaf nodes than the inline root's four slots forces a level between.
        let leaves = leaves_of(NODE * (INLINE + 1));
        let shape = plan_tree(leaves.len(), INLINE, NODE).unwrap();
        assert_eq!(shape.depth, 2);
        assert_eq!(shape.level_nodes, vec![INLINE + 1, 1]);
        assert_eq!(shape.node_blocks, INLINE + 2);

        let blocks: Vec<u64> = (900..900 + shape.node_blocks as u64).collect();
        let tree = build_tree(&leaves, INLINE, NODE, &blocks).unwrap();

        // The root holds a single index entry pointing at the one interior node,
        // which is the last block allocated because levels fill from the leaves up.
        let ExtentNode::Index { entries, depth } = &tree.root else {
            panic!("root indexes the interior level");
        };
        assert_eq!(*depth, 2);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].leaf, *blocks.last().unwrap());

        let interior = &tree.nodes.last().unwrap().node;
        assert_eq!(interior.depth(), 1);
        assert_eq!(interior.len(), INLINE + 1);
        // Every other node is a leaf node.
        assert!(tree.nodes[..INLINE + 1].iter().all(|n| n.node.depth() == 0));
    }

    #[test]
    fn every_leaf_appears_exactly_once_in_a_deep_tree() {
        // A narrow node capacity reaches depth two on a small leaf count: 100 leaves
        // fill 13 leaf nodes, which two interior nodes index, which the root indexes.
        let leaves = leaves_of(100);
        let shape = plan_tree(leaves.len(), INLINE, 8).unwrap();
        assert_eq!(shape.depth, 2);
        assert_eq!(shape.level_nodes, vec![13, 2]);

        let blocks: Vec<u64> = (900..900 + shape.node_blocks as u64).collect();
        let tree = build_tree(&leaves, INLINE, 8, &blocks).unwrap();

        // Reading the leaf nodes in allocation order recovers the file's leaves in
        // logical order, with none dropped and none repeated.
        let mut seen: Vec<ExtentLeaf> = Vec::new();
        for node in &tree.nodes {
            if let ExtentNode::Leaves(l) = &node.node {
                seen.extend(l.iter().copied());
            }
        }
        assert_eq!(seen, leaves, "leaves survive the split in logical order");

        // Every external node is pointed at exactly once, by the level above it.
        let mut pointed: Vec<u64> = Vec::new();
        for node in &tree.nodes {
            if let ExtentNode::Index { entries, .. } = &node.node {
                pointed.extend(entries.iter().map(|e| e.leaf));
            }
        }
        let ExtentNode::Index { entries, .. } = &tree.root else {
            panic!("root indexes the interior level");
        };
        pointed.extend(entries.iter().map(|e| e.leaf));
        pointed.sort_unstable();
        assert_eq!(pointed, blocks);
    }

    #[test]
    fn a_tree_deeper_than_ext4_defines_is_rejected() {
        // Capacity two at every level: depth grows like log2 of the leaf count.
        assert_eq!(plan_tree(4, 2, 2).unwrap().depth, 1);
        assert_eq!(plan_tree(64, 2, 2).unwrap().depth, 5);
        assert_eq!(plan_tree(128, 2, 2), Err(ExtentError::TooDeep { depth: 6 }));
    }

    #[test]
    fn a_node_that_cannot_narrow_a_level_is_rejected() {
        assert!(matches!(
            plan_tree(10, 4, 1),
            Err(ExtentError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn build_tree_checks_the_node_blocks_against_the_plan() {
        let leaves = leaves_of(INLINE + 1);
        assert_eq!(
            build_tree(&leaves, INLINE, NODE, &[]),
            Err(ExtentError::NodeBlockCount { need: 1, got: 0 })
        );
    }

    #[test]
    fn inline_node_round_trips_through_the_inode_block_area() {
        let leaves = build_leaves(&[BlockRange { start: 6, len: 1 }]).unwrap();
        let mut block = [0u8; Inode::BLOCK_BYTES];
        write_node(&ExtentNode::Leaves(leaves.clone()), INLINE, &mut block).unwrap();
        match parse_node(&block).unwrap() {
            ExtentNode::Leaves(back) => assert_eq!(back, leaves),
            other => panic!("expected leaves, got {other:?}"),
        }
    }

    #[test]
    fn an_index_node_round_trips_through_a_block() {
        let node = ExtentNode::Index {
            depth: 1,
            entries: vec![
                ExtentIdx {
                    block: 0,
                    leaf: 900,
                },
                ExtentIdx {
                    block: 340,
                    leaf: 0x1_0000_0001,
                },
            ],
        };
        let mut buf = vec![0u8; 4096];
        write_node(&node, NODE, &mut buf).unwrap();
        // The declared capacity is the node's, not the entry count.
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), NODE as u16);
        assert_eq!(parse_node(&buf).unwrap(), node);
    }

    #[test]
    fn write_node_rejects_more_entries_than_the_capacity() {
        let five = ExtentNode::Leaves(leaves_of(INLINE + 1));
        let mut block = [0u8; Inode::BLOCK_BYTES];
        assert_eq!(
            write_node(&five, INLINE, &mut block),
            Err(ExtentError::TooManyEntries {
                entries: 5,
                capacity: 4
            })
        );
    }

    #[test]
    fn parse_ignores_trailing_inline_bytes() {
        // Only the header's entry count is parsed; the inode's unused tail is left
        // untouched and does not become a phantom extent.
        let leaves = build_leaves(&[BlockRange { start: 6, len: 1 }]).unwrap();
        let mut block = [0xabu8; Inode::BLOCK_BYTES];
        write_node(&ExtentNode::Leaves(leaves), INLINE, &mut block).unwrap();
        match parse_node(&block).unwrap() {
            ExtentNode::Leaves(back) => assert_eq!(back.len(), 1),
            other => panic!("expected one leaf, got {other:?}"),
        }
    }

    #[test]
    fn a_header_whose_counts_disagree_is_refused() {
        // Each way the three counts can contradict the node they describe, patched into a
        // node that is otherwise exactly what the writer emits. `eh_entries` is at header
        // offset 2 and `eh_max` at 4.
        let node = |eh_entries: u16, eh_max: u16| {
            let leaves = build_leaves(&[BlockRange { start: 6, len: 1 }]).unwrap();
            let mut block = [0u8; Inode::BLOCK_BYTES];
            write_node(&ExtentNode::Leaves(leaves), INLINE, &mut block).unwrap();
            block[2..4].copy_from_slice(&eh_entries.to_le_bytes());
            block[4..6].copy_from_slice(&eh_max.to_le_bytes());
            block
        };

        // The unpatched node — one entry in a four-entry inline root — is what the
        // rejections below are measured against.
        assert!(parse_node(&node(1, INLINE as u16)).is_ok());

        for (eh_entries, eh_max, field, value, why) in [
            (0, 0, "eh_max", 0, "a node with room for nothing"),
            (
                1,
                INLINE as u16 + 1,
                "eh_max",
                INLINE as u64 + 1,
                "capacity past the sixty-byte inline area",
            ),
            (
                INLINE as u16,
                1,
                "eh_entries",
                INLINE as u64,
                "more entries than the declared capacity",
            ),
        ] {
            assert!(
                matches!(
                    parse_node(&node(eh_entries, eh_max)),
                    Err(ParseError::InvalidField {
                        structure: "ExtentHeader",
                        field: f,
                        value: v,
                    }) if f == field && v == value
                ),
                "eh_entries {eh_entries}, eh_max {eh_max} must be refused: {why}"
            );
        }
    }
}
