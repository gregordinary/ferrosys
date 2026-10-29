//! A B-tree node: its header, its table of contents, and the keys and values the table finds.
//!
//! Every tree in a container uses one node format (Apple File System Reference, pp. 122-134).
//! After the 32-byte object header come eight bytes of node fields and four locations; then
//! the node's storage area, in which the table of contents comes first, the keys follow it, and
//! the values grow backward from the end. A root node ends with 40 bytes of information about
//! the whole tree, and its values end before them.
//!
//! The free space the header locates divides the two: every key lies before it and every value
//! after it, no two keys and no two values share a byte, and the bytes of each area that no
//! entry holds add up to the total the area's free list records. All four were observed on
//! every node of every tree macOS 15, 26 and 27 wrote.
//!
//! **Every location in a node is a number the image supplies**, so every one is checked here
//! against the node's own bounds before a byte is read through it: a key that runs into the
//! free space or the values, a value that starts before the free space ends, a table that
//! claims more entries than it has room for. A failed check is a [`NodeFault`], never an index
//! past the slice.
//!
//! This module is pure: it reads bytes and does no I/O.

use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};

use super::{ObjectHeader, ParseError};

/// Where a node's storage area begins: after the object header and the node fields.
pub const NODE_DATA_START: usize = 56;

/// The bytes a root node's tree information takes at its end.
pub const TREE_INFO_SIZE: usize = 40;

/// The value offset a table entry carries where its key has no value
/// (Apple File System Reference, p. 128).
pub const NO_VALUE: u16 = 0xFFFF;

/// The bytes an index node's value takes: the child's identifier.
pub const CHILD_POINTER_SIZE: usize = 8;

/// Node flags (Apple File System Reference, p. 132).
pub mod node_flags {
    /// The tree's root node.
    pub const ROOT: u16 = 0x1;
    /// A leaf node, holding records rather than children.
    pub const LEAF: u16 = 0x2;
    /// Keys and values of the sizes the tree information gives, located by offsets alone.
    pub const FIXED_SIZE: u16 = 0x4;
    /// A sealed volume's node, whose index values carry each child's hash.
    pub const HASHED: u16 = 0x8;
    /// A node stored without an object header.
    pub const NO_HEADER: u16 = 0x10;
    /// Every flag this crate reads a node carrying.
    pub const UNDERSTOOD: u16 = ROOT | LEAF | FIXED_SIZE;
}

/// The node fields after the object header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeHeader {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 32. The node's [`node_flags`].
    pub flags: u16,
    /// Offset 34. Levels below this node: zero for a leaf.
    pub level: u16,
    /// Offset 36. Entries in the table of contents.
    pub key_count: u32,
    /// Offset 40. The table of contents, as an offset from the storage area's start and a
    /// length.
    pub table: (u16, u16),
    /// Offset 44. The free space between keys and values, offset from the key area's start.
    pub free_space: (u16, u16),
    /// Offset 48. The head of the key area's free list, and its total.
    pub key_free_list: (u16, u16),
    /// Offset 52. The head of the value area's free list, and its total.
    pub value_free_list: (u16, u16),
}

impl NodeHeader {
    /// Bytes on disk, up to the storage area.
    pub const SIZE: usize = NODE_DATA_START;

    /// Recover the node fields from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("node header", Self::SIZE, buf)?;
        let loc = |off| (get_u16(buf, off), get_u16(buf, off + 2));
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            flags: get_u16(buf, 32),
            level: get_u16(buf, 34),
            key_count: get_u32(buf, 36),
            table: loc(40),
            free_space: loc(44),
            key_free_list: loc(48),
            value_free_list: loc(52),
        })
    }

    /// Write the node fields into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a node header needs {} bytes",
            Self::SIZE
        );
        self.header.write_to(buf);
        put_u16(buf, 32, self.flags);
        put_u16(buf, 34, self.level);
        put_u32(buf, 36, self.key_count);
        let mut loc = |off, (a, b): (u16, u16)| {
            put_u16(buf, off, a);
            put_u16(buf, off + 2, b);
        };
        loc(40, self.table);
        loc(44, self.free_space);
        loc(48, self.key_free_list);
        loc(52, self.value_free_list);
    }

    /// Whether this is the tree's root node.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.flags & node_flags::ROOT != 0
    }

    /// Whether this node holds records rather than children.
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.flags & node_flags::LEAF != 0
    }

    /// Whether its table of contents holds offsets alone.
    #[must_use]
    pub const fn is_fixed_size(&self) -> bool {
        self.flags & node_flags::FIXED_SIZE != 0
    }
}

/// What a root node records about its whole tree, in its last 40 bytes
/// (Apple File System Reference, pp. 125-127).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TreeInfo {
    /// The tree's flags: `0x1` 64-bit keys, `0x2` sequential insertion, `0x4` keys without
    /// values allowed, `0x8` ephemeral children, `0x10` physical children, `0x20` not
    /// persisted, `0x40` unaligned keys and values, `0x80` hashed, `0x100` headerless nodes.
    pub flags: u32,
    /// Bytes in every node of the tree.
    pub node_size: u32,
    /// Bytes in every key, or zero where keys vary in size.
    pub key_size: u32,
    /// Bytes in every leaf value, or zero where values vary in size.
    pub value_size: u32,
    /// The longest key the tree has held.
    pub longest_key: u32,
    /// The longest value the tree has held.
    pub longest_value: u32,
    /// Records in the tree.
    pub key_count: u64,
    /// Nodes in the tree.
    pub node_count: u64,
}

/// The tree flag saying children are found by physical address.
pub const TREE_PHYSICAL: u32 = 0x10;

/// The tree flag saying entries were inserted in order, which a reader has no use for.
pub const TREE_SEQUENTIAL_INSERT: u32 = 0x2;

/// The tree flag saying a key may appear with no value.
pub const TREE_ALLOW_GHOSTS: u32 = 0x4;

/// The tree flag saying keys and values need not start at eight-byte boundaries, which a
/// reader that reads them where they are has no use for.
pub const TREE_KV_NONALIGNED: u32 = 0x40;

/// The tree flag saying index values carry each child's hash.
pub const TREE_HASHED: u32 = 0x80;

/// The tree flag saying nodes are stored without object headers.
pub const TREE_NO_HEADER: u32 = 0x100;

/// The tree flag saying children are ephemeral objects.
pub const TREE_EPHEMERAL: u32 = 0x8;

impl TreeInfo {
    /// Bytes on disk.
    pub const SIZE: usize = TREE_INFO_SIZE;

    /// Recover tree information from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("tree information", Self::SIZE, buf)?;
        Ok(Self {
            flags: get_u32(buf, 0),
            node_size: get_u32(buf, 4),
            key_size: get_u32(buf, 8),
            value_size: get_u32(buf, 12),
            longest_key: get_u32(buf, 16),
            longest_value: get_u32(buf, 20),
            key_count: get_u64(buf, 24),
            node_count: get_u64(buf, 32),
        })
    }

    /// Write the information into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= Self::SIZE, "tree information needs 40 bytes");
        put_u32(buf, 0, self.flags);
        put_u32(buf, 4, self.node_size);
        put_u32(buf, 8, self.key_size);
        put_u32(buf, 12, self.value_size);
        put_u32(buf, 16, self.longest_key);
        put_u32(buf, 20, self.longest_value);
        put_u64(buf, 24, self.key_count);
        put_u64(buf, 32, self.node_count);
    }
}

/// Why a node's bytes do not frame as the node they claim to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeFault {
    /// The node is shorter than its header, or than a root's header and tree information.
    #[error("{len} bytes cannot hold a node")]
    #[non_exhaustive]
    TooShort {
        /// The node's length.
        len: usize,
    },
    /// The table of contents does not lie between the header and the end of the storage area.
    #[error("the table of contents ({offset} bytes in, {len} long) leaves the node")]
    #[non_exhaustive]
    TableOutside {
        /// Its offset from the storage area's start.
        offset: u16,
        /// Its length.
        len: u16,
    },
    /// The table of contents has room for fewer entries than the node counts.
    #[error("{count} entries do not fit a table of contents {len} bytes long")]
    #[non_exhaustive]
    TableTooSmall {
        /// Entries the node counts.
        count: u32,
        /// The table's length.
        len: u16,
    },
    /// A fixed-size node in a tree whose sizes are not fixed, or of a size no entry has.
    #[error("a fixed-size entry of {key_size}-byte keys and {value_size}-byte values")]
    #[non_exhaustive]
    BadFixedSize {
        /// The key size the tree gives.
        key_size: u32,
        /// The value size the tree gives.
        value_size: u32,
    },
    /// A node of entries of varying size, in a tree whose information gives its keys one size.
    #[error("a node of entries of varying size in a tree whose keys take {key_size} bytes")]
    #[non_exhaustive]
    VaryingInFixedTree {
        /// The key size the tree gives.
        key_size: u32,
    },
    /// An entry's key does not lie inside the key area.
    #[error("entry {index}'s key ({offset} bytes in, {len} long) leaves the key area")]
    #[non_exhaustive]
    KeyOutside {
        /// The entry.
        index: u32,
        /// The key's offset from the key area's start.
        offset: u16,
        /// Its length.
        len: u16,
    },
    /// An entry's value does not lie inside the value area.
    #[error(
        "entry {index}'s value ({offset} bytes from the end, {len} long) leaves the value area"
    )]
    #[non_exhaustive]
    ValueOutside {
        /// The entry.
        index: u32,
        /// The value's offset back from the value area's end.
        offset: u16,
        /// Its length.
        len: u16,
    },
    /// The free space between the keys and the values does not lie inside the storage area.
    #[error("the free space ({offset} bytes into the key area, {len} long) leaves the node")]
    #[non_exhaustive]
    FreeSpaceOutside {
        /// Its offset from the key area's start.
        offset: u16,
        /// Its length.
        len: u16,
    },
    /// An entry asked for past the last the node counts.
    #[error("entry {index} of a node counting {count}")]
    #[non_exhaustive]
    NoEntry {
        /// The entry asked for.
        index: u32,
        /// Entries the node counts.
        count: u32,
    },
    /// Two entries' keys, or two entries' values, share bytes.
    #[error("entry {index}'s {part} shares bytes with another entry's")]
    #[non_exhaustive]
    Overlap {
        /// The later of the two entries.
        index: u32,
        /// `"key"` or `"value"`.
        part: &'static str,
    },
}

/// The bytes of a node's key area and value area that no entry holds, once
/// [`Node::check_layout`] has placed every entry: what the two free lists account for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Unused {
    /// Bytes of the key area, before the free space, in no key.
    pub key: usize,
    /// Bytes of the value area, after the free space, in no value.
    pub value: usize,
}

/// One node's bytes, framed: where its table, keys and values are.
///
/// Built only through [`Node::frame`], which checks the table against the node, so every
/// method that follows indexes inside bounds already established. An entry's own key and value
/// are checked when it is read.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    bytes: &'a [u8],
    header: NodeHeader,
    table_start: usize,
    key_area: usize,
    /// Where the free space begins, which is where the keys must end.
    free_start: usize,
    /// Where the free space ends, which is where the values may begin.
    value_start: usize,
    value_end: usize,
    /// The sizes a fixed-size entry's key and value take, where the node is fixed-size.
    fixed: Option<(u16, u16)>,
}

/// The sizes the entries of one tree take, as its root's information gives them, which every
/// node of the tree is framed by.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EntrySizes {
    /// Bytes in every key, or zero where keys vary.
    pub key: u32,
    /// Bytes in every leaf value, or zero where values vary.
    pub value: u32,
}

impl<'a> Node<'a> {
    /// Frame `bytes` as a node of a tree whose entries take `sizes`.
    ///
    /// # Errors
    ///
    /// A [`NodeFault`] where the header, the table of contents, the free space, or a fixed
    /// entry size does not fit the node.
    pub fn frame(bytes: &'a [u8], sizes: EntrySizes) -> Result<Self, NodeFault> {
        let len = bytes.len();
        let header = NodeHeader::read_from(bytes).map_err(|_| NodeFault::TooShort { len })?;
        let value_end = if header.is_root() {
            len.checked_sub(TREE_INFO_SIZE)
                .filter(|end| *end >= NODE_DATA_START)
                .ok_or(NodeFault::TooShort { len })?
        } else {
            len
        };
        let (offset, table_len) = header.table;
        let table_start = NODE_DATA_START + usize::from(offset);
        let key_area = table_start + usize::from(table_len);
        if key_area > value_end {
            return Err(NodeFault::TableOutside {
                offset,
                len: table_len,
            });
        }
        let (free_offset, free_len) = header.free_space;
        let free_start = key_area + usize::from(free_offset);
        let value_start = free_start + usize::from(free_len);
        if value_start > value_end {
            return Err(NodeFault::FreeSpaceOutside {
                offset: free_offset,
                len: free_len,
            });
        }
        let fixed = if header.is_fixed_size() {
            let value = if header.is_leaf() {
                sizes.value
            } else {
                CHILD_POINTER_SIZE as u32
            };
            let fits = |n: u32| n != 0 && n <= u32::from(u16::MAX);
            if !fits(sizes.key) || !fits(value) {
                return Err(NodeFault::BadFixedSize {
                    key_size: sizes.key,
                    value_size: value,
                });
            }
            Some((sizes.key as u16, value as u16))
        } else if sizes.key != 0 {
            // Every node of a tree whose keys take one size is flagged as holding entries of
            // fixed size, on every object map of the corpus.
            return Err(NodeFault::VaryingInFixedTree {
                key_size: sizes.key,
            });
        } else {
            None
        };
        let entry_size: u64 = if fixed.is_some() { 4 } else { 8 };
        if u64::from(header.key_count) * entry_size > u64::from(table_len) {
            return Err(NodeFault::TableTooSmall {
                count: header.key_count,
                len: table_len,
            });
        }
        Ok(Self {
            bytes,
            header,
            table_start,
            key_area,
            free_start,
            value_start,
            value_end,
            fixed,
        })
    }

    /// The node's fields.
    #[must_use]
    pub const fn header(&self) -> &NodeHeader {
        &self.header
    }

    /// The node's whole bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Entries in the node.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.header.key_count
    }

    /// Whether the node holds no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.header.key_count == 0
    }

    /// The tree information a root node carries in its last 40 bytes, or [`None`] for a node
    /// that is not a root.
    #[must_use]
    pub fn tree_info(&self) -> Option<TreeInfo> {
        if !self.header.is_root() {
            return None;
        }
        TreeInfo::read_from(&self.bytes[self.value_end..]).ok()
    }

    /// Entry `index`: its key, and its value or [`None`] where the key has none.
    ///
    /// # Errors
    ///
    /// [`NodeFault::KeyOutside`] or [`NodeFault::ValueOutside`] where the table places either
    /// outside its area: a key past the start of the free space, a value before its end, and
    /// [`NodeFault::NoEntry`] where `index` is not below [`len`](Self::len).
    pub fn entry(&self, index: u32) -> Result<(&'a [u8], Option<&'a [u8]>), NodeFault> {
        let (key, value) = self.locate(index)?;
        Ok((&self.bytes[key], value.map(|value| &self.bytes[value])))
    }

    /// Place every entry, and say how many bytes of each area no entry holds.
    ///
    /// # Errors
    ///
    /// What [`entry`](Self::entry) refuses for any entry, and [`NodeFault::Overlap`] where two
    /// keys or two values share a byte.
    pub fn check_layout(&self) -> Result<Unused, NodeFault> {
        let mut taken = vec![0u64; self.bytes.len().div_ceil(64)];
        let mut held = Unused::default();
        let mut claim = |range: std::ops::Range<usize>, index: u32, part: &'static str| {
            for at in range {
                let (word, bit) = (at / 64, 1u64 << (at % 64));
                if taken[word] & bit != 0 {
                    return Err(NodeFault::Overlap { index, part });
                }
                taken[word] |= bit;
            }
            Ok(())
        };
        for index in 0..self.header.key_count {
            let (key, value) = self.locate(index)?;
            held.key += key.len();
            claim(key, index, "key")?;
            if let Some(value) = value {
                held.value += value.len();
                claim(value, index, "value")?;
            }
        }
        // Every key lies in the key area and every value in the value area, and none shares a
        // byte, so what each area holds is no more than its length.
        Ok(Unused {
            key: (self.free_start - self.key_area) - held.key,
            value: (self.value_end - self.value_start) - held.value,
        })
    }

    /// Where entry `index`'s key and value are in the node's bytes.
    fn locate(
        &self,
        index: u32,
    ) -> Result<(std::ops::Range<usize>, Option<std::ops::Range<usize>>), NodeFault> {
        if index >= self.header.key_count {
            return Err(NodeFault::NoEntry {
                index,
                count: self.header.key_count,
            });
        }
        let i = index as usize;
        let (key_off, key_len, value_off, value_len) = match self.fixed {
            Some((key_len, value_len)) => {
                let at = self.table_start + 4 * i;
                (
                    get_u16(self.bytes, at),
                    key_len,
                    get_u16(self.bytes, at + 2),
                    value_len,
                )
            }
            None => {
                let at = self.table_start + 8 * i;
                (
                    get_u16(self.bytes, at),
                    get_u16(self.bytes, at + 2),
                    get_u16(self.bytes, at + 4),
                    get_u16(self.bytes, at + 6),
                )
            }
        };
        let key_start = self.key_area + usize::from(key_off);
        let key_end = key_start + usize::from(key_len);
        if key_end > self.free_start {
            return Err(NodeFault::KeyOutside {
                index,
                offset: key_off,
                len: key_len,
            });
        }
        if value_off == NO_VALUE {
            return Ok((key_start..key_end, None));
        }
        // A value's offset counts back from the end of the value area to its first byte, so
        // it must reach at least as far back as the value is long, and no further back than
        // the end of the free space.
        let outside = NodeFault::ValueOutside {
            index,
            offset: value_off,
            len: value_len,
        };
        let value_start = self
            .value_end
            .checked_sub(usize::from(value_off))
            .filter(|start| *start >= self.value_start)
            .ok_or(outside)?;
        let value_end = value_start + usize::from(value_len);
        if value_end > self.value_end {
            return Err(outside);
        }
        Ok((key_start..key_end, Some(value_start..value_end)))
    }
}

/// The child identifier an index entry's value holds.
///
/// # Errors
///
/// [`ParseError::TooShort`] where the value is shorter than an identifier.
pub fn child_oid(value: &[u8]) -> Result<u64, ParseError> {
    ParseError::need("index value", CHILD_POINTER_SIZE, value)?;
    Ok(get_u64(value, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4096-byte variable-size leaf root holding `entries`, laid out the way the format
    /// does: table first, keys packed after it, values packed back from before the tree
    /// information.
    fn leaf_root(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut node = vec![0u8; 4096];
        let table_len = (entries.len() * 8) as u16;
        NodeHeader {
            header: ObjectHeader {
                checksum: 0,
                oid: 5,
                xid: 1,
                type_word: 0x4000_0002,
                subtype: 0x0B,
            },
            flags: node_flags::ROOT | node_flags::LEAF,
            level: 0,
            key_count: entries.len() as u32,
            table: (0, table_len),
            free_space: (0, 0),
            key_free_list: (NO_VALUE, 0),
            value_free_list: (NO_VALUE, 0),
        }
        .write_to(&mut node);
        let key_area = NODE_DATA_START + usize::from(table_len);
        let value_end = 4096 - TREE_INFO_SIZE;
        let (mut k, mut v) = (0usize, 0usize);
        for (i, (key, value)) in entries.iter().enumerate() {
            node[key_area + k..key_area + k + key.len()].copy_from_slice(key);
            v += value.len();
            node[value_end - v..value_end - v + value.len()].copy_from_slice(value);
            let at = NODE_DATA_START + 8 * i;
            put_u16(&mut node, at, k as u16);
            put_u16(&mut node, at + 2, key.len() as u16);
            put_u16(&mut node, at + 4, v as u16);
            put_u16(&mut node, at + 6, value.len() as u16);
            k += key.len();
        }
        // The free space runs from the end of the keys to the start of the values.
        put_u16(&mut node, 44, k as u16);
        put_u16(&mut node, 46, (value_end - v - key_area - k) as u16);
        node
    }

    #[test]
    fn a_header_round_trips() {
        let header = NodeHeader {
            header: ObjectHeader {
                checksum: 0,
                oid: 9,
                xid: 2,
                type_word: 3,
                subtype: 0x0E,
            },
            flags: node_flags::LEAF,
            level: 0,
            key_count: 3,
            table: (0, 24),
            free_space: (40, 100),
            key_free_list: (NO_VALUE, 0),
            value_free_list: (NO_VALUE, 0),
        };
        let mut buf = [0u8; NodeHeader::SIZE];
        header.write_to(&mut buf);
        assert_eq!(NodeHeader::read_from(&buf), Ok(header));
    }

    #[test]
    fn entries_are_found_where_the_table_says() {
        let node = leaf_root(&[(b"alpha", b"one"), (b"beta", b"two!")]);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert_eq!(framed.len(), 2);
        assert_eq!(framed.entry(0), Ok((&b"alpha"[..], Some(&b"one"[..]))));
        assert_eq!(framed.entry(1), Ok((&b"beta"[..], Some(&b"two!"[..]))));
        assert!(framed.tree_info().is_some());
    }

    #[test]
    fn a_key_with_no_value_is_one_with_none() {
        let mut node = leaf_root(&[(b"ghost", b"x")]);
        put_u16(&mut node, NODE_DATA_START + 4, NO_VALUE);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert_eq!(framed.entry(0), Ok((&b"ghost"[..], None)));
    }

    #[test]
    fn a_key_running_into_the_values_is_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one")]);
        put_u16(&mut node, NODE_DATA_START + 2, 5000);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert!(matches!(
            framed.entry(0),
            Err(NodeFault::KeyOutside { index: 0, .. })
        ));
    }

    #[test]
    fn a_value_reaching_past_its_area_or_back_into_the_table_is_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one")]);
        // Two bytes back from the end, three long: past the end.
        put_u16(&mut node, NODE_DATA_START + 4, 2);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert!(matches!(
            framed.entry(0),
            Err(NodeFault::ValueOutside { .. })
        ));
        // Further back than the whole storage area.
        put_u16(&mut node, NODE_DATA_START + 4, 4090);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert!(matches!(
            framed.entry(0),
            Err(NodeFault::ValueOutside { .. })
        ));
    }

    #[test]
    fn a_key_reaching_into_the_free_space_or_a_value_starting_in_it_is_refused() {
        let node = leaf_root(&[(b"alpha", b"one"), (b"beta", b"two!")]);
        // The free space begins where the keys end: a key one byte longer runs into it.
        let mut longer = node.clone();
        put_u16(&mut longer, NODE_DATA_START + 8 + 2, 5);
        let framed = Node::frame(&longer, EntrySizes::default()).expect("frames");
        assert!(matches!(
            framed.entry(1),
            Err(NodeFault::KeyOutside { index: 1, .. })
        ));
        // And it ends where the values begin: a value reaching one byte further back starts in it.
        let mut earlier = node;
        put_u16(&mut earlier, NODE_DATA_START + 8 + 4, 8);
        let framed = Node::frame(&earlier, EntrySizes::default()).expect("frames");
        assert!(matches!(
            framed.entry(1),
            Err(NodeFault::ValueOutside { index: 1, .. })
        ));
    }

    #[test]
    fn two_values_sharing_bytes_are_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one"), (b"beta", b"two")]);
        // The second value placed where the first is.
        put_u16(&mut node, NODE_DATA_START + 8 + 4, 3);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert_eq!(framed.entry(1), Ok((&b"beta"[..], Some(&b"one"[..]))));
        assert_eq!(
            framed.check_layout(),
            Err(NodeFault::Overlap {
                index: 1,
                part: "value"
            })
        );
    }

    #[test]
    fn the_bytes_no_entry_holds_are_counted_in_each_area() {
        let node = leaf_root(&[(b"alpha", b"one"), (b"beta", b"two!")]);
        let framed = Node::frame(&node, EntrySizes::default()).expect("frames");
        assert_eq!(framed.check_layout(), Ok(Unused { key: 0, value: 0 }));
        // A key one byte shorter leaves one byte of the key area to the free list.
        let mut shorter = node;
        put_u16(&mut shorter, NODE_DATA_START + 2, 4);
        let framed = Node::frame(&shorter, EntrySizes::default()).expect("frames");
        assert_eq!(framed.check_layout(), Ok(Unused { key: 1, value: 0 }));
    }

    #[test]
    fn free_space_leaving_the_node_is_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one")]);
        put_u16(&mut node, 46, 4000);
        assert!(matches!(
            Node::frame(&node, EntrySizes::default()),
            Err(NodeFault::FreeSpaceOutside { .. })
        ));
    }

    #[test]
    fn a_table_claiming_more_entries_than_it_has_room_for_is_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one")]);
        put_u32(&mut node, 36, 2);
        assert!(matches!(
            Node::frame(&node, EntrySizes::default()),
            Err(NodeFault::TableTooSmall { count: 2, .. })
        ));
    }

    #[test]
    fn a_table_leaving_the_node_is_refused() {
        let mut node = leaf_root(&[(b"alpha", b"one")]);
        put_u16(&mut node, 40, 4000);
        assert!(matches!(
            Node::frame(&node, EntrySizes::default()),
            Err(NodeFault::TableOutside { .. })
        ));
    }

    #[test]
    fn a_fixed_size_node_takes_its_sizes_from_the_tree() {
        let mut node = vec![0u8; 4096];
        NodeHeader {
            header: ObjectHeader {
                checksum: 0,
                oid: 5,
                xid: 1,
                type_word: 0x4000_0002,
                subtype: 0x0B,
            },
            flags: node_flags::ROOT | node_flags::LEAF | node_flags::FIXED_SIZE,
            level: 0,
            key_count: 1,
            table: (0, 4),
            free_space: (
                16,
                (4096 - TREE_INFO_SIZE - 16 - (NODE_DATA_START + 4) - 16) as u16,
            ),
            key_free_list: (NO_VALUE, 0),
            value_free_list: (NO_VALUE, 0),
        }
        .write_to(&mut node);
        let key_area = NODE_DATA_START + 4;
        node[key_area..key_area + 16].copy_from_slice(&[7; 16]);
        let value_end = 4096 - TREE_INFO_SIZE;
        node[value_end - 16..value_end].copy_from_slice(&[9; 16]);
        put_u16(&mut node, NODE_DATA_START, 0);
        put_u16(&mut node, NODE_DATA_START + 2, 16);
        let sizes = EntrySizes { key: 16, value: 16 };
        let framed = Node::frame(&node, sizes).expect("frames");
        assert_eq!(framed.entry(0), Ok((&[7u8; 16][..], Some(&[9u8; 16][..]))));
        // Without sizes from the tree, a fixed-size node cannot be framed.
        assert!(matches!(
            Node::frame(&node, EntrySizes::default()),
            Err(NodeFault::BadFixedSize { .. })
        ));
    }
}
