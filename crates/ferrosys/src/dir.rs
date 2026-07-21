//! Directory layout: packing entries into a directory's data blocks.
//!
//! The [`DirLayout`] trait is a seam. A directory can be stored two ways in ext4 —
//! a linear list of entries, or a hash-indexed tree — and which one a directory
//! uses is selected here rather than by editing the materializer. This module is
//! pure: it turns a list of entries into block-sized buffers and performs no I/O.
//!
//! [`LinearDir`] packs entries sequentially, one block after another, and reserves
//! the twelve-byte checksum tail at the end of every block. The tail is where
//! `metadata_csum` records a directory block's checksum; keeping the slot always
//! free means enabling checksums fills reserved space without moving any entry.
//!
//! [`HtreeDir`] adds a search tree over those same blocks. A directory whose entries
//! fit in one block stays linear, because an index would cost a block and save no
//! search; past that it gets a root block, an optional level of interior nodes, and
//! the entry blocks, with names ordered by [`crate::hash::dir_hash`]. The blocks a
//! layout returns are the directory's logical blocks in order, and each says what
//! kind of checksum tail it carries so the materializer can fill it.

use crate::hash::{DirHash, HashSignedness, HashVersion, dir_hash};
use crate::ondisk::{
    DIR_TAIL_LEN, DX_HASH_CONTINUED, DX_MAX_INDIRECT_LEVELS, DX_NODE_COUNT_OFFSET,
    DX_ROOT_COUNT_OFFSET, DirEntry, DxEntry, ParseError, dx_limit, min_rec_len, put_u16,
    rec_len_to_disk, write_dir_tail, write_dx_entries, write_dx_node_header, write_dx_root_header,
};

/// A failure packing a directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum DirError {
    /// A single entry is larger than a directory block can hold.
    #[error("directory entry needs {need} bytes, more than a {block_size}-byte block holds")]
    EntryTooLarge {
        /// Bytes the entry's record needs.
        need: usize,
        /// The block size.
        block_size: usize,
    },
    /// A directory's entries did not begin with `"."` and `".."`.
    #[error("directory entries must begin with \".\" and \"..\"")]
    MissingDotEntries,
    /// The directory holds more entry blocks than one level of index nodes can
    /// address.
    #[error("directory index needs {blocks} entry blocks, more than the {capacity} addressable")]
    IndexTooLarge {
        /// Entry blocks the directory needs.
        blocks: usize,
        /// Entry blocks the index can address.
        capacity: usize,
    },
    /// Serializing an entry failed.
    #[error(transparent)]
    Encode(#[from] ParseError),
}

/// What a directory block holds, and so which checksum tail closes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirBlockKind {
    /// A block of directory entries, closed by the twelve-byte dirent tail.
    Entries,
    /// A block of the hash index — the root or an interior node — closed by the
    /// eight-byte index tail.
    Index {
        /// Byte offset at which the block's entry count and capacity begin.
        count_offset: usize,
        /// Index entries the block declares room for.
        limit: usize,
    },
}

/// One directory block: its bytes, and the kind of tail it reserves.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirBlock {
    /// The block's bytes, exactly one block long.
    pub bytes: Vec<u8>,
    /// What the block holds.
    pub kind: DirBlockKind,
}

impl DirBlock {
    /// A block of entries.
    #[must_use]
    fn entries(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            kind: DirBlockKind::Entries,
        }
    }
}

/// How a directory's entries are laid out in its data blocks.
///
/// The output is the directory's logical blocks in order, each exactly `block_size`
/// bytes and ready to write. The `"."` and `".."` entries are supplied by the caller
/// as the first two entries, so this trait is only concerned with placement, not with
/// a directory's required contents.
pub trait DirLayout {
    /// Pack `entries` into `block_size`-byte directory blocks.
    ///
    /// # Errors
    ///
    /// A [`DirError`] if an entry cannot fit in a block, the directory outgrows what
    /// an index addresses, or an entry fails to serialize.
    fn build_blocks(
        &self,
        entries: &[DirEntry],
        block_size: usize,
    ) -> Result<Vec<DirBlock>, DirError>;
}

/// Close a block: stretch the last entry's record length to fill the usable area, then
/// write the reserved tail when one is present. `last_off` is the byte offset of the
/// last entry; `usable` is where the tail begins, or the block end when `tail_len` is
/// zero. A filesystem without `metadata_csum` reserves no tail, so the last entry's
/// record spans the whole block and no tail dirent is written.
fn close_block(
    block: &mut [u8],
    last_off: usize,
    usable: usize,
    tail_len: usize,
) -> Result<(), DirError> {
    // The last entry's record spans the rest of the usable area so the entries
    // tile the block exactly up to the tail (or to the block end when there is none).
    // Encoding through `rec_len_to_disk` keeps the span readable when it fills a whole
    // block whose length the 16-bit field cannot hold verbatim.
    put_u16(
        block,
        last_off + 4,
        rec_len_to_disk(usable - last_off, block.len()),
    );
    if tail_len != 0 {
        write_dir_tail(&mut block[usable..usable + tail_len], 0)?;
    }
    Ok(())
}

/// Write `entries` — which must fit — into one block, closed by the reserved tail if
/// this filesystem carries one (`tail_len` bytes, zero without `metadata_csum`).
fn pack_one_block(
    entries: &[&DirEntry],
    block_size: usize,
    tail_len: usize,
) -> Result<Vec<u8>, DirError> {
    let usable = block_size - tail_len;
    let mut block = vec![0u8; block_size];
    let mut off = 0usize;
    let mut last_off = 0usize;
    for entry in entries {
        let need = min_rec_len(entry.name.len()) as usize;
        entry.write_to(&mut block[off..off + need], need, block_size)?;
        last_off = off;
        off += need;
    }
    close_block(&mut block, last_off, usable, tail_len)?;
    Ok(block)
}

/// Bytes an entry's record occupies, rejecting one no block could hold once the tail
/// (`tail_len` bytes, zero without `metadata_csum`) is set aside.
fn record_len(entry: &DirEntry, block_size: usize, tail_len: usize) -> Result<usize, DirError> {
    let need = min_rec_len(entry.name.len()) as usize;
    if need > block_size - tail_len {
        return Err(DirError::EntryTooLarge { need, block_size });
    }
    Ok(need)
}

/// Whether every entry fits in a single block, once the tail is set aside.
fn fits_in_one_block(
    entries: &[DirEntry],
    block_size: usize,
    tail_len: usize,
) -> Result<bool, DirError> {
    let mut total = 0usize;
    for entry in entries {
        total += record_len(entry, block_size, tail_len)?;
    }
    Ok(total <= block_size - tail_len)
}

/// A linear directory: entries packed in order across blocks, each block closed by the
/// reserved checksum tail when the filesystem carries one.
#[derive(Clone, Copy, Debug)]
pub struct LinearDir {
    /// Bytes reserved for the checksum tail at the end of each block:
    /// [`DIR_TAIL_LEN`] under `metadata_csum`, zero without it.
    pub tail_len: usize,
}

impl DirLayout for LinearDir {
    fn build_blocks(
        &self,
        entries: &[DirEntry],
        block_size: usize,
    ) -> Result<Vec<DirBlock>, DirError> {
        let usable = block_size - self.tail_len;
        let mut blocks: Vec<DirBlock> = Vec::new();
        let mut cur: Vec<&DirEntry> = Vec::new();
        let mut used = 0usize;

        for entry in entries {
            let need = record_len(entry, block_size, self.tail_len)?;
            if used + need > usable && !cur.is_empty() {
                blocks.push(DirBlock::entries(pack_one_block(
                    &cur,
                    block_size,
                    self.tail_len,
                )?));
                cur.clear();
                used = 0;
            }
            used += need;
            cur.push(entry);
        }

        // A directory always has at least "." and "..", so a block is always open.
        if !cur.is_empty() {
            blocks.push(DirBlock::entries(pack_one_block(
                &cur,
                block_size,
                self.tail_len,
            )?));
        }
        Ok(blocks)
    }
}

/// A hash-indexed directory: a search tree over blocks of entries ordered by name
/// hash.
///
/// A directory whose entries fit in one block is packed linearly instead, which is
/// where the `"."` and `".."` entries would otherwise cost an index its only
/// advantage. Larger directories get a root block, entry blocks, and — once the root
/// cannot name every entry block — one level of interior nodes between them.
#[derive(Clone, Copy, Debug)]
pub struct HtreeDir {
    /// The filesystem's directory-hash seed (`s_hash_seed`).
    pub seed: [u8; 16],
    /// The hash algorithm names are ordered by.
    pub version: HashVersion,
    /// How a name's bytes are interpreted when hashed.
    pub signedness: HashSignedness,
    /// Whether `metadata_csum` reserves an index block's checksum tail, which costs
    /// each index block one entry slot.
    pub checksums: bool,
}

impl HtreeDir {
    /// Split the caller's entries into the two a directory must have and the rest.
    fn split_dots(entries: &[DirEntry]) -> Result<(&DirEntry, &DirEntry, &[DirEntry]), DirError> {
        match entries {
            [dot, dotdot, rest @ ..] if dot.name == b"." && dotdot.name == b".." => {
                Ok((dot, dotdot, rest))
            }
            _ => Err(DirError::MissingDotEntries),
        }
    }

    /// Order the names by hash, then by name so equal hashes place deterministically.
    fn sort_by_hash<'a>(&self, entries: &'a [DirEntry]) -> Vec<(DirHash, &'a DirEntry)> {
        let mut hashed: Vec<(DirHash, &DirEntry)> = entries
            .iter()
            .map(|e| {
                (
                    dir_hash(&e.name, self.version, self.signedness, &self.seed),
                    e,
                )
            })
            .collect();
        hashed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
        hashed
    }
}

impl DirLayout for HtreeDir {
    fn build_blocks(
        &self,
        entries: &[DirEntry],
        block_size: usize,
    ) -> Result<Vec<DirBlock>, DirError> {
        // Entry blocks carry the twelve-byte dirent tail only under `metadata_csum`, the
        // same condition that governs the index blocks' own tail.
        let tail_len = if self.checksums { DIR_TAIL_LEN } else { 0 };
        if fits_in_one_block(entries, block_size, tail_len)? {
            return LinearDir { tail_len }.build_blocks(entries, block_size);
        }

        let (dot, dotdot, rest) = Self::split_dots(entries)?;
        let hashed = self.sort_by_hash(rest);

        // Fill entry blocks in hash order.
        let usable = block_size - tail_len;
        let mut leaves: Vec<Vec<(DirHash, &DirEntry)>> = Vec::new();
        let mut cur: Vec<(DirHash, &DirEntry)> = Vec::new();
        let mut used = 0usize;
        for (hash, entry) in hashed {
            let need = record_len(entry, block_size, tail_len)?;
            if used + need > usable && !cur.is_empty() {
                leaves.push(std::mem::take(&mut cur));
                used = 0;
            }
            used += need;
            cur.push((hash, entry));
        }
        if !cur.is_empty() {
            leaves.push(cur);
        }

        // The hash an index entry stores for each entry block: the block's lowest
        // hash, with the continued bit set when that hash also ends the block before
        // it, so a search that lands here knows to look back one block. The first
        // block's hash is implied by its parent and is never stored.
        let mut leaf_hash = vec![0u32; leaves.len()];
        for k in 1..leaves.len() {
            let first = leaves[k][0].0.major;
            let prev_last = leaves[k - 1]
                .last()
                .expect("a block holds an entry")
                .0
                .major;
            leaf_hash[k] = first
                | if first == prev_last {
                    DX_HASH_CONTINUED
                } else {
                    0
                };
        }

        let root_limit = dx_limit(block_size, DX_ROOT_COUNT_OFFSET, self.checksums);
        let node_limit = dx_limit(block_size, DX_NODE_COUNT_OFFSET, self.checksums);
        let indirect_levels = u8::from(leaves.len() > root_limit);
        if indirect_levels > 0 && leaves.len().div_ceil(node_limit) > root_limit {
            return Err(DirError::IndexTooLarge {
                blocks: leaves.len(),
                capacity: root_limit * node_limit,
            });
        }
        debug_assert!(indirect_levels <= DX_MAX_INDIRECT_LEVELS);

        // Logical block numbering: the root, then any interior nodes, then the
        // entry blocks.
        let node_count = if indirect_levels == 0 {
            0
        } else {
            leaves.len().div_ceil(node_limit)
        };
        let first_leaf_block = 1 + node_count;

        let mut nodes: Vec<DirBlock> = Vec::with_capacity(node_count);
        let root_entries: Vec<DxEntry> = if indirect_levels == 0 {
            (0..leaves.len())
                .map(|k| DxEntry {
                    hash: leaf_hash[k],
                    block: (first_leaf_block + k) as u32,
                })
                .collect()
        } else {
            let leaf_indices: Vec<usize> = (0..leaves.len()).collect();
            for chunk in leaf_indices.chunks(node_limit) {
                // Within a node the first child's hash is implied, exactly as in the
                // root; the node's own lower bound is carried by its parent's entry.
                let node_entries: Vec<DxEntry> = chunk
                    .iter()
                    .enumerate()
                    .map(|(j, &k)| DxEntry {
                        hash: if j == 0 { 0 } else { leaf_hash[k] },
                        block: (first_leaf_block + k) as u32,
                    })
                    .collect();
                let mut bytes = vec![0u8; block_size];
                write_dx_node_header(&mut bytes)?;
                write_dx_entries(&mut bytes, DX_NODE_COUNT_OFFSET, node_limit, &node_entries)?;
                nodes.push(DirBlock {
                    bytes,
                    kind: DirBlockKind::Index {
                        count_offset: DX_NODE_COUNT_OFFSET,
                        limit: node_limit,
                    },
                });
            }
            (0..node_count)
                .map(|i| DxEntry {
                    hash: leaf_hash[i * node_limit],
                    block: (1 + i) as u32,
                })
                .collect()
        };

        let mut root = vec![0u8; block_size];
        write_dx_root_header(
            &mut root,
            dot.inode,
            dotdot.inode,
            self.version.to_u8(),
            indirect_levels,
        )?;
        write_dx_entries(&mut root, DX_ROOT_COUNT_OFFSET, root_limit, &root_entries)?;

        let mut blocks = Vec::with_capacity(1 + node_count + leaves.len());
        blocks.push(DirBlock {
            bytes: root,
            kind: DirBlockKind::Index {
                count_offset: DX_ROOT_COUNT_OFFSET,
                limit: root_limit,
            },
        });
        blocks.extend(nodes);
        for leaf in &leaves {
            let refs: Vec<&DirEntry> = leaf.iter().map(|(_, e)| *e).collect();
            blocks.push(DirBlock::entries(pack_one_block(
                &refs, block_size, tail_len,
            )?));
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::{DIR_TAIL_LEN, FileType, read_dx_entries, read_dx_root_info};

    const BS: usize = 4096;
    const SEED: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];

    fn htree() -> HtreeDir {
        HtreeDir {
            seed: SEED,
            version: HashVersion::HalfMd4,
            signedness: HashSignedness::Unsigned,
            checksums: true,
        }
    }

    fn dot_entries(dir_ino: u32, parent_ino: u32) -> Vec<DirEntry> {
        vec![
            DirEntry {
                inode: dir_ino,
                file_type: FileType::Dir,
                name: b".".to_vec(),
            },
            DirEntry {
                inode: parent_ino,
                file_type: FileType::Dir,
                name: b"..".to_vec(),
            },
        ]
    }

    fn many(n: u32) -> Vec<DirEntry> {
        let mut entries = dot_entries(12, 2);
        for i in 0..n {
            entries.push(DirEntry {
                inode: 100 + i,
                file_type: FileType::RegFile,
                name: format!("entry-name-number-{i:06}").into_bytes(),
            });
        }
        entries
    }

    /// Walk a directory block's entries, returning `(inode, name, rec_len)` for each,
    /// mirroring how a reader would.
    fn walk(block: &[u8]) -> Vec<(u32, Vec<u8>, usize)> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < block.len() {
            let (e, rec_len) = DirEntry::read_from(&block[off..], block.len()).unwrap();
            out.push((e.inode, e.name, rec_len));
            off += rec_len;
        }
        out
    }

    /// Every name a directory's blocks hold, however they are laid out. This is the
    /// linear walk a reader that knows nothing of the index performs: the root's
    /// `".."` record and an interior node's unused slot carry it past the index.
    fn names(blocks: &[DirBlock], block_size: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for block in blocks {
            let usable = block_size - DIR_TAIL_LEN;
            let mut off = 0;
            while off < usable {
                let (e, rec_len) = DirEntry::read_from(&block.bytes[off..], block_size).unwrap();
                if e.inode != 0 && e.name != b"." && e.name != b".." {
                    out.push(e.name);
                }
                off += rec_len;
            }
        }
        out.sort();
        out
    }

    #[test]
    fn root_directory_tiles_one_block_with_a_reserved_tail() {
        // Root: ".", "..", and "lost+found".
        let mut entries = dot_entries(2, 2);
        entries.push(DirEntry {
            inode: 11,
            file_type: FileType::Dir,
            name: b"lost+found".to_vec(),
        });
        let blocks = LinearDir {
            tail_len: DIR_TAIL_LEN,
        }
        .build_blocks(&entries, BS)
        .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, DirBlockKind::Entries);
        let walked = walk(&blocks[0].bytes);

        assert_eq!(walked[0].1, b".");
        assert_eq!(walked[1].1, b"..");
        assert_eq!(walked[2].1, b"lost+found");
        assert_eq!(walked[3].0, 0, "tail is a zero-inode slot");

        let total: usize = walked.iter().map(|(_, _, r)| *r).sum();
        assert_eq!(total, BS);
        assert_eq!(walked[2].2, BS - DIR_TAIL_LEN - 12 - 12);
        assert_eq!(walked[3].2, DIR_TAIL_LEN);
    }

    #[test]
    fn lost_found_is_only_dot_entries() {
        let entries = dot_entries(11, 2);
        let blocks = LinearDir {
            tail_len: DIR_TAIL_LEN,
        }
        .build_blocks(&entries, BS)
        .unwrap();
        assert_eq!(blocks.len(), 1);
        let walked = walk(&blocks[0].bytes);
        assert_eq!(walked[0].2, 12);
        assert_eq!(walked[1].2, BS - DIR_TAIL_LEN - 12);
        assert_eq!(walked.last().unwrap().0, 0, "tail");
    }

    #[test]
    fn many_entries_spill_into_multiple_linear_blocks() {
        let entries = many(500);
        let blocks = LinearDir {
            tail_len: DIR_TAIL_LEN,
        }
        .build_blocks(&entries, BS)
        .unwrap();
        assert!(blocks.len() > 1, "500 entries need several blocks");

        let mut seen = 0;
        for block in &blocks {
            let walked = walk(&block.bytes);
            let total: usize = walked.iter().map(|(_, _, r)| *r).sum();
            assert_eq!(total, BS, "block tiles exactly");
            assert_eq!(walked.last().unwrap().0, 0, "block ends with the tail");
            seen += walked.iter().filter(|(ino, _, _)| *ino != 0).count();
        }
        assert_eq!(seen, entries.len(), "every entry placed exactly once");
    }

    #[test]
    fn a_directory_that_fits_in_one_block_is_not_indexed() {
        // The threshold e2fsck uses when it rebuilds a directory: an index costs a
        // block, so a single-block directory stays linear.
        let entries = many(20);
        assert!(fits_in_one_block(&entries, BS, DIR_TAIL_LEN).unwrap());
        let blocks = htree().build_blocks(&entries, BS).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, DirBlockKind::Entries);
    }

    #[test]
    fn a_directory_that_spills_gets_a_root_and_entry_blocks() {
        // 150 entries need two blocks linearly, so the index adds a root: three.
        let entries = many(150);
        assert!(!fits_in_one_block(&entries, BS, DIR_TAIL_LEN).unwrap());
        let blocks = htree().build_blocks(&entries, BS).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(
            blocks[0].kind,
            DirBlockKind::Index {
                count_offset: DX_ROOT_COUNT_OFFSET,
                limit: 507
            }
        );
        assert!(blocks[1..].iter().all(|b| b.kind == DirBlockKind::Entries));

        // The root declares no interior level and names both entry blocks.
        assert_eq!(read_dx_root_info(&blocks[0].bytes).unwrap(), (1, 0));
        let index = read_dx_entries(&blocks[0].bytes, DX_ROOT_COUNT_OFFSET).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index[0], DxEntry { hash: 0, block: 1 });
        assert_eq!(index[1].block, 2);

        // "." and ".." live in the root, and no name is lost.
        assert_eq!(names(&blocks, BS).len(), 150);
        let (dot, _) = DirEntry::read_from(&blocks[0].bytes, BS).unwrap();
        assert_eq!(dot.name, b".");
    }

    #[test]
    fn entry_blocks_are_ordered_by_hash_and_the_index_agrees() {
        let entries = many(400);
        let h = htree();
        let blocks = h.build_blocks(&entries, BS).unwrap();
        let index = read_dx_entries(&blocks[0].bytes, DX_ROOT_COUNT_OFFSET).unwrap();

        // Every name in entry block k hashes at or above the index hash for block k
        // and below the index hash for block k+1.
        for (k, entry) in index.iter().enumerate() {
            let block = &blocks[entry.block as usize];
            let lower = index[k].hash & !DX_HASH_CONTINUED;
            let upper = index.get(k + 1).map(|e| e.hash & !DX_HASH_CONTINUED);
            let mut off = 0;
            while off < BS - DIR_TAIL_LEN {
                let (e, rec_len) = DirEntry::read_from(&block.bytes[off..], BS).unwrap();
                if e.inode != 0 {
                    let major = dir_hash(&e.name, h.version, h.signedness, &h.seed).major;
                    assert!(major >= lower, "{:?} sorts before its block", e.name);
                    if let Some(upper) = upper {
                        assert!(major <= upper, "{:?} sorts after its block", e.name);
                    }
                }
                off += rec_len;
            }
        }
        assert_eq!(names(&blocks, BS).len(), 400);
    }

    #[test]
    fn the_index_hashes_rise_and_never_carry_a_stray_continued_bit() {
        let blocks = htree().build_blocks(&many(2000), BS).unwrap();
        let index = read_dx_entries(&blocks[0].bytes, DX_ROOT_COUNT_OFFSET).unwrap();
        assert!(index.len() > 2, "2000 entries need several blocks");
        for pair in index.windows(2) {
            assert!(
                pair[0].hash < pair[1].hash,
                "index hashes must strictly rise"
            );
        }
        // Distinct names rarely collide, so no block should claim a continued hash.
        assert!(index[1..].iter().all(|e| e.hash & DX_HASH_CONTINUED == 0));
    }

    #[test]
    fn each_block_records_whether_its_first_hash_continues_the_previous() {
        // The continued bit means "a name in the block before me shares my hash", so
        // a search landing here must look back one block. It is set exactly when the
        // hash at the split point straddles the two blocks.
        let h = htree();
        let blocks = h.build_blocks(&many(1200), BS).unwrap();
        let index = read_dx_entries(&blocks[0].bytes, DX_ROOT_COUNT_OFFSET).unwrap();
        assert!(index.len() > 2, "1200 entries need several blocks");

        for (k, entry) in index.iter().enumerate().skip(1) {
            let prev = &blocks[index[k - 1].block as usize];
            let last_major = walk(&prev.bytes)
                .iter()
                .filter(|(ino, _, _)| *ino != 0)
                .map(|(_, name, _)| dir_hash(name, h.version, h.signedness, &h.seed).major)
                .next_back()
                .expect("a block holds an entry");
            let first_major = entry.hash & !DX_HASH_CONTINUED;
            let continued = entry.hash & DX_HASH_CONTINUED != 0;
            assert_eq!(
                continued,
                first_major == last_major,
                "block {k} records the wrong continuation"
            );
        }
    }

    #[test]
    fn a_directory_too_large_for_the_root_grows_an_interior_level() {
        // The root of a 4096-byte block names 507 entry blocks. Shrink the block so
        // the interior level is reachable without a million entries: a 1024-byte
        // block's root names 123, its nodes 126.
        const SMALL: usize = 1024;
        assert_eq!(dx_limit(SMALL, DX_ROOT_COUNT_OFFSET, true), 123);
        assert_eq!(dx_limit(SMALL, DX_NODE_COUNT_OFFSET, true), 126);

        // Each 1012-byte entry block holds 31 of these 32-byte records, so 4600
        // entries need 149 blocks -- past the root's 123.
        let entries = many(4600);
        let blocks = htree().build_blocks(&entries, SMALL).unwrap();
        assert_eq!(read_dx_root_info(&blocks[0].bytes).unwrap().1, 1);

        let root = read_dx_entries(&blocks[0].bytes, DX_ROOT_COUNT_OFFSET).unwrap();
        assert_eq!(root.len(), 2, "149 entry blocks need two interior nodes");
        assert_eq!(root[0], DxEntry { hash: 0, block: 1 });
        assert_eq!(root[1].block, 2);

        // The interior nodes sit at logical blocks 1 and 2, entry blocks after them.
        assert_eq!(
            blocks[1].kind,
            DirBlockKind::Index {
                count_offset: DX_NODE_COUNT_OFFSET,
                limit: 126
            }
        );
        assert_eq!(blocks[2].kind, blocks[1].kind);
        assert!(blocks[3..].iter().all(|b| b.kind == DirBlockKind::Entries));

        // The nodes together name every entry block exactly once, in order.
        let mut named: Vec<u32> = Vec::new();
        for node in &blocks[1..=2] {
            named.extend(
                read_dx_entries(&node.bytes, DX_NODE_COUNT_OFFSET)
                    .unwrap()
                    .iter()
                    .map(|e| e.block),
            );
        }
        let expect: Vec<u32> = (3..blocks.len() as u32).collect();
        assert_eq!(named, expect);
        assert_eq!(names(&blocks, SMALL).len(), 4600);
    }

    #[test]
    fn a_directory_without_dot_entries_is_rejected() {
        let entries: Vec<DirEntry> = (0..300)
            .map(|i| DirEntry {
                inode: 100 + i,
                file_type: FileType::RegFile,
                name: format!("entry-name-number-{i:06}").into_bytes(),
            })
            .collect();
        assert_eq!(
            htree().build_blocks(&entries, BS),
            Err(DirError::MissingDotEntries)
        );
    }

    #[test]
    fn an_entry_larger_than_a_block_is_rejected() {
        let mut entries = dot_entries(12, 2);
        entries.push(DirEntry {
            inode: 100,
            file_type: FileType::RegFile,
            name: vec![b'a'; 255],
        });
        assert!(
            LinearDir {
                tail_len: DIR_TAIL_LEN
            }
            .build_blocks(&entries, 128)
            .is_err()
        );
    }

    #[test]
    fn clearing_checksums_gives_an_index_block_one_more_entry() {
        let mut h = htree();
        h.checksums = false;
        let blocks = h.build_blocks(&many(150), BS).unwrap();
        assert_eq!(
            blocks[0].kind,
            DirBlockKind::Index {
                count_offset: DX_ROOT_COUNT_OFFSET,
                limit: 508
            }
        );
    }
}
