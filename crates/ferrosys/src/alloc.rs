//! The block allocator: a multi-range region allocator over a [`Layout`]'s free
//! space.
//!
//! This module is pure — it decides block placement over an in-memory bitmap and
//! performs no I/O. The allocator is seeded from a layout with every fixed
//! metadata block already marked used, then hands out data blocks for file
//! contents and the resize inode's map. Allocations are returned as *multiple*
//! ranges: a request that cannot be satisfied by one contiguous run spans several,
//! which is what lets a file straddle a reserved window once backups fragment the
//! free space.
//!
//! The used-block bitmap is laid out exactly as ext4's on-disk block bitmaps —
//! bit-packed, least-significant-bit first, one 4 KiB block bitmap's worth of bits
//! per group — so the materializer serializes each group's bitmap as a direct byte
//! slice with no repacking.

use crate::geometry::{BlockRange, Layout};

/// A block allocation that could not be satisfied.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AllocError {
    /// Fewer free blocks remain than were requested.
    #[error("out of space: requested {requested} blocks, {available} free")]
    #[non_exhaustive]
    OutOfSpace {
        /// Blocks requested.
        requested: u64,
        /// Free blocks available.
        available: u64,
    },
}

/// A bit-packed used-block bitmap and a first-fit allocator over it.
///
/// The bitmap spans `group_count * blocks_per_group` bits — a whole number of
/// per-group bitmaps. Blocks past the filesystem's real size (the padding tail of
/// the final group's bitmap) are marked used at construction so they are never
/// handed out and serialize as the set padding bits an external checker expects.
///
/// It holds one bit per block of the whole filesystem, so it occupies
/// `total_blocks / 8` bytes however the image is written: 128 MiB for a 4 TiB
/// filesystem at a 4 KiB block, and 1 GiB for a 32 TiB one. That is the same bitmap the
/// image itself carries, held once for the whole filesystem rather than a group at a
/// time, because a single allocation may span groups.
#[derive(Clone, Debug)]
pub struct Allocator {
    /// The used bitmap, LSB-first, `bytes_per_group` bytes per group.
    bits: Vec<u8>,
    /// Real blocks in the filesystem; blocks at or beyond this are padding.
    total_blocks: u64,
    /// Blocks per group.
    blocks_per_group: u32,
    /// Bytes of bitmap per group (`blocks_per_group / 8`).
    bytes_per_group: usize,
    /// First block the filesystem addresses (0 for 4 KiB, 1 for 1 KiB).
    first_data_block: u64,
    /// First block a scan may consider free; advanced as allocation proceeds.
    cursor: u64,
}

impl Allocator {
    /// Build an allocator for `layout` with every fixed metadata block — superblock
    /// and descriptor copies, reserved descriptor blocks, and the flex-packed
    /// bitmaps and inode tables — already marked used, plus the final group's
    /// bitmap padding. What remains free is the space for file data.
    #[must_use]
    pub fn new(layout: &Layout) -> Self {
        let bytes_per_group = (layout.blocks_per_group / 8) as usize;
        let capacity_bits = u64::from(layout.group_count) * u64::from(layout.blocks_per_group);
        let mut alloc = Self {
            bits: vec![0u8; (capacity_bits / 8) as usize],
            total_blocks: layout.total_blocks,
            blocks_per_group: layout.blocks_per_group,
            bytes_per_group,
            first_data_block: u64::from(layout.first_data_block),
            cursor: u64::from(layout.first_data_block),
        };

        // The padding tail of the final group's bitmap: positions past the last real
        // block, which the bitmap must still describe as used.
        let last_described = u64::from(layout.first_data_block) + capacity_bits;
        for b in layout.total_blocks..last_described {
            alloc.set(b);
        }
        // Fixed metadata.
        for r in layout.metadata_regions() {
            alloc.mark_used(r);
        }
        alloc
    }

    /// Mark the blocks in `range` used.
    ///
    /// A block outside the window the group bitmaps describe — below the first data
    /// block, or past the last position the final group's bitmap covers — has no bit to
    /// set and is skipped. Such a block is never allocatable in the first place.
    pub fn mark_used(&mut self, range: BlockRange) {
        for b in range.start..range.end() {
            self.set(b);
        }
    }

    /// Whether block `b` is marked used.
    ///
    /// A block outside the window the group bitmaps describe reads as used: it is not
    /// a block the filesystem can hand out.
    #[must_use]
    pub fn is_used(&self, b: u64) -> bool {
        self.bit(b)
            .is_none_or(|i| self.bits[(i / 8) as usize] & (1 << (i % 8)) != 0)
    }

    /// Allocate `count` blocks, returning the runs that make them up — one when a
    /// contiguous run is free, several when the free space is fragmented. The runs
    /// are ordered by block number.
    ///
    /// # Errors
    ///
    /// [`AllocError::OutOfSpace`] if fewer than `count` blocks are free; on error
    /// nothing is marked used.
    pub fn allocate(&mut self, count: u64) -> Result<Vec<BlockRange>, AllocError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // Gather runs without committing, so a shortfall leaves the bitmap untouched.
        let mut ranges = Vec::new();
        let mut remaining = count;
        let mut i = self.cursor;
        let cap = self.total_blocks;
        while remaining > 0 {
            while i < cap && self.is_used(i) {
                i += 1;
            }
            if i >= cap {
                return Err(AllocError::OutOfSpace {
                    requested: count,
                    available: count - remaining,
                });
            }
            let start = i;
            while i < cap && !self.is_used(i) && (i - start) < remaining {
                i += 1;
            }
            let len = i - start;
            ranges.push(BlockRange { start, len });
            remaining -= len;
        }
        for r in &ranges {
            self.mark_used(*r);
        }
        self.cursor = i;
        Ok(ranges)
    }

    /// Allocate `count` blocks as a single contiguous run, or return `None` if no
    /// free run that long exists.
    ///
    /// Unlike [`allocate`](Self::allocate) this never fragments: it scans the whole
    /// filesystem for the first free run of at least `count` blocks and takes the
    /// front of it. It is used for the journal, which maps most cleanly as one
    /// extent; the caller falls back to [`allocate`](Self::allocate) when the free
    /// space is too fragmented for a single run. The scan starts from the first data
    /// block rather than the cursor, so a run earlier than the cursor is still found.
    #[must_use]
    pub fn allocate_contiguous(&mut self, count: u64) -> Option<BlockRange> {
        if count == 0 {
            return Some(BlockRange {
                start: self.first_data_block,
                len: 0,
            });
        }
        let cap = self.total_blocks;
        let mut i = self.first_data_block;
        while i < cap {
            while i < cap && self.is_used(i) {
                i += 1;
            }
            let start = i;
            while i < cap && !self.is_used(i) {
                i += 1;
            }
            if i - start >= count {
                let range = BlockRange { start, len: count };
                self.mark_used(range);
                return Some(range);
            }
        }
        None
    }

    /// Allocate exactly one block, the common case for a directory block or the
    /// resize inode's double-indirect block.
    ///
    /// # Errors
    ///
    /// [`AllocError::OutOfSpace`] if no block is free.
    pub fn allocate_one(&mut self) -> Result<u64, AllocError> {
        Ok(self.allocate(1)?[0].start)
    }

    /// The on-disk block bitmap for group `index`: the bit-packed used state of that
    /// group's blocks, ready to write as one bitmap block. `None` when `index` is past
    /// the last group of the layout the allocator was built over.
    #[must_use]
    pub fn group_bitmap(&self, index: u32) -> Option<&[u8]> {
        let start = index as usize * self.bytes_per_group;
        self.bits.get(start..start + self.bytes_per_group)
    }

    /// Free blocks across the whole filesystem.
    ///
    /// The bitmap describes blocks from the first data block onward, so the real blocks
    /// occupy its first `total_blocks - first_data_block` bit positions; the used ones
    /// among them are subtracted from that count. The final group's padding tail sits
    /// past those positions and is not counted.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        let positions = self.total_blocks - self.first_data_block;
        positions - used_in_prefix(&self.bits, positions)
    }

    /// Free blocks in group `index`.
    #[must_use]
    pub fn group_free_count(&self, index: u32) -> u32 {
        let start = self.first_data_block + u64::from(index) * u64::from(self.blocks_per_group);
        let end = (start + u64::from(self.blocks_per_group)).min(self.total_blocks);
        let positions = end.saturating_sub(start);
        let Some(bytes) = self.group_bitmap(index) else {
            return 0;
        };
        (positions - used_in_prefix(bytes, positions)) as u32
    }

    /// The bitmap position of block `b`, or `None` when no bitmap position describes
    /// it. A group's bitmap describes the blocks from
    /// `first_data_block + group * blocks_per_group` onward, so the whole bitmap is
    /// indexed from the first data block, not from block zero: at a 1024-byte block
    /// size, where the first data block is one, block zero has no bit. The bitmaps end
    /// at the last position the final group's bitmap covers, past the end of the
    /// filesystem itself.
    fn bit(&self, b: u64) -> Option<u64> {
        let i = b.checked_sub(self.first_data_block)?;
        ((i / 8) < self.bits.len() as u64).then_some(i)
    }

    fn set(&mut self, b: u64) {
        if let Some(i) = self.bit(b) {
            self.bits[(i / 8) as usize] |= 1 << (i % 8);
        }
    }

    #[cfg(test)]
    fn clear(&mut self, b: u64) {
        if let Some(i) = self.bit(b) {
            self.bits[(i / 8) as usize] &= !(1 << (i % 8));
        }
    }
}

/// Count the set bits among the first `n` bit positions of `bits`, bit `i` living in
/// byte `i / 8` at position `i % 8` — the used-block count of a bitmap prefix. A whole
/// byte is one `count_ones`; a partial final byte is masked to its low `n % 8` bits so
/// nothing past position `n` is counted. `n` must not exceed `bits.len() * 8`.
fn used_in_prefix(bits: &[u8], n: u64) -> u64 {
    let whole = (n / 8) as usize;
    let mut used: u64 = bits[..whole]
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum();
    let rem = (n % 8) as u32;
    if rem != 0 {
        let mask = (1u8 << rem) - 1;
        used += u64::from((bits[whole] & mask).count_ones());
    }
    used
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::FeatureSet;
    use crate::geometry::{GrowReservation, PlanRequest, plan_layout};

    const MIB: u64 = 1024 * 1024;
    const GROW_32G: u64 = 32 * 1024 * MIB;

    fn layout(mib: u64) -> Layout {
        plan_layout(
            &PlanRequest::new(mib * MIB, FeatureSet::default())
                .grow(GrowReservation::UpTo(GROW_32G)),
        )
        .unwrap()
    }

    #[test]
    fn the_bitmap_is_indexed_from_the_first_data_block() {
        // A group's bitmap describes blocks from `first_data_block + group * bpg`
        // onward, so at a 1024-byte block size, where the first data block is one,
        // bit zero of group zero's bitmap is the superblock and not a phantom block
        // zero. Indexing the bitmap by absolute block number instead shifts every
        // group after the first by one.
        let fs = FeatureSet {
            block_size: 1024,
            ..FeatureSet::default()
        };
        let l = plan_layout(&PlanRequest::new(64 * MIB, fs).grow(GrowReservation::UpTo(GROW_32G)))
            .expect("plan");
        assert_eq!(l.first_data_block, 1);

        let alloc = Allocator::new(&l);
        assert!(alloc.is_used(1), "the superblock is block 1");
        assert_eq!(
            alloc.group_bitmap(0).expect("group 0")[0] & 1,
            1,
            "and it is bit 0 of group 0"
        );

        // Group 1 opens with its backup superblock, which is bit 0 of its bitmap.
        let g1 = l.groups[1].start_block;
        assert!(l.groups[1].has_super);
        assert!(alloc.is_used(g1));
        assert_eq!(alloc.group_bitmap(1).expect("group 1")[0] & 1, 1);
    }

    #[test]
    fn metadata_is_marked_used_from_the_layout() {
        let l = layout(64);
        let a = Allocator::new(&l);
        // Superblock, GDT, and reserved GDT: blocks 0..=4 used.
        for b in 0..=4 {
            assert!(a.is_used(b), "block {b} (super/gdt/rgdt) should be used");
        }
        // Block bitmap (5), inode bitmap (21), inode table (37..1060) used.
        assert!(a.is_used(5));
        assert!(a.is_used(21));
        assert!(a.is_used(37));
        assert!(a.is_used(1060));
        // A block just past the inode table is free.
        assert!(!a.is_used(1061));
        // The unused table slots the single-member flex reserves stay free and
        // available for data — blocks between the used bitmaps and table.
        assert!(!a.is_used(6), "unused block-bitmap slot is free");
        assert!(!a.is_used(20), "unused inode-bitmap slot is free");
        assert!(!a.is_used(36));
    }

    #[test]
    fn allocate_returns_contiguous_run_when_possible() {
        let l = layout(64);
        let mut a = Allocator::new(&l);
        let ranges = a.allocate(4).unwrap();
        assert_eq!(ranges.len(), 1, "free space is contiguous here");
        assert_eq!(ranges[0].len, 4);
        // The allocated blocks are now used.
        for b in ranges[0].start..ranges[0].end() {
            assert!(a.is_used(b));
        }
    }

    #[test]
    fn allocate_spans_multiple_ranges_across_a_reserved_window() {
        // Free a small pocket, then a reserved block, then more free space, and ask
        // for more than the pocket holds: the allocation must straddle the window.
        let l = layout(64);
        let mut a = Allocator::new(&l);
        // Mark everything used, then open two pockets separated by a used block: a
        // request larger than either pocket must span both.
        for b in 0..l.total_blocks {
            a.set(b);
        }
        for b in [100u64, 101, 103, 104] {
            a.clear(b);
        }
        a.cursor = 100;
        let ranges = a.allocate(4).unwrap();
        assert_eq!(
            ranges,
            vec![
                BlockRange { start: 100, len: 2 },
                BlockRange { start: 103, len: 2 },
            ]
        );
    }

    #[test]
    fn allocate_contiguous_takes_one_run_and_skips_short_gaps() {
        let l = layout(64);
        let mut a = Allocator::new(&l);
        // Open a short pocket then a long free run; a request longer than the pocket
        // must land wholly in the long run, as one range.
        for b in 0..l.total_blocks {
            a.set(b);
        }
        for b in [50u64, 51] {
            a.clear(b);
        }
        for b in 200..400 {
            a.clear(b);
        }
        let range = a.allocate_contiguous(100).expect("a 100-block run is free");
        assert_eq!(
            range,
            BlockRange {
                start: 200,
                len: 100
            }
        );
        for b in range.start..range.end() {
            assert!(a.is_used(b));
        }
        // The short pocket is untouched.
        assert!(!a.is_used(50));
    }

    #[test]
    fn allocate_contiguous_returns_none_when_no_run_is_long_enough() {
        let l = layout(64);
        let mut a = Allocator::new(&l);
        for b in 0..l.total_blocks {
            a.set(b);
        }
        for b in [10u64, 11, 20, 21, 22] {
            a.clear(b);
        }
        assert_eq!(a.allocate_contiguous(4), None);
    }

    #[test]
    fn out_of_space_leaves_the_bitmap_untouched() {
        let l = layout(64);
        let mut a = Allocator::new(&l);
        let free_before = a.free_count();
        let err = a.allocate(free_before + 1).unwrap_err();
        assert!(matches!(err, AllocError::OutOfSpace { .. }));
        assert_eq!(a.free_count(), free_before, "no partial allocation");
    }

    #[test]
    fn group_bitmap_slices_align_to_groups() {
        let l = layout(512);
        let a = Allocator::new(&l);
        // Each group's bitmap is one block-bitmap's worth of bytes.
        let g0 = a.group_bitmap(0).expect("group 0");
        assert_eq!(g0.len(), (l.blocks_per_group / 8) as usize);
        // Group 0's first byte encodes blocks 0..=7: super/gdt/rgdt/bbmp all used.
        assert_eq!(g0[0], 0b1111_1111);
    }

    #[test]
    fn padding_tail_of_final_group_is_marked_used() {
        // 200 MiB: final group holds 18432 of 32768 blocks; the rest are padding.
        let l = layout(200);
        let a = Allocator::new(&l);
        let last_start = u64::from(l.blocks_per_group);
        assert!(a.is_used(last_start + 18432), "first padding block");
        assert!(a.is_used(last_start + 32767), "last padding block");
        // Free count excludes padding.
        assert!(a.free_count() < l.total_blocks);
    }

    #[test]
    fn free_counts_are_consistent_between_whole_and_per_group() {
        let l = layout(512);
        let a = Allocator::new(&l);
        let per_group: u64 = (0..l.group_count)
            .map(|g| u64::from(a.group_free_count(g)))
            .sum();
        assert_eq!(per_group, a.free_count());
    }

    #[test]
    fn popcount_free_count_matches_a_block_by_block_scan() {
        // The popcount count equals a block-by-block `is_used` scan, whole-filesystem
        // and per-group, including the partial final group whose bitmap carries a
        // used-marked padding tail past the last real block. Allocating first makes the
        // used set more than the freshly-formatted metadata.
        for mib in [64u64, 512] {
            let l = layout(mib);
            let mut a = Allocator::new(&l);
            a.allocate(1000).expect("room for a scattered run");
            let scan = |lo: u64, hi: u64| (lo..hi).filter(|&b| !a.is_used(b)).count() as u64;

            let fdb = u64::from(l.first_data_block);
            assert_eq!(
                a.free_count(),
                scan(fdb, l.total_blocks),
                "{mib} MiB whole-fs"
            );
            for g in 0..l.group_count {
                let start = fdb + u64::from(g) * u64::from(l.blocks_per_group);
                let end = (start + u64::from(l.blocks_per_group)).min(l.total_blocks);
                assert_eq!(
                    u64::from(a.group_free_count(g)),
                    scan(start, end),
                    "{mib} MiB group {g}"
                );
            }
        }
    }
}
