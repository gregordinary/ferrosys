//! Which blocks a container uses, held to what its space manager records.
//!
//! The space manager records, chunk by chunk, which of the container's blocks are in use. The
//! free queues hold the runs a transaction freed until a later one may take them again, and
//! the internal pool holds the space manager's own blocks under a bitmap of its own. None of
//! it is read to read a file, and all of it is what a write trusts: a block in use that the
//! space manager records as free is a block the next write may take.
//!
//! So a scan gathers every block the container reaches and holds the records to them:
//! block zero, the two checkpoint areas, the internal pool and its bitmaps, the container's
//! object map with every version it maps, and for each volume its object map with every
//! version it maps and its tree of snapshots, its extent-reference and snapshot trees, each
//! snapshot's copy of the superblock and extent-reference tree, and every run of data those
//! trees record.
//!
//! # What it holds the container to
//!
//! Each rule holds on every container macOS 14, 15, 26 and 27 were observed to write, through
//! snapshots taken and deleted, clones, and volumes encrypted and decrypted:
//!
//! - **Every block in use is marked in use, and one thing reaches each block.** A block in use
//!   that its chunk's bitmap marks free, a block two things reach, and a run the main free
//!   queue holds as freed that something still reaches are each [`Severity::Integrity`]: a
//!   write may take the block.
//! - **Every block marked in use is reached**, or held by the main free queue. One nothing
//!   reaches is space spent on nothing, [`Severity::Conformance`], where every part of the
//!   container is walked; where a volume is one this reader does not read, or the reaper is
//!   deleting something, it is noted at [`Severity::Cosmetic`].
//! - **The counts it keeps about itself** are [`Severity::Conformance`]: each chunk's free count
//!   is what its bitmap leaves, the space manager's is the chunks' total, each free queue's is
//!   the blocks it holds and its oldest transaction the oldest it holds, a volume's count of its
//!   own blocks is what its object map, its trees and its data take — its snapshots' copies of
//!   its superblock are counted by the container — and the space manager's reserve is what the
//!   volumes reserve and, of that, what each takes.
//! - **The internal pool**: its bitmap marks the space manager's chunk-info, address and bitmap
//!   blocks and the runs its own free queue holds, and no other block. The arrays the space
//!   manager keeps past its fields follow one another from the end of the structure, each
//!   padded to eight bytes, and its free list of bitmap blocks runs from its head to its tail
//!   through every block kept for the bitmap and not in use.
//! - **The live checkpoint's mappings**: each object lies whole inside the checkpoint data area,
//!   apart from every other, and records the type, subtype and identifier its mapping names; the
//!   last mapping block alone carries the flag saying so.
//! - **The reaper** carries the flag the format says is always set, and records a list exactly
//!   where it records list blocks.
//! - **A second device's account**, which only a Fusion set has, counts nothing, keeps its free
//!   queue empty, and records its list as beginning where the main device's ends.
//!
//! A run of one block is kept in a free queue as its key alone, and a record of an object map
//! standing for a deleted object reaches nothing: its block is the freed one, which the main
//! free queue holds. Two parts of the space manager are read past: the allocation zones, zero
//! on every container observed, and every checkpoint but the live one. `fsck_apfs` passes a
//! mapping's subtype, its reserved word and its volume, the reaper's list count and the second
//! device's list offset, which is why this holds them.
//!
//! Nothing the space manager records sizes an allocation before it is held: the internal pool
//! to the bitmap that must hold a bit for each of its blocks, and every run a free queue holds
//! to the container, or to the pool for the pool's own queue.
//!
//! This module does I/O, through the container it borrows.

use std::fmt;
use std::io::{Read, Seek};

use crate::finding::Severity;

use super::btree::{self, Children, Order, TreeRoot};
use super::container::{Container, Expect, ReadError, Xid};
use super::geometry::{ChunkGeometry, chunk_span, manager_arrays, second_list_offset};
use super::ondisk::{
    CHECKPOINT_AREA_IS_TREE, CHECKPOINT_MAP_LAST, CheckpointMapping, ChunkInfo, ChunkList,
    FreeQueue, FreeQueueKey, KeyHeader, MapValue, PhysicalExtent, REAPER_ALWAYS, REAPER_CONTINUE,
    ReapList, Reaper, SnapshotMeta, SpaceDevice, SpaceManager, Storage, kind, record_kind,
};
use super::scan::{Category, Scan};

/// What reaches a run of blocks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum By {
    BlockZero,
    DescriptorArea,
    DataArea,
    PoolBitmaps,
    InternalPool,
    ContainerMap,
    ContainerMapped,
    Keybag,
    MediaKeybag,
    Jumpstart,
    MainQueue,
    /// A part of the volume in a slot.
    Volume(usize, Part),
}

/// The part of a volume a run belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    Map,
    Mapped,
    ExtentReferences,
    Snapshots,
    SnapshotCopy,
    Data,
}

impl fmt::Display for By {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            By::BlockZero => f.write_str("block zero"),
            By::DescriptorArea => f.write_str("the checkpoint descriptor area"),
            By::DataArea => f.write_str("the checkpoint data area"),
            By::PoolBitmaps => f.write_str("the internal pool's bitmaps"),
            By::InternalPool => f.write_str("the internal pool"),
            By::ContainerMap => f.write_str("the container's object map"),
            By::ContainerMapped => f.write_str("an object the container's object map maps"),
            By::Keybag => f.write_str("the container's keybag"),
            By::MediaKeybag => f.write_str("the container's media keybag"),
            By::Jumpstart => f.write_str("the embedded boot driver's description"),
            By::MainQueue => f.write_str("the main free queue"),
            By::Volume(slot, part) => {
                let what = match part {
                    Part::Map => "object map",
                    Part::Mapped => "object map's objects",
                    Part::ExtentReferences => "extent-reference trees",
                    Part::Snapshots => "snapshot tree",
                    Part::SnapshotCopy => "snapshots' superblock copies",
                    Part::Data => "data",
                };
                write!(f, "volume {slot}'s {what}")
            }
        }
    }
}

/// A run of blocks, `start` up to `end`, and what reaches it.
#[derive(Clone, Copy, Debug)]
struct Run {
    start: u64,
    end: u64,
    by: By,
}

/// Everything the check gathers.
struct Space {
    block_count: u64,
    block_size: u64,
    runs: Vec<Run>,
    /// What the container holds that is not walked, so blocks it may use are not reached.
    partial: Vec<String>,
}

impl Space {
    /// Note that `by` reaches `count` blocks from `start`. The part past the container's end is
    /// reported and left out; the part inside it is reached.
    fn reach(&mut self, scan: &mut Scan, start: u64, count: u64, by: By) {
        if count == 0 {
            return;
        }
        let end = start.saturating_add(count);
        if end > self.block_count {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(start),
                None,
                format!(
                    "{by} reaches {count} blocks from block {start}, past the container's {} \
                     blocks",
                    self.block_count
                ),
            );
        }
        let end = end.min(self.block_count);
        if start < end {
            self.runs.push(Run { start, end, by });
        }
    }

    /// Blocks an object of `bytes` takes.
    fn blocks(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.block_size)
    }
}

/// Hold the container's record of the blocks it uses to what it holds.
pub(super) fn check<R: Read + Seek>(container: &mut Container<R>, scan: &mut Scan) {
    let sb = container.superblock().clone();
    let live = container.xid();
    let mut space = Space {
        block_count: sb.block_count,
        block_size: u64::from(sb.block_size),
        runs: Vec::new(),
        partial: Vec::new(),
    };
    let areas = sb.checkpoint;
    space.reach(scan, 0, 1, By::BlockZero);
    space.reach(
        scan,
        areas.desc_base,
        u64::from(sb.desc_area_blocks()),
        By::DescriptorArea,
    );
    let data_blocks = u64::from(areas.data_blocks & !CHECKPOINT_AREA_IS_TREE);
    space.reach(scan, areas.data_base, data_blocks, By::DataArea);
    // The data area as the mappings are held to it, where it lies inside the container. One that
    // does not is reported once, above, and each mapping is held to the container instead.
    let data = areas
        .data_base
        .checked_add(data_blocks)
        .filter(|&end| end <= sb.block_count)
        .map(|end| (areas.data_base, end));
    space.reach(scan, sb.keylocker.start, sb.keylocker.count, By::Keybag);
    space.reach(
        scan,
        sb.media_keybag.start,
        sb.media_keybag.count,
        By::MediaKeybag,
    );
    if sb.efi_jumpstart != 0 {
        space.reach(scan, sb.efi_jumpstart, 1, By::Jumpstart);
        space
            .partial
            .push("the embedded boot driver's extents".to_string());
    }
    if sb.evict_mapping_tree_oid != 0 || sb.blocked_out.count != 0 {
        space.partial.push("a shrink in progress".to_string());
    }

    let mappings = match container.checkpoint_mappings() {
        Ok(mappings) => mappings,
        Err(e) => {
            scan.failed(None, "the live checkpoint's mappings", &e);
            return;
        }
    };
    hold_mappings(container, &space, data, &sb, scan);
    let Some(sm_mapping) = mappings
        .iter()
        .find(|m| m.oid == sb.space_manager_oid)
        .copied()
    else {
        scan.at(
            Category::Space,
            Severity::Structural,
            Some(container.checkpoint_address()),
            None,
            format!(
                "the live checkpoint maps no space manager, object {}",
                sb.space_manager_oid
            ),
        );
        return;
    };
    let object = match container.read_ephemeral(&sm_mapping, kind::SPACE_MANAGER, live) {
        Ok(object) => object,
        Err(e) => {
            scan.failed(None, "the space manager", &e);
            return;
        }
    };
    let sm = match SpaceManager::read_from(&object) {
        Ok(sm) => sm,
        Err(e) => {
            scan.failed(None, "the space manager", &e.into());
            return;
        }
    };
    let at = Some(sm_mapping.address);
    if !hold_geometry(&sm, &sb, at, scan) {
        return;
    }
    let pool = hold_pool(&sm, &sb, at, scan);
    space.reach(
        scan,
        sm.ip_bm_base,
        u64::from(sm.ip_bm_block_count),
        By::PoolBitmaps,
    );
    space.reach(scan, sm.ip_base, sm.ip_block_count, By::InternalPool);

    let main_queue = read_queue(
        container,
        &sm,
        SpaceManager::MAIN_QUEUE,
        "main",
        (0, sb.block_count),
        at,
        scan,
    );
    let pool_queue = if pool {
        read_queue(
            container,
            &sm,
            SpaceManager::INTERNAL_POOL,
            "internal pool's",
            (sm.ip_base, sm.ip_base + sm.ip_block_count),
            at,
            scan,
        )
    } else {
        None
    };
    // A second device is a Fusion set's, which this crate does not read and refuses by its
    // incompatible feature. Every container macOS wrote counts nothing on it, keeps its free
    // queue empty, and records its list as beginning where the main device's ends.
    let main = &sm.devices[SpaceManager::MAIN];
    let listed = u64::from(if main.cab_count != 0 {
        main.cab_count
    } else {
        main.cib_count
    });
    let second = SpaceDevice {
        addr_offset: 0,
        ..sm.devices[1]
    };
    if second != SpaceDevice::default()
        || sm.free_queues[2] != FreeQueue::default()
        || u64::from(sm.devices[1].addr_offset)
            != second_list_offset(u64::from(main.addr_offset), listed)
    {
        scan.at(
            Category::Space,
            Severity::Conformance,
            at,
            None,
            "the space manager keeps an account of a second device, which only a Fusion set has"
                .to_string(),
        );
    }
    hold_arrays(&sm, &object, live, at, scan);
    read_reaper(container, &mappings, sb.reaper_oid, live, &mut space, scan);

    reach_map(
        container,
        &mut space,
        scan,
        sb.object_map_oid,
        By::ContainerMap,
        By::ContainerMapped,
    );
    let readable: Vec<_> = container.volumes().to_vec();
    for (slot, _) in sb.volumes() {
        match readable.iter().find(|v| v.slot == slot) {
            Some(volume) if volume.refusal().is_none() => {
                reach_volume(container, &mut space, scan, slot, &volume.superblock);
            }
            _ => space.partial.push(format!(
                "the volume in slot {slot}, which this reader does not read"
            )),
        }
    }

    // What the space manager keeps reserved for volumes is what they reserve, and what it
    // counts as allocated from that is, for each volume, the smaller of what the volume reserves
    // and what it takes: a volume allocated past its reserve counts its reserve, and one within
    // it counts what it allocated (observed, macOS 14 to 27).
    if space.partial.is_empty() {
        let (mut reserved, mut taken) = (0u64, 0u64);
        for (slot, _) in sb.volumes() {
            if let Some(volume) = readable.iter().find(|v| v.slot == slot) {
                let v = &volume.superblock;
                reserved = reserved.saturating_add(v.reserve_blocks);
                taken = taken.saturating_add(v.reserve_blocks.min(v.allocated_blocks));
            }
        }
        if (reserved, taken) != (sm.fs_reserve_block_count, sm.fs_reserve_alloc_count) {
            scan.at(
                Category::Space,
                Severity::Conformance,
                at,
                None,
                format!(
                    "the space manager records {} blocks reserved for volumes, {} of them \
                     allocated, and the volumes reserve {reserved}, {taken} of them allocated",
                    sm.fs_reserve_block_count, sm.fs_reserve_alloc_count
                ),
            );
        }
    }
    let reached = merge(&mut space, scan);
    let Some(main_queue) = main_queue else {
        return;
    };
    let mut accounted = reached.clone();
    for &(start, end) in &main_queue {
        if let Some(by) = covered(&reached, start, end) {
            scan.at(
                Category::Space,
                Severity::Integrity,
                Some(start),
                None,
                format!(
                    "the main free queue holds blocks {start} to {} as freed, and {by} still \
                     reaches them",
                    end - 1
                ),
            );
        }
        accounted.push((start, end, By::MainQueue));
    }
    accounted.sort_by_key(|r| r.0);
    compare_chunks(
        container, &sm, &object, &space, &accounted, pool_queue, at, scan,
    );
}

/// Hold every mapping block of the live checkpoint and every mapping in it: the last block
/// flagged as the last and no other, each mapping whole blocks inside the data area, apart from
/// every other, naming no volume the container does not list, and naming an object that
/// records the mapping's type, subtype and identifier. `data` is the data area's first block and
/// its end, where it lies inside the container; where it does not, each mapping is held to the
/// container instead.
fn hold_mappings<R: Read + Seek>(
    container: &mut Container<R>,
    space: &Space,
    data: Option<(u64, u64)>,
    sb: &super::ondisk::ContainerSuperblock,
    scan: &mut Scan,
) {
    let live = container.xid();
    let maps = match container.checkpoint_maps() {
        Ok(maps) => maps,
        Err(e) => {
            scan.failed(None, "the live checkpoint's mappings", &e);
            return;
        }
    };
    let last = maps.len().saturating_sub(1);
    let (low, high) = data.unwrap_or((0, sb.block_count));
    let area = if data.is_some() {
        "the checkpoint data area"
    } else {
        "the container"
    };
    let mut placed: Vec<(u64, u64, u64)> = Vec::new();
    for (i, (address, map, mappings)) in maps.iter().enumerate() {
        // The last mapping block of a checkpoint alone carries the flag (reference p. 42).
        let want = if i == last { CHECKPOINT_MAP_LAST } else { 0 };
        if map.flags != want {
            scan.at(
                Category::Space,
                Severity::Conformance,
                Some(*address),
                None,
                format!(
                    "mapping block {} of {} records flags {:#x}, where the last block records {:#x} \
                     and the others none",
                    i + 1,
                    maps.len(),
                    map.flags,
                    CHECKPOINT_MAP_LAST
                ),
            );
        }
        for m in mappings {
            let blocks = space.blocks(u64::from(m.size));
            let inside =
                m.address >= low && m.address.checked_add(blocks).is_some_and(|end| end <= high);
            if !inside || u64::from(m.size) % space.block_size != 0 || m.size == 0 {
                scan.at(
                    Category::Space,
                    Severity::Structural,
                    Some(m.address),
                    None,
                    format!(
                        "the live checkpoint maps object {} of {} bytes to block {}, which is \
                         not whole blocks inside {area}",
                        m.oid, m.size, m.address
                    ),
                );
                continue;
            }
            placed.push((m.address, m.address + blocks, m.oid));
            if m.pad != 0 {
                scan.at(
                    Category::Space,
                    Severity::Conformance,
                    Some(*address),
                    None,
                    format!(
                        "the mapping of object {} records {:#x} where it is reserved",
                        m.oid, m.pad
                    ),
                );
            }
            if m.volume_oid != 0 && !sb.volumes().any(|(_, oid)| oid == m.volume_oid) {
                scan.at(
                    Category::Space,
                    Severity::Conformance,
                    Some(*address),
                    None,
                    format!(
                        "the mapping of object {} names volume {}, which the container does not \
                         list",
                        m.oid, m.volume_oid
                    ),
                );
            }
            match container.read_ephemeral(m, m.kind(), live) {
                Ok(object) => {
                    let header = super::ondisk::ObjectHeader::read_from(&object);
                    if header.is_ok_and(|h| h.subtype != m.subtype) {
                        scan.at(
                            Category::Space,
                            Severity::Conformance,
                            Some(m.address),
                            None,
                            format!(
                                "the live checkpoint maps object {} as of subtype {:#x}, and the \
                                 object records another",
                                m.oid, m.subtype
                            ),
                        );
                    }
                }
                Err(e) => scan.failed(None, &format!("ephemeral object {}", m.oid), &e),
            }
        }
    }
    placed.sort_unstable();
    for (first, second) in overlaps(&placed) {
        scan.at(
            Category::Space,
            Severity::Integrity,
            Some(second.0),
            None,
            format!(
                "the live checkpoint keeps objects {} and {} in the same blocks",
                first.2, second.2
            ),
        );
    }
}

/// Hold the space manager's geometry to the container's: answers whether the chunks can be
/// read by it.
fn hold_geometry(
    sm: &SpaceManager,
    sb: &super::ondisk::ContainerSuperblock,
    at: Option<u64>,
    scan: &mut Scan,
) -> bool {
    let bs = u64::from(sb.block_size);
    let main = &sm.devices[SpaceManager::MAIN];
    let expected = ChunkGeometry::of(sb.block_count, sb.block_size);
    let mut whole = true;
    for (field, recorded, expected) in [
        ("its block size", u64::from(sm.block_size), bs),
        (
            "blocks in a chunk",
            u64::from(sm.blocks_per_chunk),
            expected.blocks_per_chunk,
        ),
        (
            "chunks in a chunk-info block",
            u64::from(sm.chunks_per_cib),
            expected.chunks_per_cib,
        ),
        (
            "chunk-info blocks in an address block",
            u64::from(sm.cibs_per_cab),
            expected.cibs_per_cab,
        ),
        ("the main device's blocks", main.block_count, sb.block_count),
        (
            "the main device's chunks",
            main.chunk_count,
            expected.chunk_count,
        ),
        (
            "the main device's chunk-info blocks",
            u64::from(main.cib_count),
            expected.cib_count,
        ),
        (
            "the main device's address blocks",
            u64::from(main.cab_count),
            expected.cab_count,
        ),
    ] {
        if recorded != expected {
            whole = false;
            scan.at(
                Category::Space,
                Severity::Structural,
                at,
                None,
                format!(
                    "the space manager records {recorded} as {field}, and a container of {} \
                     blocks of {bs} bytes has {expected}",
                    sb.block_count
                ),
            );
        }
    }
    whole
}

/// Hold the arrays past the space manager's fields: one after another from the end of the
/// structure, each padded to 8 bytes — the transactions, the bitmap's blocks, the free list, and
/// the main device's address list — every bitmap written at a transaction no later than the
/// live one, and the free list running from its head to its tail through every block kept for
/// the bitmap and not in use (every container macOS 14 to 27 wrote).
fn hold_arrays(sm: &SpaceManager, object: &[u8], live: u64, at: Option<u64>, scan: &mut Scan) {
    let n = u64::from(sm.ip_bm_block_count);
    let arrays = manager_arrays(
        u64::from(sm.struct_size),
        u64::from(sm.ip_bm_size_in_blocks),
        n,
    );
    for (what, recorded, expected) in [
        (
            "the bitmap transactions",
            u64::from(sm.ip_bm_xid_offset),
            arrays.xids,
        ),
        (
            "the bitmap blocks",
            u64::from(sm.ip_bitmap_offset),
            arrays.slots,
        ),
        (
            "the bitmap free list",
            u64::from(sm.ip_bm_free_next_offset),
            arrays.free_list,
        ),
        (
            "the main device's addresses",
            u64::from(sm.devices[SpaceManager::MAIN].addr_offset),
            arrays.addresses,
        ),
    ] {
        if recorded != expected {
            scan.at(
                Category::Space,
                Severity::Structural,
                at,
                None,
                format!(
                    "the space manager keeps {what} at byte {recorded}, and the arrays before \
                     them end at byte {expected}"
                ),
            );
            return;
        }
    }
    let (Ok(xids), Ok(indices), Ok(next)) = (
        sm.ip_bitmap_xids(object),
        sm.ip_bitmap_indices(object),
        sm.ip_bitmap_free_next(object),
    ) else {
        scan.at(
            Category::Space,
            Severity::Structural,
            at,
            None,
            "the space manager's arrays run past the object".to_string(),
        );
        return;
    };
    for xid in xids {
        if xid == 0 || xid > live {
            scan.at(
                Category::Space,
                Severity::Structural,
                at,
                None,
                format!(
                    "the internal pool's bitmap records transaction {xid}, and the live one is \
                     {live}"
                ),
            );
        }
    }
    if let Some(fault) = free_list_fault(&next, &indices, sm.ip_bm_free_head, sm.ip_bm_free_tail) {
        scan.at(
            Category::Space,
            Severity::Structural,
            at,
            None,
            format!("the internal pool's free list of bitmap blocks {fault}"),
        );
    }
}

/// What a block kept for the internal pool's bitmap is given to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    /// Neither the bitmap nor the free list.
    Unplaced,
    /// One of the bitmap's blocks.
    Bitmap,
    /// A place on the free list.
    Listed,
}

/// What is wrong with the internal pool's free list of bitmap blocks, if anything, said as what
/// the list does.
///
/// The blocks kept for the bitmap are shared out, each to one of the bitmap's blocks or to the
/// free list, none to both and none to neither. The list's order starts at `head` and ends at
/// `tail`, and `next` holds, for each block on it, the block after it. A block of the bitmap,
/// like the tail, holds 0xFFFF there. That is how every container macOS 14 to 27 formats keeps
/// them, at its first transaction and at its second, for one to thirteen bitmap blocks
/// (observed). So the list's order and the bitmap's blocks give the whole of `next`, and the
/// array the space manager records is held to the one they give.
fn free_list_fault(next: &[u16], bitmap: &[u16], head: u16, tail: u16) -> Option<String> {
    const NONE: u16 = 0xFFFF;
    let n = next.len();

    // The list as `next` orders it, from its head until an entry names no block or one past
    // those kept, and never longer than one more than there are, so a loop is seen as a block
    // met twice.
    let order: Vec<u16> = std::iter::successors((head != NONE).then_some(head), |&block| {
        next.get(usize::from(block))
            .copied()
            .filter(|&after| after != NONE)
    })
    .take(n + 1)
    .collect();

    let mut slots = vec![Slot::Unplaced; n];
    for &block in bitmap {
        match slots.get_mut(usize::from(block)) {
            Some(slot @ Slot::Unplaced) => *slot = Slot::Bitmap,
            Some(_) => {
                return Some(format!(
                    "is beside a bitmap with two blocks in block {block}"
                ));
            }
            None => {
                return Some(format!(
                    "is beside a bitmap in block {block}, past the {n} kept for it"
                ));
            }
        }
    }
    for &block in &order {
        match slots.get_mut(usize::from(block)) {
            Some(slot @ Slot::Unplaced) => *slot = Slot::Listed,
            Some(Slot::Bitmap) => {
                return Some(format!("holds block {block}, which the bitmap is in"));
            }
            Some(_) => return Some(format!("reaches block {block} twice")),
            None => {
                return Some(format!(
                    "names block {block} of the {n} kept for the bitmap"
                ));
            }
        }
    }

    match (order.last(), tail) {
        (None, NONE) => {}
        (None, _) => return Some("is empty and records a tail".to_string()),
        (Some(&last), _) if last == tail => {}
        (Some(_), _) if order.contains(&tail) => {
            return Some("does not end at its tail".to_string());
        }
        (Some(_), _) => return Some("ends before its tail".to_string()),
    }

    let unplaced = slots.iter().filter(|&&s| s == Slot::Unplaced).count();
    if unplaced > 0 {
        return Some(format!(
            "holds {} blocks, and {} of the {n} kept for the bitmap are not in use",
            order.len(),
            order.len() + unplaced
        ));
    }

    let mut want = vec![NONE; n];
    for pair in order.windows(2) {
        want[usize::from(pair[0])] = pair[1];
    }
    let differ = (0..n).find(|&block| next[block] != want[block])?;
    Some(format!(
        "leads on from block {differ}, which the bitmap is in"
    ))
}

/// The most blocks the internal pool's bitmaps may take (Apple File System Reference, p. 163).
const IP_BM_BLOCK_COUNT_MAX: u32 = 0xFFFE;

/// Hold the internal pool's geometry: inside the container, its bitmap no more blocks than
/// those kept for it, and holding a bit for every block of the pool. Answers whether the pool
/// can be read by it.
fn hold_pool(
    sm: &SpaceManager,
    sb: &super::ondisk::ContainerSuperblock,
    at: Option<u64>,
    scan: &mut Scan,
) -> bool {
    let bits = u64::from(sm.ip_bm_size_in_blocks) * u64::from(sb.block_size) * 8;
    let inside = |start: u64, count: u64| {
        start
            .checked_add(count)
            .is_some_and(|end| end <= sb.block_count)
    };
    let fault = if sm.ip_bm_block_count > IP_BM_BLOCK_COUNT_MAX
        || sm.ip_bm_size_in_blocks == 0
        || sm.ip_bm_size_in_blocks > sm.ip_bm_block_count
    {
        Some(format!(
            "the internal pool's bitmap takes {} of the {} blocks kept for it, of at most {}",
            sm.ip_bm_size_in_blocks, sm.ip_bm_block_count, IP_BM_BLOCK_COUNT_MAX
        ))
    } else if sm.ip_block_count == 0 || sm.ip_block_count > bits {
        Some(format!(
            "the internal pool records {} blocks and its bitmap holds {bits} bits",
            sm.ip_block_count
        ))
    } else if !inside(sm.ip_base, sm.ip_block_count)
        || !inside(sm.ip_bm_base, u64::from(sm.ip_bm_block_count))
    {
        Some(format!(
            "the internal pool or its bitmaps run past the container's {} blocks",
            sb.block_count
        ))
    } else {
        None
    };
    if let Some(detail) = fault {
        scan.at(Category::Space, Severity::Structural, at, None, detail);
        return false;
    }
    true
}

/// The runs free queue `which` holds, each as its first block and the block after it, or
/// [`None`] where the queue could not be read whole. A run outside `bounds` is reported and
/// left out, and a block two runs hold is reported.
fn read_queue<R: Read + Seek>(
    container: &mut Container<R>,
    sm: &SpaceManager,
    which: usize,
    name: &str,
    bounds: (u64, u64),
    at: Option<u64>,
    scan: &mut Scan,
) -> Option<Vec<(u64, u64)>> {
    let queue = sm.free_queues[which];
    let mut runs: Vec<(u64, u64, u64)> = Vec::new();
    if queue.tree_oid == 0 {
        if queue.count != 0 {
            scan.at(
                Category::Space,
                Severity::Structural,
                at,
                None,
                format!(
                    "the {name} free queue records {} blocks and has no tree",
                    queue.count
                ),
            );
        }
        return Some(Vec::new());
    }
    let tree = TreeRoot {
        oid: queue.tree_oid,
        children: Children::Ephemeral,
        subtype: kind::SPACE_MANAGER_FREE_QUEUE,
        order: Order::FreeQueue,
        max_xid: container.xid(),
    };
    let live = container.xid();
    let (mut total, mut oldest) = (0u64, u64::MAX);
    let walked = btree::census(container, &tree, &mut |key, value| {
        let key = FreeQueueKey::read_from(key)?;
        // A run of one block is kept as its key alone, a ghost (reference p. 130): on every
        // queue of every container macOS 14 to 27 wrote, the runs counted so total the count
        // the queue records.
        let count = if value.is_empty() {
            1
        } else {
            super::ondisk::key_u64(value, 0)?
        };
        total = total.saturating_add(count);
        oldest = oldest.min(key.xid);
        if key.xid > live {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(key.address),
                None,
                format!(
                    "the {name} free queue holds a run freed at transaction {}, after the live \
                     one",
                    key.xid
                ),
            );
        }
        let end = key.address.saturating_add(count);
        if key.address < bounds.0 || end > bounds.1 {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(key.address),
                None,
                format!(
                    "the {name} free queue holds {count} blocks from block {}, outside blocks \
                     {} to {}",
                    key.address,
                    bounds.0,
                    bounds.1 - 1
                ),
            );
        } else {
            runs.push((key.address, end, key.xid));
        }
        Ok(true)
    });
    match walked {
        Ok(census) => scan.census(&format!("{name} free queue"), &census),
        Err(e) => {
            scan.failed(None, &format!("the {name} free queue"), &e);
            return None;
        }
    }
    if total != queue.count {
        scan.at(
            Category::Space,
            Severity::Conformance,
            at,
            None,
            format!(
                "the {name} free queue records {} blocks and holds {total}",
                queue.count
            ),
        );
    }
    if total != 0 && oldest != queue.oldest_xid {
        scan.at(
            Category::Space,
            Severity::Conformance,
            at,
            None,
            format!(
                "the {name} free queue records transaction {} as the oldest that freed a run, \
                 and the oldest it holds is {oldest}",
                queue.oldest_xid
            ),
        );
    }
    // A block is freed once until it is used again, so the runs a queue holds are apart from one
    // another whatever transactions freed them: a block held twice is counted twice by the
    // queue's count and once by the bitmap.
    runs.sort_unstable();
    for (first, second) in overlaps(&runs) {
        scan.at(
            Category::Space,
            Severity::Integrity,
            Some(second.0),
            None,
            format!(
                "the {name} free queue holds block {} twice, in a run freed at transaction {} \
                 and in one freed at {}",
                second.0, first.2, second.2
            ),
        );
    }
    Some(
        runs.into_iter()
            .map(|(start, end, _)| (start, end))
            .collect(),
    )
}

/// Each run of `runs`, which are sorted by where they begin, that begins before an earlier one
/// ends, paired with the earlier one reaching furthest. Every run overlapping an earlier one is
/// found, a run nested inside a longer one among them, which comparing each run with its
/// neighbour misses.
fn overlaps<T: Copy>(
    runs: &[(u64, u64, T)],
) -> impl Iterator<Item = ((u64, u64, T), (u64, u64, T))> + '_ {
    let mut furthest: Option<(u64, u64, T)> = None;
    runs.iter().filter_map(move |&run| {
        let found = furthest.filter(|f| run.0 < f.1).map(|f| (f, run));
        if furthest.is_none_or(|f| run.1 > f.1) {
            furthest = Some(run);
        }
        found
    })
}

/// Read the reaper, and note what it is reaping as walked no further.
fn read_reaper<R: Read + Seek>(
    container: &mut Container<R>,
    mappings: &[CheckpointMapping],
    oid: u64,
    live: u64,
    space: &mut Space,
    scan: &mut Scan,
) {
    let Some(mapping) = mappings.iter().find(|m| m.oid == oid) else {
        scan.at(
            Category::Space,
            Severity::Structural,
            None,
            None,
            format!("the live checkpoint maps no reaper, object {oid}"),
        );
        return;
    };
    let reaper = container
        .read_ephemeral(mapping, kind::REAPER, live)
        .and_then(|bytes| Ok(Reaper::read_from(&bytes)?));
    let reaper = match reaper {
        Ok(reaper) => reaper,
        Err(e) => {
            scan.failed(None, "the reaper", &e);
            return;
        }
    };
    // The reference says the first flag is always set (p. 165), and every reaper macOS wrote
    // sets it.
    if reaper.flags & REAPER_ALWAYS == 0 {
        scan.at(
            Category::Space,
            Severity::Conformance,
            Some(mapping.address),
            None,
            format!(
                "the reaper's flags are {:#x}, without the one always set",
                reaper.flags
            ),
        );
    }
    if reaper.completed_id >= reaper.next_reap_id
        || (reaper.head == 0) != (reaper.tail == 0)
        || (reaper.head == 0) != (reaper.list_count == 0)
    {
        scan.at(
            Category::Space,
            Severity::Conformance,
            Some(mapping.address),
            None,
            format!(
                "the reaper records {} as the last reaped of {} and a list from {} to {} of {} \
                 blocks",
                reaper.completed_id,
                reaper.next_reap_id,
                reaper.head,
                reaper.tail,
                reaper.list_count
            ),
        );
    }
    // A reap finished leaves its list behind, empty, and its last identifier one below the
    // next (every reaper of every container macOS wrote after deleting a snapshot or a
    // volume's encryption). Anything else is a reap in progress, whose objects still hold
    // blocks nothing else reaches.
    let mut pending = reaper.flags & REAPER_CONTINUE != 0
        || reaper.completed_id.wrapping_add(1) != reaper.next_reap_id;
    if reaper.head != 0 {
        match mappings.iter().find(|m| m.oid == reaper.head) {
            Some(list) => match container
                .read_ephemeral(list, kind::REAP_LIST, live)
                .and_then(|bytes| Ok(ReapList::read_from(&bytes)?))
            {
                Ok(list) => pending |= list.count != 0,
                Err(e) => {
                    scan.failed(None, "the reaper's list", &e);
                    pending = true;
                }
            },
            None => {
                scan.at(
                    Category::Space,
                    Severity::Structural,
                    Some(mapping.address),
                    None,
                    format!(
                        "the reaper's list is object {} and the live checkpoint maps no such \
                         object",
                        reaper.head
                    ),
                );
                pending = true;
            }
        }
    }
    if pending {
        space
            .partial
            .push("what the reaper is deleting".to_string());
    }
}

/// Reach the object map at `address`: its header object, every node of its mapping tree and of
/// its snapshot tree, and every version it maps.
fn reach_map<R: Read + Seek>(
    container: &mut Container<R>,
    space: &mut Space,
    scan: &mut Scan,
    address: u64,
    by: By,
    mapped: By,
) {
    let live = container.xid();
    let (map, tree) = match container.object_map_at(address, live) {
        Ok(read) => read,
        Err(e) => {
            scan.failed(None, &format!("{by}"), &e);
            space.partial.push(format!("{by}"));
            return;
        }
    };
    space.reach(scan, address, 1, by);
    let mut nodes = Vec::new();
    let mut values = Vec::new();
    let walked = btree::census_nodes(
        container,
        &tree,
        &mut |_, value| {
            values.push(MapValue::read_from(value)?);
            Ok(true)
        },
        &mut |block| nodes.push(block),
    );
    if let Err(e) = walked {
        scan.failed(None, &format!("{by}'s tree"), &e);
        space.partial.push(format!("{by}"));
    }
    for block in nodes {
        space.reach(scan, block, 1, by);
    }
    for value in values {
        // A deleted object's record keeps the block its last version was at, which is freed.
        if value.flags & super::ondisk::MAP_VALUE_DELETED != 0 {
            continue;
        }
        let blocks = space.blocks(u64::from(value.size));
        space.reach(scan, value.address, blocks, mapped);
    }
    if map.snapshot_tree_oid != 0 {
        let snapshots = TreeRoot {
            oid: map.snapshot_tree_oid,
            children: Children::Physical,
            subtype: kind::OBJECT_MAP_SNAPSHOT,
            order: Order::Transaction,
            max_xid: live,
        };
        let mut nodes = Vec::new();
        let walked =
            btree::census_nodes(container, &snapshots, &mut |_, _| Ok(true), &mut |block| {
                nodes.push(block)
            });
        if let Err(e) = walked {
            scan.failed(None, &format!("{by}'s snapshot tree"), &e);
            space.partial.push(format!("{by}"));
        }
        for block in nodes {
            space.reach(scan, block, 1, by);
        }
    }
}

/// Reach every block of the volume in `slot`.
fn reach_volume<R: Read + Seek>(
    container: &mut Container<R>,
    space: &mut Space,
    scan: &mut Scan,
    slot: usize,
    volume: &super::ondisk::VolumeSuperblock,
) {
    let live = container.xid();
    reach_map(
        container,
        space,
        scan,
        volume.object_map_oid,
        By::Volume(slot, Part::Map),
        By::Volume(slot, Part::Mapped),
    );
    let mut data = Vec::new();
    let mut trees = vec![volume.extent_ref_tree_oid];
    if volume.snapshot_tree_oid != 0 {
        let tree = TreeRoot {
            oid: volume.snapshot_tree_oid,
            children: Children::Physical,
            subtype: kind::SNAPSHOT_TREE,
            order: Order::FileSystem,
            max_xid: live,
        };
        let mut nodes = Vec::new();
        let mut copies = Vec::new();
        let walked = btree::census_nodes(
            container,
            &tree,
            &mut |key, value| {
                if KeyHeader::read_from(key)?.kind == record_kind::SNAPSHOT_META {
                    let meta = SnapshotMeta::read_from(key, value)?;
                    copies.push(meta.superblock);
                    trees.push(meta.extent_ref_tree_oid);
                }
                Ok(true)
            },
            &mut |block| nodes.push(block),
        );
        if let Err(e) = walked {
            scan.failed(None, &format!("volume {slot}'s snapshot tree"), &e);
            space.partial.push(format!("volume {slot}'s snapshots"));
        }
        for block in nodes {
            space.reach(scan, block, 1, By::Volume(slot, Part::Snapshots));
        }
        for block in copies {
            space.reach(scan, block, 1, By::Volume(slot, Part::SnapshotCopy));
        }
    }
    for oid in trees.into_iter().filter(|oid| *oid != 0) {
        let tree = TreeRoot {
            oid,
            children: Children::Physical,
            subtype: kind::EXTENT_REF_TREE,
            order: Order::FileSystem,
            max_xid: live,
        };
        let mut nodes = Vec::new();
        let walked = btree::census_nodes(
            container,
            &tree,
            &mut |key, value| {
                if KeyHeader::read_from(key)?.kind == record_kind::PHYSICAL_EXTENT {
                    let run = PhysicalExtent::read_from(key, value)?;
                    data.push((run.start, run.blocks));
                }
                Ok(true)
            },
            &mut |block| nodes.push(block),
        );
        if let Err(e) = walked {
            scan.failed(None, &format!("volume {slot}'s extent-reference tree"), &e);
            space.partial.push(format!("volume {slot}'s data"));
        }
        for block in nodes {
            space.reach(scan, block, 1, By::Volume(slot, Part::ExtentReferences));
        }
    }
    // The trees of the volume and of each snapshot record the same run more than once.
    data.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, blocks) in data {
        let end = start.saturating_add(blocks);
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    for (start, end) in merged {
        space.reach(scan, start, end - start, By::Volume(slot, Part::Data));
    }
    // What the volume counts as its own is everything above but its snapshots' copies of its
    // superblock, which the container counts (every volume macOS 14 to 27 wrote, with and
    // without snapshots).
    let own: u64 = space
        .runs
        .iter()
        .filter(|r| matches!(r.by, By::Volume(s, part) if s == slot && part != Part::SnapshotCopy))
        .map(|r| r.end - r.start)
        .sum();
    if own != volume.allocated_blocks && space.partial.is_empty() {
        scan.at(
            Category::Space,
            Severity::Conformance,
            None,
            None,
            format!(
                "volume {slot} records {} blocks as its own, and its object map, its trees and \
                 its data take {own}",
                volume.allocated_blocks
            ),
        );
    }
}

/// Sort every run, report the blocks two things reach, and answer the runs merged, each with
/// what reaches its first block.
fn merge(space: &mut Space, scan: &mut Scan) -> Vec<(u64, u64, By)> {
    space.runs.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<(u64, u64, By)> = Vec::new();
    let mut reported = 0usize;
    for run in &space.runs {
        match merged.last_mut() {
            Some(last) if run.start < last.1 => {
                if reported < 16 {
                    reported += 1;
                    scan.at(
                        Category::Space,
                        Severity::Integrity,
                        Some(run.start),
                        None,
                        format!(
                            "block {} is reached as {} and as {}",
                            run.start, last.2, run.by
                        ),
                    );
                }
                last.1 = last.1.max(run.end);
            }
            Some(last) if run.start == last.1 && run.by == last.2 => last.1 = run.end,
            _ => merged.push((run.start, run.end, run.by)),
        }
    }
    merged
}

/// What in `runs`, sorted and apart, reaches a block from `start` up to `end`, if anything
/// does.
fn covered(runs: &[(u64, u64, By)], start: u64, end: u64) -> Option<By> {
    let i = runs.partition_point(|r| r.1 <= start);
    runs.get(i).filter(|r| r.0 < end).map(|r| r.2)
}

/// The runs of `runs`, sorted by first block and possibly nesting, as a queue's run inside a
/// reached one does, that meet blocks `start` up to `end`; `reach` is the furthest end of the
/// runs up to each.
fn meeting<'r>(
    runs: &'r [(u64, u64, By)],
    reach: &[u64],
    start: u64,
    end: u64,
) -> impl Iterator<Item = &'r (u64, u64, By)> {
    let from = reach.partition_point(|&far| far <= start);
    runs[from..]
        .iter()
        .take_while(move |r| r.0 < end)
        .filter(move |r| r.1 > start)
}

/// Hold every chunk's bitmap to the blocks `accounted` reaches or queues, every count to its
/// bitmap, and the internal pool's bitmap to the space manager's own blocks.
#[allow(clippy::too_many_arguments)]
fn compare_chunks<R: Read + Seek>(
    container: &mut Container<R>,
    sm: &SpaceManager,
    object: &[u8],
    space: &Space,
    accounted: &[(u64, u64, By)],
    pool_queue: Option<Vec<(u64, u64)>>,
    at: Option<u64>,
    scan: &mut Scan,
) {
    let live = container.xid();
    let main = sm.devices[SpaceManager::MAIN];
    let reach: Vec<u64> = accounted
        .iter()
        .scan(0u64, |far, r| {
            *far = (*far).max(r.1);
            Some(*far)
        })
        .collect();
    let addresses = match sm.addresses(SpaceManager::MAIN, object) {
        Ok(addresses) => addresses,
        Err(e) => {
            scan.failed(None, "the space manager's address list", &e.into());
            return;
        }
    };
    let mut pool: Vec<(u64, &'static str)> = Vec::new();
    let mut cibs = Vec::new();
    if main.cab_count != 0 {
        for (i, address) in addresses.iter().enumerate() {
            pool.push((*address, "an address block"));
            match read_list(container, *address, kind::SPACE_MANAGER_CAB, live) {
                Ok((list, block)) => {
                    if list.index as usize != i {
                        scan.at(
                            Category::Space,
                            Severity::Conformance,
                            Some(*address),
                            None,
                            format!("address block {i} records itself as number {}", list.index),
                        );
                    }
                    match list.addresses(&block) {
                        Ok(more) => cibs.extend(more),
                        Err(e) => {
                            scan.failed(None, "an address block", &e.into());
                            return;
                        }
                    }
                }
                Err(e) => {
                    scan.failed(None, "an address block", &e);
                    return;
                }
            }
        }
    } else {
        cibs = addresses;
    }
    if cibs.len() as u64 != u64::from(main.cib_count) {
        scan.at(
            Category::Space,
            Severity::Structural,
            at,
            None,
            format!(
                "the space manager records {} chunk-info blocks and lists {}",
                main.cib_count,
                cibs.len()
            ),
        );
        return;
    }
    let mut chunks: Vec<ChunkInfo> = Vec::new();
    for (i, address) in cibs.iter().enumerate() {
        pool.push((*address, "a chunk-info block"));
        match read_list(container, *address, kind::SPACE_MANAGER_CIB, live) {
            Ok((list, block)) => {
                if list.index as usize != i {
                    scan.at(
                        Category::Space,
                        Severity::Conformance,
                        Some(*address),
                        None,
                        format!(
                            "chunk-info block {i} records itself as number {}",
                            list.index
                        ),
                    );
                }
                match list.chunks(&block) {
                    Ok(more) => chunks.extend(more),
                    Err(e) => {
                        scan.failed(None, "a chunk-info block", &e.into());
                        return;
                    }
                }
            }
            Err(e) => {
                scan.failed(None, "a chunk-info block", &e);
                return;
            }
        }
    }
    if chunks.len() as u64 != main.chunk_count {
        scan.at(
            Category::Space,
            Severity::Structural,
            at,
            None,
            format!(
                "the space manager records {} chunks and its chunk-info blocks hold {}",
                main.chunk_count,
                chunks.len()
            ),
        );
        return;
    }
    let per_chunk = u64::from(sm.blocks_per_chunk);
    let bs = space.block_size as usize;
    let mut free_total = 0u64;
    let mut bitmap = vec![0u8; bs];
    let mut in_use_free = (0u64, None::<u64>);
    let mut unreached = (0u64, None::<u64>);
    for (i, chunk) in chunks.iter().enumerate() {
        let (first, blocks) = chunk_span(per_chunk, space.block_count, i as u64);
        let recorded = u64::from(chunk.block_count & super::ondisk::CI_COUNT_MASK);
        let free = u64::from(chunk.free_count & super::ondisk::CI_COUNT_MASK);
        if chunk.address != first || recorded != blocks || free > recorded {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(first),
                None,
                format!(
                    "chunk {i} records {recorded} blocks from block {}, {free} of them free, and \
                     chunk {i} is {blocks} blocks from block {first}",
                    chunk.address
                ),
            );
            continue;
        }
        free_total += free;
        if chunk.xid > live {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(first),
                None,
                format!(
                    "chunk {i} records transaction {}, after the live one, {live}",
                    chunk.xid
                ),
            );
        }
        // The blocks of this chunk something reaches or a queue holds, as bits.
        let words = blocks.div_ceil(64) as usize;
        let mut expected = vec![0u64; words];
        for run in meeting(accounted, &reach, first, first + blocks) {
            for n in run.0.max(first) - first..run.1.min(first + blocks) - first {
                expected[(n / 64) as usize] |= 1 << (n % 64);
            }
        }
        if chunk.bitmap == 0 {
            if expected.iter().all(|w| *w == 0) {
                if free != blocks {
                    scan.at(
                        Category::Space,
                        Severity::Conformance,
                        Some(first),
                        None,
                        format!(
                            "chunk {i} has no bitmap, so none of its {blocks} blocks is in use, \
                             and records {free} as free"
                        ),
                    );
                }
                continue;
            }
            bitmap.fill(0);
        } else {
            pool.push((chunk.bitmap, "a chunk's bitmap"));
            if let Err(e) = container.read_blocks(chunk.bitmap, &mut bitmap) {
                scan.failed(None, &format!("chunk {i}'s bitmap"), &e);
                continue;
            }
        }
        let mut used = 0u64;
        for (w, want) in expected.iter().enumerate() {
            let mut have = crate::bytes::get_u64(&bitmap, w * 8);
            let past = (w as u64 + 1) * 64;
            if past > blocks {
                have &= u64::MAX >> (past - blocks);
            }
            used += u64::from(have.count_ones());
            let base = first + w as u64 * 64;
            let missing = want & !have;
            if missing != 0 {
                in_use_free.0 += u64::from(missing.count_ones());
                in_use_free
                    .1
                    .get_or_insert(base + u64::from(missing.trailing_zeros()));
            }
            let extra = have & !want;
            if extra != 0 {
                unreached.0 += u64::from(extra.count_ones());
                unreached
                    .1
                    .get_or_insert(base + u64::from(extra.trailing_zeros()));
            }
        }
        if used + free != blocks {
            scan.at(
                Category::Space,
                Severity::Conformance,
                Some(first),
                None,
                format!(
                    "chunk {i} records {free} of its {blocks} blocks as free and its bitmap marks \
                     {used} in use"
                ),
            );
        }
    }
    if free_total != main.free_count {
        scan.at(
            Category::Space,
            Severity::Conformance,
            at,
            None,
            format!(
                "the space manager records {} blocks free and its chunks record {free_total}",
                main.free_count
            ),
        );
    }
    if let (n, Some(block)) = in_use_free {
        let by = meeting(accounted, &reach, block, block + 1)
            .next()
            .map_or(String::new(), |run| run.2.to_string());
        scan.at(
            Category::Space,
            Severity::Integrity,
            Some(block),
            None,
            format!(
                "{n} blocks in use are marked free, so a write may take them; the first is block \
                 {block}, reached as {by}"
            ),
        );
    }
    if let (n, Some(block)) = unreached {
        if space.partial.is_empty() {
            scan.at(
                Category::Space,
                Severity::Conformance,
                Some(block),
                None,
                format!(
                    "{n} blocks are marked in use and nothing the container holds reaches them; \
                     the first is block {block}"
                ),
            );
        } else {
            scan.at(
                Category::Space,
                Severity::Cosmetic,
                Some(block),
                None,
                format!(
                    "{n} blocks are marked in use and nothing this reader walks reaches them, \
                     the first block {block}; it does not walk {}, which may",
                    space.partial.join(", ")
                ),
            );
        }
    }
    compare_pool(container, sm, object, &mut pool, pool_queue, at, scan);
}

/// A chunk-info or address block at `address`, read and verified.
fn read_list<R: Read + Seek>(
    container: &mut Container<R>,
    address: u64,
    kind: u16,
    live: u64,
) -> Result<(ChunkList, Vec<u8>), ReadError> {
    let object = container.read_object(
        address,
        &Expect {
            kinds: if kind == super::ondisk::kind::SPACE_MANAGER_CAB {
                &[super::ondisk::kind::SPACE_MANAGER_CAB]
            } else {
                &[super::ondisk::kind::SPACE_MANAGER_CIB]
            },
            subtype: None,
            storage: Storage::Physical,
            oid: address,
            xid: Xid::AtMost(live),
        },
    )?;
    let bytes = object.to_vec();
    Ok((ChunkList::read_from(&bytes)?, bytes))
}

/// Hold the internal pool's bitmap to the space manager's own blocks, `pool`, and the runs its
/// free queue holds. Its geometry was held already ([`hold_pool`]), so every block of it is a
/// bit of the bitmap; the bitmap is read a block at a time.
fn compare_pool<R: Read + Seek>(
    container: &mut Container<R>,
    sm: &SpaceManager,
    object: &[u8],
    pool: &mut [(u64, &'static str)],
    queue: Option<Vec<(u64, u64)>>,
    at: Option<u64>,
    scan: &mut Scan,
) {
    let base = sm.ip_base;
    let size = sm.ip_block_count;
    // Every block the space manager uses, and every run its queue holds, as runs relative to
    // the pool's first block.
    let mut wanted: Vec<(u64, u64, &'static str)> = Vec::new();
    for &(block, what) in pool.iter() {
        if block < base || block - base >= size {
            scan.at(
                Category::Space,
                Severity::Structural,
                Some(block),
                None,
                format!("{what} of the space manager's lies outside the internal pool"),
            );
            continue;
        }
        wanted.push((block - base, block - base + 1, what));
    }
    let Some(queue) = queue else {
        return;
    };
    const QUEUED: &str = "the internal pool's free queue";
    for (start, end) in queue {
        wanted.push((start - base, end - base, QUEUED));
    }
    wanted.sort_unstable_by_key(|w| (w.0, w.1));
    // Two of the queue's own runs are the queue's to report, which it does as it is read.
    for (first, second) in overlaps(&wanted).filter(|(a, b)| a.2 != QUEUED || b.2 != QUEUED) {
        scan.at(
            Category::Space,
            Severity::Integrity,
            Some(base + second.0),
            None,
            format!(
                "block {} of the internal pool is both {} and {}",
                base + second.0,
                first.2,
                second.2
            ),
        );
    }
    let indices = match sm.ip_bitmap_indices(object) {
        Ok(indices) => indices,
        Err(e) => {
            scan.failed(None, "the internal pool's bitmap", &e.into());
            return;
        }
    };
    let bs = container.block_size() as usize;
    let per_block = bs as u64 * 8;
    let mut block = vec![0u8; bs];
    let (mut free, mut unused) = ((0u64, None), (0u64, None));
    for (j, index) in indices.iter().enumerate() {
        if u32::from(*index) >= sm.ip_bm_block_count {
            scan.at(
                Category::Space,
                Severity::Structural,
                at,
                None,
                format!(
                    "the internal pool's bitmap is kept in block {index} of the {} kept for it",
                    sm.ip_bm_block_count
                ),
            );
            return;
        }
        if let Err(e) = container.read_blocks(sm.ip_bm_base + u64::from(*index), &mut block) {
            scan.failed(None, "the internal pool's bitmap", &e);
            return;
        }
        let first = j as u64 * per_block;
        if first >= size {
            break;
        }
        let bits = per_block.min(size - first);
        let from = wanted.partition_point(|w| w.1 <= first);
        let mut expected = vec![0u64; bits.div_ceil(64) as usize];
        for w in wanted[from..].iter().take_while(|w| w.0 < first + bits) {
            for n in w.0.max(first) - first..w.1.min(first + bits) - first {
                expected[(n / 64) as usize] |= 1 << (n % 64);
            }
        }
        for (k, want) in expected.iter().enumerate() {
            let mut have = crate::bytes::get_u64(&block, k * 8);
            let past = (k as u64 + 1) * 64;
            if past > bits {
                have &= u64::MAX >> (past - bits);
            }
            let at = base + first + k as u64 * 64;
            let missing = want & !have;
            if missing != 0 {
                free.0 += u64::from(missing.count_ones());
                free.1
                    .get_or_insert(at + u64::from(missing.trailing_zeros()));
            }
            let extra = have & !want;
            if extra != 0 {
                unused.0 += u64::from(extra.count_ones());
                unused
                    .1
                    .get_or_insert(at + u64::from(extra.trailing_zeros()));
            }
        }
    }
    if let (n, Some(block)) = free {
        scan.at(
            Category::Space,
            Severity::Integrity,
            Some(block),
            None,
            format!(
                "the internal pool's bitmap marks free {n} blocks the space manager uses; the \
                 first is block {block}"
            ),
        );
    }
    if let (n, Some(block)) = unused {
        scan.at(
            Category::Space,
            Severity::Conformance,
            Some(block),
            None,
            format!(
                "the internal pool's bitmap marks {n} blocks in use that the space manager does \
                 not use; the first is block {block}"
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::forge::{
        self, BLOCK, CHUNK_BITMAP_AT, CHUNK_INFO_AT, DESC_BASE, FS_ROOT_AT, Forge, POOL_BITMAP_AT,
        SPACE_MANAGER_AT, VOLUME_AT, XID,
    };
    use super::super::ondisk::seal;
    use super::super::{OpenOptions, Reader};
    use super::*;
    use crate::bytes::{get_u16, get_u32, get_u64, put_u16, put_u32, put_u64};
    use crate::{ReadPolicy, Severity};

    /// Every finding of the space pass on `image`, as its severity, its block, and its words.
    fn space(image: Vec<u8>) -> Vec<(Severity, Option<u64>, String)> {
        let options =
            OpenOptions::new().common(crate::OpenOptions::new().policy(ReadPolicy::Lenient));
        let mut reader =
            Reader::open_with(std::io::Cursor::new(image), &options).expect("it opens");
        reader
            .scan()
            .anomalies()
            .iter()
            .filter(|a| a.category == Category::Space)
            .map(|a| (a.severity, a.block, a.detail.clone()))
            .collect()
    }

    /// The severity and block of each finding, the words left out.
    fn graded(image: Vec<u8>) -> Vec<(Severity, Option<u64>)> {
        space(image).into_iter().map(|(s, b, _)| (s, b)).collect()
    }

    fn reseal(image: &mut [u8], block: u64) {
        let at = block as usize * BLOCK;
        seal(&mut image[at..at + BLOCK]);
    }

    /// Change the object at `block` and reseal it.
    fn change(image: &mut [u8], block: u64, edit: impl FnOnce(&mut [u8])) {
        let at = block as usize * BLOCK;
        edit(&mut image[at..at + BLOCK]);
        reseal(image, block);
    }

    const SM: u64 = SPACE_MANAGER_AT;
    /// The main device's free count, in the space manager.
    const SM_FREE: usize = 72;
    /// The one chunk's free count, in its chunk-info block.
    const CHUNK_FREE: usize = 60;

    /// Move one block's bit in the chunk bitmap, and the two free counts with it, so only what
    /// the bitmap says about that block disagrees with the container.
    fn flip_bit(image: &mut [u8], block: u64) {
        let at = CHUNK_BITMAP_AT as usize * BLOCK + (block / 8) as usize;
        let was = image[at] >> (block % 8) & 1;
        image[at] ^= 1 << (block % 8);
        let delta: i64 = if was == 1 { 1 } else { -1 };
        change(image, CHUNK_INFO_AT, |b| {
            let free = get_u32(b, CHUNK_FREE) as i64 + delta;
            put_u32(b, CHUNK_FREE, free as u32);
        });
        change(image, SM, |b| {
            let free = get_u64(b, SM_FREE) as i64 + delta;
            put_u64(b, SM_FREE, free as u64);
        });
    }

    fn queued() -> Forge {
        let mut forge = Forge::populated();
        // A run freed a transaction ago, and a run of one block, kept as its key alone.
        forge.main_queue = vec![(XID - 1, 200, 3), (XID, 210, 1)];
        forge
    }

    #[test]
    fn a_container_that_accounts_for_every_block_scans_clean() {
        assert_eq!(space(Forge::new().image()), []);
        assert_eq!(space(Forge::populated().image()), []);
        assert_eq!(space(Forge::with_snapshot().image()), []);
        // A snapshot keeping an extent-reference tree of its own, recording a run no other
        // tree does.
        let mut kept = Forge::with_snapshot();
        kept.snapshot_references = Some(vec![forge::Reference::run(220, 2, 99, 1)]);
        assert_eq!(space(kept.image()), []);
        assert_eq!(space(queued().image()), []);
        let mut two = Forge::populated();
        two.second = Some(forge::second_volume(b"Other", 1));
        two.container.max_volumes = 2;
        assert_eq!(space(two.image()), []);
    }

    #[test]
    fn a_block_in_use_the_bitmap_marks_free_is_integrity_damage() {
        let mut image = Forge::populated().image();
        flip_bit(&mut image, FS_ROOT_AT);
        let found = space(image);
        assert_eq!(
            found.iter().map(|f| (f.0, f.1)).collect::<Vec<_>>(),
            [(Severity::Integrity, Some(FS_ROOT_AT))]
        );
        assert!(
            found[0].2.contains("volume 0's object map's objects"),
            "{found:?}"
        );
    }

    #[test]
    fn a_block_marked_in_use_that_nothing_reaches_is_a_finding() {
        let mut image = Forge::populated().image();
        flip_bit(&mut image, 200);
        assert_eq!(graded(image), [(Severity::Conformance, Some(200))]);
    }

    #[test]
    fn each_free_count_is_held_to_the_bitmap_and_to_the_chunks() {
        // The chunk's count, and the total with it.
        let mut image = Forge::populated().image();
        change(&mut image, CHUNK_INFO_AT, |b| {
            put_u32(b, CHUNK_FREE, get_u32(b, CHUNK_FREE) - 1);
        });
        change(&mut image, SM, |b| {
            put_u64(b, SM_FREE, get_u64(b, SM_FREE) - 1)
        });
        assert_eq!(graded(image), [(Severity::Conformance, Some(0))]);
        // The total alone.
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| {
            put_u64(b, SM_FREE, get_u64(b, SM_FREE) + 1)
        });
        assert_eq!(graded(image), [(Severity::Conformance, Some(SM))]);
    }

    #[test]
    fn a_volume_takes_what_its_superblock_counts_as_its_own() {
        let mut image = Forge::with_snapshot().image();
        change(&mut image, VOLUME_AT, |b| {
            put_u64(b, 88, get_u64(b, 88) + 1)
        });
        assert_eq!(graded(image), [(Severity::Conformance, None)]);
    }

    #[test]
    fn a_free_queue_is_held_to_its_count_its_oldest_run_and_what_it_frees() {
        const COUNT: usize = 240;
        const OLDEST: usize = 256;
        let mut image = queued().image();
        change(&mut image, SM, |b| put_u64(b, COUNT, get_u64(b, COUNT) + 1));
        assert_eq!(graded(image), [(Severity::Conformance, Some(SM))]);

        let mut image = queued().image();
        change(&mut image, SM, |b| put_u64(b, OLDEST, XID));
        assert_eq!(graded(image), [(Severity::Conformance, Some(SM))]);

        // A run the queue holds as freed that the volume still uses.
        let mut forge = queued();
        forge.main_queue.push((XID, FS_ROOT_AT, 1));
        assert_eq!(
            graded(forge.image()),
            [(Severity::Integrity, Some(FS_ROOT_AT))]
        );

        // A run past the container's end is left out, which leaves its count unmet and the
        // blocks the bitmap marks for it reached by nothing.
        let mut forge = queued();
        forge.main_queue.push((XID, forge::BLOCKS - 2, 4));
        let found = graded(forge.image());
        assert!(
            found.contains(&(Severity::Structural, Some(forge::BLOCKS - 2))),
            "{found:?}"
        );
    }

    #[test]
    fn every_run_overlapping_one_before_it_is_found_once_a_nested_one_among_them() {
        // The third run is inside the first and apart from the second, which a comparison of
        // neighbours does not see; the last begins where the first ends.
        let runs = [(0, 10, 'a'), (1, 2, 'b'), (3, 4, 'c'), (10, 11, 'd')];
        let found: Vec<_> = overlaps(&runs).map(|(a, b)| (a.2, b.2)).collect();
        assert_eq!(found, [('a', 'b'), ('a', 'c')]);
    }

    #[test]
    fn a_block_either_free_queue_holds_twice_is_integrity_damage() {
        // A block freed at two transactions, and a run overlapping another in part: the count and
        // the oldest transaction agree with the runs, and the bitmap marks each block once, so
        // nothing but the runs themselves says so. A run beginning where another ends is apart
        // from it.
        for (extra, found) in [
            ((XID, 200, 1), Some(200)),
            ((XID, 201, 4), Some(201)),
            ((XID, 203, 2), None),
        ] {
            let mut forge = queued();
            forge.main_queue.push(extra);
            let want: Vec<_> = found
                .map(|b| (Severity::Integrity, Some(b)))
                .into_iter()
                .collect();
            assert_eq!(graded(forge.image()), want, "{extra:?}");
        }
        // The internal pool's queue, in the pool's own blocks past its chunk bitmap.
        let first = CHUNK_BITMAP_AT + 1;
        let pool = |extra: Option<(u64, u64, u64)>| {
            let mut forge = Forge::populated();
            forge.pool_queue = vec![(XID - 1, first, 2), (XID, first + 3, 1)];
            forge.pool_queue.extend(extra);
            forge.image()
        };
        assert_eq!(space(pool(None)), []);
        for (extra, found) in [
            ((XID, first, 1), Some(first)),
            ((XID, first + 1, 2), Some(first + 1)),
            ((XID, first + 2, 1), None),
        ] {
            let want: Vec<_> = found
                .map(|b| (Severity::Integrity, Some(b)))
                .into_iter()
                .collect();
            assert_eq!(graded(pool(Some(extra))), want, "{extra:?}");
        }
    }

    #[test]
    fn the_internal_pools_bitmap_is_held_to_the_space_managers_blocks() {
        // The chunk-info block marked free.
        let mut image = Forge::populated().image();
        image[POOL_BITMAP_AT as usize * BLOCK] &= !1;
        assert_eq!(graded(image), [(Severity::Integrity, Some(CHUNK_INFO_AT))]);
        // A third block of the pool marked in use, which the space manager does not use.
        let mut image = Forge::populated().image();
        image[POOL_BITMAP_AT as usize * BLOCK] |= 0b100;
        change(&mut image, SM, |b| put_u64(b, 152, 3));
        let found = graded(image);
        assert!(
            found.contains(&(Severity::Conformance, Some(CHUNK_BITMAP_AT + 1))),
            "{found:?}"
        );
    }

    #[test]
    fn the_space_managers_arrays_follow_its_fields_and_hold_together() {
        // Every array moved on eight bytes, each still where its offset says and read whole,
        // leaving a gap after the fields.
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| {
            put_u32(b, 324, 2528);
            put_u64(b, 2528, XID);
            put_u32(b, 328, 2536);
            put_u16(b, 2536, 0);
            put_u32(b, 332, 2544);
            put_u16(b, 2544, 0xFFFF);
            put_u32(b, 80, 2552);
            put_u64(b, 2552, CHUNK_INFO_AT);
            put_u32(b, 128, 2560);
        });
        assert_eq!(graded(image), [(Severity::Structural, Some(SM))]);
        // The bitmap written after the live transaction.
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| put_u64(b, 2520, XID + 1));
        assert_eq!(graded(image), [(Severity::Structural, Some(SM))]);
        // The free list naming the block the bitmap is in.
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| {
            put_u16(b, 320, 0);
            put_u16(b, 322, 0);
        });
        assert_eq!(graded(image), [(Severity::Structural, Some(SM))]);
    }

    /// The free list of `s` bitmap blocks in the shape a container macOS formats keeps it, at
    /// its first transaction or its second: `next`, the bitmap's blocks, the head and the tail.
    fn formatted_list(s: u16, second: bool) -> (Vec<u16>, Vec<u16>, u16, u16) {
        let n = 16 * s;
        let mut bitmap: Vec<u16> = (0..s).collect();
        let mut order: Vec<u16> = (s..n).collect();
        if second {
            bitmap[0] = s;
            order.remove(0);
            order.push(0);
        }
        let mut next = vec![0xFFFF; usize::from(n)];
        for pair in order.windows(2) {
            next[usize::from(pair[0])] = pair[1];
        }
        (next, bitmap, order[0], *order.last().expect("a free block"))
    }

    #[test]
    fn the_bitmap_free_list_is_the_one_its_order_and_the_bitmap_give() {
        for s in 1..=13 {
            for second in [false, true] {
                let (next, bitmap, head, tail) = formatted_list(s, second);
                assert_eq!(
                    free_list_fault(&next, &bitmap, head, tail),
                    None,
                    "{s} {second}"
                );
            }
        }
        let (next, bitmap, head, tail) = formatted_list(2, true);
        let fault = |next: &[u16], bitmap: &[u16], head, tail| {
            free_list_fault(next, bitmap, head, tail).expect("a fault")
        };
        // The bitmap holding two blocks in one, or one past those kept.
        assert!(fault(&next, &[2, 2], head, tail).contains("two blocks in block 2"));
        assert!(fault(&next, &[2, 40], head, tail).contains("block 40, past the 32"));
        // The list holding a block of the bitmap, a block twice, or one past those kept.
        assert!(fault(&next, &bitmap, 1, tail).contains("holds block 1"));
        let mut looped = next.clone();
        looped[10] = 4;
        assert!(fault(&looped, &bitmap, head, tail).contains("reaches block 4 twice"));
        let mut past = next.clone();
        past[10] = 32;
        assert!(fault(&past, &bitmap, head, tail).contains("names block 32 of the 32"));
        // The list's ends against its head and tail.
        assert!(fault(&next, &bitmap, 0xFFFF, tail).contains("empty and records a tail"));
        assert!(fault(&next, &bitmap, head, 10).contains("does not end at its tail"));
        let mut short = next.clone();
        short[10] = 0xFFFF;
        assert!(fault(&short, &bitmap, head, tail).contains("ends before its tail"));
        // A block on neither, and a block of the bitmap that leads on.
        assert!(fault(&short, &bitmap, head, 10).contains("holds 8 blocks, and 30 of the 32"));
        let mut leads = next.clone();
        leads[1] = 5;
        assert!(fault(&leads, &bitmap, head, tail).contains("leads on from block 1"));
    }

    #[test]
    fn a_run_nested_inside_another_is_met_where_it_lies() {
        // A queue's run inside a reached one, sorted by first block: ends are not in order, so
        // the runs meeting a block are found by the furthest end reached so far.
        let runs = [
            (10, 40, By::DataArea),
            (12, 14, By::MainQueue),
            (20, 30, By::DescriptorArea),
        ];
        let reach: Vec<u64> = runs
            .iter()
            .scan(0u64, |far, r| {
                *far = (*far).max(r.1);
                Some(*far)
            })
            .collect();
        let met =
            |start, end| -> Vec<u64> { meeting(&runs, &reach, start, end).map(|r| r.0).collect() };
        assert_eq!(met(15, 16), [10]);
        assert_eq!(met(13, 21), [10, 12, 20]);
        assert_eq!(met(35, 50), [10]);
        assert_eq!(met(40, 50), Vec::<u64>::new());
        assert_eq!(met(0, 10), Vec::<u64>::new());
    }

    #[test]
    fn an_identifier_two_mappings_name_is_no_one_object() {
        // The reaper's mapping given the main queue's identifier: a lookup of the queue by its
        // identifier, as a queue's lower nodes are found, cannot say which block it is.
        let mut image = queued().image();
        let queue = get_u64(&image, DESC_BASE as usize * BLOCK + 40 + 2 * 40 + 24);
        let mut container = Container::open(std::io::Cursor::new(image.clone())).expect("opens");
        assert!(container.ephemeral_address(queue).is_ok());
        change(&mut image, DESC_BASE, |b| put_u64(b, 40 + 40 + 24, queue));
        let mut container = Container::open(std::io::Cursor::new(image)).expect("opens");
        assert!(matches!(
            container.ephemeral_address(queue),
            Err(ReadError::WrongObject { fault, .. })
                if fault == "an identifier another mapping of the checkpoint names"
        ));
    }

    #[test]
    fn each_mapping_names_an_object_that_records_it() {
        const FIRST: usize = 40;
        let edited = |edit: &dyn Fn(&mut [u8])| {
            let mut image = Forge::populated().image();
            change(&mut image, DESC_BASE, edit);
            graded(image)
        };
        let conformance = [(Severity::Conformance, Some(DESC_BASE))];
        // The last block's flag, the reserved word, and a volume the container does not list.
        assert_eq!(edited(&|b| put_u32(b, 32, 0)), conformance);
        assert_eq!(edited(&|b| put_u32(b, FIRST + 12, 1)), conformance);
        assert_eq!(edited(&|b| put_u64(b, FIRST + 16, 7)), conformance);
        // A subtype the object does not record.
        assert_eq!(
            edited(&|b| put_u32(b, FIRST + 4, 3)),
            [(Severity::Conformance, Some(SM))]
        );
        // An object outside the data area.
        let found = edited(&|b| put_u64(b, FIRST + 32, 100));
        assert!(
            found.contains(&(Severity::Structural, Some(100))),
            "{found:?}"
        );
        // No space manager mapped at all.
        let found = edited(&|b| put_u64(b, FIRST + 24, 7));
        assert_eq!(found, [(Severity::Structural, Some(DESC_BASE + 1))]);
    }

    #[test]
    fn a_data_area_past_the_container_is_reported_and_no_mapping_is_held_to_it() {
        // The area and the first mapping moved to where an end past either is past what 64 bits
        // hold: in block zero and the live checkpoint superblock alike, so a strict open reads
        // the checkpoint as whole.
        const DATA_BLOCKS: usize = 108;
        const DATA_BASE: usize = 120;
        const FIRST_ADDRESS: usize = 40 + 32;
        let far = u64::MAX - 100;
        let mut image = Forge::populated().image();
        for block in [0, DESC_BASE + 1] {
            change(&mut image, block, |b| {
                put_u32(b, DATA_BLOCKS, 512);
                put_u64(b, DATA_BASE, far);
            });
        }
        change(&mut image, DESC_BASE, |b| put_u64(b, FIRST_ADDRESS, far));
        for policy in [ReadPolicy::Strict, ReadPolicy::Lenient] {
            let options = OpenOptions::new().common(crate::OpenOptions::new().policy(policy));
            let mut reader =
                Reader::open_with(std::io::Cursor::new(image.clone()), &options).expect("it opens");
            let found: Vec<_> = reader
                .scan()
                .anomalies()
                .iter()
                .filter(|a| a.category == Category::Space && a.block == Some(far))
                .map(|a| (a.severity, a.detail.contains("container")))
                .collect();
            // The area past the container's blocks, and the mapping outside the container.
            assert_eq!(
                found,
                [(Severity::Structural, true), (Severity::Structural, true)],
                "{policy:?}"
            );
        }
    }

    #[test]
    fn the_reaper_is_held_to_its_flag_and_its_account_of_itself() {
        const REAPER: u64 = SM + 1;
        let mut image = Forge::populated().image();
        change(&mut image, REAPER, |b| put_u32(b, 64, 0));
        assert_eq!(graded(image), [(Severity::Conformance, Some(REAPER))]);
        let mut image = Forge::populated().image();
        change(&mut image, REAPER, |b| put_u64(b, 40, 1));
        assert_eq!(graded(image), [(Severity::Conformance, Some(REAPER))]);
        // A reap in progress: what it holds is not walked, so a block nothing reaches is not
        // called spent on nothing.
        let mut image = Forge::populated().image();
        change(&mut image, REAPER, |b| put_u64(b, 32, 3));
        flip_bit(&mut image, 200);
        assert_eq!(graded(image), [(Severity::Cosmetic, Some(200))]);
    }

    #[test]
    fn a_second_device_and_a_reserve_are_held_to_the_volumes() {
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| put_u64(b, 96, 1));
        assert_eq!(graded(image), [(Severity::Conformance, Some(SM))]);
        // A volume reserving blocks the space manager does not record as reserved.
        let mut image = Forge::populated().image();
        change(&mut image, VOLUME_AT, |b| put_u64(b, 72, 100));
        assert_eq!(graded(image.clone()), [(Severity::Conformance, Some(SM))]);
        // And recorded: the reserve, and of it what the volume takes.
        let taken = get_u64(&image, VOLUME_AT as usize * BLOCK + 88);
        change(&mut image, SM, |b| {
            put_u64(b, 184, 100);
            put_u64(b, 192, taken);
        });
        assert_eq!(graded(image), []);
    }

    #[test]
    fn a_deleted_objects_record_reaches_nothing() {
        // Its block is free; reading the record as the object's would call it a block in use
        // marked free.
        let mut forge = Forge::populated();
        forge.deleted = vec![(1095, XID, 200)];
        assert_eq!(space(forge.image()), []);
    }

    #[test]
    fn a_block_two_things_reach_is_integrity_damage() {
        let mut forge = Forge::populated();
        let hello = forge::extent(16, 0, 0, 0).0;
        forge.records.retain(|(key, _)| key[..8] != hello[..8]);
        forge.extent(16, 0, 2, FS_ROOT_AT);
        let found = graded(forge.image());
        assert!(
            found.contains(&(Severity::Integrity, Some(FS_ROOT_AT))),
            "{found:?}"
        );
    }

    #[test]
    fn a_space_manager_of_another_geometry_is_refused_and_read_no_further() {
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| put_u32(b, 40, 125));
        assert_eq!(graded(image), [(Severity::Structural, Some(SM))]);
    }

    #[test]
    fn a_block_count_no_container_has_is_a_geometry_the_space_manager_disagrees_with() {
        // Every superblock claims 2^62 blocks: more chunk-info blocks than any field holds,
        // which the geometry computes without narrowing and the space manager's fields fail.
        let mut image = Forge::populated().image();
        for block in 0..DESC_BASE + 8 {
            let at = block as usize * BLOCK;
            if image[at + 32..at + 36] == *b"NXSB" {
                change(&mut image, block, |b| put_u64(b, 40, 1 << 62));
            }
        }
        let found = graded(image);
        assert!(
            found.contains(&(Severity::Structural, Some(SM))),
            "{found:?}"
        );
    }

    #[test]
    fn an_internal_pool_no_bitmap_could_hold_is_refused_before_anything_is_sized_by_it() {
        let mut image = Forge::populated().image();
        change(&mut image, SM, |b| put_u64(b, 152, u64::MAX / 4));
        let found = graded(image);
        assert!(
            found.contains(&(Severity::Structural, Some(SM))),
            "{found:?}"
        );
        // A free queue run of every block there could be.
        let mut image = queued().image();
        let tree = (SM + 2) as usize * BLOCK;
        let toc = get_u16(&image, tree + 56 + 2) as usize;
        put_u64(&mut image, tree + BLOCK - 40 - toc, u64::MAX / 2);
        reseal(&mut image, SM + 2);
        let found = graded(image);
        assert!(
            found.iter().any(|f| f.0 == Severity::Structural),
            "{found:?}"
        );
    }
}
