//! The file allocation table: one entry per cluster, packed at the width the type gives it.
//!
//! The table is the format's whole allocation record. Entry `n` says what follows cluster
//! `n` in its chain: another cluster number, an end-of-chain mark, a bad-cluster mark, or
//! zero for free. Entries 0 and 1 name no cluster — the data region's first cluster is
//! numbered 2 — and carry the media descriptor and a pair of status bits instead.
//!
//! # Why the width is the whole difficulty
//!
//! FAT12 packs three bytes to two entries, so an entry begins on a byte boundary only every
//! other time and one may straddle a sector boundary. FAT16 and FAT32 divide evenly. Every
//! function here therefore takes the [`FatType`] and computes the position rather than
//! assuming one, and the FAT32 functions mask to 28 bits: the top four are reserved, and a
//! driver preserves them across an update rather than writing them.
//!
//! Nothing here interprets a chain. These are the byte-level accessors; following one is the
//! reader's business and building one is the writer's.

use crate::bytes::{get_u8, get_u16, get_u32, put_u8, put_u16, put_u32};
use crate::fat::FatType;

/// The entry every table holds at index 0: the media descriptor in the low eight bits, with
/// every other bit of the entry's width set.
///
/// It is not an allocation. A driver compares its low byte against the boot sector's media
/// descriptor as a coarse check that the table belongs to the volume.
#[must_use]
pub const fn media_entry(fat_type: FatType, media: u8) -> u32 {
    (entry_mask(fat_type) & !0xFF) | media as u32
}

/// The entry every table holds at index 1: every bit of the entry's width set.
///
/// On FAT16 and FAT32 the top two bits double as status flags — a clean-shutdown bit and a
/// hard-error bit — and both are set to mean "clean" and "no error". Writing the value whole
/// is therefore both the conventional content and the correct status.
#[must_use]
pub const fn tail_entry(fat_type: FatType) -> u32 {
    entry_mask(fat_type)
}

/// The value written into the last entry of a chain.
///
/// Any value from `mask - 7` up marks the end, and every driver tests the range rather than
/// the value; this is the one every mainstream formatter writes.
#[must_use]
pub const fn end_of_chain(fat_type: FatType) -> u32 {
    entry_mask(fat_type) & !0x7
}

/// The value marking a cluster unusable. It is the one value below [`end_of_chain`] that no
/// chain may contain.
#[must_use]
pub const fn bad_cluster(fat_type: FatType) -> u32 {
    entry_mask(fat_type) - 8
}

/// The value in a free cluster's entry.
pub const FREE: u32 = 0;

/// Every bit an entry of this type holds. FAT32's entry is 32 bits wide and only 28 of them
/// are the cluster number.
#[must_use]
pub const fn entry_mask(fat_type: FatType) -> u32 {
    match fat_type {
        FatType::Fat12 => 0x0000_0FFF,
        FatType::Fat16 => 0x0000_FFFF,
        FatType::Fat32 => 0x0FFF_FFFF,
    }
}

/// Whether `entry` marks the end of a chain, by the range test every driver applies rather
/// than by equality with what a formatter happens to write.
#[must_use]
pub const fn is_end_of_chain(fat_type: FatType, entry: u32) -> bool {
    entry >= end_of_chain(fat_type)
}

/// Whether `entry` names a cluster that could exist — neither free, nor reserved, nor bad,
/// nor an end-of-chain mark. Whether the volume *has* that cluster is a separate question,
/// answered by the layout.
#[must_use]
pub const fn is_cluster(fat_type: FatType, entry: u32) -> bool {
    entry >= 2 && entry < bad_cluster(fat_type)
}

/// Where entry `cluster` begins within a table, in bytes.
///
/// On FAT12 this is not a multiple of the entry width: two entries share three bytes, so the
/// even-numbered one occupies the low twelve bits of a byte pair and the odd one the high
/// twelve.
#[must_use]
pub const fn entry_offset(fat_type: FatType, cluster: u32) -> u64 {
    let n = cluster as u64;
    match fat_type {
        FatType::Fat12 => n + n / 2,
        FatType::Fat16 => n * 2,
        FatType::Fat32 => n * 4,
    }
}

/// Bytes one entry's read or write touches, from its offset.
///
/// This is not the entry's width. A 12-bit entry occupies a byte and a half and shares the
/// other half with its neighbour, so reading or writing one touches two bytes whichever side
/// of the shared nibble it sits on — which is what a caller sizing a buffer for a range of
/// entries needs, rather than the width.
#[must_use]
pub const fn entry_span(fat_type: FatType) -> u64 {
    match fat_type {
        FatType::Fat12 | FatType::Fat16 => 2,
        FatType::Fat32 => 4,
    }
}

/// Whether a table of `bytes` bytes holds an entry for `cluster`.
///
/// All three widths need exactly the bytes their offset touches. The addition is checked, so
/// a cluster number large enough to wrap the offset arithmetic is refused rather than
/// answering for some other entry.
#[must_use]
pub const fn fits(fat_type: FatType, cluster: u32, bytes: u64) -> bool {
    let off = entry_offset(fat_type, cluster);
    match off.checked_add(entry_span(fat_type)) {
        Some(end) => end <= bytes,
        None => false,
    }
}

/// The entry for `cluster`, read from a table whose byte 0 is `table`'s byte 0.
///
/// Returns `None` where the table is too short to hold the entry, so a cluster number out of
/// the table's range is answered rather than indexed.
///
/// The value is masked to the type's width: FAT32's top four bits are reserved and are not
/// part of the cluster number, so a caller comparing against
/// [`end_of_chain`] or [`is_cluster`] is comparing like with like.
#[must_use]
pub fn read_entry(fat_type: FatType, table: &[u8], cluster: u32) -> Option<u32> {
    if !fits(fat_type, cluster, table.len() as u64) {
        return None;
    }
    let off = entry_offset(fat_type, cluster) as usize;
    Some(match fat_type {
        FatType::Fat12 => {
            // Two entries share three bytes. The even one is the low twelve bits of the pair
            // at its offset and the odd one is the high twelve, so the pair is read whole and
            // then shifted or masked.
            let pair = u32::from(get_u16(table, off));
            if cluster & 1 == 0 {
                pair & 0xFFF
            } else {
                pair >> 4
            }
        }
        FatType::Fat16 => u32::from(get_u16(table, off)),
        FatType::Fat32 => get_u32(table, off) & entry_mask(FatType::Fat32),
    })
}

/// Write `value` into the entry for `cluster`, in a table whose byte 0 is `table`'s byte 0.
///
/// Returns `false` where the table is too short to hold the entry, having written nothing.
///
/// Two widths write less than a whole field, and both matter. A FAT12 entry shares a byte
/// with its neighbour, so the neighbour's half is read and preserved; a FAT32 entry's top
/// four bits are reserved, so they are preserved too. A write that clobbered either would
/// corrupt a cluster this call was not addressing.
pub fn write_entry(fat_type: FatType, table: &mut [u8], cluster: u32, value: u32) -> bool {
    if !fits(fat_type, cluster, table.len() as u64) {
        return false;
    }
    let off = entry_offset(fat_type, cluster) as usize;
    match fat_type {
        FatType::Fat12 => {
            // The two entries sharing these three bytes each own one nibble of the middle
            // one, so the middle byte is read and half of it kept. `fits` has already
            // established that both bytes are there.
            let value = value & 0xFFF;
            if cluster & 1 == 0 {
                put_u8(table, off, value as u8);
                let keep = get_u8(table, off + 1) & 0xF0;
                put_u8(table, off + 1, keep | (value >> 8) as u8);
            } else {
                let keep = get_u8(table, off) & 0x0F;
                put_u8(table, off, keep | ((value << 4) & 0xF0) as u8);
                put_u8(table, off + 1, (value >> 4) as u8);
            }
        }
        FatType::Fat16 => put_u16(table, off, value as u16),
        FatType::Fat32 => {
            let reserved = get_u32(table, off) & !entry_mask(FatType::Fat32);
            put_u32(table, off, reserved | (value & entry_mask(FatType::Fat32)));
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserved_entries_are_what_the_baseline_writes() {
        // Read out of images the pinned `mkfs.fat` wrote, so these are transcribed
        // observations rather than a restatement of the code above.
        assert_eq!(media_entry(FatType::Fat12, 0xF8), 0xFF8);
        assert_eq!(tail_entry(FatType::Fat12), 0xFFF);
        assert_eq!(media_entry(FatType::Fat16, 0xF8), 0xFFF8);
        assert_eq!(tail_entry(FatType::Fat16), 0xFFFF);
        assert_eq!(media_entry(FatType::Fat32, 0xF8), 0x0FFF_FFF8);
        assert_eq!(tail_entry(FatType::Fat32), 0x0FFF_FFFF);
        assert_eq!(end_of_chain(FatType::Fat32), 0x0FFF_FFF8);
        // Removable media puts a different byte in the low eight bits and changes nothing
        // above them.
        assert_eq!(media_entry(FatType::Fat16, 0xF0), 0xFFF0);
    }

    #[test]
    fn an_end_of_chain_mark_is_recognized_by_range_and_not_by_value() {
        for kind in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            let mask = entry_mask(kind);
            assert!(is_end_of_chain(kind, end_of_chain(kind)));
            assert!(is_end_of_chain(kind, mask), "{kind}: the all-ones mark");
            // Every value from mask - 7 up ends a chain, and the one below it is the
            // bad-cluster mark rather than an end.
            assert!(is_end_of_chain(kind, mask - 7));
            assert!(!is_end_of_chain(kind, bad_cluster(kind)));
            assert!(!is_cluster(kind, bad_cluster(kind)));
            assert!(!is_cluster(kind, FREE));
            assert!(!is_cluster(kind, 1), "cluster 1 does not exist");
            assert!(is_cluster(kind, 2), "the data region begins at cluster 2");
        }
    }

    #[test]
    fn twelve_bit_entries_pack_three_bytes_to_two_clusters() {
        // The packing the specification states, checked against bytes written by hand: entry
        // 2 is 0x123 and entry 3 is 0x456, which occupy `23 61 45`.
        let mut table = vec![0u8; 16];
        assert!(write_entry(FatType::Fat12, &mut table, 2, 0x123));
        assert!(write_entry(FatType::Fat12, &mut table, 3, 0x456));
        assert_eq!(&table[3..6], &[0x23, 0x61, 0x45]);
        assert_eq!(read_entry(FatType::Fat12, &table, 2), Some(0x123));
        assert_eq!(read_entry(FatType::Fat12, &table, 3), Some(0x456));

        // And writing one does not disturb the other, in either order — the half-byte they
        // share is read and preserved rather than overwritten.
        assert!(write_entry(FatType::Fat12, &mut table, 3, 0xFFF));
        assert_eq!(read_entry(FatType::Fat12, &table, 2), Some(0x123));
        assert!(write_entry(FatType::Fat12, &mut table, 2, 0xABC));
        assert_eq!(read_entry(FatType::Fat12, &table, 3), Some(0xFFF));
    }

    #[test]
    fn every_width_round_trips_every_value_it_holds() {
        for (kind, count) in [
            (FatType::Fat12, 200u32),
            (FatType::Fat16, 200),
            (FatType::Fat32, 200),
        ] {
            let mask = entry_mask(kind);
            let mut table = vec![0u8; 4096];
            // A value derived from the cluster number, so a write that landed on the wrong
            // entry reads back as a different value rather than as the same one.
            for n in 0..count {
                assert!(write_entry(kind, &mut table, n, (n * 7 + 1) & mask));
            }
            for n in 0..count {
                assert_eq!(
                    read_entry(kind, &table, n),
                    Some((n * 7 + 1) & mask),
                    "{kind}: entry {n}"
                );
            }
        }
    }

    #[test]
    fn a_fat32_entry_preserves_the_four_bits_that_are_not_the_cluster_number() {
        // A driver keeps them across an update, so a write that zeroed them would be
        // rewriting a field it was not addressing.
        let mut table = vec![0u8; 32];
        put_u32(&mut table, 8, 0xF000_0000);
        assert!(write_entry(FatType::Fat32, &mut table, 2, 0x0123_4567));
        assert_eq!(get_u32(&table, 8), 0xF123_4567);
        // And reading masks them off, so the value compares against a cluster number.
        assert_eq!(read_entry(FatType::Fat32, &table, 2), Some(0x0123_4567));
    }

    #[test]
    fn an_entry_past_the_table_is_answered_rather_than_indexed() {
        for kind in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            let mut table = vec![0u8; 6];
            let past = 1000;
            assert!(!fits(kind, past, table.len() as u64));
            assert_eq!(read_entry(kind, &table, past), None);
            assert!(!write_entry(kind, &mut table, past, 1));
            assert!(table.iter().all(|&b| b == 0), "a refused write wrote bytes");
            // The highest cluster number there is addresses an offset far past any table,
            // and is answered by the same path rather than wrapping into a valid one.
            assert_eq!(read_entry(kind, &table, u32::MAX), None, "{kind}");
        }
        // The last entry a table holds is in, and the one after it is out — the boundary the
        // check is actually about.
        let table = vec![0u8; 8];
        assert!(fits(FatType::Fat32, 1, 8));
        assert!(!fits(FatType::Fat32, 2, 8));
        assert!(read_entry(FatType::Fat32, &table, 1).is_some());
        assert!(read_entry(FatType::Fat32, &table, 2).is_none());
        // FAT12's last entry is the one whose two bytes are both there, which for an
        // odd-length table is the entry before the one the width alone would allow.
        assert!(fits(FatType::Fat12, 4, 8), "entry 4 begins at byte 6");
        assert!(!fits(FatType::Fat12, 5, 8), "entry 5 begins at byte 7");
    }

    #[test]
    fn the_offsets_are_where_the_format_puts_them() {
        assert_eq!(entry_offset(FatType::Fat12, 0), 0);
        assert_eq!(entry_offset(FatType::Fat12, 2), 3);
        assert_eq!(entry_offset(FatType::Fat12, 3), 4);
        assert_eq!(entry_offset(FatType::Fat12, 4), 6);
        assert_eq!(entry_offset(FatType::Fat16, 2), 4);
        assert_eq!(entry_offset(FatType::Fat32, 2), 8);
    }
}
