//! The chunk layer: the one path from a logical address to a place on the device.
//!
//! Every address above this module is logical — every tree root, every child pointer, every
//! extent — and none of them is a byte offset into anything. The chunk tree is what turns one
//! into the other, and this is the map built from it.
//!
//! # The bootstrap
//!
//! The chunk tree's own root is a logical address, so finding it needs the map that reading it
//! would build. The format breaks the circle by copying the chunk items that cover the chunk
//! tree into the superblock, as an array of `(key, chunk)` pairs — so a reader loads that
//! array first, translates the chunk root through it, reads the chunk tree, and adds
//! everything the tree says. [`ChunkMap::from_bootstrap`] is the first half and
//! [`ChunkMap::insert`] is what the second half calls.
//!
//! # One path, and why there is not a shortcut beside it
//!
//! On a filesystem this crate writes the mapping would be simple enough to inline. On the
//! filesystems it must *read* it is not: a chunk's logical start and its physical start are
//! unrelated numbers, and on a filesystem that has been balanced they are far apart. A
//! shortcut that assumed otherwise would work on every image this project produces and be
//! wrong on half the images it opens, so there is one translation and every read goes through
//! it.
//!
//! # What it refuses
//!
//! A chunk whose stripes are pieces rather than copies needs more than one device to read, and
//! a chunk whose profile the format does not define means nothing at all. Both are refused by
//! name rather than translated as though the first stripe were the whole of them — a wrong
//! translation is a successful read of the wrong bytes.
//!
//! This module is pure: it holds a map and answers questions about it. Reading the chunk tree
//! that fills it is [`Volume`](super::Volume)'s.

use super::ReadError;
use super::ondisk::{BlockGroupFlags, Chunk, DiskKey, ItemType, Stripe, objectid};

/// One chunk of the map: a run of logical space, and where its copies are on this device.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MappedChunk {
    /// The logical address the run begins at, which is the chunk item's key offset rather than
    /// a field of the chunk.
    pub logical: u64,
    /// How much logical space it covers.
    pub length: u64,
    /// What the space holds and how it is replicated.
    pub flags: BlockGroupFlags,
    /// Where each copy begins on this device, in ascending stripe order. Never empty: a chunk
    /// with no copy on the device in hand is not in the map.
    pub copies: Vec<u64>,
}

impl MappedChunk {
    /// One past the last logical byte this chunk covers.
    ///
    /// The sum is checked when the chunk enters the map, so this cannot overflow.
    #[must_use]
    pub const fn logical_end(&self) -> u64 {
        self.logical + self.length
    }
}

/// Every chunk of one device's filesystem, ordered by logical address and free of overlap.
///
/// Built in two stages — the superblock's bootstrap array, then the chunk tree read through it
/// — and consulted by every read above this layer.
#[derive(Clone, Default, Debug)]
pub struct ChunkMap {
    /// Sorted by `logical`, with no two entries overlapping. Both properties are established
    /// by [`insert`](Self::insert) and relied on by [`translate`](Self::translate)'s binary
    /// search.
    chunks: Vec<MappedChunk>,
}

impl ChunkMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    /// Every chunk, in ascending logical order.
    #[must_use]
    pub fn chunks(&self) -> &[MappedChunk] {
        &self.chunks
    }

    /// How many chunks the map holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the map holds no chunks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Add one chunk, given the key it was found under and the buffer its stripes sit in.
    ///
    /// `devid` and `device_bytes` are the device in hand: a stripe on some other device is
    /// skipped, and a chunk with no stripe on this one is refused, because a filesystem
    /// spanning devices is not one this image is the whole of.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadChunk`] for a chunk that cannot describe a mapping — no length, no
    /// stripes, a profile whose stripes are not copies, a placement that leaves the device, or
    /// a logical run that leaves the 64-bit range. [`ReadError::ChunkOverlap`] where the run
    /// meets one already in the map, since two mappings for one address is two answers.
    pub fn insert(
        &mut self,
        key: &DiskKey,
        chunk: &Chunk,
        record: &[u8],
        devid: u64,
        device_bytes: u64,
    ) -> Result<(), ReadError> {
        if key.kind != ItemType::CHUNK_ITEM || key.objectid != objectid::FIRST_CHUNK_TREE {
            return Err(ReadError::BadChunk {
                logical: key.offset,
                fault: "a chunk item is keyed by the first-chunk-tree objectid and the chunk type",
            });
        }
        let logical = key.offset;
        if chunk.length == 0 {
            return Err(ReadError::BadChunk {
                logical,
                fault: "a chunk covers no logical space",
            });
        }
        if logical.checked_add(chunk.length).is_none() {
            return Err(ReadError::BadChunk {
                logical,
                fault: "a chunk's logical run leaves the address space",
            });
        }
        if chunk.num_stripes == 0 {
            return Err(ReadError::BadChunk {
                logical,
                fault: "a chunk records no copy of itself",
            });
        }
        if !chunk.ty.is_mirrored() {
            return Err(ReadError::UnsupportedProfile {
                logical,
                flags: chunk.ty.bits(),
            });
        }

        let mut copies = Vec::new();
        for index in 0..chunk.num_stripes {
            let Stripe {
                devid: stripe_dev,
                offset,
                ..
            } = chunk.stripe_at(record, index)?;
            if stripe_dev != devid {
                // A copy on a device this image is not. The filesystem may still be readable
                // through the copies that are here, so this is a stripe skipped rather than a
                // chunk refused — and a chunk with no copy at all here is caught below.
                continue;
            }
            match offset.checked_add(chunk.length) {
                Some(end) if end <= device_bytes => copies.push(offset),
                _ => {
                    return Err(ReadError::BadChunk {
                        logical,
                        fault: "a copy of a chunk is placed past the end of the device",
                    });
                }
            }
        }
        if copies.is_empty() {
            return Err(ReadError::BadChunk {
                logical,
                fault: "no copy of a chunk is on the device this image holds",
            });
        }

        let at = self.chunks.partition_point(|c| c.logical < logical);
        let overlaps_before = at
            .checked_sub(1)
            .is_some_and(|prev| self.chunks[prev].logical_end() > logical);
        let overlaps_after = self
            .chunks
            .get(at)
            .is_some_and(|next| next.logical < logical + chunk.length);
        if overlaps_before || overlaps_after {
            return Err(ReadError::ChunkOverlap { logical });
        }
        self.chunks.insert(
            at,
            MappedChunk {
                logical,
                length: chunk.length,
                flags: chunk.ty,
                copies,
            },
        );
        Ok(())
    }

    /// Load the chunks the superblock's bootstrap array carries.
    ///
    /// The array is a run of `(key, chunk)` pairs whose total length the superblock records.
    /// It carries only what is needed to reach the chunk tree — one system chunk on a
    /// filesystem the pinned baseline writes — so the map it produces is complete for that one
    /// address and for nothing else.
    ///
    /// # Errors
    ///
    /// Whatever [`insert`](Self::insert) refuses, and [`ReadError::BadBootstrap`] where the
    /// array's own framing does not hold: a pair that runs past the recorded length, or a
    /// length past the array.
    pub fn from_bootstrap(array: &[u8], devid: u64, device_bytes: u64) -> Result<Self, ReadError> {
        let mut map = Self::new();
        let mut at = 0usize;
        while at < array.len() {
            let rest = &array[at..];
            if rest.len() < DiskKey::SIZE {
                return Err(ReadError::BadBootstrap {
                    at,
                    fault: "a key runs past the end of the bootstrap array",
                });
            }
            let key = DiskKey::read_from(rest)?;
            let head = &rest[DiskKey::SIZE..];
            if head.len() < Chunk::SIZE {
                return Err(ReadError::BadBootstrap {
                    at,
                    fault: "a chunk runs past the end of the bootstrap array",
                });
            }
            let chunk = Chunk::read_from(head)?;
            let encoded = chunk.encoded_len();
            if head.len() < encoded {
                return Err(ReadError::BadBootstrap {
                    at,
                    fault: "a chunk's stripes run past the end of the bootstrap array",
                });
            }
            map.insert(&key, &chunk, &head[..encoded], devid, device_bytes)?;
            at += DiskKey::SIZE + encoded;
        }
        if map.is_empty() {
            return Err(ReadError::BadBootstrap {
                at: 0,
                fault: "the bootstrap array carries no chunk, so no address can be translated",
            });
        }
        Ok(map)
    }

    /// The chunk covering `logical`, or [`None`] where nothing maps it.
    #[must_use]
    pub fn chunk_at(&self, logical: u64) -> Option<&MappedChunk> {
        let at = self.chunks.partition_point(|c| c.logical <= logical);
        let candidate = self.chunks.get(at.checked_sub(1)?)?;
        (logical < candidate.logical_end()).then_some(candidate)
    }

    /// Where on the device the `len` bytes at `logical` begin.
    ///
    /// The whole run must fall inside one chunk. A run that begins inside a chunk and ends
    /// past it is refused rather than translated from its start, because the bytes past the
    /// boundary belong to a different place on the device and reading them as though they
    /// followed would hand back a block assembled out of two.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnmappedLogical`] where no chunk covers the address, or where the run
    /// leaves the chunk that covers its start.
    pub fn translate(&self, logical: u64, len: u64) -> Result<u64, ReadError> {
        let chunk = self
            .chunk_at(logical)
            .ok_or(ReadError::UnmappedLogical { logical, len })?;
        let within = logical - chunk.logical;
        match within.checked_add(len) {
            Some(end) if end <= chunk.length => {}
            _ => return Err(ReadError::UnmappedLogical { logical, len }),
        }
        // The sum is bounded: `insert` established that this copy plus the chunk's whole
        // length is within the device, and `within + len` is no larger than that length.
        Ok(chunk.copies[0] + within)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVID: u64 = 1;
    const DEVICE_BYTES: u64 = 1 << 30;

    /// A chunk record — the head and its stripes — as it sits in a leaf or in the bootstrap
    /// array, with one copy per entry of `at`.
    fn record(length: u64, flags: BlockGroupFlags, at: &[(u64, u64)]) -> (Chunk, Vec<u8>) {
        let chunk = Chunk {
            length,
            owner: objectid::EXTENT_TREE,
            stripe_len: 64 << 10,
            ty: flags,
            io_align: 64 << 10,
            io_width: 64 << 10,
            sector_size: 4096,
            num_stripes: at.len() as u16,
            sub_stripes: 1,
        };
        let mut buf = vec![0u8; chunk.encoded_len()];
        chunk.write_to(&mut buf);
        for (index, &(devid, offset)) in at.iter().enumerate() {
            Stripe {
                devid,
                offset,
                dev_uuid: [0xec; 16],
            }
            .write_to(&mut buf[Chunk::SIZE + index * Stripe::SIZE..]);
        }
        (chunk, buf)
    }

    fn key_at(logical: u64) -> DiskKey {
        DiskKey::new(objectid::FIRST_CHUNK_TREE, ItemType::CHUNK_ITEM, logical)
    }

    /// One chunk of a fixture map: its logical start, its length, its type-and-profile word,
    /// and one `(device, physical offset)` per copy.
    type Entry<'a> = (u64, u64, BlockGroupFlags, &'a [(u64, u64)]);

    fn map_with(entries: &[Entry<'_>]) -> ChunkMap {
        let mut map = ChunkMap::new();
        for &(logical, length, flags, at) in entries {
            let (chunk, buf) = record(length, flags, at);
            map.insert(&key_at(logical), &chunk, &buf, DEVID, DEVICE_BYTES)
                .expect("a well-formed chunk");
        }
        map
    }

    #[test]
    fn a_logical_address_lands_where_the_chunk_puts_it_and_not_where_it_started() {
        // The mapping the pinned baseline writes for a 1 GiB image: a metadata chunk whose
        // logical start and physical start are unrelated numbers. An identity shortcut would
        // have read this filesystem's root tree out of the wrong eight megabytes.
        let map = map_with(&[(
            30_408_704,
            53_673_984,
            BlockGroupFlags::METADATA | BlockGroupFlags::DUP,
            &[(DEVID, 38_797_312), (DEVID, 92_471_296)],
        )]);
        assert_eq!(
            map.translate(30_605_312, 16_384).expect("mapped"),
            38_993_920
        );
        // The first byte of the chunk, and the last block of it.
        assert_eq!(
            map.translate(30_408_704, 16_384).expect("mapped"),
            38_797_312
        );
        let last = 30_408_704 + 53_673_984 - 16_384;
        assert_eq!(
            map.translate(last, 16_384).expect("mapped"),
            38_797_312 + 53_673_984 - 16_384
        );
    }

    #[test]
    fn an_address_no_chunk_covers_is_no_address() {
        let map = map_with(&[(
            1 << 20,
            8 << 20,
            BlockGroupFlags::SYSTEM | BlockGroupFlags::DUP,
            &[(DEVID, 1 << 20)],
        )]);
        // Below every chunk, and past the only one.
        assert!(matches!(
            map.translate(0, 4096),
            Err(ReadError::UnmappedLogical { .. })
        ));
        assert!(matches!(
            map.translate((1 << 20) + (8 << 20), 4096),
            Err(ReadError::UnmappedLogical { .. })
        ));
        // And the gap between two chunks is not covered by either of them.
        let gapped = map_with(&[
            (0, 1 << 20, BlockGroupFlags::SYSTEM, &[(DEVID, 0)]),
            (4 << 20, 1 << 20, BlockGroupFlags::DATA, &[(DEVID, 4 << 20)]),
        ]);
        assert!(matches!(
            gapped.translate(2 << 20, 4096),
            Err(ReadError::UnmappedLogical { .. })
        ));
    }

    #[test]
    fn a_run_that_leaves_its_chunk_is_refused_rather_than_translated_from_its_start() {
        // The bytes past the boundary are somewhere else on the device entirely, so a
        // translation from the start would hand back a block assembled out of two places.
        let map = map_with(&[
            (0, 1 << 20, BlockGroupFlags::SYSTEM, &[(DEVID, 8 << 20)]),
            (
                1 << 20,
                1 << 20,
                BlockGroupFlags::METADATA,
                &[(DEVID, 64 << 20)],
            ),
        ]);
        assert_eq!(
            map.translate((1 << 20) - 4096, 4096).expect("inside"),
            (8 << 20) + (1 << 20) - 4096
        );
        assert!(matches!(
            map.translate((1 << 20) - 4096, 8192),
            Err(ReadError::UnmappedLogical { .. })
        ));
        // A length that would wrap the range is refused by the same check rather than
        // wrapping into a run that appears to fit.
        assert!(matches!(
            map.translate(4096, u64::MAX),
            Err(ReadError::UnmappedLogical { .. })
        ));
    }

    #[test]
    fn two_chunks_claiming_one_address_is_two_answers_and_is_refused() {
        let mut map = map_with(&[(0, 8 << 20, BlockGroupFlags::DATA, &[(DEVID, 0)])]);
        // Beginning inside the one already there.
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID, 16 << 20)]);
        assert!(matches!(
            map.insert(&key_at(4 << 20), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::ChunkOverlap { .. })
        ));
        // And ending inside it, having begun below.
        let (chunk, buf) = record(8 << 20, BlockGroupFlags::DATA, &[(DEVID, 16 << 20)]);
        assert!(matches!(
            map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::ChunkOverlap { .. })
        ));
        // Exactly abutting is not overlapping, and is how a filesystem's chunks actually sit.
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID, 16 << 20)]);
        map.insert(&key_at(8 << 20), &chunk, &buf, DEVID, DEVICE_BYTES)
            .expect("abutting is not overlapping");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn a_chunk_whose_stripes_are_pieces_rather_than_copies_is_refused_by_name() {
        // Every striped profile needs more than one device to read. Translating one through
        // its first stripe would hand back every *n*th piece of the run as though it were the
        // run.
        let mut map = ChunkMap::new();
        for striped in [
            BlockGroupFlags::RAID0,
            BlockGroupFlags::RAID10,
            BlockGroupFlags::RAID5,
            BlockGroupFlags::RAID6,
        ] {
            let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA | striped, &[(DEVID, 0)]);
            assert!(matches!(
                map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
                Err(ReadError::UnsupportedProfile { .. })
            ));
        }
        // And so is a profile word the format does not define, for the stronger reason that
        // nothing says what its stripes are.
        let (chunk, buf) = record(
            1 << 20,
            BlockGroupFlags::DATA | BlockGroupFlags::RAID1 | BlockGroupFlags::DUP,
            &[(DEVID, 0)],
        );
        assert!(matches!(
            map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::UnsupportedProfile { .. })
        ));
    }

    #[test]
    fn a_copy_placed_past_the_device_is_refused_where_the_chunk_enters_the_map() {
        let mut map = ChunkMap::new();
        // Ending one byte past the device.
        let (chunk, buf) = record(
            1 << 20,
            BlockGroupFlags::DATA,
            &[(DEVID, DEVICE_BYTES - (1 << 20) + 1)],
        );
        assert!(matches!(
            map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::BadChunk { .. })
        ));
        // And a placement whose sum leaves the range, which would otherwise wrap into an
        // offset that looks small and legal.
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID, u64::MAX)]);
        assert!(matches!(
            map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::BadChunk { .. })
        ));
        // Ending exactly at the device's last byte is inside it.
        let (chunk, buf) = record(
            1 << 20,
            BlockGroupFlags::DATA,
            &[(DEVID, DEVICE_BYTES - (1 << 20))],
        );
        map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES)
            .expect("exactly filling the device");
    }

    #[test]
    fn a_chunk_with_no_copy_on_this_device_is_not_in_the_map() {
        let mut map = ChunkMap::new();
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID + 1, 0)]);
        assert!(matches!(
            map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::BadChunk { .. })
        ));
        // A chunk with copies on both keeps only the one that is here, and stays readable.
        let (chunk, buf) = record(
            1 << 20,
            BlockGroupFlags::METADATA | BlockGroupFlags::RAID1,
            &[(DEVID + 1, 0), (DEVID, 4 << 20)],
        );
        map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES)
            .expect("one copy is here");
        assert_eq!(map.chunks()[0].copies, vec![4 << 20]);
        assert_eq!(map.translate(4096, 4096).expect("mapped"), (4 << 20) + 4096);
    }

    #[test]
    fn a_chunk_that_describes_no_run_at_all_is_refused() {
        let mut map = ChunkMap::new();
        for (length, stripes) in [(0u64, &[(DEVID, 0)][..]), (1 << 20, &[][..])] {
            let (chunk, buf) = record(length, BlockGroupFlags::DATA, stripes);
            assert!(matches!(
                map.insert(&key_at(0), &chunk, &buf, DEVID, DEVICE_BYTES),
                Err(ReadError::BadChunk { .. })
            ));
        }
        // A logical run that leaves the address space, which is the other end of the same
        // arithmetic the device bound covers at the physical end.
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID, 0)]);
        assert!(matches!(
            map.insert(&key_at(u64::MAX), &chunk, &buf, DEVID, DEVICE_BYTES),
            Err(ReadError::BadChunk { .. })
        ));
    }

    #[test]
    fn an_item_keyed_as_something_other_than_a_chunk_does_not_enter_the_map() {
        // The bootstrap array is a run of pairs with nothing framing them but their own
        // lengths, so what makes a pair a chunk is its key. An array whose first key says
        // something else is one this reader has misread, not one it should map.
        let mut map = ChunkMap::new();
        let (chunk, buf) = record(1 << 20, BlockGroupFlags::DATA, &[(DEVID, 0)]);
        for key in [
            DiskKey::new(objectid::FIRST_CHUNK_TREE, ItemType::DEV_ITEM, 0),
            DiskKey::new(objectid::DEV_ITEMS, ItemType::CHUNK_ITEM, 0),
        ] {
            assert!(matches!(
                map.insert(&key, &chunk, &buf, DEVID, DEVICE_BYTES),
                Err(ReadError::BadChunk { .. })
            ));
        }
    }

    #[test]
    fn the_bootstrap_array_is_read_pair_by_pair_to_the_length_the_superblock_recorded() {
        // The array the pinned baseline writes: one 129-byte pair, a 17-byte key and a chunk
        // of two stripes.
        let (_, buf) = record(
            8 << 20,
            BlockGroupFlags::SYSTEM | BlockGroupFlags::DUP,
            &[(DEVID, 22_020_096), (DEVID, 30_408_704)],
        );
        let mut array = vec![0u8; DiskKey::SIZE];
        key_at(22_020_096).write_to(&mut array);
        array.extend_from_slice(&buf);
        assert_eq!(array.len(), 129);

        let map = ChunkMap::from_bootstrap(&array, DEVID, DEVICE_BYTES).expect("one pair");
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.translate(22_036_480, 16_384).expect("the chunk tree"),
            22_036_480
        );
        assert_eq!(map.chunks()[0].copies, vec![22_020_096, 30_408_704]);
    }

    #[test]
    fn a_bootstrap_array_whose_framing_does_not_hold_is_refused_rather_than_guessed_at() {
        let (_, buf) = record(8 << 20, BlockGroupFlags::SYSTEM, &[(DEVID, 0)]);
        let mut array = vec![0u8; DiskKey::SIZE];
        key_at(0).write_to(&mut array);
        array.extend_from_slice(&buf);

        // A recorded length that stops inside the key, inside the chunk head, and inside the
        // stripes — the three places a pair can be cut off, each of which would otherwise
        // have a reader parse whatever followed as the next pair.
        for cut in [
            DiskKey::SIZE - 1,
            DiskKey::SIZE + Chunk::SIZE - 1,
            array.len() - 1,
        ] {
            assert!(
                matches!(
                    ChunkMap::from_bootstrap(&array[..cut], DEVID, DEVICE_BYTES),
                    Err(ReadError::BadBootstrap { .. })
                ),
                "a pair cut at {cut} bytes"
            );
        }
        // An array with nothing in it translates nothing, so it is a refusal rather than an
        // empty map that fails one call later with no explanation.
        assert!(matches!(
            ChunkMap::from_bootstrap(&[], DEVID, DEVICE_BYTES),
            Err(ReadError::BadBootstrap { .. })
        ));
    }
}
