//! A bounded cache of blocks read from a source, the least recently used given up first.
//!
//! Two readers return to blocks they have already read: the ext reader to its group
//! descriptor and inode table blocks, which serve many inodes apiece, and the btrfs volume to
//! its tree blocks, whose upper levels every descent passes through. One cache serves both.
//! Which blocks are worth holding, and what a block is, stays with the caller; this keeps a
//! bounded number of values under the address each was read from.
//!
//! Every value it hands back was put there by a caller that read it the way an uncached read
//! would have, and the source does not change under a reader, so nothing it holds goes stale.
//! Giving up the least recently used value first is a stack algorithm: after the same
//! accesses, what a larger cache holds is a superset of what a smaller one holds, so a larger
//! cache never misses where a smaller one hits.
//!
//! The slots are searched in order. At the few hundred a reader holds, a search costs less
//! than the read of any one block it saves.

/// At most `capacity` values, each under the address it was read from.
pub(crate) struct BlockCache<V> {
    slots: Vec<Slot<V>>,
    capacity: usize,
    /// Counts accesses, so a slot's `used` orders the slots by recency.
    clock: u64,
}

struct Slot<V> {
    key: u64,
    used: u64,
    value: V,
}

impl<V> BlockCache<V> {
    /// A cache of at most `capacity` values. Zero holds nothing, and every read goes to the
    /// source.
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            slots: Vec::new(),
            capacity,
            clock: 0,
        }
    }

    /// A cache holding `budget` bytes of blocks `block` bytes long, and never fewer than
    /// `floor` of them, so the largest block size a format defines still holds a working set.
    pub(crate) fn within(budget: usize, block: usize, floor: usize) -> Self {
        Self::new((budget / block.max(1)).max(floor))
    }

    /// The value held under `key`, which becomes the most recently used.
    pub(crate) fn get(&mut self, key: u64) -> Option<&V> {
        self.clock += 1;
        let clock = self.clock;
        let slot = self.slots.iter_mut().find(|slot| slot.key == key)?;
        slot.used = clock;
        Some(&slot.value)
    }

    /// Hold `value` under `key`, giving up the least recently used value if the cache is
    /// full. A caller inserts only after a [`get`](Self::get) of the same key missed, so a
    /// key is never held twice.
    pub(crate) fn insert(&mut self, key: u64, value: V) {
        if self.capacity == 0 {
            return;
        }
        self.clock += 1;
        let slot = Slot {
            key,
            used: self.clock,
            value,
        };
        if self.slots.len() < self.capacity {
            self.slots.push(slot);
        } else if let Some(oldest) = self.slots.iter_mut().min_by_key(|slot| slot.used) {
            *oldest = slot;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `trace` through a cache of `capacity`, inserting on every miss, and say which
    /// accesses hit.
    fn hits(capacity: usize, trace: &[u64]) -> Vec<bool> {
        let mut cache = BlockCache::new(capacity);
        trace
            .iter()
            .map(|&key| {
                let hit = cache.get(key).is_some();
                if !hit {
                    cache.insert(key, key * 10);
                }
                hit
            })
            .collect()
    }

    #[test]
    fn a_value_comes_back_under_its_key_and_the_least_recently_used_goes_first() {
        let mut cache = BlockCache::new(2);
        cache.insert(1, "one");
        cache.insert(2, "two");
        // Touching 1 makes 2 the least recently used, so 3 takes its slot.
        assert_eq!(cache.get(1), Some(&"one"));
        cache.insert(3, "three");
        assert_eq!(cache.get(2), None);
        assert_eq!(cache.get(1), Some(&"one"));
        assert_eq!(cache.get(3), Some(&"three"));
    }

    #[test]
    fn a_cache_of_nothing_holds_nothing() {
        let mut cache = BlockCache::new(0);
        cache.insert(7, ());
        assert!(cache.get(7).is_none());
        assert_eq!(BlockCache::<()>::within(4096, 65536, 4).capacity, 4);
        assert_eq!(BlockCache::<()>::within(256 << 10, 4096, 4).capacity, 64);
    }

    #[test]
    fn a_larger_cache_hits_wherever_a_smaller_one_does() {
        // The stack property, over a trace with the shape a tree descent has: a few hot
        // addresses revisited between long runs of cold ones.
        let mut state = 0x5eed_u64;
        let trace: Vec<u64> = (0..4000)
            .map(|step| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                if step % 3 == 0 {
                    (state >> 60) % 4
                } else {
                    (state >> 40) % 300
                }
            })
            .collect();
        let mut previous = hits(0, &trace);
        assert!(previous.iter().all(|&hit| !hit));
        for capacity in [1, 2, 4, 16, 64, 256, 512] {
            let now = hits(capacity, &trace);
            for (at, (&small, &large)) in previous.iter().zip(&now).enumerate() {
                assert!(!small || large, "capacity {capacity} missed access {at}");
            }
            previous = now;
        }
    }
}
