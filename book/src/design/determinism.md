# Deterministic output

The default materialization is byte-reproducible in every family. The same source and the
same inputs produce a byte-identical image on any machine.

Every value a filesystem would normally draw from its environment is an input instead.
Which values those are is a property of the format, so each family names its own. The list
is short in all four, because a format records only what it has a field for:

- **ext2, ext3, and ext4** take three: the **filesystem UUID**, a 16-byte value, the
  **directory-hash seed** that a hash-indexed directory orders its names by, and
  **timestamps**. The image records the hash seed beside the byte signedness names are
  compared under. A directory built on one host therefore reads the same way on another.
- **FAT12, FAT16, and FAT32** take two: the **volume serial number**, a 32-bit value the
  boot sector and its backup carry, and **timestamps**. A directory entry's dates are civil
  dates rather than instants, and the conversion is UTC. Nothing about the machine's own
  zone reaches an image either.
- **exFAT** takes one: the **volume serial number**. An empty exFAT volume records no time
  anywhere, so timestamps reach an image only with the files that carry them. An empty
  volume is reproducible from that one value alone.
- **btrfs** takes five: the **filesystem id** a person sees, the **chunk tree id** every
  tree block repeats, and the **device id**. The other two are the **top-level subvolume
  id** and one **instant**. The format's own tooling draws all five from a random source
  and the clock. Making them inputs is what makes a filesystem's bytes a function of what
  it was asked for.

A caller that wants clock- or random-derived values computes them and passes
them in explicitly, keeping that choice out of the default path.

What a filesystem assigns internally is fixed the same way. Inode-number assignment is a
function of the source in sorted path order, and so is cluster allocation. Two runs over
the same source therefore place the same objects in the same places, and write identical
bytes. Anything that reaches on-disk order (directory entries, block groups, an entry
set's position in its directory) is sorted or otherwise fixed into a determinate order.

## The scope of the guarantee

ferrosys guarantees identical bytes for one version, one feature set, and identical
inputs. Across versions the guarantee holds where the on-disk feature set is pinned
exactly. `ext::FeatureSet::DEFAULT` is frozen and safe to pin, and
`ext::FeatureSet::LATEST` tracks current `mke2fs` and moves between releases by design.

A consumer pinning an on-disk contract records the whole resolved feature set, which
`ext::FeatureSet::pin` emits. A feature-name list is not enough, because it omits the
block and inode sizes.
