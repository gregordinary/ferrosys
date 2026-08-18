# Deterministic output

The default materialization is byte-reproducible in every family — ext2, ext3,
and ext4; FAT12, FAT16, and FAT32; exFAT; and btrfs: the same source and the same
inputs produce a byte-identical image on any machine.

Every value a filesystem would normally draw from its environment is an input
instead. Which values those are is a property of the format, so each family names
its own — and the list is short in all four, because a format records only what it
has a field for:

- **ext** takes three: the **filesystem UUID**, a 16-byte value; the
  **directory-hash seed**, which is what a hash-indexed directory orders its names
  by; and **timestamps**. The hash seed is recorded in the image alongside the byte
  signedness names are compared under, so a directory built on one host reads the
  same way on another.
- **FAT** takes two: the **volume serial number**, a 32-bit value the boot sector
  and its backup carry, and **timestamps**. A directory entry's dates are civil
  dates rather than instants, and the conversion is UTC, so nothing about the
  machine's own zone reaches an image either.
- **exFAT** takes one: the **volume serial number**. An empty exFAT volume records
  no time anywhere, so timestamps reach an image only with the files that carry
  them, and an empty volume is reproducible from that one value alone.
- **btrfs** takes five: the **filesystem id** a person sees, the **chunk tree id**
  every tree block repeats, the **device id**, the **top-level subvolume id**, and
  one **instant** — the five values the format's own tooling draws from a random
  source and the clock, made inputs so that a filesystem's bytes are a function of
  what it was asked for.

A caller that wants clock- or random-derived values computes them and passes
them in explicitly, keeping that choice out of the default path.

What a filesystem assigns internally is fixed the same way. Inode-number
assignment is a function of the source in sorted path order, and so is cluster
allocation, so two runs over the same source place the same objects in the same
places — and therefore write identical bytes. Anything that reaches on-disk order
(directory entries, block groups, an entry set's position in its directory) is
sorted or otherwise fixed into a determinate order.
