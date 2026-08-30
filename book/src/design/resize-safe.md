# Resize-safe geometry

This page is about one family. Growing a filesystem in place is an ext concern. FAT12,
FAT16, FAT32, and exFAT each fix their allocation tables at format time, and a resize
rewrites those tables. btrfs grows through its own chunk tree under a running kernel. This
page describes the geometry ferrosys writes into an ext2, ext3, or ext4 image so that
growth is safe.

An ext4 filesystem grows by adding block groups, and each new group needs a slot in the
group-descriptor table. If nothing was set aside for that table to grow, the kernel
converts the filesystem to a distributed descriptor layout the first time it grows. That
in-place conversion can corrupt the filesystem.

`ferrosys` writes a geometry that never needs that conversion. Two structures make growth
safe, and the planner fixes both before any byte is written:

## Reserved descriptor blocks

The formatter takes a **maximum grow target**, the largest size the image can ever
occupy. It reserves exactly enough group-descriptor-table blocks to describe a filesystem
that large. The resize inode tracks the reservation, and its double-indirect map points at
the reserved blocks in the primary group and every backup. Growth up to that target
consumes the reserved blocks in place. The descriptor table never has to move.

The target is named, not derived from the image's size by a fixed multiplier. A caller who
knows the device the image will be flashed to names it, and ferrosys honors that target to
the format's ceiling. The planner rejects a target larger than the reservation can
represent. It refuses rather than write a filesystem that would need the corrupting
conversion to grow.

A caller who names no target gets the largest reservation that costs at most one block in
sixty-four of the filesystem.

Filling the resize inode's map costs the same 1024 blocks at a 4096-byte block, whatever
the image's size. That is a sixty-fourth of a 256 MiB filesystem and a quarter of a 16 MiB
one. From 256 MiB up, the reservation is the whole map, about 8 TiB of reach. Below that
it is the share the image can spare: a 16 MiB image reserves 64 blocks and grows online to
520 GiB.

Growth headroom therefore never costs more than 1.6% of a filesystem. Asking for no target
can never turn an image that would format into one that does not.

## Superblock and descriptor backups

ferrosys copies the superblock and the group-descriptor table into backup groups by the
`sparse_super` rule. The backups are group 1, and the groups that are powers of 3, 5,
and 7. If the primary copy is damaged, a checker can recover the filesystem from a backup.
The backups sit where growth does not disturb them.

## Flex block groups

A flex block group packs the block bitmaps, inode bitmaps, and inode tables of its groups
into its first group. The remaining groups are contiguous data space. ferrosys computes the
packing to the byte, including the partial final group and the table slots a single-group
flex block group reserves for later growth.

Together these give the property the crate is built around. A kernel can grow the image,
in place and online, up to its declared maximum. A checker accepts it clean at every size
along the way.
