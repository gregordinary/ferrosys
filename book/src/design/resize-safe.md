# Resize-safe geometry

This page is about one family. Growing a filesystem in place is an ext concern: FAT12,
FAT16, FAT32, and exFAT each fix their allocation tables at format time and are resized by
rewriting them, and btrfs grows through its own chunk tree under a running kernel. What
follows is the geometry an ext2, ext3, or ext4 image is written with so that growth is
safe.

An ext4 filesystem grows by adding block groups, and each new group needs a slot
in the group-descriptor table. If no room was set aside for that table to grow,
the kernel converts the filesystem to a distributed descriptor layout the first
time it is enlarged — an in-place conversion that can corrupt the filesystem.

`ferrosys` writes a geometry that never needs that conversion. Two
structures make growth safe, and both are decided when the layout is planned,
before any byte is written:

## Reserved descriptor blocks

The formatter takes a **maximum grow target** — the largest size the image may
ever occupy — and reserves exactly enough group-descriptor-table blocks to
describe a filesystem that large. The reservation is tracked through the resize
inode, whose double-indirect map points at the reserved blocks in the primary
group and every backup. Growing the filesystem, up to that target, consumes the
reserved blocks in place; the descriptor table never has to move.

The target is named, not derived from the image's size by a fixed multiplier. A
caller who knows the device the image will be flashed to names it, and that
target is honored to the format's ceiling. A target larger than the reservation
can represent is rejected when the layout is planned, rather than written as a
filesystem that would need the corrupting conversion to grow.

A caller who names no target gets the largest reservation that costs at most one
block in sixty-four of the filesystem. Filling the resize inode's map costs the
same 1024 blocks at a 4096-byte block whatever the image's size — a
sixty-fourth of a 256 MiB filesystem, and a quarter of a 16 MiB one — so from
256 MiB up this is the whole map, about 8 TiB of reach, and below it the share
the image can spare: a 16 MiB image reserves 64 blocks and grows online to
520 GiB. Growth headroom therefore never costs more than 1.6% of a filesystem,
and asking for no target can never turn an image that would format into one that
does not.

## Superblock and descriptor backups

The superblock and the group-descriptor table are copied into backup groups
following the `sparse_super` rule — group 1, and the groups that are powers of 3,
5, and 7. A checker can recover the filesystem from a backup if the primary copy
is damaged, and the backups are placed so that growth does not disturb them.

## Flex block groups

The block bitmaps, inode bitmaps, and inode tables of the groups in a flex block
group are packed together in the flex group's first group, leaving the remaining
groups as contiguous data space. The packing is computed to the byte, including
the partial final group and the table slots a single-group flex block group
reserves for later growth.

Together these give the property the crate is built around: an image that a
kernel can grow, in place and online, up to its declared maximum, and that a
checker accepts clean at every size along the way.
