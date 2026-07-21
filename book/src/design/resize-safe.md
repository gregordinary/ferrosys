# Resize-safe geometry

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
caller who knows the device the image will be flashed to names it; a caller who
names none gets the format maximum — as much headroom as the resize inode can
address — so an image built without a target still grows onto any device up to
that ceiling. A target larger than the reservation can represent is rejected when
the layout is planned, rather than written as a filesystem that would need the
corrupting conversion to grow.

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
