# Safe by construction

`ferrosys` forbids `unsafe` at the crate root:

```rust,ignore
#![forbid(unsafe_code)]
```

`forbid` — not `deny` — means the prohibition cannot be locally overridden.
There is no `unsafe` block anywhere in the crate.

## On-disk types serialize through explicit byte accessors

All four families fix their byte order in the format, not in the host. ext2, ext3, and
ext4, FAT12 through FAT32, exFAT, and btrfs all store their structures little-endian.
The jbd2 journal superblock an ext filesystem carries is big-endian.

Every family reads and writes each on-disk structure field by field, through explicit
accessors of the order that structure defines. The byte layout is therefore spelled out
at every field. The result is portable across architectures: an image built on a
big-endian host is byte-identical to one built on a little-endian host.
