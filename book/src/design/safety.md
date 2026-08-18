# Safe by construction

`ferrosys` forbids `unsafe` at the crate root:

```rust,ignore
#![forbid(unsafe_code)]
```

`forbid` — not `deny` — means the prohibition cannot be locally overridden.
There is no `unsafe` block anywhere in the crate.

## On-disk types serialize through explicit byte accessors

All four families fix their byte order in the format rather than following the
host's: ext2, ext3, and ext4, FAT12 through FAT32, exFAT, and btrfs all store
their structures little-endian, and the jbd2 journal superblock an ext filesystem
carries is big-endian. Every on-disk
structure in every family is read and written field by field through explicit
accessors of the order that structure is defined in, so the byte layout is
spelled out at every field. The result is portable across architectures — an
image built on a big-endian host is byte-identical to one built on a
little-endian host.
