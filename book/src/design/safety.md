# Safe by construction

`ferrosys` forbids `unsafe` at the crate root:

```rust,ignore
#![forbid(unsafe_code)]
```

`forbid` — not `deny` — means the prohibition cannot be locally overridden.
There is no `unsafe` block anywhere in the crate.

## On-disk types serialize through explicit byte accessors

ext4 stores its structures little-endian on disk, regardless of the host's byte
order. Every on-disk structure is read and written field by field through
explicit little-endian byte accessors, so the byte layout is spelled out at every
field. The result is portable across architectures — an image built on a
big-endian host is byte-identical to one built on a little-endian host.
