# ferrosys

A pure-Rust ext2/ext3/ext4 filesystem: a formatter and reader with resize-safe,
byte-reproducible on-disk geometry. It builds and reads filesystem images in
userspace, over ordinary byte streams, in safe Rust.

Formatting runs in two phases: a planner computes the complete on-disk layout as an
in-memory value, and a materializer writes bytes against that plan. The UUID, hash
seed, and timestamps are inputs the caller supplies, so the same inputs produce the
same image byte for byte. The crate builds on Rust 1.88 or newer.

> **Status:** under active development. The API is not yet stable. Following Cargo's
> `0.x` semantics, a breaking change bumps the minor version, and a `0.x` requirement
> resolves only within that minor — so a breaking release reaches no one unasked.

```rust
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{format, FormatOptions, GrowReservation, Metadata, Reader, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
    .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), Metadata::new(0o644, time));

// Format a 64 MiB image reserving descriptor blocks to grow up to 32 GiB.
let mut options = FormatOptions::new([0x11; 16], time, [0u8; 16]);
options.grow = GrowReservation::UpTo(32 << 30);
let image = format(source, 64 << 20, options).expect("format");

// Read it back, over any Read + Seek source.
let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
let root = reader.inode(2).expect("root inode");
let contents = reader.read_dir(&root).expect("read root");
assert!(contents.iter().any(|e| e.name == b"etc"));
```

## What it does

- **Resize-safe geometry** — superblock and group-descriptor backups and reserved GDT
  blocks, sized by a grow reservation (none, a target size, or the format maximum), so
  the image grows in place without relocating its descriptor table. Block sizes of
  1024, 2048, and 4096.
- **Tunable geometry** — the inode count follows a bytes-per-inode ratio or an exact
  value, reserved super-user space is a percentage to two decimal places (exact to the
  block), and the filesystem carries a volume label of up to sixteen bytes. Each
  defaults to what the size implies.
- **Full file-type fidelity** — regular files, directories, fast and slow symlinks,
  hard links, and character / block device, FIFO, and socket nodes, each with its
  ownership, mode bits, and access / change / modification times at nanosecond
  precision.
- **Extent trees of any depth** — a file's mapping spills from the inode into external
  extent nodes as it grows, so file size is bounded by the filesystem.
- **Hash-indexed directories** (`dir_index`) — a directory that outgrows one block
  gains an htree ordered by the half-MD4, TEA, or legacy name hash. The hash and the
  byte signedness of names are recorded in the image, so output is independent of the
  build host.
- **Extended attributes and POSIX ACLs** — inline in the inode and in an external
  attribute block, including `security.capability`, SELinux labels, and
  `system.posix_acl_*`.
- **Metadata checksums** (`metadata_csum`, `metadata_csum_seed`) — a crc32c over the
  superblock, group descriptors, inodes, bitmaps, directory blocks, and attribute
  blocks, so a checker detects corruption of the filesystem's own metadata.
- **A format-time journal** (`has_journal`) — a jbd2 v2 log in the journal inode, sized
  from the filesystem, so the kernel journals writes from the first mount.
- **An orphan file** (`orphan_file`) — the inodes awaiting deletion live in a dedicated
  file, so concurrent deletions share no list.
- **A robust reader** — parses an image over any `Read + Seek` source at any byte offset
  (a partition inside a whole-disk image), bounds-checking every field, so a malformed
  image is a typed error. A strict conformance policy rejects anything a conformant
  modern ext4 would not carry; a lenient scan walks the whole image and collects every
  deviation as a typed anomaly, rendered as JSON, SARIF, or a table. The scan's every
  allocation is bounded by the bytes the source holds rather than by a count the image
  claims, so it is the path to point at an image built to be hostile.
- **Foreign images** — the reader reads filesystems other tools wrote: any inode size,
  including the 128-byte inode; both the extent tree and the classic direct/indirect map
  that ext2 and ext3 use; and checksums verified against each object's own bytes, so a
  field the filesystem carries and this crate does not model reads cleanly. `lookup`
  resolves a path through symbolic links against the image's own root.
- **Streaming in both directions** — `format_to` writes an image to any seekable
  destination, touching only the blocks the filesystem uses, so a file stays sparse and a
  filesystem larger than memory is possible, and `format` collects the same bytes in
  memory. A source may hand back a file's contents as a handle rather than a buffer, so a
  format's peak memory is the largest single file rather than the sum of them all. Reading
  is the same shape: `read_into` reads a range of a file, `read_data_to` streams one to a
  writer a window at a time, and `walk_with` walks the tree lazily, handing each entry to a
  callback that may read as it goes — so pulling a multi-gigabyte file out of an image
  costs a working set rather than its size.
- **64-bit addressing** — block numbers beyond 2^32, for filesystems past 16 TiB.

## Features

Four. `ext` is on by default and is the whole filesystem surface — the formatter, the
reader, the feature model, and the on-disk structures, all reached through the `ext`
module. Turning it off leaves the family-agnostic substrate the crate root carries: the
`crc32c` primitive and `detect`, which says which filesystem an image holds. That is the
build for a consumer that classifies images without reading them.

The other three are off by default, so a build that wants none of them depends only on
`thiserror`. Each enables `ext`, since each is a way of describing or emitting an ext
filesystem.

- **`tar`** — `ArchiveSource` builds a filesystem from a tar stream with its PAX
  timestamps, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` ACL records;
  `ArchiveSource::from_path` leaves each member's bytes on disk until that file is placed.
  `ArchiveSink` writes a filesystem back out as one, streaming each member.
- **`dir`** — `DirectorySource` walks a directory tree on this machine into a filesystem,
  carrying modes, ownership, all three times, symlinks, hard links, device, FIFO and
  socket nodes, and extended attributes with their POSIX ACLs. Each file's bytes are read
  as that file is placed and no descriptor is held in between, so the tree may hold any
  number of files. `owner(uid, gid)` replaces the host's ownership, which is what a build
  that does not run as root wants. `DirectorySink` writes a filesystem back out as a tree,
  creating each directory and then opening it so a name in the image can never reach a
  place the destination does not contain. The metadata and attributes both read are
  Linux's, so the types are built there; elsewhere the feature compiles to nothing and
  `ArchiveSource` and `ArchiveSink` are the portable way to describe and emit a tree.
- **`serde`** — `Serialize` on the scan taxonomy (`Anomaly`, `ScanReport`, `Severity`,
  `Category`, `Location`), the planned geometry (`Layout`, `GroupLayout`, `BlockRange`),
  and the feature model (`FeatureSet`, `Profile`), for a consumer embedding them in a
  document of its own. The crate's own `to_json` and `to_sarif` emitters are unaffected:
  they stay the schema-versioned canonical form.

## Command line

[`ferrosys-cli`](https://crates.io/crates/ferrosys-cli) puts this crate on the command
line as the `ferrosys` binary: `format`, `inspect`, `extract`, and `detect`.

## Documentation

The [guide](https://gregordinary.github.io/ferrosys/) is a narrative introduction, and the
[API reference](https://gregordinary.github.io/ferrosys/api/) documents every public item.

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your option.
