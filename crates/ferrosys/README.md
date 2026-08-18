# ferrosys

Pure-Rust filesystem tooling: a formatter and reader with byte-reproducible on-disk
geometry. It builds and reads filesystem images in userspace, over ordinary byte streams,
in safe Rust. Each filesystem family is a module behind a feature of its own — `ext` is
ext2, ext3, and ext4, with resize-safe geometry, `fat` is FAT12, FAT16, and FAT32,
`exfat` is the interchange format SDXC cards specify, and `btrfs` is the copy-on-write
filesystem Fedora and openSUSE boot from.

Formatting runs in two phases: a planner computes the complete on-disk layout as an
in-memory value, and a materializer writes bytes against that plan. The UUID, hash
seed, and timestamps are inputs the caller supplies, so the same inputs produce the
same image byte for byte. The crate builds on Rust 1.88 or newer.

> **Status:** under active development. Following Cargo's
> `0.x` semantics, a breaking change bumps the minor version, and a `0.x` requirement
> resolves only within that minor — so a breaking release reaches no one unasked.

```rust
use ferrosys::ext::{
    format, FormatOptions, GrowReservation, Metadata, Reader, Timestamp, TreeBuilder,
};

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

The same tree vocabulary writes a FAT volume, under the `fat` feature — an EFI system
partition here, and the type follows from the cluster count rather than being asked for:

```rust
# #[cfg(feature = "fat")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use ferrosys::fat::{FatType, FormatOptions, Timestamp, VolumeLabel, format};
use ferrosys::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/EFI".to_vec(), Metadata::new(0o755, time))
    .file(b"/EFI/BOOTX64.EFI".to_vec(), b"MZ", Metadata::new(0o644, time));

let options = FormatOptions::new(0x1234_abcd, time).label(VolumeLabel::new("ESP")?);
let image = format(source, 64 << 20, options)?;
assert_eq!(image.layout().fat_type, FatType::Fat16);
# Ok(())
# }
# #[cfg(not(feature = "fat"))]
# fn main() {}
```

And an exFAT volume, under the `exfat` feature, where one input is enough to make the output
byte-reproducible — an empty exFAT volume records no time at all:

```rust
# #[cfg(feature = "exfat")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use ferrosys::exfat::{FormatOptions, Timestamp, VolumeLabel, format};
use ferrosys::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
    .file(b"/DCIM/IMG_0001.JPG".to_vec(), vec![0xff; 4096], Metadata::new(0o644, time));

let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
let image = format(source, 64 << 20, options)?;
assert_eq!(image.layout().bytes_per_cluster, 4 << 10);
# Ok(())
# }
# #[cfg(not(feature = "exfat"))]
# fn main() {}
```

## What it does

The ext family:

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
  deviation as a typed anomaly, projected into the crate's family-agnostic `Finding` and
  rendered as JSON, SARIF, or a table. The scan's every allocation is bounded by the bytes
  the source holds rather than by a count the image claims, so it is the path to point at
  an image built to be hostile.
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

The FAT family:

- **The type is derived, never chosen** — nothing in a FAT image records which of the
  three it is, so every driver counts the clusters and compares against two thresholds.
  The planner solves that circular count the way the format's own reference computation
  does, and the type falls out of it. A volume at one of the two counts that two
  mainstream drivers read as two different filesystems is never written: the planner
  declares the largest count neither disputes and leaves the few clusters between unused.
- **Every geometry the format defines** — 512-, 1024-, 2048-, and 4096-byte sectors, one
  or two file allocation tables, and an allocation unit up to 32 KiB, which is where the
  format's own guidance stops. Reserved, root, and table regions are cluster-aligned so
  the data region begins on a cluster boundary. The volume the caller gives is the volume
  the filesystem describes.
- **Byte-reproducible output** — the volume serial number and the times a directory entry
  carries are inputs, and the date conversion is UTC, so nothing about the machine that
  wrote an image reaches it.
- **Volume identity, held to what the format holds** — an eleven-byte label, upper-cased
  and checked against what a directory entry's name field may contain, written to the boot
  sector and to the root directory alike; the media descriptor, held to the values the
  format defines, the partition's start offset, and the boot loader's own bytes are inputs.
- **A reader for any conformant volume with one or two tables, whatever wrote it** — chains
  followed at all three entry widths, long names reassembled and tied to their short entry
  by checksum, and a whole-volume scan reporting what a checker would: a copy of the
  allocation table that disagrees with the first, a long name that belongs to no entry, a
  chain that loops or that two files both claim, and clusters allocated and reached by
  nothing.
- **The code page a short name is written in is an input, never a guess** — no FAT volume
  records one, and it was a property of the machine and the moment each name was created
  rather than of the volume. The default interprets nothing and hands the bytes back as
  they are; five single-byte OEM pages are built in, and any other is a caller's table.

The exFAT family:

- **Byte-reproducible from one input** — an empty exFAT volume records no time anywhere, so
  the volume serial number is the whole of what a formatter would otherwise take from its
  environment. Times reach the image only with the files that carry them.
- **The volume's own up-case table decides what a name matches** — exFAT folds names for
  comparison through a table each volume carries in its cluster heap, so a lookup resolves
  what a driver reading the same volume resolves rather than what this crate's copy of a
  table would. The writer emits the mapping the format recommends, and the reader decodes
  whichever one it finds, compressed or literal, and checks it against its own checksum.
- **Timestamps to ten milliseconds, with the zone the entry recorded** — three times per
  file, each with a hundredths byte and a UTC offset the format stores beside it, so an
  instant survives a round trip instead of being read as though every volume were written
  where it is being read.
- **Consecutive streams the allocation table does not describe** — a stream flagged
  `NoFatChain` occupies a run of clusters resolved by arithmetic, with no chain in the table
  at all. The writer allocates every run that way and the reader reads both shapes, so a
  volume another implementation chained through the table reads back identically.
- **An allocation bitmap, held against what the tree reaches** — one bit per cluster, written
  from the same planned allocation the table is, and checked in both directions by a scan: a
  cluster in use that no stream reaches, and a cluster a stream occupies that the bitmap
  calls free. The second is the disagreement a checker does not look for.
- **A reader for any conformant volume, whatever wrote it** — entry sets reassembled and held
  to their set checksum and name hash, both run shapes followed, every field bounded to the
  range the format states, and a whole-volume scan collecting each deviation as a typed
  anomaly. Every length an image declares is narrowed to what the volume could hold, so a
  crafted field costs what the bytes cost rather than what the number claims.

The btrfs family, which this crate reads in full and writes from a source tree:

- **The logical address space, and the trees on it** — every address in a btrfs is logical,
  and a chunk tree maps that space onto the device. `Volume` is that map and the trees
  through it; `Reader` is the filesystem view built on it. Two entry points, because the
  format has two layers and the tools that make this family worth reading work at both.
- **Every metadata block verified from the bytes that came off the device** — recomputed
  rather than compared against a value re-serialized through this crate's own types, so a
  filesystem this crate did not write verifies as itself. A block also records its own
  address and the filesystem it belongs to, and both are held against what the reader
  believed when it went to fetch it.
- **File data held against the checksums the filesystem recorded for it** — a crc32c per
  sector in a tree of its own, which is the one check no other family here can make: a file
  whose bytes decayed on the medium sits under trees that are entirely well-formed.
- **Subvolumes walked as part of one tree** — a directory entry naming a `ROOT_ITEM` is
  where a subvolume is mounted, so a walk crosses the seam and a path across it is one path.
  A node is a subvolume and an inode together, because an inode number means nothing alone.
- **Every bound a crafted image needs** — a leaf whose items are packed the way the format
  packs them, an item whose data stays inside its leaf under 64-bit arithmetic on every
  target, a descent with a decreasing measure and a visited set, and a superblock copy that
  records another place as its own.
- **A source tree written whole, in one transaction** — ten trees and one more per
  subvolume, every block checksummed, a crc32c beside every sector of file data, every
  allocated block recorded in the extent tree with the tree that owns it, and every
  superblock copy the device has room for. A caller names which of the source's directories
  become subvolumes, and which one a mount that names none lands in. It streams into a
  seekable destination and touches only the blocks it occupies, so a volume far larger than
  memory becomes a file that stays sparse; and the five values a formatter would
  conventionally invent are inputs, so two formats of the same parameters are the same bytes.

## Features

Ten, and the first four are the filesystem families — a build takes the families it
names. `ext` is on by default and is that family's whole surface: the formatter, the
reader, the feature model, and the on-disk structures, all reached through the `ext`
module. `fat` is off by default and adds the FAT12/FAT16/FAT32 formatter, reader,
geometry planner, on-disk structures, and classifier, under the `fat` module. `exfat` is
off by default and adds the same set for exFAT — formatter, reader, geometry planner,
on-disk structures, and classifier — under the `exfat` module. `btrfs` is off by default
and adds that family's reader, its logical address space, its B-trees, its geometry planner,
its writer with subvolumes, its on-disk structures, and its classifier, under the `btrfs`
module. Granularity is per *family*
rather than per format, since each set is one lineage sharing its on-disk structures, and
exFAT is a family of its own rather than a fourth FAT: it shares a name with FAT and no
bytes.

Turning every family off is a real build rather than a smaller version of the same one:
it leaves the family-agnostic substrate the crate root carries — the `crc32c` primitive,
the source and extraction vocabulary, and `detect`, which says which filesystem an image
holds — and no family code at all. That is the build for a consumer that classifies
images without reading them.

Three more name an algorithm rather than a family, because an encoding is a property of a
run of bytes and not of the format around it. Each is off by default, and each is what lets a
build read a file whose extents are stored that way — `zlib` for DEFLATE, `lzo` for LZO1X,
`zstd` for Zstandard. btrfs is the family here that stores runs that way, so a build that
wants to read them names a decoder beside it: `--features btrfs,zstd`. A build without the
decoder for the algorithm a file was stored with declines that *file* by name; one without a
decoder for an algorithm the filesystem advertises in its feature word declines the
*filesystem*, which is what that word means. `lzo` takes no dependency, its decoder being in
this crate; the other two take `miniz_oxide` and `ruzstd`, both of which decode and neither of
which is reached by anything else. Verification needs none of them: the checksums a filesystem
records cover the bytes it stored, so a compressed extent is verified without being expanded.

The last three are off by default, so a build that wants none of them depends only on
`thiserror`. None of them names a family: a source feeds whichever family is being written
and a sink drains whichever one was opened, so `--features fat,dir` is a build that formats a
FAT volume from a directory tree and extracts one back, with no ext code compiled.

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
- **`serde`** — `Serialize` on the findings vocabulary (`Finding`, `FindingReport`,
  `Severity`, `Family`) and ext's own taxonomy behind it (`Anomaly`, `ScanReport`,
  `Category`, `Location`), the planned geometry (`Layout`, `GroupLayout`, `BlockRange`),
  and the feature model (`FeatureSet`, `Profile`), for a consumer embedding them in a
  document of its own. The crate's own `to_json` and `to_sarif` emitters are unaffected:
  they stay the schema-versioned canonical form.

## Command line

[`ferrosys-cli`](https://crates.io/crates/ferrosys-cli) puts this crate on the command
line as the `ferrosys` binary: `format`, `inspect`, `extract`, `detect`, and `identity`.

## Documentation

The [guide](https://gregordinary.github.io/ferrosys/) is a narrative introduction, and the
[API reference](https://gregordinary.github.io/ferrosys/api/) documents every public item.

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your option.
